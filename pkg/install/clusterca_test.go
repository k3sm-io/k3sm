/*
Copyright The k3sm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package install

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
)

// TestProvisionAgentClusterCA pins the worker's root-only cluster CA copy,
// the anchor its netd checks a managed update's signer against: an install
// with a token writes the CA the token pinned, a later install without one
// keeps that copy (the service user can change neither it nor its directory),
// a node joined before the copy existed gets it once from its credential.
func TestProvisionAgentClusterCA(t *testing.T) {
	t.Run("an agent install with a token writes the pinned CA before netd starts", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		seedJoinedAgent(t, f)
		if err := Install(context.Background(), f, agentCfg(t)); err != nil {
			t.Fatalf("Install: %v", err)
		}
		got, ok := f.files[AgentClusterCAPath]
		if !ok {
			t.Fatalf("no %s written", AgentClusterCAPath)
		}
		if err := checkCAPEM(got); err != nil {
			t.Fatalf("%s is not a CA: %v", AgentClusterCAPath, err)
		}
		pin, err := certs.CertPin(got)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.EqualFold(pin, theTokenPinOf(f)) {
			t.Errorf("the written CA pins %s, the token pins %s", pin, theTokenPinOf(f))
		}
		write, boot := -1, -1
		for i, c := range f.calls {
			if write < 0 && strings.HasPrefix(c, "WriteRootOnlyFile:"+AgentClusterCAPath+":") {
				write = i
			}
			if boot < 0 && c == "Bootstrap:"+NetdLabel {
				boot = i
			}
		}
		if write < 0 || boot < 0 || write > boot {
			t.Errorf("the cluster CA copy (call %d) must be written before netd is bootstrapped (call %d)", write, boot)
		}
	})
	t.Run("an agent reinstall without a token keeps the existing copy", func(t *testing.T) {
		f := &fakeSystem{}
		seedJoinedAgent(t, f)
		other, err := certs.NewCA("k3sm-cluster-ca")
		if err != nil {
			t.Fatal(err)
		}
		f.putFile(AgentClusterCAPath, other.CertPEM)
		cfg := agentCfg(t).withDefaults()
		if err := provisionAgentClusterCA(f, cfg, nil); err != nil {
			t.Fatalf("provisionAgentClusterCA = %v", err)
		}
		if !bytes.Equal(f.files[AgentClusterCAPath], other.CertPEM) {
			t.Error("the root-only copy was replaced without a pinned CA")
		}
	})
	t.Run("a node joined before the copy existed gets it from its credential", func(t *testing.T) {
		f := &fakeSystem{}
		cred := mintNodeCredential(t, Config{}.withDefaults().agentWorkDir())
		cred.seed(f)
		cfg := agentCfg(t).withDefaults()
		if err := provisionAgentClusterCA(f, cfg, nil); err != nil {
			t.Fatalf("provisionAgentClusterCA = %v", err)
		}
		if !bytes.Equal(f.files[AgentClusterCAPath], cred.caPEM) {
			t.Error("the copy is not the credential's cluster CA")
		}
	})
	t.Run("a served CA that is not a CA refuses", func(t *testing.T) {
		f := &fakeSystem{}
		if err := provisionAgentClusterCA(f, agentCfg(t).withDefaults(), []byte("not pem")); err == nil {
			t.Fatal("provisionAgentClusterCA accepted a non-CA")
		}
	})
}

// theTokenPinOf is the CA hash the fake's staged operator token carries.
func theTokenPinOf(f *fakeSystem) string {
	tok := strings.TrimSpace(string(f.files[operatorTokenFile]))
	tok = strings.TrimPrefix(tok, "K10")
	if i := strings.Index(tok, "::"); i >= 0 {
		return tok[:i]
	}
	return tok
}

// mintCA returns a fresh cluster CA certificate as PEM.
func mintCA(t *testing.T) []byte {
	t.Helper()
	ca, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatal(err)
	}
	return ca.CertPEM
}

// anchorCallAt is the index of the first recorded call with prefix, or -1.
func anchorCallAt(f *fakeSystem, prefix string) int {
	return slices.IndexFunc(f.calls, func(c string) bool { return strings.HasPrefix(c, prefix) })
}

// TestProvisionServerClusterCA pins a server's root-held cluster CA copy.
func TestProvisionServerClusterCA(t *testing.T) {
	anchorWrite := "WriteRootOnlyFile:" + AgentClusterCAPath + ":0644"
	t.Run("an upgraded server gets the copy before the swap and before netd restarts", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		ca := mintCA(t)
		cfg := testConfig(t)
		f.putFile(certs.ClusterCACertPath(cfg.withDefaults().serverWorkDir()), ca)
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if !bytes.Equal(f.files[AgentClusterCAPath], ca) {
			t.Fatalf("the copy is %q", f.files[AgentClusterCAPath])
		}
		write := anchorCallAt(f, anchorWrite)
		swap, boot := anchorCallAt(f, "SwapInstallRoot:"), anchorCallAt(f, "Bootstrap:"+NetdLabel)
		bootout := anchorCallAt(f, "Bootout:"+NetdLabel)
		if write < 0 || swap < 0 || boot < 0 || write > swap || write > boot || (bootout >= 0 && write > bootout) {
			t.Errorf("copy at call %d, swap at %d, netd bootout at %d, bootstrap at %d", write, swap, bootout, boot)
		}
	})
	t.Run("a first install gets the copy once the control plane has minted its CA", func(t *testing.T) {
		shrinkRestartBudgets(t)
		ca := mintCA(t)
		f := &fakeSystem{bootCA: ca}
		if err := Install(context.Background(), f, testConfig(t)); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if !bytes.Equal(f.files[AgentClusterCAPath], ca) {
			t.Fatalf("the copy is %q", f.files[AgentClusterCAPath])
		}
		write, boot := anchorCallAt(f, anchorWrite), anchorCallAt(f, "Bootstrap:"+ServerLabel)
		if write < boot {
			t.Errorf("copy at call %d, before the server bootstrap at %d", write, boot)
		}
	})
	t.Run("a copy that differs from the CA on disk is kept and named", func(t *testing.T) {
		held, onDisk := mintCA(t), mintCA(t)
		f := &fakeSystem{}
		f.putFile(AgentClusterCAPath, held)
		var logged bytes.Buffer
		cfg := testConfig(t).withDefaults()
		cfg.Logger = slog.New(slog.NewTextHandler(&logged, nil))
		if err := provisionServerClusterCA(context.Background(), f, cfg, onDisk); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(f.files[AgentClusterCAPath], held) {
			t.Error("the copy was replaced from a file the service user owns")
		}
		for _, want := range []string{AgentClusterCAPath, "sudo k3sm install", "differs"} {
			if !strings.Contains(logged.String(), want) {
				t.Errorf("log lacks %q:\n%s", want, logged.String())
			}
		}
	})
	t.Run("an equal copy is not rewritten", func(t *testing.T) {
		ca := mintCA(t)
		f := &fakeSystem{}
		f.putFile(AgentClusterCAPath, ca)
		if err := provisionServerClusterCA(context.Background(), f, testConfig(t).withDefaults(), ca); err != nil {
			t.Fatal(err)
		}
		if anchorCallAt(f, anchorWrite) >= 0 {
			t.Error("an equal copy was rewritten")
		}
	})
	t.Run("a copy that is not a CA is replaced", func(t *testing.T) {
		ca := mintCA(t)
		f := &fakeSystem{}
		f.putFile(AgentClusterCAPath, []byte("not pem"))
		if err := provisionServerClusterCA(context.Background(), f, testConfig(t).withDefaults(), ca); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(f.files[AgentClusterCAPath], ca) {
			t.Error("an unusable copy was kept")
		}
	})
	t.Run("a control plane CA that is not a CA writes nothing", func(t *testing.T) {
		f := &fakeSystem{}
		if err := provisionServerClusterCA(context.Background(), f, testConfig(t).withDefaults(), []byte("not pem")); err != nil {
			t.Fatal(err)
		}
		if _, ok := f.files[AgentClusterCAPath]; ok {
			t.Error("a certificate that is not a CA was copied")
		}
	})
	t.Run("a joining server writes the CA its token pinned", func(t *testing.T) {
		ca, held := mintCA(t), mintCA(t)
		f := &fakeSystem{}
		f.putFile(AgentClusterCAPath, held)
		if err := provisionAgentClusterCA(f, testConfig(t).withDefaults(), ca); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(f.files[AgentClusterCAPath], ca) {
			t.Error("the pinned CA was not written")
		}
	})
	t.Run("a server with nothing pinned leaves the copy to step 2e", func(t *testing.T) {
		f := &fakeSystem{}
		if err := provisionAgentClusterCA(f, testConfig(t).withDefaults(), nil); err != nil {
			t.Fatal(err)
		}
		if _, ok := f.files[AgentClusterCAPath]; ok {
			t.Error("a copy was written with nothing to write")
		}
	})
}

// TestServerClusterCACopyAcrossNewClusters walks the installs that can follow a CA
// appearing in the PKI dir: a valid copy is never replaced, and removing it is what
// lets the next install write the current CA.
func TestServerClusterCACopyAcrossNewClusters(t *testing.T) {
	anchorWrite := "WriteRootOnlyFile:" + AgentClusterCAPath + ":0644"
	loggedConfig := func(t *testing.T) (Config, *bytes.Buffer) {
		t.Helper()
		var logged bytes.Buffer
		cfg := testConfig(t)
		cfg.Logger = slog.New(slog.NewTextHandler(&logged, nil))
		return cfg, &logged
	}
	t.Run("a new cluster with no copy gets one", func(t *testing.T) {
		shrinkRestartBudgets(t)
		ca := mintCA(t)
		f := &fakeSystem{bootCA: ca}
		if err := Install(context.Background(), f, testConfig(t)); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if !bytes.Equal(f.files[AgentClusterCAPath], ca) {
			t.Errorf("the copy is %q", f.files[AgentClusterCAPath])
		}
	})
	t.Run("an emptied work dir keeps the copy and names the way forward", func(t *testing.T) {
		shrinkRestartBudgets(t)
		held, minted := mintCA(t), mintCA(t)
		f := &fakeSystem{bootCA: minted}
		f.putFile(AgentClusterCAPath, held)
		cfg, logged := loggedConfig(t)
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if !bytes.Equal(f.files[AgentClusterCAPath], held) {
			t.Error("a valid copy was replaced")
		}
		for _, want := range []string{"level=WARN", "new cluster", "sudo rm " + AgentClusterCAPath, "sudo k3sm install"} {
			if !strings.Contains(logged.String(), want) {
				t.Errorf("log lacks %q:\n%s", want, logged.String())
			}
		}

		// The remedy the warning gives.
		delete(f.files, AgentClusterCAPath)
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install after removing the copy: %v", err)
		}
		if !bytes.Equal(f.files[AgentClusterCAPath], minted) {
			t.Errorf("after removing the copy it is %q", f.files[AgentClusterCAPath])
		}
	})
	t.Run("uninstall keeps the copy and the next install leaves it alone", func(t *testing.T) {
		shrinkRestartBudgets(t)
		ca := mintCA(t)
		f := &fakeSystem{bootCA: ca}
		cfg := testConfig(t)
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if err := Uninstall(context.Background(), f, cfg); err != nil {
			t.Fatalf("Uninstall: %v", err)
		}
		if !bytes.Equal(f.files[AgentClusterCAPath], ca) {
			t.Fatal("uninstall removed the copy")
		}
		f.calls = nil
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if anchorCallAt(f, anchorWrite) >= 0 {
			t.Error("an equal copy was rewritten")
		}
		if !bytes.Equal(f.files[AgentClusterCAPath], ca) {
			t.Errorf("the copy is %q", f.files[AgentClusterCAPath])
		}
	})
}

// queuedWrites gives a net.Pipe end the buffering a socket has: a TLS peer writes its
// whole flight before it reads, and the client's alert would otherwise wait for it.
type queuedWrites struct {
	net.Conn
	queue  chan []byte
	closed chan struct{}
	done   chan struct{}
	once   sync.Once
}

func newQueuedWrites(c net.Conn) *queuedWrites {
	q := &queuedWrites{Conn: c, queue: make(chan []byte, 64), closed: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(q.done)
		for {
			select {
			case b := <-q.queue:
				if _, err := c.Write(b); err != nil {
					return
				}
			case <-q.closed:
				return
			}
		}
	}()
	return q
}

func (q *queuedWrites) Write(b []byte) (int, error) {
	select {
	case q.queue <- bytes.Clone(b):
		return len(b), nil
	case <-q.closed:
		return 0, net.ErrClosed
	}
}

// Close is safe to call twice: the TLS server closes its transport on some
// failed handshakes, and the helper closes it again on the way out.
func (q *queuedWrites) Close() error {
	q.once.Do(func() { close(q.closed) })
	err := q.Conn.Close()
	<-q.done
	return err
}

// servingAs answers DialAPIServer with an in-memory TLS server whose certificate ca
// issued.
func servingAs(t *testing.T, ca *certs.CA) func(context.Context, string) (net.Conn, error) {
	t.Helper()
	certPEM, keyPEM, err := ca.IssueServing("kube-apiserver", []string{"kubernetes"}, []net.IP{net.ParseIP("10.43.0.1")}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return func(ctx context.Context, _ string) (net.Conn, error) {
		client, server := net.Pipe()
		done := make(chan struct{})
		t.Cleanup(func() { <-done })
		go func() {
			defer close(done)
			queued := newQueuedWrites(server)
			defer func() { _ = queued.Close() }()
			_ = tls.Server(queued, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}).HandshakeContext(ctx)
		}()
		return client, nil
	}
}

func mintFullCA(t *testing.T) *certs.CA {
	t.Helper()
	ca, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// TestCheckServedCA pins the answer to whether the listening apiserver's
// certificate chains to a candidate CA.
func TestCheckServedCA(t *testing.T) {
	const addr = "127.0.0.1:6443"
	ca := mintFullCA(t)
	t.Run("a certificate the candidate issued matches", func(t *testing.T) {
		f := &fakeSystem{apiServerDial: servingAs(t, ca)}
		if v, err := checkServedCA(context.Background(), f, addr, ca.CertPEM); v != servedCAMatches {
			t.Errorf("verdict = %v, %v", v, err)
		}
	})
	t.Run("a certificate another CA issued differs", func(t *testing.T) {
		f := &fakeSystem{apiServerDial: servingAs(t, mintFullCA(t))}
		if v, err := checkServedCA(context.Background(), f, addr, ca.CertPEM); v != servedCADiffers || err == nil {
			t.Errorf("verdict = %v, %v", v, err)
		}
	})
	t.Run("nothing listening gives no verdict", func(t *testing.T) {
		if v, err := checkServedCA(context.Background(), &fakeSystem{}, addr, ca.CertPEM); v != servedCANoAnswer || err == nil {
			t.Errorf("verdict = %v, %v", v, err)
		}
	})
	t.Run("a listener that closes the handshake gives no verdict", func(t *testing.T) {
		f := &fakeSystem{apiServerDial: func(context.Context, string) (net.Conn, error) {
			client, server := net.Pipe()
			if err := server.Close(); err != nil {
				return nil, err
			}
			return client, nil
		}}
		if v, err := checkServedCA(context.Background(), f, addr, ca.CertPEM); v != servedCANoAnswer || err == nil {
			t.Errorf("verdict = %v, %v", v, err)
		}
	})
	t.Run("a handshake that stalls ends with its context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		f := &fakeSystem{apiServerDial: func(context.Context, string) (net.Conn, error) {
			client, server := net.Pipe()
			t.Cleanup(func() { _ = server.Close() })
			return client, nil
		}}
		if v, err := checkServedCA(ctx, f, addr, ca.CertPEM); v != servedCANoAnswer || err == nil {
			t.Errorf("verdict = %v, %v", v, err)
		}
	})
	t.Run("the check is bounded under five seconds", func(t *testing.T) {
		var deadline time.Time
		f := &fakeSystem{apiServerDial: func(ctx context.Context, _ string) (net.Conn, error) {
			deadline, _ = ctx.Deadline()
			return nil, errors.New("not listening")
		}}
		start := time.Now()
		if v, _ := checkServedCA(context.Background(), f, addr, ca.CertPEM); v != servedCANoAnswer {
			t.Errorf("verdict = %v", v)
		}
		if deadline.IsZero() || deadline.Sub(start) >= 5*time.Second {
			t.Errorf("deadline is %v after the start", deadline.Sub(start))
		}
	})
}

// TestChainsToCandidateAsksOnlyWhichCAIssued pins that a leaf out of date or naming
// nothing still chains to the CA that issued it.
func TestChainsToCandidateAsksOnlyWhichCAIssued(t *testing.T) {
	ca := mintFullCA(t)
	certPEM, _, err := ca.IssueServing("kube-apiserver", nil, nil, time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.CertPEM)
	if err := chainsToCandidate([]*x509.Certificate{leaf}, roots); err != nil {
		t.Errorf("chainsToCandidate = %v", err)
	}
	other := x509.NewCertPool()
	other.AppendCertsFromPEM(mintCA(t))
	if err := chainsToCandidate([]*x509.Certificate{leaf}, other); !errors.Is(err, errServedCADiffers) {
		t.Errorf("chainsToCandidate against another CA = %v", err)
	}
	if err := chainsToCandidate(nil, roots); !errors.Is(err, errServedCADiffers) {
		t.Errorf("chainsToCandidate with no certificate = %v", err)
	}
}

// TestFirstServerClusterCACopyIsChecked pins a server's first copy against what its
// apiserver serves, when one is up to ask.
func TestFirstServerClusterCACopyIsChecked(t *testing.T) {
	pkiPath := func(cfg Config) string { return certs.ClusterCACertPath(cfg.withDefaults().serverWorkDir()) }
	setup := func(t *testing.T) (*fakeSystem, Config, *bytes.Buffer) {
		t.Helper()
		shrinkRestartBudgets(t)
		var logged bytes.Buffer
		cfg := testConfig(t)
		cfg.Logger = slog.New(slog.NewTextHandler(&logged, nil))
		return &fakeSystem{}, cfg, &logged
	}
	t.Run("an upgrade checks before the daemons stop and writes on a match", func(t *testing.T) {
		f, cfg, logged := setup(t)
		ca := mintFullCA(t)
		f.putFile(pkiPath(cfg), ca.CertPEM)
		f.putLoaded(NetdLabel, ServerLabel)
		f.apiServerDial = servingAs(t, ca)
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if !bytes.Equal(f.files[AgentClusterCAPath], ca.CertPEM) {
			t.Fatalf("the copy is %q", f.files[AgentClusterCAPath])
		}
		dial, bootout := anchorCallAt(f, "DialAPIServer:127.0.0.1:"), anchorCallAt(f, "Bootout:"+ServerLabel)
		if dial < 0 || bootout < 0 || dial > bootout {
			t.Errorf("dial at call %d, server bootout at call %d", dial, bootout)
		}
		if strings.Contains(logged.String(), "unverified") {
			t.Errorf("a checked copy was logged as unverified:\n%s", logged.String())
		}
	})
	t.Run("an upgrade writes nothing when the served certificate does not chain", func(t *testing.T) {
		f, cfg, logged := setup(t)
		ca := mintFullCA(t)
		f.putFile(pkiPath(cfg), ca.CertPEM)
		f.putLoaded(NetdLabel, ServerLabel)
		f.apiServerDial = servingAs(t, mintFullCA(t))
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if got, ok := f.files[AgentClusterCAPath]; ok {
			t.Errorf("a copy was written: %q", got)
		}
		for _, want := range []string{"level=WARN", "does not chain", "sudo k3sm install"} {
			if !strings.Contains(logged.String(), want) {
				t.Errorf("log lacks %q:\n%s", want, logged.String())
			}
		}
	})
	t.Run("a stopped node keeps writing and logs the copy as unverified", func(t *testing.T) {
		f, cfg, logged := setup(t)
		ca := mintCA(t)
		f.putFile(pkiPath(cfg), ca)
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if !bytes.Equal(f.files[AgentClusterCAPath], ca) {
			t.Errorf("the copy is %q", f.files[AgentClusterCAPath])
		}
		if !strings.Contains(logged.String(), "unverified") {
			t.Errorf("log does not say the copy is unverified:\n%s", logged.String())
		}
	})
	t.Run("a new install writes when nothing answers yet and logs it as unverified", func(t *testing.T) {
		f, cfg, logged := setup(t)
		ca := mintCA(t)
		f.bootCA = ca
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if !bytes.Equal(f.files[AgentClusterCAPath], ca) {
			t.Errorf("the copy is %q", f.files[AgentClusterCAPath])
		}
		if !strings.Contains(logged.String(), "unverified") {
			t.Errorf("log does not say the copy is unverified:\n%s", logged.String())
		}
	})
	t.Run("a new install writes nothing when the apiserver answers with another CA", func(t *testing.T) {
		f, cfg, _ := setup(t)
		f.bootCA = mintCA(t)
		f.apiServerDial = servingAs(t, mintFullCA(t))
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if got, ok := f.files[AgentClusterCAPath]; ok {
			t.Errorf("a copy was written: %q", got)
		}
	})
	t.Run("a CA that changes after the check writes nothing", func(t *testing.T) {
		f, cfg, _ := setup(t)
		ca := mintFullCA(t)
		f.putFileSwappedAfterRead(pkiPath(cfg), ca.CertPEM, mintCA(t))
		f.putLoaded(NetdLabel, ServerLabel)
		f.apiServerDial = servingAs(t, ca)
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if got, ok := f.files[AgentClusterCAPath]; ok {
			t.Errorf("a copy was written: %q", got)
		}
	})
	t.Run("the check asks the address the running apiserver binds", func(t *testing.T) {
		f, cfg, _ := setup(t)
		f.putFile(pkiPath(cfg), mintCA(t))
		configureServerArgs(f, cfg, "--mesh-ip", "100.64.0.1")
		cfg.MeshIP = "100.64.1.1"
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		dial := anchorCallAt(f, "DialAPIServer:")
		if dial < 0 || !strings.HasPrefix(f.calls[dial], "DialAPIServer:100.64.0.1:") {
			t.Errorf("first dial is at %d in %v", dial, f.calls)
		}
	})
	t.Run("a valid copy asks nothing", func(t *testing.T) {
		f, cfg, _ := setup(t)
		ca := mintCA(t)
		f.putFile(pkiPath(cfg), ca)
		f.putFile(AgentClusterCAPath, ca)
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if at := anchorCallAt(f, "DialAPIServer:"); at >= 0 {
			t.Errorf("dialed at call %d", at)
		}
	})
}

// TestFirstWorkerClusterCACopyIsChecked pins a worker's first copy, taken from its
// node credential, against a root-held token's CA hash when there is one.
func TestFirstWorkerClusterCACopyIsChecked(t *testing.T) {
	setup := func(t *testing.T, tokenPinsOtherCA bool, owner int) (*fakeSystem, Config, nodeCredentialFixture, *bytes.Buffer) {
		t.Helper()
		f := &fakeSystem{}
		cred := mintNodeCredential(t, Config{}.withDefaults().agentWorkDir())
		cred.seed(f)
		var logged bytes.Buffer
		cfg := agentCfg(t).withDefaults()
		cfg.TokenFile = ""
		cfg.Logger = slog.New(slog.NewTextHandler(&logged, nil))
		pinned := cred.caPEM
		if tokenPinsOtherCA {
			pinned = mintCA(t)
		}
		pin, err := certs.CertPin(pinned)
		if err != nil {
			t.Fatal(err)
		}
		f.putFile(cfg.agentTokenPath(), []byte(bootstrap.FormatToken(pin, "boot-abc", "secret")+"\n"))
		f.putOwned(cfg.agentTokenPath(), owner, 0, 0o600, EntryRegular)
		return f, cfg, cred, &logged
	}
	provision := func(t *testing.T, f *fakeSystem, cfg Config) {
		t.Helper()
		cfg.heldTokenPin = rootHeldTokenPin(f, cfg)
		if err := provisionAgentClusterCA(f, cfg, nil); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("a root-held token with the same hash passes", func(t *testing.T) {
		f, cfg, cred, logged := setup(t, false, 0)
		provision(t, f, cfg)
		if !bytes.Equal(f.files[AgentClusterCAPath], cred.caPEM) {
			t.Errorf("the copy is %q", f.files[AgentClusterCAPath])
		}
		if strings.Contains(logged.String(), "unverified") {
			t.Errorf("a checked copy was logged as unverified:\n%s", logged.String())
		}
	})
	t.Run("a root-held token with another hash writes nothing", func(t *testing.T) {
		f, cfg, _, logged := setup(t, true, 0)
		provision(t, f, cfg)
		if got, ok := f.files[AgentClusterCAPath]; ok {
			t.Errorf("a copy was written: %q", got)
		}
		for _, want := range []string{"level=WARN", "--token-file"} {
			if !strings.Contains(logged.String(), want) {
				t.Errorf("log lacks %q:\n%s", want, logged.String())
			}
		}
	})
	t.Run("a token the service user owns is not a check", func(t *testing.T) {
		f, cfg, cred, logged := setup(t, true, 271)
		provision(t, f, cfg)
		if !bytes.Equal(f.files[AgentClusterCAPath], cred.caPEM) {
			t.Errorf("the copy is %q", f.files[AgentClusterCAPath])
		}
		if !strings.Contains(logged.String(), "unverified") {
			t.Errorf("log does not say the copy is unverified:\n%s", logged.String())
		}
	})
	t.Run("a token others can write is not a check", func(t *testing.T) {
		f, cfg, cred, _ := setup(t, true, 0)
		f.putOwned(cfg.agentTokenPath(), 0, 0, 0o620, EntryRegular)
		provision(t, f, cfg)
		if !bytes.Equal(f.files[AgentClusterCAPath], cred.caPEM) {
			t.Errorf("the copy is %q", f.files[AgentClusterCAPath])
		}
	})
	t.Run("no token logs the copy as unverified", func(t *testing.T) {
		f, cfg, cred, logged := setup(t, false, 0)
		delete(f.files, cfg.agentTokenPath())
		provision(t, f, cfg)
		if !bytes.Equal(f.files[AgentClusterCAPath], cred.caPEM) {
			t.Errorf("the copy is %q", f.files[AgentClusterCAPath])
		}
		if !strings.Contains(logged.String(), "unverified") {
			t.Errorf("log does not say the copy is unverified:\n%s", logged.String())
		}
	})
	t.Run("an install reads the hash before the work dir changes hands", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f, cfg, _, _ := setup(t, true, 0)
		f.putOwned(cfg.agentWorkDir(), 0, 0, 0o700, EntryDir)
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if got, ok := f.files[AgentClusterCAPath]; ok {
			t.Errorf("a copy was written: %q", got)
		}
	})
}
