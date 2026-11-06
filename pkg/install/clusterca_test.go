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
	"log/slog"
	"slices"
	"strings"
	"testing"

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
		if err := provisionServerClusterCA(f, cfg, onDisk); err != nil {
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
		if err := provisionServerClusterCA(f, testConfig(t).withDefaults(), ca); err != nil {
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
		if err := provisionServerClusterCA(f, testConfig(t).withDefaults(), ca); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(f.files[AgentClusterCAPath], ca) {
			t.Error("an unusable copy was kept")
		}
	})
	t.Run("a control plane CA that is not a CA writes nothing", func(t *testing.T) {
		f := &fakeSystem{}
		if err := provisionServerClusterCA(f, testConfig(t).withDefaults(), []byte("not pem")); err != nil {
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
