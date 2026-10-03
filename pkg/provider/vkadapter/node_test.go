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

package vkadapter

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	k8stesting "k8s.io/client-go/testing"
)

// pinnedVKVersion is the Virtual Kubelet release the node assembly in node.go
// reproduces nodeutil from, and that the SCM canary below was run against.
const pinnedVKVersion = "v1.14.0"

// isWrite reports whether a recorded action writes to the apiserver.
func isWrite(a k8stesting.Action) bool {
	switch a.GetVerb() {
	case "create", "update", "patch", "delete", "delete-collection":
		return true
	}
	return false
}

// eventFrom reports whether a recorded event create came from component.
func eventFrom(a k8stesting.Action, component string) bool {
	if a.GetVerb() != "create" || a.GetResource().Resource != "events" {
		return false
	}
	ev, ok := a.(k8stesting.CreateAction).GetObject().(*corev1.Event)
	return ok && ev.Source.Component == component
}

// nodeReadyTrue reports whether the tracker's Node has Ready=True.
func nodeReadyTrue(h *nodeHarness, name string) bool {
	n, err := h.cs.Tracker().Get(corev1.SchemeGroupVersion.WithResource("nodes"), "", name)
	if err != nil {
		return false
	}
	for _, c := range n.(*corev1.Node).Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// TestNodeRunLifecycleParity pins the parts of nodeutil's Node lifecycle the
// adapter reproduces: Ready with a nil and with a supplied NodeProvider, the
// naive provider's ready callback only for the nil one, the Lease, the
// pod-controller event source reaching the event sink, and an unwind in which
// Run returns only after both controllers are done and nothing writes after.
//
// Not t.Parallel: each case runs a whole node.
func TestNodeRunLifecycleParity(t *testing.T) {
	tests := []struct {
		name         string
		nodeProvider func(*corev1.Node) (NodeProvider, error)
		wantReadyCb  bool
	}{
		{name: "nil NodeProvider: the naive provider and its ready callback", wantReadyCb: true},
		{
			name: "supplied NodeProvider: no ready callback",
			nodeProvider: func(*corev1.Node) (NodeProvider, error) {
				return NewNaiveNodeProvider(), nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const name = "k3sm-lifecycle"
			h := newNodeHarness(t)
			p := newRecordingProvider()
			n, err := NewNode(name, NodeConfig{
				Client:         h.cs,
				Provider:       p,
				HTTPListenAddr: "127.0.0.1:0",
				NumWorkers:     1,
				ConfigureNode:  func(*corev1.Node) {},
				NodeProvider:   tt.nodeProvider,
			})
			if err != nil {
				t.Fatalf("NewNode: %v", err)
			}
			if got := n.readyCb != nil; got != tt.wantReadyCb {
				t.Fatalf("ready callback installed = %v, want %v", got, tt.wantReadyCb)
			}
			stop := runNode(t, n)
			waitClosed(t, h.leaseCreated, "the Lease create")

			if tt.wantReadyCb {
				deadline := time.Now().Add(stepTimeout)
				for !nodeReadyTrue(h, name) {
					if time.Now().After(deadline) {
						t.Fatal("the ready callback never marked the registered Node Ready")
					}
					time.Sleep(20 * time.Millisecond)
				}
			} else if nodeReadyTrue(h, name) {
				t.Error("a supplied NodeProvider owns Ready, but the Node was marked Ready by the adapter")
			}

			h.cyclePod(t, p, name)
			component := name + "/pod-controller"
			deadline := time.Now().Add(stepTimeout)
			for {
				found := false
				for _, a := range h.cs.Actions() {
					if eventFrom(a, component) {
						found = true
						break
					}
				}
				if found {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("no event from component %q reached the sink", component)
				}
				time.Sleep(20 * time.Millisecond)
			}

			if err := stop(); err != nil && !errors.Is(err, context.Canceled) {
				t.Fatalf("Run after cancel: %v", err)
			}
			for what, ch := range map[string]<-chan struct{}{"pod controller": n.pc.Done(), "node controller": n.nc.Done()} {
				select {
				case <-ch:
				default:
					t.Errorf("Run returned while the %s was still running", what)
				}
			}
			writes := func() int {
				c := 0
				for _, a := range h.cs.Actions() {
					if isWrite(a) {
						c++
					}
				}
				return c
			}
			before := writes()
			time.Sleep(300 * time.Millisecond)
			if after := writes(); after != before {
				t.Errorf("%d apiserver writes after Run returned", after-before)
			}
		})
	}
}

// countingGetter is an ObjectGetter that counts its calls.
type countingGetter struct{ calls atomic.Int64 }

func (g *countingGetter) Secret(_ context.Context, ns, name string) (*corev1.Secret, error) {
	g.calls.Add(1)
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}, nil
}

func (g *countingGetter) ConfigMap(_ context.Context, ns, name string) (*corev1.ConfigMap, error) {
	g.calls.Add(1)
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}, nil
}

// TestSCMAdaptersInformerNeverCalled is the canary on the Virtual Kubelet
// version: through a full pod create/delete cycle VK must never ask the node's
// Secret/ConfigMap/Service adapters for their informer, and never read a
// Secret or ConfigMap through them. A VK bump that starts doing either fails
// here, rather than reopening a cluster-wide watch or a read path nobody
// reviewed. The test refuses to run against any VK but the one it was
// written for.
func TestSCMAdaptersInformerNeverCalled(t *testing.T) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("no build info: cannot confirm the Virtual Kubelet version this canary was written against")
	}
	var vkVersion string
	for _, d := range bi.Deps {
		if d.Path == "github.com/virtual-kubelet/virtual-kubelet" {
			vkVersion = d.Version
			if d.Replace != nil {
				vkVersion = d.Replace.Version
			}
		}
	}
	if vkVersion != pinnedVKVersion {
		t.Fatalf("Virtual Kubelet is %q, this canary was written against %s: re-read node/podcontroller.go and node/pod.go for any use of the Secret/ConfigMap/Service informers or listers, then update pinnedVKVersion", vkVersion, pinnedVKVersion)
	}

	const name = "k3sm-canary"
	h := newNodeHarness(t)
	p := newRecordingProvider()
	g := &countingGetter{}
	n, err := NewNode(name, NodeConfig{
		Client:         h.cs,
		Provider:       p,
		HTTPListenAddr: "127.0.0.1:0",
		NumWorkers:     1,
		ConfigureNode:  func(*corev1.Node) {},
		Objects:        g,
	})
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	stop := runNode(t, n)
	h.cyclePod(t, p, name)
	_ = stop()

	if got := n.scm.informerCalls.Load(); got != 0 {
		t.Errorf("Virtual Kubelet called Informer() on the SCM adapters %d times", got)
	}
	if got := g.calls.Load(); got != 0 {
		t.Errorf("Virtual Kubelet read %d Secrets/ConfigMaps through the node's listers during a pod cycle", got)
	}

	s := n.scm
	t.Run("every List refuses", func(t *testing.T) {
		lists := map[string]func() error{
			"secrets": func() error { _, err := scopedSecretInformer{s}.Lister().List(labels.Everything()); return err },
			"secrets in ns": func() error {
				_, err := scopedSecretInformer{s}.Lister().Secrets("ns").List(labels.Everything())
				return err
			},
			"configmaps": func() error { _, err := scopedConfigMapInformer{s}.Lister().List(labels.Everything()); return err },
			"configmaps in ns": func() error {
				_, err := scopedConfigMapInformer{s}.Lister().ConfigMaps("ns").List(labels.Everything())
				return err
			},
			"services": func() error { _, err := scopedServiceInformer{s}.Lister().List(labels.Everything()); return err },
			"services in ns": func() error {
				_, err := scopedServiceInformer{s}.Lister().Services("ns").List(labels.Everything())
				return err
			},
			"service get by name": func() error { _, err := scopedServiceInformer{s}.Lister().Services("ns").Get("svc"); return err },
			"secret get, no seam": func() error {
				_, err := scopedSecretInformer{&scmAdapters{}}.Lister().Secrets("ns").Get("x")
				return err
			},
			"config get, no seam": func() error {
				_, err := scopedConfigMapInformer{&scmAdapters{}}.Lister().ConfigMaps("ns").Get("x")
				return err
			},
		}
		wantErr := map[string]error{
			"service get by name": errServiceReadUnsupported,
			"secret get, no seam": errNoObjectGetter,
			"config get, no seam": errNoObjectGetter,
		}
		for what, call := range lists {
			want := errListUnsupported
			if w, ok := wantErr[what]; ok {
				want = w
			}
			if err := call(); !errors.Is(err, want) {
				t.Errorf("%s: err = %v, want %v", what, err, want)
			}
		}
	})

	t.Run("a by-name Get goes to the ObjectGetter", func(t *testing.T) {
		sec, err := scopedSecretInformer{s}.Lister().Secrets("ns").Get("db")
		if err != nil || sec.Namespace != "ns" || sec.Name != "db" {
			t.Fatalf("secret Get = %v, %v; want ns/db", sec, err)
		}
		cm, err := scopedConfigMapInformer{s}.Lister().ConfigMaps("ns").Get("cfg")
		if err != nil || cm.Namespace != "ns" || cm.Name != "cfg" {
			t.Fatalf("configmap Get = %v, %v; want ns/cfg", cm, err)
		}
		if got := g.calls.Load(); got != 2 {
			t.Errorf("ObjectGetter calls = %d, want 2", got)
		}
	})

	t.Run("the counter counts: Informer() increments it", func(t *testing.T) {
		inf := scopedSecretInformer{s}.Informer()
		if got := s.informerCalls.Load(); got != 1 {
			t.Fatalf("informerCalls = %d after one Informer() call, want 1", got)
		}
		if inf.HasSynced() {
			t.Error("the placeholder informer reports synced, but it is never run")
		}
	})
}

// testPKI is a CA plus a server leaf (127.0.0.1) and a client leaf it signed.
type testPKI struct {
	pool   *x509.CertPool
	server tls.Certificate
	client tls.Certificate
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := func(serial int64, cn string, usage x509.ExtKeyUsage, ips []net.IP) tls.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
			IPAddresses:  ips,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return testPKI{
		pool:   pool,
		server: leaf(2, "node", x509.ExtKeyUsageServerAuth, []net.IP{net.ParseIP("127.0.0.1")}),
		client: leaf(3, "apiserver", x509.ExtKeyUsageClientAuth, nil),
	}
}

// TestNodeProviderRoutesRequireClientCert runs the assembled node with TLS and
// proves the kubelet HTTP API's posture end to end: a request without a client
// certificate never reaches a handler, and with one, AuthorizeHandler sees both
// an ExtraRoutes path (/containerLogs) and a Virtual Kubelet route (/exec)
// before either handler does.
func TestNodeProviderRoutesRequireClientCert(t *testing.T) {
	pki := newTestPKI(t)
	var (
		mu    sync.Mutex
		seen  []string
		allow atomic.Bool
	)
	authorize := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			seen = append(seen, r.URL.Path)
			mu.Unlock()
			if !allow.Load() {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	h := newNodeHarness(t)
	n, err := NewNode("k3sm-routes", NodeConfig{
		Client:         h.cs,
		Provider:       newRecordingProvider(),
		HTTPListenAddr: "127.0.0.1:0",
		NumWorkers:     1,
		ConfigureNode:  func(*corev1.Node) {},
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{pki.server},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    pki.pool,
			MinVersion:   tls.VersionTLS12,
		},
		AuthorizeHandler: authorize,
		ExtraRoutes: []Route{{Pattern: "/containerLogs/", Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "extra")
		})}},
	})
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	runNode(t, n)
	if n.boundAddr == nil {
		t.Fatal("the node started no kubelet HTTP listener with TLS configured")
	}
	base := "https://" + n.boundAddr.String()
	paths := []string{"/containerLogs/default/p/c", "/exec/default/p/c"}

	client := func(certs []tls.Certificate) *http.Client {
		return &http.Client{
			Timeout: stepTimeout,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{
				RootCAs:      pki.pool,
				Certificates: certs,
				MinVersion:   tls.VersionTLS12,
			}},
		}
	}

	t.Run("no client certificate is refused before any handler", func(t *testing.T) {
		c := client(nil)
		for _, p := range paths {
			resp, err := c.Get(base + p)
			if err == nil {
				_ = resp.Body.Close()
				t.Errorf("GET %s without a client certificate answered %d, want a TLS failure", p, resp.StatusCode)
			}
		}
		mu.Lock()
		defer mu.Unlock()
		if len(seen) != 0 {
			t.Errorf("AuthorizeHandler saw %v from a client with no certificate", seen)
		}
	})

	t.Run("with a certificate, AuthorizeHandler wraps ExtraRoutes and VK routes", func(t *testing.T) {
		c := client([]tls.Certificate{pki.client})
		for _, p := range paths {
			resp, err := c.Get(base + p)
			if err != nil {
				t.Fatalf("GET %s: %v", p, err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("GET %s = %d, want 403 from AuthorizeHandler", p, resp.StatusCode)
			}
		}
		mu.Lock()
		got := append([]string(nil), seen...)
		mu.Unlock()
		if len(got) != len(paths) || got[0] != paths[0] || got[1] != paths[1] {
			t.Errorf("AuthorizeHandler saw %v, want %v", got, paths)
		}

		allow.Store(true)
		resp, err := c.Get(base + paths[0])
		if err != nil {
			t.Fatalf("GET %s: %v", paths[0], err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(body) != "extra" {
			t.Errorf("authorized GET %s = %q, want the ExtraRoutes handler's %q", paths[0], body, "extra")
		}
	})
}
