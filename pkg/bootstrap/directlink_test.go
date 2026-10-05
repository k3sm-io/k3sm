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

package bootstrap_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"
	netv1alpha1 "k3sm.io/apis/net/v1alpha1"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
)

// recordingDirectLinks is a DirectLinkWriter that records every write and can
// refuse with a fixed error.
type recordingDirectLinks struct {
	mu     sync.Mutex
	writes []netv1alpha1.DirectLinkSpec
	err    error
}

func (r *recordingDirectLinks) ApplyDirectLink(_ context.Context, spec netv1alpha1.DirectLinkSpec) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	r.writes = append(r.writes, spec)
	return nil
}

func (r *recordingDirectLinks) GetDirectLink(_ context.Context, node string) (*netv1alpha1.DirectLink, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.writes) - 1; i >= 0; i-- {
		if r.writes[i].NodeName == node {
			dl := &netv1alpha1.DirectLink{Spec: r.writes[i]}
			dl.Name = node
			dl.Status.Ports = []netv1alpha1.DirectLinkPortStatus{{Iface: "en2", State: netv1alpha1.DirectLinkStateUp}}
			return dl, true, nil
		}
	}
	return nil, false, nil
}

func (r *recordingDirectLinks) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.writes)
}

type directLinkFixture struct {
	srv       *bootstrap.Server
	clusterCA *certs.CA
	signingCA *certs.CA
	writer    *recordingDirectLinks
	url       string
}

func newDirectLinkFixture(t *testing.T, writer *recordingDirectLinks) *directLinkFixture {
	t.Helper()
	clusterCA, _ := certs.NewCA("k3sm-cluster-ca")
	signingCA, _ := certs.NewCA("k3sm-signing-ca")
	cfg := bootstrap.ServerConfig{
		ClusterCA:     clusterCA,
		SigningCA:     signingCA,
		Tokens:        bootstrap.NewTokenStore(nil),
		NodePasswords: bootstrap.NewMemoryNodePasswords(),
		Enroller:      &fakeEnroller{podCIDR: "100.64.1.0/24", meshIP: "100.64.1.1"},
	}
	if writer != nil {
		cfg.DirectLinks = writer
	}
	srv, err := bootstrap.NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &directLinkFixture{srv: srv, clusterCA: clusterCA, signingCA: signingCA, writer: writer, url: "https://supervisor.invalid:9345"}
}

// handlerTransport serves requests from a handler in memory, with no socket: it
// stamps the TLS state a verified client certificate would leave (leaf nil: no
// certificate) and the connection's local address, which is everything the
// handlers read from the connection.
type handlerTransport struct {
	h     http.Handler
	leaf  *x509.Certificate
	local net.Addr
}

func (tr handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.RemoteAddr = "192.0.2.50:51234"
	r.TLS = &tls.ConnectionState{}
	if tr.leaf != nil {
		r.TLS.VerifiedChains = [][]*x509.Certificate{{tr.leaf}}
	}
	if tr.local != nil {
		r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, tr.local))
	}
	if r.Body == nil {
		r.Body = http.NoBody
	}
	w := httptest.NewRecorder()
	tr.h.ServeHTTP(w, r)
	return w.Result(), nil
}

// client returns an in-memory client presenting a node certificate with the
// given CN and organizations, as the listener would have verified it.
func (f *directLinkFixture) client(t *testing.T, cn string, org []string) *http.Client {
	t.Helper()
	certPEM, _, err := f.signingCA.IssueClient(cn, org, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: handlerTransport{h: f.srv.Handler(), leaf: leaf}}
}

func (f *directLinkFixture) anonymous() *http.Client {
	return &http.Client{Transport: handlerTransport{h: f.srv.Handler()}}
}

func directSpec(node string) netv1alpha1.DirectLinkSpec {
	return netv1alpha1.DirectLinkSpec{
		SchemaVersion: netv1alpha1.DirectLinkSchemaVersion,
		NodeName:      node,
		Medium:        netv1alpha1.MediumThunderbolt,
		Ports: []netv1alpha1.DirectLinkPort{{
			Iface: "en2", PortOrdinal: 0, DomainUUID: "uuid-a", PeerDomainUUID: "uuid-b",
			SpeedGbps: 40, LinkIP: "169.254.0.9", LinkUp: true,
		}},
	}
}

// TestDirectLinkVerbIdentityCheck pins the publish verb's authentication: only a
// node certificate naming the spec's own node writes, and nothing else reaches the
// writer.
func TestDirectLinkVerbIdentityCheck(t *testing.T) {
	writer := &recordingDirectLinks{}
	f := newDirectLinkFixture(t, writer)
	nodes := []string{"system:nodes"}
	rows := []struct {
		name    string
		client  func() *http.Client
		spec    netv1alpha1.DirectLinkSpec
		wantErr bool
	}{
		{"its own node writes", func() *http.Client { return f.client(t, "system:node:worker-1", nodes) }, directSpec("worker-1"), false},
		{"another node's spec is refused", func() *http.Client { return f.client(t, "system:node:worker-2", nodes) }, directSpec("worker-1"), true},
		{"a non-node identity is refused", func() *http.Client { return f.client(t, "system:node:worker-1", nil) }, directSpec("worker-1"), true},
		{"an anonymous caller is refused", f.anonymous, directSpec("worker-1"), true},
		{"an invalid spec is refused", func() *http.Client { return f.client(t, "system:node:worker-1", nodes) }, func() netv1alpha1.DirectLinkSpec {
			s := directSpec("worker-1")
			s.Ports[0].Iface = "bridge0"
			return s
		}(), true},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			before := writer.count()
			err := bootstrap.PublishDirectLink(context.Background(), tc.client(), f.url, tc.spec)
			if (err != nil) != tc.wantErr {
				t.Fatalf("PublishDirectLink err = %v, wantErr %v", err, tc.wantErr)
			}
			wrote := writer.count() - before
			if tc.wantErr && wrote != 0 {
				t.Fatalf("a refused publish reached the writer (%d writes)", wrote)
			}
			if !tc.wantErr && wrote != 1 {
				t.Fatalf("an accepted publish wrote %d times, want 1", wrote)
			}
		})
	}
}

// TestDirectLinkReadIsSelfScoped pins the read half: a node reads its own
// object (status included) and the node is the certificate's, never a parameter.
func TestDirectLinkReadIsSelfScoped(t *testing.T) {
	writer := &recordingDirectLinks{}
	f := newDirectLinkFixture(t, writer)
	nodes := []string{"system:nodes"}
	if _, ok, err := bootstrap.FetchDirectLink(context.Background(), f.client(t, "system:node:worker-1", nodes), f.url); err != nil || ok {
		t.Fatalf("read before any publish = ok %v err %v, want none", ok, err)
	}
	if err := bootstrap.PublishDirectLink(context.Background(), f.client(t, "system:node:worker-1", nodes), f.url, directSpec("worker-1")); err != nil {
		t.Fatal(err)
	}
	dl, ok, err := bootstrap.FetchDirectLink(context.Background(), f.client(t, "system:node:worker-1", nodes), f.url)
	if err != nil || !ok || dl.Name != "worker-1" || len(dl.Status.Ports) != 1 {
		t.Fatalf("own read = %+v ok %v err %v", dl, ok, err)
	}
	if _, ok, err := bootstrap.FetchDirectLink(context.Background(), f.client(t, "system:node:worker-2", nodes), f.url); err != nil || ok {
		t.Fatalf("another node's read = ok %v err %v, want its own (absent) object only", ok, err)
	}
}

// TestDirectLinkVerbNamesItsRefusals pins the client-side mapping: a domain-UUID
// collision is ErrDomainUUIDClaimed (409), a server without the verb is
// ErrServerTooOld (404), and a node the server does not know is ErrNoMeshPeer.
func TestDirectLinkVerbNamesItsRefusals(t *testing.T) {
	t.Run("collision", func(t *testing.T) {
		f := newDirectLinkFixture(t, &recordingDirectLinks{err: fmt.Errorf("%w: uuid-a is listed by worker-2", bootstrap.ErrDomainUUIDClaimed)})
		err := bootstrap.PublishDirectLink(context.Background(), f.client(t, "system:node:worker-1", []string{"system:nodes"}), f.url, directSpec("worker-1"))
		if !errors.Is(err, bootstrap.ErrDomainUUIDClaimed) {
			t.Fatalf("err = %v, want ErrDomainUUIDClaimed", err)
		}
	})
	t.Run("old server", func(t *testing.T) {
		f := newDirectLinkFixture(t, nil)
		err := bootstrap.PublishDirectLink(context.Background(), f.client(t, "system:node:worker-1", []string{"system:nodes"}), f.url, directSpec("worker-1"))
		if !errors.Is(err, bootstrap.ErrServerTooOld) {
			t.Fatalf("err = %v, want ErrServerTooOld", err)
		}
	})
	t.Run("no mesh peer", func(t *testing.T) {
		f := newDirectLinkFixture(t, &recordingDirectLinks{err: fmt.Errorf("%w: worker-1", bootstrap.ErrNoMeshPeer)})
		err := bootstrap.PublishDirectLink(context.Background(), f.client(t, "system:node:worker-1", []string{"system:nodes"}), f.url, directSpec("worker-1"))
		if !errors.Is(err, bootstrap.ErrNoMeshPeer) {
			t.Fatalf("err = %v, want ErrNoMeshPeer", err)
		}
	})
}

// TestOneShotTokenJoin drives a pairing token through the real join handler: the
// bound name joins once, another name is refused 403, and a second join with the
// same token is refused because the first one spent it. ServerLinkIP comes back
// from the connection's local address.
func TestOneShotTokenJoin(t *testing.T) {
	clusterCA, _ := certs.NewCA("k3sm-cluster-ca")
	signingCA, _ := certs.NewCA("k3sm-signing-ca")
	tokens := bootstrap.NewFileTokenStore(filepath.Join(t.TempDir(), bootstrap.BootstrapTokensFile), nil)
	user, secret, _, err := tokens.CreateBound(2*time.Minute, "new-mac", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	var completed, cabled []string
	srv, err := bootstrap.NewServer(bootstrap.ServerConfig{
		ClusterCA:     clusterCA,
		SigningCA:     signingCA,
		Tokens:        tokens,
		NodePasswords: bootstrap.NewMemoryNodePasswords(),
		Enroller:      &fakeEnroller{podCIDR: "100.64.1.0/24", meshIP: "100.64.1.1", peers: []netv1.MeshPeerSpec{}},
		LinkIPFor: func(a net.Addr) string {
			if strings.HasSuffix(a.String(), "%en2]:9345") {
				return "169.254.0.1"
			}
			return ""
		},
		OnOneShotJoin: func(node string) { completed = append(completed, node) },
		OnCableJoin: func(local net.Addr, podCIDR string, ord int32) {
			cabled = append(cabled, fmt.Sprintf("%s %s %d", local, podCIDR, ord))
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	link := &net.TCPAddr{IP: net.ParseIP("fe80::1"), Port: 9345, Zone: "en2"}
	client := &http.Client{Transport: handlerTransport{h: srv.Handler(), local: link}}
	token := bootstrap.FormatToken(clusterCA.PinHash(), user, secret)
	join := func(node string) (*bootstrap.JoinResult, error) {
		return bootstrap.Join(context.Background(), bootstrap.JoinOptions{
			Server: "https://[fe80::1%25en2]:9345", Token: token, NodeName: node, NodePassword: "pw-" + node,
			MeshEndpoint: "192.0.2.50:51820", HTTPClient: client,
			Cable: &bootstrap.JoinCable{PortOrdinal: 1},
		})
	}
	if _, err := join("someone-else"); err == nil || !contains(err.Error(), "403") {
		t.Fatalf("a join under another name = %v, want a 403 refusal", err)
	}
	res, err := join("new-mac")
	if err != nil {
		t.Fatalf("the bound name's join: %v", err)
	}
	if res.ServerLinkIP != "169.254.0.1" {
		t.Errorf("ServerLinkIP = %q, want the address LinkIPFor resolved", res.ServerLinkIP)
	}
	if len(completed) != 1 || completed[0] != "new-mac" {
		t.Errorf("OnOneShotJoin saw %v, want [new-mac]", completed)
	}
	if len(cabled) != 1 || cabled[0] != "[fe80::1%en2]:9345 100.64.1.0/24 1" {
		t.Errorf("OnCableJoin saw %v, want the join's local address, its pod /24 and port 1", cabled)
	}
	if _, err := join("new-mac"); err == nil || !contains(err.Error(), "401") {
		t.Fatalf("a second join with the spent token = %v, want a 401 refusal", err)
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

// TestJoinRefusesAOneShotTokenTheWindowDoesNotAdmit pins the join-time bound: a
// verified one-shot token whose window refuses is answered 403, nothing is
// counted, and the token is released, not spent.
func TestJoinRefusesAOneShotTokenTheWindowDoesNotAdmit(t *testing.T) {
	tokens := bootstrap.NewFileTokenStore(filepath.Join(t.TempDir(), bootstrap.BootstrapTokensFile), nil)
	window := time.Date(2026, 10, 5, 12, 10, 0, 0, time.UTC)
	user, secret, _, err := tokens.CreateBound(2*time.Minute, "new-mac", window)
	if err != nil {
		t.Fatal(err)
	}
	clusterCA, _ := certs.NewCA("k3sm-cluster-ca")
	signingCA, _ := certs.NewCA("k3sm-signing-ca")
	admit := errors.New("the pairing window does not admit this join (window-closed)")
	var counted int
	var gotWindow time.Time
	srv, err := bootstrap.NewServer(bootstrap.ServerConfig{
		ClusterCA: clusterCA, SigningCA: signingCA, Tokens: tokens,
		NodePasswords: bootstrap.NewMemoryNodePasswords(),
		Enroller:      &fakeEnroller{podCIDR: "100.64.1.0/24", meshIP: "100.64.1.1", peers: []netv1.MeshPeerSpec{}},
		OneShotAdmit:  func(w time.Time, node string) error { gotWindow = w; return admit },
		OnOneShotJoin: func(string) { counted++ },
	})
	if err != nil {
		t.Fatal(err)
	}
	token := bootstrap.FormatToken(clusterCA.PinHash(), user, secret)
	_, err = bootstrap.Join(context.Background(), bootstrap.JoinOptions{
		Server: "https://[fe80::1%25en2]:9345", Token: token, NodeName: "new-mac", NodePassword: "pw",
		MeshEndpoint: "192.0.2.50:51820",
		HTTPClient:   &http.Client{Transport: handlerTransport{h: srv.Handler(), local: &net.TCPAddr{IP: net.ParseIP("fe80::1"), Port: 9345, Zone: "en2"}}},
	})
	if err == nil || !contains(err.Error(), "403") {
		t.Fatalf("a join the window refuses = %v, want a 403", err)
	}
	if counted != 0 {
		t.Errorf("a refused join was counted %d time(s)", counted)
	}
	if !gotWindow.Equal(window) {
		t.Errorf("OneShotAdmit saw window %v, want the token's stamped generation %v", gotWindow, window)
	}
	if n, _ := tokens.OutstandingOneShot(window); n != 1 {
		t.Errorf("outstanding after a refused join = %d, want 1 (released, not spent)", n)
	}
}
