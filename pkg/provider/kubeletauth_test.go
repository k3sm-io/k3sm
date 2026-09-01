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

package provider

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/provider/vkadapter"
)

// execPath is the shape of the VK kubelet endpoint's exec route
// (/exec/<namespace>/<pod>/<container>) — the highest-value route on the surface,
// since reaching it is an interactive process inside a pod.
const execPath = "/exec/default/web/app"

// kubeletTestPKI is a throwaway cluster PKI: the client-identity (signing) CA that
// a node's kubelet endpoint anchors on, plus a foreign CA standing in for anything
// the cluster did not issue.
type kubeletTestPKI struct {
	signing *certs.CA
	foreign *certs.CA
}

func newKubeletTestPKI(t *testing.T) kubeletTestPKI {
	t.Helper()
	signing, err := certs.NewCA("k3sm-signing-ca")
	if err != nil {
		t.Fatalf("signing CA: %v", err)
	}
	foreign, err := certs.NewCA("someone-elses-ca")
	if err != nil {
		t.Fatalf("foreign CA: %v", err)
	}
	return kubeletTestPKI{signing: signing, foreign: foreign}
}

// clientCert mints a client keypair with CommonName cn and groups org from ca and
// returns it as a tls.Certificate ready to present.
func clientCert(t *testing.T, ca *certs.CA, cn string, org []string) tls.Certificate {
	t.Helper()
	certPEM, keyPEM, err := ca.IssueClient(cn, org, time.Hour)
	if err != nil {
		t.Fatalf("issue client cert CN=%s: %v", cn, err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("assemble client keypair CN=%s: %v", cn, err)
	}
	return pair
}

// TestKubeletEndpointRequiresClientCert is the B176 gate: the VK node's kubelet
// HTTP endpoint (:10250 — logs, exec, attach, port-forward, stats) is served over
// mutual TLS anchored on the cluster's client-identity CA, and admits exactly ONE
// identity — the CN the PKI mints for the apiserver's kubelet client.
//
// It runs against a real in-process TLS listener configured by the SAME production
// code path the node uses (NewKubeletEndpointAuth → ServingTLS → Handler), not a
// restatement of it, so a regression in either half is caught here. Before B176
// this endpoint ran nodeutil.NoAuth() over a tls.NoClientCert listener on a
// wildcard bind: every subtest below except the apiserver one would have served
// exec to its caller.
//
// The exec handler records whether it ran. Asserting a 401/403 status is not
// enough on this surface — the load-bearing claim is that a rejected caller never
// reaches the route at all.
func TestKubeletEndpointRequiresClientCert(t *testing.T) {
	pki := newKubeletTestPKI(t)

	auth, err := NewKubeletEndpointAuth(pki.signing.CertPEM, nil)
	if err != nil {
		t.Fatalf("NewKubeletEndpointAuth: %v", err)
	}

	var execServed atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc(execPath, func(w http.ResponseWriter, r *http.Request) {
		execServed.Add(1)
		_, _ = io.WriteString(w, "exec stream")
	})

	// The serving half is built exactly as cmd/k3sm's kubeletServingTLS builds it:
	// a serving keypair, then auth.ServingTLS stamping the client requirement on.
	serving, err := certs.SelfSignedServing([]string{"k3sm-node", "localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("serving cert: %v", err)
	}
	srvTLS := auth.ServingTLS(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serving},
	})
	if srvTLS.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("ServingTLS ClientAuth = %v, want tls.RequireAndVerifyClientCert", srvTLS.ClientAuth)
	}

	srv := httptest.NewUnstartedServer(auth.Handler(mux))
	srv.TLS = srvTLS
	srv.StartTLS()
	defer srv.Close()

	// The client trusts the node's serving cert out of band (the apiserver does this
	// via --kubelet-certificate-authority, or skips it single-node); what is under
	// test is the OTHER direction.
	servingLeaf, err := x509.ParseCertificate(serving.Certificate[0])
	if err != nil {
		t.Fatalf("parse serving leaf: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(servingLeaf)

	// get issues one request to the exec route presenting present (nil = none).
	//
	// The certificate is supplied through GetClientCertificate, NOT Certificates,
	// and that is load-bearing: Go's TLS client filters Certificates against the
	// acceptable-CA hints in the server's CertificateRequest, so a cert from a
	// foreign CA would simply not be SENT and the subtest would pass on the client's
	// politeness rather than on the server's refusal. GetClientCertificate is
	// consulted unconditionally, so the foreign cert really is presented and really
	// is rejected by the listener.
	get := func(t *testing.T, present *tls.Certificate) (int, error) {
		t.Helper()
		cfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
			ServerName: "localhost",
		}
		if present != nil {
			cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return present, nil
			}
		}
		c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
		defer c.CloseIdleConnections()
		resp, err := c.Get(srv.URL + execPath)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode, nil
	}

	tests := []struct {
		name string
		// present is the client certificate this caller offers (nil = none).
		present func(t *testing.T) *tls.Certificate
		// wantServed is whether the exec route may run for this caller.
		wantServed bool
		// wantStatus is the HTTP status when the request survives the handshake;
		// 0 means the handshake itself must fail.
		wantStatus int
	}{
		{
			name:       "no client certificate is refused at the handshake",
			present:    func(*testing.T) *tls.Certificate { return nil },
			wantServed: false,
			wantStatus: 0,
		},
		{
			name: "a certificate from a different CA is refused at the handshake",
			present: func(t *testing.T) *tls.Certificate {
				// The right CommonName, the wrong issuer: an attacker who knows the
				// accepted identity but cannot sign for the cluster.
				c := clientCert(t, pki.foreign, certs.APIServerKubeletClientCN, nil)
				return &c
			},
			wantServed: false,
			wantStatus: 0,
		},
		{
			name: "a valid cluster identity that is not the apiserver is refused by the authorizer",
			present: func(t *testing.T) *tls.Certificate {
				// A joined worker's own credential: issued by the SAME signing CA, so it
				// completes the handshake. Every node in the cluster holds one of these,
				// which is precisely why chain validity cannot be the whole predicate.
				c := clientCert(t, pki.signing, "system:node:worker-2", []string{"system:nodes"})
				return &c
			},
			wantServed: false,
			wantStatus: http.StatusForbidden,
		},
		{
			name: "the cluster admin identity is refused by the authorizer",
			present: func(t *testing.T) *tls.Certificate {
				// system:masters is cluster-admin AT THE APISERVER; the kubelet endpoint
				// admits one identity and grants nothing by group.
				c := clientCert(t, pki.signing, "k3sm-admin", []string{"system:masters"})
				return &c
			},
			wantServed: false,
			wantStatus: http.StatusForbidden,
		},
		{
			name: "the apiserver's kubelet-client identity is served",
			present: func(t *testing.T) *tls.Certificate {
				c := clientCert(t, pki.signing, certs.APIServerKubeletClientCN, nil)
				return &c
			},
			wantServed: true,
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := execServed.Load()
			status, err := get(t, tt.present(t))
			switch {
			case tt.wantStatus == 0:
				if err == nil {
					t.Errorf("request succeeded with status %d, want a TLS handshake failure", status)
				}
			case err != nil:
				t.Fatalf("request failed: %v (want status %d)", err, tt.wantStatus)
			case status != tt.wantStatus:
				t.Errorf("status = %d, want %d", status, tt.wantStatus)
			}
			served := execServed.Load() != before
			if served != tt.wantServed {
				t.Errorf("exec route served = %v, want %v", served, tt.wantServed)
			}
		})
	}
}

// TestKubeletEndpointAuthFailsClosed pins the constructor and predicate edges the
// live listener cannot exercise: a node with no client-identity CA must refuse to
// start rather than serve the endpoint open, and the authorization predicate must
// deny anything whose peer chain the TLS stack did not actually verify.
func TestKubeletEndpointAuthFailsClosed(t *testing.T) {
	t.Run("an absent or unparseable CA is a hard error", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			pem  []byte
		}{
			{"nil", nil},
			{"empty", []byte{}},
			{"not PEM", []byte("this is not a certificate")},
			{"a PEM block that is not a certificate", []byte("-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n")},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if _, err := NewKubeletEndpointAuth(tc.pem, nil); !errors.Is(err, ErrNoKubeletClientCA) {
					t.Errorf("NewKubeletEndpointAuth(%s) error = %v, want ErrNoKubeletClientCA", tc.name, err)
				}
			})
		}
	})

	t.Run("an unverified peer chain is never authorized", func(t *testing.T) {
		ca, err := certs.NewCA("k3sm-signing-ca")
		if err != nil {
			t.Fatalf("NewCA: %v", err)
		}
		auth, err := NewKubeletEndpointAuth(ca.CertPEM, nil)
		if err != nil {
			t.Fatalf("NewKubeletEndpointAuth: %v", err)
		}
		certPEM, _, err := ca.IssueClient(certs.APIServerKubeletClientCN, nil, time.Hour)
		if err != nil {
			t.Fatalf("IssueClient: %v", err)
		}
		leaf := parseLeafPEM(t, certPEM)

		// PeerCertificates without VerifiedChains is what a tls.RequestClientCert (or
		// NoClientCert) listener yields: a certificate was presented but nothing
		// checked it. Reading the wrong field here would authorize a self-signed
		// impostor carrying the right CommonName.
		if auth.AuthorizedIdentity(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}) {
			t.Error("AuthorizedIdentity accepted a peer certificate the TLS stack never verified")
		}
		if auth.AuthorizedIdentity(nil) {
			t.Error("AuthorizedIdentity accepted a nil connection state")
		}
		if auth.AuthorizedIdentity(&tls.ConnectionState{}) {
			t.Error("AuthorizedIdentity accepted an empty connection state")
		}
		if !auth.AuthorizedIdentity(&tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}) {
			t.Errorf("AuthorizedIdentity rejected the verified apiserver identity CN=%s", certs.APIServerKubeletClientCN)
		}
	})
}

// TestProviderRoutesRefuseUnauthenticatedWiring pins the structural half of the
// B176 fix: vkadapter.NewNode REFUSES to build a node whose kubelet provider
// routes would be served without mutual TLS plus an authorizer. It is the mutation
// guard for the exact pre-B176 shape — a serving-only tls.Config with an
// always-allow handler — which was previously a valid NodeConfig.
func TestProviderRoutesRefuseUnauthenticatedWiring(t *testing.T) {
	ca, err := certs.NewCA("k3sm-signing-ca")
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM) {
		t.Fatal("AppendCertsFromPEM: no certificate parsed")
	}
	pass := func(h http.Handler) http.Handler { return h }

	tests := []struct {
		name string
		cfg  vkadapter.NodeConfig
		// wantErrContains names the specific reason, so a case cannot pass because
		// NewNode happened to fail for some unrelated reason.
		wantErrContains string
	}{
		{
			name:            "the pre-B176 shape: serving TLS, no client auth, no authorizer",
			cfg:             vkadapter.NodeConfig{TLSConfig: &tls.Config{}},
			wantErrContains: "AuthorizeHandler",
		},
		{
			name:            "client auth required but no authorizer",
			cfg:             vkadapter.NodeConfig{TLSConfig: &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}},
			wantErrContains: "AuthorizeHandler",
		},
		{
			name:            "an authorizer over a listener that only requests a cert",
			cfg:             vkadapter.NodeConfig{TLSConfig: &tls.Config{ClientAuth: tls.RequestClientCert, ClientCAs: pool}, AuthorizeHandler: pass},
			wantErrContains: "RequireAndVerifyClientCert",
		},
		{
			name:            "client auth required against a nil CA pool",
			cfg:             vkadapter.NodeConfig{TLSConfig: &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert}, AuthorizeHandler: pass},
			wantErrContains: "ClientCAs",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			cfg.ConfigureNode = func(*corev1.Node) {}
			_, err := vkadapter.NewNode("k3sm-node", cfg)
			if err == nil {
				t.Fatalf("NewNode accepted a config that would serve the provider routes unauthenticated")
			}
			if !strings.Contains(err.Error(), tt.wantErrContains) {
				t.Errorf("NewNode error = %q, want it to name %q", err, tt.wantErrContains)
			}
		})
	}
}

// parseLeafPEM decodes a single PEM-encoded certificate.
func parseLeafPEM(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("parse leaf: no PEM block")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf
}
