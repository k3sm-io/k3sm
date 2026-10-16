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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
)

// netserveCSRPEM mints a P-256 key and returns a PEM CSR over it carrying
// subject and dnsNames.
func netserveCSRPEM(t *testing.T, subject pkix.Name, dnsNames []string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: subject, DNSNames: dnsNames}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// postNetserve POSTs a NetserveCertRequest and returns the status code and the
// decoded certificate on a 200.
func postNetserve(t *testing.T, client *http.Client, baseURL string, body bootstrap.NetserveCertRequest) (int, []byte) {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+bootstrap.NetserveCertPath, bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}
	var out bootstrap.NetserveCertResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp.StatusCode, []byte(out.CertPEM)
}

// TestNetserveCertVerbIsNodeBound is the security table for the netserve
// issuance verb: it signs a client certificate that reads every pod, Service and
// NetworkPolicy in the cluster, so who may obtain one for which node is the whole
// property. Each row pins one refusal; the success rows pin the subject.
func TestNetserveCertVerbIsNodeBound(t *testing.T) {
	csr := func(t *testing.T) string { return netserveCSRPEM(t, pkix.Name{CommonName: "whatever"}, nil) }

	t.Run("no client certificate is 401", func(t *testing.T) {
		f := newMeshEndpointFixture(t)
		code, cert := postNetserve(t, f.anonymousClient(t), f.ts.URL, bootstrap.NetserveCertRequest{NodeName: "worker-1", CSRPEM: csr(t)})
		if code != http.StatusUnauthorized || cert != nil {
			t.Errorf("status = %d, want 401: an anonymous caller must not obtain a netserve identity", code)
		}
	})

	t.Run("a node credential for a cannot obtain a certificate for b", func(t *testing.T) {
		f := newMeshEndpointFixture(t)
		client := f.nodeClient(t, f.signingCA, "system:node:worker-a", []string{"system:nodes"})
		code, cert := postNetserve(t, client, f.ts.URL, bootstrap.NetserveCertRequest{NodeName: "worker-b", CSRPEM: csr(t)})
		if code != http.StatusForbidden || cert != nil {
			t.Errorf("status = %d, want 403: the body's node name must be the certificate's", code)
		}
	})

	t.Run("a netserve certificate cannot obtain another one", func(t *testing.T) {
		f := newMeshEndpointFixture(t)
		s := certs.NetserveSubject("worker-1")
		client := f.nodeClient(t, f.signingCA, s.CommonName, s.Organization)
		code, cert := postNetserve(t, client, f.ts.URL, bootstrap.NetserveCertRequest{NodeName: "worker-1", CSRPEM: csr(t)})
		if code != http.StatusForbidden || cert != nil {
			t.Errorf("status = %d, want 403: only a system:nodes identity may ask", code)
		}
	})

	t.Run("a verified certificate that is not a node is 403", func(t *testing.T) {
		f := newMeshEndpointFixture(t)
		client := f.nodeClient(t, f.signingCA, certs.APIServerKubeletClientCN, nil)
		code, _ := postNetserve(t, client, f.ts.URL, bootstrap.NetserveCertRequest{NodeName: "worker-1", CSRPEM: csr(t)})
		if code != http.StatusForbidden {
			t.Errorf("status = %d, want 403", code)
		}
	})

	t.Run("a CSR asking for a SAN is refused", func(t *testing.T) {
		f := newMeshEndpointFixture(t)
		client := f.nodeClient(t, f.signingCA, "system:node:worker-1", []string{"system:nodes"})
		code, cert := postNetserve(t, client, f.ts.URL, bootstrap.NetserveCertRequest{
			NodeName: "worker-1",
			CSRPEM:   netserveCSRPEM(t, pkix.Name{CommonName: "x"}, []string{"kubernetes.default.svc"}),
		})
		if code != http.StatusForbidden || cert != nil {
			t.Errorf("status = %d, want 403: the signer must not vouch for a name it never checked", code)
		}
	})

	t.Run("the node's own certificate obtains exactly its netserve identity", func(t *testing.T) {
		f := newMeshEndpointFixture(t)
		client := f.nodeClient(t, f.signingCA, "system:node:worker-1", []string{"system:nodes"})
		// The CSR asks for system:masters; the subject is the server's, not the CSR's.
		code, certPEM := postNetserve(t, client, f.ts.URL, bootstrap.NetserveCertRequest{
			NodeName: "worker-1",
			CSRPEM:   netserveCSRPEM(t, pkix.Name{CommonName: "admin", Organization: []string{"system:masters"}}, nil),
		})
		if code != http.StatusOK {
			t.Fatalf("status = %d, want 200", code)
		}
		leaf := parseCertPEM(t, certPEM)
		if leaf.Subject.CommonName != "k3sm:netserve:worker-1" || !slices.Equal(leaf.Subject.Organization, []string{"k3sm:netservers"}) {
			t.Errorf("subject = CN %q O %v, want CN k3sm:netserve:worker-1 O [k3sm:netservers]", leaf.Subject.CommonName, leaf.Subject.Organization)
		}
		if len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.URIs)+len(leaf.EmailAddresses) != 0 {
			t.Errorf("the netserve certificate carries SANs: %v %v", leaf.DNSNames, leaf.IPAddresses)
		}
		if !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
			t.Errorf("EKU = %v, want client auth only", leaf.ExtKeyUsage)
		}
		if err := leaf.CheckSignatureFrom(f.signingCA.Cert); err != nil {
			t.Errorf("not signed by the signing CA: %v", err)
		}
		// The node certificate that obtained it expires in an hour; the netserve
		// certificate must not outlive it.
		if leaf.NotAfter.After(time.Now().Add(time.Hour + time.Minute)) {
			t.Errorf("NotAfter %s outlives the presenting node certificate (one hour)", leaf.NotAfter)
		}
	})

	t.Run("the production client helper fetches a matching pair", func(t *testing.T) {
		f := newMeshEndpointFixture(t)
		client := f.nodeClient(t, f.signingCA, "system:node:worker-1", []string{"system:nodes"})
		certPEM, keyPEM, err := bootstrap.FetchNetserveCert(context.Background(), client, f.ts.URL, "worker-1")
		if err != nil {
			t.Fatalf("FetchNetserveCert: %v", err)
		}
		if err := bootstrap.CheckNetserveKeyPair(certPEM, keyPEM, "worker-1"); err != nil {
			t.Fatalf("CheckNetserveKeyPair: %v", err)
		}
		if err := bootstrap.CheckNetserveKeyPair(certPEM, keyPEM, "worker-2"); err == nil {
			t.Error("a pair for worker-1 checked as worker-2's")
		}
	})
}

// notFoundTransport answers every request 404, in memory: a control plane that
// predates the netserve route.
type notFoundTransport struct{}

func (notFoundTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	http.NotFound(rec, r)
	return rec.Result(), nil
}

// TestFetchNetserveCertOnOlderServer pins the upgrade-order signal: a control
// plane that does not serve the route answers 404, which the client names as
// ErrNetserveCertUnsupported rather than a transient failure.
func TestFetchNetserveCertOnOlderServer(t *testing.T) {
	client := &http.Client{Transport: notFoundTransport{}}
	_, _, err := bootstrap.FetchNetserveCert(context.Background(), client, "https://192.0.2.1:9345", "worker-1")
	if !errors.Is(err, bootstrap.ErrNetserveCertUnsupported) {
		t.Fatalf("err = %v, want ErrNetserveCertUnsupported", err)
	}
}

// TestApproveAndSignNetserveCSR pins the signer: subject from the caller, no
// SAN accepted, empty node name refused.
func TestApproveAndSignNetserveCSR(t *testing.T) {
	ca, err := certs.NewCA("k3sm-signing-ca")
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	parse := func(p string) *x509.CertificateRequest {
		block, _ := pem.Decode([]byte(p))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Fatalf("parse CSR: %v", err)
		}
		return csr
	}
	if _, err := bootstrap.ApproveAndSignNetserveCSR(ca, parse(netserveCSRPEM(t, pkix.Name{}, []string{"a"})), "n", time.Hour); !errors.Is(err, bootstrap.ErrNetserveCSRSAN) {
		t.Errorf("SAN CSR err = %v, want ErrNetserveCSRSAN", err)
	}
	if _, err := bootstrap.ApproveAndSignNetserveCSR(ca, parse(netserveCSRPEM(t, pkix.Name{}, nil)), "", time.Hour); !errors.Is(err, bootstrap.ErrEmptyIdentity) {
		t.Errorf("empty node err = %v, want ErrEmptyIdentity", err)
	}
	certPEM, err := bootstrap.ApproveAndSignNetserveCSR(ca, parse(netserveCSRPEM(t, pkix.Name{CommonName: "system:node:n", Organization: []string{"system:nodes"}}, nil)), "n", time.Hour)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	leaf := parseCertPEM(t, certPEM)
	if node, ok := certs.NetserveNodeName(leaf); !ok || node != "n" {
		t.Errorf("NetserveNodeName = %q, %v; want n, true", node, ok)
	}
}
