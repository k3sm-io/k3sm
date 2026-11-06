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
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
)

// reservedNodeNames are the names no joining node may take.
var reservedNodeNames = []string{
	"kubernetes", "kubernetes.default", "kubernetes.default.svc",
	"kubernetes.default.svc.cluster.local", "kubernetes.default.svc.example.test", "localhost",
}

// TestValidateNodeNameRefusesReservedNames pins the fixed set, and that names which
// only resemble it stay usable.
func TestValidateNodeNameRefusesReservedNames(t *testing.T) {
	t.Parallel()
	for _, name := range reservedNodeNames {
		err := bootstrap.ValidateNodeName(name)
		if err == nil {
			t.Errorf("ValidateNodeName(%q) accepted a reserved name", name)
			continue
		}
		if !strings.Contains(err.Error(), "--node-name") {
			t.Errorf("ValidateNodeName(%q) = %q, want it to name the remedy", name, err)
		}
	}
	for _, name := range []string{"kubernetes-1", "my-kubernetes", "localhost-2", "kubernetes.example.test", "worker-1"} {
		if err := bootstrap.ValidateNodeName(name); err != nil {
			t.Errorf("ValidateNodeName(%q) = %v, want it accepted", name, err)
		}
	}
}

// TestCheckNodeCSRRefusesReservedDNSSANs pins that a reserved SAN is refused
// whatever node asks, the node named the same included.
func TestCheckNodeCSRRefusesReservedDNSSANs(t *testing.T) {
	t.Parallel()
	for _, san := range reservedNodeNames {
		for _, node := range []string{"worker-a", san} {
			csr := newTestCSR(t, pkix.Name{CommonName: node}, []string{san}, nil)
			if err := bootstrap.CheckNodeCSR(csr, node); !errors.Is(err, bootstrap.ErrCrossNodeSAN) {
				t.Errorf("CheckNodeCSR(SAN %q, node %q) = %v, want ErrCrossNodeSAN", san, node, err)
			}
		}
	}
}

// reservedJoinServer is a join server for the handler tests here, driven with no
// listener, whose --tls-san DNS names are configured.
func reservedJoinServer(t *testing.T, enroller bootstrap.Enroller, configured []string) (*bootstrap.Server, string) {
	t.Helper()
	clusterCA, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatalf("cluster CA: %v", err)
	}
	signingCA, err := certs.NewCA("k3sm-signing-ca")
	if err != nil {
		t.Fatalf("signing CA: %v", err)
	}
	tokens := bootstrap.NewTokenStore(nil)
	user, secret, _, err := tokens.Create(time.Hour)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	srv, err := bootstrap.NewServer(bootstrap.ServerConfig{
		ClusterCA:         clusterCA,
		SigningCA:         signingCA,
		Tokens:            tokens,
		NodePasswords:     bootstrap.NewMemoryNodePasswords(),
		Enroller:          enroller,
		SelfNodeName:      "k3sm-host",
		ReservedNodeNames: configured,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return srv, bootstrap.FormatToken(clusterCA.PinHash(), user, secret)
}

// postReservedJoin sends one join for name to srv's handler. servingSANs, when set,
// makes it carry a kubelet serving request listing them.
func postReservedJoin(t *testing.T, srv *bootstrap.Server, token, name string, clientSANs, servingSANs []string) (int, string) {
	t.Helper()
	req := bootstrap.JoinRequest{
		SchemaVersion: bootstrap.JoinSchemaVersion,
		Token:         token,
		NodeName:      name,
		NodePassword:  "node-password",
		ClientCSRPEM:  nodeCSRPEM(t, name, clientSANs, nil),
		Mesh: netv1.MeshEnrollRequest{
			NodeName:  name,
			PublicKey: "cHVibGljLWtleS1iYXNlNjQtMzJieXRlcy12YWx1ZT0=",
			Endpoint:  "192.0.2.66:51820",
		}.WithDefaults(),
	}
	if servingSANs != nil {
		req.ServingCSRPEM = nodeCSRPEM(t, name, servingSANs, nil)
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, bootstrap.JoinPath, bytes.NewReader(body)))
	return rec.Code, rec.Body.String()
}

// TestJoinRefusesAReservedNodeName pins the refusal a person sees, and that nothing
// was bound or allocated for the name first. A --tls-san DNS name is refused the same way.
func TestJoinRefusesAReservedNodeName(t *testing.T) {
	t.Parallel()
	const configured = "api.example.test"
	for _, name := range append(slices.Clone(reservedNodeNames), configured) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			enroller := newPeerStoreEnroller("100.64.3.0/24", "100.64.3.1")
			srv, token := reservedJoinServer(t, enroller, []string{configured})
			status, body := postReservedJoin(t, srv, token, name, nil, nil)
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d (%s), want 400", status, body)
			}
			if !strings.Contains(body, name) || !strings.Contains(body, "reserved") || !strings.Contains(body, "--node-name") {
				t.Errorf("refusal %q must name the node, say why, and name the remedy", body)
			}
			if n := enroller.calls(); n != 0 {
				t.Errorf("the enroller ran %d times for a refused name", n)
			}
		})
	}
}

// TestJoinOfAnOrdinaryNameIsUnaffected pins the shapes a join takes: this build's,
// and a released agent's, which lists localhost in its serving request. Both get a
// leaf naming only the node and its assigned address.
func TestJoinOfAnOrdinaryNameIsUnaffected(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		serving []string
	}{
		{"this build's serving request", []string{"worker-a"}},
		{"a released agent's serving request", []string{"worker-a", "localhost"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			enroller := newPeerStoreEnroller("100.64.3.0/24", "100.64.3.1")
			srv, token := reservedJoinServer(t, enroller, []string{"api.example.test"})
			status, body := postReservedJoin(t, srv, token, "worker-a", []string{"worker-a"}, tc.serving)
			if status != http.StatusOK {
				t.Fatalf("status = %d (%s), want 200", status, body)
			}
			var resp bootstrap.JoinResponse
			if err := json.Unmarshal([]byte(body), &resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			leaf := parseCertPEM(t, []byte(resp.KubeletServingCertPEM))
			if !slices.Equal(leaf.DNSNames, []string{"worker-a"}) {
				t.Errorf("DNS SANs = %v, want the node name alone", leaf.DNSNames)
			}
			if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("100.64.3.1")) {
				t.Errorf("IP SANs = %v, want the assigned address alone", leaf.IPAddresses)
			}
		})
	}
}

// TestJoinRefusesARequestListingAReservedSAN pins the SAN check for an ordinary node
// name, on each request and for a configured name. localhost is disregarded only in
// a serving request.
func TestJoinRefusesARequestListingAReservedSAN(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name            string
		client, serving []string
	}{
		{"a fixed name in the client request", []string{"kubernetes.default.svc"}, nil},
		{"localhost in the client request", []string{"localhost"}, nil},
		{"a fixed name in the serving request", nil, []string{"kubernetes"}},
		{"a configured name in the client request", []string{"api.example.test"}, nil},
		{"a configured name in the serving request", nil, []string{"API.example.test"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			enroller := newPeerStoreEnroller("100.64.3.0/24", "100.64.3.1")
			srv, token := reservedJoinServer(t, enroller, []string{"api.example.test"})
			status, body := postReservedJoin(t, srv, token, "worker-a", tc.client, tc.serving)
			if status != http.StatusForbidden {
				t.Fatalf("status = %d (%s), want 403", status, body)
			}
			if n := enroller.calls(); n != 0 {
				t.Errorf("the enroller ran %d times for a refused request", n)
			}
		})
	}
}

// TestJoinClientRefusesAReservedNameLocally pins that the agent fails with the same
// message before it sends anything.
func TestJoinClientRefusesAReservedNameLocally(t *testing.T) {
	t.Parallel()
	ca, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatal(err)
	}
	token := bootstrap.FormatToken(ca.PinHash(), "abcdef", "0123456789abcdef")
	_, err = bootstrap.Join(t.Context(), bootstrap.JoinOptions{
		Server:     "https://192.0.2.1:9345",
		Token:      token,
		NodeName:   "localhost",
		HTTPClient: &http.Client{Transport: refuseTransport{t}},
	})
	if !errors.Is(err, bootstrap.ErrReservedNodeName) {
		t.Fatalf("Join = %v, want ErrReservedNodeName", err)
	}
}

// refuseTransport fails the test if a request is sent.
type refuseTransport struct{ t *testing.T }

func (r refuseTransport) RoundTrip(*http.Request) (*http.Response, error) {
	r.t.Error("a request was sent")
	return nil, errors.New("no request expected")
}

// TestKubeletServingLeafNamesOnlyTheNode pins what an issued kubelet leaf carries:
// the node's name and its assigned address, whatever the request listed.
func TestKubeletServingLeafNamesOnlyTheNode(t *testing.T) {
	t.Parallel()
	clusterCA, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatal(err)
	}
	id := bootstrap.NodeIdentity{NodeName: "worker-a", InternalIP: "100.64.3.1"}
	csr := newTestCSR(t, pkix.Name{CommonName: "worker-a"}, []string{"worker-a"}, nil)
	certPEM, err := bootstrap.ApproveAndSignKubeletServing(clusterCA, csr, id, time.Hour)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	leaf := parseCertPEM(t, certPEM)
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "worker-a" {
		t.Errorf("DNS SANs = %v, want the node name alone", leaf.DNSNames)
	}
	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("100.64.3.1")) {
		t.Errorf("IP SANs = %v, want the assigned address alone", leaf.IPAddresses)
	}
}

// TestApproveRefusesAReservedIdentity pins the signers' own check, independent of
// the handler's.
func TestApproveRefusesAReservedIdentity(t *testing.T) {
	t.Parallel()
	clusterCA, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		id   bootstrap.NodeIdentity
	}{
		{"a reserved node name", bootstrap.NodeIdentity{NodeName: "kubernetes", InternalIP: "100.64.3.1"}},
		{"localhost", bootstrap.NodeIdentity{NodeName: "localhost", InternalIP: "100.64.3.1"}},
		{"the first Service address", bootstrap.NodeIdentity{NodeName: "worker-a", InternalIP: "10.43.0.1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			csr := newTestCSR(t, pkix.Name{}, nil, nil)
			if _, err := bootstrap.ApproveAndSignKubeletServing(clusterCA, csr, tc.id, time.Hour); err == nil {
				t.Error("the serving signer accepted it")
			}
			if _, err := bootstrap.ApproveAndSignNodeCSR(clusterCA, csr, tc.id, time.Hour); err == nil {
				t.Error("the client signer accepted it")
			}
		})
	}
}
