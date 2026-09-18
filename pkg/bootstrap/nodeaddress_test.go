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
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
)

// joinServerRig is a live bootstrap server over httptest — the REAL handler, real
// CAs, a real token store and a caller-supplied enroller — plus the raw HTTP means
// to POST a hand-built JoinRequest at it. The hand-built request is what makes a
// claim about ORDER observable: only a request whose CSR is deliberately bad can
// tell "refused before the enroll" from "refused after it".
//
// It is the one join-server fixture in this package; a test that needs different
// allocator behaviour supplies a different enroller, never a second harness.
type joinServerRig struct {
	ts       *httptest.Server
	token    string
	assigned string
}

// newNodeAddressRig is the fixed-assignment rig the address gates use: every node
// is assigned assignedMeshIP.
func newNodeAddressRig(t *testing.T, assignedMeshIP string) *joinServerRig {
	t.Helper()
	rig := newJoinServerRig(t, &fakeEnroller{podCIDR: "100.64.1.0/24", meshIP: assignedMeshIP})
	rig.assigned = assignedMeshIP
	return rig
}

// newJoinServerRig stands the bootstrap server up over enroller.
func newJoinServerRig(t *testing.T, enroller bootstrap.Enroller) *joinServerRig {
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
		ClusterCA:     clusterCA,
		SigningCA:     signingCA,
		Tokens:        tokens,
		NodePasswords: bootstrap.NewMemoryNodePasswords(),
		Enroller:      enroller,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &joinServerRig{ts: ts, token: bootstrap.FormatToken(clusterCA.PinHash(), user, secret)}
}

// post sends req and returns the status and the trimmed body.
func (r *joinServerRig) post(t *testing.T, req bootstrap.JoinRequest) (int, string) {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal join request: %v", err)
	}
	resp, err := r.ts.Client().Post(r.ts.URL+bootstrap.JoinPath, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post join: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		t.Fatalf("read join response: %v", err)
	}
	return resp.StatusCode, strings.TrimSpace(string(raw))
}

// TestJoinIssuesForTheAssignedNodeAddress is the server half of B338: the
// InternalIP an issued node certificate names is the mesh enroll's ASSIGNMENT,
// unconditionally, and the request's nodeIP is only an equality gate on it.
//
// Fails before: handleJoin built its NodeIdentity from req.NodeIP, so the
// certificates named whatever the client asked for while the enroller assigned
// the address independently.
func TestJoinIssuesForTheAssignedNodeAddress(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("no nodeIP: the certificates and the response carry the assignment", func(t *testing.T) {
		t.Parallel()
		rig := newNodeAddressRig(t, "100.64.1.1")
		res, err := bootstrap.Join(ctx, bootstrap.JoinOptions{
			Server: rig.ts.URL, Token: rig.token, NodeName: "worker-1",
			NodePassword: "pw", MeshEndpoint: "192.168.1.50:51820", HTTPClient: rig.ts.Client(),
		})
		if err != nil {
			t.Fatalf("a join carrying no nodeIP must be served: %v", err)
		}
		if res.NodeIP != rig.assigned {
			t.Errorf("response nodeIP = %q, want the assigned %q", res.NodeIP, rig.assigned)
		}
		for _, tc := range []struct {
			what string
			pem  []byte
		}{
			{"client", res.NodeClientCertPEM},
			{"kubelet serving", res.KubeletServingCertPEM},
		} {
			cert := parseCertPEM(t, tc.pem)
			if len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != rig.assigned {
				t.Errorf("%s cert IP SANs = %v, want exactly [%s]", tc.what, cert.IPAddresses, rig.assigned)
			}
		}
	})

	t.Run("a mismatching nodeIP is refused before any certificate is issued", func(t *testing.T) {
		t.Parallel()
		rig := newNodeAddressRig(t, "100.64.1.1")
		status, reason := rig.post(t, bootstrap.JoinRequest{
			SchemaVersion: bootstrap.JoinSchemaVersion,
			Token:         rig.token,
			NodeName:      "worker-1",
			NodeIP:        "100.64.7.7",
			NodePassword:  "pw",
			// A CSR the server would happily sign, so the only thing that can refuse
			// this request is the address gate: if it ever stopped firing, the row
			// comes back 200 with a certificate naming an address the allocator gave
			// no one.
			ClientCSRPEM: nodeCSRPEM(t, "worker-1", []string{"worker-1"}, []net.IP{net.ParseIP("100.64.7.7")}),
			Mesh:         netv1.MeshEnrollRequest{NodeName: "worker-1"}.WithDefaults(),
		})
		if status != http.StatusConflict {
			t.Fatalf("status = %d (%s), want 409: an address the control plane did not assign is a conflict, decided before the CSR", status, reason)
		}
		for _, want := range []string{"100.64.7.7", "100.64.1.1", "--node-ip"} {
			if !strings.Contains(reason, want) {
				t.Errorf("refusal %q must name %q", reason, want)
			}
		}
		if strings.Contains(strings.ToUpper(reason), "CSR") {
			t.Errorf("refusal %q names the CSR, so the address gate is not what refused this", reason)
		}
		if strings.Contains(reason, "CERTIFICATE") {
			t.Errorf("refusal %q carries a certificate", reason)
		}
		// Nothing about the allocator beyond the two addresses in play.
		if strings.Contains(reason, "100.64.1.0/24") || strings.Contains(strings.ToLower(reason), "peer") {
			t.Errorf("refusal %q leaks allocator state beyond the requested and assigned addresses", reason)
		}
	})

	t.Run("a matching nodeIP is served", func(t *testing.T) {
		t.Parallel()
		rig := newNodeAddressRig(t, "100.64.1.1")
		res, err := bootstrap.Join(ctx, bootstrap.JoinOptions{
			Server: rig.ts.URL, Token: rig.token, NodeName: "worker-1", NodeIP: "100.64.1.1",
			NodePassword: "pw", MeshEndpoint: "192.168.1.50:51820", HTTPClient: rig.ts.Client(),
		})
		if err != nil {
			t.Fatalf("a join asserting the assigned address must be served: %v", err)
		}
		cert := parseCertPEM(t, res.NodeClientCertPEM)
		if len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "100.64.1.1" {
			t.Errorf("client cert IP SANs = %v, want exactly [100.64.1.1]", cert.IPAddresses)
		}
	})

	t.Run("an enroll that assigns no address issues nothing", func(t *testing.T) {
		t.Parallel()
		// Fail CLOSED. With no assignment there is no address to name, and the
		// alternative (fall back to what the client asked for) is the defect.
		rig := newNodeAddressRig(t, "")
		status, reason := rig.post(t, bootstrap.JoinRequest{
			SchemaVersion: bootstrap.JoinSchemaVersion,
			Token:         rig.token,
			NodeName:      "worker-1",
			NodeIP:        "100.64.7.7",
			NodePassword:  "pw",
			// Well-formed, so the request reaches the enroll that has nothing to
			// assign — which is the arm under test.
			ClientCSRPEM: nodeCSRPEM(t, "worker-1", []string{"worker-1"}, nil),
			Mesh:         netv1.MeshEnrollRequest{NodeName: "worker-1"}.WithDefaults(),
		})
		if status != http.StatusInternalServerError {
			t.Fatalf("status = %d (%s), want 500: an enroll with no assigned address cannot yield a certificate", status, reason)
		}
	})

	t.Run("a node name is still required", func(t *testing.T) {
		t.Parallel()
		rig := newNodeAddressRig(t, "100.64.1.1")
		status, reason := rig.post(t, bootstrap.JoinRequest{
			SchemaVersion: bootstrap.JoinSchemaVersion,
			Token:         rig.token,
			NodePassword:  "pw",
		})
		if status != http.StatusBadRequest || !strings.Contains(reason, "nodeName") {
			t.Errorf("status/%d reason %q, want 400 naming nodeName", status, reason)
		}
	})
}
