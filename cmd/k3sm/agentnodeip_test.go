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

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/hostnet"
)

// assigningEnroller is a mesh allocator with the ONE property this gate is about:
// the address a node gets is decided HERE, by node name, and no join request can
// influence it. It mirrors the shipped meshEnroller's two rules (reuse the CIDR
// already held under this node name, else take the lowest free index above the
// control plane's 0) at a scale a unit test can assert on.
//
// Locking discipline: mu guards assigned; httptest serves each request on its own
// goroutine.
type assigningEnroller struct {
	mu       sync.Mutex
	assigned map[string]string // nodeName -> podCIDR index
	next     int
}

func (e *assigningEnroller) Enroll(_ context.Context, nodeName string, _ netv1.MeshEnrollRequest) (netv1.MeshEnrollResponse, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.assigned == nil {
		e.assigned = map[string]string{}
		e.next = 1
	}
	cidr, ok := e.assigned[nodeName]
	if !ok {
		cidr = fmt.Sprintf("100.64.%d.0/24", e.next)
		e.assigned[nodeName] = cidr
		e.next++
	}
	return netv1.MeshEnrollResponse{
		NodeName: nodeName,
		PodCIDR:  cidr,
		MeshIP:   strings.TrimSuffix(cidr, ".0/24") + ".1",
	}.WithDefaults(), nil
}

func (e *assigningEnroller) RefreshEndpoint(context.Context, string, string) error { return nil }
func (e *assigningEnroller) Deregister(context.Context, string) error              { return nil }

// joinRig is a live bootstrap server over httptest: the REAL pkg/bootstrap
// handler, real CAs, a real token store, and the assigning enroller above. It is
// the whole server half of the join, so what this gate asserts about issuance is
// what the supervisor actually does.
type joinRig struct {
	ts        *httptest.Server
	clusterCA *certs.CA
	signingCA *certs.CA
	token     string
}

func newJoinRig(t *testing.T) *joinRig {
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
		Enroller:      &assigningEnroller{},
	})
	if err != nil {
		t.Fatalf("new bootstrap server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &joinRig{ts: ts, clusterCA: clusterCA, signingCA: signingCA,
		token: bootstrap.FormatToken(clusterCA.PinHash(), user, secret)}
}

// join runs the agent-side join client against the rig, asserting nothing.
func (r *joinRig) join(ctx context.Context, nodeName, nodeIP string) (*bootstrap.JoinResult, error) {
	return bootstrap.Join(ctx, bootstrap.JoinOptions{
		Server:       r.ts.URL,
		Token:        r.token,
		NodeName:     nodeName,
		NodeIP:       nodeIP,
		NodePassword: "node-secret-" + nodeName,
		MeshEndpoint: "192.168.1.50:51820",
		HTTPClient:   r.ts.Client(), // the live pin is pkg/bootstrap's own test
	})
}

// certIPSANs parses a PEM certificate and returns its IP SANs as strings.
func certIPSANs(t *testing.T, certPEM []byte) []string {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("no CERTIFICATE PEM block in %q", certPEM)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	out := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

// TestAgentJoinDerivesTheNodeIPFromTheAssignment is the B338 gate: the address a
// worker holds inside the cluster is the CONTROL PLANE'S to assign, and every
// consumer of it — the issued certificates, the Node object's InternalIP, the
// node's own datapath — takes it from that one assignment.
//
// Fails before: the join bound the operator's `--node-ip` verbatim into both
// certificates (server.go's NodeIdentity was built from req.NodeIP) while the
// enroller assigned the mesh address independently, so a join naming
// 100.64.9.9 against a node assigned 100.64.1.1 was issued certificates for
// 100.64.9.9 — an address the node never holds, and one the allocator may have
// given some other node. An empty --node-ip was refused outright, so an operator
// had no way to avoid guessing.
func TestAgentJoinDerivesTheNodeIPFromTheAssignment(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("a join with no --node-ip is issued for the assigned address", func(t *testing.T) {
		t.Parallel()
		rig := newJoinRig(t)
		res, err := rig.join(ctx, "worker-a", "")
		if err != nil {
			t.Fatalf("a join that lets the control plane assign the address must succeed: %v", err)
		}
		const want = "100.64.1.1"
		if res.MeshIP != want {
			t.Fatalf("assigned meshIP = %q, want %q", res.MeshIP, want)
		}
		if res.NodeIP != want {
			t.Errorf("join response nodeIP = %q, want the assigned %q (the address the certificates name)", res.NodeIP, want)
		}
		if got := certIPSANs(t, res.NodeClientCertPEM); len(got) != 1 || got[0] != want {
			t.Errorf("client cert IP SANs = %v, want exactly [%s] (the assignment)", got, want)
		}
		if got := certIPSANs(t, res.KubeletServingCertPEM); len(got) != 1 || got[0] != want {
			t.Errorf("kubelet serving cert IP SANs = %v, want exactly [%s] (the assignment)", got, want)
		}

		// ...and the agent's own wiring advertises that same address: the Node
		// object's InternalIP, the serving-cert SAN set the node reloads with, and
		// the node-local datapath all read it off the join, never off the flag.
		opts := agentOptions{workDir: t.TempDir(), nodeName: "worker-a", clusterIP: "10.43.0.10", domain: "cluster.local"}
		nodeOpts := agentNodeOptions(opts, res, "/var/lib/k3sm/agent/node.kubeconfig", hostnet.Mode{Backend: hostnet.BackendHelper}, nil)
		if nodeOpts.nodeIP != want {
			t.Errorf("worker nodeOptions.nodeIP = %q, want the assigned %q", nodeOpts.nodeIP, want)
		}
		if cfg := workerNetserveConfig(opts, res, hostnet.Mode{Backend: hostnet.BackendHelper}, false, nil); cfg.NodeIP != want {
			t.Errorf("worker netserve NodeIP = %q, want the assigned %q", cfg.NodeIP, want)
		}
	})

	t.Run("a --node-ip that differs from the assignment is refused before signing", func(t *testing.T) {
		t.Parallel()
		rig := newJoinRig(t)
		res, err := rig.join(ctx, "worker-a", "100.64.9.9")
		if err == nil {
			t.Fatalf("a join asserting an address the control plane did not assign must be refused; it was issued %v",
				certIPSANs(t, res.NodeClientCertPEM))
		}
		if res != nil {
			t.Error("a refused join must yield no certificate at all")
		}
		for _, want := range []string{"100.64.9.9", "100.64.1.1"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("refusal %q must name %s (both the requested and the assigned address)", err, want)
			}
		}

		// The refusal lands BEFORE any CSR is parsed: a request whose CSR is
		// unparseable garbage is still refused for the address, not for the CSR.
		body, merr := json.Marshal(bootstrap.JoinRequest{
			SchemaVersion: bootstrap.JoinSchemaVersion,
			Token:         rig.token,
			NodeName:      "worker-a",
			NodeIP:        "100.64.9.9",
			NodePassword:  "node-secret-worker-a",
			ClientCSRPEM:  "not a CSR at all",
			Mesh:          netv1.MeshEnrollRequest{NodeName: "worker-a"}.WithDefaults(),
		})
		if merr != nil {
			t.Fatalf("marshal join request: %v", merr)
		}
		resp, perr := rig.ts.Client().Post(rig.ts.URL+bootstrap.JoinPath, "application/json", bytes.NewReader(body))
		if perr != nil {
			t.Fatalf("post join: %v", perr)
		}
		defer resp.Body.Close()
		raw := make([]byte, 512)
		n, _ := resp.Body.Read(raw)
		reason := strings.TrimSpace(string(raw[:n]))
		if resp.StatusCode != http.StatusConflict {
			t.Errorf("status = %s (%s), want 409 Conflict: the address mismatch is decided before the CSR is read", resp.Status, reason)
		}
		if strings.Contains(reason, "CSR") {
			t.Errorf("refusal %q reports the CSR: the join must be refused before any CSR is parsed", reason)
		}
	})

	t.Run("a --node-ip that matches the assignment is issued", func(t *testing.T) {
		t.Parallel()
		rig := newJoinRig(t)
		res, err := rig.join(ctx, "worker-a", "100.64.1.1")
		if err != nil {
			t.Fatalf("a join asserting the address the control plane assigns must succeed: %v", err)
		}
		if got := certIPSANs(t, res.NodeClientCertPEM); len(got) != 1 || got[0] != "100.64.1.1" {
			t.Errorf("client cert IP SANs = %v, want exactly [100.64.1.1]", got)
		}
		if res.NodeIP != "100.64.1.1" {
			t.Errorf("join response nodeIP = %q, want 100.64.1.1", res.NodeIP)
		}
	})

	t.Run("a second join by the same node name reuses its assignment", func(t *testing.T) {
		t.Parallel()
		rig := newJoinRig(t)
		first, err := rig.join(ctx, "worker-a", "")
		if err != nil {
			t.Fatalf("first join: %v", err)
		}
		other, err := rig.join(ctx, "worker-b", "")
		if err != nil {
			t.Fatalf("second node's join: %v", err)
		}
		if other.NodeIP == first.NodeIP {
			t.Fatalf("two nodes were assigned the same address %q", other.NodeIP)
		}
		again, err := rig.join(ctx, "worker-a", "")
		if err != nil {
			t.Fatalf("rejoin: %v", err)
		}
		if again.NodeIP != first.NodeIP {
			t.Errorf("rejoin nodeIP = %q, want the address this node already holds, %q", again.NodeIP, first.NodeIP)
		}
		if got := certIPSANs(t, again.NodeClientCertPEM); len(got) != 1 || got[0] != first.NodeIP {
			t.Errorf("rejoined client cert IP SANs = %v, want exactly [%s]", got, first.NodeIP)
		}
	})

	t.Run("an old server's refusal names the operator's two ways out", func(t *testing.T) {
		t.Parallel()
		// A control plane built before the address became the server's to assign
		// answers an absent nodeIP with exactly this 400.
		old := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "join request missing nodeName or nodeIP", http.StatusBadRequest)
		}))
		defer old.Close()

		_, err := bootstrap.Join(ctx, bootstrap.JoinOptions{
			Server:       old.URL,
			Token:        bootstrap.FormatToken(strings.Repeat("ab", 32), "boot-x", "s3cr3t"),
			NodeName:     "worker-a",
			NodePassword: "pw",
			MeshEndpoint: "192.168.1.50:51820",
			HTTPClient:   old.Client(),
		})
		if err == nil {
			t.Fatal("a join an old server refuses must fail")
		}
		if !errors.Is(err, bootstrap.ErrServerRequiresNodeIP) {
			t.Errorf("error %q must be ErrServerRequiresNodeIP, so the agent can report it as terminal", err)
		}
		for _, want := range []string{"--node-ip", "upgrade the control plane"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q must name %q", err, want)
			}
		}
	})
}
