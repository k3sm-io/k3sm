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
	"errors"
	"net/http"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
)

// postDeregister POSTs a raw deregistration body and returns the status code, so
// a row can assert the CODE rather than only that the call failed.
func postDeregister(t *testing.T, client *http.Client, baseURL, body string) (int, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		baseURL+bootstrap.DeregisterPath, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

// TestDeregisterVerb is the security table for the deregistration verb.
//
// The verb DELETES a node's MeshPeer and Node, reachable from the LAN (the
// bootstrap listener binds the wildcard on the mesh path), so it is the most
// destructive route the supervisor serves. Its authentication is the listener's
// OPTIONAL mTLS plus the handler's own checks, exactly as the endpoint refresh's
// is — tls.VerifyClientCertIfGiven completes the handshake with no client
// certificate, by necessity, because join must keep working for a node that has
// none. Each denial row pins one refusal AND asserts the enroller was never
// called: "the request was refused" and "nothing was deleted" are different
// claims, and only the second one is the property that matters here.
func TestDeregisterVerb(t *testing.T) {
	const body = `{"nodeName":"worker-1"}`

	t.Run("no client certificate is 401 and deletes nothing", func(t *testing.T) {
		f := newMeshEndpointFixture(t)
		code, err := postDeregister(t, f.anonymousClient(t), f.ts.URL, body)
		if err != nil {
			t.Fatalf("the handshake must succeed with no client certificate (join depends on it): %v", err)
		}
		if code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401 — an anonymous caller must not be able to delete a node", code)
		}
		if got := f.enroller.deregisters(); len(got) != 0 {
			t.Errorf("Deregister was called %v for an unauthenticated request", got)
		}
	})

	t.Run("a verified certificate that is not a node is 403", func(t *testing.T) {
		f := newMeshEndpointFixture(t)
		// Issued by the cluster's own signing CA, so the chain verifies — this is
		// the apiserver's kubelet client, which carries no Organization.
		client := f.nodeClient(t, f.signingCA, certs.APIServerKubeletClientCN, nil)
		code, err := postDeregister(t, client, f.ts.URL, body)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		if code != http.StatusForbidden {
			t.Errorf("status = %d, want 403 — chain validity alone is not a node identity", code)
		}
		if got := f.enroller.deregisters(); len(got) != 0 {
			t.Errorf("Deregister was called %v for a non-node identity", got)
		}
	})

	t.Run("a node may not deregister another node", func(t *testing.T) {
		f := newMeshEndpointFixture(t)
		client := f.nodeClient(t, f.signingCA, "system:node:worker-2", []string{"system:nodes"})
		code, err := postDeregister(t, client, f.ts.URL, body) // body names worker-1
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		if code != http.StatusForbidden {
			t.Errorf("status = %d, want 403 — every joined node holds a signing-CA certificate, so the self-scoping guard is the only thing stopping one node from evicting another", code)
		}
		if got := f.enroller.deregisters(); len(got) != 0 {
			t.Errorf("Deregister was called %v for a cross-node deletion", got)
		}
		if after, _ := f.enroller.snapshot(); after.NodeName != "worker-1" {
			t.Errorf("worker-1's peer was removed under worker-2's certificate: %+v", after)
		}
	})

	t.Run("a consistent node identity deregisters itself", func(t *testing.T) {
		f := newMeshEndpointFixture(t)
		client := f.nodeClient(t, f.signingCA, "system:node:worker-1", []string{"system:nodes"})
		code, err := postDeregister(t, client, f.ts.URL, body)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		if code != http.StatusOK {
			t.Fatalf("status = %d, want 200", code)
		}
		if got := f.enroller.deregisters(); len(got) != 1 || got[0] != "worker-1" {
			t.Fatalf("Deregister calls = %v, want exactly [worker-1] — the name the certificate authenticated", got)
		}
		if after, _ := f.enroller.snapshot(); after.NodeName != "" {
			t.Errorf("the peer survived a successful deregistration: %+v", after)
		}
	})

	t.Run("the production client helper drives the same exchange", func(t *testing.T) {
		f := newMeshEndpointFixture(t)
		client := f.nodeClient(t, f.signingCA, "system:node:worker-1", []string{"system:nodes"})
		if err := bootstrap.DeregisterNode(context.Background(), client, f.ts.URL, "worker-1"); err != nil {
			t.Fatalf("DeregisterNode: %v", err)
		}
		if got := f.enroller.deregisters(); len(got) != 1 || got[0] != "worker-1" {
			t.Errorf("Deregister calls = %v, want [worker-1]", got)
		}
	})

	t.Run("a failing delete is 500 and the client reports it", func(t *testing.T) {
		f := newMeshEndpointFixture(t)
		f.enroller.deregisterErr = errors.New("the datastore said no")
		client := f.nodeClient(t, f.signingCA, "system:node:worker-1", []string{"system:nodes"})
		err := bootstrap.DeregisterNode(context.Background(), client, f.ts.URL, "worker-1")
		if err == nil {
			t.Fatal("DeregisterNode must report a server-side failure: an uninstall that believed a failed delete leaves a peer entry behind with nobody watching")
		}
		if !strings.Contains(err.Error(), "500") {
			t.Errorf("error = %v, want it to name the 500 status", err)
		}
	})

	t.Run("the join token is not a credential for this verb", func(t *testing.T) {
		f := newMeshEndpointFixture(t)
		code, err := postDeregister(t, f.anonymousClient(t), f.ts.URL, `{"nodeName":"worker-1","token":"`+f.token+`"}`)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		if code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401 — the token is TTL-bounded and is deliberately not retained after a join", code)
		}
		if got := f.enroller.deregisters(); len(got) != 0 {
			t.Errorf("Deregister was called %v for a token-only request", got)
		}
	})

	t.Run("GET is refused", func(t *testing.T) {
		f := newMeshEndpointFixture(t)
		client := f.nodeClient(t, f.signingCA, "system:node:worker-1", []string{"system:nodes"})
		resp, err := client.Get(f.ts.URL + bootstrap.DeregisterPath)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want 405 — a deletion is never a GET", resp.StatusCode)
		}
	})
}
