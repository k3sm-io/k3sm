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
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	netv1 "k3sm.io/apis/net/v1"

	"k3sm.io/k3sm/pkg/bootstrap"
)

// fenceMeshRequest is the mesh sub-payload BOTH joins of the interleaving row
// carry — the same wireguard public key and the same endpoint.
//
// That sameness is the point, not a convenience. A node retrying its join (a
// launchd restart of an agent whose first attempt died after the enroll) presents
// the key it persisted and the endpoint it still owns, so the second write can be
// identical to the first in every field. Nothing about the peer's CONTENT can
// tell the two apart, which is why the fence is a per-enroll id rather than a
// comparison of what was written.
func fenceMeshRequest(nodeName string) netv1.MeshEnrollRequest {
	return netv1.MeshEnrollRequest{
		NodeName:  nodeName,
		PublicKey: "dGVzdC1wdWJsaWMta2V5LWJhc2U2NC0zMmJ5dGVzPT0=",
		Endpoint:  "192.168.1.50:51820",
	}.WithDefaults()
}

// fenceJoin builds a join request for nodeName carrying fenceMeshRequest. With
// ips nil the CSR passes every check and the join succeeds; with an IP SAN the
// allocator will not assign, it fails at the SIGNER — on the far side of the
// enroll, which is the only window this gate is about.
func fenceJoin(t *testing.T, rig *joinServerRig, nodeName string, ips []net.IP) bootstrap.JoinRequest {
	t.Helper()
	return bootstrap.JoinRequest{
		SchemaVersion: bootstrap.JoinSchemaVersion,
		Token:         rig.token,
		NodeName:      nodeName,
		NodePassword:  "pw-" + nodeName,
		ClientCSRPEM:  nodeCSRPEM(t, nodeName, []string{nodeName}, ips),
		Mesh:          fenceMeshRequest(nodeName),
	}
}

// postJoin posts a join and REPORTS its failures instead of ending the test. It
// exists because the interleaved join runs on the server's handler goroutine, and
// t.Fatalf outside the test goroutine is not a test failure — it is an undefined
// one.
func postJoin(client *http.Client, baseURL string, req bootstrap.JoinRequest) (int, string, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return 0, "", err
	}
	resp, err := client.Post(baseURL+bootstrap.JoinPath, "application/json", bytes.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, strings.TrimSpace(string(raw)), nil
}

// assertReleasesAreIdentified checks every release the handler issued named the
// write it was undoing. A release with no id is a release by NAME, which is the
// unfenced delete this gate exists to forbid — the enroller refuses it, but the
// handler must never reach for it in the first place.
func assertReleasesAreIdentified(t *testing.T, enroller *allocatingEnroller) {
	t.Helper()
	for i, alloc := range enroller.releasedWith() {
		if alloc.EnrollID == "" {
			t.Errorf("release %d carried no enroll id (%+v); a release must name the write it undoes", i, alloc)
		}
		if !alloc.Fresh {
			t.Errorf("release %d carried a REUSED allocation (%+v); only a freshly carved index is ever given back", i, alloc)
		}
	}
}

// TestReleaseAllocationIsFencedToItsOwnPeer: a join that fails after the enroll
// gives back the peer IT wrote, and never the one a later enroll of the same node
// name wrote in the meantime.
//
// The window is real and needs no adversary. Enroll and ReleaseAllocation share
// the enroller's lock, but the steps BETWEEN them — the CSR checks, the signing,
// the response — do not hold it, so a second join of the same node name can
// complete inside that window. It then legitimately reports REUSED, having found
// the peer the first join wrote, and the first join's failure arrives afterwards.
// Released by name, that failure deletes the peer the second join is already
// relying on: a node that joined successfully loses its pod network to a request
// that never touched it.
func TestReleaseAllocationIsFencedToItsOwnPeer(t *testing.T) {
	t.Parallel()

	t.Run("a newer join's peer survives the older join's failure", func(t *testing.T) {
		t.Parallel()
		enroller := &allocatingEnroller{}
		rig := newJoinServerRig(t, enroller)

		// The interleaving, made deterministic: the SECOND join runs to completion
		// inside the first join's release, which is exactly the ordering that makes
		// the first join's peer stale. No sleeps and no goroutine race.
		var (
			secondStatus int
			secondBody   string
			secondErr    error
		)
		enroller.beforeRelease = func() {
			secondStatus, secondBody, secondErr = postJoin(rig.ts.Client(), rig.ts.URL, fenceJoin(t, rig, "worker-1", nil))
		}

		status, reason := rig.post(t, fenceJoin(t, rig, "worker-1", []net.IP{net.ParseIP("203.0.113.9")}))
		if status != http.StatusForbidden {
			t.Fatalf("the first join's status = %d (%s), want the CSR denial 403", status, reason)
		}
		if secondErr != nil {
			t.Fatalf("the interleaved join: %v", secondErr)
		}
		if secondStatus != http.StatusOK {
			t.Fatalf("the interleaved join's status = %d (%s), want 200: it is a well-formed join of a node that already has a peer", secondStatus, secondBody)
		}

		index, held := enroller.indexOf("worker-1")
		if !held {
			t.Fatal("the failed join deleted the peer the SUCCESSFUL join is using: a node that joined loses its pod network to another request's CSR failure")
		}
		if index != 1 {
			t.Errorf("worker-1 holds index %d, want the unchanged 1", index)
		}
		if got := enroller.stampOf("worker-1"); got != "enroll-2" {
			t.Errorf("the peer carries the stamp %q, want the second enroll's enroll-2", got)
		}
		if _, releases := enroller.calls(); len(releases) != 1 || releases[0] != "worker-1" {
			t.Errorf("ReleaseAllocation calls = %v, want exactly one attempt for worker-1", releases)
		}
		if allocs := enroller.releasedWith(); len(allocs) != 1 || allocs[0].EnrollID != "enroll-1" {
			t.Errorf("the release carried %+v, want the FIRST join's enroll-1 — the id is what tells the two writes apart", allocs)
		}
		assertReleasesAreIdentified(t, enroller)
	})

	t.Run("with nobody in between the peer is released", func(t *testing.T) {
		t.Parallel()
		enroller := &allocatingEnroller{}
		rig := newJoinServerRig(t, enroller)

		status, reason := rig.post(t, fenceJoin(t, rig, "worker-1", []net.IP{net.ParseIP("203.0.113.9")}))
		if status != http.StatusForbidden {
			t.Fatalf("status = %d (%s), want 403", status, reason)
		}
		if index, held := enroller.indexOf("worker-1"); held {
			t.Errorf("the failed join kept index %d; the fence must not turn the release off, only aim it", index)
		}
		if got := enroller.stampOf("worker-1"); got != "" {
			t.Errorf("the released node still carries the stamp %q", got)
		}
		assertReleasesAreIdentified(t, enroller)

		// Free in the sense that matters: the next node is handed the index.
		res, err := rig.join(t, "worker-2")
		if err != nil {
			t.Fatalf("the join after the release: %v", err)
		}
		if res.NodeIP != "100.64.1.1" {
			t.Errorf("worker-2 was assigned %q, want the freed 100.64.1.1", res.NodeIP)
		}
	})

	t.Run("a release is never issued without an id", func(t *testing.T) {
		t.Parallel()
		enroller := &allocatingEnroller{}
		rig := newJoinServerRig(t, enroller)

		// Two failures on two names, plus a failure on a name that already holds a
		// peer (which must not be released at all). Whatever the handler releases,
		// it releases by IDENTITY.
		for _, node := range []string{"worker-1", "worker-2"} {
			if status, reason := rig.post(t, fenceJoin(t, rig, node, []net.IP{net.ParseIP("203.0.113.9")})); status != http.StatusForbidden {
				t.Fatalf("%s: status = %d (%s), want 403", node, status, reason)
			}
		}
		if _, err := rig.join(t, "worker-3"); err != nil {
			t.Fatalf("the successful join: %v", err)
		}
		if status, reason := rig.post(t, fenceJoin(t, rig, "worker-3", []net.IP{net.ParseIP("203.0.113.9")})); status != http.StatusForbidden {
			t.Fatalf("worker-3 rejoin: status = %d (%s), want 403", status, reason)
		}
		if allocs := enroller.releasedWith(); len(allocs) != 2 {
			t.Errorf("the handler issued %d releases (%+v), want 2: the rejoin's REUSED allocation is never released", len(allocs), allocs)
		}
		assertReleasesAreIdentified(t, enroller)
		if index, held := enroller.indexOf("worker-3"); !held || index != 1 {
			t.Errorf("worker-3 holds (%d, held=%v) after its rejoin failed, want the index its successful join took", index, held)
		}
	})
}
