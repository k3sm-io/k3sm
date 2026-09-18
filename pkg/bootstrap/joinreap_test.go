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
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"

	netv1 "k3sm.io/apis/net/v1"

	"k3sm.io/k3sm/pkg/bootstrap"
)

// allocatingEnroller models the shipped meshEnroller's allocation rule at a scale
// a unit test can assert on: a node name that already holds an index keeps it (the
// rejoin path), any other name takes the lowest free index. It reports which of the
// two happened, counts its calls, and frees an index again on ReleaseAllocation —
// so a test can observe the one thing this gate is about, which is whether a join
// that failed left its index burned.
//
// Locking discipline: mu guards every field; httptest serves each join on its own
// goroutine.
type allocatingEnroller struct {
	mu      sync.Mutex
	byNode  map[string]int
	byIndex map[int]string
	// enrolls counts EVERY Enroll call. "The request was refused" and "the enroll
	// never ran" are different claims, and the ordering rows assert the second.
	enrolls int
	// releases is the node name of every ReleaseAllocation call, in order.
	releases []string
	// releaseErr is what ReleaseAllocation returns, so a row can drive the
	// handler's reap-failure arm.
	releaseErr error
}

func (e *allocatingEnroller) Enroll(_ context.Context, nodeName string, _ netv1.MeshEnrollRequest) (netv1.MeshEnrollResponse, bootstrap.Allocation, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.byNode == nil {
		e.byNode, e.byIndex = map[string]int{}, map[int]string{}
	}
	e.enrolls++
	index, held := e.byNode[nodeName]
	alloc := bootstrap.AllocationReused
	if !held {
		for index = 1; ; index++ {
			if _, taken := e.byIndex[index]; !taken {
				break
			}
		}
		e.byNode[nodeName], e.byIndex[index] = index, nodeName
		alloc = bootstrap.AllocationFresh
	}
	return netv1.MeshEnrollResponse{
		NodeName: nodeName,
		PodCIDR:  fmt.Sprintf("100.64.%d.0/24", index),
		MeshIP:   fmt.Sprintf("100.64.%d.1", index),
	}.WithDefaults(), alloc, nil
}

// ReleaseAllocation frees the node's index, which is what the real enroller's
// MeshPeer delete does to the state the next assignment reads.
func (e *allocatingEnroller) ReleaseAllocation(_ context.Context, nodeName string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.releases = append(e.releases, nodeName)
	if e.releaseErr != nil {
		return e.releaseErr
	}
	if index, held := e.byNode[nodeName]; held {
		delete(e.byNode, nodeName)
		delete(e.byIndex, index)
	}
	return nil
}

// RefreshEndpoint satisfies bootstrap.Enroller. This fixture exercises the JOIN
// path only; a refresh reaching it would be a test wiring mistake, so it reports
// the "rejoin" error rather than silently succeeding.
func (e *allocatingEnroller) RefreshEndpoint(_ context.Context, _, _ string) error {
	return bootstrap.ErrNoMeshPeer
}

// Deregister satisfies bootstrap.Enroller. Reaping a failed join is
// ReleaseAllocation's job and never this one — a deregistration here would delete
// the Node object too — so it fails loudly.
func (e *allocatingEnroller) Deregister(_ context.Context, nodeName string) error {
	return fmt.Errorf("the join fixture's enroller was asked to deregister %q", nodeName)
}

// indexOf returns the index the node currently holds, and whether it holds one.
func (e *allocatingEnroller) indexOf(nodeName string) (int, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	index, held := e.byNode[nodeName]
	return index, held
}

// calls returns the Enroll count and the node names ReleaseAllocation was called with.
func (e *allocatingEnroller) calls() (int, []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.enrolls, append([]string(nil), e.releases...)
}

// join runs the agent-side Join client against the rig with a well-formed request.
func (r *joinServerRig) join(t *testing.T, nodeName string) (*bootstrap.JoinResult, error) {
	t.Helper()
	return bootstrap.Join(context.Background(), bootstrap.JoinOptions{
		Server:       r.ts.URL,
		Token:        r.token,
		NodeName:     nodeName,
		NodePassword: "pw-" + nodeName,
		MeshEndpoint: "192.168.1.50:51820",
		HTTPClient:   r.ts.Client(),
	})
}

// crossNodeCSRJoin is a join request whose CSR is well-formed and passes every
// check that can be made WITHOUT the assigned address, and fails the one that
// cannot: its IP SAN is an address the allocator will not assign this node. It is
// the only way to reach a signer failure on the far side of the enroll, which is
// exactly the window this gate is about.
func crossNodeCSRJoin(t *testing.T, rig *joinServerRig, nodeName string) bootstrap.JoinRequest {
	t.Helper()
	return bootstrap.JoinRequest{
		SchemaVersion: bootstrap.JoinSchemaVersion,
		Token:         rig.token,
		NodeName:      nodeName,
		NodePassword:  "pw-" + nodeName,
		ClientCSRPEM:  nodeCSRPEM(t, nodeName, []string{nodeName}, []net.IP{net.ParseIP("203.0.113.9")}),
		Mesh:          netv1.MeshEnrollRequest{NodeName: nodeName}.WithDefaults(),
	}
}

// TestJoinReleasesTheAllocationOnACSRFailure is B339: a join that fails AFTER the
// mesh enroll must not leave the index the enroll carved behind it.
//
// Since the enroll became the step that DECIDES the node's address it runs before
// the CSRs are touched, so every CSR rejection happens with a MeshPeer already
// written. Nothing recycled it: a token holder could burn one pod /24 per aborted
// join until the cluster CIDR ran out, with no node ever joining. The fix is in two
// halves, and this gate asserts both — everything judgeable without the address is
// judged BEFORE the enroll, and the allocation the enroll FRESHLY carved is
// released when what is left still fails.
//
// The reap is scoped to a FRESH allocation on purpose. A rejoin reuses the peer an
// earlier SUCCESSFUL join wrote; deleting that peer because a later join's CSR was
// bad would strand a live node's pod network on a failure that never touched it.
func TestJoinReleasesTheAllocationOnACSRFailure(t *testing.T) {
	t.Parallel()

	t.Run("a malformed CSR is refused before the enroll", func(t *testing.T) {
		t.Parallel()
		enroller := &allocatingEnroller{}
		rig := newJoinServerRig(t, enroller)
		status, reason := rig.post(t, bootstrap.JoinRequest{
			SchemaVersion: bootstrap.JoinSchemaVersion,
			Token:         rig.token,
			NodeName:      "worker-1",
			NodePassword:  "pw-worker-1",
			ClientCSRPEM:  "-----BEGIN CERTIFICATE REQUEST-----\nnot base64\n-----END CERTIFICATE REQUEST-----",
			Mesh:          netv1.MeshEnrollRequest{NodeName: "worker-1"}.WithDefaults(),
		})
		if status != http.StatusBadRequest {
			t.Fatalf("status = %d (%s), want 400", status, reason)
		}
		enrolls, releases := enroller.calls()
		if enrolls != 0 {
			t.Errorf("the enroll ran %d times for a CSR the server cannot parse; it must be refused BEFORE the enroll, so no MeshPeer is written at all", enrolls)
		}
		if _, held := enroller.indexOf("worker-1"); held {
			t.Error("a join refused at the CSR left a mesh allocation behind")
		}
		if len(releases) != 0 {
			t.Errorf("released %v; nothing was allocated, so nothing may be reaped", releases)
		}
	})

	t.Run("a CSR carrying a forbidden SAN is refused before the enroll", func(t *testing.T) {
		t.Parallel()
		enroller := &allocatingEnroller{}
		rig := newJoinServerRig(t, enroller)
		status, reason := rig.post(t, bootstrap.JoinRequest{
			SchemaVersion: bootstrap.JoinSchemaVersion,
			Token:         rig.token,
			NodeName:      "worker-1",
			NodePassword:  "pw-worker-1",
			// A DNS SAN for a name this node may not assert. Nothing about the
			// assigned address is needed to know that, so it is decidable — and
			// therefore decided — before the allocator is asked for anything.
			ClientCSRPEM: nodeCSRPEM(t, "worker-1", []string{"worker-1", "kubernetes.default.svc"}, nil),
			Mesh:         netv1.MeshEnrollRequest{NodeName: "worker-1"}.WithDefaults(),
		})
		if status != http.StatusForbidden {
			t.Fatalf("status = %d (%s), want 403", status, reason)
		}
		enrolls, _ := enroller.calls()
		if enrolls != 0 {
			t.Errorf("the enroll ran %d times for a CSR naming another identity; the SAN policy that does not depend on the address must be applied BEFORE the enroll", enrolls)
		}
		if _, held := enroller.indexOf("worker-1"); held {
			t.Error("a join refused at the SAN policy left a mesh allocation behind")
		}
	})

	t.Run("a signer failure on a fresh name frees the index", func(t *testing.T) {
		t.Parallel()
		enroller := &allocatingEnroller{}
		rig := newJoinServerRig(t, enroller)
		status, reason := rig.post(t, crossNodeCSRJoin(t, rig, "worker-1"))
		if status != http.StatusForbidden {
			t.Fatalf("status = %d (%s), want 403: a CSR naming an address the allocator did not assign is denied", status, reason)
		}
		if index, held := enroller.indexOf("worker-1"); held {
			t.Errorf("the failed join kept index %d — a token holder can burn every index in the cluster CIDR with joins that abort at the CSR", index)
		}
		if _, releases := enroller.calls(); len(releases) != 1 || releases[0] != "worker-1" {
			t.Errorf("ReleaseAllocation calls = %v, want exactly [worker-1]", releases)
		}
		// The index is free in the sense that matters: the next node gets it.
		res, err := rig.join(t, "worker-2")
		if err != nil {
			t.Fatalf("the join after the reap: %v", err)
		}
		if res.NodeIP != "100.64.1.1" {
			t.Errorf("worker-2 was assigned %q, want the freed 100.64.1.1", res.NodeIP)
		}
	})

	t.Run("a signer failure on a rejoin keeps the existing peer", func(t *testing.T) {
		t.Parallel()
		enroller := &allocatingEnroller{}
		rig := newJoinServerRig(t, enroller)
		if _, err := rig.join(t, "worker-1"); err != nil {
			t.Fatalf("the first join must succeed: %v", err)
		}
		before, held := enroller.indexOf("worker-1")
		if !held {
			t.Fatal("precondition: the successful join must hold an index")
		}

		status, reason := rig.post(t, crossNodeCSRJoin(t, rig, "worker-1"))
		if status != http.StatusForbidden {
			t.Fatalf("status = %d (%s), want 403", status, reason)
		}
		after, held := enroller.indexOf("worker-1")
		if !held || after != before {
			t.Errorf("index after the failed rejoin = (%d, held=%v), want the unchanged %d: the peer belongs to an EARLIER successful join and a live node's pod network must not be deleted by a later failure", after, held, before)
		}
		if _, releases := enroller.calls(); len(releases) != 0 {
			t.Errorf("released %v; a REUSED allocation is never reaped", releases)
		}
	})

	t.Run("a successful join keeps its peer", func(t *testing.T) {
		t.Parallel()
		enroller := &allocatingEnroller{}
		rig := newJoinServerRig(t, enroller)
		res, err := rig.join(t, "worker-1")
		if err != nil {
			t.Fatalf("join: %v", err)
		}
		if res.NodeIP != "100.64.1.1" || res.PodCIDR != "100.64.1.0/24" {
			t.Errorf("join returned nodeIP %q podCIDR %q, want 100.64.1.1 / 100.64.1.0/24", res.NodeIP, res.PodCIDR)
		}
		if index, held := enroller.indexOf("worker-1"); !held || index != 1 {
			t.Errorf("index after a SUCCESSFUL join = (%d, held=%v), want held 1", index, held)
		}
		if _, releases := enroller.calls(); len(releases) != 0 {
			t.Errorf("released %v after a successful join", releases)
		}
	})

	t.Run("a reap that fails does not change the join's own error", func(t *testing.T) {
		t.Parallel()
		enroller := &allocatingEnroller{releaseErr: fmt.Errorf("apiserver unreachable")}
		rig := newJoinServerRig(t, enroller)
		status, reason := rig.post(t, crossNodeCSRJoin(t, rig, "worker-1"))
		if status != http.StatusForbidden {
			t.Fatalf("status = %d (%s), want the CSR denial 403 — the reap failure is logged, not served", status, reason)
		}
		if _, releases := enroller.calls(); len(releases) != 1 {
			t.Errorf("ReleaseAllocation calls = %v, want one attempt", releases)
		}
	})
}
