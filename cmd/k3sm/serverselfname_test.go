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
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/hostnet"
)

// selfEnrollOptions is the control-plane bring-up this file drives: the mesh path
// (meshIP set) with NO datapath, so the helper stops after the enroll and no test
// needs a wireguard device, a netd socket or root.
func selfEnrollOptions(workDir, nodeName string) serverOptions {
	return serverOptions{
		workDir:  workDir,
		nodeName: nodeName,
		// Loopback, so serverMeshEndpoint has an answer on a host with no usable
		// underlay address — it prefers a real one when the scan finds it, and
		// either value is fine here: nothing dials it.
		nodeIP: "127.0.0.1",
		meshIP: "100.64.0.1",
	}
}

// TestServerBindsItsOwnNodePassword is the cmd half of B348's second layer: the
// control-plane node takes the first-write-wins node-password binding for its own
// name at bring-up, so that name is no longer there for a join to claim — and it
// does so with a PERSISTED value, so the second boot presents the same one.
func TestServerBindsItsOwnNodePassword(t *testing.T) {
	ctx := context.Background()
	const nodeName = "k3sm-host"

	t.Run("the enroll binds this node's own name", func(t *testing.T) {
		e, api := enrollerOverStub(t)
		passwords := bootstrap.NewMemoryNodePasswords()
		workDir := t.TempDir()

		res, down, err := enrollSelfAndBringUpMesh(ctx, e, passwords,
			selfEnrollOptions(workDir, nodeName), hostnet.Mode{Backend: hostnet.BackendNone}, "", quietLogger())
		if err != nil {
			t.Fatalf("self-enroll: %v", err)
		}
		defer func() { _ = down(ctx) }()
		if res.PodCIDR != "100.64.0.0/24" {
			t.Errorf("self-enroll podCIDR = %q, want the index-0 carve 100.64.0.0/24", res.PodCIDR)
		}
		if api.peer(nodeName) == nil {
			t.Error("the self-enroll wrote no MeshPeer")
		}
		if _, bound := passwords.StoredHash(nodeName); !bound {
			t.Fatal("the control-plane node did not bind its own name: a join presenting that name would take the binding first-write-wins")
		}

		// The value is on disk, 0600, and is what was bound — the property the
		// restart case below depends on.
		path := filepath.Join(workDir, serverNodePasswordRef)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("the node-password was not persisted: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("node-password mode = %o, want 600", perm)
		}
		stored, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read the persisted node-password: %v", err)
		}
		if err := passwords.Ensure(ctx, nodeName, string(stored)); err != nil {
			t.Errorf("the persisted node-password does not verify against the binding it took: %v", err)
		}
	})

	t.Run("two sequential start-ups against one store succeed", func(t *testing.T) {
		// THE RESTART CASE, and the reason the password is load-or-create rather
		// than minted per boot. The store outlives the process in HA (a Secret on
		// the shared datastore), so a fresh random value on the second start would
		// fail the bcrypt compare against the binding the first start took — this
		// node would be locked out of its own name by its own previous boot.
		e, _ := enrollerOverStub(t)
		passwords := bootstrap.NewMemoryNodePasswords()
		workDir := t.TempDir()
		opts := selfEnrollOptions(workDir, nodeName)
		mode := hostnet.Mode{Backend: hostnet.BackendNone}

		for _, boot := range []string{"first", "second"} {
			_, down, err := enrollSelfAndBringUpMesh(ctx, e, passwords, opts, mode, "", quietLogger())
			if err != nil {
				t.Fatalf("%s start-up: %v", boot, err)
			}
			_ = down(ctx)
		}
	})

	t.Run("a name already bound to another password is refused", func(t *testing.T) {
		// The binding is enforced, not merely recorded: if some other party got
		// there first, this node says so and does not proceed to enroll as if it
		// owned the name.
		e, api := enrollerOverStub(t)
		passwords := bootstrap.NewMemoryNodePasswords()
		if err := passwords.Ensure(ctx, nodeName, "someone-elses-password"); err != nil {
			t.Fatalf("seed the binding: %v", err)
		}

		_, _, err := enrollSelfAndBringUpMesh(ctx, e, passwords,
			selfEnrollOptions(t.TempDir(), nodeName), hostnet.Mode{Backend: hostnet.BackendNone}, "", quietLogger())
		if !errors.Is(err, bootstrap.ErrNodePasswordMismatch) {
			t.Fatalf("self-enroll error = %v, want ErrNodePasswordMismatch", err)
		}
		if api.peer(nodeName) != nil {
			t.Error("a node that could not bind its own name still wrote its MeshPeer")
		}
	})
}

// TestEnrollRefusesToOverwriteTheControlPlanePeer is B348's third layer: the
// WORKER-JOIN enroll path may not write over the MeshPeer that holds the
// control-plane node's pod index, whatever name the request carries.
//
// It keys on the EXISTING object's index rather than on a copy of the server's
// name, so it needs no second source of truth and it still closes the overwrite
// if the handler's name guard is ever bypassed or absent.
func TestEnrollRefusesToOverwriteTheControlPlanePeer(t *testing.T) {
	ctx := context.Background()
	const selfName = "k3sm-host"

	t.Run("Enroll refuses the join path", func(t *testing.T) {
		e, api := enrollerOverStub(t)
		seedPeer(t, api, selfName, "100.64.0.0/24")
		before := *api.peer(selfName)

		_, alloc, err := e.Enroll(ctx, selfName, enrollRequest(selfName))
		if !errors.Is(err, ErrServerPeerOverwrite) {
			t.Fatalf("Enroll error = %v, want ErrServerPeerOverwrite", err)
		}
		if alloc.Fresh || alloc.EnrollID != "" {
			t.Errorf("a refused enroll reported allocation %+v, want the zero value: it carved nothing to release", alloc)
		}
		if got := *api.peer(selfName); !reflect.DeepEqual(got.Spec, before.Spec) {
			t.Errorf("the control-plane peer changed:\n got  %+v\n want %+v", got.Spec, before.Spec)
		}
	})

	t.Run("writePeer refuses without the explicit permission", func(t *testing.T) {
		// The same refusal at the write itself, decided on the object read back
		// from the apiserver. It is the arm that still holds when the list Enroll
		// scanned was stale, and it is where EnrollSelf's permission is spent.
		e, api := enrollerOverStub(t)
		seedPeer(t, api, selfName, "100.64.0.0/24")
		before := *api.peer(selfName)

		peer, err := bootstrap.BuildMeshPeer(selfName, "100.64.0.0/24", "100.64.0.1", enrollRequest(selfName))
		if err != nil {
			t.Fatalf("build peer: %v", err)
		}
		if err := e.writePeer(ctx, peer, false); !errors.Is(err, ErrServerPeerOverwrite) {
			t.Fatalf("writePeer(allowServerIndex=false) error = %v, want ErrServerPeerOverwrite", err)
		}
		if got := *api.peer(selfName); !reflect.DeepEqual(got.Spec, before.Spec) {
			t.Errorf("the control-plane peer changed:\n got  %+v\n want %+v", got.Spec, before.Spec)
		}

		// And the permitted write — the control-plane process writing its own
		// peer — still goes through, or the server could not re-enroll itself on
		// any restart.
		if err := e.writePeer(ctx, peer, true); err != nil {
			t.Fatalf("writePeer(allowServerIndex=true) must still write the server's own peer: %v", err)
		}
		if got := api.peer(selfName); got == nil || got.Spec.Endpoint != enrollRequest(selfName).Endpoint {
			t.Errorf("the permitted write did not land: %+v", got)
		}
	})

	t.Run("EnrollSelf still rewrites its own peer", func(t *testing.T) {
		// The end-to-end shape of the same permission: a restarted control plane
		// re-enrolls over the peer its previous boot wrote.
		e, api := enrollerOverStub(t)
		seedPeer(t, api, selfName, "100.64.0.0/24")

		res, err := e.EnrollSelf(ctx, selfName, enrollRequest(selfName))
		if err != nil {
			t.Fatalf("EnrollSelf: %v", err)
		}
		if res.PodCIDR != "100.64.0.0/24" {
			t.Errorf("EnrollSelf podCIDR = %q, want 100.64.0.0/24", res.PodCIDR)
		}
		if got := api.peer(selfName); got == nil || got.Spec.Endpoint != enrollRequest(selfName).Endpoint {
			t.Errorf("EnrollSelf did not update its own peer: %+v", got)
		}
	})

	t.Run("an ordinary worker enroll is untouched", func(t *testing.T) {
		e, api := enrollerOverStub(t)
		seedPeer(t, api, selfName, "100.64.0.0/24")

		res, alloc, err := e.Enroll(ctx, "worker-1", enrollRequest("worker-1"))
		if err != nil {
			t.Fatalf("an ordinary worker enroll must still be served: %v", err)
		}
		if !alloc.Fresh {
			t.Error("a first join must report a FRESH allocation")
		}
		if res.PodCIDR == "100.64.0.0/24" {
			t.Fatalf("the worker was assigned the control-plane carve %q", res.PodCIDR)
		}
		if api.peer("worker-1") == nil {
			t.Error("the worker enroll wrote no MeshPeer")
		}
		if got := api.peer(selfName); got == nil || got.Spec.PublicKey != testPubKey {
			t.Errorf("the worker enroll disturbed the control-plane peer: %+v", got)
		}
	})
}
