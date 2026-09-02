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
	"slices"
	"testing"

	runtimed "k3sm.io/runtimed/pkg/runtime"
)

// TestRuntimedSocketPath pins the derivation the node's control-socket listener
// binds: the runtime root's run dir, the leaf name runtimed itself uses, and the
// default root resolving to the exact path `k3sm image` dials with no --socket.
func TestRuntimedSocketPath(t *testing.T) {
	tests := []struct {
		name string
		root string
		want string
	}{
		{
			// The shipped posture. It must be byte-identical to the client's
			// default, or `k3sm image ls` on a stock install dials a socket the
			// node did not bind — the exact defect this listener exists to fix.
			name: "empty root is the runtimed default socket",
			root: "",
			want: runtimed.DefaultSocketPath,
		},
		{
			// The same conclusion by the other route: an explicitly-passed default
			// root must not derive a different string from the empty one.
			name: "the default root derives the default socket",
			root: "/var/lib/k3sm",
			want: runtimed.DefaultSocketPath,
		},
		{
			// A `k3sm dev` cluster or a lab node roots elsewhere and must serve
			// beside its OWN image store, never contend for the shared one.
			name: "a custom root serves under its own run dir",
			root: "/opt/k3sm-lab/data",
			want: "/opt/k3sm-lab/data/run/runtimed.sock",
		},
		{
			name: "a trailing separator does not double up",
			root: "/opt/k3sm-lab/data/",
			want: "/opt/k3sm-lab/data/run/runtimed.sock",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := RuntimedSocketPath(tc.root); got != tc.want {
				t.Fatalf("RuntimedSocketPath(%q) = %q, want %q", tc.root, got, tc.want)
			}
		})
	}
}

// TestRuntimedSocketPathIsAlwaysDenied is the invariant that makes serving the
// socket safe to add: whatever root a node runs on, the path it BINDS is in the
// deny-set every pod profile carries.
//
// It matters because the socket's own permissions do not fence a pod out — the
// 0700 dir / 0600 node admit the daemon's uid, and a confined pod runs as that
// same uid (see docs/privilege-model.md). The Seatbelt deny is the fence, so a
// root whose served path escaped baseSocketDenies would hand every pod on that
// node the node's control API. Asserting it over several roots, rather than
// trusting that both sites call one function today, is what keeps a future
// second derivation from reopening it silently.
func TestRuntimedSocketPathIsAlwaysDenied(t *testing.T) {
	for _, root := range []string{"", "/var/lib/k3sm", "/opt/k3sm-lab/data", "/Users/lab/.k3sm/rt"} {
		t.Run(root, func(t *testing.T) {
			served := RuntimedSocketPath(root)
			denied := baseSocketDenies(root)
			if !slices.Contains(denied, served) {
				t.Fatalf("served socket %q (root %q) is not in the pod deny-set %v", served, root, denied)
			}
		})
	}
}

// TestServableRuntimeRejectsAFake pins the comma-ok half of the
// ControlSocketSource capability: a provider built over an injected
// runtimev1.RuntimeServer reports false, so the node serves nothing rather than
// binding a socket over a runtime that cannot back the runtime/v1 services.
//
// The true half is unreachable from a unit test by construction — it needs a real
// runtime.New, which wants a writable image root and the host capability probes —
// and is covered by hack/acceptance/image-socket.sh instead.
func TestServableRuntimeRejectsAFake(t *testing.T) {
	r := newRuntimedWith(newFakeRuntimeServer(), RuntimedConfig{NodeName: "n", Root: t.TempDir()}, nil, nil)
	if rt, ok := r.ServableRuntime(); ok || rt != nil {
		t.Fatalf("ServableRuntime over a fake = (%v, %v), want (nil, false)", rt, ok)
	}
	// The VK provider must not invent a capability its Runtime does not have.
	if rt, ok := NewVKProvider(r, "n").ServableRuntime(); ok || rt != nil {
		t.Fatalf("VKProvider.ServableRuntime over a fake = (%v, %v), want (nil, false)", rt, ok)
	}
	// HostProcess implements no runtime/v1 service at all, so it must not even
	// satisfy the capability.
	if _, ok := any(NewHostProcess("n", t.TempDir(), "127.0.0.1", nil)).(ControlSocketSource); ok {
		t.Fatal("HostProcess reports ControlSocketSource; it has no runtimed to serve")
	}
}
