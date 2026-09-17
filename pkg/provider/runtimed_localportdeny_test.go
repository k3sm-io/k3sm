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
	"context"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestKinePortStampedOnEveryPod proves the provider stamps the node's denied
// local ports (in production, kine's EFFECTIVE port) onto every pod's
// SandboxProfile UNCONDITIONALLY — a plain pod and a pod that additionally
// asked for internet egress both carry it, exactly like the socket-deny stamp
// (TestRuntimedDeniesHelperSocket).
//
// It asserts the STAMPED FIELD only (PodBox.SandboxProfile.DeniedLocalPorts),
// never the rendered SBPL text: the generator's emission of a per-port deny
// line is a separate deliverable, and a test pinned to that text would be
// coupled to work this one does not own.
func TestKinePortStampedOnEveryPod(t *testing.T) {
	const kinePort = 12379
	f := newFakeRuntimeServer()
	r := newRuntimedWith(f, RuntimedConfig{
		NodeName: "n",
		NodeIP:   "192.168.1.10",
		Root:     t.TempDir(), PodLogsDir: t.TempDir(),
		DeniedLocalPorts: []int{kinePort},
	}, nil, nil)

	plain := runtimedPod("default", "web")
	networked := runtimedPod("default", "egress")
	networked.Annotations = map[string]string{runtimev1.AnnotationInternetEgress: ""}

	for _, pod := range []*corev1.Pod{plain, networked} {
		box, err := r.buildBox(context.Background(), pod, "192.168.1.10")
		if err != nil {
			t.Fatalf("buildBox(%s): %v", pod.Name, err)
		}
		got := box.GetSandboxProfile().GetDeniedLocalPorts()
		want := []uint32{kinePort}
		if !slices.Equal(got, want) {
			t.Errorf("pod %s: DeniedLocalPorts = %v, want %v", pod.Name, got, want)
		}
	}
}

// TestLocalPortDenyStampIsAUnion pins the STAMP SITE (stampLocalPortDenies)
// against a profile that already carries a denied port — the exact sibling of
// TestSocketDenyStampIsAUnion, for the exact same reason: nothing in the
// current translation path pre-sets DeniedLocalPorts, so a bare `=` at the
// stamp site is behaviourally identical today, and a defence nothing asserts
// is one a later edit silently removes.
func TestLocalPortDenyStampIsAUnion(t *testing.T) {
	const preExisting uint32 = 9999
	const nodePort = 12379

	r := &runtimedRuntime{deniedLocalPorts: []uint32{nodePort}}
	sp := &runtimev1.SandboxProfile{DeniedLocalPorts: []uint32{preExisting}}
	r.stampLocalPortDenies(sp)
	got := sp.GetDeniedLocalPorts()

	want := []uint32{preExisting, nodePort}
	if !slices.Equal(got, want) {
		t.Errorf("DeniedLocalPorts = %v, want %v", got, want)
	}

	// A nil profile must be a no-op, not a panic.
	r.stampLocalPortDenies(nil)

	// Idempotent: stamping twice must not duplicate.
	r.stampLocalPortDenies(sp)
	if got := sp.GetDeniedLocalPorts(); !slices.Equal(got, want) {
		t.Errorf("second stamp changed the set: got %v, want %v", got, want)
	}
}

// TestNormalizeLocalPortDeniesUnion proves the sort/dedupe contract
// normalizeLocalPortDenies gives the constructor, independent of any pod
// translation.
func TestNormalizeLocalPortDeniesUnion(t *testing.T) {
	got, err := normalizeLocalPortDenies([]int{12379, 80, 12379, 443})
	if err != nil {
		t.Fatalf("normalizeLocalPortDenies: %v", err)
	}
	want := []uint32{80, 443, 12379}
	if !slices.Equal(got, want) {
		t.Errorf("normalizeLocalPortDenies = %v, want %v", got, want)
	}
}

// TestNormalizeLocalPortDeniesRejectsOutOfRange proves an out-of-range port
// fails NORMALIZATION closed rather than being silently dropped or clamped.
func TestNormalizeLocalPortDeniesRejectsOutOfRange(t *testing.T) {
	for _, bad := range []int{0, -1, 65536, 100000} {
		if _, err := normalizeLocalPortDenies([]int{bad}); err == nil {
			t.Errorf("normalizeLocalPortDenies(%d): want an error, got nil", bad)
		}
	}
}

// TestNewRuntimedRejectsOutOfRangeLocalPort proves the PRODUCTION constructor
// (not just the normalization helper) fails closed on an out-of-range
// DeniedLocalPorts entry — the fail-closed contract the brief requires "from
// the constructor". The check runs before any real construction, so this
// needs no staged exec shim or runtime root.
func TestNewRuntimedRejectsOutOfRangeLocalPort(t *testing.T) {
	_, err := NewRuntimed(RuntimedConfig{
		NodeName: "n", Root: t.TempDir(), PodLogsDir: t.TempDir(),
		DeniedLocalPorts: []int{70000},
	})
	if err == nil {
		t.Fatal("NewRuntimed: want an error for an out-of-range denied local port, got nil")
	}
}
