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
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"k3sm.io/darwin-net/pkg/podnet"
)

// fakeIPAM is a PodIPAM over a REAL podnet.Allocator (real /32 IPAM semantics —
// distinct in-CIDR addresses, release/reuse, ErrPoolExhausted) with the
// root-gated lo0 alias plumbing faked away (darwin-net does not export its alias
// manager seam, so *podnet.Network itself is not constructible rootless here).
// It mirrors podnet.Network's idempotent-Setup / leak-free-Teardown contract.
type fakeIPAM struct {
	alloc *podnet.Allocator

	mu     sync.Mutex
	byPod  map[string]netip.Addr
	sweeps []map[string]netip.Addr // recorded SweepStale known-sets
}

func newFakeIPAM(t *testing.T, cidr string) *fakeIPAM {
	t.Helper()
	alloc, err := podnet.NewAllocator(netip.MustParsePrefix(cidr))
	if err != nil {
		t.Fatalf("NewAllocator(%s): %v", cidr, err)
	}
	return &fakeIPAM{alloc: alloc, byPod: map[string]netip.Addr{}}
}

func (f *fakeIPAM) Setup(_ context.Context, podID string) (netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ip, ok := f.byPod[podID]; ok {
		return ip, nil // idempotent per podID
	}
	ip, err := f.alloc.Allocate()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("allocate pod ip for %s: %w", podID, err)
	}
	f.byPod[podID] = ip
	return ip, nil
}

func (f *fakeIPAM) Teardown(_ context.Context, podID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	ip, ok := f.byPod[podID]
	if !ok {
		return nil // leak-free: unknown pod is a no-op success
	}
	delete(f.byPod, podID)
	return f.alloc.Release(ip)
}

func (f *fakeIPAM) SweepStale(_ context.Context, known map[string]netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweeps = append(f.sweeps, known)
	return nil
}

// allocations returns a snapshot of the current podID->IP bindings.
func (f *fakeIPAM) allocations() map[string]netip.Addr {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]netip.Addr, len(f.byPod))
	for k, v := range f.byPod {
		out[k] = v
	}
	return out
}

// exhaust drains every remaining address in the pool so the next Setup hits
// ErrPoolExhausted deterministically.
func (f *fakeIPAM) exhaust(t *testing.T) {
	t.Helper()
	for {
		if _, err := f.alloc.Allocate(); err != nil {
			if !errors.Is(err, podnet.ErrPoolExhausted) {
				t.Fatalf("exhaust: %v", err)
			}
			return
		}
	}
}

const testNodeIP = "192.168.1.10"

// newRuntimedWithPodNet builds a runtimed-backed provider runtime over the fake
// runtime server with the podnet adapter injected — the M10.1 assembly shape.
func newRuntimedWithPodNet(t *testing.T) (*runtimedRuntime, *fakeRuntimeServer, *fakeIPAM, *PodNetAdapter) {
	t.Helper()
	ipam := newFakeIPAM(t, "100.64.0.0/24")
	adapter := NewPodNetAdapter(ipam, testNodeIP, nil)
	f := newFakeRuntimeServer()
	r := newRuntimedWith(f, RuntimedConfig{
		NodeName: "n",
		NodeIP:   testNodeIP,
		Root:     t.TempDir(),
		Network:  adapter,
	}, nil, nil)
	return r, f, ipam, adapter
}

// podWithEnv builds a pod whose container carries a status.podIP downward-API
// env fieldRef — the M10.1 ordering canary (resolvable only if the /32 was
// allocated BEFORE env resolution).
func podWithEnv(ns, name string) *corev1.Pod {
	pod := runtimedPod(ns, name)
	pod.Spec.Containers[0].Env = []corev1.EnvVar{{
		Name:      "POD_IP",
		ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.podIP"}},
	}}
	return pod
}

// createdEnv returns the resolved literal value of env var name on the created
// box's first container.
func createdEnv(t *testing.T, f *fakeRuntimeServer, podUID, name string) string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	box, ok := f.created[podUID]
	if !ok {
		t.Fatalf("pod %s not created", podUID)
	}
	for _, e := range box.GetContainers()[0].GetEnv() {
		if e.GetName() == name {
			return e.GetValue()
		}
	}
	t.Fatalf("env %s not found on created box %s", name, podUID)
	return ""
}

// createdPodIP returns the created box's PodIp.
func createdPodIP(t *testing.T, f *fakeRuntimeServer, podUID string) string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	box, ok := f.created[podUID]
	if !ok {
		t.Fatalf("pod %s not created", podUID)
	}
	return box.GetPodIp()
}

// TestCreatePodAssignsDistinctPodIP is the M10.1-a1 server-side per-pod-IP gate
// (Res.1): the runtimed provider allocates each pod a DISTINCT in-CIDR /32 ≠
// nodeIP through the injected podnet adapter BEFORE translation — so box.PodIp
// and the resolved status.podIP downward-API env carry it (the ordering fix for
// the POD_IP env bug, where env resolution used to read the node IP) — while a
// hostNetwork pod skips podnet entirely (podIP = nodeIP, zero allocation),
// DeletePod releases the /32 for reuse, and pool exhaustion surfaces as a
// distinguishable error (errors.Is podnet.ErrPoolExhausted).
//
// Fails-before: box.PodIp/env were the node IP for every pod (podIP ≈ nodeIP on
// both paths); passes-after with the adapter wired.
func TestCreatePodAssignsDistinctPodIP(t *testing.T) {
	ctx := context.Background()
	cidr := netip.MustParsePrefix("100.64.0.0/24")

	t.Run("two pods get distinct in-CIDR /32s and the env fieldRef resolves to them", func(t *testing.T) {
		r, f, _, _ := newRuntimedWithPodNet(t)
		podA, podB := podWithEnv("default", "a"), podWithEnv("default", "b")
		if err := r.CreatePod(ctx, podA); err != nil {
			t.Fatalf("CreatePod a: %v", err)
		}
		if err := r.CreatePod(ctx, podB); err != nil {
			t.Fatalf("CreatePod b: %v", err)
		}
		ipA, ipB := createdPodIP(t, f, "uid-a"), createdPodIP(t, f, "uid-b")
		if ipA == ipB {
			t.Errorf("pod a and b share PodIp %q, want distinct /32s", ipA)
		}
		for name, ip := range map[string]string{"a": ipA, "b": ipB} {
			if ip == testNodeIP {
				t.Errorf("pod %s PodIp = nodeIP %q, want a distinct podnet /32", name, ip)
			}
			addr, err := netip.ParseAddr(ip)
			if err != nil || !cidr.Contains(addr) {
				t.Errorf("pod %s PodIp = %q, want an address in %s (parse err: %v)", name, ip, cidr, err)
			}
		}
		// THE ordering assert: the status.podIP downward-API env resolved to the
		// allocated /32, proving allocation preceded env resolution.
		if got := createdEnv(t, f, "uid-a", "POD_IP"); got != ipA {
			t.Errorf("pod a POD_IP env = %q, want the allocated /32 %q", got, ipA)
		}
		if got := createdEnv(t, f, "uid-b", "POD_IP"); got != ipB {
			t.Errorf("pod b POD_IP env = %q, want the allocated /32 %q", got, ipB)
		}
	})

	t.Run("hostNetwork pod gets the node IP and allocates nothing", func(t *testing.T) {
		r, f, ipam, adapter := newRuntimedWithPodNet(t)
		pod := podWithEnv("default", "hostnet")
		pod.Spec.HostNetwork = true
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		if got := createdPodIP(t, f, "uid-hostnet"); got != testNodeIP {
			t.Errorf("hostNetwork PodIp = %q, want nodeIP %q", got, testNodeIP)
		}
		if got := createdEnv(t, f, "uid-hostnet", "POD_IP"); got != testNodeIP {
			t.Errorf("hostNetwork POD_IP env = %q, want nodeIP %q", got, testNodeIP)
		}
		if allocs := ipam.allocations(); len(allocs) != 0 {
			t.Errorf("hostNetwork pod allocated from the pool: %v, want none", allocs)
		}
		// The runtimed-side seam (which the host-process spine calls
		// unconditionally) resolves the marked pod to the node IP too.
		if ip, err := adapter.Setup(ctx, "uid-hostnet"); err != nil || ip != testNodeIP {
			t.Errorf("adapter.Setup(hostNetwork pod) = (%q, %v), want (%q, nil)", ip, err, testNodeIP)
		}
	})

	t.Run("DeletePod releases the /32 so a later pod can reuse it", func(t *testing.T) {
		r, _, ipam, _ := newRuntimedWithPodNet(t)
		podA := podWithEnv("default", "a")
		if err := r.CreatePod(ctx, podA); err != nil {
			t.Fatalf("CreatePod a: %v", err)
		}
		ipA := ipam.allocations()["uid-a"]
		// Exhaust the rest of the pool: only a released ipA can satisfy pod c.
		ipam.exhaust(t)
		if err := r.CreatePod(ctx, podWithEnv("default", "blocked")); err == nil {
			t.Fatal("CreatePod on an exhausted pool succeeded, want error")
		}
		if err := r.DeletePod(ctx, podA); err != nil {
			t.Fatalf("DeletePod a: %v", err)
		}
		if _, held := ipam.allocations()["uid-a"]; held {
			t.Fatal("DeletePod did not release pod a's allocation")
		}
		if err := r.CreatePod(ctx, podWithEnv("default", "c")); err != nil {
			t.Fatalf("CreatePod c after release: %v", err)
		}
		if got := ipam.allocations()["uid-c"]; got != ipA {
			t.Errorf("pod c got %s, want the released %s (reuse)", got, ipA)
		}
	})

	t.Run("pool exhaustion surfaces distinguishably", func(t *testing.T) {
		r, _, ipam, _ := newRuntimedWithPodNet(t)
		ipam.exhaust(t)
		err := r.CreatePod(ctx, podWithEnv("default", "over"))
		if err == nil {
			t.Fatal("CreatePod on an exhausted pool succeeded, want ErrPoolExhausted")
		}
		if !errors.Is(err, podnet.ErrPoolExhausted) {
			t.Errorf("CreatePod error = %v, want errors.Is podnet.ErrPoolExhausted", err)
		}
	})
}

// TestPodNetAdapterReconcileStartup pins the adapter's runtime.NetworkReconciler
// leg: ReconcileStartup performs exactly one FULL stale-alias sweep (empty known
// set — nothing survives a daemon restart to reattach), the fail-closed
// crash-recovery contract runtimed invokes once before serving CreatePod.
func TestPodNetAdapterReconcileStartup(t *testing.T) {
	ipam := newFakeIPAM(t, "100.64.0.0/24")
	adapter := NewPodNetAdapter(ipam, testNodeIP, nil)
	if err := adapter.ReconcileStartup(context.Background()); err != nil {
		t.Fatalf("ReconcileStartup: %v", err)
	}
	ipam.mu.Lock()
	defer ipam.mu.Unlock()
	if len(ipam.sweeps) != 1 {
		t.Fatalf("SweepStale called %d times, want 1", len(ipam.sweeps))
	}
	if len(ipam.sweeps[0]) != 0 {
		t.Errorf("SweepStale known set = %v, want empty (full sweep)", ipam.sweeps[0])
	}
}

// TestPodNetAdapterTeardownIdempotent pins the teardown contract callers rely
// on: unknown pods are a no-op success and a marked hostNetwork pod is only
// unmarked (no pool interaction) — so the provider's belt-and-braces DeletePod
// teardown after runtimed's own never errors on the double release.
func TestPodNetAdapterTeardownIdempotent(t *testing.T) {
	ctx := context.Background()
	ipam := newFakeIPAM(t, "100.64.0.0/24")
	adapter := NewPodNetAdapter(ipam, testNodeIP, nil)

	if err := adapter.Teardown("never-set-up"); err != nil {
		t.Errorf("Teardown(unknown) = %v, want nil (no-op success)", err)
	}
	ip, err := adapter.Setup(ctx, "p1")
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if again, err := adapter.Setup(ctx, "p1"); err != nil || again != ip {
		t.Errorf("re-Setup(p1) = (%q, %v), want idempotent (%q, nil)", again, err, ip)
	}
	if err := adapter.Teardown("p1"); err != nil {
		t.Fatalf("Teardown(p1): %v", err)
	}
	if err := adapter.Teardown("p1"); err != nil {
		t.Errorf("second Teardown(p1) = %v, want nil (idempotent)", err)
	}
	adapter.MarkHostNetwork("hn")
	if got, err := adapter.Setup(ctx, "hn"); err != nil || got != testNodeIP {
		t.Errorf("Setup(marked) = (%q, %v), want (%q, nil)", got, err, testNodeIP)
	}
	if err := adapter.Teardown("hn"); err != nil {
		t.Errorf("Teardown(marked) = %v, want nil", err)
	}
	if allocs := ipam.allocations(); len(allocs) != 0 {
		t.Errorf("pool still holds %v after teardowns, want empty", allocs)
	}
}
