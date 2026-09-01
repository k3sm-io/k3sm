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
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	netv1 "k3sm.io/apis/net/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/darwin-net/pkg/dns"
	"k3sm.io/darwin-net/pkg/podnet"
	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"

	runtimed "k3sm.io/runtimed/pkg/runtime"
)

// The node facts this file's assertions are pinned to. The NAT parameters are
// deliberately in ranges no other fixture in this package uses, so "these values
// arrived" cannot be a coincidence of some shared default.
const (
	guestPodCIDR   = "100.64.0.0/24"
	guestNodeIP    = "192.168.1.10"
	guestNodeName  = "n0"
	guestDNSVIP    = "10.43.0.10"
	guestNATGw     = "192.168.77.1"
	guestNATSubnet = "192.168.77.0/24"
)

// recordingVMBackend is runtimed's vm backend seam, available, capturing the
// sandbox.VMSpec it is handed. It is the ONE fake on the consumer side of the
// wiring under test: everything between the provider's CreatePod and this call is
// the real code path (the real runtime.Runtime, the real backend selection, the
// real createVMPod). CreateVM then returns the same lab-gated stub error the
// shipped backend does, so the pod fails exactly where production fails today.
type recordingVMBackend struct {
	mu     sync.Mutex
	calls  int
	last   sandbox.VMSpec
	podIDs []string
}

func (b *recordingVMBackend) Available() bool                  { return true }
func (b *recordingVMBackend) Name() string                     { return "recording-vm" }
func (b *recordingVMBackend) GuestRosettaShareSupported() bool { return false }

// The lifecycle legs of runtimed's VMBackend seam. This fake records a boot
// request and never leaves a helper behind (CreateVM returns the lab-gated stub
// error), so every one of them is a faithful no-op: there is nothing to stop,
// nothing to reap, no exit edge to watch, and no helper output to retain.
func (b *recordingVMBackend) StopVM(context.Context, string, time.Duration) error { return nil }
func (b *recordingVMBackend) StopAllVMs(context.Context) error                    { return nil }
func (b *recordingVMBackend) ReapOrphanVMs() error                                { return nil }
func (b *recordingVMBackend) VMDone(string) (<-chan struct{}, bool)               { return nil, false }
func (b *recordingVMBackend) VMHelperOutput(string) string                        { return "" }

func (b *recordingVMBackend) CreateVM(_ context.Context, spec sandbox.VMSpec) error {
	b.mu.Lock()
	b.calls++
	b.last = spec
	b.podIDs = append(b.podIDs, spec.PodID)
	b.mu.Unlock()
	return sandbox.ErrVMBootNotImplemented
}

func (b *recordingVMBackend) created() (int, sandbox.VMSpec) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls, b.last
}

// availableSeatbelt is a sandbox.Backend that reports AVAILABLE and nothing else.
// It exists so the host-process control pod resolves to the Seatbelt rung rather
// than degrading UP to the vm rung (sandbox.SelectBackend degrades an UNSPECIFIED
// pod to vm when Seatbelt is unavailable — which would make the negative leg pass
// for the wrong reason). WrapCommand is never reached: testRegistry stops that
// pod at image pull, before any spawn.
type availableSeatbelt struct{}

func (availableSeatbelt) Available() bool { return true }
func (availableSeatbelt) Name() string    { return "test-seatbelt" }
func (availableSeatbelt) WrapCommand(context.Context, string, []string, supervisor.LaunchSpec) (string, []string, func() error, error) {
	return "", nil, nil, errors.New("test seatbelt backend does not spawn")
}

// guestVMImage is the OCI reference the vm pod's container names, and the ONLY
// reference testRegistry serves. The host-process control pod keeps a different
// one (see hostPod), which is what keeps that leg's pull refusal a routing fact.
const guestVMImage = "docker.io/library/alpine:3"

// errPullRefused stops the host-process control pod at the image pull — the
// first step past the vm/host-process fork — with no registry traffic and no
// spawn, so the negative leg proves the route taken without leaving the process.
var errPullRefused = errors.New("test registry: this world serves one image")

// testRegistry is the pull + image-config seam pair, serving exactly one image:
// guestVMImage. Every other reference is refused with errPullRefused.
//
// It has to SERVE rather than refuse outright because runtimed's vm spine now
// resolves a pod's containers BEFORE the backend is reached (M11.2-d11
// resolveVMContainers): each container is pulled, its run config is read, and
// the two are merged with the pod spec, so a vm pod whose image cannot be pulled
// fails at IMAGE_PULL and never reaches CreateVM. Both halves are on ONE fake
// and the config is looked up THROUGH the manifest's own reference — runtimed's
// own vm-fixture shape (its imageWorld) — so the seam cannot serve a config for
// one image and a manifest for another.
//
// Serving a single image is what leaves the negative leg intact: the
// host-process pod's reference is unknown here, so it still stops at the pull.
type testRegistry struct {
	mu   sync.Mutex
	refs []string
}

func (r *testRegistry) Pull(_ context.Context, ref string, _ *image.RegistryCredential, _ image.PlatformPolicy, _ runtimev1.ImagePullPolicy) (*image.PullResult, error) {
	r.mu.Lock()
	r.refs = append(r.refs, ref)
	r.mu.Unlock()
	if ref != guestVMImage {
		return nil, errPullRefused
	}
	return &image.PullResult{
		Manifest: &runtimev1.ImageManifest{
			Reference: ref,
			Config:    &runtimev1.Descriptor{Digest: "sha256:" + strings.Repeat("a", 64)},
		},
		CacheHit: true,
	}, nil
}

// ImageRunConfig serves guestVMImage's declared run config. The entrypoint is
// the pod-supplied command's counterpart in the four-quadrant merge; what that
// merge produces is runtimed's own gate (TestVMContainerMergeQuadrants) and is
// deliberately not re-asserted here — this file asserts VMSpec.Network.
func (r *testRegistry) ImageRunConfig(mfst *runtimev1.ImageManifest) (image.ImageRunConfig, error) {
	if ref := mfst.GetReference(); ref != guestVMImage {
		return image.ImageRunConfig{}, fmt.Errorf("no config for %q", ref)
	}
	return image.ImageRunConfig{Entrypoint: []string{"/entrypoint.sh"}}, nil
}

// MaterializeTree completes the Unpacker seam. The vm path DOES call it: it is
// what fills the pod-wide rootfs the k3sm.rootfs virtiofs share exports, without
// which the guest has no executable to run. (It did not until the M11 validation
// found every vm pod booting onto an empty rootfs; this comment previously
// asserted the opposite and is corrected here.) The fake reports a tree at the
// requested destination and touches no blob store.
func (r *testRegistry) MaterializeTree(_ context.Context, _ *runtimev1.ImageManifest, policy image.UnpackPolicy, dst string) (*image.MaterializeResult, error) {
	return &image.MaterializeResult{Tree: &image.Tree{Key: "sha256:fake", Rootfs: dst, Policy: policy}}, nil
}

func (r *testRegistry) pulled() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.refs...)
}

// Compile-time proof the fakes satisfy the seams they are injected into: a
// renamed method would otherwise silently fall back to the PRODUCTION default
// (the real VZ backend, the real registry puller), and the whole file would be
// testing something else.
var (
	_ runtimed.VMBackend = (*recordingVMBackend)(nil)
	_ sandbox.Backend    = availableSeatbelt{}
	_ runtimed.Puller    = (*testRegistry)(nil)
	_ runtimed.Unpacker  = (*testRegistry)(nil)
)

// guestNode is the node assembly under test: the REAL runtimed runtime over the
// REAL *PodNetAdapter, wrapped by the REAL provider — production's own shape (see
// NewRuntimed, which wires the one adapter into both sides). Only the LEAF
// effects are faked: the IPAM's lo0 plumbing (fakeIPAM, over a real
// podnet.Allocator), the vm backend, the sandbox backend, and the registry.
//
// Faking the runtimed side as well — the newRuntimedWith(fakeRuntimeServer)
// idiom this package uses elsewhere — would prove only that two fakes agree, and
// would say nothing about whether the provider's config reaches VMSpec.Network.
type guestNode struct {
	r       *runtimedRuntime
	adapter *PodNetAdapter
	ipam    *fakeIPAM
	vmb     *recordingVMBackend
	images  *testRegistry
}

func newGuestNode(t *testing.T) *guestNode {
	t.Helper()
	ipam := newFakeIPAM(t, guestPodCIDR)
	ipam.vm = podnet.VMNetworkConfig{
		NATSubnet: netip.MustParsePrefix(guestNATSubnet),
		Gateway:   netip.MustParseAddr(guestNATGw),
		DNSVIP:    netip.MustParseAddr(guestDNSVIP),
	}
	adapter := NewPodNetAdapter(ipam, guestNodeIP, nil)
	vmb := &recordingVMBackend{}
	images := &testRegistry{}
	root := t.TempDir()
	rt, err := runtimed.New(runtimed.Config{Root: root, RuntimeVersion: "test"}, runtimed.Deps{
		Network:   adapter,
		VMBackend: vmb,
		Backend:   availableSeatbelt{},
		// Both image seams are the one fake: the vm spine pulls each container
		// and reads its run config back through the SAME manifest, and the
		// production Unpacker default would read that config out of a blob store
		// no unit test commits to.
		Puller:   images,
		Unpacker: images,
		// Pin the host probes: their production defaults fork a process (Rosetta)
		// and drive Metal (GPU), which would make a unit test depend on the test
		// host's hardware. None of them participates in the wiring under test.
		HostRosetta:  func(context.Context) sandbox.HostRosettaState { return sandbox.HostRosettaAbsent },
		GuestRosetta: func() sandbox.GuestRosettaState { return sandbox.GuestRosettaNotSupported },
		GPUProbe:     func() sandbox.GPUProbeResult { return sandbox.GPUProbeResult{} },
	})
	if err != nil {
		t.Fatalf("runtimed.New: %v", err)
	}
	// The SAME adapter on both sides, and the SAME root — exactly as NewRuntimed
	// assembles a node (a second adapter would be a second allocator; a second
	// root would make every pod's data_volume_path fail runtimed's derivation).
	r := newRuntimedWith(rt, RuntimedConfig{
		NodeName:      guestNodeName,
		NodeIP:        guestNodeIP,
		Root:          root,
		ResolverVIP:   guestDNSVIP,
		ClusterDomain: "cluster.local",
		Network:       adapter,
	}, nil, nil)
	return &guestNode{r: r, adapter: adapter, ipam: ipam, vmb: vmb, images: images}
}

// vmPod is a vm-RuntimeClass pod in namespace ns. The namespace is load-bearing:
// the guest's search list is derived FROM it by dns.PodDNSConfig +
// dns.GuestResolvConfFields, so a namespace-specific search domain in the
// recorded VMSpec is a value no fake in this test could have supplied.
// Its container names guestVMImage and carries a command of its own, because
// both are what a vm pod must have to resolve at all: runtimed's mapper refuses
// an image this registry does not serve before the backend is reached, and the
// served image declares an entrypoint the pod's command replaces.
func vmPod(ns, name string) *corev1.Pod {
	vm := "vm"
	pod := hostPod(ns, name)
	pod.Spec.RuntimeClassName = &vm
	pod.Spec.Containers[0].Image = guestVMImage
	pod.Spec.Containers[0].Command = []string{"/bin/sleep", "3600"}
	return pod
}

// hostPod is the control: no runtimeClassName, so it resolves to the
// host-process backend. Its image is deliberately one testRegistry does not
// serve, so the pod stops at the pull — the step that proves the route.
func hostPod(ns, name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID("uid-" + name)},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "c0", Image: "registry/app:latest", Command: []string{"/app"}}},
		},
	}
}

// TestGuestNetworkWiredToRuntimed is the M11.4-a1 named gate for the B6 producer
// wiring: the k3sm provider produces a vm pod's guest network — podnet's
// allocation + NAT parameters and pkg/dns's resolv.conf, structured and rendered
// — BEFORE translation, and the adapter carries it to runtimed, which stamps it
// onto sandbox.VMSpec.Network for the vm backend.
//
// WHY IT IS NOT VACUOUS. The assertion is against the spec the vm backend
// RECEIVED at the far end of the real runtimed path, and the values asserted are
// ones only the producer could have made: the search list is derived from the
// POD'S NAMESPACE, and the PodIP is drawn from the node's real address pool. The
// test hands neither in at both ends. The negative leg then shows the producer is
// not simply consulted for everything, and the teardown leg shows the carrier has
// no lifetime of its own to leak from.
func TestGuestNetworkWiredToRuntimed(t *testing.T) {
	t.Parallel()

	t.Run("a vm pod's guest network reaches the vm backend as VMSpec.Network", func(t *testing.T) {
		n := newGuestNode(t)
		pod := vmPod("team-a", "guest")
		id := string(pod.UID)

		// The lab-gated CreateVM stub fails the pod AFTER recording the spec —
		// production's exact behaviour today, and orthogonal to what is asserted.
		if err := n.r.CreatePod(context.Background(), pod); err == nil {
			t.Fatal("CreatePod: want the lab-gated vm boot failure, got nil")
		}

		calls, spec := n.vmb.created()
		if calls != 1 {
			t.Fatalf("CreateVM called %d times, want exactly 1 — the pod must reach the vm backend", calls)
		}
		if spec.PodID != id {
			t.Errorf("VMSpec.PodID = %q, want %q", spec.PodID, id)
		}

		// The search list is the load-bearing assertion: dns.PodDNSConfig built it
		// from THIS pod's namespace and dns.GuestResolvConfFields normalized it.
		// Nothing else in this test knows the string "team-a.svc.cluster.local".
		wantSearch := []string{"team-a.svc.cluster.local", "svc.cluster.local", "cluster.local"}
		if !reflect.DeepEqual(spec.Network.Searches, wantSearch) {
			t.Errorf("VMSpec.Network.Searches = %v, want %v (the pod's namespace-scoped cluster search list)",
				spec.Network.Searches, wantSearch)
		}
		if want := []string{guestDNSVIP}; !reflect.DeepEqual(spec.Network.Nameservers, want) {
			t.Errorf("VMSpec.Network.Nameservers = %v, want %v", spec.Network.Nameservers, want)
		}
		if want := []string{"ndots:5"}; !reflect.DeepEqual(spec.Network.Options, want) {
			t.Errorf("VMSpec.Network.Options = %v, want %v", spec.Network.Options, want)
		}
		// The rendered form is carried BESIDE the structured one and must describe
		// the same configuration — asserted verbatim, since a guest that renders
		// its own resolv.conf and a host diagnostic that disagrees is the exact
		// divergence the shared normalization pass exists to prevent.
		wantResolv := "nameserver " + guestDNSVIP + "\n" +
			"search team-a.svc.cluster.local svc.cluster.local cluster.local\n" +
			"options ndots:5\n"
		if spec.Network.ResolvConf != wantResolv {
			t.Errorf("VMSpec.Network.ResolvConf =\n%q\nwant\n%q", spec.Network.ResolvConf, wantResolv)
		}

		// The pod IP came from the node's real 253-address pool, via SetupGuest —
		// not from the node IP, and not from the host-process Setup.
		allocated, ok := n.ipam.allocations()[id]
		if !ok {
			t.Fatal("no address allocated for the vm pod — SetupGuest never drew from the node pool")
		}
		if spec.Network.PodIP != allocated {
			t.Errorf("VMSpec.Network.PodIP = %v, want the allocated %v", spec.Network.PodIP, allocated)
		}
		if !netip.MustParsePrefix(guestPodCIDR).Contains(spec.Network.PodIP) {
			t.Errorf("VMSpec.Network.PodIP = %v, want an address inside the node podCIDR %s", spec.Network.PodIP, guestPodCIDR)
		}
		if spec.Network.PodIP.String() == guestNodeIP {
			t.Errorf("VMSpec.Network.PodIP = %v, want the guest's OWN address, not the node IP", spec.Network.PodIP)
		}
		// SetupGuest is consulted TWICE on the create path and both calls are for
		// THIS pod: podIP calls it to learn the /32 it publishes as the pod's
		// cluster identity, and buildBox calls it again immediately before
		// translation. What must hold is not a call count but IDEMPOTENCE — the
		// node pool holds exactly ONE address for the pod, asserted below, which
		// is the property a second allocation would break and a count assertion
		// would miss.
		guestCalls := n.ipam.guestSetupCalls()
		if len(guestCalls) == 0 {
			t.Errorf("SetupGuest calls = %v, want the vm pod's guest allocation to have been drawn", guestCalls)
		}
		for _, c := range guestCalls {
			if c != id {
				t.Errorf("SetupGuest called for %q, want only %q", c, id)
			}
		}
		if got := len(n.ipam.allocations()); got != 1 {
			t.Errorf("the node pool holds %d allocations, want exactly 1 — SetupGuest must be idempotent per podID", got)
		}
		// And no lo0 /32 was plumbed for it: a guest owns its address inside its
		// own netstack, so the host must never answer for it.
		if got := n.ipam.setupCalls(); len(got) != 0 {
			t.Errorf("host-process Setup was called %v for a vm pod — a guest gets no lo0 alias", got)
		}

		// The NAT advisory fields darwin-net composed reach the backend intact.
		if got, want := spec.Network.Gateway, netip.MustParseAddr(guestNATGw); got != want {
			t.Errorf("VMSpec.Network.Gateway = %v, want %v", got, want)
		}
		if got, want := spec.Network.NATSubnet, netip.MustParsePrefix(guestNATSubnet); got != want {
			t.Errorf("VMSpec.Network.NATSubnet = %v, want %v", got, want)
		}
		if got, want := spec.Network.DNSVIP, netip.MustParseAddr(guestDNSVIP); got != want {
			t.Errorf("VMSpec.Network.DNSVIP = %v, want %v", got, want)
		}
	})

	t.Run("a host-process pod never consults the guest producer", func(t *testing.T) {
		n := newGuestNode(t)
		pod := hostPod("team-a", "native")
		id := string(pod.UID)

		// It fails at the image pull — the first step PAST the vm/host-process
		// fork — which is what proves it took the host-process route at all.
		err := n.r.CreatePod(context.Background(), pod)
		if err == nil {
			t.Fatal("CreatePod: want the refused pull, got nil")
		}
		if got := n.images.pulled(); len(got) != 1 {
			t.Fatalf("puller saw %v, want exactly one pull — the pod must reach the host-process spine", got)
		}
		if calls, _ := n.vmb.created(); calls != 0 {
			t.Errorf("CreateVM called %d times for a host-process pod, want 0", calls)
		}
		if got := n.ipam.guestSetupCalls(); len(got) != 0 {
			t.Errorf("SetupGuest called %v for a host-process pod — it binds an lo0 /32 and reads no guest config", got)
		}
		if _, ok := n.adapter.GuestNetwork(id); ok {
			t.Error("the adapter holds a guest config for a host-process pod; GuestNetwork must report comma-ok false")
		}
		// Non-vacuity: the pod DID allocate through the host-process seam, so the
		// absence above is a routing fact, not a pod that allocated nothing.
		if got := n.ipam.setupCalls(); len(got) == 0 {
			t.Error("host-process Setup was never called; the control pod allocated nothing and proves nothing")
		}
	})

	t.Run("DeletePod clears the guest config and returns the address after a failed create", func(t *testing.T) {
		n := newGuestNode(t)
		pod := vmPod("team-a", "churn")
		id := string(pod.UID)

		// CreatePod fails at the lab-gated boot — AFTER SetupGuest allocated. This
		// is the leak shape: the pod never existed to runtimed, so only the
		// provider-side release can reclaim what the provider-side produce took.
		if err := n.r.CreatePod(context.Background(), pod); err == nil {
			t.Fatal("CreatePod: want the lab-gated vm boot failure, got nil")
		}
		if _, ok := n.adapter.GuestNetwork(id); !ok {
			t.Fatal("no guest config recorded for the vm pod; there is nothing for the teardown leg to clear")
		}
		before, ok := n.adapter.GuestNetwork(id)
		if !ok || !before.PodIP.IsValid() {
			t.Fatalf("recorded guest config = %+v, want one carrying the allocated pod IP", before)
		}

		if err := n.r.DeletePod(context.Background(), pod); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		if cfg, ok := n.adapter.GuestNetwork(id); ok {
			t.Errorf("the adapter still holds %+v for a deleted pod — the guest carrier leaked", cfg)
		}
		if _, ok := n.ipam.allocations()[id]; ok {
			t.Error("the pod's address was not released; a churned vm pod would burn one of the 253")
		}

		// A second delete is a no-op success (VK deletes are retried).
		if err := n.r.DeletePod(context.Background(), pod); err != nil {
			t.Errorf("second DeletePod: %v, want idempotent success", err)
		}
	})

	t.Run("pool exhaustion on the guest path reads the same as on the host path", func(t *testing.T) {
		n := newGuestNode(t)
		n.ipam.exhaust(t)

		err := n.r.CreatePod(context.Background(), vmPod("team-a", "late"))
		if err == nil {
			t.Fatal("CreatePod: want a pool-exhaustion failure, got nil")
		}
		if !errors.Is(err, podnet.ErrPoolExhausted) {
			t.Errorf("CreatePod error %v does not wrap podnet.ErrPoolExhausted; the sentinel must survive the guest path", err)
		}
		// The friendly clause is what an operator reads. It existed only inside
		// podIP before the guest path drew from the same pool.
		if want := "pod ip pool exhausted on node " + guestNodeName + " (253 pods/node)"; !strings.Contains(err.Error(), want) {
			t.Errorf("CreatePod error = %q, want it to name the exhaustion as %q", err, want)
		}
		if calls, _ := n.vmb.created(); calls != 0 {
			t.Errorf("CreateVM called %d times after a failed allocation, want 0 — the pod must not reach the backend", calls)
		}
	})
}

// podnetTestDNSConfig is the per-pod cluster DNS config the provider derives for
// a pod in namespace team-a — built through the SAME darwin-net producer the
// provider calls, so the adapter test cannot drift from what production feeds it.
func podnetTestDNSConfig() netv1.DNSConfig {
	return dns.PodDNSConfig(guestDNSVIP, "cluster.local", "team-a")
}

// TestPodNetAdapterGuestLifecycle pins the adapter half on its own: SetupGuest
// records, GuestNetwork serves comma-ok, and the ONE existing Teardown clears the
// record. It is deliberately separate from the wiring gate above — that gate
// would still pass if the config were cleared by some second, parallel lifecycle,
// and "no new leak surface" is a claim about there being exactly one.
func TestPodNetAdapterGuestLifecycle(t *testing.T) {
	t.Parallel()

	ipam := newFakeIPAM(t, guestPodCIDR)
	ipam.vm = podnet.VMNetworkConfig{DNSVIP: netip.MustParseAddr(guestDNSVIP)}
	a := NewPodNetAdapter(ipam, guestNodeIP, nil)
	dnsCfg := podnetTestDNSConfig()

	if _, ok := a.GuestNetwork("p1"); ok {
		t.Error("GuestNetwork reported a config for a pod that was never set up")
	}

	cfg, err := a.SetupGuest(context.Background(), "p1", dnsCfg)
	if err != nil {
		t.Fatalf("SetupGuest: %v", err)
	}
	got, ok := a.GuestNetwork("p1")
	if !ok {
		t.Fatal("GuestNetwork reported no config after SetupGuest")
	}
	if !reflect.DeepEqual(got, cfg) {
		t.Errorf("GuestNetwork = %+v, want the config SetupGuest returned %+v", got, cfg)
	}

	// Idempotent per podID: the second call returns the SAME address (the pod has
	// one identity), not a second draw from the pool.
	again, err := a.SetupGuest(context.Background(), "p1", dnsCfg)
	if err != nil {
		t.Fatalf("SetupGuest (repeat): %v", err)
	}
	if again.PodIP != cfg.PodIP {
		t.Errorf("repeat SetupGuest allocated %v, want the same address %v", again.PodIP, cfg.PodIP)
	}

	if err := a.Teardown("p1"); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if cfg, ok := a.GuestNetwork("p1"); ok {
		t.Errorf("GuestNetwork still serves %+v after Teardown — the guest record outlived the address it describes", cfg)
	}
	if _, ok := ipam.allocations()["p1"]; ok {
		t.Error("Teardown did not release the guest's address")
	}
	if err := a.Teardown("p1"); err != nil {
		t.Errorf("second Teardown: %v, want idempotent success", err)
	}
}
