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
	"log/slog"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
)

// terminalUpdateFixture is a provider with a real reference manager, a fake
// IPAM and an interconnect attacher, so every resource UpdatePod could acquire
// is observable, and a pod with an interconnect annotation in the apiserver.
type terminalUpdateFixture struct {
	r       *runtimedRuntime
	f       *fakeRuntimeServer
	ipam    *fakeIPAM
	aliases *fakeAliases
	src     *switchSource
	pod     *corev1.Pod
}

func newTerminalUpdateFixture(t *testing.T, s hostStats) *terminalUpdateFixture {
	t.Helper()
	ctx := context.Background()
	pod := evPod("terminal", nil, "", "")
	pod.Annotations = map[string]string{netv1alpha1.AnnotationInterconnects: netv1alpha1.MediumThunderbolt}
	cs := fake.NewClientset()
	if _, err := cs.CoreV1().Pods(pod.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("apiserver create: %v", err)
	}
	f := newFakeRuntimeServer()
	aliases := &fakeAliases{}
	ipam := newFakeIPAM(t, "100.64.0.0/24")
	refs := newPodRefManager(cs, clock.RealClock{}, slog.New(slog.DiscardHandler))
	desired := desiredValue(t, netv1alpha1.InterconnectFallbackNetwork, []string{pod.Namespace})
	r := newRuntimedWith(f, RuntimedConfig{
		NodeName: "n", NodeIP: testNodeIP, Root: t.TempDir(), PodLogsDir: t.TempDir(),
		Client: cs, Recorder: record.NewFakeRecorder(200),
		Network:      NewPodNetAdapter(ipam, testNodeIP, nil),
		Interconnect: InterconnectConfig{Aliases: aliases, Desired: func() (string, bool) { return desired, true }},
	}, newKubeResolver(cs, refs), slog.New(slog.DiscardHandler))
	src := &switchSource{s: s}
	r.setAdmissionSource(src)
	return &terminalUpdateFixture{r: r, f: f, ipam: ipam, aliases: aliases, src: src, pod: pod}
}

// ipamSetups is how many times the pod network was asked for an address.
func (x *terminalUpdateFixture) ipamSetups() int {
	x.ipam.mu.Lock()
	defer x.ipam.mu.Unlock()
	return len(x.ipam.setups)
}

// registeredRefs reports the pod's reference set, and whether it has one.
func (x *terminalUpdateFixture) registeredRefs() (int, bool) {
	x.r.refs.mu.Lock()
	defer x.r.refs.mu.Unlock()
	set, ok := x.r.refs.byPod[x.pod.UID]
	return len(set), ok
}

// terminalUpdates are the spec edits that make virtual-kubelet's podsEqual
// differ and so reach UpdatePod. The configMap volume adds a reference, so a
// re-registration of an already registered pod shows in its set.
func terminalUpdates() []struct {
	name string
	edit func(*corev1.Pod)
} {
	return []struct {
		name string
		edit func(*corev1.Pod)
	}{
		{"a changed label", func(p *corev1.Pod) { p.Labels = map[string]string{"edited": "yes"} }},
		{"a changed annotation", func(p *corev1.Pod) { p.Annotations["edited"] = "yes" }},
		{"a changed image", func(p *corev1.Pod) { p.Spec.Containers[0].Image = "registry/edited:2" }},
		{"a changed toleration", func(p *corev1.Pod) {
			p.Spec.Tolerations = []corev1.Toleration{{Key: "edited", Operator: corev1.TolerationOpExists}}
		}},
		{"a new reference", func(p *corev1.Pod) {
			p.Spec.Volumes = []corev1.Volume{{Name: "v", VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "edited"}},
			}}}
		}},
	}
}

// TestUpdatePodOnRejectedTrackAcquiresNothing: virtual-kubelet calls UpdatePod
// for a refused pod whose spec differs from the tracked one, and a refused
// pod's delete frees nothing. An update must therefore acquire nothing: no /32
// and lo0 alias, no interconnect attach, no reference registration, no runtime
// call. Fails when UpdatePod registers and allocates before looking at the
// track: the lease and the references stay held until the daemon restarts.
//
// The evicted cases: runtimed already forgot an evicted pod, so an update could
// only fail in the runtime and be returned to virtual-kubelet. What the pod
// holds is DeletePod's to free, so the update leaves it exactly as it was.
func TestUpdatePodOnRejectedTrackAcquiresNothing(t *testing.T) {
	ctx := context.Background()
	for _, tc := range terminalUpdates() {
		t.Run("refused, "+tc.name, func(t *testing.T) {
			x := newTerminalUpdateFixture(t, compressorAt(85))
			id := string(x.pod.UID)
			if err := x.r.CreatePod(ctx, x.pod.DeepCopy()); err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			tr := x.r.trackByID(id)
			if tr == nil || !tr.rejected {
				t.Fatalf("setup: the pod was not refused (%s)", trackState(tr))
			}

			updated := x.pod.DeepCopy()
			tc.edit(updated)
			if err := x.r.UpdatePod(ctx, updated); err != nil {
				t.Errorf("UpdatePod = %v, want nil", err)
			}

			if ip, ok := x.ipam.allocations()[id]; ok {
				t.Errorf("the update allocated /32 %s and its lo0 alias", ip)
			}
			if n := x.ipamSetups(); n != 0 {
				t.Errorf("pod network setups = %d, want 0", n)
			}
			if rec := x.r.interconnect.record(id); rec != nil {
				t.Errorf("the update attached the interconnect (%+v)", rec)
			}
			if n := attachedSlots(x.r.interconnect); n != 0 {
				t.Errorf("interconnect slots held = %d, want 0", n)
			}
			if ensured, _ := x.aliases.calls(); len(ensured) != 0 {
				t.Errorf("interconnect aliases ensured %v, want none", ensured)
			}
			if _, registered := x.registeredRefs(); registered {
				t.Error("the update registered the refused pod's references")
			}
			if n := x.f.updateCount(); n != 0 {
				t.Errorf("runtime UpdatePod calls = %d, want 0", n)
			}
			if n := x.f.createCount(); n != 0 {
				t.Errorf("runtime CreatePod calls = %d, want 0", n)
			}
			if got := x.r.trackByID(id); got != tr || !got.rejected {
				t.Errorf("the refusal did not stand (%s)", trackState(got))
			}
		})
	}
	for _, tc := range terminalUpdates() {
		t.Run("evicted, "+tc.name, func(t *testing.T) {
			x := newTerminalUpdateFixture(t, compressorAt(10))
			id := string(x.pod.UID)
			if err := x.r.CreatePod(ctx, x.pod.DeepCopy()); err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			if err := x.r.evictPod(ctx, x.pod, evictionNotice{signal: signalCompressor, message: "evicted for the test"}); err != nil {
				t.Fatalf("evictPod: %v", err)
			}
			tr := x.r.trackByID(id)
			if tr == nil || tr.evictedStatus() == nil {
				t.Fatalf("setup: the pod is not evicted (%s)", trackState(tr))
			}
			setups := x.ipamSetups()
			refs, registered := x.registeredRefs()

			updated := x.pod.DeepCopy()
			tc.edit(updated)
			if err := x.r.UpdatePod(ctx, updated); err != nil {
				t.Errorf("UpdatePod = %v, want nil", err)
			}

			if n := x.f.updateCount(); n != 0 {
				t.Errorf("runtime UpdatePod calls = %d, want 0", n)
			}
			if n := x.ipamSetups(); n != setups {
				t.Errorf("pod network setups = %d, want the create's %d", n, setups)
			}
			if gotRefs, gotRegistered := x.registeredRefs(); gotRefs != refs || gotRegistered != registered {
				t.Errorf("references = %d/%v, want the create's %d/%v", gotRefs, gotRegistered, refs, registered)
			}
			if got := x.r.trackByID(id); got != tr || got.evictedStatus() == nil {
				t.Errorf("the eviction did not stand (%s)", trackState(got))
			}
		})
	}
}
