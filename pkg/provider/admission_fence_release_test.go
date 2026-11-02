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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
)

// TestCreatePodFencedByRejectionReleasesNetworkAndRefs: a BestEffort pod with
// an interconnect runs on a calm node. A repeat create of it is admitted (the
// pod has a live track) and held inside the admission window; the pod is then
// deleted, which forgets its track, and pressure rises before a third create
// decides.
//
// "a re-create's in-flight count keeps the refusal off": the held re-create
// holds an in-flight count like a first create does, so the third create
// yields instead of refusing. Fails when admitOnCreate takes no count on the
// prior-live-track branch: the third create installs the rejected track.
//
// "a refusal that lands anyway is released at the fence": the count is dropped
// by hand, so the refusal lands. The held create then acquires the pod's /32
// (with its lo0 alias in the adapter), its interconnect slot and its
// references before it reaches the terminal-track fence, and the fence must
// release all of them, because a rejected track's delete frees nothing. Fails
// without that release: the lease, the slot and the references stay held.
func TestCreatePodFencedByRejectionReleasesNetworkAndRefs(t *testing.T) {
	for _, tc := range []struct {
		name         string
		dropInFlight bool
	}{
		{name: "a re-create's in-flight count keeps the refusal off"},
		{name: "a refusal that lands anyway is released at the fence", dropInFlight: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			pod := evPod("fenced", nil, "", "")
			pod.Annotations = map[string]string{netv1alpha1.AnnotationInterconnects: netv1alpha1.MediumThunderbolt}
			id := string(pod.UID)

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
			src := &switchSource{s: compressorAt(10)}
			r.setAdmissionSource(src)

			if err := r.CreatePod(ctx, pod.DeepCopy()); err != nil {
				t.Fatalf("create 1: %v", err)
			}
			if _, ok := ipam.allocations()[id]; !ok {
				t.Fatal("create 1 allocated no /32")
			}
			if rec := r.interconnect.record(id); rec == nil || !rec.attached {
				t.Fatalf("create 1 attached no interconnect slot (%+v)", rec)
			}

			entered, release := holdFirstAdmitted(r)
			held := make(chan error, 1)
			go func() { held <- r.CreatePod(ctx, pod.DeepCopy()) }()
			awaitClosed(t, entered, "the re-create to reach the admission window")

			if err := r.DeletePod(ctx, pod.DeepCopy()); err != nil {
				t.Fatalf("DeletePod: %v", err)
			}
			if tr := r.trackByID(id); tr != nil {
				t.Fatalf("the delete left a track (%s)", trackState(tr))
			}
			if tc.dropInFlight {
				r.admitDone(id)
			}
			src.set(compressorAt(85))
			if err := r.CreatePod(ctx, pod.DeepCopy()); err != nil {
				t.Fatalf("create 3: %v", err)
			}
			tr := r.trackByID(id)
			if !tc.dropInFlight {
				if tr != nil && (tr.rejected || tr.evictedStatus() != nil) {
					t.Fatalf("create 3 refused the pod while the re-create was in flight (%s)", trackState(tr))
				}
				close(release)
				if err := awaitErr(t, held, "the re-create"); err != nil {
					t.Fatalf("re-create: %v", err)
				}
				return
			}
			if tr == nil || !tr.rejected {
				t.Fatalf("create 3 under pressure did not refuse the pod (%s)", trackState(tr))
			}
			close(release)
			if err := awaitErr(t, held, "the re-create"); err != nil {
				t.Fatalf("re-create: %v", err)
			}

			if tr := r.trackByID(id); tr == nil || !tr.rejected {
				t.Fatalf("the refusal did not stand (%s)", trackState(tr))
			}
			if ip, ok := ipam.allocations()[id]; ok {
				t.Errorf("the fenced create kept the /32 %s and its lo0 alias", ip)
			}
			if rec := r.interconnect.record(id); rec != nil {
				t.Errorf("the fenced create kept its interconnect attach (%+v)", rec)
			}
			if n := attachedSlots(r.interconnect); n != 0 {
				t.Errorf("interconnect slots held = %d, want 0", n)
			}
			ensured, removed := aliases.calls()
			if len(removed) != len(ensured) {
				t.Errorf("interconnect aliases ensured %v, removed %v: the fenced create's alias stayed", ensured, removed)
			}
			r.refs.mu.Lock()
			_, registered := r.refs.byPod[pod.UID]
			r.refs.mu.Unlock()
			if registered {
				t.Error("the fenced create kept the pod's reference registration")
			}
			r.mu.Lock()
			n := r.admitting[id]
			r.mu.Unlock()
			if n != 0 {
				t.Errorf("in-flight admitted creates after all returned = %d, want 0", n)
			}
		})
	}
}
