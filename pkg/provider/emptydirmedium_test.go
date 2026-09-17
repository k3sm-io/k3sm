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
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"

	netv1 "k3sm.io/apis/net/v1"

	"k3sm.io/k3sm/pkg/runtimeclass"
)

// emptyDirPod builds a one-container pod carrying the given emptyDir volumes, in
// declaration order. The medium strings are passed as the API's own
// corev1.StorageMedium so a row can name a value upstream validates ("Memory",
// "HugePages-2Mi") without this fixture re-deciding which ones are legal.
func emptyDirPod(name string, media ...string) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name, UID: types.UID("uid-" + name)},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "c0", Image: "registry/web:1", Command: []string{"/web"}},
			},
		},
	}
	for i, m := range media {
		pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
			Name: emptyDirVolumeNames[i],
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMedium(m)},
			},
		})
	}
	return pod
}

// emptyDirVolumeNames are stable per-index volume names, so a row can assert
// WHICH volume the refusal named rather than that some volume was named.
var emptyDirVolumeNames = []string{"vol-a", "vol-b", "vol-c"}

// TestTranslateEmptyDirMemoryMedium is the gate for the native path's emptyDir
// medium verdict: a NATIVE pod asking for any non-empty medium is refused at
// CreatePod, before the runtimed RPC, with a Warning Event that names the volume.
//
// WHY A REFUSAL IS THE ASSERTED BEHAVIOR: native pods have no mount namespace and
// no tmpfs, and runtimed's native materialize has no Medium branch — it returns an
// ordinary directory on disk. Before this gate, a pod asking for `medium: Memory`
// got that disk directory with no error, no Event, and no status field to notice
// it by, which is a lie the workload cannot detect.
//
// BOTH LEGS ARE LOAD-BEARING, and the accept leg is the one that decays silently:
// a check exercised only on its reject leg degrades into a refuse-everything gate
// that would make every ordinary emptyDir pod unschedulable. So each row asserts
// the CreatePod RPC count in both directions: 0 when refused, 1 when admitted.
//
// The vm rows are not a courtesy: the medium verdict belongs to the backend that
// will run the pod, and the vm path's share plan classifies `medium: Memory` as a
// real guest tmpfs. A check that read pod.Spec.RuntimeClassName, or that ignored
// the backend entirely, would refuse a pod the vm guest serves correctly.
func TestTranslateEmptyDirMemoryMedium(t *testing.T) {
	t.Parallel()

	const (
		native = "" // no runtimeClassName ⇒ SANDBOX_BACKEND_UNSPECIFIED ⇒ a native rung
		vm     = runtimeclass.Name
	)

	tests := []struct {
		name         string
		media        []string // one emptyDir volume per element, in order
		runtimeClass string
		wantRejected bool
		wantVolume   string // the volume the refusal must name
		wantMedium   string // the medium the refusal must echo
	}{
		// ---- accept leg -------------------------------------------------------
		{
			// No volumes at all: the overwhelmingly common pod, untouched.
			name: "no_volumes_admitted", runtimeClass: native,
		},
		{
			// The DEFAULT medium is the empty string, and it is the ONE value the
			// native path can serve honestly: an ordinary disk-backed directory is
			// exactly what upstream promises for it.
			name: "native_default_medium_admitted", media: []string{""}, runtimeClass: native,
		},
		{
			// The vm backend owns its own classification: its guest has a Linux tmpfs,
			// so Memory is honoured there and must not be refused here.
			name: "vm_memory_admitted", media: []string{"Memory"}, runtimeClass: vm,
		},
		{
			// Whatever the vm path decides about HugePages, it decides it — this
			// provider-side gate is native-only and must not pre-empt it.
			name: "vm_hugepages_untouched", media: []string{"HugePages"}, runtimeClass: vm,
		},

		// ---- reject leg -------------------------------------------------------
		{
			name: "native_memory_refused", media: []string{"Memory"}, runtimeClass: native,
			wantRejected: true, wantVolume: "vol-a", wantMedium: "Memory",
		},
		{
			// The check is a CLOSED SET on the empty medium, not a Memory special
			// case: HugePages has no native implementation either, and admitting it
			// would restore the silent disk-backing for every medium but one.
			name: "native_hugepages_refused", media: []string{"HugePages"}, runtimeClass: native,
			wantRejected: true, wantVolume: "vol-a", wantMedium: "HugePages",
		},
		{
			name: "native_hugepages_sized_refused", media: []string{"HugePages-2Mi"}, runtimeClass: native,
			wantRejected: true, wantVolume: "vol-a", wantMedium: "HugePages-2Mi",
		},
		{
			// A pod mixing an ordinary emptyDir with a memory-backed one is refused,
			// and the Event names the OFFENDING volume — not the first volume, and
			// not "a volume". An operator with three scratch mounts cannot act on the
			// latter.
			name: "native_first_offender_named", media: []string{"", "Memory", "Memory"}, runtimeClass: native,
			wantRejected: true, wantVolume: "vol-b", wantMedium: "Memory",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &platformFake{
				fakeRuntimeServer: newFakeRuntimeServer(),
				info:              capabilityInfo(NodeCapabilities{VMBackend: true}),
			}
			rec := record.NewFakeRecorder(8)
			r := newRuntimedWith(f, RuntimedConfig{
				NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: t.TempDir(), Recorder: rec,
			}, nil, nil)

			pod := emptyDirPod("scratch", tc.media...)
			if tc.runtimeClass != "" {
				rc := tc.runtimeClass
				pod.Spec.RuntimeClassName = &rc
			}

			err := r.CreatePod(context.Background(), pod)
			_, createCalls := f.counts()

			if !tc.wantRejected {
				if err != nil {
					t.Fatalf("CreatePod = %v, want the pod admitted (a reject-only gate is a refuse-everything gate)", err)
				}
				if createCalls != 1 {
					t.Errorf("CreatePod RPC calls = %d, want 1 — an admitted pod must reach runtimed", createCalls)
				}
				if ev := nextLifecycleEvent(rec.Events, 0); strings.Contains(ev, reasonFailedEmptyDirMedium) {
					t.Errorf("admitted pod recorded %q, want no %s event", ev, reasonFailedEmptyDirMedium)
				}
				return
			}

			if err == nil {
				t.Fatal("CreatePod = nil error, want a refusal — a silently disk-backed medium is undetectable to the workload")
			}
			if !errors.Is(err, ErrEmptyDirMediumUnsupported) {
				t.Errorf("CreatePod error %v does not wrap ErrEmptyDirMediumUnsupported; a caller cannot tell it from a transient failure", err)
			}
			if !strings.Contains(err.Error(), tc.wantVolume) {
				t.Errorf("CreatePod error %q does not name volume %q", err, tc.wantVolume)
			}
			if createCalls != 0 {
				t.Errorf("CreatePod RPC calls = %d, want 0 — the refusal must land BEFORE the RPC", createCalls)
			}
			if r.trackByID(string(pod.UID)) != nil {
				t.Error("a refused pod was tracked; it must leave no bookkeeping behind")
			}

			var ev string
			select {
			case ev = <-rec.Events:
			default:
				t.Fatal("no Event recorded; on a headless Mac `kubectl describe pod` is the operator's only diagnostic surface")
			}
			if !strings.HasPrefix(ev, corev1.EventTypeWarning+" "+reasonFailedEmptyDirMedium+" ") {
				t.Errorf("Event = %q, want a %s %s event", ev, corev1.EventTypeWarning, reasonFailedEmptyDirMedium)
			}
			if !strings.Contains(ev, tc.wantVolume) {
				t.Errorf("Event %q does not name the offending volume %q", ev, tc.wantVolume)
			}
			if !strings.Contains(ev, tc.wantMedium) {
				t.Errorf("Event %q does not echo the medium %q", ev, tc.wantMedium)
			}
			// Both ways out, on the pod itself: a refusal an operator cannot act on
			// is only marginally better than the silence it replaced.
			if !strings.Contains(ev, "runtimeClassName: "+runtimeclass.Name) {
				t.Errorf("Event %q does not point at the %s RuntimeClass, which does honour medium: Memory", ev, runtimeclass.Name)
			}
			if !strings.Contains(ev, "medium") {
				t.Errorf("Event %q does not name the field to remove", ev)
			}
		})
	}
}

// TestPreflightEmptyDirMediumReadsTheBoxBackend pins the ONE fact the refusal's
// scope depends on: the verdict is taken from the backend toPodBox already
// resolved onto the box, not from pod.Spec.RuntimeClassName. The two agree today,
// so no CreatePod-level row can tell them apart — this one can, by handing the
// preflight a native pod spec carrying a vm box and vice versa.
//
// It matters because the RuntimeClass→backend table lives in apis
// (DefaultHandlerConfig) and is what runtimed will actually enforce. A
// provider-side string comparison against "vm" would be a second, divergeable
// answer to "is this pod native", and the divergence would surface as a pod
// refused for a medium its guest serves.
func TestPreflightEmptyDirMediumReadsTheBoxBackend(t *testing.T) {
	t.Parallel()

	newRuntime := func() (*runtimedRuntime, *record.FakeRecorder) {
		rec := record.NewFakeRecorder(4)
		r := newRuntimedWith(newFakeRuntimeServer(), RuntimedConfig{
			NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: t.TempDir(), Recorder: rec,
		}, nil, nil)
		return r, rec
	}

	// A pod whose spec says vm, handed a box resolved to a NATIVE backend: the box
	// wins, so it is refused.
	t.Run("native_box_refuses_a_vm_named_pod", func(t *testing.T) {
		t.Parallel()
		r, _ := newRuntime()
		pod := emptyDirPod("mixed", "Memory")
		rc := runtimeclass.Name
		pod.Spec.RuntimeClassName = &rc
		nativeBox, err := toPodBox(emptyDirPod("mixed", "Memory"), "10.42.0.7", "192.168.1.10", t.TempDir(), "", netv1.DNSConfig{}, nil)
		if err != nil {
			t.Fatalf("toPodBox: %v", err)
		}
		if err := r.preflightEmptyDirMedium(pod, nativeBox); !errors.Is(err, ErrEmptyDirMediumUnsupported) {
			t.Errorf("preflightEmptyDirMedium = %v, want the box's native backend to decide", err)
		}
	})

	// The mirror: a pod whose spec names no RuntimeClass, handed a box resolved to
	// the VM backend. The box wins again, so it is admitted.
	t.Run("vm_box_admits_an_unclassed_pod", func(t *testing.T) {
		t.Parallel()
		r, _ := newRuntime()
		vmPod := emptyDirPod("guest", "Memory")
		rc := runtimeclass.Name
		vmPod.Spec.RuntimeClassName = &rc
		vmBox, err := toPodBox(vmPod, "10.42.0.7", "192.168.1.10", t.TempDir(), "", netv1.DNSConfig{}, nil)
		if err != nil {
			t.Fatalf("toPodBox: %v", err)
		}
		if err := r.preflightEmptyDirMedium(emptyDirPod("guest", "Memory"), vmBox); err != nil {
			t.Errorf("preflightEmptyDirMedium = %v, want nil — the vm path owns its own medium verdict", err)
		}
	})
}
