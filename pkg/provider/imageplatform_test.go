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
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"

	netv1 "k3sm.io/apis/net/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/runtimeclass"
	runtimed "k3sm.io/runtimed/pkg/runtime"
)

// platformPod is a pod with two init containers and two regular containers, so
// the POD-LEVEL annotation's "applies to every container" contract is observable
// rather than assumed from a single-container fixture.
func platformPod(annotation string) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "multi", UID: types.UID("uid-multi")},
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{
				{Name: "i0", Image: "registry/init0:1", Command: []string{"/i0"}},
				{Name: "i1", Image: "registry/init1:1", Command: []string{"/i1"}},
			},
			Containers: []corev1.Container{
				{Name: "c0", Image: "registry/web:1", Command: []string{"/web"}},
				{Name: "c1", Image: "registry/side:1", Command: []string{"/side"}},
			},
		},
	}
	if annotation != "" {
		pod.Annotations = map[string]string{runtimev1.AnnotationImagePlatform: annotation}
	}
	return pod
}

// translatePlatformPod runs the REAL translation (toPodBox), so the stamp is
// asserted where it actually happens rather than through a helper called
// directly.
func translatePlatformPod(t *testing.T, pod *corev1.Pod) (*runtimev1.PodBox, error) {
	t.Helper()
	return toPodBox(pod, "10.42.0.7", "192.168.1.10", t.TempDir(), "", netv1.DNSConfig{}, nil)
}

// TestImagePlatformAnnotationStampsContainers is the M11.4-d3 stamp gate: the
// pod-level k3sm.io/image-platform annotation is parsed ONCE, provider-side, into
// the TYPED runtimev1.Platform message and stamped onto every container.
//
// What each group of rows exists to prove:
//
//   - absent — no annotation stamps NOTHING. An absent override means "apply the
//     node's default policy" on the wire (apis Container.image_platform), so a
//     synthesized default here would freeze a provider-side guess into the
//     contract.
//   - valid — the stamped value is the NORMALIZED message, not a string
//     round-trip: os/arch/variant are separate typed fields, tokens are
//     lowercased, and the one OCI equivalence k3sm honours (arm64 with an empty
//     variant IS arm64/v8) has been applied. A downstream reader must never have
//     to re-parse or re-normalize.
//   - malformed — FAILS the pod closed, naming the annotation. A pod that asked
//     for a platform and silently got the node's default would run the wrong
//     binaries with no signal anywhere.
func TestImagePlatformAnnotationStampsContainers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		annotation string
		want       *runtimev1.Platform // nil ⇒ expect no stamp
		wantErr    bool
	}{
		// absent
		{name: "absent", annotation: ""},

		// valid
		{
			name:       "linux_amd64",
			annotation: "linux/amd64",
			want:       &runtimev1.Platform{Os: "linux", Architecture: "amd64"},
		},
		{
			// The normalization that matters: an arm64 with NO variant is arm64/v8.
			// Without it the stamped message would never equal a candidate.
			name:       "linux_arm64_gains_v8_variant",
			annotation: "linux/arm64",
			want:       &runtimev1.Platform{Os: "linux", Architecture: "arm64", Variant: "v8"},
		},
		{
			name:       "darwin_arm64_explicit_v8",
			annotation: "darwin/arm64/v8",
			want:       &runtimev1.Platform{Os: "darwin", Architecture: "arm64", Variant: "v8"},
		},
		{
			name:       "case_and_space_folded",
			annotation: "  Darwin/AMD64  ",
			want:       &runtimev1.Platform{Os: "darwin", Architecture: "amd64"},
		},

		// malformed — every shape fails CLOSED
		{name: "malformed_empty", annotation: " ", wantErr: true},
		{name: "malformed_os_only", annotation: "linux", wantErr: true},
		{name: "malformed_too_many_parts", annotation: "linux/arm64/v8/extra", wantErr: true},
		{name: "malformed_empty_os", annotation: "/amd64", wantErr: true},
		{name: "malformed_empty_variant", annotation: "linux/amd64/", wantErr: true},
		{name: "malformed_control_bytes", annotation: "linux/amd64\nInjected: yes", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pod := platformPod(tc.annotation)
			// An empty-string annotation value must still be treated as PRESENT —
			// the key exists, so it is a malformed value, not an absent override.
			if tc.name == "absent" {
				if _, ok := pod.Annotations[runtimev1.AnnotationImagePlatform]; ok {
					t.Fatal("fixture set the annotation for the absent case")
				}
			}
			box, err := translatePlatformPod(t, pod)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("toPodBox(%q) = nil error, want a fail-closed rejection", tc.annotation)
				}
				if !strings.Contains(err.Error(), runtimev1.AnnotationImagePlatform) {
					t.Errorf("error %q does not name the annotation %s; an operator cannot act on it",
						err, runtimev1.AnnotationImagePlatform)
				}
				return
			}
			if err != nil {
				t.Fatalf("toPodBox(%q): %v", tc.annotation, err)
			}
			assertStamped(t, box, tc.want)
		})
	}

	// The pod-level contract, asserted across BOTH container lists at once: every
	// init container and every regular container carries the SAME value. A stamp
	// that reached only box.Containers would leave an init container pulling the
	// node default and the mains pulling the override — one pod, two platforms,
	// which is exactly what the pod-level annotation forbids.
	t.Run("multi_container_all_stamped", func(t *testing.T) {
		t.Parallel()
		box, err := translatePlatformPod(t, platformPod("linux/amd64"))
		if err != nil {
			t.Fatalf("toPodBox: %v", err)
		}
		if got := len(box.GetInitContainers()); got != 2 {
			t.Fatalf("init containers = %d, want 2 (fixture)", got)
		}
		if got := len(box.GetContainers()); got != 2 {
			t.Fatalf("containers = %d, want 2 (fixture)", got)
		}
		assertStamped(t, box, &runtimev1.Platform{Os: "linux", Architecture: "amd64"})
	})
}

// assertStamped checks every container of the box against want (nil ⇒ no stamp),
// comparing the TYPED message field by field — never a rendered string, which
// would pass for a value that had been round-tripped through one.
func assertStamped(t *testing.T, box *runtimev1.PodBox, want *runtimev1.Platform) {
	t.Helper()
	check := func(kind string, cs []*runtimev1.Container) {
		for _, c := range cs {
			got := c.GetImagePlatform()
			if want == nil {
				if got != nil {
					t.Errorf("%s %s: image_platform = %+v, want nil (no override)", kind, c.GetName(), got)
				}
				continue
			}
			if got == nil {
				t.Errorf("%s %s: image_platform is nil, want %+v", kind, c.GetName(), want)
				continue
			}
			if got.GetOs() != want.GetOs() || got.GetArchitecture() != want.GetArchitecture() ||
				got.GetVariant() != want.GetVariant() || got.GetOsVersion() != "" {
				t.Errorf("%s %s: image_platform = {os:%q arch:%q variant:%q osVersion:%q}, want {os:%q arch:%q variant:%q osVersion:\"\"}",
					kind, c.GetName(), got.GetOs(), got.GetArchitecture(), got.GetVariant(), got.GetOsVersion(),
					want.GetOs(), want.GetArchitecture(), want.GetVariant())
			}
		}
	}
	check("init container", box.GetInitContainers())
	check("container", box.GetContainers())
}

// platformFake is the recording runtime seam for the preflight gate: it serves a
// canned GetRuntimeInfo (the node-capability probe) and COUNTS CreatePod RPCs, so
// "the RPC was never reached" is an assertion rather than an inference from an
// error string. Everything else is inherited from fakeRuntimeServer.
type platformFake struct {
	*fakeRuntimeServer

	mu          sync.Mutex
	info        *runtimev1.GetRuntimeInfoResponse
	infoCalls   int
	createCalls int
}

func (f *platformFake) GetRuntimeInfo(context.Context, *runtimev1.GetRuntimeInfoRequest) (*runtimev1.GetRuntimeInfoResponse, error) {
	f.mu.Lock()
	f.infoCalls++
	f.mu.Unlock()
	return f.info, nil
}

func (f *platformFake) CreatePod(ctx context.Context, req *runtimev1.CreatePodRequest) (*runtimev1.CreatePodResponse, error) {
	f.mu.Lock()
	f.createCalls++
	f.mu.Unlock()
	return f.fakeRuntimeServer.CreatePod(ctx, req)
}

func (f *platformFake) counts() (info, create int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.infoCalls, f.createCalls
}

// capabilityInfo renders the GetRuntimeInfo response advertising exactly caps,
// through the runtimed condition-type constants the provider's mapper reads — a
// producer/consumer rename must be a compile error here, never a silently
// unadvertised capability.
func capabilityInfo(caps NodeCapabilities) *runtimev1.GetRuntimeInfoResponse {
	status := func(b bool) runtimev1.ConditionStatus {
		if b {
			return runtimev1.ConditionStatus_CONDITION_STATUS_TRUE
		}
		return runtimev1.ConditionStatus_CONDITION_STATUS_FALSE
	}
	return &runtimev1.GetRuntimeInfoResponse{
		Healthy: true,
		Conditions: []*runtimev1.RuntimeCondition{
			{Type: runtimed.ConditionVMBackendAvailable, Status: status(caps.VMBackend), Reason: "Test"},
			{Type: runtimed.ConditionRosettaHostAvailable, Status: status(caps.RosettaHost), Reason: "Test"},
			{Type: runtimed.ConditionRosettaGuestAvailable, Status: status(caps.RosettaGuest), Reason: "Test"},
		},
	}
}

// TestImagePlatformPreflightFailsClosed is the M11.4-d3 pre-RPC gate: a pod whose
// k3sm.io/image-platform annotation names a platform this node's capabilities
// cannot serve is refused BEFORE runtimed is asked to create it, with a Warning
// Event naming the missing capability label.
//
// BOTH LEGS ARE LOAD-BEARING. A fail-closed check exercised only on its reject
// leg silently degrades into a fail-ALWAYS one, which would make every annotated
// pod unschedulable on every node — a strictly worse outcome than the gap it
// closes. So each row asserts the CreatePod RPC count in both directions: 0 when
// refused, 1 when admitted.
func TestImagePlatformPreflightFailsClosed(t *testing.T) {
	t.Parallel()

	const (
		native = "" // no runtimeClassName ⇒ SANDBOX_BACKEND_UNSPECIFIED ⇒ a native rung
		vm     = runtimeclass.Name
	)

	tests := []struct {
		name         string
		annotation   string
		runtimeClass string
		caps         NodeCapabilities
		wantRejected bool
		wantLabel    string // the capability label the Event must name ("" ⇒ none exists)
		wantProbe    bool   // whether the node-capability RPC should have been made
	}{
		// ---- accept leg -------------------------------------------------------
		{
			// No annotation: no override, no capability probe, straight through.
			name: "unannotated_admitted_without_a_probe", annotation: "", runtimeClass: native,
			caps: NodeCapabilities{}, wantProbe: false,
		},
		{
			name: "native_arm64_admitted", annotation: "darwin/arm64", runtimeClass: native,
			caps: NodeCapabilities{}, wantProbe: true,
		},
		{
			// The node advertises k3sm.io/rosetta, so the host CAN translate the
			// annotated darwin/amd64 payload — admitted, RPC reached.
			name: "native_amd64_admitted_with_host_rosetta", annotation: "darwin/amd64", runtimeClass: native,
			caps: NodeCapabilities{RosettaHost: true}, wantProbe: true,
		},
		{
			name: "vm_arm64_admitted", annotation: "linux/arm64/v8", runtimeClass: vm,
			caps: NodeCapabilities{VMBackend: true}, wantProbe: true,
		},
		{
			// BOTH conjuncts present ⇒ the node carries k3sm.io/rosetta-linux ⇒
			// linux/amd64 is servable. The positive half of the conjunction row below.
			name: "vm_amd64_admitted_with_both_conjuncts", annotation: "linux/amd64", runtimeClass: vm,
			caps: NodeCapabilities{VMBackend: true, RosettaGuest: true}, wantProbe: true,
		},

		// ---- reject leg -------------------------------------------------------
		{
			name: "native_amd64_refused_without_host_rosetta", annotation: "darwin/amd64", runtimeClass: native,
			caps: NodeCapabilities{}, wantRejected: true, wantLabel: runtimeclass.LabelRosetta, wantProbe: true,
		},
		{
			// THE CONJUNCTION ROW. Guest Rosetta is available but there is no vm
			// backend to run a guest in, so k3sm.io/rosetta-linux is NOT carried and
			// linux/amd64 is NOT servable. Collapsing the label to the guest bool
			// alone is the specific bug this row exists to catch.
			name: "vm_amd64_refused_when_guest_rosetta_without_vm_backend", annotation: "linux/amd64", runtimeClass: vm,
			caps:         NodeCapabilities{VMBackend: false, RosettaGuest: true},
			wantRejected: true, wantLabel: runtimeclass.LabelRosettaLinux, wantProbe: true,
		},
		{
			// Every capability advertised, and still refused: a native pod cannot run
			// a LINUX payload at all. No capability label grants it, so the message
			// must not invent one to name.
			name: "native_pod_refused_for_a_linux_platform", annotation: "linux/arm64", runtimeClass: native,
			caps:         NodeCapabilities{VMBackend: true, RosettaHost: true, RosettaGuest: true},
			wantRejected: true, wantLabel: "", wantProbe: true,
		},
		{
			// The capability probe FAILED to advertise anything (the fail-closed zero
			// value Capabilities returns on an unanswerable probe) — the annotated
			// amd64 pod is refused rather than admitted on an unanswered question.
			name: "vm_amd64_refused_when_node_advertises_nothing", annotation: "linux/amd64", runtimeClass: vm,
			caps:         NodeCapabilities{},
			wantRejected: true, wantLabel: runtimeclass.LabelRosettaLinux, wantProbe: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &platformFake{fakeRuntimeServer: newFakeRuntimeServer(), info: capabilityInfo(tc.caps)}
			rec := record.NewFakeRecorder(8)
			r := newRuntimedWith(f, RuntimedConfig{
				NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir(), Recorder: rec,
			}, nil, nil)

			pod := platformPod(tc.annotation)
			pod.Spec.RuntimeClassName = nil
			if tc.runtimeClass != "" {
				rc := tc.runtimeClass
				pod.Spec.RuntimeClassName = &rc
			}

			err := r.CreatePod(context.Background(), pod)
			infoCalls, createCalls := f.counts()

			if gotProbe := infoCalls > 0; gotProbe != tc.wantProbe {
				t.Errorf("node-capability probe made = %v (calls=%d), want %v", gotProbe, infoCalls, tc.wantProbe)
			}

			if !tc.wantRejected {
				if err != nil {
					t.Fatalf("CreatePod = %v, want the pod admitted (a reject-only gate is a fail-ALWAYS gate)", err)
				}
				if createCalls != 1 {
					t.Errorf("CreatePod RPC calls = %d, want 1 — an admitted pod must reach runtimed", createCalls)
				}
				select {
				case ev := <-rec.Events:
					t.Errorf("admitted pod recorded an Event %q, want none", ev)
				default:
				}
				return
			}

			if err == nil {
				t.Fatal("CreatePod = nil error, want a fail-closed refusal")
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
			if !strings.HasPrefix(ev, corev1.EventTypeWarning+" "+reasonFailedImagePlatform+" ") {
				t.Errorf("Event = %q, want a %s %s event", ev, corev1.EventTypeWarning, reasonFailedImagePlatform)
			}
			if !strings.Contains(ev, runtimev1.AnnotationImagePlatform) {
				t.Errorf("Event %q does not name the annotation %s", ev, runtimev1.AnnotationImagePlatform)
			}
			if tc.wantLabel != "" {
				if !strings.Contains(ev, tc.wantLabel) {
					t.Errorf("Event %q does not name the missing capability label %s", ev, tc.wantLabel)
				}
			} else {
				for _, label := range []string{runtimeclass.LabelRosetta, runtimeclass.LabelRosettaLinux} {
					if strings.Contains(ev, label) {
						t.Errorf("Event %q names %s, but no capability label can make this platform servable", ev, label)
					}
				}
			}
			// The refusal must also reach the CreatePod caller, not only the Event.
			if !strings.Contains(err.Error(), runtimev1.AnnotationImagePlatform) {
				t.Errorf("CreatePod error %q does not name the annotation", err)
			}
		})
	}
}
