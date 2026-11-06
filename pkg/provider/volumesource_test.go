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
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"

	netv1 "k3sm.io/apis/net/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"

	"k3sm.io/k3sm/pkg/runtimeclass"
)

// testClusterRegistry is the cluster registry authority the tests hand the
// translation, spelled as cmd/k3sm's flatRegistryHost spells it.
const testClusterRegistry = "registry-k3sm:6450"

const testArtifactDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// volumePod builds a one-container pod carrying vol. When mounted, the
// container mounts it at /data; otherwise nothing mounts it.
func volumePod(name string, vol corev1.Volume, mounted bool) *corev1.Pod {
	c := corev1.Container{Name: "c0", Image: "registry/web:1", Command: []string{"/web"}}
	if mounted {
		c.VolumeMounts = []corev1.VolumeMount{{Name: vol.Name, MountPath: "/data", ReadOnly: true}}
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name, UID: types.UID("uid-" + name)},
		Spec: corev1.PodSpec{
			Volumes:    []corev1.Volume{vol},
			Containers: []corev1.Container{c},
		},
	}
}

func imageVolume(name, reference string, policy corev1.PullPolicy) corev1.Volume {
	return corev1.Volume{Name: name, VolumeSource: corev1.VolumeSource{
		Image: &corev1.ImageVolumeSource{Reference: reference, PullPolicy: policy},
	}}
}

func boxVolume(box *runtimev1.PodBox, name string) *runtimev1.Volume {
	for _, v := range box.GetVolumes() {
		if v.GetName() == name {
			return v
		}
	}
	return nil
}

// TestToPodBoxMapsImageVolume pins the translation of a corev1 image volume
// onto the runtime's image source: the reference verbatim, the pull policy
// through the container pull-policy mapping, and no paths (reserved: a
// non-empty set asks the runtime for a subset this provider never requests).
func TestToPodBoxMapsImageVolume(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		reference string
		policy    corev1.PullPolicy
		want      runtimev1.ImagePullPolicy
		mounted   bool
	}{
		{"digest_if_not_present", testClusterRegistry + "/models/qwen3@" + testArtifactDigest, corev1.PullIfNotPresent, runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_IF_NOT_PRESENT, true},
		{"tag_always", testClusterRegistry + "/models/qwen3:v1", corev1.PullAlways, runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS, true},
		{"never", testClusterRegistry + "/wasm/hello:v1", corev1.PullNever, runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER, true},
		{"policy_unset", testClusterRegistry + "/models/qwen3:v1", "", runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_UNSPECIFIED, true},
		// An image volume is a source the node serves whether or not a
		// container mounts it, as a kubelet pulls it either way.
		{"unmounted", testClusterRegistry + "/models/qwen3:v1", corev1.PullIfNotPresent, runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_IF_NOT_PRESENT, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pod := volumePod("img", imageVolume("model", tc.reference, tc.policy), tc.mounted)
			box, err := toPodBox(pod, "10.42.0.5", "192.168.1.10", t.TempDir(), "", testClusterRegistry, netv1.DNSConfig{}, nil)
			if err != nil {
				t.Fatalf("toPodBox: %v", err)
			}
			v := boxVolume(box, "model")
			if v == nil {
				t.Fatalf("volume %q was dropped; box volumes = %v", "model", box.GetVolumes())
			}
			src := v.GetImage()
			if src == nil {
				t.Fatalf("volume %q carries no image source: %v", "model", v)
			}
			if got := src.GetReference(); got != tc.reference {
				t.Errorf("reference = %q, want %q", got, tc.reference)
			}
			if got := src.GetPullPolicy(); got != tc.want {
				t.Errorf("pull_policy = %v, want %v", got, tc.want)
			}
			if got := src.GetPaths(); len(got) != 0 {
				t.Errorf("paths = %v, want none", got)
			}
		})
	}
}

// TestToPodBoxRefusesForeignImageVolume pins that an image volume must name
// the cluster registry authority exactly: any other host, a bare name that
// would default to a public registry, a loopback spelling of a registry, a
// near-miss of the cluster name, a reference that does not parse, and any image
// volume at all on a node that maps no cluster registry are refused, mounted or
// not, with ErrImageVolumeRegistry. The CreatePod leg asserts the refusal lands
// before the runtime call, as a Warning Event with the stable reason, on both
// backends.
func TestToPodBoxRefusesForeignImageVolume(t *testing.T) {
	t.Parallel()
	const repo = "/models/qwen3:v1"
	tests := []struct {
		name      string
		reference string
		cluster   string
	}{
		{"public_registry", "ghcr.io/acme/qwen3:v1", testClusterRegistry},
		{"bare_name_defaults_to_docker_hub", "models/qwen3:v1", testClusterRegistry},
		{"docker_hub_explicit", "docker.io/models/qwen3:v1", testClusterRegistry},
		{"loopback_spelling", "localhost:6451" + repo, testClusterRegistry},
		{"other_port", "registry-k3sm:6451" + repo, testClusterRegistry},
		{"no_port", "registry-k3sm" + repo, testClusterRegistry},
		{"suffix_lookalike", "registry-k3sm.example.com:6450" + repo, testClusterRegistry},
		{"unparseable", testClusterRegistry + "/Models/UPPER:v1", testClusterRegistry},
		{"empty_reference", "", testClusterRegistry},
		{"node_maps_no_cluster_registry", testClusterRegistry + repo, ""},
	}

	for _, tc := range tests {
		for _, mounted := range []bool{true, false} {
			name := tc.name + "/unmounted"
			if mounted {
				name = tc.name + "/mounted"
			}
			t.Run("toPodBox/"+name, func(t *testing.T) {
				t.Parallel()
				pod := volumePod("img", imageVolume("model", tc.reference, corev1.PullIfNotPresent), mounted)
				box, err := toPodBox(pod, "10.42.0.5", "192.168.1.10", t.TempDir(), "", tc.cluster, netv1.DNSConfig{}, nil)
				if !errors.Is(err, ErrImageVolumeRegistry) {
					t.Fatalf("toPodBox = (%v, %v), want an error wrapping ErrImageVolumeRegistry", box.GetVolumes(), err)
				}
				var vr *volumeRefusal
				if !errors.As(err, &vr) {
					t.Fatalf("error %v is not a *volumeRefusal", err)
				}
				if vr.reason != reasonArtifactPullRefused || vr.volume != "model" {
					t.Errorf("refusal = {reason %q, volume %q}, want {%q, %q}", vr.reason, vr.volume, reasonArtifactPullRefused, "model")
				}
			})
		}
	}

	for _, be := range []struct{ name, runtimeClass string }{{"native", ""}, {"vm", runtimeclass.Name}} {
		t.Run("CreatePod/"+be.name, func(t *testing.T) {
			t.Parallel()
			f := &platformFake{fakeRuntimeServer: newFakeRuntimeServer(), info: capabilityInfo(NodeCapabilities{VMBackend: true})}
			rec := record.NewFakeRecorder(8)
			r := newRuntimedWith(f, RuntimedConfig{
				NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: t.TempDir(), Recorder: rec,
				FlatRegistry: image.FlatRegistry{Host: testClusterRegistry},
			}, nil, nil)
			pod := volumePod("img", imageVolume("model", "ghcr.io/acme/qwen3:v1", corev1.PullIfNotPresent), true)
			if be.runtimeClass != "" {
				rc := be.runtimeClass
				pod.Spec.RuntimeClassName = &rc
			}
			err := r.CreatePod(context.Background(), pod)
			if !errors.Is(err, ErrImageVolumeRegistry) {
				t.Fatalf("CreatePod = %v, want an error wrapping ErrImageVolumeRegistry", err)
			}
			if _, creates := f.counts(); creates != 0 {
				t.Errorf("CreatePod RPC calls = %d, want 0: the refusal must land before the RPC", creates)
			}
			events := pendingEvents(rec.Events)
			assertOneRefusalEvent(t, events, reasonArtifactPullRefused, "model")
			if ev := strings.Join(events, "|"); strings.Contains(ev, "ghcr.io") {
				t.Errorf("event carries the pod's reference text: %q", ev)
			}
		})
	}

	// The accept leg through CreatePod: the cluster host reaches runtimed.
	t.Run("CreatePod/cluster_registry_admitted", func(t *testing.T) {
		t.Parallel()
		f := &platformFake{fakeRuntimeServer: newFakeRuntimeServer(), info: capabilityInfo(NodeCapabilities{VMBackend: true})}
		rec := record.NewFakeRecorder(8)
		r := newRuntimedWith(f, RuntimedConfig{
			NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: t.TempDir(), Recorder: rec,
			FlatRegistry: image.FlatRegistry{Host: testClusterRegistry},
		}, nil, nil)
		pod := volumePod("img", imageVolume("model", testClusterRegistry+"/models/qwen3:v1", corev1.PullIfNotPresent), true)
		if err := r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod = %v, want the pod admitted (a reject-only gate is a refuse-everything gate)", err)
		}
		if _, creates := f.counts(); creates != 1 {
			t.Errorf("CreatePod RPC calls = %d, want 1", creates)
		}
	})
}

// assertOneRefusalEvent asserts exactly one Warning Event with reason, and
// that it names the volume.
func assertOneRefusalEvent(t *testing.T, events []string, reason, volume string) {
	t.Helper()
	var hits []string
	for _, ev := range events {
		if strings.HasPrefix(ev, corev1.EventTypeWarning+" "+reason+" ") {
			hits = append(hits, ev)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("Warning %s events = %d (%q), want exactly 1; all events: %q", reason, len(hits), hits, events)
	}
	if !strings.Contains(hits[0], `"`+volume+`"`) {
		t.Errorf("event %q does not name volume %q", hits[0], volume)
	}
}

// TestToPodBoxRefusesMountedUnmodeledVolume pins the end of the silent drop
// for a volume a container mounts: a mounted volume whose source the
// translation does not model (hostPath, nfs, csi, a generic ephemeral volume,
// and every other in-tree kind) is refused with ErrVolumeSourceUnsupported and
// a fixed kind token, where it used to vanish and fail later at the runtime
// naming only the mount.
//
// The unmounted leg is pinned too, in the other direction: a declared volume
// no container mounts still runs today, so it stays dropped rather than
// refusing a pod that works.
//
// The completeness leg walks every pointer field of corev1.VolumeSource, so a
// source upstream adds later is either modeled or refused, never dropped.
func TestToPodBoxRefusesMountedUnmodeledVolume(t *testing.T) {
	t.Parallel()
	vol := func(name string, src corev1.VolumeSource) corev1.Volume {
		return corev1.Volume{Name: name, VolumeSource: src}
	}
	refused := []struct {
		name     string
		vol      corev1.Volume
		wantKind string
	}{
		{"hostPath", vol("logs", corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log"}}), "hostPath"},
		{"nfs", vol("share", corev1.VolumeSource{NFS: &corev1.NFSVolumeSource{Server: "nfs.example", Path: "/export"}}), "nfs"},
		{"csi", vol("csi", corev1.VolumeSource{CSI: &corev1.CSIVolumeSource{Driver: "d"}}), "csi"},
		{"ephemeral", vol("scratch", corev1.VolumeSource{Ephemeral: &corev1.EphemeralVolumeSource{}}), "ephemeral"},
		{"gitRepo", vol("src", corev1.VolumeSource{GitRepo: &corev1.GitRepoVolumeSource{Repository: "https://example.com/r.git"}}), "gitRepo"},
		{"no_source", vol("empty", corev1.VolumeSource{}), volumeKindNone},
	}
	for _, tc := range refused {
		t.Run("mounted/"+tc.name, func(t *testing.T) {
			t.Parallel()
			pod := volumePod("v", tc.vol, true)
			_, err := toPodBox(pod, "10.42.0.5", "192.168.1.10", t.TempDir(), "", testClusterRegistry, netv1.DNSConfig{}, nil)
			if !errors.Is(err, ErrVolumeSourceUnsupported) {
				t.Fatalf("toPodBox = %v, want an error wrapping ErrVolumeSourceUnsupported", err)
			}
			var vr *volumeRefusal
			if !errors.As(err, &vr) {
				t.Fatalf("error %v is not a *volumeRefusal", err)
			}
			if vr.reason != reasonFailedVolumeSource || vr.volume != tc.vol.Name || vr.kind != tc.wantKind {
				t.Errorf("refusal = {%q, %q, %q}, want {%q, %q, %q}", vr.reason, vr.volume, vr.kind, reasonFailedVolumeSource, tc.vol.Name, tc.wantKind)
			}
		})
		t.Run("unmounted_still_dropped/"+tc.name, func(t *testing.T) {
			t.Parallel()
			pod := volumePod("v", tc.vol, false)
			box, err := toPodBox(pod, "10.42.0.5", "192.168.1.10", t.TempDir(), "", testClusterRegistry, netv1.DNSConfig{}, nil)
			if err != nil {
				t.Fatalf("toPodBox = %v, want an unmounted %s volume to keep running as it does today", err, tc.name)
			}
			if v := boxVolume(box, tc.vol.Name); v != nil {
				t.Errorf("unmounted unmodeled volume reached the box: %v", v)
			}
		})
	}

	// An init container's mount counts: it fails at the runtime the same way.
	t.Run("mounted_by_init_container", func(t *testing.T) {
		t.Parallel()
		pod := volumePod("v", refused[0].vol, false)
		pod.Spec.InitContainers = []corev1.Container{{Name: "i0", Image: "registry/web:1", VolumeMounts: []corev1.VolumeMount{{Name: "logs", MountPath: "/logs"}}}}
		if _, err := toPodBox(pod, "10.42.0.5", "192.168.1.10", t.TempDir(), "", testClusterRegistry, netv1.DNSConfig{}, nil); !errors.Is(err, ErrVolumeSourceUnsupported) {
			t.Fatalf("toPodBox = %v, want ErrVolumeSourceUnsupported", err)
		}
	})

	t.Run("every_volume_source_is_modeled_or_refused", func(t *testing.T) {
		t.Parallel()
		st := reflect.TypeFor[corev1.VolumeSource]()
		for i := 0; i < st.NumField(); i++ {
			f := st.Field(i)
			if f.Type.Kind() != reflect.Pointer {
				continue
			}
			var src corev1.VolumeSource
			reflect.ValueOf(&src).Elem().Field(i).Set(reflect.New(f.Type.Elem()))
			if src.Image != nil {
				src.Image.Reference = testClusterRegistry + "/models/qwen3:v1"
			}
			pod := volumePod("v", vol("v0", src), true)
			box, err := toPodBox(pod, "10.42.0.5", "192.168.1.10", t.TempDir(), "", testClusterRegistry, netv1.DNSConfig{}, nil)
			switch {
			case err == nil && boxVolume(box, "v0") != nil:
			case errors.Is(err, ErrVolumeSourceUnsupported):
				var vr *volumeRefusal
				if errors.As(err, &vr) && vr.kind != jsonName(f) {
					t.Errorf("%s: refusal kind %q, want %q", f.Name, vr.kind, jsonName(f))
				}
			default:
				t.Errorf("%s: a mounted volume was neither carried nor refused (err %v)", f.Name, err)
			}
		}
	})

	for _, be := range []struct{ name, runtimeClass string }{{"native", ""}, {"vm", runtimeclass.Name}} {
		t.Run("CreatePod/"+be.name, func(t *testing.T) {
			t.Parallel()
			f := &platformFake{fakeRuntimeServer: newFakeRuntimeServer(), info: capabilityInfo(NodeCapabilities{VMBackend: true})}
			rec := record.NewFakeRecorder(8)
			r := newRuntimedWith(f, RuntimedConfig{
				NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: t.TempDir(), Recorder: rec,
			}, nil, nil)
			pod := volumePod("v", refused[0].vol, true)
			if be.runtimeClass != "" {
				rc := be.runtimeClass
				pod.Spec.RuntimeClassName = &rc
			}
			err := r.CreatePod(context.Background(), pod)
			if !errors.Is(err, ErrVolumeSourceUnsupported) {
				t.Fatalf("CreatePod = %v, want an error wrapping ErrVolumeSourceUnsupported", err)
			}
			if _, creates := f.counts(); creates != 0 {
				t.Errorf("CreatePod RPC calls = %d, want 0: the refusal must land before the RPC", creates)
			}
			if r.trackByID(string(pod.UID)) != nil {
				t.Error("a refused pod was tracked; it must leave no bookkeeping behind")
			}
			events := pendingEvents(rec.Events)
			assertOneRefusalEvent(t, events, reasonFailedVolumeSource, "logs")
			if !strings.Contains(strings.Join(events, "|"), "hostPath") {
				t.Errorf("events %q do not name the kind hostPath", events)
			}
			if strings.Contains(strings.Join(events, "|"), "/var/log") {
				t.Errorf("events %q carry the pod's host path text", events)
			}
		})
	}
}

// jsonName is the JSON field name of a corev1.VolumeSource field.
func jsonName(f reflect.StructField) string {
	name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
	return name
}
