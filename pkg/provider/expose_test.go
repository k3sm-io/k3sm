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
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/k3sm/internal/hostacl"
	"k3sm.io/k3sm/pkg/runtimeclass"
	"k3sm.io/runtimed/pkg/hostshare"
)

func exposeVolume(name string, mut func(*corev1.CSIVolumeSource)) corev1.Volume {
	c := &corev1.CSIVolumeSource{Driver: ExposeDriver, VolumeAttributes: map[string]string{"user": "miko"}}
	if mut != nil {
		mut(c)
	}
	return corev1.Volume{Name: name, VolumeSource: corev1.VolumeSource{CSI: c}}
}

func exposePod(ns, name string, vol corev1.Volume, mounted bool) *corev1.Pod {
	c := corev1.Container{Name: "c0", Image: "native", Command: []string{"/bin/sh"}}
	if mounted {
		c.VolumeMounts = []corev1.VolumeMount{{Name: vol.Name, MountPath: "/var/run/app"}}
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID("uid-" + name)},
		Spec:       corev1.PodSpec{Volumes: []corev1.Volume{vol}, Containers: []corev1.Container{c}},
	}
}

func ptrTo[T any](v T) *T { return &v }

// TestToPodBoxExpose pins the translation of an inline CSI volume of the
// reserved driver onto the runtime's exposure source, the refusal of every
// shape the node would not honour, and that every other CSI driver stays
// refused as an unmodeled source.
func TestToPodBoxExpose(t *testing.T) {
	t.Parallel()
	translate := func(pod *corev1.Pod) (*corev1.Pod, error) {
		_, err := toPodBox(pod, "10.42.0.5", "192.168.1.10", t.TempDir(), "", testClusterRegistry, netv1.DNSConfig{}, "", nil)
		return pod, err
	}
	for _, tc := range []struct {
		name   string
		mut    func(*corev1.CSIVolumeSource)
		wantRW bool
	}{
		{"read_by_default", nil, false},
		{"read", func(c *corev1.CSIVolumeSource) { c.VolumeAttributes["access"] = "read" }, false},
		{"read_write", func(c *corev1.CSIVolumeSource) { c.VolumeAttributes["access"] = "read-write" }, true},
		{"readOnly_false", func(c *corev1.CSIVolumeSource) { c.ReadOnly = ptrTo(false) }, false},
		{"empty_fsType", func(c *corev1.CSIVolumeSource) { c.FSType = ptrTo("") }, false},
	} {
		t.Run("maps/"+tc.name, func(t *testing.T) {
			t.Parallel()
			pod := exposePod("default", "ex", exposeVolume("sockets", tc.mut), true)
			box, err := toPodBox(pod, "10.42.0.5", "192.168.1.10", t.TempDir(), "", testClusterRegistry, netv1.DNSConfig{}, "", nil)
			if err != nil {
				t.Fatalf("toPodBox = %v, want the exposure mapped", err)
			}
			v := boxVolume(box, "sockets")
			x := v.GetExpose()
			if x == nil || x.GetUser() != "miko" || x.GetReadWrite() != tc.wantRW || x.GetUid() != 0 {
				t.Fatalf("box volume = %v, want expose{user miko, read_write %v, uid unresolved}", v, tc.wantRW)
			}
		})
	}
	for _, tc := range []struct {
		name string
		mut  func(*corev1.CSIVolumeSource)
		pod  func(*corev1.Pod)
		want string
	}{
		{"no_user", func(c *corev1.CSIVolumeSource) { delete(c.VolumeAttributes, "user") }, nil, "volumeAttributes.user is required"},
		{"user_not_plain", func(c *corev1.CSIVolumeSource) { c.VolumeAttributes["user"] = "../root" }, nil, "not a plain account name"},
		{"unknown_key", func(c *corev1.CSIVolumeSource) { c.VolumeAttributes["mode"] = "0777" }, nil, `unknown volumeAttributes key "mode"`},
		{"bad_access", func(c *corev1.CSIVolumeSource) { c.VolumeAttributes["access"] = "write" }, nil, "not read or read-write"},
		{"fsType", func(c *corev1.CSIVolumeSource) { c.FSType = ptrTo("apfs") }, nil, "no fsType"},
		{"readOnly", func(c *corev1.CSIVolumeSource) { c.ReadOnly = ptrTo(true) }, nil, "leave readOnly unset or false"},
		{"secret_ref", func(c *corev1.CSIVolumeSource) { c.NodePublishSecretRef = &corev1.LocalObjectReference{Name: "s"} }, nil, "no nodePublishSecretRef"},
		{"vm_pod", nil, func(p *corev1.Pod) { rc := runtimeclass.Name; p.Spec.RuntimeClassName = &rc }, "native-pod only"},
	} {
		t.Run("refused/"+tc.name, func(t *testing.T) {
			t.Parallel()
			pod := exposePod("default", "ex", exposeVolume("sockets", tc.mut), true)
			if tc.pod != nil {
				tc.pod(pod)
			}
			_, err := translate(pod)
			var vr *volumeRefusal
			if !errors.As(err, &vr) || vr.reason != reasonFailedExposure || vr.volume != "sockets" || !errors.Is(err, ErrVolumeSourceUnsupported) {
				t.Fatalf("toPodBox = %v, want a FailedExposure refusal of volume sockets", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not say %q", err, tc.want)
			}
			if msg := msgFailedExposure(vr.volume, vr.err); !strings.Contains(msg, tc.want) {
				t.Errorf("event message %q does not say %q", msg, tc.want)
			}
		})
	}
	t.Run("other_driver_stays_unmodeled", func(t *testing.T) {
		t.Parallel()
		vol := exposeVolume("sockets", func(c *corev1.CSIVolumeSource) { c.Driver = "expose.k3sm.io.example" })
		_, err := translate(exposePod("default", "ex", vol, true))
		var vr *volumeRefusal
		if !errors.As(err, &vr) || vr.reason != reasonFailedVolumeSource || vr.kind != "csi" {
			t.Fatalf("toPodBox = %v, want the unmodeled-source refusal", err)
		}
	})
	t.Run("unmounted_is_skipped", func(t *testing.T) {
		t.Parallel()
		pod := exposePod("default", "ex", exposeVolume("sockets", func(c *corev1.CSIVolumeSource) { c.FSType = ptrTo("apfs") }), false)
		box, err := toPodBox(pod, "10.42.0.5", "192.168.1.10", t.TempDir(), "", testClusterRegistry, netv1.DNSConfig{}, "", nil)
		if err != nil || boxVolume(box, "sockets") != nil {
			t.Fatalf("toPodBox = %v, volume %v; want an unmounted exposure skipped", err, boxVolume(box, "sockets"))
		}
	})
}

// TestCreatePodExpose pins the provider's half of the exposure decision: the
// account is resolved on the node and the volume reaches the runtime, with a
// Normal ExposureGranted Event naming the account, access and host path, only
// when a root-made grant admits it; otherwise the pod is refused before the
// RPC with one FailedExposure Event.
func TestCreatePodExpose(t *testing.T) {
	t.Parallel()
	grants := []hostshare.ExposeGrant{{UID: 501, User: "miko", Namespaces: []string{"apps"}, ReadWrite: false}}
	newRT := func(rec *record.FakeRecorder, load func(string) ([]hostshare.ExposeGrant, error)) (*fakeRuntimeServer, *runtimedRuntime, string) {
		f := newFakeRuntimeServer()
		root := t.TempDir()
		r := newRuntimedWith(f, RuntimedConfig{
			NodeName: "n", NodeIP: "192.168.1.10", Root: root, PodLogsDir: t.TempDir(), Recorder: rec,
			HostSharesFile: "/node/host-shares",
		}, nil, nil)
		r.loadExposeGrants = load
		r.lookupExposeUser = func(name string) (uint32, error) {
			if name == "miko" {
				return 501, nil
			}
			return 0, errors.New("unknown user")
		}
		r.exposeAccountName = func(uid uint32) (string, error) {
			if uid == 501 {
				return "miko", nil
			}
			return "", errors.New("unknown uid")
		}
		return f, r, root
	}
	loadGrants := func(string) ([]hostshare.ExposeGrant, error) { return grants, nil }

	t.Run("granted", func(t *testing.T) {
		t.Parallel()
		rec := record.NewFakeRecorder(16)
		f, r, root := newRT(rec, loadGrants)
		pod := exposePod("apps", "yureid-0", exposeVolume("sockets", nil), true)
		if err := r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod = %v, want the granted exposure to reach the runtime", err)
		}
		f.mu.Lock()
		box := f.created[string(pod.UID)]
		f.mu.Unlock()
		if x := boxVolume(box, "sockets").GetExpose(); x == nil || x.GetUid() != 501 || x.GetUser() != "miko" || x.GetReadWrite() {
			t.Fatalf("runtime got %v, want expose{miko, uid 501, read}", x)
		}
		events := strings.Join(pendingEvents(rec.Events), "|")
		dir := filepath.Join(root, "expose", "apps", "yureid-0", "sockets")
		for _, want := range []string{corev1.EventTypeNormal + " " + reasonExposureGranted, "miko", "read", dir} {
			if !strings.Contains(events, want) {
				t.Errorf("events %q lack %q", events, want)
			}
		}
	})
	for _, tc := range []struct {
		name string
		ns   string
		vol  corev1.Volume
		load func(string) ([]hostshare.ExposeGrant, error)
		want string
	}{
		{"no_grant_for_namespace", "other", exposeVolume("sockets", nil), loadGrants, "sudo k3sm expose allow --user miko --namespace other"},
		{"read_write_over_read_grant", "apps", exposeVolume("sockets", func(c *corev1.CSIVolumeSource) { c.VolumeAttributes["access"] = "read-write" }), loadGrants, "allows read only"},
		{"unknown_account", "apps", exposeVolume("sockets", func(c *corev1.CSIVolumeSource) { c.VolumeAttributes["user"] = "ghost" }), loadGrants, `host account "ghost" does not exist`},
		{"file_unreadable", "apps", exposeVolume("sockets", nil), func(string) ([]hostshare.ExposeGrant, error) {
			return nil, &loadError{errors.New("/node/host-shares: not owned by root")}
		}, "could not be read"},
	} {
		t.Run("refused/"+tc.name, func(t *testing.T) {
			t.Parallel()
			rec := record.NewFakeRecorder(16)
			f, r, _ := newRT(rec, tc.load)
			err := r.CreatePod(context.Background(), exposePod(tc.ns, "yureid-0", tc.vol, true))
			if !errors.Is(err, ErrVolumeSourceUnsupported) {
				t.Fatalf("CreatePod = %v, want ErrVolumeSourceUnsupported", err)
			}
			f.mu.Lock()
			creates := f.createCalls
			f.mu.Unlock()
			if creates != 0 {
				t.Errorf("CreatePod RPC calls = %d, want 0", creates)
			}
			events := pendingEvents(rec.Events)
			assertOneRefusalEvent(t, events, reasonFailedExposure, "sockets")
			if joined := strings.Join(events, "|"); !strings.Contains(joined, tc.want) || strings.Contains(joined, "/node/host-shares") {
				t.Errorf("events %q: want %q and no node path", joined, tc.want)
			}
		})
	}
}

// TestExposeACLGrantAndRevoke runs the node's ExposeACL on a real directory
// under the test's temp dir: Grant gives the uid an inheritable entry (and
// write only for read-write), Revoke removes it from the directory itself.
func TestExposeACLGrantAndRevoke(t *testing.T) {
	t.Parallel()
	const uid = 4294967294 // nobody, which every Mac resolves
	for _, tc := range []struct {
		name      string
		readWrite bool
	}{{"read", false}, {"read_write", true}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			base, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			// The data root is reached through a symlink, as /var/lib/k3sm is
			// (/var is a symlink on macOS); hostacl refuses any symlink on
			// the way, so the data root must be resolved first.
			real := filepath.Join(base, "real")
			const leaf = "expose/ns/pod-0/vol"
			if err := os.MkdirAll(filepath.Join(real, leaf), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, filepath.Join(base, "link")); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(base, "link", leaf)
			var acl exposeACL
			if err := acl.Grant(filepath.Join(base, "link", "expose", "ns"), uid, tc.readWrite); err == nil {
				t.Fatal("Grant on a directory that is not an exposure leaf = nil")
			}
			if err := acl.Grant(dir, uid, tc.readWrite); err != nil {
				if errors.Is(err, hostacl.ErrUnsupported) {
					t.Skip(err)
				}
				t.Fatalf("Grant = %v", err)
			}
			realDir := filepath.Join(real, leaf)
			p, err := hostacl.Allowed(realDir, uid)
			if err != nil {
				t.Fatal(err)
			}
			if p&hostacl.Search == 0 || (p&hostacl.Write != 0) != tc.readWrite {
				t.Fatalf("after Grant the entry allows %#x; want search, and write only for read-write", p)
			}
			if err := acl.Revoke(dir, uid); err != nil {
				t.Fatalf("Revoke = %v", err)
			}
			if p, err := hostacl.Allowed(realDir, uid); err != nil || p != 0 {
				t.Fatalf("after Revoke the entry allows %#x (%v); want none", p, err)
			}
		})
	}
}
