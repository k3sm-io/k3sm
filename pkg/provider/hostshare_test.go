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

	"k3sm.io/runtimed/pkg/hostshare"
)

func hostSharePod(path, mountPath string, readOnly bool) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "hs", UID: types.UID("uid-hs")},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{{Name: "code", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: path}}}},
			Containers: []corev1.Container{{
				Name: "c0", Image: "native", Command: []string{"/bin/sh"},
				VolumeMounts: []corev1.VolumeMount{{Name: "code", MountPath: mountPath, ReadOnly: readOnly}},
			}},
		},
	}
}

// TestCreatePodHostShare pins the provider's half of the host-share decision:
// a native pod's hostPath volume reaches the runtime, with a Normal
// HostShareGranted Event naming the path, only when the node's allowlist
// admits it at its own path; otherwise the pod is refused before the RPC with
// one FailedHostShare Event.
func TestCreatePodHostShare(t *testing.T) {
	t.Parallel()
	// /private/tmp, not t.TempDir: TMPDIR on a Mac resolves under /private/var,
	// a tree no share may name.
	base, err := os.MkdirTemp("/private/tmp", "k3sm-hs-")
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	share, other := filepath.Join(base, "share"), filepath.Join(base, "other")
	for _, d := range []string{share + "/sub", other} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	entries := []hostshare.Entry{{Mode: hostshare.ModeReadWrite, Path: share}}
	load := func(string) ([]hostshare.Entry, error) { return entries, nil }

	newRT := func(rec *record.FakeRecorder) (*fakeRuntimeServer, *runtimedRuntime) {
		f := newFakeRuntimeServer()
		r := newRuntimedWith(f, RuntimedConfig{
			NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: t.TempDir(), Recorder: rec,
			HostSharesFile: "/node/host-shares",
		}, nil, nil)
		r.loadHostShares = load
		return f, r
	}

	t.Run("granted", func(t *testing.T) {
		t.Parallel()
		rec := record.NewFakeRecorder(16)
		f, r := newRT(rec)
		pod := hostSharePod(share+"/sub", share+"/sub", false)
		if err := r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod = %v, want the admitted share to reach the runtime", err)
		}
		f.mu.Lock()
		box := f.created[string(pod.UID)]
		f.mu.Unlock()
		if v := boxVolume(box, "code"); v == nil || v.GetHostPath().GetPath() != share+"/sub" {
			t.Fatalf("runtime got volume %v, want hostPath %s", v, share+"/sub")
		}
		events := strings.Join(pendingEvents(rec.Events), "|")
		if !strings.Contains(events, reasonHostShareGranted) || !strings.Contains(events, share+"/sub") {
			t.Errorf("events %q lack a HostShareGranted naming the path", events)
		}
	})
	for _, tc := range []struct {
		name string
		pod  *corev1.Pod
	}{
		{"not_listed", hostSharePod(other, other, false)},
		{"other_mount_path", hostSharePod(share, "/workspace", false)},
	} {
		t.Run("refused/"+tc.name, func(t *testing.T) {
			t.Parallel()
			rec := record.NewFakeRecorder(16)
			f, r := newRT(rec)
			err := r.CreatePod(context.Background(), tc.pod)
			if !errors.Is(err, hostshare.ErrNotShared) || !errors.Is(err, ErrVolumeSourceUnsupported) {
				t.Fatalf("CreatePod = %v, want ErrNotShared and ErrVolumeSourceUnsupported", err)
			}
			f.mu.Lock()
			creates := f.createCalls
			f.mu.Unlock()
			if creates != 0 {
				t.Errorf("CreatePod RPC calls = %d, want 0", creates)
			}
			assertOneRefusalEvent(t, pendingEvents(rec.Events), reasonFailedHostShare, "code")
		})
	}
}
