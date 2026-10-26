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
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/provider/podlogs"
	"k3sm.io/k3sm/pkg/provider/vkadapter"
)

// TestLogsOfTerminatedVMPodSurviveRestart pins that after a node-daemon
// restart, `kubectl logs` on a TERMINATED pod the apiserver still holds reads
// its retained log file, as the kubelet does, instead of answering NotFound.
//
// The provider under test is built from durable state only, which is what a
// restart leaves: an empty track map, the apiserver's pod objects, and the CRI
// log tree on disk. A terminated vm pod never re-attaches and Virtual Kubelet
// never syncs a terminal pod, so before the fix nothing ever tracked it again.
func TestLogsOfTerminatedVMPodSurviveRestart(t *testing.T) {
	started := time.Unix(1_700_000_000, 0)
	logsDir := t.TempDir()

	// writeInstance writes one container instance file where runtimed writes it.
	writeInstance := func(t *testing.T, pod *corev1.Pod, container string, n int32, content string) string {
		t.Helper()
		path := podlogs.BuildContainerLogsPath(logsDir, pod.Namespace, pod.Name, string(pod.UID), container, n)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte(criLine(started, "stdout", "F", content)), 0o600); err != nil {
			t.Fatalf("write log: %v", err)
		}
		return path
	}

	terminated := func(name string, phase corev1.PodPhase) corev1.Pod {
		p := attachTestPod(name, phase, "", started)
		p.Status.ContainerStatuses = []corev1.ContainerStatus{
			{Name: "c0", ContainerID: "k3sm://" + name + "-c0", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0, ContainerID: "k3sm://" + name + "-c0"}}},
			{Name: "c1", ContainerID: "k3sm://" + name + "-c1", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0, ContainerID: "k3sm://" + name + "-c1"}}},
		}
		return p
	}

	// The reported case: a vm RuntimeClass Job pod that ran to completion.
	vmJob := terminated("vmjob", corev1.PodSucceeded)
	vmJob.Spec.RuntimeClassName = ptr("vm")
	writeInstance(t, &vmJob, "c0", 0, "vm job output")

	// A terminated native pod, with a previous instance retained beside the
	// current one.
	nativeJob := terminated("nativejob", corev1.PodFailed)
	writeInstance(t, &nativeJob, "c0", 0, "native first instance")
	writeInstance(t, &nativeJob, "c0", 1, "native second instance")
	// A rotated file of the current instance is never the file a read starts from.
	rotated := podlogs.BuildContainerLogsPath(logsDir, nativeJob.Namespace, nativeJob.Name, string(nativeJob.UID), "c0", 1) + ".20260101-000000"
	if err := os.WriteFile(rotated, []byte(criLine(started, "stdout", "F", "rotated")), 0o600); err != nil {
		t.Fatalf("write rotated log: %v", err)
	}

	// A running native pod survives the restart by attach and keeps reading its
	// logs through the runtime's log_path, as before.
	web := attachTestPod("web", corev1.PodRunning, "100.64.0.7", started)
	webLog := writeInstance(t, &web, "c0", 2, "native running output")

	// A terminated pod whose container never wrote a file.
	silent := terminated("silent", corev1.PodSucceeded)

	rt := newAttachRuntime()
	rt.results["uid-web"] = attachResult{status: &runtimev1.PodStatus{
		PodId: "uid-web",
		Phase: runtimev1.PodPhase_POD_PHASE_RUNNING,
		ContainerStatuses: []*runtimev1.ContainerStatus{
			{
				Name: "c0", Image: "registry/web:latest", ContainerId: "cid0", RestartCount: 2, LogPath: webLog,
				State: &runtimev1.ContainerState{Running: &runtimev1.ContainerStateRunning{StartedAt: timestamppb.New(started)}},
			},
			{
				Name: "c1", Image: "registry/web:latest", ContainerId: "cid1",
				State: &runtimev1.ContainerState{Running: &runtimev1.ContainerStateRunning{StartedAt: timestamppb.New(started)}},
			},
		},
	}}
	src := &fakePodSource{listed: []corev1.Pod{vmJob, nativeJob, web, silent}, got: map[string]*corev1.Pod{}}
	for _, p := range src.listed {
		src.got[p.Namespace+"/"+p.Name] = p.DeepCopy()
	}
	r := newRuntimedWith(rt, RuntimedConfig{NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: logsDir}, nil, nil)
	r.podSource = src
	ctx := context.Background()
	r.adoptNodePods(ctx, rt)

	read := func(t *testing.T, name string, opts *corev1.PodLogOptions) (string, error) {
		t.Helper()
		rc, err := r.GetContainerLogs(ctx, "default", name, "c0", opts)
		if err != nil {
			return "", err
		}
		defer func() { _ = rc.Close() }()
		b, err := io.ReadAll(rc)
		return string(b), err
	}

	tests := []struct {
		name string
		pod  string
		opts *corev1.PodLogOptions
		want string
	}{
		{name: "terminated vm pod serves its retained log", pod: "vmjob", opts: &corev1.PodLogOptions{}, want: "vm job output\n"},
		{name: "follow on a terminated vm pod drains once and ends", pod: "vmjob", opts: &corev1.PodLogOptions{Follow: true}, want: "vm job output\n"},
		{name: "terminated native pod serves its current instance", pod: "nativejob", opts: &corev1.PodLogOptions{}, want: "native second instance\n"},
		{name: "terminated native pod serves its previous instance", pod: "nativejob", opts: &corev1.PodLogOptions{Previous: true}, want: "native first instance\n"},
		{name: "running native pod still reads through log_path", pod: "web", opts: &corev1.PodLogOptions{}, want: "native running output\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := read(t, tt.pod, tt.opts)
			if err != nil {
				t.Fatalf("GetContainerLogs %s: %v", tt.pod, err)
			}
			if got != tt.want {
				t.Errorf("logs = %q, want %q", got, tt.want)
			}
		})
	}

	t.Run("the logs endpoint finds the retained pod", func(t *testing.T) {
		if _, ok := r.GetPodByName(ctx, "default", "vmjob"); !ok {
			t.Error("GetPodByName(vmjob) = not found, want the retained pod (the endpoint's 404 otherwise)")
		}
	})

	t.Run("a terminated pod with no log file is NotFound", func(t *testing.T) {
		_, err := read(t, "silent", &corev1.PodLogOptions{})
		if !vkadapter.IsNotFound(err) {
			t.Errorf("err = %v, want NotFound", err)
		}
		_, err = read(t, "vmjob", &corev1.PodLogOptions{Previous: true})
		if !vkadapter.IsNotFound(err) {
			t.Errorf("previous with one instance: err = %v, want NotFound", err)
		}
	})

	t.Run("an unknown pod is still NotFound", func(t *testing.T) {
		if _, err := read(t, "nosuch", &corev1.PodLogOptions{}); !vkadapter.IsNotFound(err) {
			t.Errorf("err = %v, want NotFound", err)
		}
	})

	t.Run("the log GC keeps a retained pod's tree", func(t *testing.T) {
		r.MarkPodsSynced()
		known, synced := r.KnownPodUIDs(ctx)
		if !synced {
			t.Fatal("KnownPodUIDs not synced after MarkPodsSynced")
		}
		for _, uid := range []string{"uid-vmjob", "uid-nativejob", "uid-web"} {
			if _, ok := known[uid]; !ok {
				t.Errorf("KnownPodUIDs lacks %s; the GC would remove its log tree", uid)
			}
		}
	})

	t.Run("a retained pod deleted from the apiserver is dropped", func(t *testing.T) {
		src.mu.Lock()
		src.listed = []corev1.Pod{nativeJob, web, silent}
		delete(src.got, "default/vmjob")
		src.mu.Unlock()
		r.reapOrphans(ctx)
		if _, ok := r.GetPodByName(ctx, "default", "vmjob"); ok {
			t.Error("GetPodByName(vmjob) found a pod the apiserver no longer holds")
		}
		known, _ := r.KnownPodUIDs(ctx)
		if _, ok := known["uid-vmjob"]; ok {
			t.Error("KnownPodUIDs still reports the deleted pod; its log tree would never be collected")
		}
		if _, ok := r.GetPodByName(ctx, "default", "nativejob"); !ok {
			t.Error("GetPodByName(nativejob) lost a pod the apiserver still holds")
		}
	})

	// A name is not an identity. Once the apiserver's object for a name carries a
	// different UID, the retained incarnation is not that pod, and serving its
	// files would show the new pod another workload's output.
	t.Run("a recreated pod with the same name is not served the old logs", func(t *testing.T) {
		successor := nativeJob.DeepCopy()
		successor.UID = "uid-nativejob-successor"
		src.mu.Lock()
		src.got["default/nativejob"] = successor
		src.mu.Unlock()
		if _, ok := r.GetPodByName(ctx, "default", "nativejob"); ok {
			t.Error("GetPodByName(nativejob) returned the retained predecessor of a recreated pod")
		}
		if _, err := read(t, "nativejob", &corev1.PodLogOptions{}); !vkadapter.IsNotFound(err) {
			t.Errorf("logs of a recreated pod: err = %v, want NotFound (never the predecessor's file)", err)
		}
	})

	t.Run("two retained pods with one name are ambiguous", func(t *testing.T) {
		a := attachTestPod("twin", corev1.PodSucceeded, "", started)
		b := attachTestPod("twin", corev1.PodSucceeded, "", started)
		b.UID = "uid-twin-2"
		writeInstance(t, &a, "c0", 0, "twin a")
		writeInstance(t, &b, "c0", 0, "twin b")
		r.retainTerminatedPods([]corev1.Pod{a, b})
		src.mu.Lock()
		src.got["default/twin"] = a.DeepCopy()
		src.mu.Unlock()
		if _, err := read(t, "twin", &corev1.PodLogOptions{}); !vkadapter.IsNotFound(err) {
			t.Errorf("err = %v, want NotFound for an ambiguous name", err)
		}
	})

	// The retained read path is derived from names, so it must not follow a link
	// planted in the tree: neither a symlinked instance file nor a symlinked
	// container directory may redirect it, even to a readable log.
	t.Run("symlinks in the retained tree are refused", func(t *testing.T) {
		outside := filepath.Join(t.TempDir(), "secret.log")
		if err := os.WriteFile(outside, []byte(criLine(started, "stdout", "F", "outside the tree")), 0o600); err != nil {
			t.Fatal(err)
		}

		linkFile := terminated("linkfile", corev1.PodSucceeded)
		fileDir := podlogs.BuildContainerLogsDirectory(logsDir, "default", "linkfile", string(linkFile.UID), "c0")
		if err := os.MkdirAll(fileDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(fileDir, "0.log")); err != nil {
			t.Fatal(err)
		}

		linkDir := terminated("linkdir", corev1.PodSucceeded)
		outsideDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(outsideDir, "0.log"), []byte(criLine(started, "stdout", "F", "outside the tree")), 0o600); err != nil {
			t.Fatal(err)
		}
		podDir := podlogs.BuildPodLogsDirectory(logsDir, "default", "linkdir", string(linkDir.UID))
		if err := os.MkdirAll(podDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outsideDir, filepath.Join(podDir, "c0")); err != nil {
			t.Fatal(err)
		}

		r.retainTerminatedPods([]corev1.Pod{linkFile, linkDir})
		src.mu.Lock()
		src.got["default/linkfile"] = linkFile.DeepCopy()
		src.got["default/linkdir"] = linkDir.DeepCopy()
		src.mu.Unlock()

		got, err := read(t, "linkfile", &corev1.PodLogOptions{})
		if !vkadapter.IsNotFound(err) {
			t.Errorf("symlinked instance file: logs = %q, err = %v, want NotFound", got, err)
		}
		got, err = read(t, "linkdir", &corev1.PodLogOptions{})
		if err == nil || !errors.Is(err, errUnsafeLogDir) {
			t.Errorf("symlinked container directory: logs = %q, err = %v, want a refusal", got, err)
		}
	})

	t.Run("a name that is not one path segment is refused", func(t *testing.T) {
		p := terminated("trav", corev1.PodSucceeded)
		if _, err := r.retainedLogPath(&p, "../../etc", false); err == nil {
			t.Error("retainedLogPath accepted a container name outside the declared set")
		}
		p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: "../x"})
		if _, err := r.retainedLogPath(&p, "../x", false); err == nil || vkadapter.IsNotFound(err) {
			t.Errorf("err = %v, want a refusal of a multi-segment name", err)
		}
		p.Spec.Containers[0].Name = ".."
		if _, err := r.retainedLogPath(&p, "..", false); err == nil || vkadapter.IsNotFound(err) {
			t.Errorf("err = %v, want a refusal of a dot-dot name", err)
		}
	})
}
