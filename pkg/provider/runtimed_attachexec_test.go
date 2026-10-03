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
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	utilexec "k8s.io/utils/exec"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// execAttachRuntime is the re-attachment fake with an Exec RPC: the attach,
// reap and status verbs come from attachRuntime, Exec from fakeStreamRuntime.
type execAttachRuntime struct {
	*attachRuntime
	exec *fakeStreamRuntime
}

// Exec serves the runtime Exec RPC through the streaming fake.
func (e *execAttachRuntime) Exec(s grpc.BidiStreamingServer[runtimev1.ExecRequest, runtimev1.ExecResponse]) error {
	return e.exec.Exec(s)
}

// TestExecReachesAnAttachedPod pins `kubectl exec` on a pod the provider
// learned through the startup re-attach path rather than through CreatePod.
// The runtime keeps each container's resident shim across a node-daemon
// restart and serves Exec on an attached pod through it, so the provider must
// not refuse or lose such a pod: RunInContainer resolves it, streams the
// command and stdin to the runtime Exec, and returns the command's stdout and
// exit code exactly as for a created pod.
func TestExecReachesAnAttachedPod(t *testing.T) {
	tests := []struct {
		name     string
		exit     int32
		wantCode int // -1 means a nil error
	}{
		{"a clean exit returns nil", 0, -1},
		{"a non-zero exit surfaces its code", 137, 137},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			started := time.Unix(1_700_000_000, 0)
			web := attachTestPod("web", corev1.PodRunning, "100.64.0.7", started)
			running := &runtimev1.ContainerState{Running: &runtimev1.ContainerStateRunning{StartedAt: timestamppb.New(started)}}
			rt := &execAttachRuntime{attachRuntime: newAttachRuntime(), exec: &fakeStreamRuntime{exitCode: tt.exit}}
			rt.results["uid-web"] = attachResult{status: &runtimev1.PodStatus{
				PodId: "uid-web",
				Phase: runtimev1.PodPhase_POD_PHASE_RUNNING,
				PodIp: "100.64.0.7",
				ContainerStatuses: []*runtimev1.ContainerStatus{
					{Name: "c0", Image: "registry/web:latest", ContainerId: "cid0", Ready: true, State: running},
					{Name: "c1", Image: "registry/web:latest", ContainerId: "cid1", Ready: true, State: running},
				},
			}}
			r := newRuntimedWith(rt, RuntimedConfig{
				NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: t.TempDir(),
				Network: NewPodNetAdapter(newFakeIPAM(t, "100.64.0.0/24"), "192.168.1.10", nil),
			}, nil, nil)
			r.podSource = &fakePodSource{listed: []corev1.Pod{web}}
			r.adoptNodePods(context.Background(), rt)
			if r.trackByID("uid-web") == nil {
				t.Fatalf("uid-web was not re-attached; runtime calls = %v", rt.sequence())
			}

			stdout := &syncBuffer{}
			attach := &fakeAttachIO{stdin: strings.NewReader("hello"), stdout: stdout, stderr: &syncBuffer{}}
			err := r.RunInContainer(context.Background(), "default", "web", "c1", []string{"sh", "-c", "echo hi"}, attach)

			if tt.wantCode < 0 {
				if err != nil {
					t.Fatalf("RunInContainer on an attached pod: %v", err)
				}
			} else {
				var ec utilexec.CodeExitError
				if !errors.As(err, &ec) || ec.Code != tt.wantCode {
					t.Fatalf("err = %v, want CodeExitError code %d", err, tt.wantCode)
				}
			}
			if out := stdout.String(); !strings.Contains(out, "ran:sh -c echo hi") || !strings.Contains(out, "hello") {
				t.Errorf("stdout = %q, want the command and stdin streamed back", out)
			}
			rt.exec.mu.Lock()
			gotPod, gotCmd := rt.exec.execPodID, rt.exec.execCmd
			rt.exec.mu.Unlock()
			if gotPod != "uid-web" {
				t.Errorf("runtime Exec addressed pod %q, want the attached pod uid-web", gotPod)
			}
			if !slices.Equal(gotCmd, []string{"sh", "-c", "echo hi"}) {
				t.Errorf("runtime Exec received command %v", gotCmd)
			}
			for _, call := range rt.sequence() {
				if strings.HasPrefix(call, "create:") {
					t.Errorf("the pod was created (%s), want it learned through the attach only", call)
				}
			}
		})
	}
}
