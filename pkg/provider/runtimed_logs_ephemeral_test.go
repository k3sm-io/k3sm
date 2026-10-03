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
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// ephemeralLogRuntime is logPathRuntime plus one ephemeral container status, the
// shape the runtime reports after `kubectl debug` adds a container to a running
// pod.
type ephemeralLogRuntime struct {
	*logPathRuntime
	ephemeral *runtimev1.ContainerStatus
}

func (f *ephemeralLogRuntime) GetPodStatus(ctx context.Context, req *runtimev1.GetPodStatusRequest) (*runtimev1.GetPodStatusResponse, error) {
	resp, err := f.logPathRuntime.GetPodStatus(ctx, req)
	if err != nil {
		return nil, err
	}
	resp.Status.EphemeralContainerStatuses = []*runtimev1.ContainerStatus{f.ephemeral}
	return resp, nil
}

// TestContainerLogsResolveEphemeralContainers proves `kubectl logs -c <name>`
// reaches an ephemeral container. Ephemeral containers cannot be attached to
// interactively on this node, so their logs are the only way `kubectl debug`
// output reaches the user; kubectl's own debug path falls back to them.
func TestContainerLogsResolveEphemeralContainers(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	mainLog := filepath.Join(dir, "c0.log")
	if err := os.WriteFile(mainLog, []byte(criLine(now, "stdout", "F", "main output")), 0o600); err != nil {
		t.Fatalf("write main log: %v", err)
	}
	dbgLog := filepath.Join(dir, "dbg1.log")
	if err := os.WriteFile(dbgLog, []byte(criLine(now, "stdout", "F", "debug marker")), 0o600); err != nil {
		t.Fatalf("write ephemeral log: %v", err)
	}

	tests := []struct {
		name      string
		container string
		ephemeral *runtimev1.ContainerStatus
		want      string
		wantErr   string
	}{
		{
			name:      "exited ephemeral container reads its terminated log path",
			container: "dbg1",
			ephemeral: &runtimev1.ContainerStatus{
				Name:        "dbg1",
				ContainerId: "dbg1-id",
				State:       &runtimev1.ContainerState{Terminated: &runtimev1.ContainerStateTerminated{LogPath: dbgLog}},
			},
			want: "debug marker\n",
		},
		{
			name:      "running ephemeral container reads its current log path",
			container: "dbg1",
			ephemeral: &runtimev1.ContainerStatus{
				Name:        "dbg1",
				ContainerId: "dbg1-id",
				LogPath:     dbgLog,
				State:       &runtimev1.ContainerState{Running: &runtimev1.ContainerStateRunning{}},
			},
			want: "debug marker\n",
		},
		{
			name:      "regular container still resolves alongside an ephemeral one",
			container: "c0",
			ephemeral: &runtimev1.ContainerStatus{Name: "dbg1", LogPath: dbgLog},
			want:      "main output\n",
		},
		{
			name:      "unknown container name is not available",
			container: "nope",
			ephemeral: &runtimev1.ContainerStatus{Name: "dbg1", LogPath: dbgLog},
			wantErr:   `container "nope" in pod "web" is not available`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &ephemeralLogRuntime{
				logPathRuntime: &logPathRuntime{logPath: mainLog, running: true},
				ephemeral:      tt.ephemeral,
			}
			r := newLogProvider(t, f)

			rc, err := r.GetContainerLogs(context.Background(), "default", "web", tt.container, &corev1.PodLogOptions{})
			if tt.wantErr != "" {
				if err == nil {
					_ = rc.Close()
					t.Fatalf("GetContainerLogs(%q) returned no error, want %q", tt.container, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("GetContainerLogs(%q): %v", tt.container, err)
			}
			defer func() { _ = rc.Close() }()
			got, err := io.ReadAll(rc)
			if err != nil {
				t.Fatalf("read logs: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("logs = %q, want %q", got, tt.want)
			}
		})
	}
}
