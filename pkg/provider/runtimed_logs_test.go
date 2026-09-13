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
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	testclock "k8s.io/utils/clock/testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// logPathRuntime is a runtimev1.RuntimeServer that reports per-container
// log_path values (current instance and the previous one) and records the
// PodBox it was handed. It answers GetLogs Unimplemented on purpose: the
// provider must never reach for the RPC again, so a test that passed by
// accidentally streaming over the wire would be lying about where the bytes
// came from.
type logPathRuntime struct {
	runtimev1.UnimplementedRuntimeServer

	mu       sync.Mutex
	box      *runtimev1.PodBox
	logPath  string
	prevPath string
	running  bool
	reopened []string
}

func (f *logPathRuntime) CreatePod(_ context.Context, req *runtimev1.CreatePodRequest) (*runtimev1.CreatePodResponse, error) {
	f.mu.Lock()
	f.box = req.GetPod()
	f.mu.Unlock()
	return &runtimev1.CreatePodResponse{Status: f.status(req.GetPod().GetPodId())}, nil
}

func (f *logPathRuntime) DeletePod(_ context.Context, _ *runtimev1.DeletePodRequest) (*runtimev1.DeletePodResponse, error) {
	return &runtimev1.DeletePodResponse{}, nil
}

func (f *logPathRuntime) GetPodStatus(_ context.Context, req *runtimev1.GetPodStatusRequest) (*runtimev1.GetPodStatusResponse, error) {
	return &runtimev1.GetPodStatusResponse{Status: f.status(req.GetPodId())}, nil
}

func (f *logPathRuntime) ReopenContainerLog(_ context.Context, req *runtimev1.ReopenContainerLogRequest) (*runtimev1.ReopenContainerLogResponse, error) {
	f.mu.Lock()
	f.reopened = append(f.reopened, req.GetPodId()+"/"+req.GetContainer())
	f.mu.Unlock()
	return &runtimev1.ReopenContainerLogResponse{}, nil
}

// status renders one running (or terminated) container "c0" carrying the
// configured log paths.
func (f *logPathRuntime) status(podID string) *runtimev1.PodStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	cs := &runtimev1.ContainerStatus{
		Name:        "c0",
		ContainerId: "c0-id",
		LogPath:     f.logPath,
	}
	if f.running {
		cs.State = &runtimev1.ContainerState{Running: &runtimev1.ContainerStateRunning{}}
	} else {
		cs.State = &runtimev1.ContainerState{Terminated: &runtimev1.ContainerStateTerminated{LogPath: f.logPath}}
	}
	if f.prevPath != "" {
		cs.LastTerminationState = &runtimev1.ContainerState{
			Terminated: &runtimev1.ContainerStateTerminated{LogPath: f.prevPath, ContainerId: "c0-prev"},
		}
	}
	return &runtimev1.PodStatus{
		PodId:             podID,
		Phase:             runtimev1.PodPhase_POD_PHASE_RUNNING,
		ContainerStatuses: []*runtimev1.ContainerStatus{cs},
	}
}

// criLine renders one CRI log line.
func criLine(ts time.Time, stream, tag, content string) string {
	return ts.Format("2006-01-02T15:04:05.000000000Z07:00") + " " + stream + " " + tag + " " + content + "\n"
}

// TestContainerLogsReadFromLogPath is the B282 gate, and the SUCCESSOR to B163's
// TestContainerLogOptsForwarded.
//
// That test asserted every `kubectl logs` option reached the runtime as a field
// on a GetLogsRequest. The contract has moved: the node is the kubelet now, so
// the options must reach a FILE READER and be evaluated against the bytes on
// disk at ContainerStatus.log_path. The fake below answers GetLogs with
// Unimplemented, so any implementation that still went over the RPC fails here
// rather than passing on a technicality.
//
// Each case asserts the RENDERED OUTPUT, not a struct field, which is the only
// assertion that can tell "the option was plumbed" from "the option was applied".
func TestContainerLogsReadFromLogPath(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	path := filepath.Join(dir, "0.log")
	body := criLine(now.Add(-3*time.Minute), "stdout", "F", "one") +
		criLine(now.Add(-2*time.Minute), "stderr", "F", "two") +
		criLine(now.Add(-1*time.Minute), "stdout", "P", "thr") +
		criLine(now.Add(-1*time.Minute), "stdout", "F", "ee")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	prev := filepath.Join(dir, "prev.log")
	if err := os.WriteFile(prev, []byte(criLine(now.Add(-time.Hour), "stdout", "F", "older instance")), 0o600); err != nil {
		t.Fatalf("write previous log: %v", err)
	}

	tail := func(n int64) *int64 { return &n }
	limit := func(n int64) *int64 { return &n }

	tests := []struct {
		name string
		opts *corev1.PodLogOptions
		want string
	}{
		{
			name: "no options reads the whole file with P segments concatenated",
			opts: &corev1.PodLogOptions{},
			want: "one\ntwo\nthree\n",
		},
		{
			name: "tailLines counts FILE lines, not logical lines",
			opts: &corev1.PodLogOptions{TailLines: tail(2)},
			want: "thr" + "ee\n",
		},
		{
			name: "tailLines=0 is zero lines, distinct from unset",
			opts: &corev1.PodLogOptions{TailLines: tail(0)},
			want: "",
		},
		{
			name: "timestamps prefix only the first segment of a logical line",
			opts: &corev1.PodLogOptions{TailLines: tail(2), Timestamps: true},
			want: now.Add(-1*time.Minute).Format("2006-01-02T15:04:05.000000000Z07:00") + " three\n",
		},
		{
			name: "sinceTime is strictly Before, so the line stamped at it is kept",
			opts: &corev1.PodLogOptions{SinceTime: &metav1.Time{Time: now.Add(-2 * time.Minute)}},
			want: "two\nthree\n",
		},
		{
			name: "sinceSeconds resolves against the provider clock",
			opts: &corev1.PodLogOptions{SinceSeconds: tail(150)},
			want: "two\nthree\n",
		},
		{
			name: "limitBytes cuts mid-line on the rendered bytes",
			opts: &corev1.PodLogOptions{LimitBytes: limit(5)},
			want: "one\nt",
		},
		{
			name: "previous reads the last terminated instance's file",
			opts: &corev1.PodLogOptions{Previous: true},
			want: "older instance\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &logPathRuntime{logPath: path, prevPath: prev, running: true}
			r := newLogProvider(t, f)
			r.clk = testclock.NewFakeClock(now)

			rc, err := r.GetContainerLogs(context.Background(), "default", "web", "c0", tt.opts)
			if err != nil {
				t.Fatalf("GetContainerLogs: %v", err)
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

	// The refusal that `--previous` owed a user before this landed: once the log
	// GC has pruned the previous instance, saying so is the honest answer. The
	// wrong answer — and the one a naive implementation gives — is the CURRENT
	// instance's output presented as the previous one's.
	t.Run("previous with no retained instance refuses by name", func(t *testing.T) {
		f := &logPathRuntime{logPath: path, running: true}
		r := newLogProvider(t, f)
		_, err := r.GetContainerLogs(context.Background(), "default", "web", "c0", &corev1.PodLogOptions{Previous: true})
		if err == nil {
			t.Fatal("GetContainerLogs(previous) with no retained instance returned no error")
		}
		if want := `previous terminated container "c0" in pod "web" not found`; !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to contain %q (the kubelet's own text)", err, want)
		}
	})

	// follow must hand bytes back as they land, and must end with ONE final drain
	// after the container exits, so the last thing a dying process wrote is not
	// lost. Both are asserted on one stream.
	t.Run("follow streams incrementally and drains once after exit", func(t *testing.T) {
		fdir := t.TempDir()
		fpath := filepath.Join(fdir, "0.log")
		if err := os.WriteFile(fpath, []byte(criLine(now, "stdout", "F", "first")), 0o600); err != nil {
			t.Fatalf("write log: %v", err)
		}
		f := &logPathRuntime{logPath: fpath, running: true}
		r := newLogProvider(t, f)

		rc, err := r.GetContainerLogs(context.Background(), "default", "web", "c0", &corev1.PodLogOptions{Follow: true})
		if err != nil {
			t.Fatalf("GetContainerLogs: %v", err)
		}
		defer func() { _ = rc.Close() }()

		buf := make([]byte, 64)
		n, err := rc.Read(buf)
		if err != nil {
			t.Fatalf("read before the stream ended: %v", err)
		}
		if got := string(buf[:n]); !strings.HasPrefix(got, "first") {
			t.Fatalf("first read = %q, want the existing line while the stream is still open", got)
		}

		appendLine(t, fpath, criLine(now.Add(time.Second), "stdout", "F", "later"))
		n, err = rc.Read(buf)
		if err != nil {
			t.Fatalf("read of the followed line: %v", err)
		}
		if got := string(buf[:n]); !strings.HasPrefix(got, "later") {
			t.Fatalf("second read = %q, want the line written after the stream opened", got)
		}

		// The container exits, and writes one last line as it goes. The stream
		// must deliver that line and only then end.
		appendLine(t, fpath, criLine(now.Add(2*time.Second), "stderr", "F", "goodbye"))
		f.mu.Lock()
		f.running = false
		f.mu.Unlock()

		rest, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("final drain: %v", err)
		}
		if !strings.Contains(string(rest), "goodbye") {
			t.Errorf("final drain = %q, want it to contain the last line written before the container exited", rest)
		}
	})
}

// appendLine appends one line to a log file the way the runtime's writer would.
func appendLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open log for append: %v", err)
	}
	if _, err := f.WriteString(line); err != nil {
		t.Fatalf("append log line: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close log: %v", err)
	}
}

// newLogProvider builds a provider over f with one created pod, ready to serve
// logs.
func newLogProvider(t *testing.T, f runtimev1.RuntimeServer) *runtimedRuntime {
	t.Helper()
	r := newRuntimedWith(f, RuntimedConfig{NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: t.TempDir()}, nil, nil)
	if err := r.CreatePod(context.Background(), runtimedPod("default", "web")); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	return r
}

// TestCreatePodSetsLogDirectory proves the node creates the pod's CRI log tree
// and NAMES it on the box, before the runtime is asked to start anything.
//
// Both halves matter and neither implies the other. runtimed creates no
// directory above the container's own, so a box that names a tree nobody created
// starts a pod with nowhere to write; and a tree created under a directory the
// box does not name is a tree nothing will ever write into. The directory shape
// is the kubelet's, checked literally, because it is what every log shipper and
// every support answer in the ecosystem globs.
func TestCreatePodSetsLogDirectory(t *testing.T) {
	root := t.TempDir()
	f := &logPathRuntime{running: true}
	r := newRuntimedWith(f, RuntimedConfig{NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: root}, nil, nil)

	pod := runtimedPod("default", "web")
	pod.Spec.InitContainers = []corev1.Container{{Name: "init0", Image: "registry/init:latest"}}
	if err := r.CreatePod(context.Background(), pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}

	wantDir := filepath.Join(root, "default_web_uid-web")
	f.mu.Lock()
	box := f.box
	f.mu.Unlock()
	if box == nil {
		t.Fatal("the runtime never received a PodBox")
	}
	if box.GetLogDirectory() != wantDir {
		t.Errorf("PodBox.log_directory = %q, want %q", box.GetLogDirectory(), wantDir)
	}

	// Init containers get a directory too: `kubectl logs -c init0` is a thing, and
	// an init container that fails is exactly when somebody asks for it.
	for _, name := range []string{"c0", "init0"} {
		dir := filepath.Join(wantDir, name)
		info, err := os.Stat(dir)
		if err != nil {
			t.Errorf("container log directory %s: %v", dir, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("%s is not a directory", dir)
			continue
		}
		// 0700, not upstream's 0755: this tree is owned by _k3sm, whose primary
		// group is the default group of every ordinary macOS account.
		if perm := info.Mode().Perm(); perm != 0o700 {
			t.Errorf("%s mode = %#o, want 0700 (pod output must not be readable by every local account)", dir, perm)
		}
	}

	// And the tree goes when the pod does.
	if err := r.DeletePod(context.Background(), pod); err != nil {
		t.Fatalf("DeletePod: %v", err)
	}
	if _, err := os.Stat(wantDir); !os.IsNotExist(err) {
		t.Errorf("pod log directory still present after DeletePod: stat err = %v, want not-exist", err)
	}
}
