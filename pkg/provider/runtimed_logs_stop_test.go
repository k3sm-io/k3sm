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
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/provider/podlogs"
)

// stopTestDeadline bounds every wait in these tests. It is a failure bound only:
// a passing run never reaches it.
const stopTestDeadline = 20 * time.Second

// stoppingRuntime behaves as runtimed does across a delete: the pod leaves the
// table the moment DeletePod begins, so GetPodStatus answers an in-band NotFound
// while the stop is still running, and the output keeps landing until the RPC
// returns. Each DeletePod blocks on release.
type stoppingRuntime struct {
	logPathRuntime

	entered  chan struct{}
	release  chan struct{}
	notFound chan struct{}

	// beforeReturn runs as the stop finishes, the output's last write.
	beforeReturn func()
	// deleteErr is what DeletePod returns once released.
	deleteErr error

	enterOnce    sync.Once
	notFoundOnce sync.Once
	releaseOnce  sync.Once
	stateMu      sync.Mutex
	gone         map[string]bool
	statusErr    error
}

func newStoppingRuntime(logPath string) *stoppingRuntime {
	return &stoppingRuntime{
		logPathRuntime: logPathRuntime{logPath: logPath, running: true},
		entered:        make(chan struct{}),
		release:        make(chan struct{}),
		notFound:       make(chan struct{}),
		gone:           map[string]bool{},
	}
}

// finishStop releases every DeletePod, now and to come.
func (f *stoppingRuntime) finishStop() {
	f.releaseOnce.Do(func() { close(f.release) })
}

func (f *stoppingRuntime) forget(id string) {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	f.gone[id] = true
}

func (f *stoppingRuntime) failStatus(err error) {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	f.statusErr = err
}

func (f *stoppingRuntime) DeletePod(_ context.Context, req *runtimev1.DeletePodRequest) (*runtimev1.DeletePodResponse, error) {
	f.forget(req.GetPodId())
	f.enterOnce.Do(func() { close(f.entered) })
	<-f.release
	if f.beforeReturn != nil {
		f.beforeReturn()
	}
	return &runtimev1.DeletePodResponse{}, f.deleteErr
}

func (f *stoppingRuntime) GetPodStatus(ctx context.Context, req *runtimev1.GetPodStatusRequest) (*runtimev1.GetPodStatusResponse, error) {
	f.stateMu.Lock()
	gone, statusErr := f.gone[req.GetPodId()], f.statusErr
	f.stateMu.Unlock()
	if statusErr != nil {
		return nil, statusErr
	}
	if gone {
		f.notFoundOnce.Do(func() { close(f.notFound) })
		return &runtimev1.GetPodStatusResponse{
			Error: &rpcstatus.Status{Code: int32(codes.NotFound), Message: "pod not found"},
		}, nil
	}
	return f.logPathRuntime.GetPodStatus(ctx, req)
}

// awaitStopEvent fails the test if ch does not close within the deadline.
func awaitStopEvent(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	timer := time.NewTimer(stopTestDeadline)
	defer timer.Stop()
	select {
	case <-ch:
	case <-timer.C:
		t.Fatalf("timed out waiting for %s", what)
	}
}

// followerGoroutines counts the goroutines a follow owns: the producer behind
// the pipe, and the file watcher's reader.
func followerGoroutines() int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			stacks := string(buf[:n])
			return strings.Count(stacks, "created by k3sm.io/k3sm/pkg/provider.(*runtimedRuntime).GetContainerLogs") +
				strings.Count(stacks, "created by github.com/fsnotify/fsnotify.")
		}
		buf = make([]byte, 2*len(buf))
	}
}

// awaitNoFollowers fails the test unless the follower count returns to baseline.
func awaitNoFollowers(t *testing.T, baseline int) {
	t.Helper()
	timer := time.NewTimer(stopTestDeadline)
	defer timer.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for followerGoroutines() > baseline {
		select {
		case <-ticker.C:
		case <-timer.C:
			t.Fatalf("%d follower goroutines outlived the stream, baseline %d", followerGoroutines(), baseline)
		}
	}
}

// followHarness is one pod on a provider, with a follower open and its first
// line read.
type followHarness struct {
	f        *stoppingRuntime
	r        *runtimedRuntime
	pod      *corev1.Pod
	path     string
	rc       io.ReadCloser
	br       *bufio.Reader
	baseline int
}

func newFollowHarness(t *testing.T, pod *corev1.Pod) *followHarness {
	t.Helper()
	logsDir := t.TempDir()
	container := pod.Spec.Containers[0].Name
	path := podlogs.BuildContainerLogsPath(logsDir, pod.Namespace, pod.Name, string(pod.UID), container, 0)
	f := newStoppingRuntime(path)
	r := newRuntimedWith(f, RuntimedConfig{NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: logsDir}, nil, nil)
	if err := r.CreatePod(context.Background(), pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("make log dir: %v", err)
	}
	if err := os.WriteFile(path, []byte(stopLine("before")), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	baseline := followerGoroutines()
	rc, err := r.GetContainerLogs(context.Background(), pod.Namespace, pod.Name, "c0", &corev1.PodLogOptions{Follow: true})
	if err != nil {
		t.Fatalf("GetContainerLogs: %v", err)
	}
	t.Cleanup(f.finishStop)
	t.Cleanup(func() { _ = rc.Close() })
	// A hung stream fails its read rather than the whole test binary.
	watchdog := time.AfterFunc(stopTestDeadline, func() { _ = rc.Close() })
	t.Cleanup(func() { watchdog.Stop() })

	h := &followHarness{f: f, r: r, pod: pod, path: path, rc: rc, br: bufio.NewReader(rc), baseline: baseline}
	h.wantLine(t, "before")
	if n := followerGoroutines(); n <= baseline {
		t.Fatalf("no follower goroutine counted with one running (%d, baseline %d): the leak check is blind", n, baseline)
	}
	return h
}

func stopLine(content string) string {
	return criLine(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), "stdout", "F", content)
}

func (h *followHarness) wantLine(t *testing.T, want string) {
	t.Helper()
	got, err := h.br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading %q: the stream ended: %v", want, err)
	}
	if strings.TrimSuffix(got, "\n") != want {
		t.Fatalf("line = %q, want %q", got, want)
	}
}

// deleteAsync runs the provider's delete and closes the returned channel when it
// returns, recording its error in *err.
func (h *followHarness) deleteAsync(pod *corev1.Pod, err *error) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		*err = h.r.DeletePod(context.Background(), pod)
	}()
	return done
}

// wantLogsRemoved fails unless the delete removed the file a follower holds.
func (h *followHarness) wantLogsRemoved(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(h.path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("log file after the delete: stat err = %v, want it removed", err)
	}
}

// fillerLines is more output than the reader's buffer holds, so a follower
// blocked on its client has the tail of it left to read from the file.
const fillerLines = 64

// writeFinalOutput appends the stop's last output: filler, then the last line. It
// runs inside the fake's DeletePod, off the test's goroutine.
func writeFinalOutput(t *testing.T, path string) {
	t.Helper()
	var b strings.Builder
	for i := range fillerLines {
		b.WriteString(stopLine(fmt.Sprintf("filler %02d %s", i, strings.Repeat("x", 1024))))
	}
	b.WriteString(stopLine("last"))
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Errorf("open log for the final output: %v", err)
		return
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(b.String()); err != nil {
		t.Errorf("write the final output: %v", err)
	}
}

// TestLogsFollowStaysOpenThroughVMPodStop is the `kubectl logs -f` contract over
// a delete: the runtime forgets the pod as the stop begins, and the stream keeps
// following until the delete has returned and the file has been read to its end.
func TestLogsFollowStaysOpenThroughVMPodStop(t *testing.T) {
	vm := vmPod("default", "web")
	native := runtimedPod("default", "web")

	for _, tt := range []struct {
		name string
		pod  *corev1.Pod
	}{
		{"vm pod", vm},
		{"native pod", native},
	} {
		t.Run(tt.name+" follows through the stop and ends cleanly", func(t *testing.T) {
			h := newFollowHarness(t, tt.pod)
			h.f.beforeReturn = func() { writeFinalOutput(t, h.path) }

			var delErr error
			deleted := h.deleteAsync(tt.pod, &delErr)
			awaitStopEvent(t, h.f.entered, "the runtime's stop to begin")
			awaitStopEvent(t, h.f.notFound, "the follower to read the runtime's NotFound")

			appendLine(t, h.path, stopLine("during"))
			h.wantLine(t, "during")

			// The follower is not read from again until the delete has returned
			// and the file is gone: neither may wait on the other, and the tail
			// is only reachable through the descriptor it still holds.
			h.f.finishStop()
			awaitStopEvent(t, deleted, "the delete to return with a follower attached")
			if delErr != nil {
				t.Fatalf("DeletePod: %v", delErr)
			}
			h.wantLogsRemoved(t)

			rest, err := io.ReadAll(h.br)
			if err != nil {
				t.Fatalf("stream end: %v, want a clean end", err)
			}
			if got := strings.Count(string(rest), "filler"); got != fillerLines {
				t.Errorf("filler lines after the delete = %d, want %d", got, fillerLines)
			}
			if !strings.HasSuffix(string(rest), "last\n") {
				t.Errorf("stream did not end with the last line; tail = %q", rest[max(0, len(rest)-40):])
			}
			// Before Close: the stream's end alone releases the goroutines.
			awaitNoFollowers(t, h.baseline)
		})
	}

	t.Run("a NotFound outside a delete ends with the error", func(t *testing.T) {
		h := newFollowHarness(t, native.DeepCopy())
		h.f.forget(string(h.pod.UID))

		_, err := io.ReadAll(h.br)
		want := `container "c0" in pod "web" is not available`
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("stream end = %v, want %q", err, want)
		}
		awaitNoFollowers(t, h.baseline)
	})

	t.Run("a failed delete the runtime has forgotten ends cleanly", func(t *testing.T) {
		h := newFollowHarness(t, native.DeepCopy())
		h.f.deleteErr = status.Error(codes.Internal, "stop failed")

		var delErr error
		deleted := h.deleteAsync(h.pod, &delErr)
		awaitStopEvent(t, h.f.notFound, "the follower to read the runtime's NotFound")
		h.f.finishStop()
		awaitStopEvent(t, deleted, "the delete to return")
		if status.Code(errors.Unwrap(delErr)) != codes.Internal {
			t.Fatalf("DeletePod = %v, want the runtime's refusal", delErr)
		}

		if _, err := io.ReadAll(h.br); err != nil {
			t.Fatalf("stream end: %v, want a clean end", err)
		}
		awaitNoFollowers(t, h.baseline)
	})

	t.Run("a stalled client holds neither the delete nor a goroutine", func(t *testing.T) {
		h := newFollowHarness(t, native.DeepCopy())
		h.f.beforeReturn = func() { writeFinalOutput(t, h.path) }

		var delErr error
		deleted := h.deleteAsync(h.pod, &delErr)
		h.f.finishStop()
		awaitStopEvent(t, deleted, "the delete to return with a stalled client")
		if delErr != nil {
			t.Fatalf("DeletePod: %v", delErr)
		}
		h.wantLogsRemoved(t)

		if err := h.rc.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		awaitNoFollowers(t, h.baseline)
	})

	t.Run("a same-name successor does not keep the follower open", func(t *testing.T) {
		h := newFollowHarness(t, native.DeepCopy())
		successor := native.DeepCopy()
		successor.UID = types.UID(string(native.UID) + "-next")
		if err := h.r.CreatePod(context.Background(), successor); err != nil {
			t.Fatalf("CreatePod successor: %v", err)
		}

		var delErr error
		deleted := h.deleteAsync(h.pod, &delErr)
		h.f.finishStop()
		awaitStopEvent(t, deleted, "the delete to return")
		if delErr != nil {
			t.Fatalf("DeletePod: %v", delErr)
		}

		if _, err := io.ReadAll(h.br); err != nil {
			t.Fatalf("stream end: %v, want a clean end", err)
		}
		awaitNoFollowers(t, h.baseline)
	})

	t.Run("an unreachable runtime after the delete does not keep the follower open", func(t *testing.T) {
		h := newFollowHarness(t, native.DeepCopy())
		h.f.beforeReturn = func() { h.f.failStatus(status.Error(codes.Unavailable, "runtime restarting")) }

		var delErr error
		deleted := h.deleteAsync(h.pod, &delErr)
		h.f.finishStop()
		awaitStopEvent(t, deleted, "the delete to return")
		if delErr != nil {
			t.Fatalf("DeletePod: %v", delErr)
		}

		if _, err := io.ReadAll(h.br); err != nil {
			t.Fatalf("stream end: %v, want a clean end", err)
		}
		awaitNoFollowers(t, h.baseline)
	})
}
