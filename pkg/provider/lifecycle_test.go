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
	"time"

	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/clock"
	testclock "k8s.io/utils/clock/testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// --- lifecycle test fakes ----------------------------------------------------

// lifecycleEvent is one observed runtime side effect of a lifecycle hook test: an
// exec hook invocation or the terminating DeletePod RPC. Recording both in one
// ordered slice lets a test assert a preStop hook ran BEFORE termination and the
// grace the residual deduction passed to runtimed.
type lifecycleEvent struct {
	kind      string // "exec" | "delete"
	container string // exec: the target container
	command   []string
	grace     int64 // delete: grace_period_seconds passed to runtimed
}

// fakeLifecycleServer extends the in-memory fakeRuntimeServer with an Exec that
// records (and scripts the exit of) lifecycle exec hooks, and a DeletePod that
// records its ordinal + grace — so a hook test sees the dispatch order and the
// residual grace without a live runtimed. The exec path is the SAME r.rt.Exec the
// exec-probe uses (runExecProbe).
type fakeLifecycleServer struct {
	*fakeRuntimeServer

	emu      sync.Mutex
	events   []lifecycleEvent
	execExit int32 // scripted exec exit code (0 = success)
	execErr  error // when set, Exec fails outright (transport-level)
}

func (f *fakeLifecycleServer) Exec(stream grpc.BidiStreamingServer[runtimev1.ExecRequest, runtimev1.ExecResponse]) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}
	f.emu.Lock()
	f.events = append(f.events, lifecycleEvent{kind: "exec", container: req.GetContainer(), command: append([]string(nil), req.GetCommand()...)})
	exit, eerr := f.execExit, f.execErr
	f.emu.Unlock()
	if eerr != nil {
		return eerr
	}
	return stream.Send(&runtimev1.ExecResponse{Exit: &runtimev1.ExecResult{ExitCode: exit}})
}

func (f *fakeLifecycleServer) DeletePod(ctx context.Context, req *runtimev1.DeletePodRequest) (*runtimev1.DeletePodResponse, error) {
	f.emu.Lock()
	f.events = append(f.events, lifecycleEvent{kind: "delete", grace: req.GetGracePeriodSeconds()})
	f.emu.Unlock()
	return f.fakeRuntimeServer.DeletePod(ctx, req)
}

// snapshot returns a copy of the recorded events (ordered).
func (f *fakeLifecycleServer) snapshot() []lifecycleEvent {
	f.emu.Lock()
	defer f.emu.Unlock()
	return append([]lifecycleEvent(nil), f.events...)
}

func newLifecycleFake(t *testing.T, clk clock.Clock) (*runtimedRuntime, *fakeLifecycleServer) {
	t.Helper()
	f := &fakeLifecycleServer{fakeRuntimeServer: newFakeRuntimeServer()}
	r := newRuntimedWith(f, RuntimedConfig{NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir()}, nil, nil)
	if clk != nil {
		r.clk = clk
	}
	return r, f
}

// lifecyclePod is a single-container pod with the given termination grace and one
// lifecycle container.
func lifecyclePod(name string, grace int64, c corev1.Container) *corev1.Pod {
	p := probePod(name, c)
	p.Spec.TerminationGracePeriodSeconds = ptr(grace)
	return p
}

func hasKind(f *fakeLifecycleServer, kind string) bool {
	for _, e := range f.snapshot() {
		if e.kind == kind {
			return true
		}
	}
	return false
}

// deleteGrace returns the grace_period_seconds the (single) DeletePod RPC carried.
func deleteGrace(t *testing.T, f *fakeLifecycleServer) int64 {
	t.Helper()
	for _, e := range f.snapshot() {
		if e.kind == "delete" {
			return e.grace
		}
	}
	t.Fatal("no DeletePod RPC recorded")
	return 0
}

// waitForEvent blocks until an event of kind is recorded (postStart is dispatched
// asynchronously, so the test polls rather than racing the goroutine). It never
// sleeps in whole seconds.
func waitForEvent(t *testing.T, f *fakeLifecycleServer, kind string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if hasKind(f, kind) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("event %q never recorded; events=%+v", kind, f.snapshot())
}

// --- TestLifecycleHooksExecHTTP ----------------------------------------------

// TestLifecycleHooksExecHTTP is the B10 gate: the provider serves container
// postStart/preStop lifecycle hooks (exec, httpGet, sleep) itself — runtimed never
// sees them (toPodBox drops Lifecycle). It proves, with no live runtimed (the exec
// seam is the in-process Exec stream the exec-probe tests fake; httpGet is a
// fakeRoundTripper):
//   - postStart is DISPATCHED after CreatePod (in a goroutine);
//   - preStop runs BEFORE the runtimed DeletePod RPC, in order;
//   - the residual grace passed to runtimed is the budget minus preStop wall-time,
//     floored at 1s (never 0 — a 0 would skip SIGTERM);
//   - the httpGet handler reuses buildCheck's host/port/scheme resolution;
//   - a sleep preStop delays termination by its duration (bounded by the grace);
//   - preStop is best-effort: a failing hook does NOT abort the delete.
func TestLifecycleHooksExecHTTP(t *testing.T) {
	t.Run("postStart exec dispatched after CreatePod", func(t *testing.T) {
		r, f := newLifecycleFake(t, testclock.NewFakeClock(time.Unix(0, 0)))
		pod := lifecyclePod("ps", 30, corev1.Container{
			Name:    "c0",
			Command: []string{"/web"},
			Lifecycle: &corev1.Lifecycle{PostStart: &corev1.LifecycleHandler{
				Exec: &corev1.ExecAction{Command: []string{"/bin/poststart"}},
			}},
		})
		if err := r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		t.Cleanup(func() { _ = r.DeletePod(context.Background(), pod) })

		waitForEvent(t, f, "exec") // postStart is fired in a bounded goroutine
		ev := f.snapshot()
		if len(ev) != 1 || ev[0].kind != "exec" || ev[0].container != "c0" {
			t.Fatalf("postStart exec not dispatched after create: events=%+v", ev)
		}
		if len(ev[0].command) == 0 || ev[0].command[0] != "/bin/poststart" {
			t.Errorf("postStart exec command = %v, want [/bin/poststart]", ev[0].command)
		}
	})

	t.Run("preStop exec runs before the DeletePod RPC, in order", func(t *testing.T) {
		r, f := newLifecycleFake(t, testclock.NewFakeClock(time.Unix(0, 0)))
		pod := lifecyclePod("pre", 30, corev1.Container{
			Name:    "c0",
			Command: []string{"/web"},
			Lifecycle: &corev1.Lifecycle{PreStop: &corev1.LifecycleHandler{
				Exec: &corev1.ExecAction{Command: []string{"/bin/prestop"}},
			}},
		})
		if err := r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		if err := r.DeletePod(context.Background(), pod); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		ev := f.snapshot()
		if len(ev) != 2 || ev[0].kind != "exec" || ev[1].kind != "delete" {
			t.Fatalf("want [exec, delete] in order (preStop before terminate), got %+v", ev)
		}
		if ev[0].container != "c0" || len(ev[0].command) == 0 || ev[0].command[0] != "/bin/prestop" {
			t.Errorf("preStop exec = (%q,%v), want (c0,[/bin/prestop])", ev[0].container, ev[0].command)
		}
		// The fake clock is never stepped, so preStop elapsed is 0 ⇒ the full grace
		// reaches runtimed (no spurious deduction).
		if ev[1].grace != 30 {
			t.Errorf("DeletePod grace = %d, want 30 (instant hook, no deduction)", ev[1].grace)
		}
	})

	t.Run("preStop grace is deducted by elapsed (sleep handler delays terminate)", func(t *testing.T) {
		clk := testclock.NewFakeClock(time.Unix(0, 0))
		r, f := newLifecycleFake(t, clk)
		pod := lifecyclePod("ded", 30, corev1.Container{
			Name:    "c0",
			Command: []string{"/web"},
			Lifecycle: &corev1.Lifecycle{PreStop: &corev1.LifecycleHandler{
				Sleep: &corev1.SleepAction{Seconds: 4},
			}},
		})
		if err := r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		done := make(chan error, 1)
		go func() { done <- r.DeletePod(context.Background(), pod) }()

		waitWaiters(t, clk, 1) // the preStop sleep is parked on its 4s timer
		if hasKind(f, "delete") {
			t.Fatal("DeletePod RPC fired before the preStop sleep elapsed (sleep did not delay terminate)")
		}
		clk.Step(4 * time.Second) // the sleep elapses
		if err := <-done; err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		if g := deleteGrace(t, f); g != 26 {
			t.Errorf("residual grace = %d, want 26 (30 budget − 4s preStop)", g)
		}
	})

	t.Run("a preStop that drains the full grace floors at 1s (never 0)", func(t *testing.T) {
		clk := testclock.NewFakeClock(time.Unix(0, 0))
		r, f := newLifecycleFake(t, clk)
		pod := lifecyclePod("floor", 5, corev1.Container{
			Name:    "c0",
			Command: []string{"/web"},
			Lifecycle: &corev1.Lifecycle{PreStop: &corev1.LifecycleHandler{
				Sleep: &corev1.SleepAction{Seconds: 5}, // == the whole grace budget
			}},
		})
		if err := r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		done := make(chan error, 1)
		go func() { done <- r.DeletePod(context.Background(), pod) }()

		waitWaiters(t, clk, 1)
		clk.Step(5 * time.Second)
		if err := <-done; err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		// 5 − 5 = 0, but the floor MUST pass 1 so runtimed still sends SIGTERM
		// (a resolved 0 is an immediate SIGKILL with no SIGTERM).
		if g := deleteGrace(t, f); g != 1 {
			t.Errorf("residual grace = %d, want 1 (floored, never 0)", g)
		}
	})

	t.Run("httpGet preStop hits the probe transport with buildCheck resolution", func(t *testing.T) {
		r, f := newLifecycleFake(t, testclock.NewFakeClock(time.Unix(0, 0)))
		rt := &fakeRoundTripper{status: 200}
		r.probeTransport = rt
		pod := lifecyclePod("http", 30, corev1.Container{
			Name:    "c0",
			Command: []string{"/web"},
			Ports:   []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}},
			Lifecycle: &corev1.Lifecycle{PreStop: &corev1.LifecycleHandler{
				HTTPGet: &corev1.HTTPGetAction{Path: "/quit", Port: intstr.FromString("http")},
			}},
		})
		// By delete time the pod IP is bound; the httpGet host defaults to it.
		pod.Status.PodIP = "10.0.0.5"
		if err := r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		if err := r.DeletePod(context.Background(), pod); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		// Named port resolved via the container port table + host defaulted to the
		// pod IP — exactly buildCheck's resolution.
		if !strings.Contains(rt.gotURL, "10.0.0.5:8080/quit") {
			t.Fatalf("httpGet preStop did not resolve like buildCheck: gotURL=%q, want host=pod IP, named port→8080", rt.gotURL)
		}
		if !hasKind(f, "delete") {
			t.Error("DeletePod RPC must still fire after an httpGet preStop")
		}
	})

	t.Run("a failing preStop does not abort the delete (best-effort)", func(t *testing.T) {
		r, f := newLifecycleFake(t, testclock.NewFakeClock(time.Unix(0, 0)))
		f.execExit = 7 // the preStop hook exits non-zero
		pod := lifecyclePod("besteffort", 30, corev1.Container{
			Name:    "c0",
			Command: []string{"/web"},
			Lifecycle: &corev1.Lifecycle{PreStop: &corev1.LifecycleHandler{
				Exec: &corev1.ExecAction{Command: []string{"/bin/fails"}},
			}},
		})
		if err := r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		if err := r.DeletePod(context.Background(), pod); err != nil {
			t.Fatalf("DeletePod must not error on a failed preStop: %v", err)
		}
		ev := f.snapshot()
		if len(ev) != 2 || ev[0].kind != "exec" || ev[1].kind != "delete" {
			t.Fatalf("a failed preStop must still terminate: want [exec, delete], got %+v", ev)
		}
	})
}
