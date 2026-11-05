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
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"

	budgetv1alpha1 "k3sm.io/apis/budget/v1alpha1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// fileEvictions reads the history file in dir and returns band's eviction total.
func fileEvictions(t *testing.T, dir string, band budgetv1alpha1.Band) int64 {
	t.Helper()
	st, err := readHistory(filepath.Join(dir, budgetHistoryFile))
	if err != nil {
		t.Fatal(err)
	}
	return st.Totals[band].Evictions
}

// TestStopBudgetHistoryFlushesAfterTheContextEnds: the node context ends
// before the node teardown calls StopBudgetHistory, so the writer has already
// made its final flush and exited. A change recorded after that (the eviction
// loop's last count, a teardown's intent) is still on disk once stop returns.
//
// Fails-before: stop saw the writer already stopped and reported true, and
// nothing wrote the later change.
func TestStopBudgetHistoryFlushesAfterTheContextEnds(t *testing.T) {
	synctest.Test(t, testStopBudgetHistoryFlushesAfterTheContextEnds)
}

func testStopBudgetHistoryFlushesAfterTheContextEnds(t *testing.T) {
	dir := t.TempDir()
	h := OpenBudgetHistory(dir, "fp", discardLog())
	ctx, cancel := context.WithCancel(context.Background())
	h.start(ctx)
	cancel()
	// Once the bubble is idle the writer has made its final flush and returned,
	// or it is parked and never will.
	synctest.Wait()
	select {
	case <-h.stopped:
	default:
		t.Fatal("the writer did not exit when its context ended")
	}
	h.record("", budgetv1alpha1.BandBatch, budgetv1alpha1.CounterEviction, time.Now())
	if !h.stop(BudgetHistoryStopBound) {
		t.Fatal("stop did not finish in its bound")
	}
	if got := fileEvictions(t, dir, budgetv1alpha1.BandBatch); got != 1 {
		t.Fatalf("the file holds evictions=%d after stop, want 1", got)
	}
	// A change after stop has returned is no longer covered; a second stop
	// still writes what is pending.
	h.record("", budgetv1alpha1.BandBatch, budgetv1alpha1.CounterEviction, time.Now())
	if !h.stop(BudgetHistoryStopBound) {
		t.Fatal("a second stop did not finish in its bound")
	}
	if got := fileEvictions(t, dir, budgetv1alpha1.BandBatch); got != 2 {
		t.Fatalf("the file holds evictions=%d after a second stop, want 2", got)
	}
}

// TestBudgetHistoryStartAfterStopLaunchesNoWriter: a start that runs after stop
// (a Watch racing the node teardown) launches no writer nobody would join, and
// a change recorded before stop with no writer ever started is still written.
//
// Fails-before: stop with no writer returned at once without writing, and the
// late start launched a writer after the teardown had finished.
func TestBudgetHistoryStartAfterStopLaunchesNoWriter(t *testing.T) {
	dir := t.TempDir()
	h := OpenBudgetHistory(dir, "fp", discardLog())
	h.record("", budgetv1alpha1.BandBatch, budgetv1alpha1.CounterEviction, time.Now())
	if !h.stop(BudgetHistoryStopBound) {
		t.Fatal("stop did not finish in its bound")
	}
	h.start(context.Background())
	if h.started.Load() {
		t.Fatal("a start after stop launched a writer")
	}
	if got := fileEvictions(t, dir, budgetv1alpha1.BandBatch); got != 1 {
		t.Fatalf("the file holds evictions=%d after stop, want 1", got)
	}
}

// TestBudgetHistoryStopOutwaitsTheFinalFlush: the node teardown's wait is
// strictly longer than the writer's own final-flush bound, so a final flush
// that uses its whole bound is still joined.
//
// Fails-before: both were budgetHistoryFinalFlushBound, so a flush near its
// bound raced the teardown's timer.
func TestBudgetHistoryStopOutwaitsTheFinalFlush(t *testing.T) {
	if BudgetHistoryStopBound <= budgetHistoryFinalFlushBound {
		t.Fatalf("BudgetHistoryStopBound %v must exceed budgetHistoryFinalFlushBound %v",
			BudgetHistoryStopBound, budgetHistoryFinalFlushBound)
	}
}

// TestInconclusiveStopKeepsItsIntent: a stop RPC that may have reached
// runtimed (a deadline, an unavailable or reset transport, an Unknown status)
// keeps its intent, because the kill may have happened: the container's later
// exit 137 is k3sm's own, not a SIGKILL k3sm did not send.
//
// Fails-before: every stop error dropped the intent, so the exit counted as
// uninitiated.
func TestInconclusiveStopKeepsItsIntent(t *testing.T) {
	ctx := context.Background()
	queueDelete := func(f *fakeRuntimeServer, err error) {
		f.mu.Lock()
		f.deleteFIFO = append(f.deleteFIFO, err)
		f.mu.Unlock()
	}
	cases := []struct {
		name string
		stop func(t *testing.T, r *runtimedRuntime, f *fakeRuntimeServer, pod *corev1.Pod)
	}{
		{"teardown DeletePod DeadlineExceeded", func(t *testing.T, r *runtimedRuntime, f *fakeRuntimeServer, pod *corev1.Pod) {
			queueDelete(f, status.Error(codes.DeadlineExceeded, "deadline"))
			if err := r.teardownPod(ctx, pod, minimumGracePeriodSeconds, nil); err == nil {
				t.Fatal("the delete did not fail")
			}
		}},
		{"teardown DeletePod Unavailable", func(t *testing.T, r *runtimedRuntime, f *fakeRuntimeServer, pod *corev1.Pod) {
			queueDelete(f, status.Error(codes.Unavailable, "connection reset"))
			if err := r.teardownPod(ctx, pod, minimumGracePeriodSeconds, nil); err == nil {
				t.Fatal("the delete did not fail")
			}
		}},
		{"evict DeletePod Unavailable", func(t *testing.T, r *runtimedRuntime, f *fakeRuntimeServer, pod *corev1.Pod) {
			queueDelete(f, status.Error(codes.Unavailable, "connection reset"))
			if err := r.evictPod(ctx, pod, evictionNotice{signal: signalCompressor, message: "x"}); err == nil {
				t.Fatal("the eviction's delete did not fail")
			}
		}},
		{"evict DeletePod DeadlineExceeded", func(t *testing.T, r *runtimedRuntime, f *fakeRuntimeServer, pod *corev1.Pod) {
			queueDelete(f, status.Error(codes.DeadlineExceeded, "deadline"))
			if err := r.evictPod(ctx, pod, evictionNotice{signal: signalCompressor, message: "x"}); err == nil {
				t.Fatal("the eviction's delete did not fail")
			}
		}},
		{"StopContainer Unavailable", func(t *testing.T, r *runtimedRuntime, f *fakeRuntimeServer, pod *corev1.Pod) {
			f.setStopErr(status.Error(codes.Unavailable, "connection reset"))
			if err := r.stopContainerReason(ctx, string(pod.UID), "c0", reasonFailedPostStartHook); err == nil {
				t.Fatal("the stop did not fail")
			}
		}},
		{"StopContainer Unknown transport error", func(t *testing.T, r *runtimedRuntime, f *fakeRuntimeServer, pod *corev1.Pod) {
			f.setStopErr(errors.New("connection reset"))
			if err := r.stopContainerReason(ctx, string(pod.UID), "c0", reasonFailedPostStartHook); err == nil {
				t.Fatal("the stop did not fail")
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, f := newRuntimedFake(t)
			r.history = openHistory(t, t.TempDir(), "fp")
			pod := runtimedPod("default", "web")
			if err := r.CreatePod(ctx, pod); err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			tc.stop(t, r, f, pod)
			if got := intentsFor(r.history, pod.UID); len(got) != 1 {
				t.Fatalf("intents after an inconclusive stop = %+v, want the one recorded", got)
			}
			observe(t, r.history, pod.UID, "c0", 0, 1, exitOf(137, "Error"), time.Now())
			if got := uninitiated(t, r.history, time.Now()); got != 0 {
				t.Fatalf("the exit after an inconclusive stop counted as uninitiated: %d", got)
			}
		})
	}
}

// TestDefinitiveStopRefusalDropsItsIntent: a stop runtimed definitively did
// not carry out (NotFound, InvalidArgument, FailedPrecondition, Unimplemented,
// PermissionDenied, in transport or in the response) drops its intent, so a
// later exit 137 is classified as if k3sm had not stopped the container.
func TestDefinitiveStopRefusalDropsItsIntent(t *testing.T) {
	ctx := context.Background()
	queueDelete := func(f *fakeRuntimeServer, err error) {
		f.mu.Lock()
		f.deleteFIFO = append(f.deleteFIFO, err)
		f.mu.Unlock()
	}
	refusal := func(c codes.Code) *runtimev1.StopContainerResponse {
		return &runtimev1.StopContainerResponse{Error: status.New(c, "refused").Proto()}
	}
	cases := []struct {
		name string
		stop func(t *testing.T, r *runtimedRuntime, f *fakeRuntimeServer, pod *corev1.Pod)
	}{
		{"teardown DeletePod NotFound", func(t *testing.T, r *runtimedRuntime, f *fakeRuntimeServer, pod *corev1.Pod) {
			queueDelete(f, status.Error(codes.NotFound, "no such pod"))
			if err := r.teardownPod(ctx, pod, minimumGracePeriodSeconds, nil); err == nil {
				t.Fatal("the delete did not fail")
			}
		}},
		{"teardown DeletePod PermissionDenied", func(t *testing.T, r *runtimedRuntime, f *fakeRuntimeServer, pod *corev1.Pod) {
			queueDelete(f, status.Error(codes.PermissionDenied, "denied"))
			if err := r.teardownPod(ctx, pod, minimumGracePeriodSeconds, nil); err == nil {
				t.Fatal("the delete did not fail")
			}
		}},
		{"evict DeletePod NotFound", func(t *testing.T, r *runtimedRuntime, f *fakeRuntimeServer, pod *corev1.Pod) {
			queueDelete(f, status.Error(codes.NotFound, "no such pod"))
			if err := r.evictPod(ctx, pod, evictionNotice{signal: signalCompressor, message: "x"}); err == nil {
				t.Fatal("the eviction's delete did not fail")
			}
		}},
		{"StopContainer NotFound", func(t *testing.T, r *runtimedRuntime, f *fakeRuntimeServer, pod *corev1.Pod) {
			f.setStopErr(status.Error(codes.NotFound, "no such container"))
			if err := r.stopContainerReason(ctx, string(pod.UID), "c0", reasonFailedPostStartHook); err == nil {
				t.Fatal("the stop did not fail")
			}
		}},
		{"StopContainer verb missing", func(t *testing.T, r *runtimedRuntime, f *fakeRuntimeServer, pod *corev1.Pod) {
			f.setStopErr(status.Error(codes.Unimplemented, "unknown method StopContainer"))
			if err := r.stopContainerReason(ctx, string(pod.UID), "c0", reasonFailedPostStartHook); !errors.Is(err, errStopVerbMissing) {
				t.Fatalf("err = %v, want errStopVerbMissing", err)
			}
		}},
		{"StopContainer refused FailedPrecondition", func(t *testing.T, r *runtimedRuntime, f *fakeRuntimeServer, pod *corev1.Pod) {
			f.setStopResp(refusal(codes.FailedPrecondition))
			if err := r.stopContainerReason(ctx, string(pod.UID), "c0", reasonFailedPostStartHook); err == nil {
				t.Fatal("the stop did not fail")
			}
		}},
		{"StopContainer refused unsupported", func(t *testing.T, r *runtimedRuntime, f *fakeRuntimeServer, pod *corev1.Pod) {
			f.setStopResp(refusal(codes.Unimplemented))
			if err := r.stopContainerReason(ctx, string(pod.UID), "c0", reasonFailedPostStartHook); !errors.Is(err, errStopUnsupported) {
				t.Fatalf("err = %v, want errStopUnsupported", err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, f := newRuntimedFake(t)
			r.history = openHistory(t, t.TempDir(), "fp")
			pod := runtimedPod("default", "web")
			if err := r.CreatePod(ctx, pod); err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			tc.stop(t, r, f, pod)
			if got := intentsFor(r.history, pod.UID); len(got) != 0 {
				t.Fatalf("intents after a definitive refusal = %+v, want none", got)
			}
			observe(t, r.history, pod.UID, "c0", 0, 1, exitOf(137, "Error"), time.Now())
			if got := uninitiated(t, r.history, time.Now()); got != 1 {
				t.Fatalf("the exit after a refused stop counted %d uninitiated, want 1", got)
			}
		})
	}
}
