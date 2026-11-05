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
	"testing"
	"testing/synctest"
	"time"

	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestRefusedRestartDropsItsStopIntent: a liveness restart records its stop
// intent before the RestartContainer RPC. When runtimed refuses the restart, or
// answers that it definitively did not act, nothing was killed, so the intent is
// dropped and the container's next exit 137 counts as a SIGKILL k3sm did not
// send. A failure that leaves the outcome open keeps the intent, as the stop
// paths do.
//
// Fails-before: the worker recorded the intent and dropped it on no failure
// path, so the unrelated exit 137 consumed it and kernelKillsTotal stayed 0.
func TestRefusedRestartDropsItsStopIntent(t *testing.T) {
	cases := []struct {
		name        string
		refuse      func(f *fakeRuntimeServer)
		wantIntents int
		wantKills   int64
	}{
		{"embedded refusal (unsupported)", func(f *fakeRuntimeServer) {
			f.setRestartResp(&runtimev1.RestartContainerResponse{
				Error:         &rpcstatus.Status{Code: int32(codes.FailedPrecondition), Message: "no per-container restart"},
				FailureReason: runtimev1.FailureReason_FAILURE_REASON_UNSUPPORTED,
			})
		}, 0, 1},
		{"embedded refusal (transient)", func(f *fakeRuntimeServer) {
			f.setRestartResp(&runtimev1.RestartContainerResponse{
				Error:         &rpcstatus.Status{Code: int32(codes.FailedPrecondition), Message: "the pod is being stopped"},
				FailureReason: runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE,
			})
		}, 0, 1},
		{"transport NotFound", func(f *fakeRuntimeServer) {
			f.setRestartErr(status.Error(codes.NotFound, "no such pod"))
		}, 0, 1},
		{"transport Unavailable keeps the intent", func(f *fakeRuntimeServer) {
			f.setRestartErr(status.Error(codes.Unavailable, "connection reset"))
		}, 1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r, f, _ := newRestartFake(t)
				quiesceInBubble(t, r)
				r.history = openHistory(t, t.TempDir(), "fp")
				pod := runtimedPod("default", "web")
				if err := r.CreatePod(context.Background(), pod); err != nil {
					t.Fatalf("CreatePod: %v", err)
				}
				tc.refuse(f)
				if err := r.restartForLiveness(context.Background(), string(pod.UID), "c0"); err != nil {
					t.Fatalf("restartForLiveness: %v", err)
				}
				// The worker has made its attempt and parks on the next
				// backoff wait of the fake clock, which never advances.
				synctest.Wait()
				if n, _ := f.restartState(); n != 1 {
					t.Fatalf("RestartContainer calls = %d, want 1", n)
				}
				if got := intentsFor(r.history, pod.UID); len(got) != tc.wantIntents {
					t.Fatalf("intents after the failed restart = %+v, want %d", got, tc.wantIntents)
				}
				r.observeBudgetExits(pod, exitStatus(string(pod.UID), 137, "Error", 0, time.Unix(5000, 0)))
				if got := uninitiated(t, r.history, r.clk.Now()); got != tc.wantKills {
					t.Fatalf("kernelKillsTotal after the exit 137 = %d, want %d", got, tc.wantKills)
				}
			})
		})
	}
}
