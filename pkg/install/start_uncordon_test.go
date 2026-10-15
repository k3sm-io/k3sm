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

package install

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// stoppedNodeOfRole is a node of the given role that `k3sm stop` has stopped,
// with a MarkNode seam the caller replaces. The call log is cleared.
func stoppedNodeOfRole(t *testing.T, role Role) (*fakeSystem, Config, *bytes.Buffer) {
	t.Helper()
	if role == RoleServer {
		f, cfg, logs := stoppableNode(t)
		if err := Stop(context.Background(), f, cfg, ActorUser, "test"); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		f.calls = nil
		return f, cfg, logs
	}
	shrinkRestartBudgets(t)
	f := &fakeSystem{}
	seedJoinedAgent(t, f)
	var logs bytes.Buffer
	cfg := agentCfg(t)
	cfg.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	if err := Install(context.Background(), f, cfg); err != nil {
		t.Fatalf("Install: %v", err)
	}
	cfg.MarkNode = func(context.Context, bool, string, string) error { return nil }
	cfg.RemoveMesh = func(context.Context) error { return nil }
	if err := Stop(context.Background(), f, cfg, ActorUser, "test"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	f.calls = nil
	return f, cfg, &logs
}

// TestStartUncordonsOnceTheNodeIsReachable is the gate for the start-time
// uncordon: on either role it retries until the apiserver answers, stops at
// once on an identity the cluster rejects, fails with ErrNodeStillCordoned
// (one Error line) when the budget runs out, and still runs on a re-run
// against a node that is already running, which is how an exhausted budget is
// repaired.
func TestStartUncordonsOnceTheNodeIsReachable(t *testing.T) {
	nodes := schema.GroupResource{Resource: "nodes"}
	deadline := fmt.Errorf("patch node k3sm-mac: %w", context.DeadlineExceeded)
	forbidden := apierrors.NewForbidden(nodes, "k3sm-mac", errors.New("node may not patch another node"))
	conflict := apierrors.NewConflict(nodes, "k3sm-mac", errors.New("the object has been modified"))

	cases := []struct {
		name string
		// rerun starts the node once with a MarkNode that succeeds, so the
		// start under test finds no stop marker and every daemon running.
		rerun bool
		// pending seeds the uncordon-pending marker before the start under
		// test; wantPending is whether it is there after.
		pending, wantPending bool
		// errs is what MarkNode returns per call, in order; past the end it
		// returns nil, unless never.
		errs  []error
		never error
		// wantCalls is the exact number of uncordon calls; 0 means "more than one".
		wantCalls int
		wantErr   func(error) bool
		wantLog   []string
	}{
		{
			name:      "deadline errors then success: retried until it lands",
			errs:      []error{deadline, deadline, deadline},
			wantCalls: 4,
		},
		{
			name:      "forbidden: not retried, returned wrapped",
			errs:      []error{forbidden},
			wantCalls: 1,
			wantErr: func(err error) bool {
				return apierrors.IsForbidden(err) && !errors.Is(err, ErrNodeStillCordoned)
			},
			wantLog: []string{"level=ERROR", "result=still-cordoned", "class=forbidden"},
		},
		{
			name:  "never succeeds: ErrNodeStillCordoned after the budget, the repair recorded",
			never: deadline,
			wantErr: func(err error) bool {
				return errors.Is(err, ErrNodeStillCordoned) && errors.Is(err, context.DeadlineExceeded)
			},
			wantLog:     []string{"level=ERROR", "result=still-cordoned", "class=timeout"},
			wantPending: true,
		},
		{
			name:      "re-run on a running node still uncordons once",
			rerun:     true,
			wantCalls: 1,
		},
		{
			name:      "re-run on a running node, no pending repair, apiserver down: one attempt, nil",
			rerun:     true,
			never:     deadline,
			wantCalls: 1,
			wantLog:   []string{"level=WARN", "could not uncordon"},
		},
		{
			name:    "re-run on a running node with a pending repair, apiserver down: the full budget, then the error",
			rerun:   true,
			pending: true,
			never:   deadline,
			wantErr: func(err error) bool { return errors.Is(err, ErrNodeStillCordoned) },
			wantLog: []string{"level=ERROR", "result=still-cordoned"},
			// Still pending: the next start must try again.
			wantPending: true,
		},
		{
			name:      "re-run on a running node with a pending repair: uncordoned, the marker removed",
			rerun:     true,
			pending:   true,
			errs:      []error{deadline},
			wantCalls: 2,
		},
		{
			name:      "conflict then success: retried",
			errs:      []error{conflict},
			wantCalls: 2,
		},
	}
	for _, role := range []Role{RoleServer, RoleAgent} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("%s/%s", role, tc.name), func(t *testing.T) {
				f, cfg, logs := stoppedNodeOfRole(t, role)
				uncordonBudget = restartBudget{running: 200 * time.Millisecond, poll: time.Millisecond}
				ctx := context.Background()
				if tc.rerun {
					if err := Start(ctx, f, cfg, ActorUser, "first"); err != nil {
						t.Fatalf("first Start: %v", err)
					}
					f.calls = nil
				}
				if tc.pending {
					if err := writeUncordonPending(f, cfg.withDefaults(), ActorUser, time.Now()); err != nil {
						t.Fatal(err)
					}
				}
				var calls int
				cfg.MarkNode = func(ctx context.Context, stopped bool, actor, _ string) error {
					if stopped {
						t.Errorf("Start cordoned the node")
					}
					calls++
					if tc.never != nil {
						return tc.never
					}
					if calls <= len(tc.errs) {
						return tc.errs[calls-1]
					}
					return nil
				}
				logs.Reset()
				err := Start(ctx, f, cfg, ActorUser, "test")
				switch {
				case tc.wantErr == nil && err != nil:
					t.Fatalf("Start = %v, want nil", err)
				case tc.wantErr != nil && (err == nil || !tc.wantErr(err)):
					t.Fatalf("Start = %v, not the error this case wants", err)
				}
				if tc.wantCalls > 0 && calls != tc.wantCalls {
					t.Errorf("MarkNode(uncordon) called %d times, want %d", calls, tc.wantCalls)
				}
				if tc.wantCalls == 0 && calls < 2 {
					t.Errorf("MarkNode(uncordon) called %d times; a budget of retries wants more than one", calls)
				}
				for _, want := range tc.wantLog {
					if !strings.Contains(logs.String(), want) {
						t.Errorf("start log lacks %q:\n%s", want, logs.String())
					}
				}
				if got := uncordonPendingPresent(f, cfg.withDefaults()); got != tc.wantPending {
					t.Errorf("uncordon-pending marker present = %v, want %v", got, tc.wantPending)
				}
				if tc.wantErr != nil && strings.Count(logs.String(), "level=ERROR") != 1 {
					t.Errorf("want exactly one Error line:\n%s", logs.String())
				}
				if tc.wantErr != nil && strings.Contains(logs.String(), "level=WARN msg=\"could not uncordon") {
					t.Errorf("the uncordon failure was warned and continued:\n%s", logs.String())
				}
			})
		}
	}
}

// TestUncordonPendingMarkerLifecycle pins who else reads and clears the
// uncordon-pending marker: install --start uses the same retrying uncordon
// and records the repair, and a stop and an uninstall remove the marker.
func TestUncordonPendingMarkerLifecycle(t *testing.T) {
	ctx := context.Background()
	down := func(context.Context, bool, string, string) error { return context.DeadlineExceeded }

	t.Run("install --start runs out of budget: ErrNodeStillCordoned and the marker", func(t *testing.T) {
		f, cfg, _ := stoppedNodeOfRole(t, RoleServer)
		uncordonBudget = restartBudget{running: 50 * time.Millisecond, poll: time.Millisecond}
		cfg.MarkNode = down
		cfg.Start = true
		if err := Install(ctx, f, cfg); !errors.Is(err, ErrNodeStillCordoned) {
			t.Fatalf("Install --start = %v, want ErrNodeStillCordoned", err)
		}
		if !uncordonPendingPresent(f, cfg.withDefaults()) {
			t.Error("install --start did not record the pending uncordon")
		}
	})
	t.Run("a stop removes the marker", func(t *testing.T) {
		f, cfg, _ := stoppableNode(t)
		if err := writeUncordonPending(f, cfg.withDefaults(), ActorUser, time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := Stop(ctx, f, cfg, ActorUser, "test"); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		if uncordonPendingPresent(f, cfg.withDefaults()) {
			t.Error("the uncordon-pending marker survived a stop")
		}
	})
	t.Run("an uninstall removes the marker", func(t *testing.T) {
		f, cfg, _ := stoppableNode(t)
		if err := writeUncordonPending(f, cfg.withDefaults(), ActorUser, time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := Uninstall(ctx, f, Config{Logger: cfg.Logger}); err != nil {
			t.Fatalf("Uninstall: %v", err)
		}
		if uncordonPendingPresent(f, cfg.withDefaults()) {
			t.Error("the uncordon-pending marker survived an uninstall")
		}
	})
}

// TestMarkNodeErrorClass pins which MarkNode failures the start-time uncordon
// retries.
func TestMarkNodeErrorClass(t *testing.T) {
	nodes := schema.GroupResource{Resource: "nodes"}
	for _, tc := range []struct {
		name      string
		err       error
		wantClass string
		wantRetry bool
	}{
		{"identity", fmt.Errorf("%w: this node holds no usable credential", ErrNodeIdentity), "identity", false},
		{"forbidden", apierrors.NewForbidden(nodes, "n", errors.New("no")), "forbidden", false},
		{"unauthorized", apierrors.NewUnauthorized("bad cert"), "unauthorized", false},
		{"not found", apierrors.NewNotFound(nodes, "n"), "not-found", true},
		{"conflict", apierrors.NewConflict(nodes, "n", errors.New("modified")), "conflict", true},
		{"unavailable", apierrors.NewServiceUnavailable("starting"), "unavailable", true},
		{"too many requests", apierrors.NewTooManyRequests("slow down", 1), "too-many-requests", true},
		{"deadline", fmt.Errorf("get node: %w", context.DeadlineExceeded), "timeout", true},
		{"bad request", apierrors.NewBadRequest("malformed patch"), "rejected", false},
		{"invalid (422)", apierrors.NewInvalid(schema.GroupKind{Kind: "Node"}, "n", nil), "rejected", false},
		{"method not supported (405)", apierrors.NewMethodNotSupported(nodes, "patch"), "rejected", false},
		{"internal error (500)", apierrors.NewInternalError(errors.New("etcd leader changed")), "other", true},
		{"service unavailable (503)", apierrors.NewServiceUnavailable("starting"), "unavailable", true},
		{"other", errors.New("EOF"), "other", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			class, retry := markNodeErrorClass(tc.err)
			if class != tc.wantClass || retry != tc.wantRetry {
				t.Errorf("markNodeErrorClass = (%q, %v), want (%q, %v)", class, retry, tc.wantClass, tc.wantRetry)
			}
		})
	}
}
