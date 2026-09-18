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

package main

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/bootstrap"
)

// rateLimited is the refusal the control plane answers a token that has spent
// its join budget, with a wait short enough that a test pays it for real.
func rateLimited(wait time.Duration) error {
	return &bootstrap.JoinRateLimitedError{
		RetryAfter: wait,
		Status:     "429 Too Many Requests",
		Reason:     "join refused: too many join attempts for this token",
	}
}

// TestAgentWaitsOutARateLimitedJoin is the agent half of B346.
//
// The server bounds how fast ONE token may drive a join, so several Macs
// onboarded at once against one token take turns. An agent calls the join once
// per process start and `k3sm install` waits one bounded budget for the
// credential that join writes, so a rate-limited attempt treated as terminal
// fails the install on precisely the case the server-side limit exists to
// protect. This start waits instead — bounded, and only for that one condition.
//
// Fails before the fix: agentTokenJoin called bootstrap.Join once and returned
// whatever it got.
func TestAgentWaitsOutARateLimitedJoin(t *testing.T) {
	t.Parallel()

	t.Run("a rate-limited join is retried within the start", func(t *testing.T) {
		t.Parallel()
		calls := 0
		join := func(context.Context, bootstrap.JoinOptions) (*bootstrap.JoinResult, error) {
			calls++
			if calls <= 2 {
				return nil, rateLimited(time.Millisecond)
			}
			return &bootstrap.JoinResult{NodeName: "worker-1"}, nil
		}
		res, err := awaitJoin(context.Background(), join, bootstrap.JoinOptions{}, quietLogger())
		if err != nil {
			t.Fatalf("a join the server asked this node to retry must not fail the start: %v", err)
		}
		if res == nil || res.NodeName != "worker-1" {
			t.Fatalf("result = %+v, want the third attempt's join", res)
		}
		if calls != 3 {
			t.Errorf("join attempts = %d, want 3 (two refusals waited out, then the join)", calls)
		}
	})

	t.Run("every other outcome comes straight back", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			name string
			err  error
		}{
			{"a rejected token", errors.New("join rejected (401 Unauthorized): invalid join token")},
			{"a server that predates assigned addresses", bootstrap.ErrServerRequiresNodeIP},
			{"a refused node name", errors.New("join rejected (403 Forbidden): join refused: that node name is not available")},
		} {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				calls := 0
				join := func(context.Context, bootstrap.JoinOptions) (*bootstrap.JoinResult, error) {
					calls++
					return nil, tc.err
				}
				_, err := awaitJoin(context.Background(), join, bootstrap.JoinOptions{}, quietLogger())
				if !errors.Is(err, tc.err) {
					t.Errorf("err = %v, want the join's own error unchanged", err)
				}
				if calls != 1 {
					t.Errorf("join attempts = %d, want 1: waiting changes nothing about this failure, and a retry burns the install's budget", calls)
				}
			})
		}
	})

	t.Run("a join that succeeds first time is not delayed", func(t *testing.T) {
		t.Parallel()
		calls := 0
		join := func(context.Context, bootstrap.JoinOptions) (*bootstrap.JoinResult, error) {
			calls++
			return &bootstrap.JoinResult{NodeName: "worker-1"}, nil
		}
		if _, err := awaitJoin(context.Background(), join, bootstrap.JoinOptions{}, quietLogger()); err != nil {
			t.Fatalf("awaitJoin: %v", err)
		}
		if calls != 1 {
			t.Errorf("join attempts = %d, want 1", calls)
		}
	})

	t.Run("the grace is bounded and the failure names the cheap fix", func(t *testing.T) {
		// Not parallel: it shrinks the package-level grace.
		restore := joinRateLimitGrace
		joinRateLimitGrace = 30 * time.Millisecond
		t.Cleanup(func() { joinRateLimitGrace = restore })

		calls := 0
		join := func(context.Context, bootstrap.JoinOptions) (*bootstrap.JoinResult, error) {
			calls++
			return nil, rateLimited(10 * time.Millisecond)
		}
		_, err := awaitJoin(context.Background(), join, bootstrap.JoinOptions{}, quietLogger())
		if !errors.Is(err, bootstrap.ErrJoinRateLimited) {
			t.Fatalf("err = %v, want the rate-limit refusal once the grace is spent", err)
		}
		if calls < 2 {
			t.Errorf("join attempts = %d, want at least 2 before giving up", calls)
		}
		// The operator's way out is a token per Mac, and it has to be in the
		// message: this error is what `k3sm install` prints when a batch is too
		// large, and it is the only place the reader will look.
		if !strings.Contains(err.Error(), "k3sm token create") {
			t.Errorf("the give-up message must name the fix (a token per Mac): %v", err)
		}
	})

	t.Run("a shutdown during the wait stops the start", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		join := func(context.Context, bootstrap.JoinOptions) (*bootstrap.JoinResult, error) {
			cancel() // a SIGTERM arriving while this start waits out a refusal
			return nil, rateLimited(time.Hour)
		}
		if _, err := awaitJoin(ctx, join, bootstrap.JoinOptions{}, quietLogger()); !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled: a daemon asked to stop must not sit out a retry", err)
		}
	})

	t.Run("the wait fits inside the installer's join budget", func(t *testing.T) {
		t.Parallel()
		// pkg/install owns these two numbers and this package cannot import
		// them, so they are restated here as the literals they are: the
		// installer allows 60s for this node's credential to appear, and
		// accepts it only once the daemon has run steadily for 10s. A start can
		// spend netdProbeGrace before the join is even attempted. The sum has
		// to leave room for the join itself, or this retry turns a
		// rate-limited join into a failed install by a different route.
		const (
			installerJoinBudget = 60 * time.Second
			installerSteadyRun  = 10 * time.Second
		)
		if total := netdProbeGrace + joinRateLimitGrace + installerSteadyRun; total >= installerJoinBudget {
			t.Errorf("a start can spend netdProbeGrace + joinRateLimitGrace + the installer's steady-run wait = %s, which does not fit in its %s join budget",
				total, installerJoinBudget)
		}
	})

	t.Run("the token join goes through the retry", func(t *testing.T) {
		t.Parallel()
		// Source order, read off agentTokenJoin. The rows above prove awaitJoin
		// waits; this pins that the path an install actually takes runs through
		// it, rather than calling the join client directly as it used to.
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "agent.go", nil, 0)
		if err != nil {
			t.Fatalf("parse agent.go: %v", err)
		}
		var body *ast.BlockStmt
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "agentTokenJoin" {
				body = fn.Body
			}
		}
		if body == nil {
			t.Fatal("agent.go declares no agentTokenJoin")
		}
		called := map[string]bool{}
		ast.Inspect(body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				called[fun.Name] = true
			case *ast.SelectorExpr:
				called[fun.Sel.Name] = true
			}
			return true
		})
		if !called["awaitJoin"] {
			t.Error("agentTokenJoin does not call awaitJoin: a rate-limited join would fail the start again")
		}
		if called["Join"] {
			t.Error("agentTokenJoin calls the join client directly; the retry must be the only path")
		}
	})
}
