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
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/executor"
)

// steppedClock is a clock the TEST advances: every tick of the verification
// moves it on by step, and nothing moves it otherwise.
//
// It exists because the alternative flakes. The observation window and the fake
// daemon's behaviour are driven by two different things — elapsed time and read
// counts — and under -race the window won the race: the 1ms window elapsed
// before the fake had delivered the record change and the pid drop, and the row
// that must FAIL passed. Stepping the clock per tick ties the two together, so
// the ordering asserted here is the ordering the verification sees, on any
// machine, at any load.
type steppedClock struct {
	at    time.Time
	step  time.Duration
	ticks int
}

func (c *steppedClock) clock() agentJoinClock {
	return agentJoinClock{
		now: func() time.Time { return c.at },
		tick: func(ctx context.Context, _ time.Duration) error {
			c.ticks++
			c.at = c.at.Add(c.step)
			return ctx.Err()
		},
	}
}

// crashRecordJSON encodes a record the way the daemon writes it, for the seams
// that plant a record which CHANGES while the verification is polling.
func crashRecordJSON(t *testing.T, rec executor.CrashRecord) []byte {
	t.Helper()
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestVerifyAgentJoinedAcceptsARecoveredStart is the regression for the second
// half of the 2026-09-17 install: io.k3sm.agent was bootstrapped 24ms after
// io.k3sm.netd, failed its first start at 19:03:13 on a helper socket that was
// not there, and launchd's KeepAlive retry joined the cluster ten seconds later.
//
// The verification returned on the FIRST tick that saw that entry, so the
// install failed over a daemon that was in the middle of recovering — the
// daemon backs off rather than exiting precisely so launchd can retry it, and
// the check was reading the first half of that sentence as the whole of it.
//
// A fresh failure is now remembered rather than returned: the join is proved by
// the credential AND by the daemon being observed running steadily across the
// observation window with no further entry appearing. The failure still decides
// the message when the recovery never comes.
func TestVerifyAgentJoinedAcceptsARecoveredStart(t *testing.T) {
	installStart := time.Date(2026, 9, 17, 19, 3, 11, 0, time.UTC)
	dir := Config{}.withDefaults().agentWorkDir()
	const socketFailure = "k3sm-netd helper unreachable: dial unix /var/lib/k3sm/run/netd.sock: no such file"

	cases := []struct {
		name string
		// seed describes the Mac as the verification begins and returns the
		// token the staged copy holds.
		seed       func(t *testing.T, f *fakeSystem, cfg Config) string
		wantErr    bool
		wantPhrase []string
		// wantLog are phrases the run must have LOGGED — the only place a
		// passing verification can say what it waited out.
		wantLog []string
		// wantRecordReads, when non-zero, pins how often the record was read:
		// the tripped verdict is reached on the first tick and must not spend
		// the budget.
		wantRecordReads int
	}{
		{
			// (a) The incident, told to its end: the first start failed, the
			// retry joined, and the daemon has been up ever since.
			name: "a start failure this install caused, then a join and a steady daemon, is a join",
			seed: func(t *testing.T, f *fakeSystem, cfg Config) string {
				cred := mintNodeCredential(t, dir)
				cred.seed(f)
				seedAgentCrashRecord(t, f, cfg, executor.CrashRecord{Crashes: []executor.Crash{
					agentStartFailure(installStart.Add(2*time.Second), socketFailure),
				}})
				f.putLoaded(AgentLabel)
				return cred.token
			},
			wantLog: []string{socketFailure, "recovered"},
		},
		{
			// (b) The same failure with nothing behind it: no live daemon, so
			// no recovery, and the budget runs out on the failure itself.
			//
			// HONESTY: this row passes on the pre-B332 code too — that code
			// failed the install on the first sight of the entry, which is also
			// a failure naming it. It is here to pin the MESSAGE (the count,
			// the detail, the log, the remedy) across the rewrite, not to prove
			// the change. Rows (a), (c) and (d) are the red ones.
			name: "a start failure with no recovery inside the budget fails, quoting it",
			seed: func(t *testing.T, f *fakeSystem, cfg Config) string {
				cred := mintNodeCredential(t, dir)
				cred.seed(f)
				seedAgentCrashRecord(t, f, cfg, executor.CrashRecord{Crashes: []executor.Crash{
					agentStartFailure(installStart.Add(2*time.Second), socketFailure),
				}})
				return cred.token
			},
			wantErr: true,
			wantPhrase: []string{
				socketFailure,
				"failed to start 1 times since this install began",
				AgentLogPath(),
				"k3sm token create",
			},
		},
		{
			// (c) The other direction, and the reason the observation window
			// is not just "the credential is there": the credential proves a
			// join that happened, and then the daemon fails again and goes
			// away. A single tick could not tell this from (a).
			name: "a join followed by a fresh failure with the daemon gone is not a join",
			seed: func(t *testing.T, f *fakeSystem, cfg Config) string {
				cred := mintNodeCredential(t, dir)
				cred.seed(f)
				// Absent on the first read, then holding the entry the daemon
				// wrote while this verification was watching.
				f.putFileChangingAfterReads(executor.CrashLoopPath(cfg.agentWorkDir()), nil,
					crashRecordJSON(t, executor.CrashRecord{Crashes: []executor.Crash{
						agentStartFailure(installStart.Add(4*time.Second), "join: the server rejected this token"),
					}}), 1)
				// Alive for the first read, then out of the launchd domain.
				f.putLoaded(AgentLabel)
				f.putDrain(AgentLabel, 2)
				return cred.token
			},
			wantErr: true,
			wantPhrase: []string{
				"join: the server rejected this token",
				"failed to start 1 times since this install began",
			},
		},
		{
			// (d) A tripped breaker is a loop, not a start about to recover.
			// Waiting out the budget on it only delays the same answer, so it
			// is the one verdict reached on the first tick.
			name: "a tripped record fails at once rather than waiting out the budget",
			seed: func(t *testing.T, f *fakeSystem, cfg Config) string {
				cred := mintNodeCredential(t, dir)
				cred.seed(f)
				trippedAt := installStart.Add(3 * time.Minute)
				f.putLoaded(AgentLabel)
				seedAgentCrashRecord(t, f, cfg, executor.CrashRecord{
					Crashes: []executor.Crash{
						agentStartFailure(installStart.Add(time.Second), "mesh: bring up utun: operation not permitted"),
					},
					TrippedAt: &trippedAt,
				})
				return cred.token
			},
			wantErr: true,
			wantPhrase: []string{
				"crash-loop breaker tripped",
				"mesh: bring up utun: operation not permitted",
				AgentLogPath(),
			},
			wantRecordReads: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Deliberately NOT shrinkRestartBudgets: these rows run on the
			// PRODUCTION budget and the production observation window, and the
			// clock below is what makes that cost no wall-clock time. A second
			// per tick means the 10s window is ten ticks and the 60s budget is
			// sixty — comfortably more than the handful of reads the fake needs
			// to deliver a record change or drop a pid, which is the ordering
			// every row here is about.
			clk := &steppedClock{at: installStart.Add(5 * time.Second), step: time.Second}
			f := &fakeSystem{}
			cfg := agentCfg(t).withDefaults()
			var logged bytes.Buffer
			cfg.Logger = slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug}))
			f.putFile(cfg.agentTokenPath(), []byte(tc.seed(t, f, cfg)+"\n"))

			err := verifyAgentJoinedOn(context.Background(), f, cfg, installStart, clk.clock())
			switch {
			case tc.wantErr && err == nil:
				t.Fatalf("verifyAgentJoined reported a join this install has no witness for (log: %s)", logged.String())
			case !tc.wantErr && err != nil:
				t.Fatalf("verifyAgentJoined: %v", err)
			}
			for _, want := range tc.wantPhrase {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q must carry %q — the operator needs what failed and what to do next", err, want)
				}
			}
			for _, want := range tc.wantLog {
				if !strings.Contains(logged.String(), want) {
					t.Errorf("the run must have logged %q — a verification that waited out a recorded failure has to say so; log: %s", want, logged.String())
				}
			}
			if tc.wantRecordReads > 0 {
				if n := countCalls(f, "ReadFile:"+executor.CrashLoopPath(cfg.agentWorkDir())); n != tc.wantRecordReads {
					t.Errorf("crash-record reads = %d, want %d (the verdict is reached on the first tick)", n, tc.wantRecordReads)
				}
			}
		})
	}

	// The window is latency an ordinary, healthy agent install now pays: the
	// credential is not accepted until the daemon has been observed running for
	// it. That cost is bounded here rather than left to whoever next edits the
	// constant — ten seconds is the launchd respawn interval it is chosen
	// against, and a quarter of the join budget is the most of an operator's
	// wait a liveness observation may consume before it is the wait.
	t.Run("the observation window is a bounded share of the join budget", func(t *testing.T) {
		if agentRecoveryObservation > 10*time.Second {
			t.Errorf("agentRecoveryObservation = %s, want at most 10s: it is added to every healthy agent install", agentRecoveryObservation)
		}
		if quarter := agentJoinBudget.running / 4; agentRecoveryObservation >= quarter {
			t.Errorf("agentRecoveryObservation = %s, want under %s (a quarter of the %s join budget): a window that big leaves no room for the join itself",
				agentRecoveryObservation, quarter, agentJoinBudget.running)
		}
	})
}
