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
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/executor"
)

// seedCrashRecord writes a crash-loop record into the fake root filesystem at
// the path the installed server daemon keeps its own under.
func seedCrashRecord(t *testing.T, f *fakeSystem, cfg Config, rec executor.CrashRecord) string {
	t.Helper()
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	path := executor.CrashLoopPath(cfg.serverWorkDir())
	f.putFile(path, b)
	return path
}

// A daemon parked by its crash-loop breaker is resident, idle, and serving
// nothing — and launchd reports a healthy pid for it, which is all install used
// to check. So an install could report success over a control plane that is not
// running and will not start until an operator clears the marker.
//
// The second half of the rule is the one the timing argument forces: a trip
// takes five failures, so a fault that fails slowly has produced one or two
// entries by the time the restart budget is up. Waiting for the trip would pass
// the install and let the daemon give up minutes later, unattended.
func TestVerifyDaemonsFailsWhenTheServerIsParked(t *testing.T) {
	installStart := time.Date(2026, 9, 16, 9, 0, 0, 0, time.UTC)
	trippedAt := installStart.Add(5 * time.Minute)
	crash := func(at time.Time, origin, comp string) executor.Crash {
		return executor.Crash{At: at, Origin: origin, Component: comp, Detail: "kine not listening"}
	}
	cases := []struct {
		name       string
		rec        executor.CrashRecord
		wantErr    error
		wantPhrase []string
	}{
		{
			name: "one bring-up failure since this install began, nowhere near the trip",
			rec: executor.CrashRecord{Crashes: []executor.Crash{
				crash(installStart.Add(40*time.Second), executor.CrashOriginBringUp, "kine"),
			}},
			wantErr:    ErrServerNotComingUp,
			wantPhrase: []string{"failed to come up 1 times since this install began", "kine", "k3sm server --clear-crashloop"},
		},
		{
			name: "two bring-up failures since this install began",
			rec: executor.CrashRecord{Crashes: []executor.Crash{
				crash(installStart.Add(30*time.Second), executor.CrashOriginBringUp, "kine"),
				crash(installStart.Add(70*time.Second), executor.CrashOriginBringUp, "provision/certs"),
			}},
			wantErr:    ErrServerNotComingUp,
			wantPhrase: []string{"failed to come up 2 times since this install began", "provision/certs"},
		},
		{
			name: "a tripped record always fails, whatever its dates",
			rec: executor.CrashRecord{
				Crashes:   []executor.Crash{crash(installStart.Add(-time.Hour), executor.CrashOriginBringUp, "kine")},
				TrippedAt: &trippedAt,
			},
			wantErr:    ErrServerParked,
			wantPhrase: []string{"never came up (last: kine)", "parked", "k3sm server --clear-crashloop"},
		},
		{
			name: "a tripped crash record fails too, in crash words",
			rec: executor.CrashRecord{
				Crashes:   []executor.Crash{crash(installStart.Add(-time.Hour), executor.CrashOriginCrash, "kube-apiserver")},
				TrippedAt: &trippedAt,
			},
			wantErr:    ErrServerParked,
			wantPhrase: []string{"kept crashing (last: kube-apiserver)", "parked"},
		},
		{
			name: "a tripped leader-lost record fails in lease words, not crash words",
			rec: executor.CrashRecord{
				Crashes:   []executor.Crash{crash(installStart.Add(-time.Hour), executor.CrashOriginLeaderLost, "kube-scheduler")},
				TrippedAt: &trippedAt,
			},
			wantErr:    ErrServerParked,
			wantPhrase: []string{"kept losing its leader lease (last: kube-scheduler)", "parked"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			shrinkRestartBudgets(t)
			f := reinstallFake()
			cfg := installCfg().withDefaults()
			path := seedCrashRecord(t, f, cfg, tc.rec)

			err := verifyDaemons(context.Background(), f, cfg, artifactManifest(cfg), bringUpWindow{fences: bootstrapFences{ServerLabel: installStart}})
			if err == nil {
				t.Fatal("verifyDaemons passed over a server that did not bring the control plane up")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("error %q is not %v; a caller cannot tell this from an ordinary down daemon", err, tc.wantErr)
			}
			msg := err.Error()
			for _, want := range append(tc.wantPhrase, path) {
				if !strings.Contains(msg, want) {
					t.Errorf("error %q must carry %q — the operator needs what failed, when, and the remedy", msg, want)
				}
			}
		})
	}
}

// Everything short of a trip or a failure THIS install caused passes, and each
// row passes for its own reason: the marker is bookkeeping rather than a
// verdict, and a record older than the install is the fault the operator may
// well be reinstalling to fix.
func TestVerifyDaemonsPassesWithoutAFreshFailure(t *testing.T) {
	installStart := time.Date(2026, 9, 16, 9, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		seed func(t *testing.T, f *fakeSystem, cfg Config)
	}{
		{"no record at all — the ordinary install", func(*testing.T, *fakeSystem, Config) {}},
		{"an older bring-up failure under the threshold is the fault being reinstalled over", func(t *testing.T, f *fakeSystem, cfg Config) {
			seedCrashRecord(t, f, cfg, executor.CrashRecord{Crashes: []executor.Crash{
				{At: installStart.Add(-30 * time.Minute), Origin: executor.CrashOriginBringUp, Component: "kine"},
				{At: installStart.Add(-20 * time.Minute), Origin: executor.CrashOriginBringUp, Component: "kine"},
			}})
		}},
		{"a crash after this install began is launchd's business, not the installer's", func(t *testing.T, f *fakeSystem, cfg Config) {
			seedCrashRecord(t, f, cfg, executor.CrashRecord{Crashes: []executor.Crash{
				{At: installStart.Add(time.Minute), Origin: executor.CrashOriginCrash, Component: "kube-apiserver"},
			}})
		}},
		{"a pre-origin record reads as crashes, so it fails nothing", func(t *testing.T, f *fakeSystem, cfg Config) {
			seedCrashRecord(t, f, cfg, executor.CrashRecord{Crashes: []executor.Crash{
				{At: installStart.Add(time.Minute), Component: "kine"},
			}})
		}},
		{"a corrupt record is bookkeeping, not a verdict", func(t *testing.T, f *fakeSystem, cfg Config) {
			f.putFile(executor.CrashLoopPath(cfg.serverWorkDir()), []byte("{not json"))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			shrinkRestartBudgets(t)
			f := reinstallFake()
			cfg := installCfg().withDefaults()
			tc.seed(t, f, cfg)
			if err := verifyDaemons(context.Background(), f, cfg, artifactManifest(cfg), bringUpWindow{fences: bootstrapFences{ServerLabel: installStart}}); err != nil {
				t.Fatalf("verifyDaemons: %v", err)
			}
		})
	}
}

// The whole install fails, not just the check: a control plane that is not
// coming up must not be handed back as a successful install with a kubeconfig
// written for it. The record is dated in the future of the install's own start,
// which is what a daemon failing during THIS install produces.
func TestInstallFailsWhenTheServerIsNotComingUp(t *testing.T) {
	shrinkRestartBudgets(t)
	f := reinstallFake()
	cfg := installCfg()
	seedCrashRecord(t, f, cfg.withDefaults(), executor.CrashRecord{Crashes: []executor.Crash{{
		At: time.Now().Add(time.Second), Origin: executor.CrashOriginBringUp, Component: "provision/kine",
	}}})

	err := Install(context.Background(), f, cfg)
	if err == nil {
		t.Fatal("Install must fail when the control plane it restarted never came up")
	}
	if !errors.Is(err, ErrServerNotComingUp) {
		t.Errorf("install error %q does not carry ErrServerNotComingUp", err)
	}
	if f.kubeUser != "" {
		t.Errorf("kubeconfig written to %q for a control plane that never came up", f.kubeUser)
	}
}

// TestInstallFailsWhenTheServerIsParked is the same claim for the give-up state:
// a tripped record fails the install however old it is, because a parked daemon
// is parked right now.
func TestInstallFailsWhenTheServerIsParked(t *testing.T) {
	shrinkRestartBudgets(t)
	f := reinstallFake()
	cfg := installCfg()
	trippedAt := time.Now().Add(-time.Hour)
	seedCrashRecord(t, f, cfg.withDefaults(), executor.CrashRecord{
		Crashes: []executor.Crash{{
			At: trippedAt, Origin: executor.CrashOriginBringUp, Component: "provision/kine",
		}},
		TrippedAt: &trippedAt,
	})

	err := Install(context.Background(), f, cfg)
	if err == nil {
		t.Fatal("Install must fail when the server it restarted is parked by its crash-loop breaker")
	}
	if !errors.Is(err, ErrServerParked) {
		t.Errorf("install error %q does not carry ErrServerParked", err)
	}
	if f.kubeUser != "" {
		t.Errorf("kubeconfig written to %q for a control plane that is parked", f.kubeUser)
	}
}

// TestBringUpWindowStartsAtTheDaemonBootstrap is the install half. An
// in-place install booted out a server whose apiserver was still in bring-up; the
// stop cancelled it and the old daemon recorded "apiserver not healthy: context
// canceled", dated after the install began but before the new daemon existed.
// Counted from the install's start, that entry failed the install and rolled the
// tree back. The window now starts at each label's bootstrap fence, read from
// the System clock after the old process left the domain and immediately before
// the bootstrap: an entry strictly before it is not the new daemon's, an entry at
// or after it is. The same rule holds for the server and the agent, which share
// the one counting function.
func TestBringUpWindowStartsAtTheDaemonBootstrap(t *testing.T) {
	base := time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
	cancelled := func(at time.Time, comp string) executor.Crash {
		return executor.Crash{At: at, Origin: executor.CrashOriginBringUp, Component: comp, Detail: "apiserver not healthy: context canceled"}
	}
	genuine := func(at time.Time, comp string) executor.Crash {
		return executor.Crash{At: at, Origin: executor.CrashOriginBringUp, Component: comp, Detail: "kine not listening"}
	}
	roles := []struct {
		name      string
		cfg       func(t *testing.T) Config
		label     string
		component string
	}{
		{"server", func(*testing.T) Config { return installCfg() }, ServerLabel, "kube-apiserver"},
		{"agent", func(t *testing.T) Config { return agentCfg(t) }, AgentLabel, "agent"},
	}
	rows := []struct {
		name      string
		entries   func(fence time.Time, comp string) []executor.Crash
		wantCount int
		wantLast  string // the Detail of the last counted entry
	}{
		{
			name: "an entry just before the fence is the old daemon's",
			entries: func(fence time.Time, comp string) []executor.Crash {
				return []executor.Crash{cancelled(fence.Add(-time.Nanosecond), comp)}
			},
		},
		{
			name: "an entry at the fence is the new daemon's",
			entries: func(fence time.Time, comp string) []executor.Crash {
				return []executor.Crash{genuine(fence, comp)}
			},
			wantCount: 1, wantLast: "kine not listening",
		},
		{
			name: "an entry after the fence is the new daemon's",
			entries: func(fence time.Time, comp string) []executor.Crash {
				return []executor.Crash{genuine(fence.Add(2*time.Second), comp)}
			},
			wantCount: 1, wantLast: "kine not listening",
		},
		{
			// The paired row: the two entries differ only in their timestamps
			// relative to the fence, and both are after the install began.
			name: "the old daemon's cancelled bring-up is ignored and the new daemon's failure counted",
			entries: func(fence time.Time, comp string) []executor.Crash {
				return []executor.Crash{cancelled(fence.Add(-500*time.Millisecond), comp), genuine(fence.Add(3*time.Second), comp)}
			},
			wantCount: 1, wantLast: "kine not listening",
		},
	}
	for _, r := range roles {
		for _, row := range rows {
			t.Run(r.name+": "+row.name, func(t *testing.T) {
				shrinkRestartBudgets(t)
				cfg := r.cfg(t).withDefaults()
				f := &fakeSystem{}
				f.putLoaded(NetdLabel, r.label) // an in-place reinstall over a running pair
				// Every recorded call moves the clock on a second, so the fence a
				// label gets says WHERE in the call sequence it was read.
				f.now = func() time.Time { return base.Add(time.Duration(len(f.calls)) * time.Second) }

				fences, err := restartDaemons(context.Background(), f, cfg, artifactManifest(cfg))
				if err != nil {
					t.Fatalf("restartDaemons: %v", err)
				}
				fence, ok := fences[r.label]
				if !ok {
					t.Fatalf("restartDaemons returned no fence for %s: %v", r.label, fences)
				}
				bootstrap := firstCall(f, "Bootstrap:"+r.label)
				bootout := firstCall(f, "Bootout:"+r.label)
				if want := base.Add(time.Duration(bootstrap) * time.Second); !fence.Equal(want) {
					t.Fatalf("fence for %s = %s, want %s: it must be read immediately before the bootstrap (call %d; calls %v)", r.label, fence, want, bootstrap, f.calls)
				}
				if bootout < 0 || bootout >= bootstrap {
					t.Fatalf("bootout of %s at call %d is not before its bootstrap at %d", r.label, bootout, bootstrap)
				}
				// The install began before any of this, so every entry below is
				// after startedAt: a window keyed on it would count them all.
				window := bringUpWindow{startedAt: base, fences: fences}
				rec := executor.CrashRecord{Crashes: row.entries(fence, r.component)}

				if r.label == AgentLabel {
					seedAgentCrashRecord(t, f, cfg, rec)
					_, got := readAgentFailures(f, cfg, window.since(AgentLabel))
					if got.count != row.wantCount {
						t.Fatalf("counted %d agent failures from the fence, want %d (entries %+v)", got.count, row.wantCount, rec.Crashes)
					}
					if row.wantCount > 0 && got.last.Detail != row.wantLast {
						t.Errorf("last counted %q, want %q", got.last.Detail, row.wantLast)
					}
					return
				}
				seedCrashRecord(t, f, cfg, rec)
				err = verifyDaemons(context.Background(), f, cfg, artifactManifest(cfg), window)
				if row.wantCount == 0 {
					if err != nil {
						t.Fatalf("verifyDaemons counted an entry from before the server's bootstrap: %v", err)
					}
					return
				}
				if !errors.Is(err, ErrServerNotComingUp) {
					t.Fatalf("verifyDaemons = %v, want ErrServerNotComingUp", err)
				}
				if want := "failed to come up 1 times"; !strings.Contains(err.Error(), want) {
					t.Errorf("error %q must carry %q: only the new daemon's entry counts", err, want)
				}
			})
		}
	}
}
