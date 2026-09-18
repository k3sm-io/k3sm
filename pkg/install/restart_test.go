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
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// transientBootstrapErr is what the darwin System returns when launchd rejects a
// bootstrap because the label it is replacing has not finished leaving the system
// domain (errno 37/5). The orchestration keys on the SENTINEL, never on the text,
// so the text here is only for the operator-facing message.
func transientBootstrapErr() error {
	return fmt.Errorf("launchctl bootstrap: %w: Bootstrap failed: 37: Operation already in progress", ErrLaunchctlTransient)
}

// reinstallFake is the posture every test here starts from: BOTH daemons already
// loaded (this is a reinstall over a running cluster — the only situation in which
// the bootout→bootstrap race can happen at all) and every path present.
func reinstallFake() *fakeSystem {
	f := &fakeSystem{}
	f.putLoaded(NetdLabel, ServerLabel)
	return f
}

func installCfg() Config {
	return Config{BinarySource: "/tmp/k3sm", TargetUser: "alice"}
}

func countCalls(f *fakeSystem, want string) int {
	n := 0
	for _, c := range f.calls {
		if c == want {
			n++
		}
	}
	return n
}

// TestInstallRetriesTransientBootstrapFailure is the regression for the live
// failure this whole sequence exists for: `launchctl bootout` returns BEFORE
// launchd removes the label, so the immediate `launchctl bootstrap` install used to
// issue raced the teardown and was rejected (errno 37/5). Install then returned
// mid-loop with netd booted out and DOWN and the server never restarted.
//
// The install must instead wait for the label to leave the domain and re-attempt
// the bootstrap across exactly that transient class — while still failing fast, and
// legibly, on a rejection that will never change.
func TestInstallRetriesTransientBootstrapFailure(t *testing.T) {
	t.Run("a bootstrap denied while the label drains is retried and the install completes", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := reinstallFake()
		// launchd keeps netd in the domain for two more reads after the bootout
		// returns, and rejects the first bootstrap that lands in that window.
		f.putDrain(NetdLabel, 2)
		f.putBootstrapErrs(NetdLabel, transientBootstrapErr())

		if err := Install(context.Background(), f, installCfg()); err != nil {
			t.Fatalf("Install must survive the bootout/bootstrap race: %v", err)
		}
		if n := countCalls(f, "Bootstrap:"+NetdLabel); n != 2 {
			t.Errorf("netd bootstrap attempts = %d, want 2 (one rejected by the draining teardown, one accepted)", n)
		}
		// The install waited for the label to LEAVE the domain before bootstrapping:
		// the drain takes three ServicePID reads to report "not loaded".
		if n := countCalls(f, "ServicePID:"+NetdLabel); n < 3 {
			t.Errorf("netd ServicePID reads = %d, want at least 3 (the await-unloaded poll must outlast the drain)", n)
		}
		for _, l := range []string{NetdLabel, ServerLabel} {
			if _, ok := f.loaded[l]; !ok {
				t.Errorf("%s is not loaded after a successful install", l)
			}
		}
	})

	t.Run("a bootstrap that never stops reporting the transient state fails, state-honestly", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := reinstallFake()
		f.putBootstrapAlways(NetdLabel, transientBootstrapErr())

		err := Install(context.Background(), f, installCfg())
		if err == nil {
			t.Fatal("Install must fail when launchd never accepts the bootstrap")
		}
		msg := err.Error()
		for _, want := range []string{"bootstrap " + NetdLabel, "transient", NetdLabel + " DOWN"} {
			if !strings.Contains(msg, want) {
				t.Errorf("error %q does not mention %q", msg, want)
			}
		}
		if countCalls(f, "Bootstrap:"+NetdLabel) < 2 {
			t.Error("a transient rejection must be retried before the install gives up")
		}
		// The kubeconfig is NOT written: a failed install must not leave the human
		// with credentials for a control plane that is not running.
		if f.kubeUser != "" {
			t.Errorf("kubeconfig written to %q despite the failed restart", f.kubeUser)
		}
	})

	t.Run("a permanent rejection is not retried", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := reinstallFake()
		f.putBootstrapAlways(NetdLabel, errors.New("Load failed: 5: Input/output erro")) // deliberately NOT the sentinel

		if err := Install(context.Background(), f, installCfg()); err == nil {
			t.Fatal("Install must fail on a bootstrap launchd will never accept")
		}
		// Two calls total: the ONE attempt (no retry — only ErrLaunchctlTransient is
		// retryable) plus the single best-effort re-bootstrap the rollback makes on
		// the way out. A retry loop would show many more.
		if n := countCalls(f, "Bootstrap:"+NetdLabel); n != 2 {
			t.Errorf("netd bootstrap calls = %d, want exactly 2 (one attempt + one rollback attempt); a non-transient rejection must not be retried", n)
		}
	})
}

// TestInstallReportsWhichDaemonIsDown proves a failed restart names the state of
// EVERY daemon, not just the one that failed, and that install re-bootstraps what
// it had already booted out. The old path returned mid-loop with no rollback and no
// statement of what was left running, which is how a live install ended with netd
// down and nothing saying so.
func TestInstallReportsWhichDaemonIsDown(t *testing.T) {
	t.Run("the server fails to bootstrap: netd is named up, the server named down", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := reinstallFake()
		f.putBootstrapAlways(ServerLabel, errors.New("Load failed: 122: Path had bad ownership/permissions"))

		err := Install(context.Background(), f, installCfg())
		if err == nil {
			t.Fatal("Install must fail when the server never bootstraps")
		}
		msg := err.Error()
		if !strings.Contains(msg, NetdLabel+" up (pid") {
			t.Errorf("error %q must state that netd is UP — an operator needs to know what survived", msg)
		}
		if !strings.Contains(msg, ServerLabel+" DOWN") {
			t.Errorf("error %q must state that the server is DOWN", msg)
		}
		if !strings.Contains(msg, "STILL DOWN") {
			t.Errorf("error %q must say the best-effort re-bootstrap did not recover the server", msg)
		}
	})

	t.Run("a daemon booted out before the failure is put back", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := reinstallFake()
		// The server's bootout succeeds and its first bootstrap is rejected, so
		// install fails — but the server it took down is one a bootstrap CAN load,
		// and the rollback must actually put it back rather than merely report it
		// missing. (The single queued error is consumed by the failing attempt; the
		// rollback's attempt is the one that succeeds.)
		f.putBootstrapErrs(ServerLabel, errors.New("Load failed: 122: Path had bad ownership/permissions"))

		err := Install(context.Background(), f, installCfg())
		if err == nil {
			t.Fatal("Install must fail when a daemon's bootstrap is rejected")
		}
		if !strings.Contains(err.Error(), "re-bootstrapped after the failure: "+ServerLabel) {
			t.Errorf("error %q must say the rollback put the server back", err)
		}
		// Both daemons are running again: the failed install left the machine in the
		// state it found it, not with a helper missing.
		for _, l := range []string{NetdLabel, ServerLabel} {
			if _, ok := f.loaded[l]; !ok {
				t.Errorf("%s is not loaded after the rollback", l)
			}
		}
		if f.kubeUser != "" {
			t.Errorf("kubeconfig written to %q despite the failed install", f.kubeUser)
		}
	})

	t.Run("verifyDaemons names both states", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		f.putLoaded(NetdLabel) // the server never came up
		cfg := installCfg().withDefaults()
		err := verifyDaemons(context.Background(), f, cfg, artifactManifest(cfg), time.Now())
		if err == nil {
			t.Fatal("verifyDaemons must fail when a daemon is down")
		}
		msg := err.Error()
		if !strings.Contains(msg, NetdLabel+" up (pid") || !strings.Contains(msg, ServerLabel+" DOWN") {
			t.Errorf("verifyDaemons error %q must name the state of BOTH daemons", msg)
		}
	})
}

// TestInstallVerifiesDaemonsAfterRestart proves install asserts what it claims:
// both daemons live AND the netd socket the two rendezvous on present. Without this
// an install returns success having left the helper dead — which is exactly how the
// failure went unnoticed until cluster DNS stopped answering.
func TestInstallVerifiesDaemonsAfterRestart(t *testing.T) {
	t.Run("a healthy pair verifies", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := reinstallFake()
		if err := Install(context.Background(), f, installCfg()); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if countCalls(f, "PathExists:"+DefaultNetdSocket) == 0 {
			t.Errorf("install never verified the netd socket %s", DefaultNetdSocket)
		}
	})

	t.Run("netd loaded but never binding its socket fails the install", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := reinstallFake()
		f.putMissingPath(DefaultNetdSocket)

		err := Install(context.Background(), f, installCfg())
		if err == nil {
			t.Fatal("install must fail when netd never binds the helper socket the control plane dials")
		}
		if !strings.Contains(err.Error(), DefaultNetdSocket) {
			t.Errorf("error %q must name the absent socket", err)
		}
		if f.kubeUser != "" {
			t.Errorf("kubeconfig written to %q despite an unverified install", f.kubeUser)
		}
	})
}

// TestRestartBudgetByLabel pins which daemons get the long restart budget.
//
// The budget is not a tuning knob: it is how long the install waits for a label
// to leave launchd's system domain before it refuses to bootstrap into a
// draining job. A daemon whose plist raises ExitTimeOut can legitimately take
// longer than netd's 30s to go, so giving it the short budget would fail the
// install on precisely the slow-but-healthy shutdown the wait exists to
// tolerate. Both NODE daemons raise it, so both are in the long class; netd,
// which has no orderly teardown at all, is not.
//
// The last assertion is the one that keeps this honest as the daemons' teardown
// grows: the budget must stay ABOVE the SIGTERM-to-SIGKILL grace it is waiting
// out, or the wait times out on a daemon that was going to stop cleanly.
func TestRestartBudgetByLabel(t *testing.T) {
	for _, tc := range []struct {
		label string
		want  restartBudget
		why   string
	}{
		{ServerLabel, serverRestartBudget, "the control plane tears its components down serially inside the plist's ExitTimeOut"},
		{AgentLabel, serverRestartBudget, "the agent stops its vm guests, closes the mesh device and drains the Service proxy inside its own ExitTimeOut"},
		{NetdLabel, netdRestartBudget, "netd is a single process with nothing to reap"},
		{DatavolLabel, netdRestartBudget, "a daemon added later inherits the conservative default"},
	} {
		if got := restartBudgetFor(tc.label); got != tc.want {
			t.Errorf("restartBudgetFor(%s) = %v, want %v: %s", tc.label, got, tc.want, tc.why)
		}
	}
	if serverRestartBudget.unload <= netdRestartBudget.unload {
		t.Fatalf("the long budget (%v) is not longer than the short one (%v); the distinction this test pins would be vacuous",
			serverRestartBudget.unload, netdRestartBudget.unload)
	}
	for _, grace := range []int{serverExitTimeOut, agentExitTimeOut} {
		if serverRestartBudget.unload <= time.Duration(grace)*time.Second {
			t.Errorf("the node unload budget (%v) is at or below a node plist's ExitTimeOut (%ds); the install would give up on a daemon still stopping cleanly",
				serverRestartBudget.unload, grace)
		}
	}
}

// firstCall returns the index of want in the recorded call log, or -1.
func firstCall(f *fakeSystem, want string) int {
	for i, c := range f.calls {
		if c == want {
			return i
		}
	}
	return -1
}

// lastCall returns the index of the LAST occurrence of want, or -1.
func lastCall(f *fakeSystem, want string) int {
	for i := len(f.calls) - 1; i >= 0; i-- {
		if f.calls[i] == want {
			return i
		}
	}
	return -1
}

// TestAgentRestartWaitsForTheNetdSocket is the regression for the 2026-09-17
// install that bootstrapped io.k3sm.netd at 19:03:11.969 and io.k3sm.agent 24ms
// later: the agent dialed the helper socket, got "no such file", recorded a
// bring-up failure and backed off until launchd's KeepAlive retried it ten
// seconds on.
//
// Nothing in the restart sequence waited for that socket. restartDaemon's
// success condition is a launchd PID, which says the process was spawned and
// nothing about whether netd is serving; the only socket check was
// verifyDaemons', on the far side of BOTH restarts. The server role never hit it
// because its own bring-up takes some 37 seconds — luck, not ordering — which is
// why both roles are asserted here.
//
// The wait asks netd to ANSWER rather than stat'ing the socket or merely
// connecting to it. A bound unix socket is on the filesystem before its server
// accepts, and connect(2) completes into the listen backlog with no involvement
// from the process that bound it — so both of the cheaper checks end the wait in
// exactly the windows the node daemon is refused in.
func TestAgentRestartWaitsForTheNetdSocket(t *testing.T) {
	roles := []struct {
		name  string
		cfg   func(t *testing.T) Config
		label string
	}{
		{"the control plane", func(*testing.T) Config { return installCfg() }, ServerLabel},
		{"a worker", func(t *testing.T) Config { return agentCfg(t) }, AgentLabel},
	}

	for _, r := range roles {
		t.Run(r.name+" does not start its node daemon until netd answers", func(t *testing.T) {
			shrinkRestartBudgets(t)
			cfg := r.cfg(t).withDefaults()
			f := &fakeSystem{}
			f.putLoaded(NetdLabel, r.label) // a reinstall over a running pair
			// netd is spawned and only then binds and serves: the first three
			// probes after its bootstrap are refused.
			f.putNetdRefusals(cfg.NetdSocket, 3)

			if err := restartDaemons(context.Background(), f, cfg, artifactManifest(cfg)); err != nil {
				t.Fatalf("restartDaemons: %v", err)
			}

			netdBootstrap := firstCall(f, "Bootstrap:"+NetdLabel)
			nodeBootstrap := firstCall(f, "Bootstrap:"+r.label)
			firstDial := firstCall(f, "ProbeNetd:"+cfg.NetdSocket)
			lastDial := lastCall(f, "ProbeNetd:"+cfg.NetdSocket)
			switch {
			case netdBootstrap < 0 || nodeBootstrap < 0:
				t.Fatalf("both daemons must be bootstrapped (calls: %v)", f.calls)
			case firstDial < 0:
				t.Fatalf("the restart never probed %s, so it never waited for the helper (calls: %v)", cfg.NetdSocket, f.calls)
			case firstDial < netdBootstrap:
				t.Errorf("the wait for %s began before netd was bootstrapped", cfg.NetdSocket)
			case lastDial > nodeBootstrap:
				t.Errorf("%s was bootstrapped before %s answered: the daemon starts into a helper that is not serving", r.label, cfg.NetdSocket)
			}
			// Four probes: the three refusals plus the one that was answered. A
			// sequence that probed once and went on would satisfy the ordering
			// above while waiting for nothing.
			if n := countCalls(f, "ProbeNetd:"+cfg.NetdSocket); n != 4 {
				t.Errorf("probes of %s = %d, want 4 (three refusals then the answer)", cfg.NetdSocket, n)
			}
		})

		t.Run(r.name+" fails the install when netd accepts but never answers", func(t *testing.T) {
			shrinkRestartBudgets(t)
			cfg := r.cfg(t).withDefaults()
			f := &fakeSystem{}
			f.putLoaded(NetdLabel, r.label)
			// The socket is bound and the kernel queues every connect; netd
			// itself is serving nothing. This is the state a dial-only wait
			// reports as healthy, and the node daemon would be started into it.
			f.putWedgedSocket(cfg.NetdSocket)

			err := restartDaemons(context.Background(), f, cfg, artifactManifest(cfg))
			if err == nil {
				t.Fatal("restartDaemons must fail on a socket that accepts and never answers: a connect proves the kernel queued it, not that netd is serving")
			}
			for _, want := range []string{cfg.NetdSocket, NetdLabel, NetdLogPath(), "did not answer"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q must name %q — the operator needs the socket, the helper and where its reason is", err, want)
				}
			}
			if firstCall(f, "Bootstrap:"+r.label) >= 0 {
				t.Errorf("%s was bootstrapped into a wedged helper (calls: %v)", r.label, f.calls)
			}
		})

		t.Run(r.name+" fails the install when netd never answers", func(t *testing.T) {
			shrinkRestartBudgets(t)
			cfg := r.cfg(t).withDefaults()
			f := &fakeSystem{}
			f.putLoaded(NetdLabel, r.label)
			f.putMissingPath(cfg.NetdSocket) // bootstrapped, never serving

			err := restartDaemons(context.Background(), f, cfg, artifactManifest(cfg))
			if err == nil {
				t.Fatal("restartDaemons must fail rather than start the node daemon against a helper that never came up")
			}
			for _, want := range []string{cfg.NetdSocket, NetdLabel, NetdLogPath(), r.label} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q must name %q — the operator needs the socket, the helper and where its reason is", err, want)
				}
			}
			// The node daemon was never started into the failure.
			if firstCall(f, "Bootstrap:"+r.label) >= 0 {
				t.Errorf("%s was bootstrapped despite netd never answering (calls: %v)", r.label, f.calls)
			}
		})
	}
}
