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

}
