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
	"log/slog"
	"strings"
	"time"
)

// The daemon restart sequence, and why it is a sequence at all.
//
// `launchctl bootout` returns BEFORE launchd has finished removing the label from
// the system domain. Install used to pair it with an immediate `launchctl
// bootstrap` on the stated assumption that "bootout blocks until the old job
// unloads" — which is false, and was observed to be false on a live install: the
// bootstrap that lands milliseconds later races the still-running teardown and is
// rejected with errno 37 (EINPROGRESS, "Operation already in progress" — the
// removal is still in flight) or errno 5 (EIO, returned while the label drains;
// the window was measured at 1.77s). Install then returned mid-loop, which left
// netd booted out and DOWN, the server never restarted, and nothing in the path to
// retry, roll back, or even notice.
//
// So each label is restarted as bootout → await-unloaded → bootstrap (retrying
// exactly that transient class) → await-running. The await idiom is
// executor.awaitRestartedInstance's, reused rather than reinvented: poll
// LaunchctlServicePID, whose two answer shapes ARE the two states this needs — a
// label that is no longer in the domain fails the read (that is "unloaded"), and a
// job that is loaded but has not spawned reports pid 0 (that is "not up yet").

// ErrLaunchctlTransient marks a launchctl failure that is a race against launchd's
// own bookkeeping rather than a verdict on the job: the identical command succeeds
// once the domain settles. It is the discriminator the bootstrap retry below keys
// on, and it is decided at the darwin boundary (install_darwin.go), the only place
// launchctl's output text is visible — the orchestration compares sentinels with
// errors.Is and never matches strings.
var ErrLaunchctlTransient = errors.New("launchctl reported a transient system-domain state")

// restartBudget bounds one label's restart. unload also bounds the bootstrap
// retry, because both wait out the same teardown; running bounds the wait for the
// fresh instance to report a pid; poll is the interval between launchd reads.
type restartBudget struct {
	unload  time.Duration
	running time.Duration
	poll    time.Duration
}

// The per-daemon budgets. They are vars, not consts, so a unit test can shrink
// them to microseconds; nothing in the product writes them.
//
// netd is a single Go process with no orderly teardown to perform, so 30s is
// generous. The server is not: its plist sets ExitTimeOut 45 (launchd's SIGTERM →
// SIGKILL grace), and the control plane tears its components down serially inside
// that window, so any unload budget at or below 45s would time out on precisely
// the slow-but-healthy shutdown the wait exists to tolerate. 60s clears it with
// margin.
var (
	netdRestartBudget   = restartBudget{unload: 30 * time.Second, running: 30 * time.Second, poll: 250 * time.Millisecond}
	serverRestartBudget = restartBudget{unload: 60 * time.Second, running: 60 * time.Second, poll: 250 * time.Millisecond}
)

// restartBudgetFor returns the budget for a label. Only the server gets the long
// one; every other daemon (netd today) gets the short one, so a daemon added to
// the manifest later inherits the conservative default rather than the server's.
func restartBudgetFor(label string) restartBudget {
	if label == ServerLabel {
		return serverRestartBudget
	}
	return netdRestartBudget
}

// restartDaemons (re)starts every daemon in the manifest, in manifest order (netd
// before the server that depends on it), each through the full sequence above.
//
// On a failure part-way through it does NOT simply return: whatever it has already
// booted out is, by definition, down because of this install. It re-bootstraps
// every such label best-effort and names the outcome in the error, so an operator
// reading one sentence knows which daemons are running — the state-honesty the old
// mid-loop return had none of.
func restartDaemons(ctx context.Context, sys System, m []artifact, logger *slog.Logger) error {
	var touched []string
	for _, a := range m {
		if a.kind != kindDaemon {
			continue
		}
		// Recorded BEFORE the attempt: the bootout is the first thing restartDaemon
		// does, so a failure anywhere in the sequence — including in the bootout
		// itself — can have left this label down.
		touched = append(touched, a.label)
		if err := restartDaemon(ctx, sys, a.label, logger); err != nil {
			recovery := recoverBootedOut(sys, touched)
			states, _ := daemonStates(sys)
			return fmt.Errorf("%w; %s; daemon state: %s", err, recovery, strings.Join(states, ", "))
		}
	}
	return nil
}

// restartDaemon runs one label's bootout → await-unloaded → bootstrap → await-running.
func restartDaemon(ctx context.Context, sys System, label string, logger *slog.Logger) error {
	b := restartBudgetFor(label)
	if err := sys.LaunchctlBootout(label); err != nil {
		return fmt.Errorf("bootout stale %s before (re)bootstrap: %w", label, err)
	}
	if err := awaitUnloaded(ctx, sys, label, b); err != nil {
		return err
	}
	if err := bootstrapWithRetry(ctx, sys, label, b); err != nil {
		return err
	}
	pid, err := awaitRunning(ctx, sys, label, b)
	if err != nil {
		return err
	}
	logger.Info("daemon restarted on the freshly installed binary", "label", label, "pid", pid)
	return nil
}

// awaitUnloaded blocks until launchd no longer has the label in the system domain.
// The verdict is LaunchctlServicePID's ERROR: a label that is gone has no job to
// print, and that failure is the only positive evidence the teardown finished
// (pid 0 does not mean unloaded — it is the ordinary loaded-but-not-running state).
func awaitUnloaded(ctx context.Context, sys System, label string, b restartBudget) error {
	deadline := time.Now().Add(b.unload)
	for {
		pid, err := sys.LaunchctlServicePID(label)
		if err != nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s was still loaded %s after its bootout (launchd reports pid %d); refusing to bootstrap into a draining label", label, b.unload, pid)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(b.poll):
		}
	}
}

// bootstrapWithRetry bootstraps the label, re-attempting ONLY the transient class
// (ErrLaunchctlTransient). Everything else — a malformed plist, a missing
// executable, a refused domain — is a verdict that will not change, and retrying
// it would turn a legible install failure into a minute of silence.
func bootstrapWithRetry(ctx context.Context, sys System, label string, b restartBudget) error {
	deadline := time.Now().Add(b.unload)
	for attempt := 1; ; attempt++ {
		err := sys.LaunchctlBootstrap(label)
		if err == nil {
			return nil
		}
		if !errors.Is(err, ErrLaunchctlTransient) {
			return fmt.Errorf("bootstrap %s: %w", label, err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("bootstrap %s: launchd kept reporting a transient system-domain state across %d attempts in %s: %w", label, attempt, b.unload, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(b.poll):
		}
	}
}

// awaitRunning blocks until launchd reports a live pid for the label and returns
// it. A read error (the label is not loaded — the bootstrap did not take) and a
// zero pid (the ordinary respawn window) are both tolerated until the deadline;
// the LAST reason is wrapped into the timeout so the caller can tell "never
// loaded" from "loaded but never spawned".
func awaitRunning(ctx context.Context, sys System, label string, b restartBudget) (int, error) {
	deadline := time.Now().Add(b.running)
	var last error
	for {
		pid, err := sys.LaunchctlServicePID(label)
		switch {
		case err != nil:
			last = fmt.Errorf("reading the launchd pid of %s: %w", label, err)
		case pid == 0:
			last = fmt.Errorf("%s is loaded but has not spawned", label)
		default:
			return pid, nil
		}
		if time.Now().After(deadline) {
			return 0, fmt.Errorf("%s did not come up within %s of its bootstrap: %w", label, b.running, last)
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(b.poll):
		}
	}
}

// recoverBootedOut re-bootstraps, best effort, every label this install booted out
// that launchd no longer has loaded, and returns one clause describing what it
// found and did. A label that is still loaded is skipped: this install took
// nothing away from it. Errors are reported, never returned — the caller is
// already failing, and the recovery's only job is to make the failure state
// truthful.
func recoverBootedOut(sys System, labels []string) string {
	var recovered, down []string
	for _, l := range labels {
		if _, err := sys.LaunchctlServicePID(l); err == nil {
			continue
		}
		if err := sys.LaunchctlBootstrap(l); err != nil {
			down = append(down, l)
			continue
		}
		recovered = append(recovered, l)
	}
	switch {
	case len(recovered) == 0 && len(down) == 0:
		return "no daemon was left booted out"
	case len(down) == 0:
		return "re-bootstrapped after the failure: " + strings.Join(recovered, ", ")
	case len(recovered) == 0:
		return "STILL DOWN, re-bootstrap failed: " + strings.Join(down, ", ")
	default:
		return "re-bootstrapped " + strings.Join(recovered, ", ") + "; STILL DOWN: " + strings.Join(down, ", ")
	}
}

// verifyDaemons is the assertion the install path never used to make: after the
// restarts, BOTH daemons report a live pid and the netd unix socket the two
// rendezvous on is on disk. Without it an install could return success having left
// netd down — the exact outcome the racing bootstrap produced, and the reason it
// went unnoticed until a cluster's DNS stopped answering.
//
// The socket is polled rather than sampled once: netd binds it after its own
// startup, so a single read immediately after the bootstrap tests the wrong thing.
// The error names the state of EVERY component, not just the first bad one — an
// operator needs to know what IS running as much as what is not.
func verifyDaemons(ctx context.Context, sys System, cfg Config) error {
	states, healthy := daemonStates(sys)
	switch err := awaitPath(ctx, sys, cfg.NetdSocket, restartBudgetFor(NetdLabel)); {
	case err == nil:
		states = append(states, cfg.NetdSocket+" present")
	default:
		states = append(states, err.Error())
		healthy = false
	}
	if !healthy {
		return fmt.Errorf("the restarted daemons are not both healthy: %s", strings.Join(states, "; "))
	}
	cfg.Logger.Info("verified both daemons after the restart", "state", strings.Join(states, "; "))
	return nil
}

// awaitPath polls for path to appear, within the budget's running window. Its
// error text is a state clause, because verifyDaemons reports it alongside the two
// pid clauses rather than wrapping it.
func awaitPath(ctx context.Context, sys System, path string, b restartBudget) error {
	deadline := time.Now().Add(b.running)
	for {
		ok, err := sys.PathExists(path)
		switch {
		case err != nil:
			// Unverifiable is not absent, and must not be reported as either
			// present or absent.
			return fmt.Errorf("%s unverifiable: %v", path, err)
		case ok:
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s ABSENT after %s (netd is not serving the helper socket the control plane dials)", path, b.running)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(b.poll):
		}
	}
}

// daemonStates reports one clause per daemon — "up (pid N)" or "DOWN (<why>)" —
// and whether every one of them is up. It is the single home of that vocabulary,
// used both by the post-restart verification and by the mid-restart failure path,
// so an operator reading either error reads the same sentence about the same
// machine and never has to guess which daemon survived.
func daemonStates(sys System) ([]string, bool) {
	states := make([]string, 0, 2)
	healthy := true
	for _, label := range []string{NetdLabel, ServerLabel} {
		pid, err := sys.LaunchctlServicePID(label)
		switch {
		case err != nil:
			states = append(states, label+" DOWN (not loaded in the system domain)")
			healthy = false
		case pid == 0:
			states = append(states, label+" DOWN (loaded, no process)")
			healthy = false
		default:
			states = append(states, fmt.Sprintf("%s up (pid %d)", label, pid))
		}
	}
	return states, healthy
}
