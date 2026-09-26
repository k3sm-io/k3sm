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
	"io/fs"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/nodecred"
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
// generous. A node daemon is not: its plist sets the ExitTimeOut derived above
// (launchd's SIGTERM → SIGKILL grace), and it runs its whole teardown serially
// inside that window, so any unload budget at or below the grace would time out
// on precisely the slow-but-healthy shutdown the wait exists to tolerate.
//
// So the node budget is DERIVED from that same grace rather than chosen: the
// larger of the two node plists (the server's) plus a margin for launchd to
// finish removing the label from its domain after the process is gone. Pinned by
// TestRestartBudgetByLabel, which is what catches a grace that grows past it.
const nodeUnloadMargin = 15 * time.Second

var (
	netdRestartBudget   = restartBudget{unload: 30 * time.Second, running: 30 * time.Second, poll: 250 * time.Millisecond}
	serverRestartBudget = restartBudget{unload: time.Duration(serverExitTimeOut)*time.Second + nodeUnloadMargin, running: 60 * time.Second, poll: 250 * time.Millisecond}
	// agentJoinBudget bounds the wait for a FIRST join to produce a credential
	// (see verifyDaemons). It is a different question from a restart, so it is a
	// different budget: nothing is being unloaded, and the clock is the join
	// round-trip — a bootstrap dial, two CSRs signed by the control plane, and
	// the write. 60s is the same order as the server's, and comfortably longer
	// than the agent's own 30s terminal backoff, so a token the server rejects
	// is observed as the failure it is rather than as an install that ran out of
	// patience.
	agentJoinBudget = restartBudget{unload: 60 * time.Second, running: 60 * time.Second, poll: 250 * time.Millisecond}
)

// restartBudgetFor returns the budget for a label. The two NODE daemons get the
// long one; every other daemon (netd today) gets the short one, so a daemon
// added to the manifest later inherits the conservative default rather than the
// node's.
//
// The agent is in the long class for the reason its own plist sets a raised
// ExitTimeOut: its teardown is not instantaneous either (it stops its embedded
// runtime's vm guests, closes the mesh device and drains the Service proxy's
// listeners), so any unload budget at or below that
// SIGTERM-to-SIGKILL grace would time out on precisely the slow-but-healthy
// shutdown the wait exists to tolerate — and the install would then refuse to
// bootstrap into a label it had just asked to stop.
func restartBudgetFor(label string) restartBudget {
	if label == ServerLabel || label == AgentLabel {
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
func restartDaemons(ctx context.Context, sys System, cfg Config, m []artifact) error {
	logger := cfg.Logger
	var touched []string
	// stateHonestly turns any failure in this sequence into the one-sentence
	// report the whole function exists for: what went wrong, what was
	// re-bootstrapped, and which daemons are up right now.
	stateHonestly := func(err error) error {
		recovery := recoverBootedOut(sys, touched)
		states, _ := daemonStates(sys, longRunningDaemonLabels(m))
		return fmt.Errorf("%w; %s; daemon state: %s", err, recovery, strings.Join(states, ", "))
	}
	netdRestarted := false
	for _, a := range m {
		if a.kind != kindDaemon {
			continue
		}
		// The node daemon dials netd before it does anything else, so it does not
		// go until netd ANSWERS. Nothing used to wait here at all: the only socket
		// check was verifyDaemons', which runs after both daemons are already up.
		if netdRestarted && isNodeDaemon(a.label) {
			if err := awaitNetdServing(ctx, sys, cfg.NetdSocket, a.label, restartBudgetFor(NetdLabel)); err != nil {
				return stateHonestly(err)
			}
			logger.Info("netd answered on the helper socket; starting the node daemon", "socket", cfg.NetdSocket, "label", a.label)
		}
		// Recorded BEFORE the attempt: the bootout is the first thing restartDaemon
		// does, so a failure anywhere in the sequence — including in the bootout
		// itself — can have left this label down.
		touched = append(touched, a.label)
		if err := restartDaemon(ctx, sys, a.label, a.oneshot, logger); err != nil {
			return stateHonestly(err)
		}
		if a.label == NetdLabel {
			netdRestarted = true
		}
	}
	return nil
}

// isNodeDaemon reports whether label is the role's node daemon — the one that
// dials netd on the way up. It is derived from the two labels rather than from
// the manifest position, because the manifest carries whichever of the two this
// role installs and a positional rule would silently mean something else on the
// other role.
func isNodeDaemon(label string) bool { return label == ServerLabel || label == AgentLabel }

// awaitNetdServing blocks until the netd helper ANSWERS on its unix socket, and
// is the gap between the two daemons the restart sequence used to leave open.
//
// On 2026-09-17 an install bootstrapped io.k3sm.netd and then io.k3sm.agent 24ms
// later. The agent's first start dialed the helper socket, got "no such file",
// recorded a bring-up failure and backed off; launchd's KeepAlive retry brought
// it up ten seconds later against a netd that by then was listening. Nothing was
// broken afterwards — but the install had recorded a failure it caused, and the
// join verification reads that record. The server role never hit it only because
// its own bring-up takes some 37 seconds, which is luck, not ordering.
//
// NEITHER PRESENCE NOR A CONNECT IS THE QUESTION. verifyDaemons' awaitPath
// (which still runs, on the far side of both restarts) asks whether the socket
// file is there; a bound socket exists on the filesystem from the moment netd
// binds it, which is before it accepts. And a connect is barely better: the
// kernel completes it into the listen backlog with no involvement from the
// process that bound the socket, so a netd that is listening and wedged passes a
// dial-only check while serving nothing. So this wait asks netd to ANSWER — one
// framed request, one reply (System.ProbeNetd) — and only an answer ends it.
//
// The bound is netd's own restart budget — the same window the caller already
// allows that daemon to come up in — so a helper that never answers fails the
// install here, naming the socket and the log that says why, instead of letting
// the node daemon start into the failure and record it as its own.
func awaitNetdServing(ctx context.Context, sys System, socket, label string, b restartBudget) error {
	deadline := time.Now().Add(b.running)
	var last error
	for {
		err := sys.ProbeNetd(socket)
		if err == nil {
			return nil
		}
		last = err
		if time.Now().After(deadline) {
			return fmt.Errorf("%s did not answer on %s within %s of its restart, so %s would start against a helper that is not serving and record the bring-up failure as its own (last probe: %v); the reason is the last lines of %s",
				NetdLabel, socket, b.running, label, last, NetdLogPath())
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(b.poll):
		}
	}
}

// restartDaemon runs one label's bootout → await-unloaded → bootstrap → await-running.
//
// A ONESHOT (io.k3sm.datavol) ends at await-LOADED instead. It mounts and exits,
// so waiting for a live pid would be waiting for a state the job is designed not
// to be in: on a fast machine it has already finished by the time the wait
// starts, and the install would fail on a job that did exactly what it was asked
// to do. Loaded is the whole claim install makes about it -- the mount itself was
// performed, synchronously and with its own retry, before any of this ran.
func restartDaemon(ctx context.Context, sys System, label string, oneshot bool, logger *slog.Logger) error {
	b := restartBudgetFor(label)
	if err := sys.LaunchctlBootout(label); err != nil {
		return fmt.Errorf("bootout stale %s before (re)bootstrap: %w", label, err)
	}
	if err := awaitUnloaded(ctx, sys, label, b); err != nil {
		return err
	}
	// Enable before bootstrap, every time. launchd refuses to bootstrap a label
	// disabled in the system domain with EIO, the same errno it returns while a
	// booted-out label drains, so the retry below cannot tell the two apart and
	// would spend its whole budget on a refusal that never clears. Enabling first
	// removes that case instead of reclassifying the errno. It is a no-op on an
	// enabled label; on a disabled one it overrides an earlier operator disable,
	// because running k3sm install is the newer statement of intent.
	if err := sys.LaunchctlEnable(label); err != nil {
		return fmt.Errorf("enable %s in the system domain before bootstrapping it (to clear it by hand, run: sudo launchctl enable system/%s): %w", label, label, err)
	}
	logger.Info("ensured the label is enabled in the system domain before bootstrap (an earlier operator disable, if any, is overridden: k3sm install is the newer intent)", "label", label)
	if err := bootstrapWithRetry(ctx, sys, label, b); err != nil {
		return err
	}
	if oneshot {
		if err := awaitLoaded(ctx, sys, label, b); err != nil {
			return err
		}
		logger.Info("oneshot daemon loaded on the freshly installed binary", "label", label)
		return nil
	}
	pid, err := awaitRunning(ctx, sys, label, b)
	if err != nil {
		return err
	}
	logger.Info("daemon restarted on the freshly installed binary", "label", label, "pid", pid)
	return nil
}

// bootoutDaemons stops the long-running daemons, in REVERSE manifest order --
// the server before the netd helper it drives -- and waits for each to leave the
// system domain. A label that is not loaded is a no-op success, so it is safe on
// a first install.
//
// The data-root migration needs it: copying a live datastore is copying a file
// being written, and the verification that follows would be comparing a moving
// target. Oneshots are skipped; there is nothing to stop.
func bootoutDaemons(ctx context.Context, sys System, m []artifact, logger *slog.Logger) error {
	for i := len(m) - 1; i >= 0; i-- {
		a := m[i]
		if a.kind != kindDaemon || a.oneshot {
			continue
		}
		if err := sys.LaunchctlBootout(a.label); err != nil {
			return fmt.Errorf("bootout %s: %w", a.label, err)
		}
		if err := awaitUnloaded(ctx, sys, a.label, restartBudgetFor(a.label)); err != nil {
			return err
		}
		logger.Info("daemon stopped for the data-root migration", "label", a.label)
	}
	return nil
}

// awaitLoaded blocks until launchd has the label in the system domain, whether
// or not it has a process. It is the oneshot's success condition: pid 0 is the
// ordinary state of a job that ran and exited, and LaunchctlServicePID's ERROR
// is the only thing that means "not there".
func awaitLoaded(ctx context.Context, sys System, label string, b restartBudget) error {
	deadline := time.Now().Add(b.running)
	var last error
	for {
		_, err := sys.LaunchctlServicePID(label)
		if err == nil {
			return nil
		}
		last = err
		if time.Now().After(deadline) {
			return fmt.Errorf("%s was not loaded within %s of its bootstrap: %w", label, b.running, last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(b.poll):
		}
	}
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
			return fmt.Errorf("bootstrap %s: launchd kept reporting a transient system-domain state across %d attempts in %s (if 'launchctl print-disabled system' lists %s, run: sudo launchctl enable system/%s): %w", label, attempt, b.unload, label, label, err)
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

// revertInstallRoot is the rollback for a failure that happened AFTER the staged
// install root was published and BEFORE the previous tree was reaped — the one
// window in which a rollback is both possible and correct.
//
// It does two things, in order, and both are best-effort: one reverse swap, which
// puts the previous tree back at the live path and this install's tree back at
// the staging path, and then a re-run of the restart against the reverted tree,
// because the daemons may already have been booted out (or worse, bootstrapped)
// onto the new binary. Neither failure is returned on its own — the caller is
// already failing, and this function's only job is to make the failure state
// truthful.
//
// The report is stateHonestly's shape deliberately, not a second vocabulary: one
// sentence carrying the original cause, what was rolled back, and which daemons
// are running right now. An operator reading an upgrade that failed needs those
// three facts and no others.
//
// previous is the publish's own answer to "was there a tree here before". When it
// is false the publish was a plain rename onto an absent install root — a first
// install — so there is nothing to revert TO, and saying so is more useful than
// swapping the new tree out and leaving the Mac with no install root at all.
func revertInstallRoot(ctx context.Context, sys System, cfg Config, m []artifact, previous bool, cause error) error {
	states := func() string {
		s, _ := daemonStates(sys, longRunningDaemonLabels(m))
		return strings.Join(s, ", ")
	}
	if !previous {
		return fmt.Errorf("%w; the install root %s is this install's tree and there is no previous one to roll back to (first install); daemon state: %s", cause, cfg.InstallDir, states())
	}
	staging := cfg.stagingDir()
	if _, err := sys.SwapInstallRoot(staging, filepath.Clean(cfg.InstallDir)); err != nil {
		return fmt.Errorf("%w; ROLLBACK FAILED, the install root %s still holds the NEW tree and the previous one is at %s: %v; daemon state: %s", cause, cfg.InstallDir, staging, err, states())
	}
	cfg.Logger.Warn("rolled the install root back to the previous tree", "live", filepath.Clean(cfg.InstallDir), "failed-tree", staging, "cause", cause)
	// The daemons are restarted against what is live NOW. Whatever the failure
	// was, this install may have booted a label out, or bootstrapped it onto the
	// tree that has just been swapped away; only a restart makes the running
	// processes agree with the tree on disk again.
	if err := restartDaemons(ctx, sys, cfg, m); err != nil {
		return fmt.Errorf("%w; rolled back to the previous install root (the failed tree is at %s), but restarting the daemons on it also failed: %v; daemon state: %s", cause, staging, err, states())
	}
	return fmt.Errorf("%w; rolled back to the previous install root and restarted the daemons on it (the failed tree is at %s, remove it with `sudo rm -rf %s`); daemon state: %s", cause, staging, staging, states())
}

// recoverBootedOut re-bootstraps, best effort, every label this install booted out
// that launchd no longer has loaded, and returns one clause describing what it
// found and did. A label that is still loaded is skipped: this install took
// nothing away from it. Errors are reported, never returned — the caller is
// already failing, and the recovery's only job is to make the failure state
// truthful.
//
// Each label is enabled before its bootstrap, for the reason restartDaemon does
// it: a label disabled in the system domain refuses bootstrap, and the recovery
// would otherwise report STILL DOWN for a state the code can clear itself. An
// enable failure is noted, never fatal; the bootstrap is still attempted.
func recoverBootedOut(sys System, labels []string) string {
	var recovered, down, notEnabled []string
	for _, l := range labels {
		if _, err := sys.LaunchctlServicePID(l); err == nil {
			continue
		}
		if err := sys.LaunchctlEnable(l); err != nil {
			notEnabled = append(notEnabled, l)
		}
		if err := sys.LaunchctlBootstrap(l); err != nil {
			down = append(down, l)
			continue
		}
		recovered = append(recovered, l)
	}
	var clause string
	switch {
	case len(recovered) == 0 && len(down) == 0:
		clause = "no daemon was left booted out"
	case len(down) == 0:
		clause = "re-bootstrapped after the failure: " + strings.Join(recovered, ", ")
	case len(recovered) == 0:
		clause = "STILL DOWN, re-bootstrap failed: " + strings.Join(down, ", ")
	default:
		clause = "re-bootstrapped " + strings.Join(recovered, ", ") + "; STILL DOWN: " + strings.Join(down, ", ")
	}
	for _, l := range notEnabled {
		clause += "; could not enable " + l + " (run: sudo launchctl enable system/" + l + ")"
	}
	return clause
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
func verifyDaemons(ctx context.Context, sys System, cfg Config, m []artifact, startedAt time.Time) error {
	states, healthy := daemonStates(sys, longRunningDaemonLabels(m))
	switch err := awaitPath(ctx, sys, cfg.NetdSocket, "netd is not serving the helper socket the control plane dials", restartBudgetFor(NetdLabel)); {
	case err == nil:
		states = append(states, cfg.NetdSocket+" present")
	default:
		states = append(states, err.Error())
		healthy = false
	}
	if !healthy {
		return fmt.Errorf("the restarted daemons are not all healthy: %s", strings.Join(states, "; "))
	}
	// A live pid is not the whole claim on the server role either: a daemon whose
	// crash-loop breaker has tripped is resident, idle, and serving nothing.
	if err := verifyServerNotParked(sys, cfg, m, startedAt); err != nil {
		return err
	}
	if err := verifyAgentJoined(ctx, sys, cfg, startedAt); err != nil {
		return err
	}
	cfg.Logger.Info("verified the daemons after the restart", "state", strings.Join(states, "; "))
	return nil
}

// ErrServerParked marks an install that restarted the server daemon into its
// crash-loop give-up: the breaker is tripped, so the daemon parks instead of
// bringing the control plane up. It is a sentinel so a caller can tell this
// verdict from an ordinary "daemon is down" one — the remedy is an operator
// action, not a retry.
var ErrServerParked = errors.New("the k3sm server daemon is parked by its crash-loop breaker")

// ErrServerNotComingUp marks an install whose OWN restart produced at least one
// bring-up failure: the control plane this install started did not come up, and
// launchd is respawning it into the same fault. The breaker has not given up
// yet, and that is precisely why this is a separate sentinel — install does not
// wait for it to.
var ErrServerNotComingUp = errors.New("the k3sm server daemon did not bring the control plane up")

// verifyServerNotParked is the assertion a pid cannot make on the server role,
// and it makes it in two tenses.
//
// A control plane that keeps failing trips its own breaker, and a tripped daemon
// does not exit — it PARKS: resident, idle, answering nothing, because the
// server plist's KeepAlive is a bare `true` and any exit would just be another
// lap of the loop (pkg/executor's crash-loop record). launchd reports a perfectly
// healthy pid for it. So an install that verified the pid alone would report
// success over a cluster that is not running and will not start, which is the
// same class of lie the netd socket check exists to prevent.
//
// But a trip is a state that takes MINUTES to reach: five failures inside the
// window. A fault that fails SLOWLY — a component that times out after 30s on
// every attempt — has produced one or two entries by the time the 60s restart
// budget is up, so an install that asked only "is it tripped?" would pass on
// exactly the persistent fault it exists to catch, and the daemon would give up
// unattended some minutes later with nobody watching. Hence the second, stricter
// question: has the control plane failed to come up AT ALL since this install
// began? One bring-up failure dated at or after startedAt fails the install,
// tripped or not — this install restarted that daemon, so that failure is this
// install's to report.
//
// The timestamp is what keeps a reinstall honest in the other direction: an
// OLDER record, from the very fault an operator may be reinstalling to fix, does
// not fail anything by itself. Only a trip does, because a tripped daemon is
// parked right now whatever its history. Crash-origin entries are not counted
// by the fresh check either way: a component that came up and later died is a
// different and survivable story, and launchd's restart of it is the design.
//
// It is FAIL-OPEN on everything else: an absent record is the ordinary case, and
// an unreadable or malformed one is bookkeeping, not a verdict — refusing an
// install over a corrupt marker would be a second way to lose a control plane,
// the same reason the daemon treats it as empty.
func verifyServerNotParked(sys System, cfg Config, m []artifact, startedAt time.Time) error {
	if !slices.Contains(longRunningDaemonLabels(m), ServerLabel) {
		return nil // an agent-only install runs no control plane of its own
	}
	path := executor.CrashLoopPath(cfg.serverWorkDir())
	raw, err := sys.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		cfg.Logger.Warn("could not read the server's crash-loop record", "path", path, "err", err)
		return nil
	}
	rec, err := executor.ParseCrashRecord(raw)
	if err != nil {
		cfg.Logger.Warn("the server's crash-loop record is unreadable; treating it as empty", "path", path, "err", err)
		return nil
	}
	if rec.Tripped() {
		last, _ := rec.Last()
		return fmt.Errorf("%w: %s, so it is resident and serving nothing (tripped at %s; %s: %s; record: %s). Clear it and reinstall: sudo k3sm server --clear-crashloop",
			ErrServerParked, parkedSummary(last), rec.TrippedAt.Format(time.RFC3339), last.Origin, last.Component, path)
	}
	// The daemon and this process read the same machine's clock, so comparing
	// the record's timestamps with this install's start compares a clock with
	// itself.
	fresh, last := freshBringUpFailures(rec, startedAt)
	if fresh == 0 {
		return nil
	}
	return fmt.Errorf("%w: the control plane failed to come up %d times since this install began (last: %s at %s); launchd keeps respawning it into the same fault and the breaker parks the daemon after %d. The reason is the last lines of %s, with the redacted tails in %s; fix it and reinstall (clear a parked daemon first: sudo k3sm server --clear-crashloop)",
		ErrServerNotComingUp, fresh, last.Component, last.At.Format(time.RFC3339), executor.CrashLoopThreshold, ServerLogPath(), path)
}

// freshBringUpFailures counts the bring-up failures dated at or after since, and
// returns the last of them.
func freshBringUpFailures(rec executor.CrashRecord, since time.Time) (int, executor.Crash) {
	n := 0
	var last executor.Crash
	for _, c := range rec.Crashes {
		if c.Origin != executor.CrashOriginBringUp || c.At.Before(since) {
			continue
		}
		n++
		last = c
	}
	return n, last
}

// parkedSummary says which of the two failures the breaker counted last, in the
// words an operator needs to start looking: a control plane that came up and
// then died is a different search through the log than one that never came up.
func parkedSummary(last executor.Crash) string {
	if last.Origin == executor.CrashOriginBringUp {
		return "the control plane never came up (last: " + last.Component + ")"
	}
	return "the control plane kept crashing (last: " + last.Component + ")"
}

// verifyAgentJoined is the extra assertion an agent install needs, and the
// reason a pid is not enough on this role.
//
// `k3sm agent` treats its terminal start failures as things to back off from
// rather than to die of: a token the cluster rejects, a token file that is not
// there when no credential is either, a corrupt credential, a node-password it
// cannot persist. That is right for a KeepAlive daemon (the alternative is a
// spawn loop), and it means a broken worker presents launchd with a perfectly
// healthy pid for 30 seconds at a time. An install that verified the pid alone
// would report success and hand the operator a node that never appears in
// `kubectl get nodes`.
//
// THE PRESENCE OF A FILE IS NOT A WITNESS. This check used to wait only for
// AgentCredentialPath to exist — and a credential is exactly what a Mac that
// has been installed before already has. On 2026-09-17 that passed instantly on
// a reinstall while the agent was crash-looping on "persist node-password:
// permission denied", so the install reported "the agent joined the cluster"
// about a daemon that had joined nothing. A file says only that SOME start, at
// some point in the past, succeeded; it cannot attest this install's daemon.
//
// So the claim is made from two witnesses instead, polled together over the
// join budget:
//
//   - THE CRASH RECORD, the same evidence the server role already uses
//     (verifyServerNotParked). The agent now records every start failure it
//     backs off from as a bring-up entry under its work dir, so a failure dated
//     at or after THIS install's start is this install's to report and fails it
//     immediately, quoting what the daemon recorded. Older entries fail
//     nothing — they are the fault an operator may well be reinstalling to fix.
//     It is FAIL-OPEN on everything else (absent, unreadable, malformed), for
//     the reason the server's is: bookkeeping is not a verdict.
//   - THE CREDENTIAL'S CLUSTER, not its existence. The credential counts only
//     when it parses as a complete node credential (pkg/nodecred — the same
//     reader the daemon and `k3sm status` use) AND its cluster-CA pin is the one
//     the token this install staged pins. A credential with a different pin is a
//     leftover from another cluster, so the wait continues: the daemon will
//     re-join over it. This half is FAIL-CLOSED: if the staged token cannot be
//     read back or does not parse, the install fails rather than falling back to
//     existence-and-parse, because a comparison with nothing to compare against
//     is exactly the check this function was written to stop making.
//
// The second witness is also what keeps a REINSTALL honest in the other
// direction. A worker that is simply being upgraded resumes from the credential
// it already holds and writes nothing new, so requiring a fresh write would
// fail every reinstall; requiring the right CLUSTER passes that case without
// accepting a stale file.
//
// A FRESH FAILURE IS NOT A VERDICT ON ITS OWN, and this is the half that
// changed. The check used to return on the first tick that saw a bring-up entry
// dated at or after this install began — before the daemon's own retry could
// land. But the agent is a KeepAlive job that backs off rather than exiting, so
// a failure is the beginning of a story launchd finishes: on 2026-09-17 the
// worker failed its first start 1.3s after the install bootstrapped it (netd
// was not yet serving), and launchd's retry ten seconds later joined the
// cluster. The install had already failed. So a fresh failure is now REMEMBERED
// — its detail is kept for the message — and the verification waits for the
// recovery it might be the start of: the join must be proved AND the daemon's
// pid must be observed alive on two ticks at least agentRecoveryObservation
// apart with no further entry appearing between them. A pid that goes away, or
// that comes back as a different process, restarts that window; another entry
// restarts it too. At the budget's end the newest failure is what the error
// quotes.
//
// The one thing that still fails at once is a TRIPPED record: the breaker has
// counted CrashLoopThreshold failures inside its window, which is not a start
// that is about to recover but a loop, and waiting out a budget on it only
// delays the same answer.
//
// When no token was staged there is nothing to verify: either the node already
// holds a credential, in which case the pid IS the whole claim, or it holds none
// and the daemon is backing off with an error the log names, which is not
// something this install caused and not something it can fix.
func verifyAgentJoined(ctx context.Context, sys System, cfg Config, startedAt time.Time) error {
	return verifyAgentJoinedOn(ctx, sys, cfg, startedAt, wallClock())
}

// agentJoinClock is the time verifyAgentJoinedOn reads and the way it waits
// between ticks. Production reads the wall clock and sleeps; a test supplies a
// clock it steps itself, so the observation window is crossed by ticks rather
// than by the scheduler.
//
// The seam exists because the alternative is a test whose verdict depends on how
// busy the machine is. Shrinking the window to a millisecond and racing it
// against a real poll loop made the "the daemon failed again and went away" row
// pass under -race: the window elapsed before the fake had delivered the failure
// and the pid drop. A window measured in the verification's OWN time cannot be
// won by a fast machine or lost by a slow one.
type agentJoinClock struct {
	now func() time.Time
	// tick waits d, or returns ctx's error. It is the only place this
	// verification blocks.
	tick func(ctx context.Context, d time.Duration) error
}

// wallClock is the production clock: real time, real sleeps.
func wallClock() agentJoinClock {
	return agentJoinClock{
		now: time.Now,
		tick: func(ctx context.Context, d time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(d):
				return nil
			}
		},
	}
}

func verifyAgentJoinedOn(ctx context.Context, sys System, cfg Config, startedAt time.Time, clk agentJoinClock) error {
	if cfg.Role != RoleAgent || cfg.TokenFile == "" {
		return nil
	}
	cred := AgentCredentialPath(cfg.DataRoot)
	record := executor.CrashLoopPath(cfg.agentWorkDir())
	pin, err := stagedTokenPin(sys, cfg)
	if err != nil {
		return err
	}
	deadline := clk.now().Add(agentJoinBudget.running)
	var (
		seen        agentFailureWitness // the fresh bring-up failures observed so far
		aliveSince  time.Time           // when the current uninterrupted run of this pid began
		alivePID    int
		why         string // why the last tick was not yet a join
		loggedState nodecred.State
	)
	for {
		rec, fresh := readAgentFailures(sys, cfg, startedAt)
		if rec.Tripped() {
			return fmt.Errorf("the agent daemon is not joining the cluster: its crash-loop breaker tripped at %s after %d start failures inside %s (last: %s), so this is a loop rather than a start that is about to recover. The reason is the last lines of %s; the agent's own record is %s",
				rec.TrippedAt.Format(time.RFC3339), executor.CrashLoopThreshold, executor.CrashLoopWindow, agentFailureDetail(lastCrash(rec)), AgentLogPath(), record)
		}
		if fresh.newerThan(seen) {
			// The daemon failed again while this verification was watching, so
			// whatever run of live pids preceded it did not survive.
			seen = fresh
			aliveSince = time.Time{}
			cfg.Logger.Warn("the agent recorded a start failure during this install; waiting for the retry launchd will make rather than failing on it",
				"detail", agentFailureDetail(fresh.last), "failures", fresh.count, "record", record)
		}
		switch pid, perr := sys.LaunchctlServicePID(AgentLabel); {
		case perr != nil:
			aliveSince, alivePID = time.Time{}, 0
		case pid == 0:
			aliveSince, alivePID = time.Time{}, 0
		case pid != alivePID:
			// A pid this verification has not seen before: either the first
			// observation, or launchd respawning the daemon after a start that
			// gave up. Either way the run starts here.
			aliveSince, alivePID = clk.now(), pid
		}
		joined, credWhy, state := agentCredentialProvesJoin(sys, cfg, pin)
		if joined && state != nodecred.Valid && state != loggedState {
			loggedState = state
			// The state is named rather than described, because it is no longer
			// only about dates: a credential can also be complete and in date
			// and name an address this node is not assigned.
			cfg.Logger.Warn("the agent's stored credential is for this cluster but is not usable as it stands; the daemon re-joins with the staged token or reports why",
				"credential", cred, "state", state)
		}
		steady := !aliveSince.IsZero() && clk.now().Sub(aliveSince) >= agentRecoveryObservation
		switch {
		case joined && steady:
			if seen.count > 0 {
				cfg.Logger.Warn("the agent recovered from a start failure recorded during this install",
					"credential", cred, "failures", seen.count, "detail", agentFailureDetail(seen.last), "observedRunningFor", agentRecoveryObservation, "pid", alivePID)
			}
			cfg.Logger.Info("the agent joined the cluster", "credential", cred, "pid", alivePID)
			return nil
		case !joined:
			why = credWhy
		case aliveSince.IsZero():
			why = fmt.Sprintf("%s is a credential for this cluster, but the agent daemon is not running (launchd reports no live process for %s), so nothing has presented it", cred, AgentLabel)
		default:
			why = fmt.Sprintf("%s is a credential for this cluster, but the agent daemon (pid %d) has not yet been running steadily for %s", cred, alivePID, agentRecoveryObservation)
		}
		if clk.now().After(deadline) {
			if seen.count > 0 {
				return fmt.Errorf("the agent daemon did not recover from a start failure this install caused: it failed to start %d times since this install began (last at %s: %s), and %s within %s. It backs off for %s between attempts rather than exiting, so launchd reports a healthy pid either way; the rest is in the last lines of %s — a rejected or expired token is the common one, and `k3sm token create` on the server mints a fresh one. The agent's own record is %s",
					seen.count, seen.last.At.Format(time.RFC3339), agentFailureDetail(seen.last), why, agentJoinBudget.running, agentTerminalBackoffNote, AgentLogPath(), record)
			}
			return fmt.Errorf("the agent daemon is running but has not joined the cluster within %s: %s (it backs off for %s between attempts rather than exiting, so launchd reports a healthy pid either way; the reason is the last lines of %s — a rejected or expired token is the common one, and `k3sm token create` on the server mints a fresh one)",
				agentJoinBudget.running, why, agentTerminalBackoffNote, AgentLogPath())
		}
		if err := clk.tick(ctx, agentJoinBudget.poll); err != nil {
			return err
		}
	}
}

// agentRecoveryObservation is how long the agent daemon must be observed
// running as ONE uninterrupted process — two ticks at least this far apart,
// with no new bring-up entry between them — before its credential is accepted
// as proof of a join.
//
// It is the thing a single tick cannot tell apart: an agent that failed once
// and was restarted by launchd into a healthy run looks, at any one instant,
// exactly like an agent that is about to fail again. Ten seconds is chosen
// against launchd's own respawn throttle (about ten seconds between KeepAlive
// restarts): a daemon that survives longer than the interval at which it would
// be relaunched has got past its start, and a daemon that has not will be
// caught by the next entry it writes. It is comfortably inside the 60s join
// budget, so the ordinary install pays it once and still has fifty seconds of
// patience left for the join itself.
//
// It is a var, not a const, so a unit test can shrink it; nothing in the
// product writes it.
var agentRecoveryObservation = 10 * time.Second

// agentFailureWitness is what one tick learned about the agent's fresh start
// failures: how many there have been since this install began, and the newest.
type agentFailureWitness struct {
	count int
	last  executor.Crash
}

// newerThan reports whether w holds a bring-up entry the previously observed
// witness did not. The count alone is not sufficient on its own — the record is
// pruned, so an entry can age out of the window while another arrives — so the
// newest timestamp decides whenever the count has not grown.
func (w agentFailureWitness) newerThan(prev agentFailureWitness) bool {
	if w.count == 0 {
		return false
	}
	return w.count > prev.count || w.last.At.After(prev.last.At)
}

// readAgentFailures reads the agent's crash-loop record and reports it together
// with the bring-up failures dated at or after this install began.
//
// It is FAIL-OPEN on everything that is not a failure the daemon recorded — an
// absent record is the ordinary case, and an unreadable or malformed one is
// bookkeeping rather than a verdict, for the same reason the daemon treats a
// corrupt record as empty: refusing an install over a marker nobody can parse
// would be a second way to lose a node.
func readAgentFailures(sys System, cfg Config, startedAt time.Time) (executor.CrashRecord, agentFailureWitness) {
	path := executor.CrashLoopPath(cfg.agentWorkDir())
	raw, err := sys.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return executor.CrashRecord{}, agentFailureWitness{}
	case err != nil:
		cfg.Logger.Warn("could not read the agent's crash-loop record", "path", path, "err", err)
		return executor.CrashRecord{}, agentFailureWitness{}
	}
	rec, err := executor.ParseCrashRecord(raw)
	if err != nil {
		cfg.Logger.Warn("the agent's crash-loop record is unreadable; treating it as empty", "path", path, "err", err)
		return executor.CrashRecord{}, agentFailureWitness{}
	}
	// The daemon and this process read the same machine's clock, so comparing
	// the record's timestamps with this install's start compares a clock with
	// itself.
	n, last := freshBringUpFailures(rec, startedAt)
	return rec, agentFailureWitness{count: n, last: last}
}

// lastCrash is the newest entry of any origin, for the tripped message — which
// is about the breaker rather than about this install, so it quotes what the
// breaker last counted.
func lastCrash(rec executor.CrashRecord) executor.Crash {
	if len(rec.Crashes) == 0 {
		return executor.Crash{}
	}
	return rec.Crashes[len(rec.Crashes)-1]
}

// agentFailureDetail is the recorded, already-redacted reason the agent could
// not start, or a stand-in when the entry carried none (a record left by a
// build that did not write details).
func agentFailureDetail(c executor.Crash) string {
	if strings.TrimSpace(c.Detail) == "" {
		return "no detail recorded"
	}
	return c.Detail
}

// agentCredentialProvesJoin reports whether the stored node credential is proof
// that this node belongs to the cluster the staged token names, the clause the
// failure message quotes when it is not, and the credential's own state.
//
// The state is RETURNED rather than logged here because the caller polls this
// several times a second: a warning emitted per tick would print the same
// sentence forty times over one join budget, so the caller logs each state once.
//
// The validation is pkg/nodecred's, never a second looser reader: `k3sm status`
// and the daemon already reach a verdict about these five files, and an
// installer that reached a different one about the same directory would send an
// operator to the wrong Mac.
//
// A credential that parses but is out of date still counts. Expiry is the
// daemon's decision — it re-joins with the staged token, or it fails and the
// record says so on the next tick — and an installer that failed here would be
// pre-empting a daemon that is about to fix it.
func agentCredentialProvesJoin(sys System, cfg Config, pin string) (joined bool, why string, state nodecred.State) {
	path := AgentCredentialPath(cfg.DataRoot)
	state, cred, err := nodecred.Status(sysFS{sys: sys}, cfg.agentWorkDir(), time.Now())
	switch {
	case cred == nil && err != nil:
		return false, fmt.Sprintf("%s did not parse as a node credential (%v)", path, err), state
	case cred == nil:
		return false, fmt.Sprintf("%s is ABSENT (the agent has not written the credential a completed join produces)", path), state
	case cred.ClusterCAPin != pin:
		return false, fmt.Sprintf("%s is a credential for a DIFFERENT cluster (it pins cluster CA %s; the token this install staged pins %s), so it is a file an earlier install left behind rather than proof of this join", path, cred.ClusterCAPin, pin), state
	}
	return true, "", state
}

// stagedTokenPin returns the cluster-CA pin carried by the join token THIS
// install staged, read from the STAGED COPY (agentTokenPath) rather than from
// the operator's source file.
//
// The copy is the right source for two reasons. It is the exact bytes the agent
// daemon reads, so the pin compared against the credential is the pin the join
// was actually attempted with. And it is a file this install wrote and owns:
// the operator's own token is theirs to delete the moment they like — they are
// told to, once the node is Ready — so reading it here would make the
// verification fail on a file that legitimately vanished mid-run. The SOURCE is
// still parsed, once, at staging time (stageJoinToken), which is where a
// malformed token is refused before anything is written.
//
// The pin comes from pkg/bootstrap's own parser; the hash is never recomputed
// here, because a second implementation of a pin is a second answer to "which
// cluster is this".
//
// It is FAIL-CLOSED, and deliberately not symmetric with the crash record's
// fail-open. An unreadable record costs a diagnostic; an unreadable token costs
// the comparison itself — without a pin, every self-consistent credential on
// the disk satisfies the check, including the one from the cluster this Mac
// used to belong to. That is the 2026-09-17 failure restored by a side door, so
// it is an error rather than a warning, and it names both files: the copy that
// could not be used and the source it was made from.
func stagedTokenPin(sys System, cfg Config) (string, error) {
	staged := cfg.agentTokenPath()
	raw, err := sys.ReadFile(staged)
	if err != nil {
		return "", fmt.Errorf("cannot verify this node's join: the staged join token %s could not be read back (%v), so there is nothing to compare the stored node credential's cluster against — a credential left by an earlier install would otherwise pass for a join that never happened (it is staged from %s on every install)", staged, err, cfg.TokenFile)
	}
	tok, err := bootstrap.ParseToken(string(raw))
	if err != nil {
		return "", fmt.Errorf("cannot verify this node's join: the staged join token %s is not a k3sm join token (%v), so there is no cluster-CA pin to compare the stored node credential against — it is staged from %s, so write the token `k3sm token create` printed on the server into that file and reinstall", staged, err, cfg.TokenFile)
	}
	return tok.CAHash, nil
}

// sysFS adapts the installer's privileged file seam to pkg/nodecred's read
// surface, so the credential is validated by that package rather than by a
// second reader written here.
//
// Stat is answered by READING, because System exposes no stat and its
// PathExists deliberately answers without opening the file — which is the wrong
// question for a credential: one that cannot be read has not been verified. The
// five artifacts are a few kilobytes between them and the poll is a quarter of a
// second, so reading twice costs nothing worth a seam change.
type sysFS struct{ sys System }

func (s sysFS) Stat(name string) (fs.FileInfo, error) {
	b, err := s.sys.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return statResult{name: filepath.Base(name), size: int64(len(b))}, nil
}

func (s sysFS) ReadFile(name string) ([]byte, error) { return s.sys.ReadFile(name) }

// statResult is the minimum fs.FileInfo pkg/nodecred's existence check consumes:
// it asks whether Stat succeeded, never what it said.
type statResult struct {
	name string
	size int64
}

func (s statResult) Name() string       { return s.name }
func (s statResult) Size() int64        { return s.size }
func (s statResult) Mode() fs.FileMode  { return 0 }
func (s statResult) ModTime() time.Time { return time.Time{} }
func (s statResult) IsDir() bool        { return false }
func (s statResult) Sys() any           { return nil }

// agentTerminalBackoffNote is how long `k3sm agent` waits between terminal start
// attempts, quoted in the message above so an operator reading it knows why the
// log repeats on a fixed interval. It is prose, not a control: the agent owns
// the value (cmd/k3sm's agentTerminalBackoff), and this is the installer saying
// what it observed rather than setting it.
const agentTerminalBackoffNote = "30s"

// awaitPath polls for path to appear, within the budget's running window. Its
// error text is a state clause, because verifyDaemons reports it alongside the
// pid clauses rather than wrapping it.
//
// absent is what the caller says the absence MEANS — the file is generic, the
// conclusion is not. It stays a parameter rather than a sentence baked in here
// because the conclusion belongs to whoever is waiting: the netd socket is the
// only such wait today (the agent join is no longer one — a credential file's
// presence is not proof of a join; see verifyAgentJoined), and the next one
// will not be about a socket.
func awaitPath(ctx context.Context, sys System, path, absent string, b restartBudget) error {
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
			return fmt.Errorf("%s ABSENT after %s (%s)", path, b.running, absent)
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
//
// The labels come from the caller, which derives them from the MANIFEST
// (longRunningDaemonLabels) rather than from a list typed here: the node daemon
// is io.k3sm.server on a control plane and io.k3sm.agent on a worker, and a
// hard-coded pair would report an agent install as a control plane that never
// came up, failing the install over a daemon it was never asked to lay down.
//
// It names the LONG-RUNNING daemons only. The datavol oneshot is deliberately
// absent: its healthy state is "ran and exited", which this function would report
// as DOWN and verifyDaemons would then fail the install over. `k3sm status` reads
// its last exit code, which is the question that actually has an answer.
func daemonStates(sys System, labels []string) ([]string, bool) {
	states := make([]string, 0, len(labels))
	healthy := true
	for _, label := range labels {
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

// longRunningDaemonLabels returns the labels of the manifest's long-running
// daemons, in manifest order: netd, then the role's node daemon. The oneshot
// (io.k3sm.datavol) is excluded, because it is designed to exit and "has a live
// pid" is therefore not its health.
func longRunningDaemonLabels(m []artifact) []string {
	out := make([]string, 0, 2)
	for _, a := range m {
		if a.kind == kindDaemon && !a.oneshot {
			out = append(out, a.label)
		}
	}
	return out
}
