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
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"time"

	"k3sm.io/k3sm/pkg/install"
)

// networkUsage is `k3sm network --help`.
const networkUsage = `Usage:
  sudo k3sm network lan on       answer on every network this Mac is on
  sudo k3sm network lan off      answer only on this Mac and the cluster mesh
  k3sm network lan status        show the setting (no root needed)

LAN access decides where this node's workload listeners answer: NodePort
Services, LoadBalancer Services and, on a server, the ingress host (80, 443).
With it off they bind 127.0.0.1 and this node's own address (its mesh address
once joined, its pod-range address on a single node), so nothing on your Wi-Fi
or Ethernet reaches them. With it on they bind every interface.

The change is applied live: the node daemon binds the new addresses first, then
closes the old ones. Connections already open finish; new connections from
the LAN are refused. If any listener cannot move, nothing changes and the
previous setting is restored. If the daemon does not apply it live, k3sm
restarts the node daemon in place instead (pods keep running) and says so.

With LAN access off, a LoadBalancer port below 1024 is not served (macOS lets
only root bind a specific address there), and the ingress answers on the
node's own address but not on 127.0.0.1.

Not covered: the apiserver (loopback, or the mesh address), the worker join
port (a new worker joins over the LAN, and every request needs the join
token) and the wireguard mesh port (it answers only cluster peers).

New installs start with LAN access off; an existing install keeps LAN access
on across an upgrade. 'sudo k3sm install --lan on|off' sets it at install.

Exit codes: 0 done; 1 failed (the previous setting is restored); 2 usage;
3 on/off not run as root.
`

// networkEnv is what the network verb touches, so a test can fake every
// seam: the install's files and launchd (Sys), the daemon signal, the
// in-place restart, and the clock.
type networkEnv struct {
	Sys        install.System
	RecordPath string
	DataRoot   string
	StopMarker string
	Geteuid    func() int
	// Signal sends SIGHUP to the labelled node daemon.
	Signal func(ctx context.Context, label string) error
	// Restart restarts the node daemon in place (k3sm restart: pods keep
	// running).
	Restart func(ctx context.Context) error
	// Wait bounds how long the verb waits for the daemon's applied report;
	// Poll is the interval it re-reads it at.
	Wait   time.Duration
	Poll   time.Duration
	Stdout io.Writer
	Stderr io.Writer
}

// defaultNetworkEnv is the production environment.
func defaultNetworkEnv(stdout, stderr io.Writer) networkEnv {
	sys := install.NewDarwinSystem()
	return networkEnv{
		Sys:        sys,
		RecordPath: install.DefaultNetworkRecordPath,
		DataRoot:   install.DefaultDataRoot,
		StopMarker: install.DefaultStopMarkerPath,
		Geteuid:    os.Geteuid,
		Signal:     launchctlHUP,
		Restart: func(ctx context.Context) error {
			return install.Restart(ctx, sys, lifecycleConfig(sys, stderr), install.ActorUser, "k3sm network lan")
		},
		Wait:   lanApplyTimeout + 10*time.Second,
		Poll:   200 * time.Millisecond,
		Stdout: stdout,
		Stderr: stderr,
	}
}

// launchctlHUP sends SIGHUP to a system-domain daemon through launchd.
func launchctlHUP(ctx context.Context, label string) error {
	out, err := exec.CommandContext(ctx, "launchctl", "kill", "HUP", "system/"+label).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl kill HUP system/%s: %w: %s", label, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// runNetwork is `k3sm network`.
func runNetwork(args []string, stdout, stderr io.Writer) int {
	return runNetworkEnv(context.Background(), args, defaultNetworkEnv(stdout, stderr))
}

// runNetworkEnv is runNetwork over env.
func runNetworkEnv(ctx context.Context, args []string, env networkEnv) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		fmt.Fprint(env.Stdout, networkUsage)
		return 0
	}
	if len(args) != 2 || args[0] != "lan" {
		fmt.Fprint(env.Stderr, networkUsage)
		return exitLifecycleUsage
	}
	switch args[1] {
	case "status":
		return networkLANStatus(env)
	case string(install.LANOn), string(install.LANOff):
		if env.Geteuid() != 0 {
			fmt.Fprintf(env.Stderr, "k3sm network lan %s must run as root: use 'sudo k3sm network lan %s' (nothing was done)\n", args[1], args[1])
			return exitNeedsRoot
		}
		if err := setNetworkLAN(ctx, env, install.LAN(args[1])); err != nil {
			fmt.Fprintf(env.Stderr, "k3sm network lan %s: %v\n", args[1], err)
			return exitLifecycleFailed
		}
		return 0
	}
	fmt.Fprint(env.Stderr, networkUsage)
	return exitLifecycleUsage
}

// installedNodeRole returns the role of the node daemon installed here, or
// install.ErrNotInstalled.
func installedNodeRole(sys install.System) (install.Role, error) {
	for _, role := range []install.Role{install.RoleServer, install.RoleAgent} {
		path, ok, err := install.RoleInstalled(sys, role)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", path, err)
		}
		if ok {
			return role, nil
		}
	}
	return "", install.ErrNotInstalled
}

// nodeLabel is the LaunchDaemon label of role's node daemon.
func nodeLabel(role install.Role) string {
	if role == install.RoleAgent {
		return install.AgentLabel
	}
	return install.ServerLabel
}

// lanSentence is the one-line description of a LAN state.
func lanSentence(lan install.LAN, role install.Role) string {
	what := "NodePorts and LoadBalancers"
	if role != install.RoleAgent {
		what = "NodePorts, LoadBalancers and the ingress"
	}
	if lan == install.LANOff {
		return fmt.Sprintf("LAN access is off: %s answer only on this Mac and the cluster mesh", what)
	}
	return fmt.Sprintf("LAN access is on: %s answer on every network this Mac is on", what)
}

// setNetworkLAN records want and has the node daemon apply it: write the
// record atomically, signal the daemon, wait for its report naming this
// write. A refused apply restores the previous record (and has the daemon
// apply that); a daemon that does not answer is restarted in place.
func setNetworkLAN(ctx context.Context, env networkEnv, want install.LAN) error {
	role, err := installedNodeRole(env.Sys)
	if err != nil {
		return fmt.Errorf("%w; nothing to switch (choose it at install with 'sudo k3sm install --lan %s')", err, want)
	}
	prev, prevPresent, prevErr := install.ReadNetworkRecord(env.Sys.ReadFile, env.RecordPath)
	rec := install.NewNetworkRecord(want, "k3sm network lan")
	if err := install.WriteNetworkRecord(env.Sys, env.RecordPath, rec); err != nil {
		return err
	}
	label := nodeLabel(role)
	if _, present, _ := install.ReadStopMarker(env.Sys, env.StopMarker); present {
		fmt.Fprintf(env.Stdout, "%s. Recorded; k3sm is stopped on this Mac, so it applies when you run 'sudo k3sm start'.\n", lanSentence(want, role))
		return nil
	}
	if _, err := env.Sys.LaunchctlServicePID(label); err != nil {
		fmt.Fprintf(env.Stdout, "%s. Recorded; the node daemon (%s) is not running, so it applies when it starts.\n", lanSentence(want, role), label)
		return nil
	}
	applied, how, err := applyNetworkRecord(ctx, env, role, label, rec.Serial)
	if err == nil && applied.Error == "" && applied.LAN == want {
		fmt.Fprintf(env.Stdout, "%s%s.\n", lanSentence(want, role), how)
		return nil
	}
	reason := err
	if reason == nil {
		reason = errors.New(applied.Error)
	}
	restoreNetworkRecord(ctx, env, role, label, prev, prevPresent, prevErr)
	return fmt.Errorf("the node daemon could not apply it: %w; %s", reason, restoredSentence(prev, prevPresent, prevErr))
}

// restoredSentence says what the failed change left in force.
func restoredSentence(prev install.NetworkRecord, present bool, readErr error) string {
	switch {
	case readErr != nil:
		return "the record it replaced was unusable, which the daemon reads as off, so off is recorded instead"
	case !present:
		return "no record is kept, so LAN access stays on"
	}
	return fmt.Sprintf("LAN access stays %s (restored)", prev.LAN)
}

// restoreNetworkRecord puts the previous setting back and has the daemon
// apply it, best effort: the previous value under a fresh serial, no record
// when there was none, or off when the previous record was unusable (what
// the daemon made of it).
func restoreNetworkRecord(ctx context.Context, env networkEnv, role install.Role, label string, prev install.NetworkRecord, present bool, readErr error) {
	kick := func() error { return env.Signal(ctx, label) }
	if present || readErr != nil {
		lan := prev.LAN
		if readErr != nil {
			lan = install.LANOff
		}
		back := install.NewNetworkRecord(lan, "k3sm network lan (restore)")
		if err := install.WriteNetworkRecord(env.Sys, env.RecordPath, back); err != nil {
			fmt.Fprintf(env.Stderr, "k3sm network lan: could not restore the previous setting in %s: %v\n", env.RecordPath, err)
			return
		}
		if _, ok, err := waitNetworkApplied(ctx, env, role, back.Serial, kick); err != nil || !ok {
			fmt.Fprintf(env.Stderr, "k3sm network lan: the previous setting is recorded again, but the node daemon did not confirm it (%v); check 'k3sm network lan status'\n", err)
		}
		return
	}
	if err := env.Sys.RemoveAll(env.RecordPath); err != nil {
		fmt.Fprintf(env.Stderr, "k3sm network lan: could not remove the record %s again: %v\n", env.RecordPath, err)
		return
	}
	_ = kick()
}

// applyNetworkRecord signals the daemon and waits for its report on serial;
// when no report arrives in time it restarts the node daemon in place and
// waits again. how is "" for a live apply, or the sentence saying it took a
// restart.
func applyNetworkRecord(ctx context.Context, env networkEnv, role install.Role, label, serial string) (install.NetworkApplied, string, error) {
	a, ok, err := waitNetworkApplied(ctx, env, role, serial, func() error { return env.Signal(ctx, label) })
	if err != nil || ok {
		return a, "", err
	}
	fmt.Fprintf(env.Stderr, "k3sm network lan: the node daemon did not apply the change live within %s; restarting it in place (pods keep running)\n", env.Wait)
	a, ok, err = waitNetworkApplied(ctx, env, role, serial, func() error { return env.Restart(ctx) })
	if err != nil {
		return a, "", err
	}
	if !ok {
		return a, "", fmt.Errorf("no report from the node daemon within %s of restarting it", env.Wait)
	}
	return a, " (applied by restarting the node daemon in place; pods kept running)", nil
}

// waitNetworkApplied runs kick, then polls the daemon's applied report until
// it names serial (ok) or env.Wait passes (not ok, no error). kick's own
// failure is the error.
func waitNetworkApplied(ctx context.Context, env networkEnv, role install.Role, serial string, kick func() error) (install.NetworkApplied, bool, error) {
	if err := kick(); err != nil {
		return install.NetworkApplied{}, false, err
	}
	path := install.NetworkAppliedPath(env.DataRoot, role)
	deadline := time.Now().Add(env.Wait)
	for {
		if data, err := env.Sys.ReadFile(path); err == nil {
			if a, err := install.DecodeNetworkApplied(data); err == nil && a.Serial == serial {
				return a, true, nil
			}
		}
		if time.Now().After(deadline) {
			return install.NetworkApplied{}, false, nil
		}
		select {
		case <-ctx.Done():
			return install.NetworkApplied{}, false, ctx.Err()
		case <-time.After(env.Poll):
		}
	}
}

// networkLANStatus is `k3sm network lan status`: the recorded setting, what
// it covers and what it does not, and (as root) what the daemon applied.
func networkLANStatus(env networkEnv) int {
	role, err := installedNodeRole(env.Sys)
	if err != nil {
		fmt.Fprintf(env.Stderr, "k3sm network lan status: %v\n", err)
		return exitLifecycleFailed
	}
	rec, present, err := install.ReadNetworkRecord(env.Sys.ReadFile, env.RecordPath)
	if err != nil {
		fmt.Fprintf(env.Stderr, "k3sm network lan status: %v\n", err)
		return exitLifecycleFailed
	}
	fmt.Fprintf(env.Stdout, "%s.\n", lanSentence(rec.LAN, role))
	if !present {
		fmt.Fprintln(env.Stdout, "No setting is recorded (an install from before the switch), which is on.")
	}
	fmt.Fprintf(env.Stdout, "Covers: %s\n", strings.Join(install.LANCovers(role), ", "))
	fmt.Fprintf(env.Stdout, "Always on: %s\n", strings.Join(install.LANAlwaysOn(role), ", "))
	data, err := env.Sys.ReadFile(install.NetworkAppliedPath(env.DataRoot, role))
	switch {
	case err == nil:
		a, derr := install.DecodeNetworkApplied(data)
		if derr != nil {
			break
		}
		if a.LAN != rec.LAN {
			fmt.Fprintf(env.Stdout, "The node daemon still serves LAN access %s; run 'sudo k3sm network lan %s' to apply the setting.\n", a.LAN, rec.LAN)
		}
		if a.Error != "" {
			fmt.Fprintf(env.Stdout, "Its last change was refused: %s\n", a.Error)
		}
	case errors.Is(err, fs.ErrPermission):
		// The daemon's report is in its own work dir; as a user the recorded
		// setting is the answer.
	}
	return 0
}
