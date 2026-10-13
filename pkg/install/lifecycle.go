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
	"fmt"
	"io/fs"
	"log/slog"
	"slices"
	"strings"
	"time"
	"unicode"
)

// The node lifecycle: `k3sm stop`, `k3sm start`, `k3sm restart`, and how
// install and uninstall treat a node the user stopped.
//
// A stop is the full stop (the k3s-killall analog): the daemons are disabled
// and booted out, every pod and vm helper is stopped, the mesh and the host
// network state are removed, and the plists stay so the node stays stopped
// across a reboot. It is recorded in a stop marker, written in two phases:
// `stopping` before anything is touched, and `stopped` only once nothing was
// left behind. A marker in either phase is the one fact every transition
// reads: install and restart never enable a label while it is there (unless
// asked to --start), start removes it, and uninstall clears it.

// DefaultStopMarkerPath is where the stop marker lives. /Library/Preferences is
// root-owned 0755, outside both the install root (which every install swaps)
// and the 0700 server data dir, and survives an uninstall's walk; the file is
// 0644 so an unprivileged `k3sm status` can read it. It is a var so tests can
// point it elsewhere.
var DefaultStopMarkerPath = "/Library/Preferences/io.k3sm.stop.json"

// StopPhase is the stop marker's phase.
type StopPhase string

const (
	// StopPhaseStopping is written before a stop touches anything, and stays
	// when a stop left something behind.
	StopPhaseStopping StopPhase = "stopping"
	// StopPhaseStopped is written only when a stop left nothing behind.
	StopPhaseStopped StopPhase = "stopped"
)

// The two actors a stop or start is attributed to.
const (
	ActorUser = "user"
	ActorAuto = "auto"
)

// stopMarkerVersion is the marker schema version.
const stopMarkerVersion = 1

// maxReasonLen bounds the reason a marker and a log line carry, in runes.
const maxReasonLen = 200

// StopMarker is the stop marker's content.
type StopMarker struct {
	Version int       `json:"version"`
	Phase   StopPhase `json:"phase"`
	Actor   string    `json:"actor"`
	Reason  string    `json:"reason"`
	At      time.Time `json:"at"`
}

// ErrNotInstalled is returned by Stop, Start and Restart on a Mac with no k3sm
// daemon plist.
var ErrNotInstalled = errors.New("k3sm is not installed on this Mac (no io.k3sm daemon plist)")

// markNodeTimeout bounds the cordon/uncordon call. A var so a test can shrink
// it.
var markNodeTimeout = 15 * time.Second

// removeMeshTimeout bounds the RemoveMesh call to netd. A var so a test can
// shrink it.
var removeMeshTimeout = 15 * time.Second

// StopTimeBound is the longest a server stop can take: the cordon bound, the
// node daemon's unload budget (its ExitTimeOut plus launchd's margin), the
// RemoveMesh bound, the pod SIGTERM grace, the vm helper wait, and netd's
// unload budget. A worker's is never longer.
func StopTimeBound() time.Duration {
	return markNodeTimeout + serverRestartBudget.unload + removeMeshTimeout + podGroupStopGrace + vmHostKillWait + netdRestartBudget.unload
}

// StopIncompleteError is a stop that left something behind. The stop marker
// stays `stopping`, and re-running the stop converges.
type StopIncompleteError struct {
	Left []LeftoverItem
}

// StopExitLeftoverBase is what a stop that left something behind adds its
// leftover bits to (see ExitCode). With six bits the code runs 33..95, clear
// of the shell's 126 (not executable), 127 (not found) and 128+N (signals).
const StopExitLeftoverBase = 32

// Error names every leftover and why.
func (e *StopIncompleteError) Error() string {
	parts := make([]string, len(e.Left))
	for i, item := range e.Left {
		parts[i] = fmt.Sprintf("%s (%v)", item.Kind, item.Err)
	}
	return "stop left behind: " + strings.Join(parts, "; ") + "; the node is marked stopping, re-run `sudo k3sm stop` to converge"
}

// Leftovers returns the leftover classes, each once, in the order met.
func (e *StopIncompleteError) Leftovers() []Leftover {
	var out []Leftover
	for _, item := range e.Left {
		if !slices.Contains(out, item.Kind) {
			out = append(out, item.Kind)
		}
	}
	return out
}

// ExitCode is StopExitLeftoverBase plus one bit per leftover class: 1 the
// node daemon, 2 workloads (pods, vm helpers, control-plane processes), 4 the
// mesh, 8 host network state (pf anchor, lo0 or interconnect aliases), 16
// netd, 32 the stop marker. The result is always in 33..95.
func (e *StopIncompleteError) ExitCode() int {
	mask := 0
	for _, item := range e.Left {
		mask |= item.Kind.exitBit()
	}
	return StopExitLeftoverBase + mask
}

// lifecycleIdentity validates the actor and cleans the reason: control
// characters become spaces and the text is cut to maxReasonLen runes, so a
// reason can never forge a log line or bloat the marker.
func lifecycleIdentity(actor, reason string) (string, string, error) {
	if actor != ActorUser && actor != ActorAuto {
		return "", "", fmt.Errorf("actor %q is not %q or %q", actor, ActorUser, ActorAuto)
	}
	clean := []rune(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, strings.TrimSpace(reason)))
	if len(clean) > maxReasonLen {
		clean = clean[:maxReasonLen]
	}
	return actor, string(clean), nil
}

// readStopMarker reads the stop marker. present is false only when there is
// no marker at all; a marker that exists but cannot be read or parsed is
// present with an error, because every caller treats an unreadable marker as a
// stopped node (staying stopped is the safe side of not knowing).
func readStopMarker(sys System, cfg Config) (StopMarker, bool, error) {
	raw, err := sys.ReadStopMarker(cfg.StopMarker)
	if errors.Is(err, fs.ErrNotExist) {
		return StopMarker{}, false, nil
	}
	if err != nil {
		return StopMarker{}, true, fmt.Errorf("read the stop marker %s: %w", cfg.StopMarker, err)
	}
	var m StopMarker
	if err := json.Unmarshal(raw, &m); err != nil {
		return StopMarker{}, true, fmt.Errorf("parse the stop marker %s: %w", cfg.StopMarker, err)
	}
	if m.Phase != StopPhaseStopping && m.Phase != StopPhaseStopped {
		return m, true, fmt.Errorf("the stop marker %s has unknown phase %q", cfg.StopMarker, m.Phase)
	}
	return m, true, nil
}

// stopAttrs are the log attributes that say who stopped the node, why, and
// how long ago, for every path that leaves a stopped node stopped.
func stopAttrs(m StopMarker, cfg Config) []any {
	age := "unknown"
	if !m.At.IsZero() {
		age = time.Since(m.At).Round(time.Second).String()
	}
	return []any{"stopped-by", m.Actor, "reason", m.Reason, "phase", m.Phase, "stopped-ago", age, "marker", cfg.StopMarker}
}

// writeStopMarker writes m (with the schema version) to the marker path.
func writeStopMarker(sys System, cfg Config, m StopMarker) error {
	m.Version = stopMarkerVersion
	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("encode the stop marker: %w", err)
	}
	return sys.WriteStopMarker(cfg.StopMarker, append(data, '\n'))
}

// lifecycleLog writes one lifecycle line to slog and to the unified log.
func lifecycleLog(ctx context.Context, sys System, cfg Config, level slog.Level, msg string, attrs ...any) {
	cfg.Logger.Log(ctx, level, msg, attrs...)
	var b strings.Builder
	b.WriteString(msg)
	for i := 0; i+1 < len(attrs); i += 2 {
		fmt.Fprintf(&b, " %v=%q", attrs[i], fmt.Sprint(attrs[i+1]))
	}
	sys.OSLog(level, b.String())
}

// installedDaemons is what a lifecycle verb acts on: the node daemon labels
// whose plist is on this Mac (normally exactly one), whether netd's is, and
// the role the node daemon implies.
type installedDaemons struct {
	node []string
	netd bool
	role Role
}

// labels returns every installed label, netd first (bootstrap order).
func (d installedDaemons) labels() []string {
	var out []string
	if d.netd {
		out = append(out, NetdLabel)
	}
	return append(out, d.node...)
}

// readInstalledDaemons probes the daemon plists on disk. No plist at all is
// ErrNotInstalled; an unreadable one is an error, because it is not evidence
// that the daemon is absent.
func readInstalledDaemons(sys System, cfg Config) (installedDaemons, error) {
	var d installedDaemons
	d.role = RoleServer
	for _, role := range []Role{RoleServer, RoleAgent} {
		path, ok, err := roleInstalled(sys, cfg, role)
		if err != nil {
			return d, fmt.Errorf("read %s: %w", path, err)
		}
		if ok {
			d.node = append(d.node, daemonLabel(role))
			d.role = role
		}
	}
	switch _, err := sys.ReadFile(cfg.plistPath(NetdLabel)); {
	case err == nil:
		d.netd = true
	case !errors.Is(err, fs.ErrNotExist):
		return d, fmt.Errorf("read %s: %w", cfg.plistPath(NetdLabel), err)
	}
	if len(d.node) == 0 && !d.netd {
		return d, ErrNotInstalled
	}
	return d, nil
}

// loaded reports whether launchd has label in the system domain.
func loaded(sys System, label string) bool {
	_, err := sys.LaunchctlServicePID(label)
	return err == nil
}

// markNode runs cfg.MarkNode, bounded and best effort.
func markNode(ctx context.Context, cfg Config, stopped bool, actor, reason string) {
	if cfg.MarkNode == nil {
		return
	}
	what := "uncordon this node and clear k3sm.io/stopped-by-user"
	if stopped {
		what = "cordon this node and annotate it k3sm.io/stopped-by-user"
	}
	ctx, cancel := context.WithTimeout(ctx, markNodeTimeout)
	defer cancel()
	if err := cfg.MarkNode(ctx, stopped, actor, reason); err != nil {
		cfg.Logger.Warn("could not "+what+" (best effort; the cluster may be unreachable)", "err", err, "bound", markNodeTimeout)
		return
	}
	cfg.Logger.Info("did " + what)
}

// joinedWorkersTimeout bounds the joined-worker count a server stop makes. A
// var so a test can shrink it.
var joinedWorkersTimeout = 5 * time.Second

// warnJoinedWorkers runs cfg.JoinedWorkers, bounded and best effort, and warns
// when the server being stopped has workers joined to it.
func warnJoinedWorkers(ctx context.Context, cfg Config) {
	if cfg.JoinedWorkers == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, joinedWorkersTimeout)
	defer cancel()
	n, err := cfg.JoinedWorkers(ctx)
	switch {
	case err != nil:
		cfg.Logger.Warn("could not count the workers joined to this server; if any are, stopping it cuts them off from the control plane until `sudo k3sm start`", "err", err)
	case n > 0:
		cfg.Logger.Warn(fmt.Sprintf("stopping this server halts the cluster's control plane: %d joined worker(s) lose it until `sudo k3sm start`", n), "workers", n)
	}
}

// stopDaemon disables label, confirms the disable by reading it back, boots
// it out and waits for launchd to unload it. Every failure is a leftover of
// kind; a failed disable does not stop the bootout (the daemon still goes down
// now, it would only come back at boot).
func stopDaemon(ctx context.Context, sys System, label string, kind Leftover, logger *slog.Logger) []LeftoverItem {
	var left []LeftoverItem
	if err := sys.LaunchctlDisable(label); err != nil {
		left = append(left, LeftoverItem{Kind: kind, Err: fmt.Errorf("disable %s (it would start again at boot): %w", label, err)})
	} else if disabled, err := sys.LaunchctlDisabled(label); err != nil {
		left = append(left, LeftoverItem{Kind: kind, Err: fmt.Errorf("read back the disable of %s: %w", label, err)})
	} else if !disabled {
		left = append(left, LeftoverItem{Kind: kind, Err: fmt.Errorf("launchctl print-disabled does not list %s as disabled after the disable (it would start again at boot)", label)})
	}
	if err := sys.LaunchctlBootout(label); err != nil {
		return append(left, LeftoverItem{Kind: kind, Err: fmt.Errorf("bootout %s: %w", label, err)})
	}
	if err := awaitUnloaded(ctx, sys, label, restartBudgetFor(label)); err != nil {
		return append(left, LeftoverItem{Kind: kind, Err: err})
	}
	logger.Info("daemon stopped and disabled", "label", label)
	return left
}

// removeMesh asks netd to tear the wireguard mesh down, while it still
// serves. A netd that launchd no longer has loaded took the mesh with it (the
// utun lives only in the netd process), so there is nothing to ask; one that
// is loaded and does not answer is a leftover, and the stop goes on.
func removeMesh(ctx context.Context, sys System, cfg Config, netdInstalled bool) []LeftoverItem {
	if !netdInstalled {
		return nil
	}
	if !loaded(sys, NetdLabel) {
		cfg.Logger.Info("netd is not loaded, so no mesh is up (its utun lives only in the netd process)")
		return nil
	}
	if cfg.RemoveMesh == nil {
		return []LeftoverItem{{Kind: LeftoverMesh, Err: errors.New("no RemoveMesh caller is configured")}}
	}
	ctx, cancel := context.WithTimeout(ctx, removeMeshTimeout)
	defer cancel()
	if err := cfg.RemoveMesh(ctx); err != nil {
		cfg.Logger.Warn("netd did not remove the mesh; the stop continues", "err", err)
		return []LeftoverItem{{Kind: LeftoverMesh, Err: fmt.Errorf("netd RemoveMesh: %w", err)}}
	}
	cfg.Logger.Info("netd removed the mesh")
	return nil
}

// Stop is `k3sm stop`: the full stop, in this order.
//
//  0. On a server, best effort and bounded: count the joined workers and warn
//     that stopping the control plane cuts them off. Never a prompt (the app
//     and the auto actor are unattended).
//  1. The stop marker, phase stopping (actor, reason, time). If it cannot be
//     written nothing else is done.
//  2. Best effort, bounded: cordon the Node and annotate it
//     k3sm.io/stopped-by-user. This goes before the node daemon, because on a
//     server the node daemon IS the apiserver.
//  3. The node daemon: disable (read back), bootout, await unloaded.
//  4. The workload half of the shared teardown (teardownWorkloads): pods
//     (SIGTERM, 10 s, SIGKILL), vm helpers, control-plane orphans, while the
//     mesh is still up.
//  5. RemoveMesh to netd, while netd still serves.
//  6. The network half of the shared teardown (flushHostNetwork): pf anchor,
//     lo0 aliases (scope from the installed netd plist), interconnect
//     aliases. The node identity file is kept.
//  7. netd: disable (read back), bootout, await unloaded.
//  8. The marker, phase stopped, only when nothing was left behind.
//
// The plists stay, so the node stays stopped across a reboot. Every step is
// idempotent: a rerun over a `stopping` marker converges, and a rerun over a
// `stopped` marker with every daemon unloaded does nothing and succeeds. A
// stop that left anything behind returns a *StopIncompleteError naming it.
func Stop(ctx context.Context, sys System, cfg Config, actor, reason string) error {
	cfg = cfg.withDefaults()
	actor, reason, err := lifecycleIdentity(actor, reason)
	if err != nil {
		return fmt.Errorf("stop: %w", err)
	}
	d, err := readInstalledDaemons(sys, cfg)
	if err != nil {
		return fmt.Errorf("stop: %w", err)
	}
	cfg.Role = d.role
	prev, present, perr := readStopMarker(sys, cfg)
	if perr != nil {
		cfg.Logger.Warn("the stop marker is unreadable; this stop rewrites it", "err", perr)
	}
	if present && perr == nil && prev.Phase == StopPhaseStopped && !slices.ContainsFunc(d.labels(), func(l string) bool { return loaded(sys, l) }) {
		lifecycleLog(ctx, sys, cfg, slog.LevelInfo, "k3sm stop: already stopped, nothing to do",
			"actor", actor, "reason", reason, "result", "already-stopped", "stopped-by", prev.Actor, "stopped-at", prev.At.UTC().Format(time.RFC3339))
		return nil
	}
	// 0.
	if d.role == RoleServer {
		warnJoinedWorkers(ctx, cfg)
	}
	at := time.Now().UTC()
	lifecycleLog(ctx, sys, cfg, slog.LevelInfo, "k3sm stop: starting", "actor", actor, "reason", reason, "phase", StopPhaseStopping)

	// 1.
	if err := writeStopMarker(sys, cfg, StopMarker{Phase: StopPhaseStopping, Actor: actor, Reason: reason, At: at}); err != nil {
		lifecycleLog(ctx, sys, cfg, slog.LevelError, "k3sm stop: refused, nothing was changed", "actor", actor, "reason", reason, "result", "refused", "err", err)
		return fmt.Errorf("stop: write the stop marker (nothing was changed): %w", err)
	}
	// 2.
	markNode(ctx, cfg, true, actor, reason)
	// 3.
	var left []LeftoverItem
	for _, label := range d.node {
		left = append(left, stopDaemon(ctx, sys, label, LeftoverNodeDaemon, cfg.Logger)...)
	}
	// 4.
	left = append(left, teardownWorkloads(ctx, sys, cfg)...)
	// 5.
	left = append(left, removeMesh(ctx, sys, cfg, d.netd)...)
	// 6.
	hostLeft, _ := flushHostNetwork(sys, cfg, recordedFlushPrefixes(sys, cfg), interconnectNodeIndex(sys))
	left = append(left, hostLeft...)
	// 7.
	if d.netd {
		left = append(left, stopDaemon(ctx, sys, NetdLabel, LeftoverNetd, cfg.Logger)...)
	}
	// 8.
	if len(left) == 0 {
		if err := writeStopMarker(sys, cfg, StopMarker{Phase: StopPhaseStopped, Actor: actor, Reason: reason, At: at}); err != nil {
			left = append(left, LeftoverItem{Kind: LeftoverMarker, Err: fmt.Errorf("write the stopped marker: %w", err)})
		}
	}
	if len(left) > 0 {
		serr := &StopIncompleteError{Left: left}
		lifecycleLog(ctx, sys, cfg, slog.LevelError, "k3sm stop: incomplete", "actor", actor, "reason", reason, "result", "incomplete", "leftovers", leftoverNames(serr.Leftovers()), "err", serr)
		return serr
	}
	lifecycleLog(ctx, sys, cfg, slog.LevelInfo, "k3sm stop: stopped", "actor", actor, "reason", reason, "result", "stopped", "phase", StopPhaseStopped)
	return nil
}

// leftoverNames joins leftover classes for a log line.
func leftoverNames(l []Leftover) string {
	s := make([]string, len(l))
	for i, k := range l {
		s[i] = string(k)
	}
	return strings.Join(s, ",")
}

// parsePrintDisabled reads label's override out of `launchctl print-disabled
// system` output. launchctl has printed the value as "disabled"/"enabled" and,
// on older releases, as "true"/"false" (true meaning disabled); both are read,
// so the answer comes from what this host prints, never from its OS version. A
// label with no line has no override and is not disabled. Output with no
// "disabled services" block, or a value of any other shape, is an error: the
// read-back must not guess.
func parsePrintDisabled(out, label string) (bool, error) {
	if !strings.Contains(out, "disabled services") {
		return false, fmt.Errorf("launchctl print-disabled output has no disabled services block: %q", firstLine(out))
	}
	key := "\"" + label + "\""
	for _, line := range strings.Split(out, "\n") {
		name, value, ok := strings.Cut(strings.TrimSpace(line), "=>")
		if !ok || strings.TrimSpace(name) != key {
			continue
		}
		switch strings.TrimSpace(value) {
		case "disabled", "true":
			return true, nil
		case "enabled", "false":
			return false, nil
		default:
			return false, fmt.Errorf("launchctl print-disabled lists %s with an unrecognised value %q", label, strings.TrimSpace(value))
		}
	}
	return false, nil
}

// firstLine is s up to its first newline, for an error message.
func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}
