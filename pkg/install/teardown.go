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
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"k3sm.io/darwin-net/pkg/podnet"
	"k3sm.io/k3sm/pkg/netdsvc"
	"k3sm.io/k3sm/pkg/updater/layout"
	"k3sm.io/runtimed/pkg/sandbox"
)

// The post-bootout teardown, shared by `k3sm uninstall` and `k3sm stop`.
//
// Once the node daemon is booted out, the things still holding k3sm state on
// the Mac are the same for both verbs: the pod process groups and the
// k3sm-vmhost helpers of vm pods (a daemon restart re-attaches to both, so its
// shutdown leaves them running on purpose), control-plane children that
// outlived the server, and the durable kernel state no daemon removes on the
// way out (the pf anchor an older release loaded, the lo0 aliases, the
// interconnect aliases on bridge0). One function tears all of it down, in one
// order, so the two verbs can never drift apart.
//
// What it deliberately does NOT do: walk the artifact manifest (plists, the
// install root, the identity file are uninstall's alone), and talk to netd
// (stop's RemoveMesh runs before this, while netd still serves).

// VMHostRecord is one k3sm-vmhost helper the runtime recorded: its process
// group and the group leader's kernel start time, the exact-instance identity a
// signal is matched against, and the grace the helper was spawned with. It
// mirrors runtimed's vm reap record (sandbox.vmProcRecord), whose JSON names
// these are; the record is runtimed's, and this is a narrow reader of it.
//
// RunDir is the helper's private run dir, where its control socket
// (sandbox.VMHostControlSocketName) lives: the teardown asks the helper there to
// shorten a grace its bound would cut (shortenVMHelper).
//
// Schema, HelperCDHash, HelperProtocol, RuntimeVersion and BootSession are what
// a restarted daemon checks before it adopts the helper. The teardown does not
// adopt, so it only logs them beside the stop; Schema 0 marks a record an
// earlier runtime wrote, which carries no grace, and its helper is given the
// helper's own default (sandbox.VMHelperStopWait of 0).
type VMHostRecord struct {
	Schema         int    `json:"schema,omitempty"`
	PodID          string `json:"podId"`
	Pgid           int    `json:"pgid"`
	StartUnixNano  int64  `json:"startUnixNano"`
	StopGraceNanos int64  `json:"stopGraceNanos,omitempty"`
	RunDir         string `json:"runDir,omitempty"`
	HelperCDHash   string `json:"helperCdhash,omitempty"`
	HelperProtocol int    `json:"helperProtocol,omitempty"`
	RuntimeVersion string `json:"runtimeVersion,omitempty"`
	BootSession    string `json:"bootSession,omitempty"`
}

// vmHelperStopBound bounds the graceful leg of the vm helper stop: every helper
// is sent SIGTERM at once, and the slowest is waited for at most this long
// before it is sent SIGKILL. It is runtimed's own bound for a caller that ends
// every guest on the node (sandbox.VMStopAllBound), so the teardown honours a
// pod grace exactly as far as the runtime itself would.
const vmHelperStopBound = sandbox.VMStopAllBound

// vmHostKillWait is how long the teardown waits for the vm helpers it killed to
// leave the process table. SIGKILL cannot be caught, so this only covers the
// kernel finishing the exit of a process holding a live virtual machine.
var vmHostKillWait = 5 * time.Second

// flushPrefixes is what the lo0 flush removes, and where that came from. A nil
// prefixes with a non-nil err means the source could not be read, and the
// flush is skipped rather than guessed.
type flushPrefixes struct {
	prefixes []netip.Prefix
	source   string
	err      error
}

// recordedFlushPrefixes returns the lo0 ranges k3sm aliases on this Mac: the
// pinned cluster pod aggregate and the Service CIDR the installed netd runs
// with, read from the --service-cidr of the installed netd plist. The plist is
// the record: it is what install rendered from the operator's --service-cidr,
// what launchd hands netd, and it stays on disk across a stop. A missing or
// unreadable plist, or one with no parsable --service-cidr, is an error and no
// prefixes: the caller skips the flush rather than flush a default range the
// node may never have used.
func recordedFlushPrefixes(sys System, cfg Config) flushPrefixes {
	path := cfg.plistPath(NetdLabel)
	fp := flushPrefixes{source: path}
	raw, err := sys.ReadFile(path)
	if err != nil {
		fp.err = fmt.Errorf("read the installed netd plist %s: %w", path, err)
		return fp
	}
	args, err := parseProgramArguments(raw)
	if err != nil {
		fp.err = fmt.Errorf("parse the installed netd plist %s: %w", path, err)
		return fp
	}
	svc, err := netip.ParsePrefix(flagValue(args, "service-cidr"))
	if err != nil {
		fp.err = fmt.Errorf("the installed netd plist %s carries no usable --service-cidr: %w", path, err)
		return fp
	}
	fp.prefixes = []netip.Prefix{podnet.ClusterPodCIDR, svc.Masked()}
	return fp
}

// configFlushPrefixes is the lo0 flush scope taken from cfg alone, for the one
// caller that may not skip the flush: uninstall on a Mac whose netd plist is
// already gone (a partial earlier uninstall).
func configFlushPrefixes(cfg Config) flushPrefixes {
	fp := flushPrefixes{prefixes: []netip.Prefix{podnet.ClusterPodCIDR}, source: "the uninstall configuration (no installed netd plist)"}
	if svc, err := netip.ParsePrefix(cfg.ServiceCIDR); err == nil {
		fp.prefixes = append(fp.prefixes, svc)
	}
	return fp
}

// Leftover names one class of state a stop could not remove. The values are
// the words the CLI prints and the exit code is built from.
type Leftover string

// The leftover classes, in the order the stop sequence meets them.
const (
	LeftoverNodeDaemon   Leftover = "node-daemon"
	LeftoverMesh         Leftover = "mesh"
	LeftoverPods         Leftover = "pods"
	LeftoverVMHelpers    Leftover = "vm-helpers"
	LeftoverControlPlane Leftover = "control-plane-processes"
	LeftoverPFAnchor     Leftover = "pf-anchor"
	LeftoverLo0          Leftover = "lo0-aliases"
	LeftoverInterconnect Leftover = "interconnect-aliases"
	LeftoverNetd         Leftover = "netd"
	LeftoverMarker       Leftover = "stop-marker"
)

// exitBit is the bit a leftover class sets in a stop's exit code (see
// StopIncompleteError.ExitCode). Related classes share a bit so the code stays
// inside one byte; the error text names each class.
func (l Leftover) exitBit() int {
	switch l {
	case LeftoverNodeDaemon:
		return 1
	case LeftoverPods, LeftoverVMHelpers, LeftoverControlPlane:
		return 2
	case LeftoverMesh:
		return 4
	case LeftoverPFAnchor, LeftoverLo0, LeftoverInterconnect:
		return 8
	case LeftoverNetd:
		return 16
	default:
		return 32
	}
}

// LeftoverItem is one thing a teardown step left behind, and why.
type LeftoverItem struct {
	Kind Leftover
	Err  error
}

// tailResult is what the shared teardown reports: what each failed step left
// behind, in step order, and whether the interconnect sweep completed (the
// condition uninstall removes the node identity file on).
type tailResult struct {
	left              []LeftoverItem
	interconnectSwept bool
}

// teardownWorkloads stops everything still running k3sm workloads once the
// node daemon is gone: the recorded pod process groups, the k3sm-vmhost helpers
// of vm pods, and control-plane children that outlived the server daemon.
func teardownWorkloads(ctx context.Context, sys System, cfg Config) []LeftoverItem {
	var left []LeftoverItem
	add := func(kind Leftover, err error) {
		if err != nil {
			left = append(left, LeftoverItem{Kind: kind, Err: err})
		}
	}
	// The pod process groups, by the runtime's recorded identity (podgroups.go).
	add(LeftoverPods, teardownPodGroups(ctx, sys, cfg))
	// The vm helpers, on the same contract as the pod groups: a daemon restart
	// leaves them running, and this stop ends them, SIGTERM first so each guest
	// gets the grace its pod was spawned with (stopVMHelpers).
	add(LeftoverVMHelpers, stopVMHelpers(ctx, sys, cfg))
	// Backstop: reap any control-plane children that outlived the booted-out
	// server daemon (a Stop() cut short by launchd's SIGKILL, or a crash). They
	// run out of <DataRoot>/server/bin and would otherwise hold the apiserver/
	// kine ports + the SQLite DB, breaking the next start.
	add(LeftoverControlPlane, sys.ReapOrphans(filepath.Join(cfg.serverWorkDir(), "bin")))
	return left
}

// flushHostNetwork removes the durable kernel state no daemon removes on the
// way out: the pf anchor, the lo0 aliases inside fp, and the interconnect
// aliases netd's ledger owns. icIndex is this node's cluster index (see
// interconnectNodeIndex). It reports whether the interconnect sweep completed.
func flushHostNetwork(sys System, cfg Config, fp flushPrefixes, icIndex int) ([]LeftoverItem, bool) {
	var left []LeftoverItem
	add := func(kind Leftover, err error) {
		if err != nil {
			left = append(left, LeftoverItem{Kind: kind, Err: err})
		}
	}
	// Backstop: flush the pf anchor an older release loaded the mesh MSS clamp
	// into. Nothing loads it now, so this only clears what an older release left
	// behind, which would outlive netd scoped to a utun that is gone.
	add(LeftoverPFAnchor, sys.FlushMeshPFAnchor())
	// Backstop: flush the k3sm-owned lo0 aliases. They are durable kernel state
	// no daemon removes on the way out — netd tracks per-connection alias caps
	// (not cleanup), the server's pod teardown misses anything a failed run
	// leaked, the Service VIP aliases (API + DNS VIPs) live for the daemon's
	// lifetime, and the node's own mesh-egress .1 is outside the pod
	// stale-sweep range. Scope: the pinned cluster pod aggregate + the Service
	// CIDR — exactly the address space k3sm ever aliases (never the host's own
	// addresses). This runs as root, so it is direct ifconfig, no helper.
	if fp.err != nil {
		cfg.Logger.Warn("lo0 aliases not flushed: the range k3sm aliased on this Mac is not known, and a guessed range is never flushed", "source", fp.source, "err", fp.err)
		add(LeftoverLo0, fp.err)
	} else {
		add(LeftoverLo0, sys.FlushLo0Aliases(fp.prefixes))
	}
	// Backstop: the interconnect aliases on bridge0 that netd's ledger owns, and
	// the ledger itself. Like the lo0 aliases they are durable kernel state no
	// daemon removes on the way out; unlike them they are swept by OWNERSHIP,
	// re-derived from this node's cluster index, not by range, so a
	// 169.254.0.0/24 address that is not this node's derived alias stays.
	err := sys.FlushInterconnectAliases(netdsvc.InterconnectStatePath(MeshKeyDir), icIndex, cfg.Logger)
	add(LeftoverInterconnect, err)
	return left, err == nil
}

// teardownTail is the whole shared post-bootout teardown: the workloads, then
// the host network. Each step runs whatever the previous one reported, and
// every failure is returned as the leftover it is.
func teardownTail(ctx context.Context, sys System, cfg Config, fp flushPrefixes, icIndex int) tailResult {
	left := teardownWorkloads(ctx, sys, cfg)
	hostLeft, swept := flushHostNetwork(sys, cfg, fp, icIndex)
	return tailResult{left: append(left, hostLeft...), interconnectSwept: swept}
}

// stopVMHelpers stops every k3sm-vmhost helper the runtime recorded that is
// provably still that helper: first, to each whose grace the bound cuts, a
// shorten request (shortenVMHelpers), all at once; then SIGTERM to each, a
// wait of sandbox.VMHelperStopWait(its recorded grace) capped at
// vmHelperStopBound, measured from the start of the stop,
// SIGKILL to each one still running at the end of its own wait, and then
// vmHostKillWait for the killed to leave. It is the pod groups' stop
// (teardownPodGroups) for vm pods: a SIGTERM to a helper is its guest's
// graceful stop, and the helper SIGTERMs the guest's containers, waits out the
// grace and powers the machine off itself, so the SIGKILL here is only the
// backstop for a helper that does not.
//
// A record authorizes a root signal to a process group, so it is believed only
// as far as it can be checked:
//
//   - the store directory and the record file must be trusted: not a symlink,
//     owned by root or the service user, and not group- or world-writable
//     (readVMHostRecords). An untrusted record is never read as an order;
//   - the group's leader (pid == pgid) must be alive with exactly the recorded
//     start time, runtimed's own exact-instance rule (sandbox.vmReapDecision).
//     A leader that is gone, or a recycled pgid with a different immutable
//     start, means nothing of ours is there: skipped, and not a leftover;
//   - the leader must be the installed k3sm-vmhost (its executable path) and
//     run as the service user. A start-time match on any other process is a
//     forged or corrupted record: never signalled, and reported. A helper
//     running from a version directory that is neither current nor previous
//     is stopped while that directory is there, since the tree keeps a version
//     a running pod uses; a helper of the service user whose version directory
//     is gone runs from a version the tree no longer retains, is never
//     signalled, and is reported as the leftover it is, by pid, path and
//     version.
//
// Nothing is ever matched by process name. The helpers are stopped together,
// so the stage costs the longest wait, not their sum.
//
// It returns an error naming every record it could not act on or rule out,
// and every helper still alive after its SIGKILL and vmHostKillWait.
func stopVMHelpers(ctx context.Context, sys System, cfg Config) error {
	svcUID, err := sys.ServiceUID(cfg.ServiceUser)
	if err != nil {
		return fmt.Errorf("look up the service user %s, which vm helpers run as: %w", cfg.ServiceUser, err)
	}
	store, err := sys.ReadVMHostRecords(cfg.DataRoot, []uint32{0, svcUID})
	if err != nil {
		cfg.Logger.Warn("could not read the vm helper records; a k3sm-vmhost process may survive", "data-root", cfg.DataRoot, "err", err)
		return fmt.Errorf("read the vm helper records: %w", err)
	}
	var errs error
	for _, name := range store.Rejected {
		cfg.Logger.Warn("untrusted vm helper record skipped, never acted on", "record", name)
		errs = errors.Join(errs, fmt.Errorf("untrusted vm helper record %s (not acted on)", name))
	}
	verify := func(rec VMHostRecord) (bool, error) {
		return verifyVMHelper(sys, cfg, rec, svcUID)
	}
	var helpers []VMHostRecord
	for _, rec := range store.Records {
		if rec.Pgid <= 1 || rec.StartUnixNano == 0 {
			continue
		}
		ok, verr := verify(rec)
		errs = errors.Join(errs, verr)
		if ok {
			helpers = append(helpers, rec)
		}
	}
	// Every wait below is measured from start, the one clock the SIGKILLs run
	// on, and the shorten requests go out first, together, each with the time
	// left until the shared deadline (shortenVMHelpers).
	start := sys.Now()
	shortenVMHelpers(ctx, sys, cfg, helpers, start.Add(vmHelperStopBound))
	var stopping []vmHelperStop
	for _, rec := range helpers {
		// Proven again: the requests above took time, and every signal is
		// preceded by a fresh proof the group is still the helper.
		ok, verr := verify(rec)
		errs = errors.Join(errs, verr)
		if !ok {
			continue
		}
		wait := vmHelperWait(rec)
		cfg.Logger.Info("stopping vm pod helper (SIGTERM)", "pod", rec.PodID, "pgid", rec.Pgid,
			"wait", wait, "record_schema", rec.Schema, "helper_protocol", rec.HelperProtocol,
			"runtime_version", rec.RuntimeVersion, "boot_session", rec.BootSession)
		if serr := sys.SignalProcessGroup(rec.Pgid, syscall.SIGTERM); serr != nil {
			cfg.Logger.Warn("could not signal vm helper group", "pod", rec.PodID, "pgid", rec.Pgid, "signal", "SIGTERM", "err", serr)
			errs = errors.Join(errs, fmt.Errorf("signal vm helper group %d: %w", rec.Pgid, serr))
			continue
		}
		stopping = append(stopping, vmHelperStop{rec: rec, wait: wait})
	}
	killed, kerr := awaitVMHelpers(ctx, sys, cfg, stopping, verify, sys.Now().Sub(start))
	errs = errors.Join(errs, kerr)
	if len(killed) == 0 {
		return errs
	}
	if left := sys.WaitProcessGroupsGone(ctx, killed, vmHostKillWait); len(left) > 0 {
		strs := make([]string, len(left))
		for i, pgid := range left {
			strs[i] = strconv.Itoa(pgid)
		}
		errs = errors.Join(errs, fmt.Errorf("k3sm-vmhost process groups still alive %s after SIGKILL: %s", vmHostKillWait, strings.Join(strs, ",")))
	}
	return errs
}

// vmHostShortener is the System seam the vm helper stop's shorten request
// goes through.
type vmHostShortener interface {
	// ShortenVMHostStop asks the k3sm-vmhost helper serving the control
	// socket at socket, which must be the process pid, to start its stop with
	// the grace bound leaves it (sandbox.ShortenVMHostStop). A helper that
	// predates the request reports sandbox.VMHostShortenUnsupported.
	ShortenVMHostStop(ctx context.Context, socket string, pid int, bound time.Duration) (sandbox.VMHostShortenOutcome, error)
}

// shortenVMHelpers sends the shorten request (shortenVMHelper) to every helper
// whose recorded grace does not fit vmHelperStopBound, concurrently, one
// goroutine per helper, and returns once every request has been answered or
// failed. It runs before any SIGTERM, so one slow helper delays no other
// helper's request, and no request delays the stop by more than the slowest
// one (each is bounded by the client's own timeout). Each request carries the
// time left until deadline, the shared SIGKILL deadline, measured when it is
// sent, not the constant bound.
func shortenVMHelpers(ctx context.Context, sys System, cfg Config, helpers []VMHostRecord, deadline time.Time) {
	var (
		wg sync.WaitGroup
		mu sync.Mutex // serialises the cut lines on cfg.Out and the logger
	)
	for _, rec := range helpers {
		if vmHelperWait(rec) >= sandbox.VMHelperStopWait(time.Duration(rec.StopGraceNanos)) {
			continue
		}
		wg.Add(1)
		go func(rec VMHostRecord) {
			defer wg.Done()
			report := shortenVMHelper(ctx, sys, rec, deadline.Sub(sys.Now()))
			mu.Lock()
			report(cfg)
			mu.Unlock()
		}(rec)
	}
	wg.Wait()
}

// shortenVMHelper runs before the SIGTERM of a helper whose recorded grace
// does not fit the time left, bound. It asks the helper, on its control socket,
// to start its stop with the grace the bound leaves it
// (sandbox.ShortenedStopGrace), so the guest is told the time it actually has
// instead of being killed at the bound partway through a grace it believed it
// had. The client proves the socket is served by the recorded helper's pid
// before it sends anything. The SIGTERM and the wait that follow are the same
// whatever the answer: on a shortened stop the SIGTERM is redundant, and a
// helper that predates the request, one that cannot be reached, or any error
// leaves today's SIGTERM-and-wait as the stop.
//
// The cut is printed to the command's output as well as logged, because it is
// the one place a full stop or an uninstall shortens a promise made to a
// workload.
//
// It returns the report of what came of it, run by the caller under its lock:
// every cut is logged at Warn and printed, unless the helper was already
// stopping with a grace that fits, which is only logged.
func shortenVMHelper(ctx context.Context, sys System, rec VMHostRecord, bound time.Duration) func(Config) {
	grace := sandbox.VMHelperStopWait(time.Duration(rec.StopGraceNanos)) - sandbox.VMHelperStopMargin
	cut, cerr := sandbox.ShortenedStopGrace(grace, bound)
	var (
		out sandbox.VMHostShortenOutcome
		err error
	)
	switch {
	case rec.RunDir == "":
		err = errors.New("no request sent: the record names no run dir (an earlier runtime wrote it)")
	case cerr != nil:
		cut = 0
		err = fmt.Errorf("no request sent: %w", cerr)
	default:
		out, err = sys.ShortenVMHostStop(ctx, filepath.Join(rec.RunDir, sandbox.VMHostControlSocketName), rec.Pgid, bound)
	}
	fits := bound - sandbox.VMHelperStopMargin
	switch {
	case err == nil && out.Result == sandbox.VMHostShortened:
		return func(cfg Config) {
			cfg.Logger.Warn("vm pod grace cut to fit the stop bound; the guest was told", "pod", rec.PodID, "pgid", rec.Pgid,
				"original_grace", out.From, "new_grace", out.To, "bound", bound)
			_, _ = fmt.Fprintf(cfg.Out, "vm pod %s: grace %s cut to %s to fit the %s stop bound; the guest was told\n",
				rec.PodID, out.From, out.To, bound)
		}
	case err == nil && out.Result == sandbox.VMHostAlreadyStopping && out.From <= fits:
		return func(cfg Config) {
			cfg.Logger.Info("vm pod helper was already stopping with a grace that fits the stop bound", "pod", rec.PodID, "pgid", rec.Pgid,
				"grace", out.From, "bound", bound)
		}
	case err == nil && out.Result == sandbox.VMHostAlreadyStopping:
		return func(cfg Config) {
			cfg.Logger.Warn("vm pod helper was already stopping with a grace longer than the stop bound allows; it will be killed at the bound",
				"pod", rec.PodID, "pgid", rec.Pgid, "grace", out.From, "bound", bound)
			_, _ = fmt.Fprintf(cfg.Out, "vm pod %s: already stopping with grace %s, longer than the %s stop bound allows; it is killed at the bound\n",
				rec.PodID, out.From, bound)
		}
	}
	reason := out.Reason
	if err != nil {
		reason = err.Error()
	}
	return func(cfg Config) {
		cfg.Logger.Warn("vm pod grace does not fit the stop bound and the helper could not be told; it will be killed at the bound",
			"pod", rec.PodID, "pgid", rec.Pgid, "grace", grace, "bound", bound, "reason", reason)
		_, _ = fmt.Fprintf(cfg.Out, "vm pod %s: grace %s does not fit the %s stop bound (it would be cut to %s); the helper could not be told, so it is killed at the bound: %s\n",
			rec.PodID, grace, bound, cut, reason)
	}
}

// verifyVMHelper reports whether rec's process group is provably still the
// recorded helper, the check every signal the teardown sends is preceded by:
// the group can be inspected and its leader (pid == pgid) is alive with exactly
// the recorded start time, and the leader is the installed k3sm-vmhost running
// as the service user (isInstalledVMHost). A group that cannot be inspected, a
// gone leader or a recycled pgid is false with no error (nothing of ours is
// provably there); a start-time match on another executable or uid is false
// with an error (a forged or corrupted record), as is an executable that cannot
// be read. The leader is proven to be the recorded, running helper before its
// executable is judged, so that path is a running vm pod's path, and the
// version directory it lies in is retained as in use by that pod (the layout's
// retention rule, retainedVersion) for as long as the directory is there. A
// service-user helper running from a version directory the tree no longer
// retains, one that is gone (unretainedVMHost), is false with an error of its own, naming
// its pid, path and version and how to stop it: it is a real leftover, not a
// forged record, but nothing vouches for its path any more, so it is reported
// and never signalled. A service-user helper whose version directory cannot be
// resolved for any reason but its being gone (EACCES, EIO) is false with an
// error naming the unresolvable path: whether the tree retains its version is
// unknown, so it is neither signalled nor called unretained.
func verifyVMHelper(sys System, cfg Config, rec VMHostRecord, svcUID uint32) (bool, error) {
	start, alive := sys.ProcessGroupLeaderStart(rec.Pgid)
	if !alive {
		return false, nil
	}
	if start != rec.StartUnixNano {
		cfg.Logger.Info("vm helper process group id now belongs to another process; not signalled", "pod", rec.PodID, "pgid", rec.Pgid)
		return false, nil
	}
	exe, uid, err := sys.ProcessExecutable(rec.Pgid)
	switch {
	case err != nil:
		return false, fmt.Errorf("vm helper group %d: cannot read its executable, not signalled: %w", rec.Pgid, err)
	}
	installed, rerr := isInstalledVMHost(sys, cfg, exe, []string{exe})
	switch {
	case uid == svcUID && rerr != nil:
		ver, _ := layout.New(cfg.InstallDir).VersionedBinary(filepath.Clean(exe), VMHostName)
		cfg.Logger.Warn("a vm helper runs from a version directory that cannot be resolved, so whether this install retains it is unknown; not signalled",
			"pod", rec.PodID, "pid", rec.Pgid, "exe", filepath.Clean(exe), "version", ver, "err", rerr)
		return false, fmt.Errorf("vm helper pid %d (pod %s) runs %s from version %s, whose path cannot be resolved, so whether this install retains it is unknown; not signalled: %w",
			rec.Pgid, rec.PodID, filepath.Clean(exe), ver, rerr)
	case uid != svcUID || !installed:
		if ver, ok := unretainedVMHost(sys, cfg, exe, []string{exe}); ok && uid == svcUID {
			cfg.Logger.Warn("a vm helper runs from a version this install no longer retains; not signalled, stop it by hand",
				"pod", rec.PodID, "pid", rec.Pgid, "exe", filepath.Clean(exe), "version", ver)
			return false, fmt.Errorf("vm helper pid %d (pod %s) runs %s from version %s, which this install no longer retains; not signalled, stop it with: sudo kill -TERM -%d",
				rec.Pgid, rec.PodID, filepath.Clean(exe), ver, rec.Pgid)
		}
		want := cfg.installedVMHost()
		cfg.Logger.Warn("a vm helper record names a process that is not this install's k3sm-vmhost; not signalled", "pod", rec.PodID, "pgid", rec.Pgid, "exe", exe, "uid", uid)
		return false, fmt.Errorf("vm helper record for group %d names %s (uid %d), not %s (uid %d); not signalled", rec.Pgid, exe, uid, want, svcUID)
	}
	return true, nil
}

// isInstalledVMHost reports whether exe, the executable path the kernel
// recorded for a helper, is this install's k3sm-vmhost in any of the forms the
// runtime can have started it through:
//
//   - the flat installed path (installedVMHost), which in the versioned layout
//     is a compatibility symlink;
//   - the same name through the current symlink (<InstallDir>/current/<name>);
//   - the name directly inside a retained version directory
//     (<InstallDir>/versions/<ver>/<name>), where the runtime's symlink-resolved
//     lookup lands: <ver> must be a version the tree keeps by the layout's
//     retention rule (retainedVersion), so a helper started before a flip
//     still matches while its version is kept as previous, or while a running
//     pod among podPaths keeps it in use, and a version the tree no longer
//     retains, however validly named, is refused. Without a current link (the
//     flat layout) no version directory is accepted;
//   - the flat installed path with every symlink resolved, read only when the
//     forms above do not match.
//
// Every other path, any other basename or a directory outside versions/
// included, is refused. A tree that is root-owned to / is what makes a path
// under versions/ an identity; this check names which of its files it is.
//
// The error is non-nil only when exe is a version-directory path whose
// retention is unknown (retainedVersion): the answer is then false, and the
// caller must neither signal the helper nor call it unretained.
func isInstalledVMHost(sys System, cfg Config, exe string, podPaths []string) (bool, error) {
	if !filepath.IsAbs(exe) {
		return false, nil
	}
	exe = filepath.Clean(exe)
	installed := cfg.installedVMHost()
	tree := layout.New(cfg.InstallDir)
	if exe == installed {
		return true, nil
	}
	if through, err := tree.Binary(VMHostName); err == nil && exe == through {
		return true, nil
	}
	if ver, ok := tree.VersionedBinary(exe, VMHostName); ok {
		return retainedVersion(sys, tree, ver, podPaths)
	}
	resolved, err := sys.ResolvePath(installed)
	if err != nil {
		return false, nil
	}
	resolved = filepath.Clean(resolved)
	if resolved == installed {
		return false, nil
	}
	return exe == resolved && filepath.Base(resolved) == VMHostName, nil
}

// unretainedVMHost reports whether exe, refused by isInstalledVMHost, is the
// helper's name directly inside a validly named version directory the tree
// does not retain (retainedVersion over the same podPaths), and which version
// that is. Such a helper was started from a version the updates since have
// retired and removed. It is never signalled: once its version is no longer
// retained, the tree no longer vouches for that path. The teardown reports it
// by pid and path instead, as a leftover, rather than as a forged record. A
// version whose retention is unknown is not unretained: false.
func unretainedVMHost(sys System, cfg Config, exe string, podPaths []string) (string, bool) {
	if !filepath.IsAbs(exe) {
		return "", false
	}
	tree := layout.New(cfg.InstallDir)
	ver, ok := tree.VersionedBinary(exe, VMHostName)
	if !ok {
		return "", false
	}
	if kept, err := retainedVersion(sys, tree, ver, podPaths); kept || err != nil {
		return "", false
	}
	return ver, true
}

// retainedVersion reports whether the tree keeps ver, by the layout's own
// retention rule (layout.Retained): the version current or previous points
// at, the staged version, or a version a running pod uses. podPaths are the
// paths of the running pods the caller has proven are running; the versions
// they lie in are the in-use set (layout.PodVersions, which resolves each path
// first, so a path whose version directory is gone names no version). A link
// that is missing or does not read exactly versions/<ver> retains nothing, and
// without a current link (the flat layout) no pod path retains a version
// either. The teardown has no staged version to name: a version is staged by
// the updater, which no running pod is started from.
//
// A pod path, or the versions directory, that cannot be resolved because it is
// gone (fs.ErrNotExist) names no version. Any other resolve failure (EACCES,
// EIO) leaves the version it may name unknown: when the links do not retain
// ver on their own, retainedVersion then returns false with that error, and
// the caller must neither signal the helper nor report it as unretained.
func retainedVersion(sys System, tree layout.Layout, ver string, podPaths []string) (bool, error) {
	var (
		r       layout.Retained
		unknown error
	)
	if v, err := tree.ResolveActive(sys.Readlink); err == nil {
		r.Current = v
		// Each resolve or listing failure is classified at its seam, where its
		// cause is still the only error: a path that is gone names no version,
		// any other failure leaves the version it may name unknown.
		var unreadable bool
		classify := func(err error) {
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				unreadable = true
			}
		}
		eval := func(path string) (string, error) {
			resolved, err := sys.ResolvePath(path)
			classify(err)
			return resolved, err
		}
		list := entryNames(sys)
		names := func(dir string) ([]string, error) {
			ns, err := list(dir)
			classify(err)
			return ns, err
		}
		inUse, err := tree.PodVersions(podPaths, eval, names)
		r.InUse = inUse
		if unreadable {
			unknown = err
		}
	}
	if v, err := tree.ResolvePrevious(sys.Readlink); err == nil {
		r.Previous = v
	}
	if len(r.Reasons(ver)) > 0 {
		return true, nil
	}
	return false, unknown
}

// entryNames is the listing seam layout.PodVersions maps a pod path's version
// to the versions directory's own spelling of it through: the base names of
// the entries sys.ListOwned reports directly inside dir.
func entryNames(sys System) layout.ListNames {
	return func(dir string) ([]string, error) {
		ents, err := sys.ListOwned(dir)
		if err != nil {
			return nil, err
		}
		names := make([]string, len(ents))
		for i, e := range ents {
			names[i] = filepath.Base(e.Path)
		}
		return names, nil
	}
}

// vmHelperStop is one helper the teardown sent SIGTERM, and how long it gets.
type vmHelperStop struct {
	rec  VMHostRecord
	wait time.Duration
}

// vmHelperWait is how long the teardown waits for rec's helper after its
// SIGTERM: the runtime's own wait for the grace the helper was spawned with
// (sandbox.VMHelperStopWait, the grace plus the helper's margin), capped at
// vmHelperStopBound. A helper whose grace does not fit is still SIGTERMed first;
// it is cut at the bound, as the runtime's own stop of every guest would cut it.
func vmHelperWait(rec VMHostRecord) time.Duration {
	return min(sandbox.VMHelperStopWait(time.Duration(rec.StopGraceNanos)), vmHelperStopBound)
}

// awaitVMHelpers waits for the SIGTERMed helpers in stopping, each up to its
// own wait from the start of the stop (elapsed is how much of the clock the
// shorten requests and the SIGTERMs already spent), and SIGKILLs every one still
// running when its wait ends, after verify proves again, at that moment, that
// the group is still the recorded helper (its pid may have been freed and
// reused during the wait). It returns the killed groups. The waits run on one
// clock: the helpers are taken in order of their wait, and each round waits
// only for the time between the previous helper's deadline and the next one's.
func awaitVMHelpers(ctx context.Context, sys System, cfg Config, stopping []vmHelperStop, verify func(VMHostRecord) (bool, error), elapsed time.Duration) ([]int, error) {
	slices.SortStableFunc(stopping, func(a, b vmHelperStop) int { return cmp.Compare(a.wait, b.wait) })
	var (
		killed []int
		errs   error
	)
	for len(stopping) > 0 {
		deadline := stopping[0].wait
		pgids := make([]int, len(stopping))
		for i, s := range stopping {
			pgids[i] = s.rec.Pgid
		}
		left := map[int]bool{}
		for _, pgid := range sys.WaitProcessGroupsGone(ctx, pgids, max(deadline-elapsed, 0)) {
			left[pgid] = true
		}
		elapsed = max(elapsed, deadline)
		var still []vmHelperStop
		for _, s := range stopping {
			switch {
			case !left[s.rec.Pgid]:
				cfg.Logger.Info("vm pod helper stopped", "pod", s.rec.PodID, "pgid", s.rec.Pgid)
			case s.wait > deadline:
				still = append(still, s)
			default:
				ok, verr := verify(s.rec)
				errs = errors.Join(errs, verr)
				if !ok {
					continue
				}
				cfg.Logger.Warn("vm pod helper did not exit within its grace; killing it (SIGKILL)", "pod", s.rec.PodID, "pgid", s.rec.Pgid, "wait", s.wait)
				if serr := sys.SignalProcessGroup(s.rec.Pgid, syscall.SIGKILL); serr != nil {
					cfg.Logger.Warn("could not signal vm helper group", "pod", s.rec.PodID, "pgid", s.rec.Pgid, "signal", "SIGKILL", "err", serr)
					errs = errors.Join(errs, fmt.Errorf("signal vm helper group %d: %w", s.rec.Pgid, serr))
					continue
				}
				killed = append(killed, s.rec.Pgid)
			}
		}
		stopping = still
	}
	return killed, errs
}

// maxVMHostRecordSize bounds one vm reap record read. A real record is a few
// hundred bytes; anything larger is not one.
const maxVMHostRecordSize = 64 << 10

// VMHostStore is what ReadVMHostRecords found: the usable records, and the
// names of record files it refused to trust.
type VMHostStore struct {
	Records  []VMHostRecord
	Rejected []string
}

// readVMHostRecords reads the runtime's vm reap store under dataRoot
// (<dataRoot>/vmreap, sandbox.VMReapSubdir). It is a narrow reader of
// runtimed's record shape, because runtimed exports no reader for this store,
// and it never writes or removes anything (the store is the runtime's).
//
// Trust comes first, because a record drives a root kill. The directory must
// be a real directory (not a symlink), owned by one of owners, and not group-
// or world-writable; otherwise it is an error and nothing is read. Each *.json
// entry is opened without following a symlink and must be a regular file
// owned by one of owners and not group- or world-writable; one that is not is
// listed in Rejected and not parsed. A trusted file that does not parse, or
// has a pgid of 1 or less, is skipped. An absent store holds none.
func readVMHostRecords(dataRoot string, owners []uint32) (VMHostStore, error) {
	var st VMHostStore
	root := filepath.Join(dataRoot, sandbox.VMReapSubdir)
	fi, err := os.Lstat(root)
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, fmt.Errorf("stat the vm reap store %s: %w", root, err)
	}
	if err := trustedEntry(fi, true, owners); err != nil {
		return st, fmt.Errorf("the vm reap store %s is not trusted: %w", root, err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return st, fmt.Errorf("read the vm reap store %s: %w", root, err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := readTrustedRecord(filepath.Join(root, e.Name()), owners)
		if err != nil {
			st.Rejected = append(st.Rejected, e.Name())
			continue
		}
		var rec VMHostRecord
		if json.Unmarshal(data, &rec) != nil || rec.Pgid <= 1 {
			continue
		}
		st.Records = append(st.Records, rec)
	}
	return st, nil
}

// trustedEntry checks a file's lstat/fstat result: the expected type (a
// directory when dir, else a regular file; a symlink is neither), an owner in
// owners, and no group or world write.
func trustedEntry(fi fs.FileInfo, dir bool, owners []uint32) error {
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		return errors.New("it is a symlink")
	case dir && !fi.IsDir():
		return errors.New("it is not a directory")
	case !dir && !fi.Mode().IsRegular():
		return ErrNotRegularFile
	case fi.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("it is group- or world-writable (%v)", fi.Mode().Perm())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("its owner cannot be read")
	}
	if !slices.Contains(owners, st.Uid) {
		return fmt.Errorf("it is owned by uid %d", st.Uid)
	}
	return nil
}

// readTrustedRecord reads one record file: opened O_NOFOLLOW, checked on the
// descriptor (trustedEntry), and bounded to maxVMHostRecordSize.
func readTrustedRecord(path string, owners []uint32) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err := trustedEntry(fi, false, owners); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if fi.Size() > maxVMHostRecordSize {
		return nil, fmt.Errorf("%s is %d bytes, larger than a record can be", path, fi.Size())
	}
	return io.ReadAll(io.LimitReader(f, maxVMHostRecordSize))
}

// procargsExecPath extracts the exec path from a kern.procargs2 buffer: a
// native-endian int32 argc followed by the NUL-terminated path.
func procargsExecPath(raw []byte) (string, error) {
	if len(raw) < 5 {
		return "", errors.New("kern.procargs2 is too short")
	}
	rest := raw[4:]
	end := bytes.IndexByte(rest, 0)
	if end <= 0 {
		return "", errors.New("kern.procargs2 carries no exec path")
	}
	return string(rest[:end]), nil
}
