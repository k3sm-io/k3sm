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
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"k3sm.io/darwin-net/pkg/podnet"
	"k3sm.io/k3sm/pkg/netdsvc"
	"k3sm.io/runtimed/pkg/sandbox"
)

// The post-bootout teardown, shared by `k3sm uninstall` and `k3sm stop`.
//
// Once the node daemon is booted out, the things still holding k3sm state on
// the Mac are the same for both verbs: the pod process groups (a daemon restart
// re-attaches to them, so its shutdown leaves them running on purpose), any
// k3sm-vmhost helper that outlived its daemon, control-plane children that
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
// kill is matched against. It mirrors the fields of runtimed's vm reap record
// (sandbox.vmProcRecord) that the teardown needs.
type VMHostRecord struct {
	PodID         string `json:"podId"`
	Pgid          int    `json:"pgid"`
	StartUnixNano int64  `json:"startUnixNano"`
}

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
// node daemon is gone: the recorded pod process groups, any k3sm-vmhost helper
// that survived its daemon, and control-plane children that outlived the
// server daemon.
func teardownWorkloads(ctx context.Context, sys System, cfg Config) []LeftoverItem {
	var left []LeftoverItem
	add := func(kind Leftover, err error) {
		if err != nil {
			left = append(left, LeftoverItem{Kind: kind, Err: err})
		}
	}
	// The pod process groups, by the runtime's recorded identity (podgroups.go).
	add(LeftoverPods, teardownPodGroups(ctx, sys, cfg))
	// The vm helpers. A helper carries the opposite contract to a native pod:
	// no VM outlives the daemon that booted it, so one still here is an orphan
	// and is killed outright.
	add(LeftoverVMHelpers, killVMHostSurvivors(ctx, sys, cfg))
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

// killVMHostSurvivors SIGKILLs every k3sm-vmhost helper the runtime recorded
// whose process group is still led by exactly the recorded instance, then
// waits for them to go.
//
// The identity rule is runtimed's own (sandbox.vmReapDecision): a group is
// signalled only while its leader (pid == pgid) is alive with exactly the
// recorded start time. A pgid recycled to another process has a different
// immutable start and is left alone, and so is a group whose leader is gone.
// Nothing is ever matched by process name. SIGKILL with no grace is the
// runtime's choice for an orphaned helper too: the graceful path runs inside
// the daemon that is already gone.
//
// It returns an error when the records cannot be read (a survivor cannot be
// ruled out) or when a killed helper is still there after vmHostKillWait.
func killVMHostSurvivors(ctx context.Context, sys System, cfg Config) error {
	recs, err := sys.ReadVMHostRecords(cfg.DataRoot)
	if err != nil {
		cfg.Logger.Warn("could not read the vm helper records; a k3sm-vmhost process may survive", "data-root", cfg.DataRoot, "err", err)
		return fmt.Errorf("read the vm helper records: %w", err)
	}
	var killed []int
	var errs error
	for _, rec := range recs {
		if rec.Pgid <= 1 || rec.StartUnixNano == 0 {
			continue
		}
		start, alive := sys.ProcessGroupLeaderStart(rec.Pgid)
		if !alive {
			continue
		}
		if start != rec.StartUnixNano {
			cfg.Logger.Info("vm helper process group id now belongs to another process; not signalled", "pod", rec.PodID, "pgid", rec.Pgid)
			continue
		}
		cfg.Logger.Warn("a k3sm-vmhost helper outlived its daemon; killing it (SIGKILL)", "pod", rec.PodID, "pgid", rec.Pgid)
		if serr := sys.SignalProcessGroup(rec.Pgid, syscall.SIGKILL); serr != nil {
			errs = errors.Join(errs, fmt.Errorf("signal vm helper group %d: %w", rec.Pgid, serr))
			continue
		}
		killed = append(killed, rec.Pgid)
	}
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

// maxVMHostRecordSize bounds one vm reap record read. A real record is a few
// hundred bytes; anything larger is not one.
const maxVMHostRecordSize = 64 << 10

// readVMHostRecords reads the runtime's vm reap store under dataRoot
// (<dataRoot>/vmreap, sandbox.VMReapSubdir): every regular *.json file that
// parses with a pgid above 1. It is a narrow reader of runtimed's record
// shape, because runtimed exports no reader for this store. It never writes
// or removes anything (the store is the runtime's), never follows a symlink,
// and skips a file it cannot read or parse rather than failing the teardown;
// only an unreadable store directory is an error. An absent store holds none.
func readVMHostRecords(dataRoot string) ([]VMHostRecord, error) {
	root := filepath.Join(dataRoot, sandbox.VMReapSubdir)
	entries, err := os.ReadDir(root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the vm reap store %s: %w", root, err)
	}
	var recs []VMHostRecord
	for _, e := range entries {
		if !e.Type().IsRegular() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := readRegularBounded(filepath.Join(root, e.Name()), maxVMHostRecordSize)
		if err != nil {
			continue
		}
		var rec VMHostRecord
		if json.Unmarshal(data, &rec) != nil || rec.Pgid <= 1 {
			continue
		}
		recs = append(recs, rec)
	}
	return recs, nil
}

// readRegularBounded reads at most limit bytes of the regular file at path,
// refusing a symlink (O_NOFOLLOW) and anything that is not a regular file.
func readRegularBounded(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w", path, ErrNotRegularFile)
	}
	if fi.Size() > limit {
		return nil, fmt.Errorf("%s is %d bytes, larger than a record can be", path, fi.Size())
	}
	return io.ReadAll(io.LimitReader(f, limit))
}
