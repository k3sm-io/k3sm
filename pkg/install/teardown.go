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
// that is provably still that helper, then waits for them to go.
//
// A record authorizes a root SIGKILL of a process group, so it is believed only
// as far as it can be checked:
//
//   - the store directory and the record file must be trusted: not a symlink,
//     owned by root or the service user, and not group- or world-writable
//     (readVMHostRecords). An untrusted record is never read as a kill order;
//   - the group's leader (pid == pgid) must be alive with exactly the recorded
//     start time, runtimed's own exact-instance rule (sandbox.vmReapDecision).
//     A leader that is gone, or a recycled pgid with a different immutable
//     start, means nothing of ours is there: skipped, and not a leftover;
//   - the leader must be the installed k3sm-vmhost (its executable path) and
//     run as the service user. A start-time match on any other process is a
//     forged or corrupted record: never killed, and reported.
//
// Nothing is ever matched by process name. SIGKILL with no grace is the
// runtime's choice for an orphaned helper too: the graceful path runs inside
// the daemon that is already gone.
//
// It returns an error naming every record it could not act on or rule out,
// and every killed helper still alive after vmHostKillWait.
func killVMHostSurvivors(ctx context.Context, sys System, cfg Config) error {
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
	want := cfg.installedVMHost()
	var killed []int
	for _, rec := range store.Records {
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
		exe, uid, perr := sys.ProcessExecutable(rec.Pgid)
		switch {
		case perr != nil:
			errs = errors.Join(errs, fmt.Errorf("vm helper group %d: cannot read its executable, not killed: %w", rec.Pgid, perr))
			continue
		case filepath.Clean(exe) != want || uid != svcUID:
			cfg.Logger.Warn("a vm helper record names a process that is not this install's k3sm-vmhost; not killed", "pod", rec.PodID, "pgid", rec.Pgid, "exe", exe, "uid", uid)
			errs = errors.Join(errs, fmt.Errorf("vm helper record for group %d names %s (uid %d), not %s (uid %d); not killed", rec.Pgid, exe, uid, want, svcUID))
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
