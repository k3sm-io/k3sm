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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
)

// fakeServicePID is the launchd half of the running-server probe.
type fakeServicePID struct {
	pid int
	err error
}

func (f fakeServicePID) LaunchctlServicePID(string) (int, error) { return f.pid, f.err }

// TestLiveControlPlaneProbeSignals pins the two-signal composition. launchd names the
// job when it has one; a launchd error is NOT a refusal (an uninstalled node answers
// that way and would otherwise never be restorable), and the port probe is what stays
// honest there.
func TestLiveControlPlaneProbeSignals(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	held := ln.Addr().(*net.TCPAddr).Port

	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	freePort := free.Addr().(*net.TCPAddr).Port
	_ = free.Close()

	cases := []struct {
		name     string
		sys      servicePIDReader
		kinePort int
		want     string // a substring the holder must carry; "" means no holder
	}{
		{"launchd reports a live job", fakeServicePID{pid: 4242}, freePort, install.ServerLabel},
		{"launchd job loaded but not running, port free", fakeServicePID{pid: 0}, freePort, ""},
		{"launchd job not loaded, port free", fakeServicePID{err: errors.New("could not find service")}, freePort, ""},
		{"launchd job not loaded, port held", fakeServicePID{err: errors.New("could not find service")}, held, strconv.Itoa(held)},
		{"no launchd seam at all, port held", nil, held, strconv.Itoa(held)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			holder, err := liveControlPlaneProbe(tc.sys, install.ServerLabel, tc.kinePort, 0)(context.Background())
			if err != nil {
				t.Fatalf("probe error: %v", err)
			}
			switch {
			case tc.want == "" && holder != "":
				t.Errorf("holder = %q, want none", holder)
			case tc.want != "" && !strings.Contains(holder, tc.want):
				t.Errorf("holder = %q, want it to name %q", holder, tc.want)
			}
		})
	}
}

// TestLiveControlPlaneProbeIsNotNil guards the wiring: RestoreSnapshot refuses outright
// when handed a nil probe, so a CLI that forgot to build one would fail closed — but it
// would fail for every operator, including the correct case. This asserts the CLI's own
// probe is constructed.
func TestLiveControlPlaneProbeIsNotNil(t *testing.T) {
	if liveControlPlaneProbe(nil, install.ServerLabel, 0, 0) == nil {
		t.Fatal("the CLI built a nil live-control-plane probe")
	}
}

// TestSnapshotRestoreReportPrintsTheVerificationStep is the drill's last mile: the
// command tells the operator how to CHECK the restore, and names the preserved database
// they must keep if the check fails. A restore that only says "done" is the failure mode
// backup-restore.md warns about.
func TestSnapshotRestoreReportPrintsTheVerificationStep(t *testing.T) {
	var buf bytes.Buffer
	renderSnapshotRestore(&buf, &executor.SnapshotRestoreResult{
		Snapshot:   "/backups/k3sm-snapshot-20260830T101500Z.db",
		Bytes:      4096,
		RestoredDB: "/var/lib/k3sm/server/db/state.db",
		PreviousDB: "/var/lib/k3sm/server/db/state.db.restore-20260830T101600Z.bak",
		MovedAside: []string{"/var/lib/k3sm/server/db/state.db.restore-20260830T101600Z.bak-wal"},
	})
	out := buf.String()
	for _, want := range []string{
		"/readyz?verbose",
		"k3sm kubectl get nodes",
		"k3sm kubectl get pods -A",
		"k3sm doctor",
		"launchctl bootstrap system",
		"state.db.restore-20260830T101600Z.bak",
		"state.db.restore-20260830T101600Z.bak-wal",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the restore report does not mention %q:\n%s", want, out)
		}
	}
}

// TestSnapshotSaveReportIsHonestAboutTheWAL pins the two save reports. A live cluster
// declines the checkpoint, and the report must say the snapshot is consistent anyway —
// silence there reads as a damaged backup, and a scary line reads as one too.
func TestSnapshotSaveReportIsHonestAboutTheWAL(t *testing.T) {
	base := executor.SnapshotSaveResult{
		Path:     "/var/lib/k3sm/server/db/snapshots/k3sm-snapshot-20260830T101500Z.db",
		Bytes:    8192,
		SourceDB: "/var/lib/k3sm/server/db/state.db",
		TakenAt:  time.Date(2026, 8, 30, 10, 15, 0, 0, time.UTC),
	}
	drained := base
	drained.Checkpointed = true
	var buf bytes.Buffer
	renderSnapshotSave(&buf, &drained)
	if out := buf.String(); !strings.Contains(out, "drained") || !strings.Contains(out, "k3sm snapshot restore "+base.Path) {
		t.Errorf("drained report is missing its state or the restore command:\n%s", out)
	}

	busy := base
	busy.CheckpointNote = "executor: datastore WAL was not drained by the TRUNCATE checkpoint: busy"
	buf.Reset()
	renderSnapshotSave(&buf, &busy)
	out := buf.String()
	if !strings.Contains(out, "consistent point-in-time image") {
		t.Errorf("the undrained report does not say the snapshot is still consistent:\n%s", out)
	}
	if !strings.Contains(out, "Copy it OFF this node") {
		t.Errorf("the report does not tell the operator to move the snapshot off the node:\n%s", out)
	}
}

// TestSnapshotDispatch pins the subcommand surface: no verb and an unknown verb both
// fail with usage, and the usage states the single-node scope and the etcd posture's
// limits.
func TestSnapshotDispatch(t *testing.T) {
	err := runSnapshot(nil)
	if err == nil {
		t.Fatal("k3sm snapshot with no subcommand succeeded")
	}
	for _, want := range []string{"snapshot save", "snapshot restore", "etcd", "PersistentVolume"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the usage does not mention %q:\n%s", want, err)
		}
	}
	if err := runSnapshot([]string{"rotate"}); err == nil || !strings.Contains(err.Error(), "unknown snapshot subcommand") {
		t.Errorf("unknown subcommand err = %v, want an unknown-subcommand error", err)
	}
}

// TestSnapshotIsWiredIntoTheTopLevelUsage guards the half of the wiring a subcommand
// test cannot see: a `k3sm snapshot` that works but is not listed is a command the
// operator reaching for it at 3 AM does not know exists.
func TestSnapshotIsWiredIntoTheTopLevelUsage(t *testing.T) {
	if !strings.Contains(usage, "snapshot") {
		t.Errorf("k3sm's usage does not list the snapshot command:\n%s", usage)
	}
	if !strings.Contains(usage, `"snapshot"`) {
		t.Error("the usage's implemented-commands list does not include \"snapshot\"")
	}
}

// TestAnnotateSnapshotErrorIsActionable pins that a refusal reaches the operator with the
// command that clears it, and that the typed sentinel survives the annotation.
func TestAnnotateSnapshotErrorIsActionable(t *testing.T) {
	running := annotateSnapshotError(executor.ErrControlPlaneRunning, "/var/lib/k3sm/server")
	if !errors.Is(running, executor.ErrControlPlaneRunning) {
		t.Error("annotation broke errors.Is on ErrControlPlaneRunning")
	}
	for _, want := range []string{"launchctl bootout system/" + install.ServerLabel, "launchctl bootstrap system"} {
		if !strings.Contains(running.Error(), want) {
			t.Errorf("the running-server refusal does not tell the operator to %q:\n%v", want, running)
		}
	}
	nodb := annotateSnapshotError(executor.ErrNoDatastore, "/var/lib/k3sm/server")
	if !errors.Is(nodb, executor.ErrNoDatastore) || !strings.Contains(nodb.Error(), install.DefaultServiceUser) {
		t.Errorf("the no-datastore error is not actionable: %v", nodb)
	}
	other := errors.New("some other failure")
	if annotateSnapshotError(other, "/x") != other {
		t.Error("an unrecognized error was rewritten")
	}
}

// TestSnapshotSaveDispatchesByPosture pins the save dispatch: a work dir holding an
// etcd member takes the online etcd snapshot (to the default snapshots dir, created
// 0700, or to --out) and never the SQLite path; any other work dir takes the SQLite
// path and never the etcd one; an etcd failure keeps its sentinel.
func TestSnapshotSaveDispatchesByPosture(t *testing.T) {
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	newSavers := func(member bool, calls *[]string, etcdErr error) snapshotSavers {
		return snapshotSavers{
			etcdMember: func(string) bool { return member },
			etcd: func(_ context.Context, _ string, dst string, compress bool) error {
				*calls = append(*calls, fmt.Sprintf("etcd %s compress=%t", dst, compress))
				return etcdErr
			},
			sqlite: func(_ context.Context, opts executor.SnapshotSaveOptions) (*executor.SnapshotSaveResult, error) {
				*calls = append(*calls, fmt.Sprintf("sqlite %s compress=%t", opts.Out, opts.Compress))
				return &executor.SnapshotSaveResult{Path: "x", SourceDB: "y", Checkpointed: true}, nil
			},
			now: func() time.Time { return at },
		}
	}

	t.Run("etcd member, default destination", func(t *testing.T) {
		wd := t.TempDir()
		var calls []string
		var out strings.Builder
		if err := saveSnapshot(context.Background(), &out, wd, "", false, newSavers(true, &calls, nil)); err != nil {
			t.Fatalf("save: %v", err)
		}
		want := filepath.Join(executor.SnapshotDir(wd), "k3sm-etcd-snapshot-20261002T120000Z.db")
		if len(calls) != 1 || calls[0] != "etcd "+want+" compress=false" {
			t.Fatalf("calls = %v, want one etcd save to %s", calls, want)
		}
		if fi, err := os.Stat(executor.SnapshotDir(wd)); err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("snapshots dir: %v %v, want 0700", fi, err)
		}
		if !strings.Contains(out.String(), "plaintext") {
			t.Errorf("the report does not warn that the file holds Secrets in plaintext:\n%s", out.String())
		}
	})

	t.Run("etcd member, --out file", func(t *testing.T) {
		var calls []string
		dst := filepath.Join(t.TempDir(), "snap.db")
		if err := saveSnapshot(context.Background(), io.Discard, t.TempDir(), dst, false, newSavers(true, &calls, nil)); err != nil {
			t.Fatalf("save: %v", err)
		}
		if len(calls) != 1 || calls[0] != "etcd "+dst+" compress=false" {
			t.Errorf("calls = %v, want one etcd save to %s", calls, dst)
		}
	})

	t.Run("etcd failure keeps its sentinel", func(t *testing.T) {
		var calls []string
		err := saveSnapshot(context.Background(), io.Discard, t.TempDir(), "", false, newSavers(true, &calls, executor.ErrNoEtcdClient))
		if !errors.Is(err, executor.ErrNoEtcdClient) || !strings.Contains(err.Error(), "start the server") {
			t.Errorf("err = %v, want ErrNoEtcdClient with the remedy", err)
		}
	})

	t.Run("kine posture", func(t *testing.T) {
		var calls []string
		if err := saveSnapshot(context.Background(), io.Discard, t.TempDir(), "/x/out.db", false, newSavers(false, &calls, nil)); err != nil {
			t.Fatalf("save: %v", err)
		}
		if len(calls) != 1 || calls[0] != "sqlite /x/out.db compress=false" {
			t.Errorf("calls = %v, want one SQLite save", calls)
		}
	})

	t.Run("compressed: etcd member, default destination ends in .zip", func(t *testing.T) {
		wd := t.TempDir()
		var calls []string
		var out strings.Builder
		if err := saveSnapshot(context.Background(), &out, wd, "", true, newSavers(true, &calls, nil)); err != nil {
			t.Fatalf("save: %v", err)
		}
		want := filepath.Join(executor.SnapshotDir(wd), "k3sm-etcd-snapshot-20261002T120000Z.zip")
		if len(calls) != 1 || calls[0] != "etcd "+want+" compress=true" {
			t.Fatalf("calls = %v, want one compressed etcd save to %s", calls, want)
		}
		if !strings.Contains(out.String(), "zip archive") {
			t.Errorf("the report does not say the snapshot is compressed:\n%s", out.String())
		}
	})

	t.Run("compressed: kine posture passes the option through", func(t *testing.T) {
		var calls []string
		if err := saveSnapshot(context.Background(), io.Discard, t.TempDir(), "/x/out.db", true, newSavers(false, &calls, nil)); err != nil {
			t.Fatalf("save: %v", err)
		}
		if len(calls) != 1 || calls[0] != "sqlite /x/out.db compress=true" {
			t.Errorf("calls = %v, want one compressed SQLite save", calls)
		}
	})
}

// TestResolveRestoreTarget: the posture comes from configuration (the installed
// server's role flags, or --etcd-peer-ip here), never from a member existing on disk,
// and the member identity defaults to the installed server's own flags.
func TestResolveRestoreTarget(t *testing.T) {
	installedEtcd := []string{"--cluster-init", "--etcd-peer-ip", "192.0.2.10", "--node-name=studio", "--etcd-peer-port", "2390"}
	for _, tc := range []struct {
		name      string
		installed []string
		flags     restoreFlags
		want      restoreTarget
	}{
		{"single-server install", []string{"--mesh-ip", "100.64.0.1"}, restoreFlags{}, restoreTarget{}},
		{"cluster-init install", installedEtcd, restoreFlags{},
			restoreTarget{etcd: true, name: "studio", peerIP: "192.0.2.10", peerPort: 2390}},
		{"server-join install, flags win", []string{"--server-join=true", "--etcd-peer-ip", "192.0.2.10"},
			restoreFlags{nodeName: "b", peerIP: "192.0.2.11", peerPort: 2400},
			restoreTarget{etcd: true, name: "b", peerIP: "192.0.2.11", peerPort: 2400}},
		{"--cluster-init=false is the kine posture", []string{"--cluster-init=false"}, restoreFlags{}, restoreTarget{}},
		{"no install, --etcd-peer-ip given", nil, restoreFlags{peerIP: "192.0.2.12", nodeName: "c"},
			restoreTarget{etcd: true, name: "c", peerIP: "192.0.2.12", peerPort: executor.DefaultEtcdPeerPort}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveRestoreTarget(tc.installed, tc.flags)
			got.identitySource = ""
			if got != tc.want {
				t.Errorf("resolveRestoreTarget = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestRestoreDispatchesByPosture: an etcd-configured server takes the etcd restore
// with its identity; an unconfigured work dir that holds a member is refused with the
// flag to pass; everything else takes the kine restore.
func TestRestoreDispatchesByPosture(t *testing.T) {
	var gotEtcd *executor.EtcdRestoreOptions
	kineCalled := false
	r := snapshotRestorers{
		etcdMember: func(string) bool { return true },
		etcd: func(_ context.Context, o executor.EtcdRestoreOptions) (*executor.EtcdRestoreResult, error) {
			gotEtcd = &o
			return &executor.EtcdRestoreResult{Snapshot: o.Snapshot, MemberName: o.Name, PeerURL: "https://192.0.2.10:2390",
				RevisionBump: executor.EtcdRestoreRevisionBump, PreviousDataDir: "/wd/etcd.restore-x.bak"}, nil
		},
		kine: func(context.Context, executor.SnapshotRestoreOptions) (*executor.SnapshotRestoreResult, error) {
			kineCalled = true
			return &executor.SnapshotRestoreResult{}, nil
		},
	}
	var out bytes.Buffer
	req := restoreRequest{workDir: "/wd", snapshot: "/s.db", payloadBinDir: "/Library/k3sm/bin",
		target: restoreTarget{etcd: true, name: "studio", peerIP: "192.0.2.10", peerPort: 2390}}
	if err := restoreSnapshot(context.Background(), &out, req, r); err != nil {
		t.Fatal(err)
	}
	if gotEtcd == nil || gotEtcd.Name != "studio" || gotEtcd.PeerIP != "192.0.2.10" || gotEtcd.PeerPort != 2390 || gotEtcd.PayloadBinDir != "/Library/k3sm/bin" || kineCalled {
		t.Fatalf("etcd dispatch got %+v (kine called %v)", gotEtcd, kineCalled)
	}
	for _, want := range []string{"only member of a NEW cluster", "relists", "etcd.restore-x.bak", "Re-join every OTHER server", "--server-join"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("etcd restore report lacks %q:\n%s", want, out.String())
		}
	}

	req.target = restoreTarget{}
	if err := restoreSnapshot(context.Background(), &out, req, r); !errors.Is(err, executor.ErrEtcdRestoreNeedsEtcd) || !strings.Contains(err.Error(), "--etcd-peer-ip") {
		t.Fatalf("unconfigured member restore = %v, want ErrEtcdRestoreNeedsEtcd naming --etcd-peer-ip", err)
	}
	r.etcdMember = func(string) bool { return false }
	if err := restoreSnapshot(context.Background(), &out, req, r); err != nil || !kineCalled {
		t.Fatalf("kine restore = %v (called %v)", err, kineCalled)
	}
}

// snapSentinel is written into every fake snapshot's bytes; ls must never print it.
const snapSentinel = "SNAPSHOT-BYTES-SENTINEL-5e1f"

// fakeSnapDir is a snapshots directory for node-a, with the files ls, delete and
// prune must tell apart, and the retention key spelled out on each scheduled one.
type fakeSnapDir struct {
	dir string
	now time.Time
	// keep are the five scheduled snapshots the default retention keeps; drop the
	// three it prunes; untouchable every regular file prune must never remove.
	keep, drop, untouchable []string
	linkTarget              string
}

func newFakeSnapDir(t *testing.T) *fakeSnapDir {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	f := &fakeSnapDir{dir: filepath.Join(t.TempDir(), "snapshots"), now: now}
	if err := os.Mkdir(f.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name string, mtime time.Time) {
		t.Helper()
		p := filepath.Join(f.dir, name)
		if err := os.WriteFile(p, []byte(snapSentinel), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	sched := func(stamp, mtime time.Time, zip bool) string {
		n := executor.ScheduledEtcdSnapshotName("node-a", stamp)
		if zip {
			n += ".zip"
		}
		write(n, mtime)
		return n
	}
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	f.keep = []string{
		sched(ago(time.Hour), ago(time.Hour), false),
		sched(ago(2*time.Hour), ago(2*time.Hour), false),
		sched(ago(3*time.Hour), ago(3*time.Hour), true),
		sched(ago(4*time.Hour), ago(4*time.Hour), false),
		sched(ago(5*time.Hour), ago(5*time.Hour), false),
	}
	f.drop = []string{
		sched(ago(6*time.Hour), ago(6*time.Hour), false),
		// The name says 30 minutes ago, the mtime 10 hours: the earlier one orders it.
		sched(ago(30*time.Minute), ago(10*time.Hour), false),
		// Written under a clock two days ahead: sorts as the oldest.
		sched(now.Add(48*time.Hour), now.Add(48*time.Hour), false),
	}
	other := []string{
		executor.ScheduledEtcdSnapshotName("node-b", ago(100*time.Hour)),
		"k3sm-etcd-snapshot-20200101T000000Z.db",
		"k3sm-snapshot-20200101T000000Z.zip",
		"evil\x1b[31m\r\n.db",
		executor.ScheduledEtcdSnapshotName("node-a", ago(200*time.Hour)) + ".tmp",
		"k3sm-snapshot-20200101T000000Z.zip.plain.tmp",
	}
	for _, n := range other {
		write(n, ago(100*time.Hour))
	}
	f.untouchable = append(slices.Clone(f.keep), other...)
	f.linkTarget = filepath.Join(f.dir, "k3sm-etcd-snapshot-20200101T000000Z.db")
	// A symlink of the scheduled shape, older than everything, pointing at a sibling.
	if err := os.Symlink(f.linkTarget, filepath.Join(f.dir, executor.ScheduledEtcdSnapshotName("node-a", ago(300*time.Hour)))); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(f.linkTarget, filepath.Join(f.dir, "link-to-manual")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(f.dir, executor.ScheduledEtcdSnapshotName("node-a", ago(400*time.Hour))), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(f.dir, "a-directory"), 0o700); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fakeSnapDir) manager() snapshotManager {
	return snapshotManager{owners: []uint32{0}, euid: uint32(os.Geteuid()), now: func() time.Time { return f.now }}
}

func (f *fakeSnapDir) exists(name string) bool {
	_, err := os.Lstat(filepath.Join(f.dir, name))
	return err == nil
}

// entries is the directory's names, for "nothing changed" checks.
func (f *fakeSnapDir) entries(t *testing.T) []string {
	t.Helper()
	es, err := os.ReadDir(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

// TestSnapshotListDeletePrune is the gate for `k3sm snapshot ls | delete | prune`:
// ls reports metadata only, with each file's kind, and skips what is not a final-name
// regular file; delete removes only bare-named regular files confined to the snapshots
// directory; prune keeps the newest N of this node's scheduled snapshots by the
// schedule's own retention key and never touches anything else.
func TestSnapshotListDeletePrune(t *testing.T) {
	t.Run("ls", func(t *testing.T) {
		f := newFakeSnapDir(t)
		var js bytes.Buffer
		if err := listSnapshots(&js, f.dir, "node-a", "json", f.manager()); err != nil {
			t.Fatal(err)
		}
		var infos []executor.SnapshotInfo
		if err := json.Unmarshal(js.Bytes(), &infos); err != nil {
			t.Fatalf("ls -o json is not JSON: %v\n%s", err, js.String())
		}
		got := map[string]executor.SnapshotInfo{}
		for _, in := range infos {
			got[in.Name] = in
		}
		kinds := []struct {
			name       string
			kind       executor.SnapshotKind // "" = not listed
			compressed bool
		}{
			{f.keep[0], executor.SnapshotScheduled, false},
			{f.keep[2], executor.SnapshotScheduled, true},
			{f.drop[2], executor.SnapshotScheduled, false},
			{executor.ScheduledEtcdSnapshotName("node-b", f.now.Add(-100*time.Hour)), executor.SnapshotOther, false},
			{"k3sm-etcd-snapshot-20200101T000000Z.db", executor.SnapshotManual, false},
			{"k3sm-snapshot-20200101T000000Z.zip", executor.SnapshotManual, true},
			{"evil\x1b[31m\r\n.db", executor.SnapshotOther, false},
			{executor.ScheduledEtcdSnapshotName("node-a", f.now.Add(-200*time.Hour)) + ".tmp", "", false},
			{"k3sm-snapshot-20200101T000000Z.zip.plain.tmp", "", false},
			{executor.ScheduledEtcdSnapshotName("node-a", f.now.Add(-300*time.Hour)), "", false},
			{"link-to-manual", "", false},
			{executor.ScheduledEtcdSnapshotName("node-a", f.now.Add(-400*time.Hour)), "", false},
			{"a-directory", "", false},
		}
		for _, k := range kinds {
			in, ok := got[k.name]
			switch {
			case k.kind == "" && ok:
				t.Errorf("ls listed %q, which is not a final-name regular file", k.name)
			case k.kind != "" && !ok:
				t.Errorf("ls did not list %q", k.name)
			case ok && (in.Kind != k.kind || in.Compressed != k.compressed || in.Size != int64(len(snapSentinel))):
				t.Errorf("%q = kind %s compressed %v size %d, want %s %v %d", k.name, in.Kind, in.Compressed, in.Size, k.kind, k.compressed, len(snapSentinel))
			}
		}
		if len(infos) != 12 {
			t.Errorf("ls listed %d files, want 12 (8 scheduled, 1 other node, 2 manual, 1 unrecognised)", len(infos))
		}
		if !got[f.drop[1]].Created.Equal(f.now.Add(-10*time.Hour)) || !got[f.drop[2]].Created.IsZero() {
			t.Errorf("created is not the retention key: %v, %v", got[f.drop[1]].Created, got[f.drop[2]].Created)
		}
		var text bytes.Buffer
		if err := listSnapshots(&text, f.dir, "node-a", "text", f.manager()); err != nil {
			t.Fatal(err)
		}
		for _, out := range []string{text.String(), js.String()} {
			if strings.Contains(out, snapSentinel) {
				t.Errorf("ls printed bytes from inside a snapshot:\n%s", out)
			}
		}
		if strings.ContainsAny(text.String(), "\x1b\r") {
			t.Errorf("ls text printed a raw control character:\n%q", text.String())
		}
		if !strings.Contains(text.String(), `"evil\x1b[31m\r\n.db"`) {
			t.Errorf("ls text does not show the control-character name escaped:\n%s", text.String())
		}
		if err := listSnapshots(&text, f.dir, "node-a", "yaml", f.manager()); err == nil {
			t.Error("ls -o yaml was accepted")
		}
		for format, want := range map[string]string{"json": "[]\n", "text": "No snapshots in"} {
			var out bytes.Buffer
			if err := listSnapshots(&out, filepath.Join(f.dir, "missing"), "node-a", format, f.manager()); err != nil || !strings.Contains(out.String(), want) {
				t.Errorf("ls -o %s of a missing directory = %q (%v), want an empty list", format, out.String(), err)
			}
		}
	})

	t.Run("delete refuses a name that is not a bare file name", func(t *testing.T) {
		f := newFakeSnapDir(t)
		outside := filepath.Join(filepath.Dir(f.dir), "x")
		if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
			t.Fatal(err)
		}
		before := f.entries(t)
		for _, name := range []string{"../x", "a/b", outside, "/abs", ".", "..", "", "-x", "a\x00b"} {
			// A valid name beside the bad one: one bad name refuses the whole command.
			err := deleteSnapshots(io.Discard, f.dir, []string{f.keep[0], name}, f.manager())
			if !errors.Is(err, errSnapshotName) {
				t.Errorf("delete %q = %v, want errSnapshotName", name, err)
			}
		}
		if !slices.Equal(f.entries(t), before) {
			t.Errorf("a refused delete changed the directory: %v, was %v", f.entries(t), before)
		}
		if _, err := os.Stat(outside); err != nil {
			t.Errorf("the file outside the snapshots directory was removed: %v", err)
		}
	})

	t.Run("delete removes only regular final-name files", func(t *testing.T) {
		cases := []struct {
			name    string
			wantErr error
		}{
			// Shapes k3sm writes that are not regular final-name files: refused at Lstat.
			{executor.ScheduledEtcdSnapshotName("node-a", time.Unix(1_800_000_000, 0).Add(-300*time.Hour)), errSnapshotNotRemovable},
			{executor.ScheduledEtcdSnapshotName("node-a", time.Unix(1_800_000_000, 0).Add(-400*time.Hour)), errSnapshotNotRemovable},
			// Names k3sm does not give a snapshot: refused before any filesystem call.
			{"link-to-manual", errSnapshotUnrecognised},
			{"a-directory", errSnapshotUnrecognised},
			{executor.ScheduledEtcdSnapshotName("node-a", time.Unix(1_800_000_000, 0).Add(-200*time.Hour)) + ".tmp", errSnapshotUnrecognised},
			{"k3sm-snapshot-20200101T000000Z.zip.plain.tmp", errSnapshotUnrecognised},
			{"evil\x1b[31m\r\n.db", errSnapshotUnrecognised},
			{"k3sm-etcd-snapshot-20200101T000000Z.db.sha256", errSnapshotUnrecognised},
			{"foo.db", errSnapshotUnrecognised},
			// Shapes k3sm writes, as regular files: removed.
			{"k3sm-snapshot-20200101T000000Z.zip", nil},
			{executor.ScheduledEtcdSnapshotName("node-b", time.Unix(1_800_000_000, 0).Add(-100*time.Hour)), nil},
		}
		for _, tc := range cases {
			t.Run(strconv.Quote(tc.name), func(t *testing.T) {
				f := newFakeSnapDir(t)
				for _, extra := range []string{"k3sm-etcd-snapshot-20200101T000000Z.db.sha256", "foo.db"} {
					if err := os.WriteFile(filepath.Join(f.dir, extra), []byte(snapSentinel), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				var out bytes.Buffer
				err := deleteSnapshots(&out, f.dir, []string{tc.name}, f.manager())
				if !errors.Is(err, tc.wantErr) || (tc.wantErr == nil) != (err == nil) {
					t.Fatalf("delete %q = %v, want %v", tc.name, err, tc.wantErr)
				}
				if tc.wantErr != nil && !f.exists(tc.name) {
					t.Errorf("a refused delete removed %q", tc.name)
				}
				if tc.wantErr == nil && (f.exists(tc.name) || !strings.Contains(out.String(), "removed")) {
					t.Errorf("delete %q did not remove it: %s", tc.name, out.String())
				}
				if b, err := os.ReadFile(f.linkTarget); err != nil || string(b) != snapSentinel {
					t.Errorf("the symlink's target did not survive: %q %v", b, err)
				}
				if strings.ContainsAny(out.String(), "\x1b\r") || (err != nil && strings.ContainsAny(err.Error(), "\x1b\r")) {
					t.Errorf("delete printed or returned a raw control character: %q, %v", out.String(), err)
				}
			})
		}
	})

	t.Run("delete twice succeeds and says the file is gone", func(t *testing.T) {
		f := newFakeSnapDir(t)
		name := "k3sm-etcd-snapshot-20200101T000000Z.db"
		if err := deleteSnapshots(io.Discard, f.dir, []string{name}, f.manager()); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := deleteSnapshots(&out, f.dir, []string{name}, f.manager()); err != nil || !strings.Contains(out.String(), "already gone") {
			t.Fatalf("second delete = %v %q, want success with an already-gone line", err, out.String())
		}
		// One bad target among good ones: the good one goes, the command fails.
		dir := executor.ScheduledEtcdSnapshotName("node-a", f.now.Add(-400*time.Hour))
		err := deleteSnapshots(io.Discard, f.dir, []string{f.keep[0], dir}, f.manager())
		if !errors.Is(err, errSnapshotNotRemovable) || f.exists(f.keep[0]) || !f.exists(dir) {
			t.Fatalf("mixed delete = %v (kept %v, dir %v), want a failure that removed only the snapshot", err, f.exists(f.keep[0]), f.exists(dir))
		}
		// An unrecognised name among good ones refuses the whole command.
		err = deleteSnapshots(io.Discard, f.dir, []string{f.keep[1], "foo.db"}, f.manager())
		if !errors.Is(err, errSnapshotUnrecognised) || !f.exists(f.keep[1]) {
			t.Fatalf("delete with an unrecognised name = %v (kept %v), want a refusal that removed nothing", err, f.exists(f.keep[1]))
		}
	})

	t.Run("a filesystem error carries the name sanitized, never the raw path error", func(t *testing.T) {
		name := "evil\x1b[31m\r\n.db"
		err := snapshotFileError(name, &fs.PathError{Op: "unlinkat", Path: name, Err: syscall.EACCES})
		if strings.ContainsAny(err.Error(), "\x1b\r") || !strings.Contains(err.Error(), strconv.QuoteToASCII(name)) {
			t.Errorf("error = %q, want the name escaped and nothing raw", err.Error())
		}
		if !errors.Is(err, syscall.EACCES) {
			t.Errorf("error %v lost the underlying errno", err)
		}
		if _, ok := errors.AsType[*fs.PathError](err); ok {
			t.Errorf("error %v still carries the raw *fs.PathError", err)
		}
	})

	t.Run("delete and prune refuse an unsafe snapshots directory", func(t *testing.T) {
		me := uint32(os.Geteuid())
		for _, tc := range []struct {
			name   string
			mode   os.FileMode
			owners []uint32
			euid   uint32
		}{
			{"group-writable", 0o770, []uint32{0}, me},
			{"world-writable", 0o707, []uint32{0}, me},
			{"owned by neither root, the service user nor the invoking user", 0o700, []uint32{me + 1}, me + 2},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := newFakeSnapDir(t)
				if err := os.Chmod(f.dir, tc.mode); err != nil {
					t.Fatal(err)
				}
				m := f.manager()
				m.owners, m.euid = tc.owners, tc.euid
				before := f.entries(t)
				if err := deleteSnapshots(io.Discard, f.dir, []string{f.keep[0]}, m); !errors.Is(err, errSnapshotDirUnsafe) {
					t.Errorf("delete = %v, want errSnapshotDirUnsafe", err)
				}
				if err := pruneSnapshots(io.Discard, f.dir, "node-a", 1, false, m); !errors.Is(err, errSnapshotDirUnsafe) {
					t.Errorf("prune = %v, want errSnapshotDirUnsafe", err)
				}
				fi, err := os.Stat(f.dir)
				if !slices.Equal(f.entries(t), before) || err != nil || fi.Mode().Perm() != tc.mode {
					t.Errorf("a refusal changed the directory or its mode (%v)", fi.Mode().Perm())
				}
			})
		}
	})

	t.Run("delete and prune accept a directory the invoking user owns", func(t *testing.T) {
		// A rootless `k3sm dev` cluster: neither root nor the service user owns it.
		f := newFakeSnapDir(t)
		m := f.manager()
		m.owners, m.euid = []uint32{uint32(os.Geteuid()) + 1}, uint32(os.Geteuid())
		if err := deleteSnapshots(io.Discard, f.dir, []string{f.keep[0]}, m); err != nil || f.exists(f.keep[0]) {
			t.Errorf("delete in a user-owned directory = %v (still there: %v), want it removed", err, f.exists(f.keep[0]))
		}
		var out bytes.Buffer
		if err := pruneSnapshots(&out, f.dir, "node-a", executor.DefaultEtcdSnapshotRetention, false, m); err != nil ||
			!strings.Contains(out.String(), "7 scheduled snapshots for node node-a, 2 pruned") {
			t.Errorf("prune in a user-owned directory = %v %q, want 2 pruned", err, out.String())
		}
	})

	t.Run("prune", func(t *testing.T) {
		cases := []struct {
			name      string
			retention int
			dryRun    bool
			wantGone  func(f *fakeSnapDir) []string
			wantOut   string
		}{
			{"default retention keeps the newest five by the retention key", executor.DefaultEtcdSnapshotRetention, false,
				func(f *fakeSnapDir) []string { return f.drop }, "8 scheduled snapshots for node node-a, 3 pruned"},
			{"retention 2", 2, false,
				func(f *fakeSnapDir) []string { return append(slices.Clone(f.keep[2:]), f.drop...) }, "8 scheduled snapshots for node node-a, 6 pruned"},
			{"dry run removes nothing", executor.DefaultEtcdSnapshotRetention, true,
				func(*fakeSnapDir) []string { return nil }, "3 would be pruned (dry run, nothing removed)"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				f := newFakeSnapDir(t)
				var out bytes.Buffer
				if err := pruneSnapshots(&out, f.dir, "node-a", tc.retention, tc.dryRun, f.manager()); err != nil {
					t.Fatalf("prune = %v\n%s", err, out.String())
				}
				if !strings.Contains(out.String(), tc.wantOut) {
					t.Errorf("prune output lacks %q:\n%s", tc.wantOut, out.String())
				}
				gone := tc.wantGone(f)
				for _, n := range append(slices.Clone(f.untouchable), f.drop...) {
					if want := !slices.Contains(gone, n); f.exists(n) != want {
						t.Errorf("after prune %q exists = %v, want %v", n, f.exists(n), want)
					}
				}
				for _, n := range []string{"link-to-manual", "a-directory",
					executor.ScheduledEtcdSnapshotName("node-a", f.now.Add(-300*time.Hour)),
					executor.ScheduledEtcdSnapshotName("node-a", f.now.Add(-400*time.Hour))} {
					if !f.exists(n) {
						t.Errorf("prune removed %q, which is not a regular file", n)
					}
				}
				if tc.dryRun && !strings.Contains(out.String(), "would remove "+f.drop[0]) {
					t.Errorf("dry run does not name what it would remove:\n%s", out.String())
				}
			})
		}
	})

	t.Run("prune rejects a retention below one", func(t *testing.T) {
		f := newFakeSnapDir(t)
		before := f.entries(t)
		if err := pruneSnapshots(io.Discard, f.dir, "node-a", 0, false, f.manager()); !errors.Is(err, executor.ErrEtcdSnapshotRetention) {
			t.Errorf("prune retention 0 = %v, want ErrEtcdSnapshotRetention", err)
		}
		if err := runSnapshotPrune([]string{"--work-dir", filepath.Dir(f.dir), "--node-name", "node-a", "--snapshot-retention", "0"}, io.Discard); !errors.Is(err, executor.ErrEtcdSnapshotRetention) {
			t.Errorf("prune --snapshot-retention 0 = %v, want ErrEtcdSnapshotRetention", err)
		}
		if !slices.Equal(f.entries(t), before) {
			t.Error("a rejected prune changed the directory")
		}
	})

	t.Run("prune on a kine posture is a visible no-op", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "snapshots")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		manual := filepath.Join(dir, "k3sm-snapshot-20200101T000000Z.db")
		if err := os.WriteFile(manual, []byte(snapSentinel), 0o600); err != nil {
			t.Fatal(err)
		}
		f := &fakeSnapDir{dir: dir, now: time.Unix(1_800_000_000, 0)}
		var out bytes.Buffer
		if err := pruneSnapshots(&out, dir, "node-a", 1, false, f.manager()); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "0 scheduled snapshots for node node-a, 0 pruned") {
			t.Errorf("kine prune output = %q, want the visible no-op", out.String())
		}
		if _, err := os.Stat(manual); err != nil {
			t.Errorf("prune removed a manual kine snapshot: %v", err)
		}
		out.Reset()
		if err := pruneSnapshots(&out, filepath.Join(dir, "missing"), "node-a", 1, false, f.manager()); err != nil ||
			!strings.Contains(out.String(), "0 scheduled snapshots for node node-a, 0 pruned") {
			t.Errorf("prune of a missing directory = %v %q, want the visible no-op", err, out.String())
		}
	})
}
