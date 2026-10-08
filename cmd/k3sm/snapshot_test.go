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
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
			etcd: func(_ context.Context, _ string, dst string) error {
				*calls = append(*calls, "etcd "+dst)
				return etcdErr
			},
			sqlite: func(_ context.Context, opts executor.SnapshotSaveOptions) (*executor.SnapshotSaveResult, error) {
				*calls = append(*calls, "sqlite "+opts.Out)
				return &executor.SnapshotSaveResult{Path: "x", SourceDB: "y", Checkpointed: true}, nil
			},
			now: func() time.Time { return at },
		}
	}

	t.Run("etcd member, default destination", func(t *testing.T) {
		wd := t.TempDir()
		var calls []string
		var out strings.Builder
		if err := saveSnapshot(context.Background(), &out, wd, "", newSavers(true, &calls, nil)); err != nil {
			t.Fatalf("save: %v", err)
		}
		want := filepath.Join(executor.SnapshotDir(wd), "k3sm-etcd-snapshot-20261002T120000Z.db")
		if len(calls) != 1 || calls[0] != "etcd "+want {
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
		if err := saveSnapshot(context.Background(), io.Discard, t.TempDir(), dst, newSavers(true, &calls, nil)); err != nil {
			t.Fatalf("save: %v", err)
		}
		if len(calls) != 1 || calls[0] != "etcd "+dst {
			t.Errorf("calls = %v, want one etcd save to %s", calls, dst)
		}
	})

	t.Run("etcd failure keeps its sentinel", func(t *testing.T) {
		var calls []string
		err := saveSnapshot(context.Background(), io.Discard, t.TempDir(), "", newSavers(true, &calls, executor.ErrNoEtcdClient))
		if !errors.Is(err, executor.ErrNoEtcdClient) || !strings.Contains(err.Error(), "start the server") {
			t.Errorf("err = %v, want ErrNoEtcdClient with the remedy", err)
		}
	})

	t.Run("kine posture", func(t *testing.T) {
		var calls []string
		if err := saveSnapshot(context.Background(), io.Discard, t.TempDir(), "/x/out.db", newSavers(false, &calls, nil)); err != nil {
			t.Fatalf("save: %v", err)
		}
		if len(calls) != 1 || calls[0] != "sqlite /x/out.db" {
			t.Errorf("calls = %v, want one SQLite save", calls)
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
