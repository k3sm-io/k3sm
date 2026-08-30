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
	"net"
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
// fail with usage, and the usage states the single-node scope and the pg_dump answer.
func TestSnapshotDispatch(t *testing.T) {
	err := runSnapshot(nil)
	if err == nil {
		t.Fatal("k3sm snapshot with no subcommand succeeded")
	}
	for _, want := range []string{"snapshot save", "snapshot restore", "pg_dump", "PersistentVolume"} {
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
