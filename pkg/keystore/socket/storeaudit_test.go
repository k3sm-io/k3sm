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

package socket

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"testing/synctest"

	"k3sm.io/k3sm/pkg/keystore"
	"k3sm.io/runtimed/pkg/keystorepaths"
)

// sfAppend is SF_APPEND (<sys/stat.h>), the flag every judged log carries;
// x/sys/unix defines it on darwin only, and this rig reports it on any OS.
const sfAppend = 0x00040000

// storeRig is a real store over a data root in t.TempDir(), laid out as
// install leaves it, with the test user standing in for root and for the
// service user and a flag source that reads every log as SF_APPEND
// (keystore.Config's test seams), and the server's append surface over it.
type storeRig struct {
	data string
	fs   *keystore.FileStore
	logs *keystore.ServerLogs
}

func newStoreRig(t *testing.T) *storeRig {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("the test user stands in for the service user, which is never root")
	}
	data := t.TempDir()
	mkdir := func(p string, mode os.FileMode) {
		t.Helper()
		if err := os.Mkdir(p, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	mkdir(filepath.Join(data, "server"), 0o700)
	mkdir(filepath.Join(data, "server", "keystore"), 0o700)
	mkdir(filepath.Join(data, keystorepaths.SockDir), 0o755)
	mkdir(filepath.Join(data, keystore.LogsDirName), 0o755)
	for _, d := range []string{keystore.FloorDirName, keystore.AuditDirName} {
		mkdir(filepath.Join(data, keystore.LogsDirName, d), 0o755)
	}
	r := &storeRig{data: data}
	r.writeLog(t, r.auditPath(), nil)
	r.writeLog(t, r.floorPath(), nil)
	uid, gid := os.Getuid(), os.Getgid()
	r.fs = keystore.New(keystore.Config{
		Dir:       filepath.Join(data, "server", "keystore"),
		MasterDir: filepath.Join(data, "server", "cred", "keystore-master"),
		UID:       uint32(uid), GID: uint32(gid),
		DataRoot: data,
		FloorUID: uid, FloorGID: gid,
		LogFlags: func(*os.File) (uint32, error) { return sfAppend, nil },
	})
	r.logs = r.fs.ServerLogs()
	t.Cleanup(func() { _ = r.logs.Close() })
	return r
}

func (r *storeRig) auditPath() string {
	return filepath.Join(r.data, keystore.LogsDirName, keystore.AuditDirName, keystore.AuditLogName)
}

func (r *storeRig) floorPath() string {
	return filepath.Join(r.data, keystore.LogsDirName, keystore.FloorDirName, keystore.UserFloorLogName)
}

func (r *storeRig) markerPath() string { return filepath.Join(r.data, keystore.MaintenanceMarkerName) }

// writeLog creates the log at p, 0600, holding b.
func (r *storeRig) writeLog(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
}

// swap stands in for a maintenance verb's swap of one log directory: a
// replacement directory holding a fresh log with b is built beside it and
// swapped in by rename, the retired one kept by name. It returns the
// retired log's path.
func (r *storeRig) swap(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	logs := filepath.Join(r.data, keystore.LogsDirName)
	staged := filepath.Join(logs, dir+".new")
	if err := os.Mkdir(staged, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(staged, 0o755); err != nil {
		t.Fatal(err)
	}
	r.writeLog(t, filepath.Join(staged, name), b)
	retired := filepath.Join(logs, dir+".old")
	if err := os.Rename(filepath.Join(logs, dir), retired); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(staged, filepath.Join(logs, dir)); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(retired, name)
}

// auditEntry is what a test reads back of one audit line.
type auditEntry struct {
	Op     string `json:"op"`
	Via    string `json:"via"`
	Caller struct {
		UID uint32 `json:"uid"`
	} `json:"caller"`
	Scope   string `json:"scope"`
	Name    string `json:"name"`
	Result  string `json:"result"`
	Charge  string `json:"charge"`
	Source  string `json:"source"`
	Dropped uint64 `json:"dropped"`
}

// readAudit returns the lines of the log at p, the empty ones skipped,
// and the pre-frame bytes they charge: each line, its newline and the
// leading newline its append wrote.
func readAudit(t *testing.T, p string) ([]auditEntry, int64) {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var out []auditEntry
	var charged int64
	for line := range bytes.SplitSeq(b, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var e auditEntry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("%s: a line does not parse: %v: %q", p, err, line)
		}
		if e.Op == "refused" && e.Via == "socket" && e.Charge == "reconciler" && e.Source == "pre-frame" {
			charged += int64(len(line)) + 2
		}
		out = append(out, e)
	}
	return out, charged
}

// refusedOf returns the refusals among lines, and the summaries.
func refusedOf(t *testing.T, lines []auditEntry) ([]refusal, []drop) {
	t.Helper()
	var rs []refusal
	var ds []drop
	for _, e := range lines {
		if e.Op != "refused" || e.Via != "socket" || e.Scope != "" || e.Name != "" || e.Charge != "reconciler" || e.Source != "pre-frame" {
			t.Fatalf("not a pre-frame line: %+v", e)
		}
		if e.Result == "dropped" {
			ds = append(ds, drop{e.Caller.UID, e.Dropped})
			continue
		}
		rs = append(rs, refusal{e.Caller.UID, e.Result})
	}
	return rs, ds
}

// preFrameLine is a pre-frame line of uid 0's as the server writes it in
// a synctest bubble: what another writer can append to use the budget.
const preFrameLine = `{"v":1,"ts":"2000-01-01T00:00:00Z","op":"refused","via":"socket","caller":{"uid":0},"scope":"","name":"","namespace":"","result":"root","charge":"reconciler","source":"pre-frame"}`

// fullBudget is pre-frame lines, each led by a newline, filling
// keystore.PreFrameBudget until no further one fits.
func fullBudget() []byte {
	one := "\n" + preFrameLine + "\n"
	return bytes.Repeat([]byte(one), keystore.PreFrameBudget/len(one))
}

func newStoreAuditor(t *testing.T, logs RefusalLog) *StoreAuditor {
	t.Helper()
	a, err := NewStoreAuditor(logs, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// teeAuditor passes every call to both auditors.
type teeAuditor struct{ a, b RefusalAuditor }

func (t teeAuditor) Refused(uid uint32, reason string) {
	t.a.Refused(uid, reason)
	t.b.Refused(uid, reason)
}
func (t teeAuditor) Dropped(uid uint32, n uint64) { t.a.Dropped(uid, n); t.b.Dropped(uid, n) }

// flushPending passes the minute pass's flush to whichever auditor keeps
// pending counts.
func (t teeAuditor) flushPending(ctx context.Context) {
	for _, a := range []RefusalAuditor{t.a, t.b} {
		if f, ok := a.(pendingFlusher); ok {
			f.flushPending(ctx)
		}
	}
}

func size(t *testing.T, p string) int64 {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

func TestNewStoreAuditorRefusesNil(t *testing.T) {
	if _, err := NewStoreAuditor(nil, slog.New(slog.DiscardHandler)); err == nil {
		t.Error("NewStoreAuditor took a nil log")
	}
	if _, err := NewStoreAuditor(newStoreRig(t).logs, nil); err == nil {
		t.Error("NewStoreAuditor took a nil logger")
	}
}

// TestAppendReopensOnInodeMismatch is U99: with no marker ever written, an
// audit --rotate and a floor --rebuild each swap a log under the server,
// and the next append compares its descriptors with the canonical names,
// reopens both and recounts the budget from the new audit file, so every
// later line lands in the new canonical file and none in the retired one.
func TestAppendReopensOnInodeMismatch(t *testing.T) {
	r := newStoreRig(t)
	a := newStoreAuditor(t, r.logs)
	a.Refused(0, ReasonRoot)
	if got, _ := readAudit(t, r.auditPath()); len(got) != 1 {
		t.Fatalf("first file holds %d lines, want 1", len(got))
	}
	audit0, floor0 := r.logs.Files()

	// audit --rotate, unseen: the new log already holds one pre-frame line
	// another writer put there, which the recount charges.
	seeded := []byte("\n" + preFrameLine + "\n")
	oldAudit := r.swap(t, keystore.AuditDirName, keystore.AuditLogName, seeded)
	retiredSize := size(t, oldAudit)
	a.Refused(77, ReasonSystemUID)
	audit1, floor1 := r.logs.Files()
	if audit1 == audit0 || floor1 != floor0 {
		t.Fatalf("after the audit swap the held files are %v, %v; want a new audit file and the same floor (were %v, %v)", audit1, floor1, audit0, floor0)
	}
	if n := size(t, oldAudit); n != retiredSize {
		t.Fatalf("the retired audit log grew from %d to %d bytes", retiredSize, n)
	}
	lines, charged := readAudit(t, r.auditPath())
	if rs, _ := refusedOf(t, lines); !slices.Equal(rs, []refusal{{0, ReasonRoot}, {77, ReasonSystemUID}}) {
		t.Fatalf("new audit log refusals = %v", rs)
	}
	// Recounted from the new file before the append, then charged the
	// append: the seeded line and the refusal, nothing of the retired
	// file's.
	if got, want := r.logs.PreFrameUsed(), charged; got != want || got != size(t, r.auditPath()) {
		t.Fatalf("budget used after the reopen = %d, want the new file's %d", got, want)
	}

	// floor --rebuild, unseen: the floor descriptor is reopened at the next
	// append too, and the audit file is unchanged.
	oldFloor := r.swap(t, keystore.FloorDirName, keystore.UserFloorLogName, nil)
	a.Dropped(77, 4)
	audit2, floor2 := r.logs.Files()
	if audit2 != audit1 || floor2 == floor1 {
		t.Fatalf("after the floor swap the held files are %v, %v; want the same audit file and a new floor (were %v, %v)", audit2, floor2, audit1, floor1)
	}
	if n := size(t, oldFloor); n != 0 {
		t.Fatalf("the retired floor holds %d bytes", n)
	}
	if n := size(t, oldAudit); n != retiredSize {
		t.Fatalf("the retired audit log grew from %d to %d bytes", retiredSize, n)
	}
	lines, _ = readAudit(t, r.auditPath())
	rs, ds := refusedOf(t, lines)
	if !slices.Equal(rs, []refusal{{0, ReasonRoot}, {77, ReasonSystemUID}}) || !slices.Equal(ds, []drop{{77, 4}}) {
		t.Fatalf("new audit log = %v, summaries %v", rs, ds)
	}
	// Each append first counts what the file holds, then charges what it
	// wrote: the next one leaves every line of the new file charged, and
	// only those.
	if err := r.logs.Refused(t.Context(), 600, ReasonServiceUID); err != nil {
		t.Fatal(err)
	}
	if _, charged = readAudit(t, r.auditPath()); r.logs.PreFrameUsed() != charged {
		got := r.logs.PreFrameUsed()
		t.Fatalf("budget used %d, want the new file's %d", got, charged)
	}
}

// TestMaintenanceReopensLogsAndResetsShares is U22's socket half: once the
// marker is gone the server takes the store lock exclusively, reopens both
// append descriptors and recounts from the new files before it reports
// the marker clear, so the counts reset; while the lock is held elsewhere
// it does not report clear, and the listener stays down.
func TestMaintenanceReopensLogsAndResetsShares(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newStoreRig(t)
		r.writeLog(t, r.auditPath(), fullBudget())
		// gate is the supervisor's marker read then its log reopen, as
		// Preconditions runs them.
		gate := func() (bool, error) {
			if marked, err := r.logs.MaintenanceMarked(); err != nil || marked {
				return marked, err
			}
			return false, r.logs.Reopen(context.Background())
		}
		a := newStoreAuditor(t, r.logs)
		if marked, err := gate(); err != nil || marked {
			t.Fatalf("gate at start = %v, %v", marked, err)
		}
		full := r.logs.PreFrameUsed()
		if full == 0 || full+int64(len(preFrameLine))+2 <= keystore.PreFrameBudget {
			t.Fatalf("budget used at start = %d of %d, want it spent", full, keystore.PreFrameBudget)
		}
		before := size(t, r.auditPath())
		a.Refused(0, ReasonRoot) // past the budget: dropped and counted
		if n := size(t, r.auditPath()); n != before {
			t.Fatalf("a line past the budget was written: %d -> %d bytes", before, n)
		}
		if got := r.logs.PendingDropped(0); got != 1 {
			t.Fatalf("dropped count = %d, want 1", got)
		}
		audit0, floor0 := r.logs.Files()

		// The verb runs: marker, then both swaps.
		if err := os.WriteFile(r.markerPath(), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		if marked, err := gate(); err != nil || !marked {
			t.Fatalf("gate under the marker = %v, %v", marked, err)
		}
		oldAudit := r.swap(t, keystore.AuditDirName, keystore.AuditLogName, nil)
		r.swap(t, keystore.FloorDirName, keystore.UserFloorLogName, nil)
		if err := os.Remove(r.markerPath()); err != nil {
			t.Fatal(err)
		}

		// The store lock held elsewhere: the reopen waits its bound and
		// the gate fails closed, nothing reopened.
		lock, err := os.Open(filepath.Join(r.data, "server", "keystore", ".lock"))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = lock.Close() }()
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
			t.Fatal(err)
		}
		if marked, err := gate(); err == nil || marked {
			t.Fatalf("gate with the store lock held elsewhere = %v, %v; want an error", marked, err)
		}
		if a0, f0 := r.logs.Files(); a0 != audit0 || f0 != floor0 {
			t.Fatalf("reopened without the store lock: %v, %v", a0, f0)
		}
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
			t.Fatal(err)
		}

		// Clear and the lock free: reopened and recounted.
		if marked, err := gate(); err != nil || marked {
			t.Fatalf("gate after maintenance = %v, %v", marked, err)
		}
		audit1, floor1 := r.logs.Files()
		if audit1 == audit0 || floor1 == floor0 {
			t.Fatalf("held files after maintenance %v, %v; want both new (were %v, %v)", audit1, floor1, audit0, floor0)
		}
		if got := r.logs.PreFrameUsed(); got != 0 {
			t.Fatalf("budget used after audit --rotate = %d, want 0", got)
		}
		retired := size(t, oldAudit)
		a.Refused(0, ReasonRoot) // lands, and carries the one dropped before
		a.Dropped(0, 2)
		lines, _ := readAudit(t, r.auditPath())
		rs, ds := refusedOf(t, lines)
		if !slices.Equal(rs, []refusal{{0, ReasonRoot}}) || !slices.Equal(ds, []drop{{0, 1}, {0, 2}}) {
			t.Fatalf("new audit log = %v, summaries %v; want one refusal and uid 0 dropped 1, then 2", rs, ds)
		}
		if n := size(t, oldAudit); n != retired {
			t.Fatalf("the retired audit log grew from %d to %d bytes", retired, n)
		}
		if got := r.logs.PendingDropped(0); got != 0 {
			t.Fatalf("dropped count after its summary = %d", got)
		}
		// A reopen with nothing swapped holds the same files.
		if marked, err := gate(); err != nil || marked {
			t.Fatalf("gate again = %v, %v", marked, err)
		}
		if a2, f2 := r.logs.Files(); a2 != audit1 || f2 != floor1 {
			t.Fatalf("a reopen with no maintenance moved to %v, %v", a2, f2)
		}
	})
}

// TestCheckSocketInstall holds the supervisor's install check to the
// socket directory and both logs, each refusal naming what is wrong and no
// command.
func TestCheckSocketInstall(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spoil func(t *testing.T, r *storeRig)
		want  string
	}{
		{"installed", func(*testing.T, *storeRig) {}, ""},
		{"socket directory missing", func(t *testing.T, r *storeRig) {
			if err := os.Remove(filepath.Join(r.data, keystorepaths.SockDir)); err != nil {
				t.Fatal(err)
			}
		}, "the socket directory keystore-sock is missing"},
		{"socket directory mode", func(t *testing.T, r *storeRig) {
			if err := os.Chmod(filepath.Join(r.data, keystorepaths.SockDir), 0o777); err != nil {
				t.Fatal(err)
			}
		}, "the socket directory keystore-sock is at mode 0777, not 0755"},
		{"socket directory a symlink", func(t *testing.T, r *storeRig) {
			p := filepath.Join(r.data, keystorepaths.SockDir)
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(t.TempDir(), p); err != nil {
				t.Fatal(err)
			}
		}, "the socket directory keystore-sock is not a directory"},
		{"audit log missing", func(t *testing.T, r *storeRig) {
			if err := os.Remove(r.auditPath()); err != nil {
				t.Fatal(err)
			}
		}, "the append-only log keystore-audit.log is missing"},
		{"floor wrong mode", func(t *testing.T, r *storeRig) {
			if err := os.Chmod(r.floorPath(), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "the append-only log keystore-user-floor.log, its directory or the data root is not trusted (owner, mode, links, flags or ACL)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newStoreRig(t)
			tc.spoil(t, r)
			err := r.fs.CheckSocketInstall(t.Context())
			got := ""
			if err != nil {
				got = err.Error()
			}
			if got != tc.want {
				t.Fatalf("CheckSocketInstall = %q, want %q", got, tc.want)
			}
			if bytes.Contains([]byte(got), []byte("k3sm")) || bytes.Contains([]byte(got), []byte("sudo")) {
				t.Fatalf("the refusal names a command: %q", got)
			}
		})
	}
	t.Run("unflagged log", func(t *testing.T) {
		r := newStoreRig(t)
		uid, gid := os.Getuid(), os.Getgid()
		fs := keystore.New(keystore.Config{
			Dir: filepath.Join(r.data, "server", "keystore"), MasterDir: filepath.Join(r.data, "server", "cred", "keystore-master"),
			UID: uint32(uid), GID: uint32(gid), DataRoot: r.data, FloorUID: uid, FloorGID: gid,
			LogFlags: func(*os.File) (uint32, error) { return 0, nil },
		})
		want := "the append-only log " + keystore.UserFloorLogName + " is not flagged append-only"
		if err := fs.CheckSocketInstall(t.Context()); err == nil || err.Error() != want {
			t.Fatalf("CheckSocketInstall = %v, want %q", err, want)
		}
	})
}

// TestMaintenanceMarkedReadsTheMarker holds the marker reader the
// supervisor polls.
func TestMaintenanceMarkedReadsTheMarker(t *testing.T) {
	r := newStoreRig(t)
	if marked, err := r.fs.MaintenanceMarked(); err != nil || marked {
		t.Fatalf("no marker: %v, %v", marked, err)
	}
	if err := os.WriteFile(r.markerPath(), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if marked, err := r.fs.MaintenanceMarked(); err != nil || !marked {
		t.Fatalf("marker: %v, %v", marked, err)
	}
}

// TestInstallMissingLogNamesInstall holds the check order to the upgrade
// path: on a data root whose install predates the append-only logs, the
// production start checks (the real store's install check, marker read and
// log reopen) report the install reason, which names `sudo k3sm install`,
// and open no log.
func TestInstallMissingLogNamesInstall(t *testing.T) {
	for _, name := range []string{"audit", "floor"} {
		t.Run(name, func(t *testing.T) {
			r := newStoreRig(t)
			p := r.auditPath()
			if name == "floor" {
				p = r.floorPath()
			}
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			pre := Preconditions{
				EUID:              func() int { return 260 },
				ServiceUID:        260,
				IgnoresOwnership:  func() (bool, error) { return false, nil },
				CheckInstall:      r.fs.CheckSocketInstall,
				MaintenanceMarked: r.logs.MaintenanceMarked,
				OpenLogs:          r.logs.Reopen,
				SandboxCheck:      func() error { return nil },
				ServerCount:       func(context.Context) (int, error) { return 1, nil },
			}
			reason, detail := pre.Check(t.Context())
			if reason != OffInstall || reason.Remedy() != "run `sudo k3sm install`" {
				t.Fatalf("Check = %q (%s); want the install reason naming sudo k3sm install", reason, detail)
			}
			if !bytes.Contains([]byte(detail), []byte("is missing")) {
				t.Fatalf("detail %q does not say the log is missing", detail)
			}
			if a, f := r.logs.Files(); a != (keystore.LogFileID{}) || f != (keystore.LogFileID{}) {
				t.Fatalf("a log was opened before the install was vetted: %v, %v", a, f)
			}
		})
	}
}
