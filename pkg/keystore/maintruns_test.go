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

package keystore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// lossyRuns reads the lossy-run record as doctor does, failing the test
// on an error.
func lossyRuns(t *testing.T, s *FileStore) []MaintenanceRun {
	t.Helper()
	runs, err := s.LossyMaintenanceRuns(context.Background())
	if err != nil {
		t.Fatalf("LossyMaintenanceRuns: %v", err)
	}
	return runs
}

// liveFloorIno is the live user-scope floor's inode.
func liveFloorIno(t *testing.T, s *FileStore) uint64 {
	t.Helper()
	fi, err := os.Stat(filepath.Join(s.dataRoot, logsDirName, logDirOf(userFloorLogName), userFloorLogName))
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Ino
}

// TestMaintenanceReportDurable: a lossy rebuild's drop counts outlive the
// marker in keystore-maintenance-runs (run id, verb, UTC time, the counts by
// reason, the new floor's inode), a clean run appends nothing, a saved
// report a rerun prints is recorded once, install records an earlier lossy
// run once even when it dies before removing the marker, the record keeps
// the newest 64, a record that would not parse is never written, and a
// record that does not parse is an error, never an empty list, and is left
// as found.
func TestMaintenanceReportDurable(t *testing.T) {
	at := time.Date(2026, 11, 23, 9, 30, 15, 500, time.UTC)

	t.Run("lossy rebuild survives a clean run", func(t *testing.T) {
		s, _, _ := fileLogScope(t)
		s.now = func() time.Time { return at }
		appendLogBytes(t, s, userFloorLogName, []byte("user/1001 torn"))
		rep, _ := rebuild(t, s)
		if rep.Dropped != 1 {
			t.Fatalf("the lossy rebuild dropped %d lines, want 1", rep.Dropped)
		}
		ino := liveFloorIno(t, s)
		clean, _ := rebuild(t, s)
		if clean.Lost() {
			t.Fatalf("the second rebuild dropped %+v, want a clean run", clean)
		}
		assertNoMaintenanceLeft(t, s)
		runs := lossyRuns(t, s)
		if len(runs) != 1 {
			t.Fatalf("records after a lossy and a clean rebuild: %+v, want one", runs)
		}
		r := runs[0]
		if r.Verb != verbRebuild || len(r.Run) != 16 || r.Ino != ino || !r.Time.Equal(at.Truncate(time.Second)) {
			t.Fatalf("record %+v, want floor-rebuild, a run id, inode %d, time %v", r, ino, at.Truncate(time.Second))
		}
		if r.Drops["dropped"] != 1 || r.Dropped() != 1 {
			t.Fatalf("record drops %v, want dropped=1 and nothing else", r.Drops)
		}
		b, err := os.ReadFile(filepath.Join(s.dataRoot, maintenanceRunsName))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte("token")) || bytes.Contains(b, []byte(s.dataRoot)) || bytes.Contains(b, []byte("1001")) {
			t.Fatalf("the record names an entry, a scope or a path: %q", b)
		}
		fi, err := os.Stat(filepath.Join(s.dataRoot, maintenanceRunsName))
		if err != nil || fi.Mode().Perm() != maintenanceRunsMode {
			t.Fatalf("the record's mode: %v, %v; want %o", fi.Mode(), err, maintenanceRunsMode)
		}
	})

	t.Run("clean runs append nothing", func(t *testing.T) {
		s, _, _ := fileLogScope(t)
		for _, v := range maintVerbs {
			if err := v.run(s, &inoRecorder{}); err != nil {
				t.Fatalf("%s: %v", v.name, err)
			}
		}
		if runs := lossyRuns(t, s); len(runs) != 0 {
			t.Fatalf("records after clean runs: %+v, want none", runs)
		}
		if _, err := os.Lstat(filepath.Join(s.dataRoot, maintenanceRunsName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a clean run created the record: %v", err)
		}
	})

	t.Run("a saved report is recorded once", func(t *testing.T) {
		s, _, _ := fileLogScope(t)
		appendLogBytes(t, s, userFloorLogName, []byte("not a floor line\n"))
		if _, err := s.RebuildFloor(context.Background(), &stepCrash{at: swapStepEnd}); !Committed(err) {
			t.Fatalf("rebuild failing at end: %v, want Committed", err)
		}
		for range 2 {
			rep, err := s.RebuildFloor(context.Background(), &inoRecorder{})
			if err != nil {
				t.Fatalf("rerun: %v", err)
			}
			if !rep.Earlier && rep.Lost() {
				t.Fatalf("the second rerun was lossy: %+v", rep)
			}
		}
		if runs := lossyRuns(t, s); len(runs) != 1 || runs[0].Drops["dropped"] != 1 {
			t.Fatalf("records after a saved report and a rerun: %+v, want one with dropped=1", runs)
		}
	})

	t.Run("the other verb records an earlier lossy run", func(t *testing.T) {
		s, _, _ := fileLogScope(t)
		appendLogBytes(t, s, userFloorLogName, []byte("not a floor line\n"))
		if _, err := s.RebuildFloor(context.Background(), &stepCrash{at: swapStepEnd}); !Committed(err) {
			t.Fatalf("rebuild failing at end: %v, want Committed", err)
		}
		var got []EarlierRun
		ctx := WithEarlierRun(context.Background(), func(r EarlierRun) { got = append(got, r) })
		if _, err := s.RotateAudit(ctx, &inoRecorder{}, false); err != nil {
			t.Fatalf("rotate after a committed rebuild: %v", err)
		}
		if len(got) != 1 || got[0].RecordErr != nil {
			t.Fatalf("the earlier run reported: %+v, want one, recorded", got)
		}
		if runs := lossyRuns(t, s); len(runs) != 1 || runs[0].Verb != verbRebuild || runs[0].Drops["dropped"] != 1 {
			t.Fatalf("records after rotate replaced a lossy rebuild's marker: %+v, want its one record", runs)
		}
	})

	t.Run("install records an earlier lossy run once", func(t *testing.T) {
		s, _, _ := fileLogScope(t)
		appendLogBytes(t, s, userFloorLogName, []byte("not a floor line\n"))
		if _, err := s.RebuildFloor(context.Background(), &stepCrash{at: swapStepEnd}); !Committed(err) {
			t.Fatalf("rebuild failing at end: %v, want Committed", err)
		}
		ino := liveFloorIno(t, s)
		dfd, err := s.openLogDataRoot()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = unix.Close(dfd) }()
		lfd, err := s.openLogsDir(dfd)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = unix.Close(lfd) }()
		// Twice over one marker: the second is install run again after it
		// died between the record and the marker's removal.
		for i := range 2 {
			r := EarlierRunAtInstall(dfd, lfd, s.floorUID, s.dataRoot, at)
			if r == nil || r.Dropped() != 1 || r.RecordErr != nil {
				t.Fatalf("install %d reported %+v, want the committed run, dropped 1, recorded", i+1, r)
			}
		}
		runs := lossyRuns(t, s)
		if len(runs) != 1 || runs[0].Verb != verbRebuild || runs[0].Ino != ino || runs[0].Drops["dropped"] != 1 || !runs[0].Time.Equal(at.Truncate(time.Second)) {
			t.Fatalf("records after install twice over a lossy rebuild's marker: %+v, want its one record", runs)
		}
	})

	t.Run("install over a record that does not read", func(t *testing.T) {
		s, _, _ := fileLogScope(t)
		appendLogBytes(t, s, userFloorLogName, []byte("not a floor line\n"))
		if _, err := s.RebuildFloor(context.Background(), &stepCrash{at: swapStepEnd}); !Committed(err) {
			t.Fatalf("rebuild failing at end: %v, want Committed", err)
		}
		p := filepath.Join(s.dataRoot, maintenanceRunsName)
		if err := os.WriteFile(p, []byte("not a record\n"), maintenanceRunsMode); err != nil {
			t.Fatal(err)
		}
		dfd, err := s.openLogDataRoot()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = unix.Close(dfd) }()
		lfd, err := s.openLogsDir(dfd)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = unix.Close(lfd) }()
		r := EarlierRunAtInstall(dfd, lfd, s.floorUID, s.dataRoot, at)
		if r == nil || !errors.Is(r.RecordErr, errMaintenanceRunsBad) {
			t.Fatalf("install over a damaged record reported %+v, want RecordErr naming the record", r)
		}
		if got, _ := os.ReadFile(p); string(got) != "not a record\n" {
			t.Fatalf("the damaged record was rewritten: %q", got)
		}
	})

	t.Run("a run id that would not parse is not written", func(t *testing.T) {
		s, _, _ := fileLogScope(t)
		dfd, err := s.openLogDataRoot()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = unix.Close(dfd) }()
		r, _ := lossyRunOf("00", verbRebuild, 7, map[string]int64{"dropped": 1}, at)
		if err := appendMaintenanceRun(dfd, int64(s.floorUID), s.dataRoot, r); err == nil {
			t.Fatal("a record with a short run id was appended")
		}
		if _, err := os.Lstat(filepath.Join(s.dataRoot, maintenanceRunsName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a record that would not parse created the file: %v", err)
		}
	})

	t.Run("the 65th record evicts the oldest", func(t *testing.T) {
		s, _, _ := fileLogScope(t)
		dfd, err := s.openLogDataRoot()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = unix.Close(dfd) }()
		run := func(i int) MaintenanceRun {
			r, ok := lossyRunOf(fmt.Sprintf("%016x", i), verbRebuild, uint64(1000+i), map[string]int64{"overlong": int64(i)}, at)
			if !ok {
				t.Fatal("a record with a count is not lossy")
			}
			return r
		}
		for i := 1; i <= maxMaintenanceRuns+1; i++ {
			if err := appendMaintenanceRun(dfd, int64(s.floorUID), s.dataRoot, run(i)); err != nil {
				t.Fatalf("append %d: %v", i, err)
			}
		}
		if err := appendMaintenanceRun(dfd, int64(s.floorUID), s.dataRoot, run(maxMaintenanceRuns+1)); err != nil {
			t.Fatalf("append a run id already held: %v", err)
		}
		runs := lossyRuns(t, s)
		if len(runs) != maxMaintenanceRuns || runs[0].Run != run(2).Run || runs[len(runs)-1].Run != run(maxMaintenanceRuns+1).Run {
			t.Fatalf("%d records, first %s, last %s; want %d, the oldest evicted", len(runs), runs[0].Run, runs[len(runs)-1].Run, maxMaintenanceRuns)
		}
	})

	t.Run("a corrupt record is an error and is left as found", func(t *testing.T) {
		for name, body := range map[string]string{
			"garbage":      "not a record\n",
			"no header":    run1Line + "\n",
			"torn":         maintenanceRunsHeader + "\n" + run1Line,
			"zero counts":  maintenanceRunsHeader + "\nrun=00000000000000aa verb=floor-rebuild time=2026-11-23T09:30:15Z ino=7 dropped=0 overlong=0 past-share=0 absent=0 removed=0\n",
			"repeated run": maintenanceRunsHeader + "\n" + run1Line + "\n" + run1Line + "\n",
			"overlong":     maintenanceRunsHeader + "\n" + run1Line + string(bytes.Repeat([]byte(" "), maxMaintenanceRunLine)) + "\n",
		} {
			t.Run(name, func(t *testing.T) {
				s, _, _ := fileLogScope(t)
				p := filepath.Join(s.dataRoot, maintenanceRunsName)
				if err := os.WriteFile(p, []byte(body), maintenanceRunsMode); err != nil {
					t.Fatal(err)
				}
				runs, err := s.LossyMaintenanceRuns(context.Background())
				if !errors.Is(err, errMaintenanceRunsBad) || runs != nil {
					t.Fatalf("reading a corrupt record: %+v, %v; want errMaintenanceRunsBad and no list", runs, err)
				}
				appendLogBytes(t, s, userFloorLogName, []byte("user/1001 torn"))
				rep, err := s.RebuildFloor(context.Background(), &inoRecorder{})
				if !Committed(err) || !errors.Is(err, errMaintenanceRunsBad) || rep.Dropped != 1 {
					t.Fatalf("a lossy rebuild over a corrupt record: %+v, %v; want committed, naming the record", rep, err)
				}
				if got, _ := os.ReadFile(p); string(got) != body {
					t.Fatalf("the corrupt record was rewritten: %q", got)
				}
				assertNoMaintenanceLeft(t, s)
			})
		}
	})
}

// run1Line is a well-formed record line.
const run1Line = "run=0123456789abcdef verb=floor-rebuild time=2026-11-23T09:30:15Z ino=7 dropped=1 overlong=0 past-share=0 absent=0 removed=0"
