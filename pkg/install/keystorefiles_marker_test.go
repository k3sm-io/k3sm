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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/keystore"
)

// A stale marker recording a committed floor --rebuild that was never
// reported is reported by install before it removes the marker: printed to
// stderr with the saved report, and audited (op floor-rebuild, result
// committed). A marker of a run that never committed reports nothing.
func TestKeystoreFilesReportsCommittedMarker(t *testing.T) {
	for _, committed := range []bool{true, false} {
		t.Run(fmt.Sprintf("committed %v", committed), func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0o755); err != nil {
				t.Fatal(err)
			}
			rec := &attrRecorder{}
			setSeam(t, &euidSeam, func() int { return 0 })
			setSeam[fileAttrWriter](t, &fileAttrSeam, rec)
			setSeam(t, &keystoreFstatSeam, rec.fakeStat(271))
			var stderr bytes.Buffer
			setSeam[io.Writer](t, &keystoreStderr, &stderr)
			if err := ensureKeystoreFiles(root, 271, 20, os.Getuid()); err != nil {
				t.Fatalf("install: %v", err)
			}
			floor := filepath.Join(root, keystore.LogsDirName, keystore.FloorDirName, keystore.UserFloorLogName)
			var st unix.Stat_t
			if err := unix.Stat(floor, &st); err != nil {
				t.Fatal(err)
			}
			ino := st.Ino
			if !committed {
				ino++
			}
			mk := fmt.Sprintf("verb=floor-rebuild\nrun=00000000000000aa\nswapped=1\ndev=%d\nino=%d\nreport.dropped=2\nreport.keys=5\n", st.Dev, ino)
			if err := os.WriteFile(filepath.Join(root, keystore.MaintenanceMarkerName), []byte(mk), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := ensureKeystoreFiles(root, 271, 20, os.Getuid()); err != nil {
				t.Fatalf("install over the marker: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(root, keystore.MaintenanceMarkerName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the marker is still there: %v", err)
			}
			audit, err := os.ReadFile(filepath.Join(root, keystore.LogsDirName, keystore.AuditDirName, keystore.AuditLogName))
			if err != nil {
				t.Fatal(err)
			}
			line := `"op":"floor-rebuild","via":"root","scope":"system","name":"-","namespace":"","result":"committed"`
			want := "install: an earlier floor --rebuild committed and dropped 2 lines, and was not reported: dropped=2, keys=5; install does not exit 4 for it: the earlier run's drop counts are kept in keystore-maintenance-runs in the data root, which k3sm doctor reads\n"
			if !committed {
				if stderr.Len() != 0 || strings.Contains(string(audit), line) {
					t.Fatalf("a marker that never committed was reported: %q / %q", stderr.String(), audit)
				}
				return
			}
			if stderr.String() != want {
				t.Fatalf("install printed %q, want %q", stderr.String(), want)
			}
			if !strings.Contains(string(audit), line) {
				t.Fatalf("the audit log %q holds no committed floor-rebuild line", audit)
			}
		})
	}
}

// Install says where an earlier lossy run's drop counts are kept: in the
// lossy-run record doctor reads, when it was recorded; in its line only,
// with the copy-it-down hint, when it was not. A clean earlier run gets no
// hint, and the hint never points at doctor's keystore-floor row.
func TestEarlierRunDropHint(t *testing.T) {
	if h := earlierRunDropHint(&keystore.EarlierRun{Verb: "floor-rebuild", Report: map[string]int64{"keys": 5}}); h != "" {
		t.Fatalf("a clean earlier run got the hint %q", h)
	}
	h := earlierRunDropHint(&keystore.EarlierRun{Verb: "floor-rebuild", Report: map[string]int64{"absent": 1, "keys": 5}})
	if !strings.Contains(h, "kept in "+keystore.MaintenanceRunsName) || !strings.Contains(h, "k3sm doctor reads") || strings.Contains(h, "copy this line down") || strings.Contains(h, "no other record") {
		t.Fatalf("a recorded lossy earlier run got %q, want the record doctor reads and no copy-it-down", h)
	}
	h = earlierRunDropHint(&keystore.EarlierRun{Verb: "floor-rebuild", Report: map[string]int64{"absent": 1, "keys": 5}, RecordErr: errors.New("damaged")})
	if !strings.Contains(h, "could not be recorded") || !strings.Contains(h, "in this line only") || !strings.Contains(h, "committed line for that run") || !strings.Contains(h, "copy this line down") {
		t.Fatalf("an unrecorded lossy earlier run got %q, want the counts only here, why, the committed audit line and copy it down", h)
	}
	if strings.Contains(h, "keystore-floor") {
		t.Fatalf("a lossy earlier run got %q, which points at doctor's keystore-floor row", h)
	}
}

// TestInstallRecordsLossyEarlierRun: install that removes the marker of a
// committed lossy run appends that run's record to keystore-maintenance-runs
// before the marker goes, and says the counts are kept there; a second
// install over the same marker (one that died between the record and the
// marker's removal) records it once; a record that does not read is left as
// found, the marker still goes, and the line says the counts are in it only
// and why.
func TestInstallRecordsLossyEarlierRun(t *testing.T) {
	const run = "00000000000000ab"
	setup := func(t *testing.T) (root string, stderr *bytes.Buffer, placeMarker func()) {
		t.Helper()
		root = t.TempDir()
		if err := os.Chmod(root, 0o755); err != nil {
			t.Fatal(err)
		}
		rec := &attrRecorder{}
		setSeam(t, &euidSeam, func() int { return 0 })
		setSeam[fileAttrWriter](t, &fileAttrSeam, rec)
		setSeam(t, &keystoreFstatSeam, rec.fakeStat(271))
		stderr = &bytes.Buffer{}
		setSeam[io.Writer](t, &keystoreStderr, stderr)
		if err := ensureKeystoreFiles(root, 271, 20, os.Getuid()); err != nil {
			t.Fatalf("install: %v", err)
		}
		stderr.Reset()
		var st unix.Stat_t
		if err := unix.Stat(filepath.Join(root, keystore.LogsDirName, keystore.FloorDirName, keystore.UserFloorLogName), &st); err != nil {
			t.Fatal(err)
		}
		mk := fmt.Sprintf("verb=floor-rebuild\nrun=%s\nswapped=1\ndev=%d\nino=%d\nreport.overlong=3\nreport.keys=5\n", run, st.Dev, st.Ino)
		placeMarker = func() {
			t.Helper()
			if err := os.WriteFile(filepath.Join(root, keystore.MaintenanceMarkerName), []byte(mk), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return root, stderr, placeMarker
	}
	installOver := func(t *testing.T, root string) {
		t.Helper()
		if err := ensureKeystoreFiles(root, 271, 20, os.Getuid()); err != nil {
			t.Fatalf("install over the marker: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(root, keystore.MaintenanceMarkerName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the marker is still there: %v", err)
		}
	}

	t.Run("recorded once", func(t *testing.T) {
		root, stderr, placeMarker := setup(t)
		placeMarker()
		installOver(t, root)
		want := "install: an earlier floor --rebuild committed and dropped 3 lines, and was not reported: keys=5, overlong=3; install does not exit 4 for it: the earlier run's drop counts are kept in keystore-maintenance-runs in the data root, which k3sm doctor reads\n"
		if stderr.String() != want {
			t.Fatalf("install printed %q, want %q", stderr.String(), want)
		}
		// The marker again, as an install that died after the record and
		// before removing the marker leaves it.
		placeMarker()
		installOver(t, root)
		b, err := os.ReadFile(filepath.Join(root, keystore.MaintenanceRunsName))
		if err != nil {
			t.Fatalf("the record: %v", err)
		}
		lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
		if len(lines) != 2 || !strings.HasPrefix(lines[1], "run="+run+" verb=floor-rebuild ") || !strings.HasSuffix(lines[1], " dropped=0 overlong=3 past-share=0 absent=0 removed=0") {
			t.Fatalf("the record after two installs over one marker: %q, want a header and one record of run %s with overlong=3", b, run)
		}
		fi, err := os.Stat(filepath.Join(root, keystore.MaintenanceRunsName))
		if err != nil || fi.Mode().Perm() != 0o644 {
			t.Fatalf("the record's mode: %v, %v; want 0644", fi, err)
		}
	})

	t.Run("a record that does not read", func(t *testing.T) {
		root, stderr, placeMarker := setup(t)
		p := filepath.Join(root, keystore.MaintenanceRunsName)
		const body = "not a record\n"
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		placeMarker()
		installOver(t, root)
		out := stderr.String()
		if !strings.Contains(out, "its drop counts were not recorded: ") || !strings.Contains(out, "damaged or untrusted") || !strings.Contains(out, "could not be recorded, so they are in this line only") || !strings.Contains(out, "copy this line down") || strings.Contains(out, "which k3sm doctor reads") {
			t.Fatalf("install over a damaged record printed %q, want the counts in this line only, why, and copy it down", out)
		}
		if got, _ := os.ReadFile(p); string(got) != body {
			t.Fatalf("the damaged record was rewritten: %q", got)
		}
	})
}
