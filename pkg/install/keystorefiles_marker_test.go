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
			mk := fmt.Sprintf("verb=floor-rebuild\nrun=00\nswapped=1\ndev=%d\nino=%d\nreport.dropped=2\nreport.keys=5\n", st.Dev, ino)
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
			want := "install: an earlier floor --rebuild committed and dropped 2 lines, and was not reported: dropped=2, keys=5; install does not exit 4 for it: the earlier run's drop counts are in this line and in no other record (the audit log holds a committed line for that run, without them), so copy this line down\n"
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

// Install adds the copy-it-down hint only to an earlier run that dropped
// lines, and it no longer points at doctor, whose row reads PASS.
func TestEarlierRunDropHint(t *testing.T) {
	if h := earlierRunDropHint(&keystore.EarlierRun{Verb: "floor-rebuild", Report: map[string]int64{"keys": 5}}); h != "" {
		t.Fatalf("a clean earlier run got the hint %q", h)
	}
	h := earlierRunDropHint(&keystore.EarlierRun{Verb: "floor-rebuild", Report: map[string]int64{"absent": 1, "keys": 5}})
	if !strings.Contains(h, "drop counts are in this line and in no other record") || !strings.Contains(h, "committed line for that run") || !strings.Contains(h, "copy this line down") {
		t.Fatalf("a lossy earlier run got %q, want the counts only here, the committed audit line and copy it down", h)
	}
	if strings.Contains(h, "doctor") || strings.Contains(h, "keystore-floor") {
		t.Fatalf("a lossy earlier run got %q, which points at doctor's keystore-floor row", h)
	}
}
