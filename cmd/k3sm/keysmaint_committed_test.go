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
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/keystore"
)

// keysEndCrash fails the swap's end step, after the swap committed.
type keysEndCrash struct{ keysAttrRecorder }

func (*keysEndCrash) BeforeSwapStep(step string) error {
	if step == "end" {
		return errors.New("crash before end")
	}
	return nil
}

// A rebuild that fails after its swap committed exits 4, prints its drop
// counts and audits committed, never refused. A rotate run next finds its
// marker, prints its saved report to stderr as an earlier committed run,
// and writes its audit line (op floor-rebuild, result committed) before it
// replaces the marker.
func TestKeysMaintenanceCommittedAfterSwap(t *testing.T) {
	h := newKeysHarness(t)
	var lines []string
	h.wrap = func(s keysStore) keysStore { return keysAuditRecorder{keysStore: s, lines: &lines} }
	h.stdin = strings.NewReader("tok")
	h.mustRun(keysOK, "put", "system/api-token", "--in", "-")
	h.euid = 0
	h.logFlags = keysFlagged
	logs := map[string]string{
		keystore.FloorDirName: "keystore-user-floor.log",
		keystore.AuditDirName: "keystore-audit.log",
	}
	for dir, name := range logs {
		if err := os.MkdirAll(filepath.Join(h.cfg.DataRoot, keystore.LogsDirName, dir), 0o755); err != nil {
			t.Fatal(err)
		}
		body := ""
		if dir == keystore.FloorDirName {
			body = "not a floor line\n"
		}
		if err := os.WriteFile(filepath.Join(h.cfg.DataRoot, keystore.LogsDirName, dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	h.attrs = &keysEndCrash{}
	lines = nil
	h.mustRun(keysCommitted, "floor", "--rebuild")
	if !strings.Contains(h.stdout.String(), "dropped 1 lines of the old floor that did not parse") {
		t.Errorf("the committed rebuild printed %q, want its drop counts", h.stdout.String())
	}
	if !slices.Equal(lines, []string{"floor-rebuild  committed"}) {
		t.Errorf("the committed rebuild's audit lines %q, want committed", lines)
	}
	h.attrs = &keysAttrRecorder{}
	h.stdout.Reset()
	h.stderr.Reset()
	lines = nil
	h.mustRun(keysOK, "audit", "--rotate")
	if !strings.Contains(h.stderr.String(), "an earlier floor --rebuild committed and was not reported: ") || !strings.Contains(h.stderr.String(), "dropped=1") {
		t.Errorf("rotate after a committed rebuild printed %q to stderr, want the earlier report", h.stderr.String())
	}
	if strings.Contains(h.stderr.String(), "not written") {
		t.Errorf("the earlier run's audit line was not written: %q", h.stderr.String())
	}
	one, err := os.ReadFile(filepath.Join(h.cfg.DataRoot, keystore.LogsDirName, keystore.AuditDirName, keystore.ArchivesDirName, "keystore-audit.log.1"))
	if err != nil || !strings.Contains(string(one), `"op":"floor-rebuild","via":"root","scope":"system","name":"-","namespace":"","result":"committed"`) {
		t.Errorf("the rotated log %q (%v) holds no committed floor-rebuild line", one, err)
	}
}
