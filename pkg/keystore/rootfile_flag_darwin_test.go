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
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// A flag on a root-written file is refused, and the refusal names, as its
// first repair, clearing the flag on that exact root-owned path (single-
// quoted), before the second repair, restoring from a backup (the
// removed-scopes record) or install (the marker). A refusal for the mode
// alone names no chflags.
func TestRootFileFlagNamesChflags(t *testing.T) {
	ctx := context.Background()
	s, _, _ := fileLogScope(t)
	if _, err := s.RemoveScope(ctx, 1001); err != nil {
		t.Fatal(err)
	}
	rec := removedRecordPath(s)
	m := filepath.Join(s.dataRoot, maintenanceMarkerName)
	mk := marker{verb: "rotate", run: "00", swapped: true, dev: 1, ino: 2, report: map[string]int64{"archived": 3}}
	if err := os.WriteFile(m, mk.encode(), markerMode); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{rec, m} {
		if err := unix.Chflags(p, unix.UF_NODUMP); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = unix.Chflags(p, 0) })
	}
	dfd, err := s.openLogDataRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(dfd) }()
	_, err = s.readRemovedScopes(dfd)
	if !errors.Is(err, errRemovedScopesBad) {
		t.Fatalf("a flagged record: %v, want errRemovedScopesBad", err)
	}
	msg := err.Error()
	fix := "sudo chflags 0 '" + rec + "'"
	if i, j := strings.Index(msg, fix), strings.Index(msg, "restore it from a backup"); i < 0 || j < 0 || i > j {
		t.Fatalf("the refusal %q does not name %q before restoring from a backup", msg, fix)
	}
	_, err = s.RebuildFloor(ctx, &inoRecorder{})
	if fix := "sudo chflags 0 '" + m + "'"; err == nil || !strings.Contains(err.Error(), fix) || strings.Index(err.Error(), fix) > strings.Index(err.Error(), "sudo k3sm install") {
		t.Fatalf("a flagged marker: %v, want %q named before install", err, fix)
	}
	if err := unix.Chflags(rec, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(rec, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, err := s.readRemovedScopes(dfd); !errors.Is(err, errRemovedScopesBad) || strings.Contains(err.Error(), "chflags") {
		t.Fatalf("a group-writable record: %v, want errRemovedScopesBad naming no chflags", err)
	}
}
