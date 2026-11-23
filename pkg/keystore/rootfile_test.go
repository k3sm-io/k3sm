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
	"testing"

	"golang.org/x/sys/unix"
)

// linkAside gives the file p a second link in a directory of its own, as
// any local user can for a root-owned unflagged file.
func linkAside(t *testing.T, p string) {
	t.Helper()
	if err := os.Link(p, filepath.Join(t.TempDir(), "alias")); err != nil {
		t.Fatal(err)
	}
}

// A second link on the removed-scopes record does not block revocation:
// the record still reads, so a copied-back scope is still refused as
// removed, not as a damaged record, and a later rm-scope still writes it.
func TestRemovedScopesSecondLinkReads(t *testing.T) {
	ctx := context.Background()
	s, server, _ := fileLogScope(t)
	saved := filepath.Join(t.TempDir(), "1001")
	copyTree(t, scopeDir(server, "1001"), saved)
	if recorded, err := s.RemoveScope(ctx, 1001); err != nil || !recorded {
		t.Fatalf("RemoveScope: %v, recorded %v", err, recorded)
	}
	linkAside(t, removedRecordPath(s))
	if r := readRecord(t, s); !r.listed(1001) {
		t.Fatal("the linked record does not list 1001")
	}
	copyTree(t, saved, scopeDir(server, "1001"))
	assertScopeRemovedEverywhere(t, s, 1001, errScopeRemoved)
}

// A second link on the maintenance marker does not refuse the verb: the
// marker is read and the crashed run's report is kept.
func TestMarkerSecondLinkReads(t *testing.T) {
	s, _, _ := fileLogScope(t)
	m := filepath.Join(s.dataRoot, maintenanceMarkerName)
	mk := marker{verb: "rotate", run: "00", swapped: true, dev: 1, ino: 2, report: map[string]int64{"archived": 3}}
	if err := os.WriteFile(m, mk.encode(), markerMode); err != nil {
		t.Fatal(err)
	}
	linkAside(t, m)
	if _, err := s.RebuildFloor(context.Background(), &inoRecorder{}); err != nil {
		t.Fatalf("rebuild over a linked marker: %v, want it read", err)
	}
}

// A second link on the floor acknowledgement does not void it: the
// acknowledgement still lifts the unattributable damage.
func TestFloorAckSecondLinkReads(t *testing.T) {
	ctx := context.Background()
	s, _, u := fileLogScope(t)
	appendLogBytes(t, s, userFloorLogName, []byte("\ngarbage\n"))
	if err := ackReviewed(t, s); err != nil {
		t.Fatalf("ackFloorDamage: %v", err)
	}
	linkAside(t, filepath.Join(s.dataRoot, floorAckName))
	if _, err := u.Put(ctx, "user/1001/a", KindOpaque, []byte("v")); err != nil {
		t.Fatalf("put under a linked acknowledgement: %v", err)
	}
	if _, ok := s.readFloorAck(); !ok {
		t.Fatal("the linked acknowledgement is ignored")
	}
}

// A group-writable root file is still refused: the judge keeps the mode.
func TestRootFileModeStillJudged(t *testing.T) {
	ctx := context.Background()
	s, _, _ := fileLogScope(t)
	if _, err := s.RemoveScope(ctx, 1001); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(removedRecordPath(s), 0o664); err != nil {
		t.Fatal(err)
	}
	dfd, err := s.openLogDataRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(dfd) }()
	if _, err := s.readRemovedScopes(dfd); !errors.Is(err, errRemovedScopesBad) {
		t.Fatalf("a group-writable record: %v, want errRemovedScopesBad", err)
	}
}
