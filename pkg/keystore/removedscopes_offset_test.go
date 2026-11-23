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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// floorHasScope reports whether the floor holds any line of scope.
func floorHasScope(t *testing.T, s *FileStore, scope string) bool {
	t.Helper()
	return bytes.Contains(readLog(t, s, userFloorLogName), []byte(scope+" "))
}

// U194: rm-scope records the floor's size at the removal, so a scope
// re-minted for the uid afterwards, whose directory is then deleted by
// hand, keeps its tombstones through a rebuild: only the removed scope's
// lines, written before the recorded size, are dropped, and a copy-back of
// the re-minted scope is refused.
func TestRebuildKeepsReMintedScopeTombstones(t *testing.T) {
	ctx := context.Background()
	s, server, _ := fileLogScope(t)
	v := userScope(t, s, 1002)
	userPut(t, v, "user/1002/x", "the removed scope's value")
	if _, err := s.RemoveScope(ctx, 1002); err != nil {
		t.Fatalf("RemoveScope: %v", err)
	}
	r := readRecord(t, s)
	floorIno, _ := inoOf(t, filepath.Join(s.dataRoot, logsDirName, floorDirName, userFloorLogName))
	if len(r.Scopes) != 1 || r.Scopes[0].FloorSize != int64(len(readLog(t, s, userFloorLogName))) || r.Scopes[0].FloorIno != floorIno {
		t.Fatalf("the record is %+v, want the floor's inode %d and size %d at the removal", r.Scopes, floorIno, len(readLog(t, s, userFloorLogName)))
	}
	recordBytes, err := os.ReadFile(removedRecordPath(s))
	if err != nil {
		t.Fatal(err)
	}

	// Re-mint, keep a copy holding a live a, then delete a.
	u := userScope(t, s, 1002)
	userPut(t, u, "user/1002/a", "re-minted a")
	userPut(t, u, "user/1002/b", "re-minted b")
	saved := filepath.Join(t.TempDir(), "1002")
	copyTree(t, scopeDir(server, "1002"), saved)
	if err := u.Delete(ctx, "user/1002/a"); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(scopeDir(server, "1002")); err != nil {
		t.Fatal(err)
	}

	rep, _ := rebuild(t, s)
	if rep.RemovedKeys != 2 { // the removed scope's .deliveries and x
		t.Errorf("dropped %d keys of the removed scope, want 2", rep.RemovedKeys)
	}
	var tomb bool
	for _, rec := range floorRecs(t, s) {
		if rec.key.scope == "user/1002" && rec.key.name == "a" && rec.tomb {
			tomb = true
		}
	}
	if !tomb {
		t.Fatal("the rebuild dropped the re-minted scope's tombstone")
	}
	if after, err := os.ReadFile(removedRecordPath(s)); err != nil || !bytes.Equal(after, recordBytes) {
		t.Fatalf("the rebuild rewrote the record: %q, %v; want it byte-identical, %q", after, err, recordBytes)
	}

	copyTree(t, saved, scopeDir(server, "1002"))
	w := &UserScope{s: s, uid: 1002, scope: userScopeOf(1002)}
	_, got, err := w.Current(ctx, "user/1002/a")
	if err == nil || !strings.Contains(err.Error(), "was deleted") {
		t.Fatalf("the copy-back of the re-minted scope: %q, %v; want refused as deleted", got, err)
	}

	// A second rebuild reads a floor of a new inode, so the recorded
	// offset no longer applies: it drops nothing more.
	if rep, _ := rebuild(t, s); rep.RemovedKeys != 0 {
		t.Errorf("a second rebuild dropped %d keys, want 0", rep.RemovedKeys)
	}
}

// A rebuild refused before its swap changes nothing: the record stays
// byte-identical (rebuild never writes it), and a later rebuild still
// drops the removed scope's lines, since the floor is still the one the
// removal was recorded against.
func TestRebuildRefusedLeavesRecordAndStillDrops(t *testing.T) {
	ctx := context.Background()
	s, _, _ := fileLogScope(t)
	v := userScope(t, s, 1002)
	userPut(t, v, "user/1002/x", "the removed scope's value")
	if _, err := s.RemoveScope(ctx, 1002); err != nil {
		t.Fatalf("RemoveScope: %v", err)
	}
	record, err := os.ReadFile(removedRecordPath(s))
	if err != nil {
		t.Fatal(err)
	}
	before := readLog(t, s, userFloorLogName)
	for _, at := range []string{swapStepReadOld, swapStepBuild, swapStepReport} {
		if _, err := s.RebuildFloor(ctx, &stepCrash{at: at}); !errors.Is(err, errRebuildRefused) && at != swapStepReport {
			t.Fatalf("a rebuild stopped before %s: %v, want a refusal", at, err)
		}
		if after, err := os.ReadFile(removedRecordPath(s)); err != nil || !bytes.Equal(after, record) {
			t.Fatalf("a rebuild stopped before %s changed the record: %q, %v", at, after, err)
		}
		if !bytes.Equal(before, readLog(t, s, userFloorLogName)) {
			t.Fatalf("a rebuild stopped before %s changed the floor", at)
		}
	}
	rep, _ := rebuild(t, s)
	if rep.RemovedKeys != 2 || floorHasScope(t, s, "user/1002") {
		t.Fatalf("the rebuild after the refusals dropped %d keys of the removed scope; want 2, none left", rep.RemovedKeys)
	}
	if rep, _ := rebuild(t, s); rep.RemovedKeys != 0 {
		t.Fatalf("a second rebuild dropped %d keys more, want 0", rep.RemovedKeys)
	}
}

// A record written before the floor offset existed parses with offset 0,
// which drops nothing; one with an offset and no floor identity, or only
// part of it (an inode alone, as an earlier build wrote), drops nothing;
// one with the whole identity drops only for the floor whose device, inode
// and birth time all match; a negative offset does not parse.
func TestRemovedScopesFloorSizeParse(t *testing.T) {
	key := bytes.Repeat([]byte("a"), 64)
	floor := floorIdentity{dev: 3, ino: 9, birth: unix.Timespec{Sec: 100, Nsec: 5}}
	r, err := parseRemovedScopes([]byte(`{"version":1,"scopes":[{"uid":7,"keys":["` + string(key) + `"]}]}`))
	if err != nil || r.Scopes[0].FloorSize != 0 || len(r.dropBefore(floor)) != 0 {
		t.Fatalf("a record without floor_size: %+v, %v; want offset 0, dropping nothing", r, err)
	}
	r, err = parseRemovedScopes([]byte(`{"version":1,"scopes":[{"uid":7,"keys":["` + string(key) + `"],"floor_size":42}]}`))
	if err != nil || len(r.dropBefore(floor)) != 0 || len(r.dropBefore(floorIdentity{})) != 0 {
		t.Fatalf("a record with floor_size 42 and no floor identity: %+v, %v; want it to drop nothing", r, err)
	}
	r, err = parseRemovedScopes([]byte(`{"version":1,"scopes":[{"uid":7,"keys":["` + string(key) + `"],"floor_size":42,"floor_ino":9}]}`))
	if err != nil || len(r.dropBefore(floor)) != 0 || len(r.dropBefore(floorIdentity{ino: 9})) != 0 {
		t.Fatalf("a record with floor_size 42 and only floor_ino: %+v, %v; want it to drop nothing", r, err)
	}
	r, err = parseRemovedScopes([]byte(`{"version":1,"scopes":[{"uid":7,"keys":["` + string(key) + `"],"floor_size":42,"floor_ino":9,"floor_dev":3,"floor_birth_sec":100,"floor_birth_nsec":5}]}`))
	if err != nil || r.dropBefore(floor)["user/7"] != 42 {
		t.Fatalf("a record with floor_size 42 for the floor %+v: %+v, %v", floor, r, err)
	}
	for _, other := range []floorIdentity{
		{dev: 4, ino: 9, birth: floor.birth},
		{dev: 3, ino: 10, birth: floor.birth},
		{dev: 3, ino: 9, birth: unix.Timespec{Sec: 100, Nsec: 6}},
	} {
		if len(r.dropBefore(other)) != 0 {
			t.Fatalf("a record for %+v drops for the floor %+v", floor, other)
		}
	}
	if _, err := parseRemovedScopes([]byte(`{"version":1,"scopes":[{"uid":7,"keys":["` + string(key) + `"],"floor_size":-1}]}`)); err == nil {
		t.Fatal("a negative floor_size parsed")
	}
}
