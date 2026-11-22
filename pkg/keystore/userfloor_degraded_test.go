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
	"testing"
)

// corruptTombstones overwrites, in place, the marker of every tombstone of
// scope, name and gen in s's floor, so each reads as a damaged line: what a
// lost tombstone looks like to the reader. The test flag source stands in
// for SF_APPEND, so the bytes can be rewritten.
func corruptTombstones(t *testing.T, s *FileStore, scope, name string, gen [generationSize]byte) {
	t.Helper()
	tomb, err := tombLine(scope, name, gen)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(s.dataRoot, userFloorLogName)
	b := readLog(t, s, userFloorLogName)
	f, err := os.OpenFile(p, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	n := 0
	for off := 0; ; {
		i := bytes.Index(b[off:], tomb)
		if i < 0 {
			break
		}
		at := off + i + len(tomb) - 2 - 1 - floorCRCLen // the "m" of "rm", before " <crc>\n"
		if _, err := f.WriteAt([]byte{'X'}, int64(at)); err != nil {
			t.Fatal(err)
		}
		n++
		off += i + len(tomb)
	}
	if n == 0 {
		t.Fatal("no tombstone to corrupt")
	}
}

// Item: a skipped floor line can be a tombstone, so a floor with damage
// writes no live line. An entry whose put lost its floor line is rm'd, its
// tombstone is then lost to damage, and its tree is copied back with a
// pointer that authenticates: the catch-up refuses to give its generation
// a live line (and the start step quarantines its scope), a put refuses before its first
// write naming CheckLogBounds and the acknowledgement, Current refuses, and rm and withdraw still work.
func TestFloorDamageDegradesLiveLines(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
		t.Fatal(err)
	}
	fl := s.userFloor.(*fileFloorLog).log
	fl.write = func(*os.File, []byte) (int, error) { return 0, errors.New("injected floor write failure") }
	if _, err := u.Put(ctx, "user/1001/lost", KindOpaque, []byte("v")); !errors.Is(err, errCommitted) {
		t.Fatalf("put whose floor line fails: %v, want errCommitted", err)
	}
	fl.write = nil
	gen := entryGeneration(t, server, "lost")
	dir := filepath.Join(scopeDir(server, "1001"), scopeEntriesName, "lost")
	saved := filepath.Join(t.TempDir(), "lost")
	copyTree(t, dir, saved)
	if err := u.Delete(ctx, "user/1001/lost"); err != nil {
		t.Fatalf("rm: %v", err)
	}
	corruptTombstones(t, s, "user/1001", "lost", gen)
	restoreTree(t, saved, dir)
	if n := floorDamage(t, s); n == 0 {
		t.Fatal("the corrupted tombstone is not counted as damage")
	}
	live, err := floorLine("user/1001", "lost", gen, 1)
	if err != nil {
		t.Fatal(err)
	}
	liveLines := func() int { return bytes.Count(readLog(t, s, userFloorLogName), live) }

	_, scopeErrs, err := s.catchUpUser(ctx)
	if err != nil || !errors.Is(scopeErrs, errFloorDegraded) {
		t.Fatalf("catchUpUser over a damaged floor: %v, %v; want errFloorDegraded", err, scopeErrs)
	}
	if n := liveLines(); n != 0 {
		t.Fatalf("the catch-up wrote %d live line(s) for a generation a lost tombstone buried", n)
	}
	s2 := reopenStore(t, s)
	if err := s2.startUserScopes(ctx); !errors.Is(err, errCatchUpRefused) || !s2.userScopesStarted.Load() {
		t.Fatalf("start over a refused live-line catch-up: %v, started %v; want it started with the refusal named", err, s2.userScopesStarted.Load())
	}
	if q, err := s2.UserScope(1001); err != nil {
		t.Fatalf("UserScope of the scope whose catch-up was refused: %v, want a view that still revokes", err)
	} else if _, _, err := q.Current(ctx, "user/1001/token"); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("current in the scope whose catch-up was refused: %v, want errFloorDegraded (quarantined)", err)
	}

	if _, _, err := u.Current(ctx, "user/1001/lost"); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("current of the copied-back tree over a damaged floor: %v, want errFloorDegraded", err)
	}
	// The corrupted tombstone names its key (a generation taint); a put of
	// another name is refused once damage no key can be read from is there.
	appendLogBytes(t, s, userFloorLogName, []byte("\ngarbage line\n"))
	before := readLog(t, s, userFloorLogName)
	_, err = u.Put(ctx, "user/1001/other", KindOpaque, []byte("v"))
	if !errors.Is(err, errFloorDegraded) {
		t.Fatalf("put over a damaged floor: %v, want errFloorDegraded", err)
	}
	for _, want := range []string{"CheckLogBounds", "root maintenance"} {
		if !bytes.Contains([]byte(err.Error()), []byte(want)) {
			t.Fatalf("the put's refusal %q does not name %s", err, want)
		}
	}
	if got := readLog(t, s, userFloorLogName); !bytes.Equal(got, before) {
		t.Fatal("a put over a damaged floor wrote to the floor")
	}
	if _, err := os.Stat(filepath.Join(scopeDir(server, "1001"), scopeEntriesName, "other")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a put over a damaged floor wrote its entry: %v", err)
	}
	if n := liveLines(); n != 0 {
		t.Fatalf("%d live line(s) for the buried generation", n)
	}
	if err := u.withdrawDelivery(ctx, testDelivery(1).uid); err != nil {
		t.Fatalf("withdraw over a damaged floor: %v", err)
	}
	if err := u.Delete(ctx, "user/1001/token"); err != nil {
		t.Fatalf("rm over a damaged floor: %v", err)
	}
}
