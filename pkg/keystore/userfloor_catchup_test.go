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
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// dropEntryLines is a user-scope floor that loses every entry line put
// appends, as a crash between the pointer and the floor line does.
type dropEntryLines struct{ userFloorLog }

func (d dropEntryLines) append(scope, name string, gen [generationSize]byte, seq uint64, revoke bool) error {
	if name != deliveriesFloorName {
		return errors.New("the floor line was lost")
	}
	return d.userFloorLog.append(scope, name, gen, seq, revoke)
}

// lostLineEntry puts user/1001/lost with its floor line lost and returns
// the store, the entry's directory, a saved copy of its tree and its
// generation.
func lostLineEntry(t *testing.T) (*FileStore, *UserScope, string, string, [generationSize]byte) {
	t.Helper()
	s, server, u := fileLogScope(t)
	real := s.userFloor
	s.userFloor = dropEntryLines{real}
	if _, err := u.Put(context.Background(), "user/1001/lost", KindOpaque, []byte("v")); !errors.Is(err, errCommitted) {
		t.Fatalf("put with its floor line lost: %v, want errCommitted", err)
	}
	s.userFloor = real
	if live, err := s.userFloor.liveGens("user/1001", "lost"); err != nil || len(live) != 0 {
		t.Fatalf("the floor's live generations for the lost line: %x, %v, want none", live, err)
	}
	dir := filepath.Join(scopeDir(server, "1001"), scopeEntriesName, "lost")
	saved := filepath.Join(t.TempDir(), "lost")
	copyTree(t, dir, saved)
	return s, u, dir, saved, entryGeneration(t, server, "lost")
}

// rewriteGeneration rewrites the generation file and the headers of the
// named record files in dir to gen, with no key, as a tree-writer can.
func rewriteGeneration(t *testing.T, dir string, gen [generationSize]byte, records ...string) {
	t.Helper()
	genPath := filepath.Join(dir, generationName)
	if err := os.Remove(genPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(genPath, []byte(hex.EncodeToString(gen[:])+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	giveToService(t, genPath)
	for _, f := range records {
		p := filepath.Join(dir, f)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		r, err := parseRecord(b)
		if err != nil {
			t.Fatal(err)
		}
		r.generation = gen
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, r.marshal(), 0o600); err != nil {
			t.Fatal(err)
		}
		giveToService(t, p)
	}
}

// The start catch-up appends the floor line a put lost, at the
// authenticated pointer's generation, so once a tree-writer rewrites every
// generation header (the pointer's included) to another value, rm still
// buries the real generation and the original tree copied back is refused
// as deleted.
func TestStartCatchUpRestoresLostEntryFloorLine(t *testing.T) {
	ctx := context.Background()
	s, u, dir, saved, gen := lostLineEntry(t)
	if err := s.startUserScopes(ctx); err != nil {
		t.Fatalf("startUserScopes: %v", err)
	}
	if live, err := s.userFloor.liveGens("user/1001", "lost"); err != nil || !slices.Contains(live, gen) {
		t.Fatalf("the floor's live generations after the start catch-up: %x, %v, want %x", live, err, gen)
	}
	rewriteGeneration(t, dir, guid(0x5C), currentName, versionName(1))
	if err := u.Delete(ctx, "user/1001/lost"); err != nil && !errors.Is(err, errCommitted) {
		t.Fatalf("rm of the rewritten tree: %v", err)
	}
	copyBack(t, saved, dir)
	_, _, err := u.Current(ctx, "user/1001/lost")
	checkUserDeleted(t, "current", err)
}

// A second start catch-up appends nothing for an entry whose floor line is
// already there.
func TestStartCatchUpEntryLineOnce(t *testing.T) {
	ctx := context.Background()
	s, _, _, _, _ := lostLineEntry(t)
	if err := s.startUserScopes(ctx); err != nil {
		t.Fatal(err)
	}
	before := readLog(t, s, userFloorLogName)
	if err := s.startUserScopes(ctx); err != nil {
		t.Fatal(err)
	}
	if after := readLog(t, s, userFloorLogName); string(after) != string(before) {
		t.Fatalf("a second catch-up appended %q", after[len(before):])
	}
}

// The start catch-up never revives a buried generation: a tree copied back
// after rm gets no live floor line.
func TestStartCatchUpSkipsBuriedEntry(t *testing.T) {
	ctx := context.Background()
	s, u, dir, saved, _ := lostLineEntry(t)
	if err := u.Delete(ctx, "user/1001/lost"); err != nil {
		t.Fatal(err)
	}
	copyBack(t, saved, dir)
	before := readLog(t, s, userFloorLogName)
	if err := s.startUserScopes(ctx); err != nil {
		t.Fatal(err)
	}
	if after := readLog(t, s, userFloorLogName); string(after) != string(before) {
		t.Fatalf("the catch-up appended %q for a buried entry", after[len(before):])
	}
	_, _, err := u.Current(ctx, "user/1001/lost")
	checkUserDeleted(t, "current", err)
}

// The start catch-up is best effort per scope: a floor that does not take
// an entry's line is logged and named, and the user scope still starts.
func TestStartCatchUpEntryRefusedNamesScope(t *testing.T) {
	ctx := context.Background()
	s, _, _, _, _ := lostLineEntry(t)
	real := s.userFloor
	s.userFloor = dropEntryLines{real}
	err := s.startUserScopes(ctx)
	s.userFloor = real
	if err == nil || !strings.Contains(err.Error(), "user/1001") {
		t.Fatalf("startUserScopes with the entry line refused: %v, want the scope named", err)
	}
	if !s.userScopesStarted.Load() {
		t.Fatal("the user scope did not start")
	}
}

// rm buries the generation its authenticated pointer carries, alongside the
// tree's unauthenticated claims, with no start catch-up: the generation
// file and every version header rewritten (the pointer cannot be, or it no
// longer authenticates), rm names the authenticated pointer among the
// sources it buried, and the original tree copied back is refused.
func TestRmBuriesAuthenticatedPointerGeneration(t *testing.T) {
	ctx := context.Background()
	_, u, dir, saved, _ := lostLineEntry(t)
	rewriteGeneration(t, dir, guid(0x5C), versionName(1))
	err := u.Delete(ctx, "user/1001/lost")
	if !errors.Is(err, errCommitted) || !strings.Contains(err.Error(), "the authenticated pointer") {
		t.Fatalf("rm of the rewritten tree: %v, want the authenticated pointer among the sources buried", err)
	}
	copyBack(t, saved, dir)
	_, _, err = u.Current(ctx, "user/1001/lost")
	checkUserDeleted(t, "current", err)
}

// The start catch-up's entry line is in the revocation class: past the
// hard cap it draws on the uid's revocation budget, so a floor at its hard
// cap still takes the line that lets rm bury the entry's real generation.
func TestStartCatchUpEntryPastHardCap(t *testing.T) {
	ctx := context.Background()
	s, _, _, _, gen := lostLineEntry(t)
	size := int64(len(readLog(t, s, userFloorLogName)))
	s.logSoftCap, s.logHardCap = size, size
	if err := s.startUserScopes(ctx); err != nil {
		t.Fatalf("startUserScopes with the floor at its hard cap: %v", err)
	}
	if live, err := s.userFloor.liveGens("user/1001", "lost"); err != nil || !slices.Contains(live, gen) {
		t.Fatalf("the floor's live generations after the catch-up past the hard cap: %x, %v, want %x", live, err, gen)
	}
}
