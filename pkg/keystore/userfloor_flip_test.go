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
)

// Every single-bit flip of a tombstone line, for two keys, closed by the
// next append, still refuses the generation it buried: a copy-back of that
// generation, which the floor knows from its live line, is never served.
// The flip is corrected (the recovered key is tainted) or, with no unique
// correction, refuses every known generation of the floor.
func TestEveryTombstoneFlipRefusesKnownGeneration(t *testing.T) {
	s, server, _ := fileLogScope(t)
	ff := s.userFloor.(*fileFloorLog)
	long := strings.Repeat("n", maxNameLen)
	keys := []floorKey{
		{"user/1001", "token", entryGeneration(t, server, "token")},
		{"user/2147483647", long, guid(0x5D)},
	}
	other, err := floorLine("user/2147483647", long, keys[1].gen, 7)
	if err != nil {
		t.Fatal(err)
	}
	closer, err := floorLine("user/1002", "other", guid(0x11), 1)
	if err != nil {
		t.Fatal(err)
	}
	base := append(readLog(t, s, userFloorLogName), other...)
	for _, k := range keys {
		tomb, err := tombLine(k.scope, k.name, k.gen)
		if err != nil {
			t.Fatal(err)
		}
		body := tomb[:len(tomb)-1]
		served := 0
		for i := range body {
			for bit := range 8 {
				p := append([]byte(nil), body...)
				p[i] ^= 1 << bit
				b := append(append(append(append([]byte(nil), base...), '\n'), p...), '\n')
				setFloorBytes(t, s, append(b, closer...))
				if _, err := ff.floor(k.scope, k.name, k.gen); !errors.Is(err, errFloorDegraded) {
					served++
					t.Errorf("%q: the buried, known generation: %v, want errFloorDegraded", p, err)
				}
			}
		}
		t.Logf("%s %s: %d of %d single-bit flips serve the buried generation", k.scope, k.name, served, 8*len(body))
	}
}

// A tombstone with one bit flipped in its scope, copied back past: the
// entry's current is refused, not served from the floor's live line.
func TestFlippedTombstoneScopeRefusesCopyBack(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	gen := entryGeneration(t, server, "token")
	dir := filepath.Join(scopeDir(server, "1001"), scopeEntriesName, "token")
	saved := filepath.Join(t.TempDir(), "token")
	if err := os.CopyFS(saved, os.DirFS(dir)); err != nil {
		t.Fatal(err)
	}
	if err := u.Delete(ctx, "user/1001/token"); err != nil {
		t.Fatal(err)
	}
	b := readLog(t, s, userFloorLogName)
	tomb, err := tombLine("user/1001", "token", gen)
	if err != nil {
		t.Fatal(err)
	}
	at := bytes.LastIndex(b, tomb)
	if at < 0 {
		t.Fatal("no tombstone in the floor")
	}
	b[at+len("user/10")] ^= 0x01 // user/1001 -> user/1011
	closer, err := floorLine("user/1002", "other", guid(0x11), 1)
	if err != nil {
		t.Fatal(err)
	}
	setFloorBytes(t, s, append(b, closer...))
	copyBack(t, saved, dir)
	if _, _, err := u.Current(ctx, "user/1001/token"); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("current of the copied-back generation past a flipped tombstone: %v, want errFloorDegraded", err)
	}
}
