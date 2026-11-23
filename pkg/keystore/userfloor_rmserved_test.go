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
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// shortAfterFirstTombstone makes l's next write land the leading newline,
// one whole tombstone and a fragment, then fail.
func shortAfterFirstTombstone(l *appendLog) {
	l.write = func(f *os.File, b []byte) (int, error) {
		cut := 1 + bytes.IndexByte(b[1:], '\n') + 1 + 10
		n, err := f.Write(b[:cut])
		if err != nil {
			return n, err
		}
		return n, io.ErrShortWrite
	}
}

// twoLiveGenerations gives token a second live floor generation, all
// zeros, and returns both. All zeros sorts before every other generation,
// so before the put's random one whatever it is: the floor's live
// generations reach the burial sorted (liveGens), and a test that assumes
// the other one's tombstone lands first holds on every run. (guid(0)
// starts 0x10, which a random generation starting 0x0 sorts ahead of.)
func twoLiveGenerations(t *testing.T, s *FileStore, server string) (served, other [generationSize]byte) {
	t.Helper()
	served = entryGeneration(t, server, "token")
	if served == other {
		t.Fatal("the put's generation is all zeros")
	}
	line, err := floorLine("user/1001", "token", other, 1)
	if err != nil {
		t.Fatal(err)
	}
	appendLogBytes(t, s, userFloorLogName, line)
	return served, other
}

// U20: with no K_u, so no authenticated generation, an rm's burial puts the
// pointer header's generation, the one a reader serves, first: a write that
// lands short after its first tombstone buries the served generation, not
// another live floor generation, and says the entry is refused as deleted.
func TestRmBurialServedPointerFirstWithoutKu(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	served, other := twoLiveGenerations(t, s, server)
	// The pointer no longer authenticates under K_u, but its header still
	// parses: the burial has a pointer generation and no authenticated one.
	cur := filepath.Join(scopeDir(server, "1001"), scopeEntriesName, "token", currentName)
	b, err := os.ReadFile(cur)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-1] ^= 0xFF
	if err := os.WriteFile(cur, b, 0o600); err != nil {
		t.Fatal(err)
	}
	giveToService(t, cur)
	l := s.userFloor.(*fileFloorLog).log
	shortAfterFirstTombstone(l)
	err = u.Delete(ctx, "user/1001/token")
	l.write = nil
	if !errors.Is(err, errCommitted) || !strings.Contains(err.Error(), "refused as deleted") {
		t.Fatalf("rm whose burial landed its first tombstone: %v, want errCommitted saying refused as deleted", err)
	}
	if _, err := s.userFloor.floor("user/1001", "token", served); !errors.Is(err, errFloorBuried) {
		t.Fatalf("the served generation after the short burial: %v, want errFloorBuried", err)
	}
	live, err := s.userFloor.liveGens("user/1001", "token")
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 1 || live[0] != other {
		t.Fatalf("live generations after the short burial: %x, want only the other one, %x", live, other)
	}
}

// U20: with no generation a reader serves (no authenticated pointer and no
// pointer header), a burial that lands short after its first tombstone does
// not claim the entry is refused as deleted: it names the generation whose
// tombstone landed.
func TestRmBurialPartialNamesLandedWithoutServed(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	_, other := twoLiveGenerations(t, s, server)
	if err := os.Remove(filepath.Join(scopeDir(server, "1001"), scopeEntriesName, "token", currentName)); err != nil {
		t.Fatal(err)
	}
	l := s.userFloor.(*fileFloorLog).log
	shortAfterFirstTombstone(l)
	err := u.Delete(ctx, "user/1001/token")
	l.write = nil
	if !errors.Is(err, errCommitted) {
		t.Fatalf("rm whose burial landed its first tombstone: %v, want errCommitted", err)
	}
	if strings.Contains(err.Error(), "refused as deleted") {
		t.Fatalf("%q claims the entry is refused as deleted with no served generation buried", err)
	}
	if !strings.Contains(err.Error(), hex.EncodeToString(other[:])) {
		t.Fatalf("%q does not name the generation whose tombstone landed, %x", err, other)
	}
}
