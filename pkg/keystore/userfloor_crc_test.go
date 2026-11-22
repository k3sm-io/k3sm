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
	"fmt"
	"hash/crc32"
	"path/filepath"
	"strings"
	"testing"
)

// crcTestLines is a valid line of each shape: a live entry line, a
// tombstone with the longest name and scope, and a delivery-record line at
// the highest sequence.
func crcTestLines(t *testing.T) []struct {
	line []byte
	key  floorKey
} {
	t.Helper()
	g := guid(0x5D)
	long := strings.Repeat("n", maxNameLen)
	live, err := floorLine("user/1001", "token", g, 123)
	if err != nil {
		t.Fatal(err)
	}
	tomb, err := tombLine("user/2147483647", long, g)
	if err != nil {
		t.Fatal(err)
	}
	dlv, err := floorLine("user/501", deliveriesFloorName, g, 18446744073709551615)
	if err != nil {
		t.Fatal(err)
	}
	return []struct {
		line []byte
		key  floorKey
	}{
		{live, floorKey{"user/1001", "token", g}},
		{tomb, floorKey{"user/2147483647", long, g}},
		{dlv, floorKey{"user/501", deliveriesFloorName, g}},
	}
}

// Every floor line ends in " <crc>": 8 lowercase hex digits of CRC-32C
// over the bytes before it.
func TestFloorLineCarriesChecksum(t *testing.T) {
	for _, c := range crcTestLines(t) {
		line := c.line[:len(c.line)-1]
		sp := bytes.LastIndexByte(line, ' ')
		want := fmt.Sprintf("%08x", crc32.Checksum(line[:sp], crc32.MakeTable(crc32.Castagnoli)))
		if string(line[sp+1:]) != want {
			t.Fatalf("%q: checksum field %q, want %q", line, line[sp+1:], want)
		}
		if bytes.Count(line, []byte{' '}) != 4 {
			t.Fatalf("%q: not five fields", line)
		}
	}
}

// Every truncation and every single-bit flip of every valid line never
// parses, and is classified so that it taints its own key or counts as
// unattributable damage: a closed tear never reads as a lower sequence.
func TestEveryTruncationAndFlipNeverParses(t *testing.T) {
	for _, c := range crcTestLines(t) {
		body := c.line[:len(c.line)-1]
		for n := 1; n < len(body); n++ {
			checkDamagedLine(t, body[:n], c.key)
		}
		for i := range body {
			for bit := range 8 {
				p := append([]byte(nil), body...)
				p[i] ^= 1 << bit
				checkDamagedLine(t, p, c.key)
			}
		}
	}
}

// checkDamagedLine fails unless p does not parse and, recorded as a
// skipped line, taints k or counts as unattributable.
func checkDamagedLine(t *testing.T, p []byte, k floorKey) {
	t.Helper()
	if r, err := parseFloorLine(p); err == nil {
		t.Fatalf("%q parses, as %+v", p, r)
	}
	var st logState
	st.taintLine(0, p)
	if _, unattrib := st.unattributedAt(); !unattrib && !st.tainted(k) {
		kind, got := classifyFloorDamage(p)
		t.Fatalf("%q: classified %v %+v, which neither taints %+v nor is unattributable", p, kind, got, k)
	}
}

// Every truncation of a live line, closed by the next append's leading
// newline, is read as damage that refuses its key's known generation, or
// counts as unattributable: never as a line at a lower sequence.
func TestClosedTearRefusesKnownGeneration(t *testing.T) {
	s, server, _ := fileLogScope(t)
	ff := s.userFloor.(*fileFloorLog)
	gen := entryGeneration(t, server, "token")
	key := floorKey{"user/1001", "token", gen}
	line, err := floorLine("user/1001", "token", gen, 123)
	if err != nil {
		t.Fatal(err)
	}
	closer, err := floorLine("user/1002", "other", guid(0x11), 1)
	if err != nil {
		t.Fatal(err)
	}
	base := readLog(t, s, userFloorLogName)
	body := line[:len(line)-1]
	for n := 1; n < len(body); n++ {
		b := append(append(append(append([]byte(nil), base...), '\n'), body[:n]...), '\n')
		setFloorBytes(t, s, append(b, closer...))
		var tainted, unattrib bool
		var seq uint64
		if err := ff.read(func(st *logState) {
			tainted = st.tainted(key)
			_, unattrib = st.unattributedAt()
			seq = st.maxSeq[key]
		}); err != nil {
			t.Fatal(err)
		}
		if seq != 1 {
			t.Fatalf("%q closed: the key's sequence reads %d, want 1", body[:n], seq)
		}
		if !tainted && !unattrib {
			t.Fatalf("%q closed: neither taints the key nor is unattributable", body[:n])
		}
		if tainted {
			if _, err := ff.floor(key.scope, key.name, key.gen); !errors.Is(err, errFloorDegraded) {
				t.Fatalf("%q closed: the known generation: %v, want errFloorDegraded", body[:n], err)
			}
		}
	}
}

// deliveriesFloorKey is uid 1001's delivery-record floor key, read from the
// floor.
func deliveriesFloorKey(t *testing.T, s *FileStore) floorKey {
	t.Helper()
	for _, l := range bytes.Split(readLog(t, s, userFloorLogName), []byte{'\n'}) {
		if r, err := parseFloorLine(l); err == nil && r.key.name == deliveriesFloorName {
			return r.key
		}
	}
	t.Fatal("no delivery-record line in the floor")
	return floorKey{}
}

// A delivery-record line at sequence 123 torn to "... 12" and closed by the
// next append keeps the record tainted: it never reads as sequence 12.
func TestDeliveryTearClosedKeepsTaint(t *testing.T) {
	ctx := context.Background()
	s, _, u := fileLogScope(t)
	if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
		t.Fatal(err)
	}
	k := deliveriesFloorKey(t, s)
	line, err := floorLine(k.scope, k.name, k.gen, 123)
	if err != nil {
		t.Fatal(err)
	}
	torn := line[:bytes.LastIndexByte(line, ' ')-1] // "... 12"
	closer, err := floorLine("user/1002", "other", guid(0x11), 1)
	if err != nil {
		t.Fatal(err)
	}
	appendLogBytes(t, s, userFloorLogName, append(append(append([]byte{'\n'}, torn...), '\n'), closer...))
	if _, err := s.userFloor.floor(k.scope, k.name, k.gen); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("the delivery record over a closed tear %q: %v, want errFloorDegraded", torn, err)
	}
	if _, err := u.Delivery(ctx, testDelivery(1).uid); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("lookup over a closed delivery-line tear: %v, want errFloorDegraded", err)
	}
}

// A tombstone whose generation has one hex digit flipped to another, its
// name intact, gives a name taint: the known generation is refused, not
// served beside a tombstone for a generation that never was.
func TestFlippedGenerationDigitTaintsName(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	gen := entryGeneration(t, server, "token")
	tomb, err := tombLine("user/1001", "token", gen)
	if err != nil {
		t.Fatal(err)
	}
	at := len("user/1001 token ")
	if tomb[at] == 'a' {
		tomb[at] = 'b'
	} else {
		tomb[at] = 'a'
	}
	kind, k := classifyFloorDamage(tomb[:len(tomb)-1])
	if (kind != taintName && kind != taintNameFlip) || k.scope != "user/1001" || k.name != "token" {
		t.Fatalf("%q: %v %+v, want a name taint on user/1001 token", tomb, kind, k)
	}
	appendLogBytes(t, s, userFloorLogName, append([]byte{'\n'}, tomb...))
	if _, _, err := u.Current(ctx, "user/1001/token"); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("current of the known generation beside a flipped tombstone: %v, want errFloorDegraded", err)
	}
}

// A tombstone of a known generation, its marker corrupted in place, still
// refuses that generation: the tree copied back after rm is not served.
func TestCorruptTombstoneOfKnownGenerationRefused(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	gen := entryGeneration(t, server, "token")
	dir := filepath.Join(scopeDir(server, "1001"), scopeEntriesName, "token")
	saved := filepath.Join(t.TempDir(), "token")
	copyTree(t, dir, saved)
	if err := u.Delete(ctx, "user/1001/token"); err != nil {
		t.Fatalf("rm: %v", err)
	}
	corruptTombstones(t, s, "user/1001", "token", gen)
	restoreTree(t, saved, dir)
	if _, _, err := u.Current(ctx, "user/1001/token"); err == nil {
		t.Fatal("the copied-back tree of a known generation is served over its corrupted tombstone")
	}
}
