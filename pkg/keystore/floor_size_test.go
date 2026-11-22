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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The tests for the floor's size bound: every floor write refuses a result
// larger than maxFloorSize, so the floor on disk always reads back.

// nameOfLen returns a checkName name of n characters made of c.
func nameOfLen(n int, c string) string {
	var b strings.Builder
	for n > 63 {
		b.WriteString(strings.Repeat(c, 62) + ".")
		n -= 63
	}
	b.WriteString(strings.Repeat(c, n))
	return b.String()
}

// fillFloor writes keep, plus filler entries, as the floor under server, so
// that its encoding is exactly size bytes.
func fillFloor(t *testing.T, server string, keep floor, size int) {
	t.Helper()
	fl := floor{}
	for name, e := range keep {
		fl[name] = e
	}
	e := floorEntry{Generation: strings.Repeat("ab", generationSize), Seq: 1}
	have := fl.size()
	for i := 0; ; i++ {
		// Stop while what is left is a single entry of a valid name length.
		left := size - have
		if left <= fl.grow(nameOfLen(maxNameLen, "z"), e) {
			name := nameOfLen(left-fl.grow("", e), "z")
			fl[name] = e
			break
		}
		name := fmt.Sprintf("fill-%s-%07d", strings.Repeat("f", 180), i)
		have += fl.grow(name, e)
		fl[name] = e
	}
	b, err := marshalFloor(fl)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != size || fl.size() != size {
		t.Fatalf("filled floor is %d bytes (size() %d), want %d", len(b), fl.size(), size)
	}
	putFloorFile(t, server, fl)
}

// TestFloorSize: size, grow and the entry bound agree with marshalFloor.
func TestFloorSize(t *testing.T) {
	gen := strings.Repeat("0f", generationSize)
	fl := floor{}
	for i, name := range []string{"a", "signer-key", nameOfLen(maxNameLen, "q")} {
		b, err := marshalFloor(fl)
		if err != nil {
			t.Fatal(err)
		}
		if fl.size() != len(b) {
			t.Fatalf("size() = %d, marshalFloor %d bytes", fl.size(), len(b))
		}
		e := floorEntry{Generation: gen, Seq: uint64(1) << (20 * i)}
		grow := fl.grow(name, e)
		fl[name] = e
		after, _ := marshalFloor(fl)
		if len(after)-len(b) != grow {
			t.Fatalf("grow(%q) = %d, the encoding grew %d", name, grow, len(after)-len(b))
		}
	}
	one := floor{"a": {Generation: gen, Seq: 1}}
	two := floor{"a": {Generation: gen, Seq: 1}, "b": {Generation: gen, Seq: 1}}
	if two.size()-one.size() != minFloorEntrySize {
		t.Fatalf("minFloorEntrySize = %d, an entry adds %d", minFloorEntrySize, two.size()-one.size())
	}
	if floor(nil).size()+maxFloorEntries*minFloorEntrySize <= maxFloorSize-minFloorEntrySize {
		t.Fatalf("maxFloorEntries %d leaves room for another entry", maxFloorEntries)
	}
}

// TestFloorFull: a floor filled to the bound refuses, before anything is
// written, the write that would take it over (a Put of a new entry, a Rotate
// whose sequence gains a digit), and the floor on disk stays as it was and
// still reads. A root verb's raise leaves out an entry that does not fit,
// and still runs; Delete still makes room.
func TestFloorFull(t *testing.T) {
	ctx := context.Background()
	// k at sequence 9, whose next Rotate writes sequence 10, a byte longer.
	setup := func(t *testing.T) (*FileStore, string, []byte) {
		s, server := newTestStore(t)
		mustPut(t, s, "k", KindOpaque, []byte("v1"))
		for i := 2; i <= 9; i++ {
			mustRotate(t, s, "k", fmt.Sprintf("v%d", i))
		}
		fillFloor(t, server, floor{"k": floorOf(t, server)["k"]}, maxFloorSize)
		before, err := os.ReadFile(floorPath(server))
		if err != nil {
			t.Fatal(err)
		}
		return s, server, before
	}
	unchanged := func(t *testing.T, s *FileStore, server string, before []byte) {
		t.Helper()
		if after, err := os.ReadFile(floorPath(server)); err != nil || !bytes.Equal(after, before) {
			t.Fatalf("the floor changed (%d bytes, %v), want the %d bytes it held", len(after), err, len(before))
		}
		mustCurrent(t, s, "k", "v9")
		if list, err := s.List(ctx); err != nil || len(list) != 1 || list[0].Err != nil {
			t.Fatalf("List over a full floor = %+v, %v", list, err)
		}
	}

	t.Run("Put of a new entry", func(t *testing.T) {
		t.Parallel()
		s, server, before := setup(t)
		if _, err := s.Put(ctx, "new", KindOpaque, []byte("x")); !errors.Is(err, errFloorFull) {
			t.Fatalf("Put into a full floor: %v, want errFloorFull", err)
		}
		if _, err := os.Lstat(filepath.Join(server, "keystore", "new")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the refused Put left its entry directory: %v", err)
		}
		unchanged(t, s, server, before)
	})
	t.Run("Rotate whose sequence gains a digit", func(t *testing.T) {
		t.Parallel()
		s, server, before := setup(t)
		entry := dirContents(t, filepath.Join(server, "keystore", "k"))
		if _, err := s.Rotate(ctx, "k", []byte("v10")); !errors.Is(err, errFloorFull) {
			t.Fatalf("Rotate into a full floor: %v, want errFloorFull", err)
		}
		if got := dirContents(t, filepath.Join(server, "keystore", "k")); len(got) != len(entry) {
			t.Fatalf("the refused Rotate changed the entry: %v, was %v", got, entry)
		}
		unchanged(t, s, server, before)
	})
	t.Run("a raise that does not fit is left out", func(t *testing.T) {
		t.Parallel()
		s, server := newTestStore(t)
		mustPut(t, s, "k", KindOpaque, []byte("v9"))
		// k is not recorded, and the floor has no room to record it.
		fillFloor(t, server, nil, maxFloorSize-minFloorEntrySize+1)
		before, err := os.ReadFile(floorPath(server))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.RaiseFloor(ctx); err != nil {
			t.Fatalf("RaiseFloor over a full floor: %v, want the raise left out", err)
		}
		unchanged(t, s, server, before)
	})
	t.Run("update refuses a result over the bound", func(t *testing.T) {
		t.Parallel()
		s, server, before := setup(t)
		l, _, err := s.lockFloor(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = l.update(func(fl floor) bool { changed, _, _ := fl.set("over", [generationSize]byte{1}); return changed })
		l.unlock()
		if !errors.Is(err, errFloorFull) {
			t.Fatalf("update over the bound: %v, want errFloorFull", err)
		}
		unchanged(t, s, server, before)
	})
	t.Run("Delete makes room", func(t *testing.T) {
		t.Parallel()
		s, server, _ := setup(t)
		if err := s.Delete(ctx, "k"); err != nil {
			t.Fatalf("Delete in a full floor: %v", err)
		}
		if _, ok := floorOf(t, server)["k"]; ok {
			t.Fatal("Delete left k's floor entry")
		}
		// k's entry is the size of n's, so n now fits.
		mustPut(t, s, "n", KindOpaque, []byte("x"))
	})
}

// TestFloorPutExactBound: a Put whose floor lands exactly on maxFloorSize
// succeeds, and the size the room check computes is the length of the floor
// written. A Put one byte over is refused with nothing written.
func TestFloorPutExactBound(t *testing.T) {
	ctx := context.Background()
	const name = "edge"
	// The floor entry a Put of name writes: sequence 1, a real generation.
	e := floorEntry{Generation: strings.Repeat("00", generationSize), Seq: 1}
	// The filler makes the floor non-empty, so the entry adds its comma too.
	add := floorEntrySize(name, e) + 1

	t.Run("lands exactly on the bound", func(t *testing.T) {
		t.Parallel()
		s, server := newTestStore(t)
		fillFloor(t, server, nil, maxFloorSize-add)
		fl := floorOf(t, server)
		// What room computes for the result of this Put.
		want := fl.size() + fl.grow(name, e)
		if want != maxFloorSize {
			t.Fatalf("room's size = %d, want exactly %d", want, maxFloorSize)
		}
		if err := fl.room(name, e); err != nil {
			t.Fatalf("room refused a floor that lands on the bound: %v", err)
		}
		if _, err := s.Put(ctx, name, KindOpaque, []byte("x")); err != nil {
			t.Fatalf("Put landing on maxFloorSize: %v", err)
		}
		got := floorOf(t, server)
		b, err := marshalFloor(got)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) != want || len(b) != maxFloorSize {
			t.Fatalf("written floor is %d bytes, room computed %d, want %d", len(b), want, maxFloorSize)
		}
		if disk, err := os.ReadFile(floorPath(server)); err != nil || len(disk) != len(b) {
			t.Fatalf("floor file is %d bytes (%v), want %d", len(disk), err, len(b))
		}
		mustCurrent(t, s, name, "x")
	})
	t.Run("one byte over is refused", func(t *testing.T) {
		t.Parallel()
		s, server := newTestStore(t)
		fillFloor(t, server, nil, maxFloorSize-add+1)
		before, err := os.ReadFile(floorPath(server))
		if err != nil {
			t.Fatal(err)
		}
		if err := floorOf(t, server).room(name, e); !errors.Is(err, errFloorFull) || !strings.Contains(err.Error(), fmt.Sprintf("(%d bytes)", maxFloorSize+1)) {
			t.Fatalf("room one byte over: %v, want errFloorFull at %d bytes", err, maxFloorSize+1)
		}
		if _, err := s.Put(ctx, name, KindOpaque, []byte("x")); !errors.Is(err, errFloorFull) {
			t.Fatalf("Put one byte over: %v, want errFloorFull", err)
		}
		if _, err := os.Lstat(filepath.Join(server, "keystore", name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the refused Put left its entry directory: %v", err)
		}
		if after, err := os.ReadFile(floorPath(server)); err != nil || !bytes.Equal(after, before) {
			t.Fatalf("the floor changed (%d bytes, %v), want the %d bytes it held", len(after), err, len(before))
		}
	})
}
