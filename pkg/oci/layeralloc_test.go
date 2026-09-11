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

package oci

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestWriteTarAllocationDoesNotScaleWithFileSize pins the invariant behind
// hoisting writeTar's copy buffer, rather than pinning a byte count that would
// drift with unrelated changes.
//
// The defect was that io.Copy allocated a scratch buffer per entry, sized
// min(32KiB, remaining) because the source is a *io.LimitedReader — so a tree of
// small files allocated roughly its own total byte volume in single-use buffers.
// The invariant that fixes it is size-independence: for a FIXED number of
// entries, writeTar's allocation must not grow with how big the files are. A
// per-entry buffer violates that; one hoisted buffer satisfies it.
//
// Stated as a ratio rather than an absolute so the test survives legitimate
// changes to header handling, while still failing loudly if per-entry buffering
// returns — with a 64x file-size spread, a per-entry buffer moves the ratio to
// well over 10x.
func TestWriteTarAllocationDoesNotScaleWithFileSize(t *testing.T) {
	const entries = 400

	measure := func(size int) uint64 {
		ents := allocTree(t, entries, size)
		// Warm once: first call faults in pages and populates the `seen` map
		// sizing, which would otherwise land in the measured sample.
		if err := writeTar(io.Discard, ents); err != nil {
			t.Fatal(err)
		}
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		if err := writeTar(io.Discard, ents); err != nil {
			t.Fatal(err)
		}
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc
	}

	small := measure(64)
	large := measure(64 * 1024) // 1024x the bytes per file

	// Guard against a degenerate measurement before interpreting the ratio.
	if small == 0 {
		t.Fatal("measured zero allocation for the small-file tree; the measurement is broken, not the code")
	}
	ratio := float64(large) / float64(small)
	if ratio > 8 {
		t.Errorf("writeTar allocated %d bytes for %d files of 64 B but %d bytes for the same count at 64 KiB "+
			"(ratio %.1fx, want < 8x): allocation is scaling with FILE SIZE, which means a per-entry copy "+
			"buffer is back — io.Copy sizes its scratch buffer to the file for anything under 32 KiB, so this "+
			"puts the whole context's byte volume back through the heap",
			small, entries, large, ratio)
	}
}

// TestWriteParentsMatchesSplitJoinSemantics is the equivalence check for
// replacing strings.Split + strings.Join with prefix slicing.
//
// It compares the RAW TAR BYTES, not the header names, because the bytes are
// what gets hashed into the layer digest — and the parent headers carry Mode,
// Uid, Gid, ModTime and Format as well as Name. An earlier version of this test
// compared names only, against an oracle that omitted Uid/Gid/ModTime; it would
// have passed while any of those fields changed underneath it. Comparing the
// serialized bytes makes the test pin what it claims to pin.
//
// The oracle below is the pre-optimisation body with a header literal kept
// byte-identical to production's, so a divergence in either the dir sequence or
// the header fields fails here.
func TestWriteParentsMatchesSplitJoinSemantics(t *testing.T) {
	t.Parallel()

	reference := func(tw *tar.Writer, name string, seen map[string]bool) error {
		parts := strings.Split(name, "/")
		for i := 1; i < len(parts); i++ {
			dir := strings.Join(parts[:i], "/")
			if dir == "" || seen[dir] {
				continue
			}
			seen[dir] = true
			if err := tw.WriteHeader(&tar.Header{
				Name:     dir + "/",
				Typeflag: tar.TypeDir,
				Mode:     modeDir,
				Uid:      entryUID,
				Gid:      entryGID,
				ModTime:  epoch,
				Format:   tar.FormatPAX,
			}); err != nil {
				return err
			}
		}
		return nil
	}

	// Corpus deliberately includes the separator-anomalous shapes that
	// filepath.Clean makes unreachable in production. They are where a
	// hand-derived equivalence argument is most likely to be wrong, so they are
	// exactly what an equivalence test should cover — the two implementations
	// must agree there too, reachable or not.
	corpora := [][]string{
		{"app/main"},
		{"app/lib/x", "app/lib/y", "app/lib/z"},
		{"a/b/c/d/e/f/g"},
		{"solo"},
		{""},
		{"/"},
		{"//"},
		{"///"},
		{"a/"},
		{"/a"},
		{"a//b"},
		{"//a"},
		{"a//"},
		{"/leading/slash"},
		{"double//slash/file"},
		{"app/lib/x", "app/lib/x", "other/lib/x"},
		{"a/b", "a/b/c", "a/b/c/d"},
		{"x//", "x/y"},
		{".", "..", "..."},
		{"a/./b", "a/../b"},
		{"é/漢/🙂"},
		{"\xff/\xc3\x28"}, // invalid UTF-8
		{strings.Repeat("d/", 60) + "leaf"},
		{strings.Repeat("/", 16) + "x"},
	}
	for i, names := range corpora {
		t.Run(fmt.Sprintf("corpus%d", i), func(t *testing.T) {
			t.Parallel()
			gotBytes, gotSeen := runWriteParents(t, names, writeParents)
			wantBytes, wantSeen := runWriteParents(t, names, reference)
			if !bytes.Equal(gotBytes, wantBytes) {
				t.Errorf("names %v: emitted tar bytes differ from the split/join reference — "+
					"these bytes are hashed into the layer digest\n got %d bytes\nwant %d bytes",
					names, len(gotBytes), len(wantBytes))
			}
			if len(gotSeen) != len(wantSeen) {
				t.Errorf("names %v: seen map has %d keys, reference has %d", names, len(gotSeen), len(wantSeen))
			}
			for k := range wantSeen {
				if !gotSeen[k] {
					t.Errorf("names %v: seen map is missing key %q that the reference recorded", names, k)
				}
			}
		})
	}
}

// runWriteParents drives a writeParents-shaped function over names and returns
// the serialized tar bytes plus the resulting seen map.
func runWriteParents(t *testing.T, names []string, fn func(*tar.Writer, string, map[string]bool) error) ([]byte, map[string]bool) {
	t.Helper()
	var sink bytes.Buffer
	tw := tar.NewWriter(&sink)
	seen := map[string]bool{}
	for _, n := range names {
		if err := fn(tw, n, seen); err != nil {
			t.Fatalf("writeParents(%q): %v", n, err)
		}
	}
	if err := tw.Flush(); err != nil {
		t.Fatal(err)
	}
	return sink.Bytes(), seen
}

// allocTree materializes n files of the given size and returns their entries.
func allocTree(t *testing.T, n, size int) []entry {
	t.Helper()
	dir := t.TempDir()
	body := make([]byte, size)
	ents := make([]entry, 0, n)
	for i := range n {
		host := filepath.Join(dir, fmt.Sprintf("f%05d", i))
		if err := os.WriteFile(host, body, 0o644); err != nil {
			t.Fatal(err)
		}
		ents = append(ents, entry{
			name: fmt.Sprintf("app/lib/f%05d", i),
			mode: 0o644,
			size: int64(size),
			host: host,
		})
	}
	return ents
}
