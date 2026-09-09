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
// replacing strings.Split + strings.Join with prefix slicing. The two must agree
// on the exact SET and ORDER of directory entries emitted, because those headers
// are part of the digested tar bytes — a divergence would silently change every
// layer digest, and the golden-digest test only covers the one fixture it builds.
func TestWriteParentsMatchesSplitJoinSemantics(t *testing.T) {
	t.Parallel()

	// reference is the pre-optimisation body, kept verbatim as the oracle.
	reference := func(tw *tar.Writer, name string, seen map[string]bool) error {
		parts := strings.Split(name, "/")
		for i := 1; i < len(parts); i++ {
			dir := strings.Join(parts[:i], "/")
			if dir == "" || seen[dir] {
				continue
			}
			seen[dir] = true
			if err := tw.WriteHeader(&tar.Header{
				Typeflag: tar.TypeDir,
				Name:     dir + "/",
				Mode:     0o755,
				Format:   tar.FormatPAX,
			}); err != nil {
				return err
			}
		}
		return nil
	}

	// Names chosen to cover: plain nesting, repeated ancestors (the seen-hit
	// path), single labels with no separator, leading slash, doubled slash, and
	// deep repetition.
	corpora := [][]string{
		{"app/main"},
		{"app/lib/x", "app/lib/y", "app/lib/z"},
		{"a/b/c/d/e/f/g"},
		{"solo"},
		{"/leading/slash"},
		{"double//slash/file"},
		{"app/lib/x", "app/lib/x", "other/lib/x"},
		{"a/b", "a/b/c", "a/b/c/d"},
		{"x//", "x/y"},
	}
	for i, names := range corpora {
		t.Run(fmt.Sprintf("corpus%d", i), func(t *testing.T) {
			t.Parallel()
			got := collectDirNames(t, names, writeParents)
			want := collectDirNames(t, names, reference)
			if len(got) != len(want) {
				t.Fatalf("names %v: emitted %d dir headers %v, reference emitted %d %v",
					names, len(got), got, len(want), want)
			}
			for j := range want {
				if got[j] != want[j] {
					t.Errorf("names %v: dir header %d = %q, reference = %q (order and set must match exactly — these bytes are digested)",
						names, j, got[j], want[j])
				}
			}
		})
	}
}

// collectDirNames runs a writeParents-shaped function over names and returns the
// directory entry names it emitted, in order.
func collectDirNames(t *testing.T, names []string, fn func(*tar.Writer, string, map[string]bool) error) []string {
	t.Helper()
	var sink strings.Builder
	tw := tar.NewWriter(&sink)
	seen := map[string]bool{}
	for _, n := range names {
		if err := fn(tw, n, seen); err != nil {
			t.Fatalf("writeParents(%q): %v", n, err)
		}
	}
	// Bodies are irrelevant; flush headers only.
	if err := tw.Flush(); err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(strings.NewReader(sink.String()))
	var out []string
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		out = append(out, h.Name)
	}
	return out
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
