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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTar is the byte-scaling core of `k3sm image build`: it runs once per
// COPY/ADD, and inside it, once per file in the copied tree. MaxContextBytes
// caps a context at 2 GiB but nothing caps the ENTRY COUNT, so the unit that
// matters is per-entry cost, and a realistic dependency tree (node_modules,
// vendor/, site-packages) is tens of thousands of small files at depth.
//
// These benchmarks exist because the two regimes behave completely differently.
// io.Copy sizes its scratch buffer as min(32KiB, remaining) when the source is a
// *io.LimitedReader, so for files UNDER 32 KiB the discarded buffer is the size
// of the file — meaning per-entry buffer garbage tracks total context BYTES, not
// entry count. The small-file case is therefore the load-bearing one, and an
// average over both would hide it.

// benchTree materializes n files of the given size at the given nesting depth
// and returns the entries writeTar would be handed for them.
func benchTree(b *testing.B, n, size, depth int) []entry {
	b.Helper()
	dir := b.TempDir()
	body := make([]byte, size)
	for i := range body {
		body[i] = byte('a' + i%26)
	}
	nest := strings.Repeat("deep/", depth)
	entries := make([]entry, 0, n)
	for i := range n {
		host := filepath.Join(dir, fmt.Sprintf("f%05d", i))
		if err := os.WriteFile(host, body, 0o644); err != nil {
			b.Fatal(err)
		}
		entries = append(entries, entry{
			name: fmt.Sprintf("app/%sf%05d", nest, i),
			mode: 0o644,
			size: int64(size),
			host: host,
		})
	}
	return entries
}

func benchWriteTar(b *testing.B, n, size, depth int) {
	entries := benchTree(b, n, size, depth)
	b.ReportAllocs()
	b.SetBytes(int64(n * size))
	b.ResetTimer()
	for range b.N {
		if err := writeTar(io.Discard, entries); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkWriteTarSmallFiles is the regime where the copy buffer equals the
// file size, so discarded buffer volume equals the bytes copied. This is the
// shape of a real dependency tree.
func BenchmarkWriteTarSmallFiles(b *testing.B) { benchWriteTar(b, 3000, 6*1024, 6) }

// BenchmarkWriteTarLargeFiles is the regime where the buffer saturates at
// 32 KiB, so per-entry garbage is constant rather than proportional.
func BenchmarkWriteTarLargeFiles(b *testing.B) { benchWriteTar(b, 500, 256*1024, 6) }

// BenchmarkWriteTarDeepTree holds bytes almost constant and varies only nesting,
// isolating the per-ancestor cost of parent-directory emission from the cost of
// copying file bodies.
func BenchmarkWriteTarDeepTree(b *testing.B) { benchWriteTar(b, 3000, 64, 10) }
