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
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// benchFloorRead writes a floor at the default caps from line, called with
// 0, 1, ... until it returns nil or the next line would take the floor past
// the reader's size bound, then reads it from scratch each iteration and
// reports the heap the read state holds and the time one read takes.
func benchFloorRead(b *testing.B, line func(i int, keys int) []byte) {
	b.Helper()
	s := &FileStore{logHardCap: defaultLogHardCap, logSoftCap: defaultLogSoftCap, logRevokeBudget: defaultLogRevocationBytes}
	l := newFileFloorLog(s).log
	keys := l.readKeyBound()
	bound := s.logReadBound()
	p := filepath.Join(b.TempDir(), userFloorLogName)
	w, err := os.Create(p)
	if err != nil {
		b.Fatal(err)
	}
	bw := bufio.NewWriterSize(w, 1<<20)
	var size int64
	for i := 0; ; i++ {
		ln := line(i, keys)
		if ln == nil || size+int64(len(ln)) > bound {
			break
		}
		size += int64(len(ln))
		_, _ = bw.Write(ln)
	}
	if err := bw.Flush(); err != nil {
		b.Fatal(err)
	}
	if err := w.Close(); err != nil {
		b.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		b.Fatal(err)
	}
	var (
		heap uint64
		read time.Duration
		got  int
		n    int
	)
	b.ResetTimer()
	for b.Loop() {
		l.state = logState{}
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		start := time.Now()
		state, err := l.sync(f, st)
		read = time.Since(start)
		if err != nil || state.bad != nil {
			b.Fatalf("read the floor: %v, %v", err, state.bad)
		}
		got = state.keys
		runtime.GC()
		runtime.ReadMemStats(&after)
		heap = after.HeapAlloc - before.HeapAlloc
		runtime.KeepAlive(state)
		n++
	}
	b.ReportMetric(float64(heap)/(1<<20), "MiB-heap")
	b.ReportMetric(read.Seconds(), "s-read")
	b.ReportMetric(float64(st.Size)/(1<<20), "MiB-file")
	b.ReportMetric(float64(got), "keys")
}

// longName is a distinct entry name of maxNameLen bytes for i.
func longName(i int) string {
	return nameOfLen(maxNameLen-12, "a") + fmt.Sprintf(".n%010d", i)
}

// BenchmarkFloorReadLongNames is the reader's heap worst case: a floor of
// distinct keys with maxNameLen-byte names and the longest scope, up to the
// reader's key bound or its size bound, whichever comes first
// (docs/design/keystore.md § "Size caps").
func BenchmarkFloorReadLongNames(b *testing.B) {
	benchFloorRead(b, func(i, keys int) []byte {
		if i >= keys {
			return nil
		}
		ln, err := floorLine(fmt.Sprintf("user/%d", maxScopeUID-i%1000), longName(i), guid(byte(i)), 18446744073709551615)
		if err != nil {
			b.Fatal(err)
		}
		return ln
	})
}

// BenchmarkFloorReadLineCount is the reader's time worst case: the most
// lines the size bound holds, the shortest that add a key up to the reader's
// key bound, then the shortest repeat lines for keys already held.
func BenchmarkFloorReadLineCount(b *testing.B) {
	benchFloorRead(b, func(i, keys int) []byte {
		k := i % keys
		ln, err := floorLine(fmt.Sprintf("user/%d", minScopeUID+k%9), fmt.Sprintf("%x", k/9), [generationSize]byte{}, uint64(i/keys))
		if err != nil {
			b.Fatal(err)
		}
		return ln
	})
}
