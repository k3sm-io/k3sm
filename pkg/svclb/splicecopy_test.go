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

package svclb

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
)

// TestOnlyWrapperseHideTheCopyFastPaths is the guard on the reason copyPooled is
// written the way it is, and it is the test this change most needs.
//
// io.copyBuffer tests src.(io.WriterTo) and dst.(io.ReaderFrom) BEFORE it looks
// at the buffer it was given. A *net.TCPConn satisfies both. So the obvious
// "simplification" — io.CopyBuffer(dst, src, buf) without the wrappers — still
// compiles, still copies bytes correctly, still passes every behavioural test in
// this package, and silently goes back to allocating 32 KiB per direction per
// connection. Only an assertion on the interfaces catches that.
func TestOnlyWrappersHideTheCopyFastPaths(t *testing.T) {
	t.Parallel()
	c1, c2 := tcpPair(t)

	// Precondition: the bare conns really do implement both fast paths. If this
	// ever stops holding, the wrappers are pointless and this test should be
	// revisited rather than deleted.
	if _, ok := any(c1).(io.WriterTo); !ok {
		t.Fatal("*net.TCPConn is no longer an io.WriterTo; the premise of copyPooled has changed")
	}
	if _, ok := any(c2).(io.ReaderFrom); !ok {
		t.Fatal("*net.TCPConn is no longer an io.ReaderFrom; the premise of copyPooled has changed")
	}

	// The wrappers must hide them, or the supplied buffer is discarded.
	if _, ok := any(onlyReader{c1}).(io.WriterTo); ok {
		t.Error("onlyReader still exposes io.WriterTo: io.copyBuffer will take the WriteTo fast path " +
			"and DISCARD the pooled buffer, restoring a 32 KiB allocation per direction per connection")
	}
	if _, ok := any(onlyWriter{c2}).(io.ReaderFrom); ok {
		t.Error("onlyWriter still exposes io.ReaderFrom: io.copyBuffer will take the ReadFrom fast path " +
			"and DISCARD the pooled buffer, restoring a 32 KiB allocation per direction per connection")
	}
}

// TestCopyPooledDoesNotAllocatePerCall pins the allocation outcome, measured
// rather than argued. A per-call 32 KiB buffer is unmistakable at this scale.
func TestCopyPooledDoesNotAllocatePerCall(t *testing.T) {
	const calls = 40

	// Each call needs its own conn pair with the write half closed, so the copy
	// sees immediate EOF and we measure the copy's own bookkeeping only.
	srcs := make([]*net.TCPConn, 0, calls)
	dsts := make([]*net.TCPConn, 0, calls)
	for range calls {
		a, b := tcpPair(t)
		// copyPooled READS from a, so a reaches EOF only when a's PEER closes
		// its write half. Closing a's own write half would leave the read
		// blocked forever.
		if err := b.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		srcs = append(srcs, a)
		dsts = append(dsts, b)
	}

	// Warm the pool so its first New is not attributed to the measurement.
	if _, err := copyPooled(dsts[0], srcs[0]); err != nil {
		t.Fatalf("copyPooled: %v", err)
	}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := 1; i < calls; i++ {
		if _, err := copyPooled(dsts[i], srcs[i]); err != nil {
			t.Fatalf("copyPooled: %v", err)
		}
	}
	runtime.ReadMemStats(&after)

	perCall := (after.TotalAlloc - before.TotalAlloc) / uint64(calls-1)
	// The bound is derived from the buffer size rather than hand-picked, so it
	// tracks spliceBufSize if that ever changes. Half the buffer separates the
	// two outcomes with margin at both ends: the pooled path measures a few
	// hundred bytes normally and ~10 KB under -race (the detector's own
	// bookkeeping, which is why this cannot be a tight bound), while a
	// discarded buffer measures at least spliceBufSize itself.
	limit := uint64(spliceBufSize / 2)
	if perCall > limit {
		t.Errorf("copyPooled allocated %d B per call, want under %d "+
			"(>= %d would mean the pooled buffer is being discarded and io.copyBuffer is "+
			"allocating its own — see TestOnlyWrappersHideTheCopyFastPaths)",
			perCall, limit, spliceBufSize)
	}
}

// TestCopyPooledCopiesFaithfully proves the pooled, chunked path still moves
// bytes exactly — including a payload several times the buffer size, so buffer
// REUSE across chunks is exercised rather than a single-chunk happy path. A
// pooled buffer that leaked state between chunks or between calls would corrupt
// proxied traffic, which is the one way this optimisation could do real damage.
func TestCopyPooledCopiesFaithfully(t *testing.T) {
	t.Parallel()
	for _, size := range []int{0, 1, 1024, spliceBufSize, spliceBufSize*3 + 7} {
		payload := make([]byte, size)
		if _, err := rand.Read(payload); err != nil {
			t.Fatal(err)
		}
		src, srcPeer := tcpPair(t)
		var got bytes.Buffer
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := srcPeer.Write(payload); err != nil {
				return
			}
			_ = srcPeer.CloseWrite()
		}()
		n, err := copyPooled(&got, src)
		wg.Wait()
		if err != nil {
			t.Fatalf("size %d: copyPooled: %v", size, err)
		}
		if n != int64(size) {
			t.Errorf("size %d: copied %d bytes, want %d", size, n, size)
		}
		if !bytes.Equal(got.Bytes(), payload) {
			t.Errorf("size %d: copied bytes differ from the source — a pooled buffer is leaking state between chunks or calls", size)
		}
	}
}

// tcpPair returns two connected TCP conns, closed at test end.
func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	got := <-ch
	if got.err != nil {
		t.Fatal(got.err)
	}
	a, b := client.(*net.TCPConn), got.c.(*net.TCPConn)
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	return a, b
}
