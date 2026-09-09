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

// TestCopyPooledDoesNotAllocatePerCall pins the PER-CALL allocation: that
// entering copyPooled does not itself allocate a 32 KiB buffer, which is what
// dropping the interface wrappers would restore.
//
// Scope limit, stated because it is easy to over-read: every peer's write half
// is closed before the copy, so io.copyBuffer's loop body never runs and this
// measures only the per-call overhead. It therefore CANNOT see a buffer
// allocated per chunk — TestCopyPooledAllocationDoesNotScaleWithChunks covers
// that, and neither test subsumes the other.
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
	// Three quarters of the buffer, not half. The bound has to clear -race's
	// own accounting from below and stay under a restored buffer from above,
	// and half the buffer was too close to the floor: measured overhead under
	// -race reaches ~14.4 KB against a 16 KB bound, i.e. ~12% headroom, which
	// is a flaky test waiting for a different machine or toolchain. At 24 KB
	// the margins are ~70% above the observed -race ceiling and ~25% below a
	// restored buffer (32.9 KB plain, 44.7 KB under -race), both verified by
	// mutation in both modes.
	limit := uint64(spliceBufSize * 3 / 4)
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

// TestCopyPooledConcurrentCopiesDoNotAlias is the guard on the pool's central
// safety claim, and the one this file was missing.
//
// copyPooled draws a shared buffer from a sync.Pool, and splice runs one copy
// per direction per connection — all concurrent. If a buffer is ever held by
// two copies at once (one shared buffer instead of a pool, a Put before the
// copy finishes, a double Put handing the same buffer to two callers), bytes
// from one proxied connection land in another. That is silent traffic
// corruption between unrelated clients, and it is the worst thing this change
// could do.
//
// Nothing else in this package tests it: the fidelity test is single-threaded
// and the benchmark drives splice synchronously from its accept loop. Verified
// against three separate aliasing mutations, each of which passes the rest of
// the suite under -race.
//
// Detection is by CONTENT, not by the race detector, so this fails on a plain
// `go test` too: each connection carries its own distinct repeated byte, and
// any byte from a different connection appearing in the output is aliasing.
func TestCopyPooledConcurrentCopiesDoNotAlias(t *testing.T) {
	const conns = 48
	// Several buffer-lengths each, so every copy loops many times and the
	// window for a shared buffer to be observed is wide.
	payloadLen := spliceBufSize*5 + 137

	var wg sync.WaitGroup
	errs := make(chan string, conns)
	for i := range conns {
		// A byte value unique per connection, avoiding 0 so a zeroed buffer is
		// distinguishable from a wrong-connection byte.
		want := byte(1 + i)
		src, peer := tcpPair(t)
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload := bytes.Repeat([]byte{want}, payloadLen)
			if _, err := peer.Write(payload); err != nil {
				return
			}
			_ = peer.CloseWrite()
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			var got bytes.Buffer
			n, err := copyPooled(&got, src)
			if err != nil {
				errs <- "copyPooled: " + err.Error()
				return
			}
			if n != int64(payloadLen) {
				errs <- "short copy"
				return
			}
			// The whole point: every byte must be this connection's own.
			for off, b := range got.Bytes() {
				if b != want {
					errs <- "ALIASING: connection expecting byte " +
						string(rune('0'+want%10)) + " saw a foreign byte at offset " +
						itoa(off) + " — a pooled buffer is shared between concurrent copies"
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// TestCopyPooledAllocationDoesNotScaleWithChunks closes the second hole: the
// zero-byte test above never executes io.copyBuffer's loop body at all, so it
// cannot see a buffer allocated per CHUNK rather than per call.
//
// A per-chunk allocation is strictly worse than the io.Copy it replaced — it
// pays 32 KiB for every 32 KiB moved instead of once per connection — and it
// passes both the zero-byte allocation test and the fidelity test. The
// invariant that catches it is scale-independence: for the same number of
// calls, allocation must not grow with the number of chunks copied.
//
// A ratio is used rather than an absolute bound because -race inflates the
// baseline substantially; a ratio is immune to that.
func TestCopyPooledAllocationDoesNotScaleWithChunks(t *testing.T) {
	measure := func(chunks int) uint64 {
		const calls = 8
		payload := bytes.Repeat([]byte("x"), spliceBufSize*chunks)
		run := func() {
			for range calls {
				src, peer := tcpPair(t)
				var wg sync.WaitGroup
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, _ = peer.Write(payload)
					_ = peer.CloseWrite()
				}()
				if _, err := copyPooled(io.Discard, src); err != nil {
					t.Fatalf("copyPooled: %v", err)
				}
				wg.Wait()
			}
		}
		run() // warm the pool and the conn machinery
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		run()
		runtime.ReadMemStats(&after)
		return (after.TotalAlloc - before.TotalAlloc) / calls
	}

	few := measure(2)
	many := measure(64) // 32x the chunks
	if few == 0 {
		t.Fatal("measured zero allocation; the measurement is broken, not the code")
	}
	ratio := float64(many) / float64(few)
	if ratio > 8 {
		t.Errorf("copyPooled allocated %d B/call copying 2 chunks but %d B/call copying 64 chunks "+
			"(ratio %.1fx, want < 8x): allocation is scaling with CHUNK COUNT, so a buffer is being "+
			"allocated per chunk rather than drawn once from the pool — strictly worse than the io.Copy "+
			"this replaced", few, many, ratio)
	}
}

// itoa avoids a fmt dependency in the hot assertion loop above.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
