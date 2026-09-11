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
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
)

// splice is the per-CONNECTION data path: forwarder.run does `go f.splice(...)`
// for every accepted TCP connection to a LoadBalancer Service port. It is not
// per-packet — the byte streams move under io.Copy — so the unit that matters is
// cost per connection, and the cost is dominated by a large fixed constant
// rather than by payload size.
//
// That constant is why this benchmark exists. On darwin BOTH stdlib zero-copy
// paths are unavailable: net/splice_stub.go is //go:build !linux and returns
// handled=false, and sendfile's internal/poll.SendFile begins with a Seek on the
// source fd, which fails on a socket. So each io.Copy between two *net.TCPConn
// falls all the way through to io.copyBuffer's `buf = make([]byte, 32*1024)`,
// and splice performs two of them.
//
// The payload is deliberately tiny: this measures the connection's own overhead,
// which is what scales with connection churn, not throughput.

// spliceBackend starts an echo listener and returns its address plus a stop func.
func spliceBackend(b *testing.B) (string, func()) {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				// Read to EOF and reply once, so both directions carry bytes and
				// both io.Copy calls in splice do real work.
				buf := make([]byte, 64)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						_, _ = c.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		wg.Wait()
	}
}

// BenchmarkSplicePerConnection measures one full client connection through
// forwarder.splice: dial, exchange a few bytes each way, half-close, tear down.
func BenchmarkSplicePerConnection(b *testing.B) {
	backendAddr, stop := spliceBackend(b)
	defer stop()

	dstAP, err := netip.ParseAddrPort(backendAddr)
	if err != nil {
		b.Fatal(err)
	}
	f := &forwarder{dst: dstAP, log: slog.New(slog.DiscardHandler)}

	// The front listener the benchmark's clients connect to. splice is driven
	// directly rather than through run(), so the accept loop is not measured.
	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer front.Close()

	ctx := context.Background()
	served := make(chan struct{}, 1)
	go func() {
		for {
			c, err := front.Accept()
			if err != nil {
				return
			}
			f.splice(ctx, c)
			select {
			case served <- struct{}{}:
			default:
			}
		}
	}()

	payload := []byte("ping")
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		c, err := net.Dial("tcp", front.Addr().String())
		if err != nil {
			b.Fatal(err)
		}
		if _, err := c.Write(payload); err != nil {
			b.Fatal(err)
		}
		// Half-close so the client->backend copy reaches EOF and splice returns.
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		if _, err := io.ReadAll(c); err != nil {
			b.Fatal(err)
		}
		_ = c.Close()
		<-served
	}
}
