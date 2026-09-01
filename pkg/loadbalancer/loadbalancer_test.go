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

package loadbalancer

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// TestApiserverLBPicksHealthy proves the picker skips a DOWN server and only returns
// healthy ones — the mechanism by which a worker keeps reaching the apiserver set after
// one server dies. The health check is injected (no real sockets).
func TestApiserverLBPicksHealthy(t *testing.T) {
	t.Parallel()

	const down, upA, upB = "10.0.0.1:6444", "10.0.0.2:6444", "10.0.0.3:6444"
	check := func(_ context.Context, server string) bool { return server != down }

	lb := New([]string{down, upA, upB}, check, nil)
	lb.UpdateHealth(context.Background())

	// Pick never returns the down server, always a healthy one.
	for i := 0; i < 20; i++ {
		s, ok := lb.Pick()
		if !ok {
			t.Fatal("Pick returned no server though two are healthy")
		}
		if s == down {
			t.Fatalf("Pick returned the DOWN server %q", s)
		}
	}

	healthy := lb.Healthy()
	if len(healthy) != 2 {
		t.Errorf("Healthy() = %v, want the two up servers", healthy)
	}

	// All servers down → Pick reports none.
	allDown := New([]string{down}, func(context.Context, string) bool { return false }, nil)
	allDown.UpdateHealth(context.Background())
	if _, ok := allDown.Pick(); ok {
		t.Error("Pick must report false when no server is healthy")
	}

	// Empty set → none.
	if _, ok := New(nil, check, nil).Pick(); ok {
		t.Error("Pick on an empty set must report false")
	}
}

// TestLoadBalancerForwardsToHealthy proves the TCP forward path end-to-end in-process:
// a client connecting to the local LB endpoint is proxied to a healthy upstream (an echo
// server), and the bytes round-trip. This is the local-endpoint mechanism the worker
// kubeconfig targets so a server death fails over without re-pointing.
func TestLoadBalancerForwardsToHealthy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Upstream echo server.
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upstream.Close()
	go func() {
		for {
			c, err := upstream.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()

	lb := New([]string{upstream.Addr().String()}, func(context.Context, string) bool { return true }, nil)
	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen front: %v", err)
	}
	go func() { _ = lb.serveListener(ctx, front) }()

	conn, err := net.DialTimeout("tcp", front.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial LB: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "ping" {
		t.Errorf("echo = %q, want ping (LB did not forward to the healthy upstream)", buf)
	}
}

// TestLoadBalancerDeliversResponseAfterClientHalfClose pins the half-duplex case the
// apiserver LB exists to carry: a client that finishes its request and half-closes must
// still receive the WHOLE response. That is `kubectl logs -f`, `exec`, and every watch —
// the client stops writing early and then reads for a long time.
//
// The upstream here deliberately sends only AFTER it has observed the client's EOF, and
// sends a payload far larger than any socket buffer, so a forwarder that tears the pair
// down when the first copy direction ends cannot accidentally satisfy the read: it has
// already closed both conns before the response exists. The brief pause after the EOF
// removes the last ordering coincidence; it does not weaken the assertion, which is
// byte-exact delivery of the full payload.
func TestLoadBalancerDeliversResponseAfterClientHalfClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const payload = 1 << 20 // 1 MiB: bigger than any loopback socket buffer

	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upstream.Close()
	sawEOF := make(chan struct{})
	go func() {
		c, err := upstream.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// Drain the request; the read ends when the client half-closes.
		_, _ = io.Copy(io.Discard, c)
		close(sawEOF)
		// A real apiserver goes on streaming here for as long as the watch lives.
		time.Sleep(50 * time.Millisecond)
		_, _ = c.Write(make([]byte, payload))
	}()

	lb := New([]string{upstream.Addr().String()}, func(context.Context, string) bool { return true }, nil)
	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen front: %v", err)
	}
	go func() { _ = lb.serveListener(ctx, front) }()

	conn, err := net.DialTimeout("tcp", front.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial LB: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := conn.Write([]byte("GET /watch")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	// The client is done writing — exactly what an in-flight watch looks like.
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("half-close: %v", err)
	}
	<-sawEOF

	n, err := io.Copy(io.Discard, conn)
	if err != nil {
		t.Fatalf("read response after the half-close: %v (got %d of %d bytes)", err, n, payload)
	}
	if n != payload {
		t.Errorf("received %d bytes, want %d — the forward truncated the response at the client's half-close", n, payload)
	}
}
