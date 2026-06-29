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
