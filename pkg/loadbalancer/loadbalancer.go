// Package loadbalancer is the client-side apiserver load-balancer for HA (M6.1). A
// joined node — and the admin kubeconfig — targets a LOCAL endpoint that health-checks
// the set of control-plane apiservers and forwards each connection to a healthy one, so
// a server death fails over WITHOUT re-pointing the kubeconfig (the k3s agent
// load-balancer model). The server set arrives in the join result (bootstrap
// JoinResult.APIServers); the live cross-Mac failover is the lab leg, but the
// set-tracking + health-check + pick-healthy + TCP-forward logic here is unit-verified.
package loadbalancer

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// HealthCheck reports whether a control-plane server (host:port) is currently serving.
// It is injected so the picker is unit-testable without real sockets; the production
// default (DialHealthCheck) is a bounded TCP dial.
type HealthCheck func(ctx context.Context, server string) bool

// LoadBalancer tracks a set of apiserver endpoints + their health and picks a healthy
// one (round-robin across the healthy subset). It also forwards raw TCP connections to a
// picked server (Serve).
//
// Locking discipline: mu guards servers/healthy/next. The HealthCheck callbacks in
// UpdateHealth run OUTSIDE the lock (a probe may block on a dial), then results are
// applied under the lock — no callback runs while mu is held.
type LoadBalancer struct {
	check  HealthCheck
	logger *slog.Logger

	mu      sync.Mutex
	servers []string
	healthy map[string]bool
	next    int
}

// New builds a load-balancer over the initial server set. A nil check defaults to a
// 2-second TCP dial; a nil logger discards.
func New(servers []string, check HealthCheck, logger *slog.Logger) *LoadBalancer {
	if check == nil {
		check = DialHealthCheck(2 * time.Second)
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	lb := &LoadBalancer{check: check, logger: logger, healthy: map[string]bool{}}
	lb.SetServers(servers)
	return lb
}

// SetServers replaces the server set, preserving the known health of surviving members
// and marking newcomers healthy-until-probed (optimistic, so a fresh set is usable
// before the first health pass).
func (lb *LoadBalancer) SetServers(servers []string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	next := make(map[string]bool, len(servers))
	for _, s := range servers {
		if h, ok := lb.healthy[s]; ok {
			next[s] = h
		} else {
			next[s] = true
		}
	}
	lb.servers = append([]string(nil), servers...)
	lb.healthy = next
}

// Pick returns a healthy server, advancing a round-robin cursor across the healthy
// subset; the bool is false when no server is healthy.
func (lb *LoadBalancer) Pick() (string, bool) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	n := len(lb.servers)
	if n == 0 {
		return "", false
	}
	for i := 0; i < n; i++ {
		s := lb.servers[(lb.next+i)%n]
		if lb.healthy[s] {
			lb.next = (lb.next + i + 1) % n
			return s, true
		}
	}
	return "", false
}

// UpdateHealth probes every server once (outside the lock) and applies the results.
func (lb *LoadBalancer) UpdateHealth(ctx context.Context) {
	lb.mu.Lock()
	servers := append([]string(nil), lb.servers...)
	lb.mu.Unlock()

	results := make(map[string]bool, len(servers))
	for _, s := range servers {
		results[s] = lb.check(ctx, s)
	}

	lb.mu.Lock()
	for s, h := range results {
		if _, ok := lb.healthy[s]; ok { // ignore a server removed mid-probe
			lb.healthy[s] = h
		}
	}
	lb.mu.Unlock()
}

// Healthy returns a snapshot of the currently-healthy servers (diagnostic / test).
func (lb *LoadBalancer) Healthy() []string {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	out := make([]string, 0, len(lb.servers))
	for _, s := range lb.servers {
		if lb.healthy[s] {
			out = append(out, s)
		}
	}
	return out
}

// Serve listens on listenAddr and forwards each connection to a healthy apiserver
// (re-picked per connection, so a server death fails the next dial over to a survivor),
// running a background health loop until ctx ends.
func (lb *LoadBalancer) Serve(ctx context.Context, listenAddr string) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listenAddr, err)
	}
	return lb.serveListener(ctx, ln)
}

// serveListener runs the accept + forward loop over ln (the seam the unit test drives
// with a 127.0.0.1:0 listener).
func (lb *LoadBalancer) serveListener(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	go lb.healthLoop(ctx, 5*time.Second)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		go lb.forward(ctx, conn)
	}
}

// healthLoop probes the server set immediately, then every interval until ctx ends.
func (lb *LoadBalancer) healthLoop(ctx context.Context, interval time.Duration) {
	lb.UpdateHealth(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			lb.UpdateHealth(ctx)
		}
	}
}

// forward proxies client↔upstream bytes both ways until either side closes or ctx ends.
func (lb *LoadBalancer) forward(ctx context.Context, client net.Conn) {
	defer client.Close()
	server, ok := lb.Pick()
	if !ok {
		lb.logger.Warn("no healthy apiserver to forward to")
		return
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	upstream, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		lb.logger.Warn("dial upstream apiserver", "server", server, "err", err)
		return
	}
	defer upstream.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstream); done <- struct{}{} }()
	select {
	case <-ctx.Done():
	case <-done:
	}
}

// DialHealthCheck returns a HealthCheck that reports a server healthy iff a TCP
// connection to it succeeds within timeout.
func DialHealthCheck(timeout time.Duration) HealthCheck {
	return func(ctx context.Context, server string) bool {
		d := net.Dialer{Timeout: timeout}
		conn, err := d.DialContext(ctx, "tcp", server)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}
}
