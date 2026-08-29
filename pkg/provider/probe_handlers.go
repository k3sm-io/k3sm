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

package provider

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// The concrete probe checks behind the runtime-agnostic runner in probe.go:
// httpGet, tcpSocket, and exec. Each is built into a checkFunc, with its target
// resolved (a named port against the container's port table, the dial host
// defaulting to the bound pod IP) at build time. The I/O seams — an
// http.RoundTripper, a dialFunc, and the runtime Exec RPC — are injected so the
// handler tests fake the targets with no real network.

// dialFunc abstracts net.Dialer.DialContext so the tcp probe can be tested
// against a fake dialer (success vs. connection-refused) instead of a real
// listener.
type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// resolvePort resolves a probe port (an int or a named ContainerPort) against the
// container's port table. An integer port is used verbatim; a named port is
// looked up in ports by name. ok is false for an unresolved name or a
// non-positive integer, which the caller turns into a failing check (a probe
// against an unresolvable port is a misconfiguration → NotReady, never silently
// healthy).
func resolvePort(p intstr.IntOrString, ports []corev1.ContainerPort) (int32, bool) {
	switch p.Type {
	case intstr.Int:
		if p.IntVal <= 0 {
			return 0, false
		}
		return p.IntVal, true
	case intstr.String:
		for i := range ports {
			if ports[i].Name == p.StrVal {
				return ports[i].ContainerPort, true
			}
		}
	}
	return 0, false
}

// boundedContext derives a handler call's context from the caller's: a POSITIVE
// timeout caps it, a non-positive one leaves ctx as the only bound.
//
// Every probe passes a positive timeout (a probe without one is a configuration
// error), so this changes nothing on the probe path. The unbounded arm exists for
// the postStart LIFECYCLE hook, which upstream does not time-cap at all — the
// kubelet runs an exec hook with timeout 0 and lets the pod worker's context be
// the only bound (k8s.io/api core/v1 types.go, Lifecycle: "management of the
// container blocks until the action is complete"). Its ctx is pod-scoped, so a
// hung hook is reclaimed by the pod's deletion, not by a stopgap deadline. The two
// handlers a lifecycle hook can reach (exec, httpGet) route through here; tcpSocket
// is not a valid lifecycle handler upstream and keeps its probe-only shape.
func boundedContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

// httpProbe returns a checkFunc that issues a GET to scheme://host:port/path with
// any custom headers and succeeds on a 2xx or 3xx status (kubelet semantics:
// redirects are not followed, the 3xx itself is success). The per-attempt timeout
// bounds the request.
func httpProbe(rt http.RoundTripper, scheme, host string, port int32, path string, headers []corev1.HTTPHeader) checkFunc {
	return func(ctx context.Context, timeout time.Duration) error {
		cctx, cancel := boundedContext(ctx, timeout)
		defer cancel()
		u := url.URL{Scheme: strings.ToLower(scheme), Host: net.JoinHostPort(host, strconv.Itoa(int(port))), Path: path}
		req, err := http.NewRequestWithContext(cctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return err
		}
		for _, h := range headers {
			if strings.EqualFold(h.Name, "Host") {
				req.Host = h.Value
				continue
			}
			req.Header.Add(h.Name, h.Value)
		}
		client := &http.Client{
			Transport: rt,
			Timeout:   timeout,
			// Do not follow redirects: a 3xx is a successful probe result.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		// Drain and close so the connection can be reclaimed promptly.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			return nil
		}
		return fmt.Errorf("http probe to %s returned status %d", u.String(), resp.StatusCode)
	}
}

// tcpProbe returns a checkFunc that succeeds iff a TCP connection to host:port can
// be opened within the timeout (the connection is immediately closed).
func tcpProbe(dial dialFunc, host string, port int32) checkFunc {
	return func(ctx context.Context, timeout time.Duration) error {
		cctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		conn, err := dial(cctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
		if err != nil {
			return err
		}
		return conn.Close()
	}
}

// grpcProbe returns a checkFunc that performs a gRPC health check against
// host:port using the standard grpc.health.v1 Health/Check RPC (kubelet parity):
// a SERVING response is success; any other serving status, an unknown service
// (the server's NOT_FOUND), or a dial/RPC error is failure (fail closed). It
// dials over the injected dialFunc seam — the same seam the tcp probe uses — with
// a fresh, unpooled ClientConn per attempt (no PKI: probe targets are pod-local,
// like the http/tcp checks), and names service in the request (empty = the
// server's overall health). The per-attempt timeout bounds the whole exchange.
func grpcProbe(dial dialFunc, host string, port int32, service string) checkFunc {
	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	return func(ctx context.Context, timeout time.Duration) error {
		cctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		// passthrough:/// skips name resolution so the context dialer is handed the
		// endpoint verbatim; the dial seam (not gRPC) owns the connect, mirroring
		// the tcp probe. The conn is lazy — the Check RPC below triggers the dial.
		conn, err := grpc.NewClient(
			"passthrough:///"+addr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithContextDialer(func(c context.Context, _ string) (net.Conn, error) {
				return dial(c, "tcp", addr)
			}),
		)
		if err != nil {
			return fmt.Errorf("grpc probe to %s: %w", addr, err)
		}
		defer func() { _ = conn.Close() }()
		resp, err := grpc_health_v1.NewHealthClient(conn).Check(cctx, &grpc_health_v1.HealthCheckRequest{Service: service})
		if err != nil {
			return fmt.Errorf("grpc probe to %s: %w", addr, err)
		}
		if s := resp.GetStatus(); s != grpc_health_v1.HealthCheckResponse_SERVING {
			return fmt.Errorf("grpc probe to %s: status %s", addr, s)
		}
		return nil
	}
}

// execCheck returns a checkFunc that runs cmd in the container via the runtime
// Exec RPC and succeeds iff it exits 0.
func execCheck(rt runtimev1.RuntimeServer, podID, container string, cmd []string) checkFunc {
	cp := append([]string(nil), cmd...)
	return func(ctx context.Context, timeout time.Duration) error {
		return runExecProbe(ctx, rt, podID, container, cp, timeout)
	}
}

// newProbeTransport is the HTTP transport for httpGet probes. Probes target
// pod-local addresses (the bound pod IP) that have no cluster PKI, so — like the
// kubelet's probe client — server certificates are not verified and connections
// are not pooled (each probe is a fresh, short-lived request).
func newProbeTransport() *http.Transport {
	return &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // probe targets are pod-local, no PKI (kubelet parity)
	}
}

// execStream is an in-process grpc.BidiStreamingServer[ExecRequest, ExecResponse]
// that drives a single exec to completion for an exec probe: it hands the runtime
// one ExecRequest then EOF (no stdin), discards stdout/stderr, and captures the
// terminal exit code. Like watchStream/logSink it lets the provider consume a
// streaming RuntimeServer method in-process; the M2 daemon split swaps it for a
// real client stream.
type execStream struct {
	grpc.ServerStream
	ctx  context.Context
	reqs chan *runtimev1.ExecRequest

	mu   sync.Mutex
	exit *runtimev1.ExecResult
}

// newExecStream returns a stream bound to ctx that yields req once, then io.EOF.
func newExecStream(ctx context.Context, req *runtimev1.ExecRequest) *execStream {
	reqs := make(chan *runtimev1.ExecRequest, 1)
	reqs <- req
	close(reqs)
	return &execStream{ctx: ctx, reqs: reqs}
}

// Context returns the stream context (honored by Exec for cancellation/timeout).
func (s *execStream) Context() context.Context { return s.ctx }

// Recv yields the single request, then io.EOF (the client's CloseSend), or the
// context error if cancelled.
func (s *execStream) Recv() (*runtimev1.ExecRequest, error) {
	select {
	case r, ok := <-s.reqs:
		if !ok {
			return nil, io.EOF
		}
		return r, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}

// Send records the terminal exit result; stdout/stderr are irrelevant to a probe
// and discarded.
func (s *execStream) Send(resp *runtimev1.ExecResponse) error {
	if ex := resp.GetExit(); ex != nil {
		s.mu.Lock()
		s.exit = ex
		s.mu.Unlock()
	}
	return nil
}

// runExecProbe runs cmd in (podID, container) via the runtime Exec RPC, bounded by
// timeout, and returns nil iff the command exits 0.
func runExecProbe(ctx context.Context, rt runtimev1.RuntimeServer, podID, container string, cmd []string, timeout time.Duration) error {
	cctx, cancel := boundedContext(ctx, timeout)
	defer cancel()
	s := newExecStream(cctx, &runtimev1.ExecRequest{
		PodId:     podID,
		Container: container,
		Command:   cmd,
		Stdout:    true,
		Stderr:    true,
	})
	if err := rt.Exec(s); err != nil {
		return fmt.Errorf("exec probe: %w", err)
	}
	s.mu.Lock()
	exit := s.exit
	s.mu.Unlock()
	if exit == nil {
		return errors.New("exec probe: no exit status")
	}
	if exit.GetExitCode() != 0 {
		return fmt.Errorf("exec probe: command exited %d", exit.GetExitCode())
	}
	return nil
}
