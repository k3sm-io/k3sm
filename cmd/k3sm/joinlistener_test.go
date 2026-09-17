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

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
)

// scriptedListen is a listenFunc that returns the scripted errors in order and
// then delegates to a real loopback bind on an ephemeral port — so the row that
// serves for real never contends for the supervisor's fixed port.
type scriptedListen struct {
	mu     sync.Mutex
	errs   []error
	calls  int
	addrs  []string
	opened []net.Listener
}

func (s *scriptedListen) listen(network, addr string) (net.Listener, error) {
	s.mu.Lock()
	n := s.calls
	s.calls++
	s.addrs = append(s.addrs, addr)
	s.mu.Unlock()
	if n < len(s.errs) {
		return nil, s.errs[n]
	}
	ln, err := net.Listen(network, "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.opened = append(s.opened, ln)
	s.mu.Unlock()
	return ln, nil
}

func (s *scriptedListen) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// TestJoinSupervisorRebindsAfterTransientFailure is B245's worker-join listener
// gate.
//
// Before it, the bind lived inside http.Server.ListenAndServeTLS, so any bind
// failure was terminal: runServer's supervisor goroutine logged once and the
// worker-join endpoint stayed dead until the daemon was restarted by hand — even
// when the cause was a previous supervisor's socket still draining, which clears
// by itself in seconds.
func TestJoinSupervisorRebindsAfterTransientFailure(t *testing.T) {
	const addr = "0.0.0.0:9345"

	t.Run("a transiently busy address is retried until it binds", func(t *testing.T) {
		script := &scriptedListen{errs: []error{listenInUse(), listenInUse()}}
		var log bytes.Buffer
		ln, err := listenJoinAddr(context.Background(), script.listen, addr, joinListenerAttempts, time.Millisecond, bufLogger(&log))
		if err != nil {
			t.Fatalf("listenJoinAddr: %v", err)
		}
		defer ln.Close()
		if got := script.count(); got != 3 {
			t.Errorf("bound after %d attempts; want 3 (two busy, then free)", got)
		}
		if !strings.Contains(log.String(), "attempt=1") || !strings.Contains(log.String(), "attempt=2") {
			t.Errorf("the retried attempts are not logged; log was:\n%s", log.String())
		}
		if !strings.Contains(log.String(), addr) {
			t.Errorf("the retry log does not name the address %s; log was:\n%s", addr, log.String())
		}
	})

	t.Run("a non-transient bind error returns immediately", func(t *testing.T) {
		fatal := errors.New("can't assign requested address")
		script := &scriptedListen{errs: []error{fatal, fatal, fatal}}
		_, err := listenJoinAddr(context.Background(), script.listen, addr, joinListenerAttempts, time.Millisecond, quietLogger())
		if err == nil {
			t.Fatal("listenJoinAddr bound despite a non-transient error")
		}
		if !errors.Is(err, fatal) {
			t.Errorf("error %v does not wrap the bind failure", err)
		}
		if got := script.count(); got != 1 {
			t.Errorf("a non-transient bind error was retried (%d attempts); waiting cannot clear it, and retrying only delays the report", got)
		}
	})

	t.Run("an address busy forever gives up at the bound", func(t *testing.T) {
		script := &scriptedListen{errs: make([]error, joinListenerAttempts)}
		for i := range script.errs {
			script.errs[i] = listenInUse()
		}
		_, err := listenJoinAddr(context.Background(), script.listen, addr, joinListenerAttempts, time.Millisecond, quietLogger())
		if err == nil {
			t.Fatal("listenJoinAddr reported success with the address busy on every attempt")
		}
		if got := script.count(); got != joinListenerAttempts {
			t.Errorf("gave up after %d attempts; want the bound %d", got, joinListenerAttempts)
		}
		if !strings.Contains(err.Error(), addr) {
			t.Errorf("give-up error %q does not name the address it could not bind", err)
		}
		if !errors.Is(err, syscall.EADDRINUSE) {
			t.Errorf("give-up error %v does not carry the last bind error", err)
		}
	})

	t.Run("darwin's own EADDRINUSE is recognised as transient", func(t *testing.T) {
		// Every other row hands listenJoinAddr a hand-built error. This one holds a
		// REAL address and lets the REAL net.Listen fail against it, so the
		// errors.Is unwrap is exercised on the shape darwin actually produces
		// (*net.OpError → *os.SyscallError → syscall.EADDRINUSE). A future Go or
		// darwin that wraps it differently reddens here rather than in a lab, where
		// it would present as a supervisor that never comes back.
		held, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("hold a loopback port: %v", err)
		}
		busy := held.Addr().String()
		// Confirm the premise before relying on it: a second bind of the held
		// address must actually be EADDRINUSE on this host.
		probe, err := net.Listen("tcp", busy)
		if err == nil {
			probe.Close()
			held.Close()
			t.Skip("this host allows a second bind of a held loopback port; the transient case cannot be reproduced")
		}
		if !errors.Is(err, syscall.EADDRINUSE) {
			held.Close()
			t.Fatalf("a real second bind of %s failed with %v, which is not EADDRINUSE — listenJoinAddr's transient test would never fire", busy, err)
		}
		// Free it partway through the retry window, from outside.
		go func() {
			time.Sleep(120 * time.Millisecond)
			held.Close()
		}()
		var log bytes.Buffer
		ln, err := listenJoinAddr(context.Background(), net.Listen, busy, joinListenerAttempts, 30*time.Millisecond, bufLogger(&log))
		if err != nil {
			t.Fatalf("listenJoinAddr never bound %s after the holder released it: %v\nlog:\n%s", busy, err, log.String())
		}
		defer ln.Close()
		if !strings.Contains(log.String(), "address is busy") {
			t.Errorf("the real busy address was bound without a retry being logged; the row proved nothing. log:\n%s", log.String())
		}
		if got := ln.Addr().String(); got != busy {
			t.Errorf("bound %s, want the requested %s", got, busy)
		}
	})

	t.Run("the supervisor serves once the address frees", func(t *testing.T) {
		// The whole point of the retry: not that the bind eventually succeeds, but
		// that the worker-join endpoint is actually up afterwards. This drives the
		// real startBootstrapServer, with the bind seam failing once.
		script := &scriptedListen{errs: []error{listenInUse()}}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ca := testClusterCA(t)
		deps := bootstrapServerDeps{
			hierarchy:     &certs.Hierarchy{Cluster: ca, Signing: testClusterCA(t)},
			meshIP:        "127.0.0.1",
			tokens:        stubTokens{},
			nodePasswords: stubNodePasswords{},
			enroller:      stubEnroller{},
			listen:        script.listen,
		}
		done := make(chan error, 1)
		go func() { done <- startBootstrapServer(ctx, deps, quietLogger()) }()

		served := waitForOpenListener(t, script)
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // the pin is asserted elsewhere; this row asserts the endpoint is up
		resp, err := client.Get("https://" + served.Addr().String() + bootstrap.CACertPath)
		if err != nil {
			t.Fatalf("the worker-join supervisor did not serve after a transiently busy bind: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", bootstrap.CACertPath, resp.StatusCode)
		}
		if !bytes.Contains(body, ca.CertPEM) {
			t.Error("the supervisor served a CA bundle that is not this cluster's CA")
		}
		cancel()
		if err := <-done; err != nil {
			t.Errorf("startBootstrapServer returned %v after a clean shutdown", err)
		}
	})
}

// listenInUse builds the error shape a real net.Listen returns for a busy address
// — the errno wrapped in *os.SyscallError inside *net.OpError. listenJoinAddr's
// errors.Is has to see through both layers, so the fake must not hand it a bare
// errno.
func listenInUse() error {
	return &net.OpError{Op: "listen", Net: "tcp", Err: os.NewSyscallError("bind", syscall.EADDRINUSE)}
}

// waitForOpenListener returns the real listener the scripted bind finally opened.
func waitForOpenListener(t *testing.T, s *scriptedListen) net.Listener {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		if len(s.opened) > 0 {
			ln := s.opened[0]
			s.mu.Unlock()
			// Give http.Server a moment to start accepting on it.
			time.Sleep(50 * time.Millisecond)
			return ln
		}
		s.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the supervisor never bound a listener")
	return nil
}

func bufLogger(b *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

type stubTokens struct{}

func (stubTokens) VerifyToken(context.Context, string) error { return nil }

type stubNodePasswords struct{}

func (stubNodePasswords) Ensure(context.Context, string, string) error { return nil }

type stubEnroller struct{}

func (stubEnroller) Enroll(context.Context, string, netv1.MeshEnrollRequest) (netv1.MeshEnrollResponse, error) {
	return netv1.MeshEnrollResponse{}, nil
}

func (stubEnroller) RefreshEndpoint(context.Context, string, string) error { return nil }
