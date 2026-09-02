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
	"context"
	"errors"
	"log/slog"
	"net"
	"time"

	runtimed "k3sm.io/runtimed/pkg/runtime"

	"k3sm.io/k3sm/pkg/provider"
	"k3sm.io/k3sm/pkg/provider/vkadapter"
)

// controlSocketSource is the optional provider capability the node's runtimed
// control-socket listener needs. It is declared HERE, at the consumer, so this
// file depends on the one method it uses rather than on a concrete provider type
// — the same shape as runtimeHealthReporter in node.go.
type controlSocketSource interface {
	ServableRuntime() (*runtimed.Runtime, bool)
}

// servableRuntime returns the in-process runtimed runtime prov drives, or nil
// when it drives none: the HostProcess runtime (no runtime/v1 services exist to
// serve) or a test double. nil means the node binds no control socket, which is
// the honest answer rather than a degraded one — there is nothing to serve.
func servableRuntime(prov vkadapter.Provider) *runtimed.Runtime {
	src, ok := prov.(controlSocketSource)
	if !ok {
		return nil
	}
	rt, ok := src.ServableRuntime()
	if !ok {
		return nil
	}
	return rt
}

// Bind budget and cadence for the control socket.
//
// The failures this retries are transient-or-permanent by nature and cheap to
// re-test: a run dir not yet created, a socket node left by a process that has
// not finished dying, a mode the installer is mid-way through fixing. Five
// attempts two seconds apart covers the seconds-long window a `launchctl
// kickstart -k` opens, and refuses to spin forever on a permanent EACCES.
//
// The budget spans the node's WHOLE lifetime rather than resetting on a
// successful bind. That is deliberate: resetting would turn a listener that
// binds and then immediately fails to serve into an unbounded hot loop, which is
// a worse failure than a node whose control socket stays down until its next
// restart. Pods are unaffected either way — nothing about pod execution goes
// through this socket.
const (
	runtimedSocketBindAttempts = 5
	runtimedSocketBindBackoff  = 2 * time.Second
	// runtimedSocketShutdownGrace bounds how long node teardown waits for the
	// listener to close. It is short because there is nothing to drain: the
	// in-flight RPCs are image metadata calls, and the caller is on its way out.
	runtimedSocketShutdownGrace = 5 * time.Second
)

// runtimedControlSocket binds and serves the node's runtimed gRPC control socket.
//
// Every collaborator is a field rather than a direct call so the contracts that
// matter — bind failure is never fatal, the retry is bounded, the listener is
// closed before run returns — are assertable in a unit test with no socket, no
// runtime and no node. Production wires runtime.Listen and (*runtime.Server).Serve.
type runtimedControlSocket struct {
	// path is the unix socket to bind (provider.RuntimedSocketPath).
	path string
	// listen binds path and returns the listener run owns and closes.
	listen func(path string) (net.Listener, error)
	// serve accepts on lis until ctx ends or lis closes. It never closes lis.
	serve func(ctx context.Context, lis net.Listener) error
	// attempts is the bind/serve failure budget; backoff is the pause between.
	attempts int
	backoff  time.Duration
	log      *slog.Logger
}

// run binds and serves until ctx is done or the failure budget is exhausted.
//
// IT NEVER RETURNS AN ERROR, and that is the contract, not an omission: a node
// that cannot bind its control socket still runs every pod it is sent, while a
// bring-up aborted over it runs none. The loss is confined to the daemon-side
// `k3sm image` commands, which report a dial failure the operator can act on.
// This is the same log-and-continue posture the ingest registry and the ingress
// listeners are started under.
//
// The listener is closed on the way out of every serve session, so by the time
// run returns the socket node is unlinked and a restart binds cleanly.
func (s runtimedControlSocket) run(ctx context.Context) {
	for attempt := 1; ctx.Err() == nil; attempt++ {
		lis, err := s.listen(s.path)
		if err != nil {
			if !s.retry(ctx, attempt, "bind", err) {
				return
			}
			continue
		}
		s.log.Info("serving the runtimed control socket", "socket", s.path)
		serveErr := s.serve(ctx, lis)
		// Close HERE, before anything else can return, so the ordering the node's
		// teardown depends on holds on every path out: listener closed, socket
		// unlinked, and only then run returns. Go unlinks a unix socket it created
		// on Close, so this is also what stops the next start from tripping over a
		// stale node. ErrClosed is expected when Serve itself raced the close.
		if cerr := lis.Close(); cerr != nil && !errors.Is(cerr, net.ErrClosed) {
			s.log.Warn("closing the runtimed control socket listener", "socket", s.path, "err", cerr)
		}
		if serveErr == nil {
			// A clean stop: ctx cancelled, or the listener closed. Either way the
			// caller is ending this listener deliberately and there is nothing to retry.
			s.log.Info("runtimed control socket stopped", "socket", s.path)
			return
		}
		if !s.retry(ctx, attempt, "serve", serveErr) {
			return
		}
	}
}

// retry reports whether run should make another attempt after a failed stage,
// logging the failure at the severity the remaining budget justifies and pausing
// for the backoff. It returns false once the budget is spent or ctx is done — the
// two ways the control socket gives up for the life of this node.
func (s runtimedControlSocket) retry(ctx context.Context, attempt int, stage string, err error) bool {
	if attempt >= s.attempts {
		s.log.Error("runtimed control socket disabled: `k3sm image` commands on this node cannot reach the daemon (pod execution is unaffected)",
			"socket", s.path, "stage", stage, "attempts", attempt, "err", err)
		return false
	}
	s.log.Warn("runtimed control socket attempt failed; retrying",
		"socket", s.path, "stage", stage, "attempt", attempt, "backoff", s.backoff, "err", err)
	t := time.NewTimer(s.backoff)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// startRuntimedControlSocket serves the runtimed gRPC control API off the SAME
// in-process runtime prov drives, and returns the teardown closure the caller
// defers. The closure is never nil, so `defer stop()` is unconditional.
//
// WHY THE NODE SERVES AT ALL. `k3sm image ls|df|prune|load|import` are clients of
// runtimed's Images service over this socket, and the installed launch daemons
// contain no standalone k3sm-runtimed — the node builds its runtime in-process
// and, until now, served no socket, so those commands failed to dial on every
// stock install. Serving the embedded runtime is what makes them work, and it
// must be the embedded one: a second runtime over the same root would be a second
// writer to one image store, and content it ingested would be invisible to the
// runtime that actually starts pods.
//
// WHAT IS EXPOSED. The full runtime.Server — the Runtime service as well as
// Images — because that is the server runtime.NewServer builds and there is one
// gRPC server per listener by construction. The socket is a 0600 node in a 0700
// dir, so the caller must be the daemon's own uid; see runtime.DefaultSocketPath
// for the exact posture and its limits. Pods are fenced off it separately, by the
// Seatbelt deny every pod profile carries (provider.RuntimedSocketPath is the one
// derivation both this listener and that deny-set go through).
//
// A provider with no runtimed behind it (HostProcess) serves nothing and says so.
func startRuntimedControlSocket(ctx context.Context, prov vkadapter.Provider, root string, log *slog.Logger) func() {
	rt := servableRuntime(prov)
	if rt == nil {
		log.Info("no runtimed control socket on this node: the selected runtime serves no runtime/v1 API, so `k3sm image` commands have no daemon to dial")
		return func() {}
	}
	socket := provider.RuntimedSocketPath(root)
	// A context of its own so teardown can stop the listener WITHOUT waiting for
	// the node's ctx: startNode also returns when the VK run loop fails, and the
	// socket must come down on that path too.
	sockCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	s := runtimedControlSocket{
		path:     socket,
		listen:   runtimed.Listen,
		serve:    runtimed.NewServer(rt).Serve,
		attempts: runtimedSocketBindAttempts,
		backoff:  runtimedSocketBindBackoff,
		log:      log,
	}
	go func() {
		defer close(done)
		s.run(sockCtx)
	}()
	return func() {
		cancel()
		select {
		case <-done:
		case <-time.After(runtimedSocketShutdownGrace):
			// Report rather than block forever: the process is exiting, and launchd
			// will reclaim the socket. A silent hang here would look like a node that
			// refuses to stop.
			log.Warn("runtimed control socket did not stop within the shutdown grace", "socket", socket, "grace", runtimedSocketShutdownGrace)
		}
	}
}
