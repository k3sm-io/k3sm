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

package operator

import (
	"context"
	"log/slog"
	"sync"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// RuntimeInfoSource is the ONE runtimed RPC this package reads: GetRuntimeInfo,
// whose response carries the node's GPU facts.
//
// It is declared at the consumer and it is one method wide, which is what lets
// the SAME value the node drives satisfy it with no adapter: runtimed's
// in-process runtime (runtimev1.RuntimeServer, which the embedded node holds)
// has exactly this signature. The generated gRPC client's method takes variadic
// grpc.CallOption and therefore does NOT satisfy it directly — an external-daemon
// posture wraps the client in a small func, which is the point of keeping the
// interface at one method rather than accepting runtimev1.RuntimeClient here.
//
// It is deliberately NOT the whole RuntimeServer. This package may read the
// daemon's runtime info and nothing else; handing it a value that can also create
// and delete pods would make a fit check a pod-lifecycle authority by accident.
type RuntimeInfoSource interface {
	// GetRuntimeInfo returns the daemon's runtime info, or an error when the
	// daemon could not be asked at all.
	GetRuntimeInfo(context.Context, *runtimev1.GetRuntimeInfoRequest) (*runtimev1.GetRuntimeInfoResponse, error)
}

// RuntimeGPU is the GPUSource the server path wires: it reads this node's GPU
// facts from runtimed's GetRuntimeInfo — the SAME RPC the node path's capability
// probe calls — and caches them.
//
// # Why it is attached rather than constructed with its source
//
// The server starts this operator as soon as the apiserver is healthy, which is
// BEFORE it brings up its in-process node, and the node is what constructs the
// runtime. So the source is handed over later, by Attach, and until then this
// reports unknown. That is the pre-existing nil-source behaviour (the fit check
// is SKIPPED) narrowed from the whole process lifetime to a bring-up window of
// seconds — never a new failure mode. A model reconciled inside that window is
// applied unchecked and is re-checked on its next reconcile, which will then
// refuse it; already-applied objects are not withdrawn, because this package
// deliberately deletes nothing (see the package doc).
//
// # Caching
//
// The facts are read ONCE and held. They are near-static by construction: the
// daemon derives them a single time in its own constructor from a Metal probe
// plus the sandbox backend it selected, so re-reading per reconcile would spend
// an RPC per model per pass to receive the same answer, and a host that gains or
// loses a GPU needs a daemon restart before the number moves at all — the same
// once-at-bring-up posture, and the same operator consequence, the node's
// capability probe already documents. A FAILED read is not cached: an error is
// about reachability, not about the host, so the next reconcile retries.
//
// # Failure posture
//
// Every degradation returns nil, which SKIPS the fit check, and logs a warning
// naming which degradation it was. It never panics and never fails a reconcile:
// an operator that refused every model because it could not reach a daemon would
// be strictly worse than one that lets the render's own mlx.k3sm.io/gpu
// extended-resource request keep the model off a GPU-less node.
//
// Concurrency: mu guards src and the cached facts. The GetRuntimeInfo call is
// made OUTSIDE the lock, so an in-flight read never blocks Attach.
type RuntimeGPU struct {
	log *slog.Logger

	mu sync.Mutex
	// src is the runtime-info reader, nil until Attach.
	src RuntimeInfoSource
	// facts is the cached answer; valid only when read is true. A nil facts with
	// read true is a SUCCESSFUL read of a daemon that reports no GPU facts (one
	// predating them) — distinct from "not read yet", and cached as the answer it
	// is.
	facts *runtimev1.GPUFacts
	read  bool
	// warned suppresses repeat warnings per degradation kind, so a daemon-less
	// posture logs each distinct reason once instead of once per model per pass.
	warned map[string]bool
}

// NewRuntimeGPU returns a RuntimeGPU with no source attached yet. A nil log uses
// slog.Default().
func NewRuntimeGPU(log *slog.Logger) *RuntimeGPU {
	if log == nil {
		log = slog.Default()
	}
	return &RuntimeGPU{log: log, warned: map[string]bool{}}
}

// Attach hands over the runtime-info source, replacing any previous one and
// discarding a cached answer so the new source is read.
//
// A nil src is accepted and detaches: a caller that could not build a runtime
// connection at all says so here rather than passing a typed-nil that would
// panic on the first read.
func (g *RuntimeGPU) Attach(src RuntimeInfoSource) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.src = src
	g.facts = nil
	g.read = false
}

// GPUFacts implements GPUSource. It returns nil — meaning "skip the fit check",
// never "the fit failed" — whenever the facts cannot be obtained.
func (g *RuntimeGPU) GPUFacts(ctx context.Context) *runtimev1.GPUFacts {
	g.mu.Lock()
	if g.read {
		facts := g.facts
		g.mu.Unlock()
		return facts
	}
	src := g.src
	g.mu.Unlock()

	if src == nil {
		g.warn("unattached", "mlx fit check skipped: no runtime connection is wired yet, so this node's gpu facts are unknown")
		return nil
	}
	info, err := src.GetRuntimeInfo(ctx, &runtimev1.GetRuntimeInfoRequest{})
	if err != nil {
		// Not cached: the failure describes reachability, not the host, so the next
		// reconcile asks again.
		g.warn("probe-failed", "mlx fit check skipped: the runtime could not be asked for this node's gpu facts", "err", err)
		return nil
	}
	// GetGpu is nil-safe on both the response and the field, so an older daemon
	// that carries no gpu message reads as nil rather than panicking here.
	facts := info.GetGpu()

	g.mu.Lock()
	g.facts = facts
	g.read = true
	g.mu.Unlock()

	if facts == nil {
		g.warn("no-facts", "mlx fit check skipped: the runtime reports no gpu facts at all (a daemon predating them); upgrading the daemon is what fixes this")
	}
	return facts
}

// warn logs one warning per degradation kind. It takes its own lock rather than
// running under the caller's, so no log handler is ever invoked with the facts
// mutex held.
func (g *RuntimeGPU) warn(kind, msg string, args ...any) {
	g.mu.Lock()
	first := !g.warned[kind]
	g.warned[kind] = true
	g.mu.Unlock()
	if first {
		g.log.Warn(msg, args...)
	}
}

// Compile-time check that the runtime-backed source satisfies the seam the
// controller reads.
var _ GPUSource = (*RuntimeGPU)(nil)
