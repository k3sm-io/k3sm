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
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"k3sm.io/k3sm/pkg/provider"
	"k3sm.io/runtimed/pkg/guestartifacts"
	"k3sm.io/runtimed/pkg/sandbox"
)

// TestBuildProviderEnsuresGuestArtifacts pins the PRODUCTION CALL SITE of the
// guest-artifact ensure (B108): buildProvider, which is the one function both
// `k3sm server` and `k3sm agent` reach their runtimed runtime through.
//
// Why this test exists at all, given that pkg/provider already tests the ensure
// mechanism and its capability wiring from every angle: none of those tests can
// tell whether anything ever CALLS it. Delete the two lines in buildProvider and
// every other test in this repo stays green while no shipped node ever
// materialises an artifact — the exact shape of the defect the startup pod reap
// had before B-something forced it into NewRuntimed. The observable is therefore
// deliberately the ensure's own narration rather than any downstream state: with
// the shipped (unminted) pin there IS no downstream state, which is precisely the
// condition under which a missing call site is invisible.
//
// It asserts on the structured `guest_kernel` ATTRIBUTE, not on the message
// prose, so rewording the log line does not break it while removing the call does.
//
// Not parallel: it swaps slog.Default() and $PATH.
func TestBuildProviderEnsuresGuestArtifacts(t *testing.T) {
	stageExecShimForTest(t)

	h := &attrCapture{}
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(prev) })

	opts := nodeOptions{
		nodeName:   "k3sm-wiring",
		nodeIP:     "127.0.0.1",
		podRoot:    t.TempDir(),
		runtime:    runtimeRuntimed,
		standalone: true,
	}
	// nil client and nil recorder are the documented degradations (data-backed
	// volumes fail closed, events go to a nop recorder); neither is what is under
	// test here.
	_, _, name, _, err := buildProvider(context.Background(), opts, nil, nil)
	if err != nil {
		t.Fatalf("buildProvider: %v (a guest-artifact outcome must never fail node bring-up)", err)
	}
	if name != runtimeRuntimed {
		t.Fatalf("buildProvider selected runtime %q, want %q", name, runtimeRuntimed)
	}

	if !h.sawAttr("guest_kernel", guestartifacts.ActiveGuestKernel) {
		t.Fatalf("buildProvider produced no guest-artifact ensure record (guest_kernel=%q). "+
			"The ensure is not being run on the path `k3sm server` and `k3sm agent` both take, "+
			"so no shipped node would ever materialise its pinned kernel + initramfs.",
			guestartifacts.ActiveGuestKernel)
	}
}

// TestGuestArtifactsDirIsUnderTheRuntimedRoot pins WHERE a node caches its
// artifacts: beside the vm spine's other state under the runtimed on-disk root,
// derived from the same --pod-root the runtime itself is given.
//
// The derivation is asserted against the runtimedConfig the node command actually
// builds, not against a path spelled twice: ensure runs BEFORE the runtime exists
// and so cannot ask it, which makes "the ensure wrote here, the runtime reads
// there" a live failure mode rather than a hypothetical one.
func TestGuestArtifactsDirIsUnderTheRuntimedRoot(t *testing.T) {
	t.Parallel()

	root := filepath.Join(t.TempDir(), "podroot")
	opts := nodeOptions{nodeName: "n1", podRoot: root, standalone: true}
	cfg := runtimedConfig(opts, nil)
	if cfg.Root != root {
		t.Fatalf("runtimedConfig().Root = %q, want the --pod-root %q", cfg.Root, root)
	}

	// A sibling of the runtime root's other state, never a child of the pod dirs
	// (which are torn down per pod) — see provider.GuestArtifactsSubdir.
	if got, want := provider.GuestArtifactsDir(cfg.Root), filepath.Join(root, "guest-artifacts"); got != want {
		t.Errorf("guest-artifact cache = %q, want %q", got, want)
	}
}

// attrCapture is a slog.Handler that records every record's attributes.
//
// Attributes only, not messages: the assertions here key on structured values,
// which are the part of a log line that carries a contract.
type attrCapture struct {
	mu    sync.Mutex
	attrs []slog.Attr
}

func (h *attrCapture) Enabled(context.Context, slog.Level) bool { return true }

func (h *attrCapture) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	r.Attrs(func(a slog.Attr) bool {
		h.attrs = append(h.attrs, a)
		return true
	})
	return nil
}

func (h *attrCapture) WithAttrs(attrs []slog.Attr) slog.Handler {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.attrs = append(h.attrs, attrs...)
	return h
}

func (h *attrCapture) WithGroup(string) slog.Handler { return h }

// sawAttr reports whether any record carried key=value.
func (h *attrCapture) sawAttr(key, value string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, a := range h.attrs {
		if a.Key == key && a.Value.String() == value {
			return true
		}
	}
	return false
}

// stageExecShimForTest puts a stand-in exec-shim helper on PATH so the runtimed
// runtime's production sandbox backend resolves (sandbox.FindExecShim). It is
// never executed: no pod is created here.
func stageExecShimForTest(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, sandbox.ExecShimName), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("stage exec shim: %v", err)
	}
	t.Setenv("PATH", dir)
}
