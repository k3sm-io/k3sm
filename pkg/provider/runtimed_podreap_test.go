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
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"k3sm.io/runtimed/pkg/sandbox"
)

// reapAlertPrefix is the message prefix runtimed's startup pod reap logs on its
// DEGRADED path (an unreadable reap store: alert + skip, never a Serve failure).
// It is matched as a prefix rather than the full sentence so a wording tweak
// upstream does not break the gate, while still pinning the one line that only
// the reap emits.
const reapAlertPrefix = "startup pod reap"

// capturedRecord is one slog record the test handler saw, flattened to the two
// facts the gate asserts on.
type capturedRecord struct {
	level   slog.Level
	message string
	attrs   map[string]string
}

// captureHandler is a slog.Handler that records every emitted record. It is
// mutex-guarded because the constructed runtime may log from its own goroutines
// (CI runs -race).
type captureHandler struct {
	mu      *sync.Mutex
	records *[]capturedRecord
	preset  []slog.Attr
}

func newCaptureHandler() *captureHandler {
	return &captureHandler{mu: &sync.Mutex{}, records: &[]capturedRecord{}}
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	rec := capturedRecord{level: r.Level, message: r.Message, attrs: map[string]string{}}
	for _, a := range h.preset {
		rec.attrs[a.Key] = a.Value.String()
	}
	r.Attrs(func(a slog.Attr) bool {
		rec.attrs[a.Key] = a.Value.String()
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	*h.records = append(*h.records, rec)
	return nil
}

func (h *captureHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := *h
	next.preset = append(append([]slog.Attr{}, h.preset...), attrs...)
	return &next
}

func (h *captureHandler) WithGroup(string) slog.Handler { return h }

// captured returns a snapshot of everything logged so far.
func (h *captureHandler) captured() []capturedRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]capturedRecord{}, *h.records...)
}

// findReapAlert returns the first ERROR-level reap record, if any.
func findReapAlert(recs []capturedRecord) (capturedRecord, bool) {
	for _, r := range recs {
		if r.level == slog.LevelError && strings.HasPrefix(r.message, reapAlertPrefix) {
			return r, true
		}
	}
	return capturedRecord{}, false
}

// stageExecShim puts a stand-in exec-shim helper on PATH so runtime.New's
// production sandbox backend resolves (sandbox.FindExecShim). It is never
// executed — no pod is created here.
func stageExecShim(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, sandbox.ExecShimName), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("stage exec shim: %v", err)
	}
	t.Setenv("PATH", dir)
}

// TestEmbeddedStartupPodReapWired pins that the EMBEDDED node path runs
// runtimed's startup pod reap. The embedded path drives the runtime by direct
// RPC and never runs runtime.Server.Serve — the daemon's own once-before-serve
// reap call site — so without an explicit call in NewRuntimed the reaper is
// present in the binary and unreachable in production.
//
// It asserts through the PRODUCTION constructor NewRuntimed, never through a
// helper the test also wrote: this repo has a recorded lesson that mutating a
// test-owned helper instead of the production call site produces a fake
// mutation-proof. Delete the ReapOrphanedPods call in NewRuntimed and this test
// goes RED.
//
// The observable it uses is the reap's own DEGRADED-path alert: the reap store
// root (the exported sandbox.PodReapSubdir component under the runtime root) is
// staged as a plain FILE, so enumerating it fails, and runtimed alerts + skips
// (it never fails closed — ReapOrphanedPods returns nil by contract). The test
// never writes or parses runtimed's private on-disk record format; it stages an
// unreadable store and reads a log record.
//
// No privilege, no network, no real pods.
func TestEmbeddedStartupPodReapWired(t *testing.T) {
	t.Run("reap runs during construction (degraded store alerts)", func(t *testing.T) {
		stageExecShim(t)
		root := t.TempDir()
		// The store root as a plain file: present, and un-enumerable as a store.
		reapRoot := filepath.Join(root, sandbox.PodReapSubdir)
		if err := os.WriteFile(reapRoot, []byte("not a directory"), 0o600); err != nil {
			t.Fatalf("stage unreadable reap store: %v", err)
		}
		h := newCaptureHandler()

		if _, err := NewRuntimed(RuntimedConfig{NodeName: "n1", Root: root, Logger: slog.New(h)}); err != nil {
			t.Fatalf("NewRuntimed: %v", err)
		}

		rec, ok := findReapAlert(h.captured())
		if !ok {
			t.Fatalf("no startup-pod-reap alert logged during NewRuntimed: the embedded path never ran ReapOrphanedPods (records: %v)", h.captured())
		}
		// The alert names the store it failed on: proof the reap read the reap
		// root derived from the runtime root under test, not some other path.
		if got := rec.attrs["root"]; got != reapRoot {
			t.Errorf("reap alert root = %q, want %q", got, reapRoot)
		}
	})

	t.Run("healthy store logs no alert (the alert is caused by the fault)", func(t *testing.T) {
		stageExecShim(t)
		root := t.TempDir() // no reap store at all: the normal no-prior-run shape
		h := newCaptureHandler()

		if _, err := NewRuntimed(RuntimedConfig{NodeName: "n1", Root: root, Logger: slog.New(h)}); err != nil {
			t.Fatalf("NewRuntimed: %v", err)
		}

		if rec, ok := findReapAlert(h.captured()); ok {
			t.Fatalf("unexpected reap alert on a healthy root: %+v", rec)
		}
	})
}
