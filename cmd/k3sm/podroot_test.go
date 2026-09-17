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
	"errors"
	"flag"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAgentPodRootDefaultsOffTempDir pins B276: `k3sm agent`'s pod root — which
// is runtimed's ON-DISK ROOT (image cache, pod dirs, every PVC bound on this
// node), not "per-pod logs/state" — no longer defaults into the temp dir.
//
// Fails-before: the flag's compiled default was
// filepath.Join(os.TempDir(), "k3sm-pods"), and the agent's install plist never
// renders --pod-root, so EVERY joined worker ran its durable data out of the
// _k3sm user's $TMPDIR under /var/folders — a tree macOS purges on its own
// schedule. Case (a) below is the red: the resolved default had os.TempDir() as
// its prefix.
//
// The migration half is pinned with it: a worker that ALREADY holds data under
// the legacy root — or whose legacy root cannot be read, which is not the same
// question — keeps it (a binary upgrade must not relocate a running node's
// volumes) and is warned, once, with the two moves that end the warning.
func TestAgentPodRootDefaultsOffTempDir(t *testing.T) {
	t.Parallel()

	const workDir = "/var/lib/k3sm/agent"
	const legacy = "/var/folders/xy/T/k3sm-pods"

	never := func(t *testing.T) func(string) (bool, error) {
		t.Helper()
		return func(dir string) (bool, error) {
			t.Errorf("hasData(%q) consulted when it must not be", dir)
			return false, nil
		}
	}
	answer := func(data bool, err error) func(*testing.T) func(string) (bool, error) {
		return func(*testing.T) func(string) (bool, error) {
			return func(string) (bool, error) { return data, err }
		}
	}

	errUnreadable := errors.New("permission denied")

	t.Run("resolution", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name         string
			explicit     string
			workDir      string
			legacyDir    string
			hasData      func(t *testing.T) func(string) (bool, error)
			wantRoot     string
			wantLegacy   bool
			wantProbeErr error
		}{
			{
				// (a) The default case, and the one that was red.
				name:      "no flag, no legacy data: the durable work-dir parent",
				workDir:   workDir,
				legacyDir: legacy,
				hasData:   answer(false, nil),
				wantRoot:  "/var/lib/k3sm",
			},
			{
				// (b) An operator who named a path gets that path, and nothing
				// else is probed on the way.
				name:      "explicit --pod-root wins unexamined",
				explicit:  "/Volumes/fast/k3sm",
				workDir:   workDir,
				legacyDir: legacy,
				hasData:   never,
				wantRoot:  "/Volumes/fast/k3sm",
			},
			{
				// (c) The already-joined worker: its data stays where it is.
				name:       "legacy root holding data keeps the node on it",
				workDir:    workDir,
				legacyDir:  legacy,
				hasData:    answer(true, nil),
				wantRoot:   legacy,
				wantLegacy: true,
			},
			{
				// (d) An empty legacy dir is a purged one (or a first join):
				// there is nothing to preserve, so take the durable default.
				name:      "legacy root present but empty: the durable default",
				workDir:   workDir,
				legacyDir: legacy,
				hasData:   answer(false, nil),
				wantRoot:  "/var/lib/k3sm",
			},
			{
				// (e) The derivation tracks --work-dir; it is not a constant.
				name:      "a non-default --work-dir moves the derived root with it",
				workDir:   "/opt/k3sm-state/agent",
				legacyDir: legacy,
				hasData:   answer(false, nil),
				wantRoot:  "/opt/k3sm-state",
			},
			{
				// An UNREADABLE legacy root is not an empty one. Resolving it to
				// the durable default would start a second, empty image cache
				// beside a still-populated root, silently — the Warn lives on the
				// branch that was not taken.
				name:         "an unreadable legacy root keeps the node on it and carries the error",
				workDir:      workDir,
				legacyDir:    legacy,
				hasData:      answer(true, errUnreadable),
				wantRoot:     legacy,
				wantLegacy:   true,
				wantProbeErr: errUnreadable,
			},
			{
				// The guard: with no legacy path to consider there is nothing to
				// probe, so the probe is never called.
				name:      "no legacy dir: the durable default, probe untouched",
				workDir:   workDir,
				legacyDir: "",
				hasData:   never,
				wantRoot:  "/var/lib/k3sm",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				got := resolveAgentPodRoot(tc.explicit, tc.workDir, tc.legacyDir, tc.hasData(t))
				if got.root != tc.wantRoot {
					t.Errorf("resolveAgentPodRoot root = %q, want %q", got.root, tc.wantRoot)
				}
				if got.legacy != tc.wantLegacy {
					t.Errorf("resolveAgentPodRoot legacy = %v, want %v", got.legacy, tc.wantLegacy)
				}
				if !errors.Is(got.probeErr, tc.wantProbeErr) {
					t.Errorf("resolveAgentPodRoot probeErr = %v, want %v", got.probeErr, tc.wantProbeErr)
				}
				// The durable default is derived once and travels with the
				// choice, so the legacy Warn can name the path a fixed node
				// would land on.
				wantDurable := "/var/lib/k3sm"
				if tc.workDir == "/opt/k3sm-state/agent" {
					wantDurable = "/opt/k3sm-state"
				}
				if got.durable != wantDurable {
					t.Errorf("resolveAgentPodRoot durable = %q, want %q", got.durable, wantDurable)
				}
				if tc.wantLegacy {
					return
				}
				if tmp := strings.TrimSuffix(os.TempDir(), "/"); tmp != "" && strings.HasPrefix(got.root, tmp) {
					t.Errorf("resolved pod root %q is under the temp dir %q; macOS purges it, and it holds this node's PVC data", got.root, tmp)
				}
			})
		}
	})

	// The flag surface itself: the agent must register --pod-root with an EMPTY
	// default, so runAgent's resolution is what decides and the compiled temp-dir
	// path cannot come back through argv parsing.
	t.Run("the parsed default is empty and resolves off the temp dir", func(t *testing.T) {
		t.Parallel()

		// parseAgent registers the real agent flag surface and parses argv through it.
		parseAgent := func(t *testing.T, args ...string) agentOptions {
			t.Helper()
			fs := flag.NewFlagSet("agent", flag.ContinueOnError)
			var opts agentOptions
			registerAgentFlags(fs, &opts)
			if err := fs.Parse(args); err != nil {
				t.Fatalf("parse %v: %v", args, err)
			}
			return opts
		}

		opts := parseAgent(t)
		if opts.podRoot != "" {
			t.Fatalf("agent --pod-root default = %q, want \"\" (the resolution, not the flag, picks the durable root)", opts.podRoot)
		}
		got := resolveAgentPodRoot(opts.podRoot, opts.workDir, legacyAgentPodRoot(), func(string) (bool, error) { return false, nil })
		if got.legacy {
			t.Errorf("a fresh agent resolved to the legacy root %q", got.root)
		}
		if want := "/var/lib/k3sm"; got.root != want {
			t.Errorf("resolved pod root = %q, want %q (the --work-dir parent)", got.root, want)
		}
		if tmp := strings.TrimSuffix(os.TempDir(), "/"); tmp != "" && strings.HasPrefix(got.root, tmp) {
			t.Errorf("resolved pod root %q is under the temp dir %q", got.root, tmp)
		}
	})

	// (f) The operator-facing half: what the two cases actually say.
	t.Run("logging", func(t *testing.T) {
		t.Parallel()

		capture := func(t *testing.T, choice podRootChoice) (string, slog.Level) {
			t.Helper()
			var buf bytes.Buffer
			rec := &levelRecordingHandler{Handler: slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})}
			logAgentPodRoot(slog.New(rec), choice)
			if rec.records != 1 {
				t.Fatalf("logAgentPodRoot emitted %d records, want exactly 1", rec.records)
			}
			return buf.String(), rec.level
		}

		t.Run("legacy warns with both paths and the remedy", func(t *testing.T) {
			t.Parallel()
			line, level := capture(t, podRootChoice{root: legacy, durable: "/var/lib/k3sm", legacy: true})
			if level != slog.LevelWarn {
				t.Errorf("legacy pod root logged at %v, want WARN", level)
			}
			for _, want := range []string{legacy, "/var/lib/k3sm", "--pod-root"} {
				if !strings.Contains(line, want) {
					t.Errorf("legacy log line %q does not name %q", line, want)
				}
			}
		})

		t.Run("an unreadable legacy root names the probe error too", func(t *testing.T) {
			t.Parallel()
			line, _ := capture(t, podRootChoice{root: legacy, durable: "/var/lib/k3sm", legacy: true, probeErr: errUnreadable})
			if !strings.Contains(line, errUnreadable.Error()) {
				t.Errorf("legacy log line %q does not name why the root could not be read (%v)", line, errUnreadable)
			}
		})

		t.Run("the derived default is reported once at info", func(t *testing.T) {
			t.Parallel()
			line, level := capture(t, podRootChoice{root: "/var/lib/k3sm", durable: "/var/lib/k3sm"})
			if level != slog.LevelInfo {
				t.Errorf("derived pod root logged at %v, want INFO", level)
			}
			if !strings.Contains(line, "/var/lib/k3sm") {
				t.Errorf("info log line %q does not name the resolved pod root", line)
			}
		})
	})

	// podRootHasData is the production probe, and its verdict is three-way: a
	// purged (absent) or empty legacy root must not pin a node to it, an
	// unreadable one must.
	t.Run("podRootHasData", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()

		absent := filepath.Join(dir, "absent")
		if data, err := podRootHasData(absent); data || err != nil {
			t.Errorf("podRootHasData(absent) = %v, %v; want false, nil", data, err)
		}

		file := filepath.Join(dir, "file")
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if data, err := podRootHasData(filepath.Join(file, "under-a-file")); data || err != nil {
			t.Errorf("podRootHasData(not-a-directory) = %v, %v; want false, nil", data, err)
		}

		empty := filepath.Join(dir, "empty")
		if err := os.MkdirAll(empty, 0o755); err != nil {
			t.Fatal(err)
		}
		if data, err := podRootHasData(empty); data || err != nil {
			t.Errorf("podRootHasData(empty) = %v, %v; want false, nil", data, err)
		}
		if err := os.WriteFile(filepath.Join(empty, "pod"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if data, err := podRootHasData(empty); !data || err != nil {
			t.Errorf("podRootHasData(non-empty) = %v, %v; want true, nil", data, err)
		}

		t.Run("unreadable", func(t *testing.T) {
			if os.Geteuid() == 0 {
				t.Skip("root reads a 0-mode directory regardless, so the denial cannot be staged")
			}
			denied := filepath.Join(dir, "denied")
			if err := os.MkdirAll(denied, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(denied, "pod"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(denied, 0o000); err != nil {
				t.Fatal(err)
			}
			// Restored so t.TempDir's cleanup can remove the tree.
			t.Cleanup(func() { _ = os.Chmod(denied, 0o755) })

			data, err := podRootHasData(denied)
			if !data {
				t.Error("podRootHasData(unreadable) = false; an existing root whose contents cannot be read must keep the node on it, not silently strand its volumes")
			}
			if err == nil {
				t.Fatal("podRootHasData(unreadable) returned no error; the operator is never told why the node stayed")
			}
			if errors.Is(err, fs.ErrNotExist) {
				t.Errorf("podRootHasData(unreadable) reported a not-exist error: %v", err)
			}
		})
	})
}

// levelRecordingHandler counts the records it sees and keeps the last one's
// level, so a test can assert BOTH that exactly one line was emitted and at
// which severity — neither of which the rendered text carries reliably.
type levelRecordingHandler struct {
	slog.Handler
	records int
	level   slog.Level
}

func (h *levelRecordingHandler) Handle(ctx context.Context, r slog.Record) error {
	h.records++
	h.level = r.Level
	return h.Handler.Handle(ctx, r)
}
