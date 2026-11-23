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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/keystore"
)

// keysAuditRecorder records each root audit line a verb asks for, and
// passes it to the real store, which writes nothing while the log is
// missing.
type keysAuditRecorder struct {
	keysStore
	lines *[]string
}

func (r keysAuditRecorder) AuditRoot(ctx context.Context, op, name, result string) error {
	*r.lines = append(*r.lines, op+" "+name+" "+result)
	return r.keysStore.AuditRoot(ctx, op, name, result)
}

// U52: every root verb that exists (put, list, show, rotate, rm, rewrap,
// deliver, undeliver; adopt in TestAdoptWritesAuditLine; floor merge in
// TestFloorMergeWritesAuditLine; floor --rebuild, rm-scope and audit
// --rotate in keysmaint_test.go) asks for exactly one audit line, via root, naming its
// op, its entry and its result, and a refusal is audited as refused. A verb
// refused before it opens the store (usage, not root) asks for none. With
// no audit log (before install made it) no line is written, nothing creates
// the log, and every verb still succeeds; pkg/keystore's
// TestAuditRootViaRootOnceLogExists shows the line written via root once
// the log exists.
func TestEveryRootVerbWritesAuditLine(t *testing.T) {
	h := newKeysHarness(t)
	var lines []string
	h.wrap = func(s keysStore) keysStore { return keysAuditRecorder{keysStore: s, lines: &lines} }
	keyOut := filepath.Join(t.TempDir(), "new-master")
	for _, tc := range []struct {
		args  []string
		stdin string
		code  int
		want  string
	}{
		{[]string{"put", "system/api-token", "--in", "-"}, "tok", keysOK, "put api-token ok"},
		{[]string{"list"}, "", keysOK, "list  ok"},
		{[]string{"ls"}, "", keysOK, "list  ok"},
		{[]string{"show", "system/api-token"}, "", keysOK, "show api-token ok"},
		{[]string{"rotate", "system/api-token", "--in", "-"}, "tok2", keysOK, "rotate api-token ok"},
		{[]string{"deliver", "system/api-token", "--namespace", "payments"}, "", keysOK, "deliver api-token ok"},
		{[]string{"undeliver", "system/api-token", "--namespace", "payments"}, "", keysOK, "undeliver api-token ok"},
		{[]string{"rewrap", "--key-out", keyOut}, "", keysOK, "rewrap  ok"},
		{[]string{"rm", "system/api-token", "--yes"}, "", keysOK, "rm api-token ok"},
		{[]string{"show", "system/api-token"}, "", keysRefused, "show api-token refused"},
	} {
		lines = nil
		h.stdin = bytes.NewReader([]byte(tc.stdin))
		h.mustRun(tc.code, tc.args...)
		if !slices.Equal(lines, []string{tc.want}) {
			t.Errorf("keys %v: audit lines %q, want exactly [%q]", tc.args, lines, tc.want)
		}
	}
	lines = nil
	h.mustRun(keysBadUsage, "show")
	h.euid = 501
	h.mustRun(keysRefused, "list")
	if len(lines) != 0 {
		t.Errorf("verbs refused before opening the store asked for audit lines: %q", lines)
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(h.work), keystore.AuditLogName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a root verb created the audit log: %v", err)
	}
}

// TestRealPrimitivesUnreachable proves TestMain's stubs are in place for
// the seams that exist today: each, called without a fake, panics naming
// its primitive (U60, in part).
func TestRealPrimitivesUnreachable(t *testing.T) {
	for _, tt := range []struct {
		primitive string
		call      func()
	}{
		{"geteuid", func() { _ = euidSeam() }},
		{"getpwnam", func() { _, _ = uidResolverSeam("_k3sm") }},
		{"exec", func() { _ = kubectlExec("/bin/false", nil, nil) }},
		{"fchown", func() { _ = fileAttrSeam.Fchown(-1, 0, 0) }},
		{"fchmod", func() { _ = fileAttrSeam.Fchmod(-1, 0) }},
		{"fchflags", func() { _ = fileAttrSeam.Fchflags(-1, 0) }},
	} {
		t.Run(tt.primitive, func(t *testing.T) {
			defer func() {
				r := recover()
				if s, _ := r.(string); !strings.Contains(s, tt.primitive) {
					t.Fatalf("the seam for %s did not panic naming it: %v", tt.primitive, r)
				}
			}()
			tt.call()
		})
	}
}

// panickingFileAttrs is the file-attribute writer TestMain installs: a
// unit test that forgets to inject a fake panics, naming the call.
type panickingFileAttrs struct{}

func (panickingFileAttrs) Fchown(int, int, int) error {
	panic("a unit test reached fchown: inject a fake file-attribute writer")
}

func (panickingFileAttrs) Fchmod(int, uint32) error {
	panic("a unit test reached fchmod: inject a fake file-attribute writer")
}

func (panickingFileAttrs) Fchflags(int, int) error {
	panic("a unit test reached fchflags: inject a fake file-attribute writer")
}

// U52 for the floor verb's merge form: floor merge and its dry run each ask
// for one audit line, the dry run under its own op since it writes nothing,
// and a usage refusal, before the store opens, asks for none.
func TestFloorMergeWritesAuditLine(t *testing.T) {
	h := newKeysHarness(t)
	var lines []string
	h.wrap = func(s keysStore) keysStore { return keysAuditRecorder{keysStore: s, lines: &lines} }
	h.put("system/k", []byte("v"))
	b := saveRecipeBackup(t, h, filepath.Join(t.TempDir(), "keystore-floor-backup"), "2026-11-22")
	h.mustRun(keysOK, "rm", "system/k", "--yes")
	if _, err := restoreRecipeBackup(t, h, b, true); err != nil {
		t.Fatalf("restore: %v", err)
	}
	for _, tc := range []struct {
		args []string
		op   string
	}{
		{[]string{"floor", "merge", "--dry-run"}, "floor-merge-dry-run"},
		{[]string{"floor", "merge"}, "floor-merge"},
	} {
		lines = nil
		code := h.run(tc.args...)
		want := tc.op + "  " + keysAuditResult(code)
		if code != keysOK && code != keysCommitted {
			t.Fatalf("keys %v exited %d: %s", tc.args, code, h.stderr.String())
		}
		if !slices.Equal(lines, []string{want}) {
			t.Errorf("keys %v: audit lines %q, want exactly [%q]", tc.args, lines, want)
		}
	}
	lines = nil
	h.mustRun(keysBadUsage, "floor", "merge", "extra")
	h.mustRun(keysBadUsage, "floor")
	if len(lines) != 0 {
		t.Errorf("floor refused for usage asked for audit lines: %q", lines)
	}
}

// U52 for adopt, and for a change made whose later step failed
// (keystore.ErrCommitted, exit 4): adopt asks for one audit line under its
// own op, refused when there is nothing to adopt; put, rotate and adopt
// that commit and then fail a step are each audited committed.
func TestAdoptWritesAuditLine(t *testing.T) {
	var lines []string
	h := newKeysHarness(t)
	h.wrap = func(s keysStore) keysStore { return keysAuditRecorder{keysStore: s, lines: &lines} }
	h.put("system/alpha", []byte("one"))
	orphanAudited(t, h, "alpha", keysOK)
	lines = nil
	h.mustRun(keysOK, "adopt", "system/alpha", "--yes")
	if want := []string{"adopt alpha ok"}; !slices.Equal(lines, want) {
		t.Errorf("adopt: audit lines %q, want %q", lines, want)
	}
	lines = nil
	h.mustRun(keysRefused, "adopt", "system/alpha", "--yes")
	if want := []string{"adopt alpha refused"}; !slices.Equal(lines, want) {
		t.Errorf("adopt with nothing to adopt: audit lines %q, want %q", lines, want)
	}

	// The recorder wraps committedStore, so it sees the exit the verb
	// returned for the injected ErrCommitted.
	h = newKeysHarness(t)
	h.wrap = func(s keysStore) keysStore { return keysAuditRecorder{keysStore: committedStore{s}, lines: &lines} }
	lines = nil
	h.stdin = strings.NewReader("one")
	h.mustRun(keysCommitted, "put", "system/beta", "--in", "-")
	if want := []string{"put beta committed"}; !slices.Equal(lines, want) {
		t.Errorf("committed put: audit lines %q, want %q", lines, want)
	}
	lines = nil
	orphanAudited(t, h, "beta", keysCommitted)
	if want := []string{"rotate beta committed"}; !slices.Equal(lines, want) {
		t.Errorf("committed rotate: audit lines %q, want %q", lines, want)
	}
	lines = nil
	h.mustRun(keysCommitted, "adopt", "system/beta", "--yes")
	if want := []string{"adopt beta committed"}; !slices.Equal(lines, want) {
		t.Errorf("committed adopt: audit lines %q, want %q", lines, want)
	}
}

// orphanAudited rotates name, the harness's only entry, to version 2
// (exiting rotateCode), then copies its version 1 pointer back and lags the
// floor to it: the files a crashed rotation leaves, with version 2 to adopt.
func orphanAudited(t *testing.T, h *keysHarness, name string, rotateCode int) {
	t.Helper()
	cur := filepath.Join(h.keystoreDir(), name, "current")
	saved, err := os.ReadFile(cur)
	if err != nil {
		t.Fatal(err)
	}
	h.stdin = strings.NewReader("two")
	h.mustRun(rotateCode, "rotate", "system/"+name, "--in", "-")
	if err := os.WriteFile(cur, saved, 0o600); err != nil {
		t.Fatal(err)
	}
	floorPath := filepath.Join(filepath.Dir(h.work), "keystore-floor.json")
	b, err := os.ReadFile(floorPath)
	if err != nil {
		t.Fatal(err)
	}
	lagged := strings.Replace(string(b), `"seq":2`, `"seq":1`, 1)
	if lagged == string(b) {
		t.Fatalf("the floor does not record sequence 2: %s", b)
	}
	if err := os.WriteFile(floorPath, []byte(lagged), 0o600); err != nil {
		t.Fatal(err)
	}
}

// keysAuditResult: an exit that made the change (4, and 5 for a floor merge
// written but not finished) is audited as committed, never as refused.
func TestKeysAuditResult(t *testing.T) {
	for code, want := range map[int]string{
		keysOK:         "ok",
		keysRefused:    "refused",
		keysBadUsage:   "refused",
		keysResumed:    "resumed",
		keysCommitted:  "committed",
		keysNotRenamed: "committed",
	} {
		if got := keysAuditResult(code); got != want {
			t.Errorf("keysAuditResult(%d) = %q, want %q", code, got, want)
		}
	}
}
