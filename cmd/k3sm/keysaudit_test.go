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
// deliver, undeliver) asks for exactly one audit line, via root, naming its
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
