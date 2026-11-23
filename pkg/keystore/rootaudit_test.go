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

package keystore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// U52 (the store's half): a root verb's audit line carries via root, only
// once the audit log exists; before it nothing is written and the verb is
// not refused. A line without via, as every line written before the field
// existed is, still reads.
func TestAuditRootViaRootOnceLogExists(t *testing.T) {
	ctx := context.Background()
	s, _ := newMasteredStore(t)
	if err := s.AuditRoot(ctx, "put", "api-token", "ok"); err != nil {
		t.Fatalf("AuditRoot before install made the log: %v, want nil", err)
	}
	if _, err := os.Lstat(filepath.Join(s.dataRoot, logsDirName, auditDirName, auditLogName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("AuditRoot created the audit log: %v", err)
	}
	withFileLogs(t, s)
	if err := s.AuditRoot(ctx, "rm", "api-token", "refused"); err != nil {
		t.Fatal(err)
	}
	if err := s.AuditRoot(ctx, "list", "", "ok"); err != nil {
		t.Fatal(err)
	}
	// Every append leads with a newline, so blank lines are skipped.
	var lines [][]byte
	for _, l := range bytes.Split(readLog(t, s, auditLogName), []byte{'\n'}) {
		if len(l) > 0 {
			lines = append(lines, l)
		}
	}
	if len(lines) != 2 {
		t.Fatalf("%d audit lines, want 2:\n%s", len(lines), bytes.Join(lines, []byte{'\n'}))
	}
	for i, want := range []auditRecord{
		{V: 1, Op: "rm", Via: "root", Scope: "system", Name: "api-token", Result: "refused"},
		{V: 1, Op: "list", Via: "root", Scope: "system", Name: auditPlaceholder, Result: "ok"},
	} {
		got, err := parseAuditLine(lines[i])
		if err != nil {
			t.Fatal(err)
		}
		got.TS = ""
		if got != want {
			t.Errorf("line %d = %+v, want %+v", i, got, want)
		}
	}
	old := []byte(`{"v":1,"ts":"2026-01-01T00:00:00Z","op":"put","scope":"user/501","name":"a","namespace":"","result":"ok"}`)
	if r, err := parseAuditLine(old); err != nil || r.Via != "" {
		t.Fatalf("a line without via: %+v, %v", r, err)
	}
	s.logFlags = func(*os.File) (uint32, error) { return 0, nil }
	if err := s.AuditRoot(ctx, "put", "api-token", "ok"); !errors.Is(err, errLogNotAppendOnly) {
		t.Fatalf("AuditRoot over an unflagged log: %v, want errLogNotAppendOnly", err)
	}
}
