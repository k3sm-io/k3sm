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
	"context"
	"errors"
	"testing"
)

// read-for-exec returns the value and appends one exec-read line, via and
// caller from the view's origin, naming neither the value, its length, nor
// a version or fingerprint; another uid's entry and a system name answer
// the absent entry's text, audited under the caller's own scope.
func TestExecReadAudited(t *testing.T) {
	ctx := context.Background()
	s, u := rotateScope(t)
	_, audit := userLogs(s)
	sock := u.WithOrigin(SocketOrigin(9))
	v, val, err := sock.ReadForExec(ctx, "user/1001/a")
	if err != nil || string(val) != "one" || v.Version != 1 {
		t.Fatalf("ReadForExec: %+v %q %v, want version 1 \"one\"", v, val, err)
	}
	lines := audit.all()
	l := lines[len(lines)-1]
	if l.op != "exec-read" || l.result != "ok" || l.name != "a" || l.scope != "user/1001" || l.revoke ||
		l.version != 0 || l.fingerprint != "" || l.via != "socket" || l.caller == nil || l.caller.PID != 9 {
		t.Fatalf("the exec-read line is %+v", l)
	}
	_, _, absent := sock.ReadForExec(ctx, "user/1001/absent")
	for _, in := range []string{"user/1002/a", "system/a"} {
		_, got, err := sock.ReadForExec(ctx, in)
		if !errors.Is(err, ErrNotFound) || got != nil || err.Error() != absent.Error() {
			t.Fatalf("ReadForExec %s: %q %v, want %v", in, got, err, absent)
		}
	}
	for _, l := range audit.all()[len(lines):] {
		if l.op != "exec-read" || l.result != "not-found" || l.scope != "user/1001" {
			t.Fatalf("a refused exec-read wrote %+v", l)
		}
	}
}

// A read whose audit line cannot be written is refused and hands out no
// value: the fail-closed rule, with no exception for reads; the failure is
// the global append failure.
func TestExecReadRefusedWhenAuditFails(t *testing.T) {
	ctx := context.Background()
	s, u := rotateScope(t)
	_, audit := userLogs(s)
	audit.fail = true
	_, val, err := u.ReadForExec(ctx, "user/1001/a")
	if !errors.Is(err, errReadAuditRefused) || val != nil {
		t.Fatalf("ReadForExec with the audit failing: %q %v, want errReadAuditRefused and no value", val, err)
	}
	if _, err := u.List(ctx); !errors.Is(err, errReadAuditRefused) {
		t.Fatalf("List with the audit failing: %v, want errReadAuditRefused", err)
	}
	if !s.AuditFailing() {
		t.Fatal("a refused read's failed append is not the global append failure")
	}
	if n := s.UnauditedOps(); n != 0 {
		t.Fatalf("a refused read counted %d unaudited operations", n)
	}
	audit.fail = false
	if _, _, err := u.ReadForExec(ctx, "user/1001/a"); err != nil || s.AuditFailing() {
		t.Fatalf("a read once appends succeed again: %v, failing %v", err, s.AuditFailing())
	}
}

// list appends one list line naming no entry.
func TestUserListAudited(t *testing.T) {
	ctx := context.Background()
	s, u := rotateScope(t)
	_, audit := userLogs(s)
	before := len(audit.all())
	es, err := u.WithOrigin(SocketOrigin(3)).List(ctx)
	if err != nil || len(es) != 1 || es[0].Name != "a" {
		t.Fatalf("List: %+v %v", es, err)
	}
	lines := audit.all()
	if len(lines) != before+1 {
		t.Fatalf("List wrote %d lines, want 1", len(lines)-before)
	}
	if l := lines[before]; l.op != "list" || l.result != "ok" || l.name != "" || l.via != "socket" || l.revoke {
		t.Fatalf("the list line is %+v", l)
	}
}

// Past its share a uid's reads are refused with the share's sentinel
// before anything is read or written, while another uid's reads go ahead:
// reads are charged to the share and are not in the revocation class.
func TestExecReadPastShareRefused(t *testing.T) {
	ctx := context.Background()
	s, a, b := shareStore(t)
	userPut(t, a, "user/1001/r", "a's")
	userPut(t, b, "user/1002/r", "b's")
	fillAudit(t, s, 1001, "", false)
	logBefore := len(readLog(t, s, auditLogName))
	// Refused at admission, before the read: never as a failed append.
	if _, val, err := a.ReadForExec(ctx, "user/1001/r"); !errors.Is(err, errShareSpent) || errors.Is(err, errReadAuditRefused) || val != nil {
		t.Fatalf("ReadForExec past the share: %q %v, want errShareSpent at admission", val, err)
	}
	if _, err := a.List(ctx); !errors.Is(err, errShareSpent) {
		t.Fatalf("List past the share: %v, want errShareSpent", err)
	}
	if got := len(readLog(t, s, auditLogName)); got != logBefore {
		t.Fatalf("refused reads wrote %d audit bytes", got-logBefore)
	}
	if s.AuditFailing() {
		t.Fatal("a share refusal set the global append failure")
	}
	if _, val, err := b.ReadForExec(ctx, "user/1002/r"); err != nil || string(val) != "b's" {
		t.Fatalf("another uid's read: %q %v", val, err)
	}
	if _, err := b.List(ctx); err != nil {
		t.Fatalf("another uid's list: %v", err)
	}
}
