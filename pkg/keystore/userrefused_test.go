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
	"testing"
)

// A post-frame refused line names the socket, the caller's uid and pid,
// the caller's own scope, the operation and the reason, and nothing else:
// no entry name, version, fingerprint or namespace; its summary carries
// the dropped count. Both read back strictly and are charged to the
// caller's uid. An operation or reason outside the closed sets writes
// nothing.
func TestPostFrameRefusedLineFields(t *testing.T) {
	ctx := context.Background()
	s, _, u := fileLogScope(t)
	sock := u.WithOrigin(SocketOrigin(77))
	before := len(nonEmptyLines(readLog(t, s, auditLogName)))
	if err := sock.Refused(ctx, "exec-read", RefusedRateLimited); err != nil {
		t.Fatal(err)
	}
	if err := sock.RefusedDropped(ctx, 3); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][2]string{{"read-for-exec", RefusedBadHeader}, {"put", "free text"}, {"show", RefusedNotServed}} {
		if err := sock.Refused(ctx, bad[0], bad[1]); !errors.Is(err, errRefusedField) {
			t.Fatalf("Refused(%q, %q) = %v, want errRefusedField", bad[0], bad[1], err)
		}
	}
	if err := sock.RefusedDropped(ctx, 0); err != nil {
		t.Fatal(err)
	}
	lines := nonEmptyLines(readLog(t, s, auditLogName))[before:]
	if len(lines) != 2 {
		t.Fatalf("%d lines written, want the refusal and its summary", len(lines))
	}
	want := []string{
		`"op":"refused","via":"socket","caller":{"uid":1001,"pid":77},"scope":"user/1001","name":"","namespace":"","request":"exec-read","result":"rate-limited"}`,
		`"op":"refused","via":"socket","caller":{"uid":1001,"pid":77},"scope":"user/1001","name":"","namespace":"","result":"dropped","dropped":3}`,
	}
	for i, line := range lines {
		if _, err := parseAuditLine(line); err != nil {
			t.Fatalf("line %q: %v", line, err)
		}
		if uid, _, err := auditLineCharge(line); err != nil || uid != 1001 {
			t.Fatalf("line %q is charged to uid %d (%v), want 1001", line, uid, err)
		}
		at := bytes.Index(line, []byte(`"op":`))
		if at < 0 || !bytes.HasPrefix(line, []byte(`{"v":1,"ts":"`)) {
			t.Fatalf("line %q", line)
		}
		if got := string(line[at:]); got != want[i] {
			t.Errorf("line %d\n got %s\nwant %s", i, got, want[i])
		}
	}
}

// A refused line is charged to the caller's share: past it the line is
// refused with the share's sentinel, nothing is written, and that is not
// the global append failure; another uid's line is written.
func TestPostFrameRefusedChargedToShare(t *testing.T) {
	ctx := context.Background()
	s, a, b := shareStore(t)
	fillAudit(t, s, 1001, "", false)
	before := len(readLog(t, s, auditLogName))
	err := a.WithOrigin(SocketOrigin(1)).Refused(ctx, "put", RefusedBadValue)
	if !LogShareRefused(err) {
		t.Fatalf("a refused line past the share = %v, want the share's refusal", err)
	}
	if got := len(readLog(t, s, auditLogName)); got != before {
		t.Fatalf("a refused line past the share wrote %d bytes", got-before)
	}
	if s.AuditFailing() {
		t.Fatal("a refused line past the share set the global append failure")
	}
	if err := b.WithOrigin(SocketOrigin(2)).Refused(ctx, "put", RefusedBadValue); err != nil {
		t.Fatalf("another uid's refused line: %v", err)
	}
}

// A refused line's append is the store's like any other: one that fails
// enters the global append failure, and one that succeeds ends it, so a
// refused request can probe whether appends work again.
func TestRefusedLineEndsAuditFailing(t *testing.T) {
	ctx := context.Background()
	s, _ := newMasteredStore(t)
	fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1)})
	u := userScope(t, s, 1001).WithOrigin(SocketOrigin(5))
	userPut(t, u, "user/1001/a", "v")
	_, audit := userLogs(s)
	audit.fail = true
	if err := u.Refused(ctx, "list", RefusedAuditFailing); err == nil {
		t.Fatal("a refused line whose append fails succeeded")
	}
	if !s.AuditFailing() {
		t.Fatal("a refused line's failed append did not enter the global append failure")
	}
	if n := s.UnauditedOps(); n != 0 {
		t.Fatalf("a refused line counted %d unaudited operations", n)
	}
	audit.fail = false
	if err := u.Refused(ctx, "list", RefusedAuditFailing); err != nil {
		t.Fatal(err)
	}
	if s.AuditFailing() {
		t.Fatal("a refused line's successful append did not end the global append failure")
	}
	l := audit.all()[len(audit.all())-1]
	if l.op != "refused" || l.request != "list" || l.result != RefusedAuditFailing || l.name != "" || l.revoke {
		t.Fatalf("the refused line is %+v", l)
	}
}
