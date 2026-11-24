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
	"strings"
	"testing"
)

// A view taken with a socket origin writes via socket and the caller (the
// view's own uid and the advisory pid) on every line of its operations, and
// the view it was taken from writes neither; the lines read back strictly.
func TestAuditSocketOriginFields(t *testing.T) {
	ctx := context.Background()
	s, _, u := fileLogScope(t)
	sock := u.WithOrigin(SocketOrigin(4242))
	v := userPut(t, sock, "user/1001/sock", "a value")
	if err := sock.Delete(ctx, "user/1001/sock"); err != nil {
		t.Fatal(err)
	}
	if err := sock.Delete(ctx, "user/1001/absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rm of an absent entry: %v, want ErrNotFound", err)
	}
	userPut(t, u, "user/1001/plain", "a value")
	lines := nonEmptyLines(readLog(t, s, auditLogName))
	// fileLogScope's put, then put, rm, the refused rm, and the plain put.
	if len(lines) != 5 {
		t.Fatalf("%d audit lines, want 5", len(lines))
	}
	for i, line := range lines[1:4] {
		r, err := parseAuditLine(line)
		if err != nil {
			t.Fatalf("line %d %q: %v", i, line, err)
		}
		if r.Via != "socket" || r.Caller == nil || r.Caller.UID != 1001 || r.Caller.PID != 4242 {
			t.Fatalf("socket line %d %s: via %q caller %+v, want socket, uid 1001, pid 4242", i, line, r.Via, r.Caller)
		}
	}
	put, _ := parseAuditLine(lines[1])
	if put.Version != 1 || put.Fingerprint != v.Fingerprint || put.Fingerprint == "" {
		t.Fatalf("the put's line names version %d fingerprint %q, want 1 and %q", put.Version, put.Fingerprint, v.Fingerprint)
	}
	if rm, _ := parseAuditLine(lines[2]); rm.Version != 0 || rm.Fingerprint != "" {
		t.Fatalf("the rm's line names version %d fingerprint %q, want neither", rm.Version, rm.Fingerprint)
	}
	plain, err := parseAuditLine(lines[4])
	if err != nil {
		t.Fatal(err)
	}
	if plain.Via != "" || plain.Caller != nil || strings.Contains(string(lines[4]), "caller") {
		t.Fatalf("a view without an origin wrote %s", lines[4])
	}
	if got := SocketOrigin(-7); got.pid != 0 {
		t.Fatalf("SocketOrigin(-7) keeps pid %d, want none", got.pid)
	}
}

// The caller object is read as strictly as the line around it: a key given
// twice, or a known key in another case, makes the line damage, charged to
// no uid.
func TestAuditCallerParsedStrictly(t *testing.T) {
	good := `{"v":1,"ts":"t","op":"rm","via":"socket","caller":{"uid":1001,"pid":7},"scope":"user/1001","name":"n","namespace":"","result":"ok"}`
	if uid, _, err := auditLineCharge([]byte(good)); err != nil || uid != 1001 {
		t.Fatalf("a well-formed socket line charges uid %d (%v), want 1001", uid, err)
	}
	for _, caller := range []string{`{"uid":1001,"uid":1002}`, `{"UID":1002}`, `{"uid":1001,"Pid":7}`, `"1001"`} {
		line := strings.Replace(good, `{"uid":1001,"pid":7}`, caller, 1)
		if _, err := parseAuditLine([]byte(line)); err == nil {
			t.Fatalf("a line with caller %s parsed", caller)
		}
	}
}

// A uid past its own share is refused with the share's sentinel, which
// matches ErrLogFull and is not the global append failure: AuditFailing
// stays false and another uid's put goes ahead. An append the sink refuses
// for any other cause is the global failure, and the next append that
// succeeds clears it.
func TestShareRefusalNotGlobalAppendFailureInStore(t *testing.T) {
	ctx := context.Background()
	s, a, b := shareStore(t)
	fillAudit(t, s, 1001, "", false)
	_, err := a.Put(ctx, "user/1001/more", KindOpaque, []byte("v"))
	if !errors.Is(err, ErrLogFull) || !errors.Is(err, errShareSpent) || !uidLogRefusal(err) {
		t.Fatalf("a put past the share: %v, want ErrLogFull and errShareSpent", err)
	}
	if s.AuditFailing() {
		t.Fatal("a share refusal set the global append failure")
	}
	userPut(t, b, "user/1002/more", "b's value")
	if s.AuditFailing() {
		t.Fatal("the global append failure is set after a successful append")
	}

	s.auditSink = &memAudit{fail: true}
	if _, err := b.Put(ctx, "user/1002/other", KindOpaque, []byte("v")); err == nil {
		t.Fatal("a put whose audit line fails succeeded")
	}
	if !s.AuditFailing() {
		t.Fatal("an append the sink refused did not set the global append failure")
	}
	s.auditSink = &memAudit{}
	userPut(t, b, "user/1002/after", "v")
	if s.AuditFailing() {
		t.Fatal("a successful append did not clear the global append failure")
	}
}

// Only a committed change whose audit line fails is an unaudited
// operation: an rm that commits and cannot append is counted; a put refused
// because its line failed changed nothing and is not.
func TestUnauditedOpsCountsCommittedRevocations(t *testing.T) {
	ctx := context.Background()
	s, _ := newMasteredStore(t)
	fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1)})
	u := userScope(t, s, 1001)
	userPut(t, u, "user/1001/a", "v")
	_, audit := userLogs(s)
	audit.fail = true
	if _, err := u.Put(ctx, "user/1001/b", KindOpaque, []byte("v")); !errors.Is(err, errAuditRefused) {
		t.Fatalf("a put whose line fails: %v, want errAuditRefused", err)
	}
	if n := s.UnauditedOps(); n != 0 {
		t.Fatalf("a refused put counted %d unaudited operations", n)
	}
	if err := u.Delete(ctx, "user/1001/a"); !Committed(err) {
		t.Fatalf("an rm whose line fails: %v, want ErrCommitted", err)
	}
	if n := s.UnauditedOps(); n != 1 {
		t.Fatalf("UnauditedOps = %d after one committed rm without its line, want 1", n)
	}
	if err := u.Delete(ctx, "user/1001/a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a second rm: %v, want ErrNotFound", err)
	}
	if n := s.UnauditedOps(); n != 1 {
		t.Fatalf("UnauditedOps = %d after a refused rm, want 1", n)
	}
}
