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
	"strings"
	"testing"
)

// rotateScope is a memory-logged store with uid 1001's scope holding
// user/1001/a at version 1, value "one".
func rotateScope(t *testing.T) (*FileStore, *UserScope) {
	t.Helper()
	s, _ := newMasteredStore(t)
	fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1)})
	u := userScope(t, s, 1001)
	userPut(t, u, "user/1001/a", "one")
	return s, u
}

// userVersionValue reads version n of user/1001/<name>.
func userVersionValue(t *testing.T, u *UserScope, name string, n uint64) []byte {
	t.Helper()
	var val []byte
	err := u.read(context.Background(), func(entries *os.Root, uk keys) error {
		e, err := openUserEntry(entries, name)
		if err != nil {
			return err
		}
		defer e.close()
		_, val, err = e.version(uk, n)
		return err
	})
	if err != nil {
		t.Fatalf("read version %d of %s: %v", n, name, err)
	}
	return val
}

// A rotate writes the next version, flips the pointer to it at the next
// sequence and appends that floor line, then its audit line naming the
// version and its fingerprint, in the revocation class; every version is
// kept.
func TestUserRotateWritesNextVersion(t *testing.T) {
	ctx := context.Background()
	s, u := rotateScope(t)
	floor, audit := userLogs(s)
	sock := u.WithOrigin(SocketOrigin(77))
	v, err := sock.Rotate(ctx, "user/1001/a", []byte("two"))
	if err != nil {
		t.Fatal(err)
	}
	if v.Version != 2 || v.Kind != KindOpaque {
		t.Fatalf("rotate returned %+v, want version 2, opaque", v)
	}
	cur, val, err := u.Current(ctx, "user/1001/a")
	if err != nil || cur.Version != 2 || string(val) != "two" || cur.Fingerprint != v.Fingerprint {
		t.Fatalf("current after rotate: %+v %q %v, want version 2 \"two\"", cur, val, err)
	}
	if got := userVersionValue(t, u, "a", 1); string(got) != "one" {
		t.Fatalf("version 1 after rotate holds %q, want \"one\" kept", got)
	}
	last := floor.lines[len(floor.lines)-1]
	if last.name != "a" || last.seq != 2 || last.tomb {
		t.Fatalf("the floor's last line is %+v, want a at sequence 2", last)
	}
	lines := audit.all()
	l := lines[len(lines)-1]
	if l.op != "rotate" || l.result != "ok" || !l.revoke || l.version != 2 || l.fingerprint != v.Fingerprint ||
		l.via != "socket" || l.caller == nil || l.caller.UID != 1001 || l.caller.PID != 77 {
		t.Fatalf("the rotate's audit line is %+v, want ok, revoke, version 2, its fingerprint, via socket, caller 1001/77", l)
	}
	if _, err := u.Rotate(ctx, "user/1001/a", nil); err == nil {
		t.Fatal("a rotate to an empty value succeeded")
	}
}

// A rotate from a version writes that version's value forward as a new
// version; it never points the pointer back. Version 0 and one above the
// current version are ErrVersionNotFound, with nothing written.
func TestUserRotateFromWritesForward(t *testing.T) {
	ctx := context.Background()
	_, u := rotateScope(t)
	if _, err := u.Rotate(ctx, "user/1001/a", []byte("two")); err != nil {
		t.Fatal(err)
	}
	v, err := u.RotateFrom(ctx, "user/1001/a", 1)
	if err != nil || v.Version != 3 {
		t.Fatalf("RotateFrom 1: %+v %v, want version 3", v, err)
	}
	if _, val, _ := u.Current(ctx, "user/1001/a"); string(val) != "one" {
		t.Fatalf("current after RotateFrom 1 holds %q, want \"one\"", val)
	}
	for _, from := range []uint64{0, 4} {
		if _, err := u.RotateFrom(ctx, "user/1001/a", from); !errors.Is(err, ErrVersionNotFound) {
			t.Fatalf("RotateFrom %d: %v, want ErrVersionNotFound", from, err)
		}
	}
	if cur, _, _ := u.Current(ctx, "user/1001/a"); cur.Version != 3 {
		t.Fatalf("a refused RotateFrom moved the pointer to %d", cur.Version)
	}
}

// Another uid's entry, a system name and an absent entry of the caller's
// own all answer the same ErrNotFound, and none is in the revocation class.
func TestUserRotateNotFoundIsNoOp(t *testing.T) {
	ctx := context.Background()
	s, u := rotateScope(t)
	_, audit := userLogs(s)
	var texts []string
	for _, in := range []string{"user/1001/absent", "user/1002/a", "system/a"} {
		_, err := u.Rotate(ctx, in, []byte("x"))
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("rotate %s: %v, want ErrNotFound", in, err)
		}
		texts = append(texts, err.Error())
	}
	if texts[0] != texts[1] || texts[1] != texts[2] {
		t.Fatalf("rotate's not-found answers differ: %q", texts)
	}
	for _, l := range audit.all() {
		if l.op == "rotate" && (l.revoke || l.result != "not-found") {
			t.Fatalf("a rotate that changed nothing wrote %+v", l)
		}
	}
}

// A rotate that finds no entry is charged like any line and refused past
// the share; a real rotation past the share goes ahead on the socket
// margin.
func TestUserRotateNoOpChargedToShare(t *testing.T) {
	ctx := context.Background()
	s, a, _ := shareStore(t)
	userPut(t, a, "user/1001/r", "one")
	fillAudit(t, s, 1001, "", false)
	before := countsOf(t, auditLogOf(s))
	if _, err := a.Rotate(ctx, "user/1001/absent", []byte("x")); !errors.Is(err, errShareSpent) {
		t.Fatalf("a no-op rotate past the share: %v, want the share refusal", err)
	}
	if _, err := a.Rotate(ctx, "user/1001/r", []byte("two")); err != nil {
		t.Fatalf("a rotation past the share: %v, want it drawn on the socket margin", err)
	}
	after := countsOf(t, auditLogOf(s))
	if after.margin[1001] <= before.margin[1001] {
		t.Fatalf("the rotation past the share drew %d on the margin, want more than %d", after.margin[1001], before.margin[1001])
	}
}

// Past the scope's byte quota a rotate is ErrQuota, nothing written.
func TestUserRotateQuota(t *testing.T) {
	ctx := context.Background()
	_, u := rotateScope(t)
	big := bytes.Repeat([]byte("q"), MaxValueSize)
	var err error
	for i := 0; i < maxScopeBytes/MaxValueSize+2; i++ {
		if _, err = u.Rotate(ctx, "user/1001/a", big); err != nil {
			break
		}
	}
	if !errors.Is(err, ErrQuota) {
		t.Fatalf("rotating past the scope's bytes: %v, want ErrQuota", err)
	}
	cur, _, _ := u.Current(ctx, "user/1001/a")
	if err := u.Delete(ctx, "user/1001/a"); err != nil {
		t.Fatalf("rm over quota: %v", err)
	}
	if cur.Version < 2 {
		t.Fatalf("no rotation landed before the quota (version %d)", cur.Version)
	}
}

// The crash order: a failure before the pointer flip commits nothing and
// removes the version; one after it returns the committed version with
// ErrCommitted, and its line says so; an audit line that fails after the
// commit leaves the rotation standing and counts it unaudited.
func TestUserRotateCrashOrder(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		step      string
		committed bool
	}{
		{"sync v2", false},
		{"sync " + currentName, true},
		{"floor a", true},
	} {
		t.Run(tc.step, func(t *testing.T) {
			s, u := rotateScope(t)
			floor, audit := userLogs(s)
			floorBefore := len(floor.lines)
			s.step = failAt(tc.step)
			v, err := u.Rotate(ctx, "user/1001/a", []byte("two"))
			s.step = func(string) error { return nil }
			cur, val, cerr := u.Current(ctx, "user/1001/a")
			if cerr != nil {
				t.Fatal(cerr)
			}
			lines := audit.all()
			l := lines[len(lines)-1]
			if !tc.committed {
				if err == nil || Committed(err) || v != (Version{}) {
					t.Fatalf("a failure before the flip: %+v %v, want a zero version and an uncommitted error", v, err)
				}
				if cur.Version != 1 || string(val) != "one" {
					t.Fatalf("current is %d %q, want version 1 kept", cur.Version, val)
				}
				if l.revoke || l.version != 0 || l.result == "ok" {
					t.Fatalf("the uncommitted rotate's line is %+v", l)
				}
				if len(floor.lines) != floorBefore {
					t.Fatal("an uncommitted rotate appended a floor line")
				}
				// The version written was removed: the next rotate is not
				// refused for an orphan.
				if v2, err := u.Rotate(ctx, "user/1001/a", []byte("again")); err != nil || v2.Version != 2 {
					t.Fatalf("the next rotate: %+v %v, want version 2", v2, err)
				}
				return
			}
			if !Committed(err) || v.Version != 2 {
				t.Fatalf("a failure after the flip: %+v %v, want version 2 and ErrCommitted", v, err)
			}
			if cur.Version != 2 || string(val) != "two" {
				t.Fatalf("current is %d %q, want version 2", cur.Version, val)
			}
			if !l.revoke || l.version != 2 || l.result != "committed" {
				t.Fatalf("the committed rotate's line is %+v, want committed, version 2, revoke", l)
			}
			if len(floor.lines) != floorBefore {
				t.Fatal("the floor line was appended after its step failed")
			}
			if names := s.lostLines.names(u.scope); len(names) != 1 || names[0] != "a" {
				t.Fatalf("lost lines %v, want a noted for catch-up", names)
			}
		})
	}
	t.Run("audit append fails after the commit", func(t *testing.T) {
		s, u := rotateScope(t)
		_, audit := userLogs(s)
		audit.fail = true
		v, err := u.Rotate(ctx, "user/1001/a", []byte("two"))
		audit.fail = false
		if !Committed(err) || v.Version != 2 || !strings.Contains(err.Error(), "audit line was not written") {
			t.Fatalf("a rotate whose line fails: %+v %v, want version 2 and ErrCommitted", v, err)
		}
		if n := s.UnauditedOps(); n != 1 {
			t.Fatalf("UnauditedOps = %d, want 1", n)
		}
		if cur, _, _ := u.Current(ctx, "user/1001/a"); cur.Version != 2 {
			t.Fatalf("current is %d after a committed rotate, want 2", cur.Version)
		}
	})
}
