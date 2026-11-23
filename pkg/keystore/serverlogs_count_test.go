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
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// preFrameCounts is one view of the pre-frame part: the total, each
// class's part, and each uid's sub-share within the classes that have one.
type preFrameCounts struct {
	used    int64
	byClass map[preFrameClass]int64
	byUID   map[preFrameKey]int64
}

func (l *ServerLogs) countsOf() preFrameCounts {
	l.mu.Lock()
	defer l.mu.Unlock()
	c := preFrameCounts{l.used, map[preFrameClass]int64{}, map[preFrameKey]int64{}}
	// A zero entry and an absent one are the same count.
	for k, v := range l.usedByClass {
		if v != 0 {
			c.byClass[k] = v
		}
	}
	for k, v := range l.usedByUID {
		if v != 0 {
			c.byUID[k] = v
		}
	}
	return c
}

func (c preFrameCounts) equal(o preFrameCounts) bool {
	return c.used == o.used && maps.Equal(c.byClass, o.byClass) && maps.Equal(c.byUID, o.byUID)
}

// newServerLogsStore is a real store over a data root in t.TempDir(), laid
// out as install leaves it, with the test user standing in for root and
// the service user and every log read as SF_APPEND.
func newServerLogsStore(t *testing.T) (*FileStore, string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("the test user stands in for the service user, which is never root")
	}
	data := t.TempDir()
	for _, d := range []struct {
		p    string
		mode os.FileMode
	}{
		{filepath.Join(data, "server"), 0o700},
		{filepath.Join(data, "server", "keystore"), 0o700},
		{filepath.Join(data, logsDirName), 0o755},
		{filepath.Join(data, logsDirName, floorDirName), 0o755},
		{filepath.Join(data, logsDirName, auditDirName), 0o755},
	} {
		if err := os.Mkdir(d.p, d.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d.p, d.mode); err != nil {
			t.Fatal(err)
		}
	}
	audit := filepath.Join(data, logsDirName, auditDirName, auditLogName)
	for _, p := range []string{audit, filepath.Join(data, logsDirName, floorDirName, userFloorLogName)} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	uid, gid := os.Getuid(), os.Getgid()
	s := New(Config{
		Dir:       filepath.Join(data, "server", "keystore"),
		MasterDir: filepath.Join(data, "server", "cred", "keystore-master"),
		UID:       uint32(uid), GID: uint32(gid),
		DataRoot: data,
		FloorUID: uid, FloorGID: gid,
		LogFlags: func(*os.File) (uint32, error) { return unix.SF_APPEND, nil },
	})
	return s, audit
}

// TestPreFrameRunningCountIsTheRecount pins the budget's one charging rule:
// after every append through the real API, the running count of every
// class (the total, the login part, each login uid's sub-share, the
// reserved part) equals a fresh recount of the audit file, byte for byte,
// whatever else the file holds.
func TestPreFrameRunningCountIsTheRecount(t *testing.T) {
	s, auditPath := newServerLogsStore(t)
	ctx := t.Context()
	l := s.ServerLogs()
	t.Cleanup(func() { _ = l.Close() })
	service := uint32(os.Getuid())
	const noUID = ^uint32(0)

	// external appends bytes to the audit file as another writer would.
	external := func(b string) {
		t.Helper()
		f, err := os.OpenFile(auditPath, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		if _, err := f.WriteString(b); err != nil {
			t.Fatal(err)
		}
	}
	check := func(step string) {
		t.Helper()
		running := l.countsOf()
		fresh := s.ServerLogs()
		defer func() { _ = fresh.Close() }()
		if err := fresh.Reopen(ctx); err != nil {
			t.Fatalf("%s: recount: %v", step, err)
		}
		if recount := fresh.countsOf(); !running.equal(recount) {
			t.Fatalf("%s: running count %+v, recount of the file %+v", step, running, recount)
		}
	}
	must := func(step string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		check(step)
	}

	if err := l.Reopen(ctx); err != nil {
		t.Fatal(err)
	}
	check("reopen of the empty log")
	must("login refusal", l.Refused(ctx, 1001, "sandboxed"))
	must("second login uid", l.Refused(ctx, 70000, "token-mismatch"))
	must("root refusal", l.Refused(ctx, 0, "root"))
	must("service-uid refusal", l.Refused(ctx, service, "service-uid"))
	must("no-uid refusal", l.Refused(ctx, noUID, "cred-unreadable"))
	must("system-uid refusal", l.Refused(ctx, 42, "system-uid"))
	must("high-uid refusal", l.Refused(ctx, 1<<31, "high-uid"))
	must("dropped summaries", l.Dropped(ctx, 1001, 3))
	must("root summary", l.Dropped(ctx, 0, 2))

	// Pending counts carried after the next line that lands.
	l.mu.Lock()
	l.pending[preFrameKey{preFrameClassLogin, 1001}] += 2
	l.pending[preFrameKey{preFrameClassRoot, 0}]++
	l.pending[preFrameKey{preFrameClassServiceUID, service}] += 5
	l.pending[preFrameKey{preFrameClassNoUID, noUID}]++
	l.pending[preFrameKey{preFrameClassSystemHigh, 42}]++
	l.mu.Unlock()
	must("pending flushed with a next line", l.Refused(ctx, 1002, "sandbox-unknown"))

	// Lines of other kinds, and a pre-frame line of another writer.
	external(`{"v":1,"op":"put","scope":"user/1001","name":"a"}` + "\n")
	external("not json\n\n")
	other, err := json.Marshal(preFrameRecord(1003, "sandboxed", "", 0, s.now()))
	if err != nil {
		t.Fatal(err)
	}
	external("\n" + string(other) + "\n")
	must("after lines of other kinds", l.Refused(ctx, 1001, "sandboxed"))

	// A torn tail, then an append that closes it.
	external(`{"v":1,"op":"put","scope":"user/10`)
	must("append after a torn tail", l.Refused(ctx, 1004, "sandboxed"))
	external(string(other[:len(other)/2]))
	must("summary after a torn tail", l.Dropped(ctx, 1004, 1))

	// A line past the budget: one login uid at its sub-share.
	for l.Refused(ctx, 1005, "sandboxed") == nil {
		check("filling a sub-share")
	}
	check("sub-share spent")
	if got := l.countsOf().byUID[preFrameKey{preFrameClassLogin, 1005}]; got > PreFrameLoginUIDShare {
		t.Fatalf("uid 1005 charged %d bytes, over its %d-byte sub-share", got, PreFrameLoginUIDShare)
	}
	must("root after a spent sub-share", l.Refused(ctx, 0, "root"))

	// A summary names its own class, and the recount charges it there
	// whatever uid it carries: a service-uid summary under a login uid is
	// the service-uid class's, not uid 1006's.
	cross, err := json.Marshal(preFrameRecord(1006, auditResultDropped, preFrameClassServiceUID, 4, s.now()))
	if err != nil {
		t.Fatal(err)
	}
	before := l.countsOf()
	external("\n" + string(cross) + "\n")
	must("a summary naming its class", l.Refused(ctx, 0, "root"))
	after := l.countsOf()
	if after.byUID[preFrameKey{preFrameClassLogin, 1006}] != 0 {
		t.Fatal("a service-uid summary under a login uid was charged to that uid")
	}
	if got, want := after.byClass[preFrameClassServiceUID]-before.byClass[preFrameClassServiceUID], int64(len(cross))+2; got != want {
		t.Fatalf("service-uid class grew %d bytes, want the summary's %d", got, want)
	}

	// Each reserved class filled to its own limit through the append
	// path, the running count equal to the recount at every step.
	for _, c := range []struct {
		uid    uint32
		reason string
		class  preFrameClass
	}{
		{0, "root", preFrameClassRoot},
		{service, "service-uid", preFrameClassServiceUID},
		{noUID, "cred-unreadable", preFrameClassNoUID},
		{42, "system-uid", preFrameClassSystemHigh},
	} {
		for l.Refused(ctx, c.uid, c.reason) == nil {
			check("filling " + string(c.class))
		}
		check(string(c.class) + " spent")
	}
	for _, c := range preFrameClasses {
		if got := l.countsOf().byClass[c]; got == 0 || got > c.budget() {
			t.Fatalf("class %s charged %d bytes, want some and at most %d", c, got, c.budget())
		}
	}
}
