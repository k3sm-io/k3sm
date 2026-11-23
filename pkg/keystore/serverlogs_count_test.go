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

// preFrameCounts is one view of the pre-frame part: the total, the login
// part, the reserved part and each login uid's sub-share.
type preFrameCounts struct {
	used, login, reserved int64
	byUID                 map[uint32]int64
}

func (l *ServerLogs) countsOf() preFrameCounts {
	l.mu.Lock()
	defer l.mu.Unlock()
	return preFrameCounts{l.used, l.usedLogin, l.used - l.usedLogin, maps.Clone(l.usedByUID)}
}

func (c preFrameCounts) equal(o preFrameCounts) bool {
	return c.used == o.used && c.login == o.login && c.reserved == o.reserved && maps.Equal(c.byUID, o.byUID)
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
	l.pending[1001] += 2
	l.pending[0]++
	l.pending[service] += 5
	l.pending[noUID]++
	l.mu.Unlock()
	must("pending flushed with a next line", l.Refused(ctx, 1002, "sandbox-unknown"))

	// Lines of other kinds, and a pre-frame line of another writer.
	external(`{"v":1,"op":"put","scope":"user/1001","name":"a"}` + "\n")
	external("not json\n\n")
	other, err := json.Marshal(preFrameRecord(1003, "sandboxed", 0, s.now()))
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
	if got := l.countsOf().byUID[1005]; got > PreFrameLoginUIDShare {
		t.Fatalf("uid 1005 charged %d bytes, over its %d-byte sub-share", got, PreFrameLoginUIDShare)
	}
	must("root after a spent sub-share", l.Refused(ctx, 0, "root"))
}
