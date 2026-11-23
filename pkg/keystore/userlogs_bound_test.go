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
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// U24: the reader is bounded. A floor larger than its bound is damage, and
// the server never appends past the bound itself.
func TestLogReaderSizeBound(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	size := int64(len(readLog(t, s, userFloorLogName)))
	s.logHardCap = size
	s.logSoftCap = size
	s.logRevokeBudget = minLogRevokeBudget
	bound := s.logReadBound()
	if want := size + maxRevokeUIDs*minLogRevokeBudget + logBoundMargin; bound != want {
		t.Fatalf("the bound is %d, want %d", bound, want)
	}
	if got := s.readBoundOf(userFloorLogName); got != bound {
		t.Fatalf("the floor's bound is %d, want %d: no pre-frame line is written to it", got, bound)
	}
	gen := entryGeneration(t, server, "token")
	line, err := floorLine("user/1001", "token", gen, 1)
	if err != nil {
		t.Fatal(err)
	}
	appendLogBytes(t, s, userFloorLogName, bytes.Repeat(line, int(bound-size)/len(line)+1))
	if _, _, err := u.Current(ctx, "user/1001/token"); !errors.Is(err, errFloorLogMalformed) {
		t.Fatalf("current over a floor past the reader's bound: %v, want errFloorLogMalformed", err)
	}
	// The server refuses to write past the bound.
	l := s.userFloor.(*fileFloorLog).log
	if err := l.appendLine(1001, line, true, true); !errors.Is(err, ErrLogFull) {
		t.Fatalf("an append past the bound: %v, want ErrLogFull", err)
	}
}

// U24: the floor holds at most maxKeys distinct keys; one more is damage.
func TestFloorKeyBound(t *testing.T) {
	ctx := context.Background()
	s, _, u := fileLogScope(t)
	l := s.userFloor.(*fileFloorLog).log
	l.maxKeys = 4
	var b []byte
	for i := range 3 {
		line, err := floorLine("user/1001", fmt.Sprintf("k%d", i), guid(1), 1)
		if err != nil {
			t.Fatal(err)
		}
		b = append(b, line...)
	}
	appendLogBytes(t, s, userFloorLogName, b)
	// token's key, the delivery record's and three more: one past four.
	if _, _, err := u.Current(ctx, "user/1001/token"); !errors.Is(err, errFloorLogMalformed) {
		t.Fatalf("current over a floor past its key bound: %v, want errFloorLogMalformed", err)
	}
}

// U24: an audit line straddling the hard cap that is longer than the
// reader's buffer is read through, so the lines past it are charged.
func TestAuditStraddlingLineCharged(t *testing.T) {
	s, _, _ := fileLogScope(t)
	size := int64(len(readLog(t, s, auditLogName)))
	s.logHardCap = size + 10
	junk := append(bytes.Repeat([]byte("x"), 100<<10), '\n')
	appendLogBytes(t, s, auditLogName, junk)
	line, err := marshalAuditLine(auditLine{op: "rm", scope: "user/1001", name: "token", result: "ok"}, s.now())
	if err != nil {
		t.Fatal(err)
	}
	appendLogBytes(t, s, auditLogName, line)
	l := s.auditSink.(*fileAuditLog).log
	f, st, err := l.open(unix.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	l.mu.Lock()
	defer l.mu.Unlock()
	state, err := l.sync(f, st)
	if err != nil {
		t.Fatal(err)
	}
	if state.pastCap[1001] != int64(len(line)) || state.off != st.Size {
		t.Fatalf("past the cap uid 1001 is charged %d bytes and reading stopped at %d of %d, want %d and the end", state.pastCap[1001], state.off, st.Size, len(line))
	}
}

// A FIFO at a log's name is refused on its descriptor without blocking the
// open.
func TestLogOpenFIFORefused(t *testing.T) {
	ctx := context.Background()
	s, _, u := fileLogScope(t)
	p := filepath.Join(s.dataRoot, logsDirName, floorDirName, userFloorLogName)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(p, logMode); err != nil {
		t.Fatal(err)
	}
	if _, _, err := u.Current(ctx, "user/1001/token"); !errors.Is(err, errLogUntrusted) {
		t.Fatalf("current over a FIFO floor: %v, want errLogUntrusted", err)
	}
}

// U24: past the hard cap, an audit line over 1 KiB is skipped, charged to no
// uid, and is not sticky damage, as the tolerant audit reader drops any line
// it cannot read; the lines after it are still charged. The floor stays
// strict (TestWithdrawMalformedFloorRefused).
func TestAuditOverlongLineSkipped(t *testing.T) {
	s, _, _ := fileLogScope(t)
	size := int64(len(readLog(t, s, auditLogName)))
	s.logHardCap = size
	long := append(bytes.Repeat([]byte("y"), 2*maxLogLine), '\n')
	appendLogBytes(t, s, auditLogName, long)
	line, err := marshalAuditLine(auditLine{op: "rm", scope: "user/1001", name: "token", result: "ok"}, s.now())
	if err != nil {
		t.Fatal(err)
	}
	appendLogBytes(t, s, auditLogName, line)
	l := s.auditSink.(*fileAuditLog).log
	f, st, err := l.open(unix.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	l.mu.Lock()
	defer l.mu.Unlock()
	state, err := l.sync(f, st)
	if err != nil || state.bad != nil {
		t.Fatalf("an over-long audit line past the cap: %v, bad %v; want it skipped", err, state.bad)
	}
	if state.pastCap[1001] != int64(len(line)) || len(state.pastCap) != 1 || state.off != st.Size {
		t.Fatalf("past the cap %v is charged and reading stopped at %d of %d, want only uid 1001's %d bytes and the end", state.pastCap, state.off, st.Size, len(line))
	}
}

// TestLogReadBoundAuditCarriesPreFrameBudget: the audit log's reader bound
// is the floor's raised by PreFrameBudget, so the pre-frame refusal lines,
// excluded from the hard-cap test, do not spend logBoundMargin; the server's
// append surface and the read-only bounds check apply it.
func TestLogReadBoundAuditCarriesPreFrameBudget(t *testing.T) {
	s, auditPath := newServerLogsStore(t)
	if got, want := s.readBoundOf(auditLogName), s.logReadBound()+PreFrameBudget; got != want {
		t.Fatalf("the audit log's bound is %d, want %d", got, want)
	}
	if got := s.readBoundOf(userFloorLogName); got != s.logReadBound() {
		t.Fatalf("the floor's bound is %d, want %d", got, s.logReadBound())
	}
	// An audit log past the floor's bound but within its own is read; one
	// past its own is refused.
	s.logHardCap, s.logSoftCap, s.logRevokeBudget = 1<<10, 1<<10, minLogRevokeBudget
	line := []byte(`{"v":1}` + "\n")
	fill := func(n int64) {
		t.Helper()
		b := bytes.Repeat(line, int(n)/len(line))
		if err := os.WriteFile(auditPath, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fill(s.logReadBound() + PreFrameBudget/2)
	if _, _, err := s.CheckServerLogs(t.Context()); err != nil {
		t.Fatalf("an audit log within its bound: %v", err)
	}
	fill(s.readBoundOf(auditLogName) + int64(2*len(line)))
	if _, _, err := s.CheckServerLogs(t.Context()); !errors.Is(err, errLogTooLarge) {
		t.Fatalf("an audit log past its bound: %v, want errLogTooLarge", err)
	}
}
