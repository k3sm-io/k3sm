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
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// syncedFloorState reads s's floor and returns a copy of its state's
// figures this test reads.
func syncedFloorState(t *testing.T, s *FileStore) (tornSize int64, taintedName bool, live bool, k floorKey) {
	t.Helper()
	l := s.userFloor.(*fileFloorLog).log
	if err := s.userFloor.check(); err != nil {
		t.Fatalf("floor check: %v", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	k = floorKey{"user/1001", "token", guid(0x77)}
	_, live = l.state.maxSeq[k]
	return l.state.tornSize, l.state.taintNames[nameKey{k.scope, k.name}], live, k
}

// auditDamage reads s's audit log from scratch, as a fresh reader does,
// and returns its torn tail and damaged line count.
func auditDamage(t *testing.T, s *FileStore) (tornSize int64, damaged int) {
	t.Helper()
	l := newFileAuditLog(s).log
	f, st, err := l.open(unix.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	l.mu.Lock()
	defer l.mu.Unlock()
	state, err := l.sync(f, st)
	if err != nil || state.bad != nil {
		t.Fatalf("a fresh reader of the audit log: %v, %v", err, state.bad)
	}
	return state.tornSize, state.damaged()
}

// tearFloor appends, after a newline, the first bytes of a whole floor line
// for user/1001 token, cut inside its generation, and returns the line and
// the cut.
func tearFloor(t *testing.T, s *FileStore) (whole []byte, cut int) {
	t.Helper()
	whole, err := floorLine("user/1001", "token", guid(0x77), 2)
	if err != nil {
		t.Fatal(err)
	}
	cut = len("user/1001 token ") + 5 // inside the generation
	appendLogBytes(t, s, userFloorLogName, append([]byte{'\n'}, whole[:cut]...))
	return whole, cut
}

// tearAudit puts the caps at 1, so the audit reader reads every line past
// the first, and appends, after a newline, the first bytes of a whole rm
// audit line for user/1001, cut inside its JSON object; it returns the line
// and the cut.
func tearAudit(t *testing.T, s *FileStore) (whole []byte, cut int) {
	t.Helper()
	s.logSoftCap, s.logHardCap = 1, 1
	whole, err := marshalAuditLine(auditLine{op: "rm", scope: "user/1001", name: "token", result: "ok", revoke: true}, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	cut = len(whole) / 2
	appendLogBytes(t, s, auditLogName, append([]byte{'\n'}, whole[:cut]...))
	return whole, cut
}

// startSealed restarts s's store and runs the start step, which seals the
// torn tail of name, and checks the log grew by exactly that newline after
// the fragment frag.
func startSealed(t *testing.T, s *FileStore, name string, frag []byte) *FileStore {
	t.Helper()
	sizeTorn := len(readLog(t, s, name))
	s2 := reopenStore(t, s)
	if err := s2.startUserScopes(context.Background()); err != nil {
		t.Fatalf("start over a torn %s: %v", name, err)
	}
	got := readLog(t, s2, name)
	if len(got) != sizeTorn+1 || got[len(got)-1] != '\n' || !bytes.HasSuffix(got[:len(got)-1], frag) {
		t.Fatalf("%s after the start step ends %q; want the fragment %q sealed with one newline", name, got[max(0, len(got)-40):], frag)
	}
	return s2
}

// The start step seals a floor torn mid-line: under the exclusive lock it
// appends the newline the torn tail lacks, so the fragment is a closed
// damaged line, read through taintLine (a name taint, not a torn tail).
func TestStartSealsTornFloorTail(t *testing.T) {
	s, _, _ := fileLogScope(t)
	whole, cut := tearFloor(t, s)
	s2 := startSealed(t, s, userFloorLogName, whole[:cut])
	torn, tainted, live, k := syncedFloorState(t, s2)
	if torn != 0 || !tainted || live {
		t.Fatalf("the sealed fragment: torn tail %d, name taint %v, %+v live %v; want no torn tail, the fragment's name taint through taintLine, and no line parsed", torn, tainted, k, live)
	}
	if d := s2.userFloor.(*fileFloorLog).log.state.damaged(); d != 1 {
		t.Fatalf("the floor's damage after the seal is %d, want 1: the closed fragment", d)
	}
}

// The start step seals the audit log's torn tail too: one newline, and the
// fragment is a closed damaged line, not a torn tail.
func TestStartSealsTornAuditTail(t *testing.T) {
	s, _, _ := fileLogScope(t)
	whole, cut := tearAudit(t, s)
	s2 := startSealed(t, s, auditLogName, whole[:cut])
	if torn, d := auditDamage(t, s2); torn != 0 || d != 1 {
		t.Fatalf("the sealed audit fragment: torn tail %d, damage %d; want no torn tail and damage 1", torn, d)
	}
}

// A sealed tail, one that already ends in a newline, is left as it is.
func TestStartSealLeavesSealedTail(t *testing.T) {
	s, _, _ := fileLogScope(t)
	floor, audit := readLog(t, s, userFloorLogName), readLog(t, s, auditLogName)
	s2 := reopenStore(t, s)
	if err := s2.startUserScopes(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readLog(t, s2, userFloorLogName), floor) || !bytes.Equal(readLog(t, s2, auditLogName), audit) {
		t.Fatal("the start step wrote to a log whose tail was already sealed")
	}
}

// A tail torn only at its newline is a whole line: the start step leaves
// it as it is, since its newline would make it parse, and the seal never
// makes a torn line parse.
func TestStartSealLeavesTailTornAtNewline(t *testing.T) {
	for _, tc := range []struct {
		name string
		log  string
		tear func(*testing.T, *FileStore) ([]byte, int)
	}{{"floor", userFloorLogName, tearFloor}, {"audit", auditLogName, tearAudit}} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _ := fileLogScope(t)
			whole, _ := tc.tear(t, s)
			appendLogBytes(t, s, tc.log, []byte{'\n'})
			appendLogBytes(t, s, tc.log, whole[:len(whole)-1])
			want := readLog(t, s, tc.log)
			s2 := reopenStore(t, s)
			if err := s2.startUserScopes(context.Background()); err != nil {
				t.Fatalf("start over a %s torn at its newline: %v", tc.log, err)
			}
			if got := readLog(t, s2, tc.log); !bytes.Equal(got, want) {
				t.Fatalf("the start step wrote %q to a %s torn only at its newline; want it left as it is", got[len(want):], tc.log)
			}
		})
	}
}

// A tear's frozen fragment lives only in one process's memory, so the
// start step seals it: a foreign writer that appends the fragment's
// completing bytes after a restart starts a line of its own, which does not
// parse, and is counted as damage on the next fresh read; the completed
// line never reads as a valid one.
func TestForeignCompletionAcrossRestartStaysTainted(t *testing.T) {
	ctx := context.Background()
	t.Run("floor", func(t *testing.T) {
		s, _, _ := fileLogScope(t)
		whole, cut := tearFloor(t, s)
		s2 := startSealed(t, s, userFloorLogName, whole[:cut])
		appendLogBytes(t, s2, userFloorLogName, whole[cut:])
		if bytes.Contains(readLog(t, s2, userFloorLogName), whole) {
			t.Fatal("the foreign completion glued to the fragment into the whole line")
		}
		s3 := reopenStore(t, s2)
		if err := s3.startUserScopes(ctx); err != nil {
			t.Fatalf("start after a foreign completion: %v", err)
		}
		torn, tainted, live, k := syncedFloorState(t, s3)
		if live || !tainted || torn != 0 {
			t.Fatalf("after a foreign completion and a restart: %+v live %v, name tainted %v, torn tail %d; want the completion never parsed, the taint kept", k, live, tainted, torn)
		}
		if d := s3.userFloor.(*fileFloorLog).log.state.damaged(); d != 2 {
			t.Fatalf("the floor's damage is %d, want 2: the sealed fragment and the foreign completion", d)
		}
	})
	t.Run("audit", func(t *testing.T) {
		s, _, _ := fileLogScope(t)
		whole, cut := tearAudit(t, s)
		s2 := startSealed(t, s, auditLogName, whole[:cut])
		appendLogBytes(t, s2, auditLogName, whole[cut:])
		if bytes.Contains(readLog(t, s2, auditLogName), whole) {
			t.Fatal("the foreign completion glued to the fragment into the whole line")
		}
		s3 := reopenStore(t, s2)
		if err := s3.startUserScopes(ctx); err != nil {
			t.Fatalf("start after a foreign completion: %v", err)
		}
		for _, line := range bytes.Split(readLog(t, s3, auditLogName), []byte{'\n'}) {
			if r, err := parseAuditLine(line); err == nil && r.Op == "rm" {
				t.Fatalf("an rm audit line %q parses after a foreign completion", line)
			}
		}
		if torn, d := auditDamage(t, s3); torn != 0 || d != 2 {
			t.Fatalf("the audit log after a foreign completion: torn tail %d, damage %d; want no torn tail and damage 2", torn, d)
		}
	})
}
