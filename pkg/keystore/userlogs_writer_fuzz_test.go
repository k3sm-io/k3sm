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
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// writerFuzzLog reads one log from scratch, as a new process would, and
// returns its state and verdict.
func writerFuzzFresh(t *testing.T, s *FileStore, floor bool, maxKeys int) *logState {
	t.Helper()
	var l *appendLog
	if floor {
		l = newFileFloorLog(s).log
	} else {
		l = newFileAuditLog(s).log
	}
	l.maxKeys = maxKeys
	return writerFuzzSync(t, l)
}

// writerFuzzSync syncs l on its file and returns the state.
func writerFuzzSync(t *testing.T, l *appendLog) *logState {
	t.Helper()
	f, st, err := l.open(unix.O_RDONLY)
	if err != nil {
		t.Fatalf("open %s: %v", l.name, err)
	}
	defer func() { _ = f.Close() }() // read-only
	l.mu.Lock()
	defer l.mu.Unlock()
	state, err := l.sync(f, st)
	if err != nil {
		t.Fatalf("sync %s: %v", l.name, err)
	}
	return state
}

// rewriteLog replaces name's bytes with b: in place (same inode) or through
// a new file renamed over it (a new inode), as a root maintenance verb
// would.
func rewriteLog(t *testing.T, s *FileStore, name string, b []byte, newInode bool) {
	t.Helper()
	p := filepath.Join(s.dataRoot, name)
	if newInode {
		tmp := p + ".new"
		if err := os.WriteFile(tmp, b, logMode); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, p); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := os.WriteFile(p, b, logMode); err != nil {
		t.Fatal(err)
	}
}

// FuzzLogWriter drives the writer, appendLine through the floor's append
// and bury, the audit log's append, and room, under small caps, budget and
// key bound, among simulated crashes (a torn audit tail), and root's
// rewrites on the cached path: a shrink to a line boundary, a new inode,
// and a same-size rewrite in place. After every step a reader from scratch
// must never refuse what the writer produced (no key-bound or size-bound
// damage; a torn tail is skipped damage, which the next append closes with
// a newline of its own), and the writer's cached state must agree with it,
// on its damage count too. The seeds
// are committed under testdata/fuzz/FuzzLogWriter.
func FuzzLogWriter(f *testing.F) {
	f.Add([]byte("\x02\x03\x04\x00\x01\x02\x03\x00\x01\x02\x03\x01\x02\x00\x01\x03\x00\x01"))
	f.Add([]byte("\x10\x01\x02\x05\x00\x00\x01\x05\x01\x01\x01\x06\x00\x04\x01\x01\x01\x01\x07\x00\x04\x00\x01\x02\x09"))
	f.Fuzz(func(t *testing.T, data []byte) {
		d := &diffInput{data}
		uid := uint32(os.Getuid())
		s := &FileStore{dataRoot: t.TempDir(), uid: uid, floorUID: int(uid), logFlags: flagged, now: func() time.Time { return time.Unix(0, 0) },
			logHardCap: int64(64 + 32*d.next()), logRevokeBudget: int64(1 + 64*d.next())}
		s.logSoftCap = s.logHardCap
		maxKeys := 1 + d.next()%8
		for _, n := range []string{userFloorLogName, auditLogName} {
			if err := os.WriteFile(filepath.Join(s.dataRoot, n), nil, logMode); err != nil {
				t.Fatal(err)
			}
		}
		fl, al := newFileFloorLog(s), newFileAuditLog(s)
		fl.log.maxKeys, al.log.maxKeys = maxKeys, maxKeys
		names := []string{"k0", "k1", "k2", "k3", deliveriesFloorName}
		for step := 0; len(d.b) > 0; step++ {
			op := d.next() % 10
			scope := fmt.Sprintf("user/%d", 1001+d.next()%2)
			name := names[d.next()%len(names)]
			gen := guid(byte(d.next() % 3))
			switch op {
			case 0, 1:
				_ = fl.append(scope, name, gen, uint64(1+d.next()%9), d.next()%2 == 0)
			case 2:
				if name == deliveriesFloorName {
					break
				}
				if d.next()%4 != 0 {
					_ = fl.bury(scope, name, gen)
					break
				}
				writerFuzzTornBurial(t, s, fl, maxKeys, scope, name)
			case 3:
				_ = al.append(auditLine{op: "rm", scope: scope, name: name, result: "ok", revoke: d.next()%2 == 0})
			case 4:
				revoke := d.next()%2 == 0
				if fl.log.room(scopeUID(scope), revoke) == nil && !revoke {
					// Admitted: a grant's new key must be written.
					if err := fl.append(scope, fmt.Sprintf("g%d", step), gen, 1, false); err != nil && s.logHardCap > int64(len(readLog(t, s, userFloorLogName))) {
						t.Fatalf("step %d: a grant admitted by room was refused its key: %v", step, err)
					}
				}
			case 5:
				// A crash mid-write: a torn audit tail, which the next audit
				// append closes.
				appendLogBytes(t, s, auditLogName, []byte(`{"v":1,"op":"put","sc`)[:1+d.next()%20])
			case 6, 7:
				// A shrink to a line boundary, in place or as a new inode.
				lg := []string{userFloorLogName, auditLogName}[d.next()%2]
				b := readLog(t, s, lg)
				cut := bytes.LastIndexByte(b[:len(b)*d.next()/256], '\n') + 1
				rewriteLog(t, s, lg, b[:cut], op == 7)
			case 8, 9:
				// A same-size rewrite of the floor: one live line's seq digit
				// changed, in place or as a new inode.
				b := readLog(t, s, userFloorLogName)
				if i := bytes.LastIndex(b, []byte(" ")); i > 0 && i+2 < len(b) && b[i+1] >= '1' && b[i+1] <= '9' && b[i+2] == '\n' {
					b = append([]byte(nil), b...)
					b[i+1] = byte('1' + d.next()%9)
					rewriteLog(t, s, userFloorLogName, b, op == 9)
				}
			}
			for _, lg := range []struct {
				floor bool
				l     *appendLog
			}{{true, fl.log}, {false, al.log}} {
				want := writerFuzzFresh(t, s, lg.floor, maxKeys)
				where := fmt.Sprintf("step %d op %d, %s", step, op, lg.l.name)
				if want.bad != nil {
					t.Fatalf("%s: a reader from scratch refuses what the writer wrote: %v", where, want.bad)
				}
				got := writerFuzzSync(t, lg.l)
				if diffClass(got.bad) != diffClass(want.bad) || got.off != want.off || got.keys != want.keys || got.damaged() != want.damaged() {
					t.Fatalf("%s: cached verdict %v at %d with %d keys, from scratch %v at %d with %d", where, got.bad, got.off, got.keys, want.bad, want.off, want.keys)
				}
				if !maps.Equal(got.maxSeq, want.maxSeq) || !maps.Equal(got.buried, want.buried) || !maps.Equal(got.pastCap, want.pastCap) {
					t.Fatalf("%s: cached state differs from a reading from scratch", where)
				}
				if lg.floor && want.keys > maxKeys {
					t.Fatalf("%s: %d keys past the bound %d", where, want.keys, maxKeys)
				}
				for u, n := range want.pastCap {
					if n > s.logRevokeBudget {
						t.Fatalf("%s: uid %d charged %d bytes past the hard cap, over its revocation budget %d", where, u, n, s.logRevokeBudget)
					}
				}
			}
		}
	})
}

// writerFuzzTornBurial tears a three-tombstone burial for (scope, name) at
// every byte, cut 0 to its whole length, over the floor as it stands: at
// each cut the writer's cached reading agrees with one from scratch, and a
// cut inside a tombstone that reaches into the scope's digits leaves that
// tombstone's key tainted or buried. The floor is put back as it was.
func writerFuzzTornBurial(t *testing.T, s *FileStore, fl *fileFloorLog, maxKeys int, scope, name string) {
	t.Helper()
	base := readLog(t, s, userFloorLogName)
	burial := []byte{'\n'}
	var starts []int
	for g := range 3 {
		line, err := tombLine(scope, name, guid(byte(g)))
		if err != nil {
			t.Fatal(err)
		}
		starts = append(starts, len(burial))
		burial = append(burial, line...)
	}
	for cut := 0; cut <= len(burial); cut++ {
		b := append(append([]byte(nil), base...), burial[:cut]...)
		rewriteLog(t, s, userFloorLogName, b, false)
		want := writerFuzzFresh(t, s, true, maxKeys)
		got := writerFuzzSync(t, fl.log)
		where := fmt.Sprintf("torn burial of %s %s at %d", scope, name, cut)
		if want.bad != nil || got.bad != nil {
			// Foreign tombstones past the key bound, which the writer never
			// writes: only the verdict's class is the same.
			if diffClass(got.bad) != diffClass(want.bad) {
				t.Fatalf("%s: cached verdict %v, from scratch %v", where, got.bad, want.bad)
			}
			continue
		}
		if diffClass(got.bad) != diffClass(want.bad) || got.off != want.off || got.keys != want.keys || got.damaged() != want.damaged() {
			t.Fatalf("%s: cached verdict %v at %d with %d keys and %d damaged, from scratch %v at %d with %d and %d", where, got.bad, got.off, got.keys, got.damaged(), want.bad, want.off, want.keys, want.damaged())
		}
		if !maps.Equal(got.maxSeq, want.maxSeq) || !maps.Equal(got.buried, want.buried) || !maps.Equal(got.pastCap, want.pastCap) {
			t.Fatalf("%s: cached state differs from a reading from scratch", where)
		}
		if len(want.taintNames)+len(want.taintGens)+len(want.taintPrefixes) >= maxTaintKeys {
			continue
		}
		for i, at := range starts {
			end := len(burial)
			if i+1 < len(starts) {
				end = starts[i+1]
			}
			if cut-at < len("user/1") || cut >= end {
				continue
			}
			k := floorKey{scope, name, guid(byte(i))}
			if !want.tainted(k) && !want.buried[k] {
				t.Fatalf("%s: tombstone %d torn at %d bytes leaves %+v neither tainted nor buried", where, i, cut-at, k)
			}
		}
	}
	rewriteLog(t, s, userFloorLogName, base, false)
}
