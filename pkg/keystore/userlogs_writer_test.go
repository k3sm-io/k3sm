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
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// freshFloorVerdict reads the floor from scratch, as a new process would,
// under the same caps and key bound, and returns its verdict.
func freshFloorVerdict(t *testing.T, s *FileStore, maxKeys int) error {
	t.Helper()
	l := newFileFloorLog(s)
	l.log.maxKeys = maxKeys
	return l.check()
}

// U24: ordinary put and rm churn up to the floor's key bound never makes
// the floor damage. A grant past the bound is refused with ErrLogFull
// naming floor --rebuild and audit --rotate, before anything is written; a
// revocation of a key the floor holds (rm's tombstone, a withdraw's floor
// line) still goes through; and a reader from scratch never refuses the
// floor the writer produced.
func TestFloorKeyBoundChurnRefusesGrants(t *testing.T) {
	ctx := context.Background()
	const bound = 6
	s, server, u := fileLogScope(t)
	if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
		t.Fatal(err)
	}
	s.userFloor.(*fileFloorLog).log.maxKeys = bound
	var refused error
	for i := range 3 * bound {
		name := fmt.Sprintf("user/1001/k%d", i)
		_, err := u.Put(ctx, name, KindOpaque, []byte("v"))
		if err != nil {
			refused = err
			break
		}
		if err := u.Delete(ctx, name); err != nil {
			t.Fatalf("rm %s: %v", name, err)
		}
		if err := freshFloorVerdict(t, s, bound); err != nil {
			t.Fatalf("after churn %d the floor reads as damage: %v", i, err)
		}
	}
	if !errors.Is(refused, ErrLogFull) {
		t.Fatalf("a grant past the key bound: %v, want ErrLogFull", refused)
	}
	for _, want := range []string{"sudo k3sm doctor", "floor --rebuild", "key bound"} {
		if !strings.Contains(refused.Error(), want) {
			t.Fatalf("refusal %q does not say %q", refused, want)
		}
	}
	// The refused grant wrote nothing: no entry, no floor line.
	floorBefore := readLog(t, s, userFloorLogName)
	snap := treeSnapshot(t, server)
	if _, err := u.Put(ctx, "user/1001/another", KindOpaque, []byte("v")); !errors.Is(err, ErrLogFull) {
		t.Fatalf("a second grant past the key bound: %v, want ErrLogFull", err)
	}
	checkTreeUnchanged(t, snap, treeSnapshot(t, server))
	if !bytes.Equal(floorBefore, readLog(t, s, userFloorLogName)) {
		t.Fatal("a refused grant appended to the floor")
	}
	if err := u.addDelivery(ctx, testDelivery(2)); !errors.Is(err, ErrLogFull) {
		t.Fatalf("deliver past the key bound: %v, want ErrLogFull", err)
	}
	// Revocations of keys the floor holds go through, whole.
	if err := u.withdrawDelivery(ctx, testDelivery(1).uid); err != nil {
		t.Fatalf("withdraw past the key bound: %v", err)
	}
	if err := u.Delete(ctx, "user/1001/token"); err != nil {
		t.Fatalf("rm of a key the floor holds, past the key bound: %v", err)
	}
	if err := freshFloorVerdict(t, s, bound); err != nil {
		t.Fatalf("the floor reads as damage after the revocations: %v", err)
	}
}

// The writer never adds a key past the bound itself: a tombstone for a
// generation the floor does not hold is a new key, refused with ErrLogFull
// once the floor is at its bound, and the floor still reads.
func TestFloorWriterRefusesKeyPastBound(t *testing.T) {
	s, _, _ := fileLogScope(t)
	fl := s.userFloor.(*fileFloorLog)
	fl.log.maxKeys = 4
	var err error
	for i := range 8 {
		if err = fl.bury("user/1001", fmt.Sprintf("n%d", i), guid(byte(i))); err != nil {
			break
		}
	}
	if !errors.Is(err, ErrLogFull) {
		t.Fatalf("a new key past the bound: %v, want ErrLogFull", err)
	}
	if err := freshFloorVerdict(t, s, 4); err != nil {
		t.Fatalf("the writer made the floor damage: %v", err)
	}
	// A line for a key the floor holds still goes through.
	if err := fl.append("user/1001", "token", entryGenerationOf(t, s), 1, false); err != nil {
		t.Fatalf("a line for a held key at the bound: %v", err)
	}
}

// entryGenerationOf returns token's generation as the floor holds it.
func entryGenerationOf(t *testing.T, s *FileStore) [generationSize]byte {
	t.Helper()
	var gen [generationSize]byte
	if err := s.userFloor.(*fileFloorLog).read(func(st *logState) {
		for k := range st.maxSeq {
			if k.name == "token" {
				gen = k.gen
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	return gen
}

// The key bound is the read bound over the shortest line that adds a key
// (55 bytes, its checksum included), held to a ceiling of 1<<18 keys, which is met first at the
// default caps and bounds the reader's memory.
func TestFloorKeyBoundDerivedFromCaps(t *testing.T) {
	s, _, _ := fileLogScope(t)
	line, err := floorLine(userScopeOf(minScopeUID), "a", [generationSize]byte{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(line) != 55 {
		t.Fatalf("the shortest floor line is %d bytes, want 55", len(line))
	}
	l := s.userFloor.(*fileFloorLog).log
	// At the default caps the size would allow about 18.3M keys; the ceiling
	// of 1<<18, which bounds the reader's memory, is met first.
	if got := l.keyBound(); got != 1<<18 {
		t.Fatalf("key bound %d at the default caps, want the ceiling %d", got, 1<<18)
	}
	// Under small caps the size-derived bound is met first.
	s.logHardCap, s.logSoftCap, s.logRevokeBudget, s.logAllowance = 1<<20, 1<<20, maxLogLine, maxLogLine
	if got, want := l.keyBound(), int(s.logReadBound()/55+1); got != want || want >= 1<<18 {
		t.Fatalf("key bound %d under 1 MiB caps, want the size-derived %d", got, want)
	}
}

// A withdraw of an already withdrawn delivery whose floor already holds
// the record's sequence appends nothing to the floor.
func TestWithdrawRepeatAppendsNoFloorLine(t *testing.T) {
	ctx := context.Background()
	s, _, u := fileLogScope(t)
	if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
		t.Fatal(err)
	}
	if err := u.withdrawDelivery(ctx, testDelivery(1).uid); err != nil {
		t.Fatal(err)
	}
	before := readLog(t, s, userFloorLogName)
	if err := u.withdrawDelivery(ctx, testDelivery(1).uid); err != nil {
		t.Fatalf("repeat withdraw: %v", err)
	}
	if after := readLog(t, s, userFloorLogName); !bytes.Equal(before, after) {
		t.Fatalf("a no-op withdraw appended %q to the floor", after[len(before):])
	}
}

// U20: a withdraw over a floor it cannot verify never re-seals a record put
// back from a backup. With a delivery withdrawn after the backup, the backup
// restored, the floor's flag clear and the process's own mark gone (a
// restart), a withdraw is refused with errWithdrawUnsealed and the record
// on disk is the restored bytes; once the floor is flagged again, the copy
// stays refused below it, so the delivery withdrawn after the backup never
// reads as live.
func TestWithdrawUnverifiedFloorSealsNothing(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	for _, n := range []int{1, 2} {
		if err := u.addDelivery(ctx, testDelivery(n)); err != nil {
			t.Fatal(err)
		}
	}
	backup := readDeliveriesBytes(t, server)
	if err := u.withdrawDelivery(ctx, testDelivery(1).uid); err != nil {
		t.Fatal(err)
	}
	putBackDeliveries(t, server, backup)
	s.logFlags = func(*os.File) (uint32, error) { return 0, nil }
	deliveriesSeen.mu.Lock()
	delete(deliveriesSeen.m, deliverySeqKey(s.dir, "user/1001", guid(0xA1)))
	deliveriesSeen.mu.Unlock()
	for _, n := range []int{2, 1} {
		err := u.withdrawDelivery(ctx, testDelivery(n).uid)
		if !errors.Is(err, errWithdrawUnsealed) || errors.Is(err, errCommitted) {
			t.Fatalf("withdraw %d over an unflagged floor and a restored record: %v, want errWithdrawUnsealed", n, err)
		}
		if !bytes.Equal(backup, readDeliveriesBytes(t, server)) {
			t.Fatalf("withdraw %d re-sealed the restored record", n)
		}
	}
	s.logFlags = flagged
	if d, err := u.lookupDelivery(ctx, testDelivery(1).uid); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("the delivery withdrawn after the backup reads as %+v, %v; want the restored copy refused (ErrCorrupt)", d, err)
	}
}

// U20: an rm over a floor whose last line has no newline buries and
// removes: its burial writes a newline first, so the torn bytes are a line
// of their own, which the reader skips as damage, and the tombstone reads
// back whole. The next read is served, and a grant of a name the torn
// line's partial name does not cover.
func TestRmOverTornFloorTailBuries(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	userPut(t, u, "user/1001/keep", "kept")
	torn := []byte("user/1001 tok")
	appendLogBytes(t, s, userFloorLogName, torn)
	before := readLog(t, s, userFloorLogName)
	tokenDir := filepath.Join(scopeDir(server, "1001"), scopeEntriesName, "token")
	gen := entryGeneration(t, server, "token")
	if err := u.Delete(ctx, "user/1001/token"); err != nil {
		t.Fatalf("rm over a torn floor tail: %v, want it to bury and remove", err)
	}
	if _, err := os.Lstat(tokenDir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the entry's tree after rm: %v, want it removed", err)
	}
	tomb, err := tombLine("user/1001", "token", gen)
	if err != nil {
		t.Fatal(err)
	}
	after := readLog(t, s, userFloorLogName)
	if !bytes.HasPrefix(after, before) || !bytes.HasPrefix(after[len(before):], append([]byte{'\n'}, tomb...)) {
		t.Fatalf("rm over a torn tail appended %q, want a newline and then the tombstone", after[len(before):])
	}
	if _, err := s.userFloor.floor("user/1001", "token", gen); !errors.Is(err, errFloorBuried) {
		t.Fatalf("the floor after rm over a torn tail: %v, want the generation buried", err)
	}
	if _, _, err := u.Current(ctx, "user/1001/keep"); err != nil {
		t.Fatalf("the next read over the closed torn line: %v", err)
	}
	// The torn line is a tear inside its name: it taints the names that
	// start with "tok", and no other.
	if _, err := u.Put(ctx, "user/1001/token", KindOpaque, []byte("v")); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("a grant of a name the closed torn line's prefix covers: %v, want errFloorDegraded", err)
	}
	if _, err := u.Put(ctx, "user/1001/other", KindOpaque, []byte("v")); err != nil {
		t.Fatalf("a grant of a name the closed torn line's prefix does not cover: %v", err)
	}
	if n := floorDamage(t, s); n != 1 {
		t.Fatalf("%d damaged lines, want 1", n)
	}
}

// U23: a grant over an audit log whose last line has no newline records a
// whole, parseable ok line: the append writes a newline first, so the torn
// bytes are a line of their own, which the tolerant reader drops. Past the
// hard cap the same holds for a revocation, and the reader charges its line
// and reports no damage.
func TestAuditTornTailAppendParses(t *testing.T) {
	ctx := context.Background()
	lastLine := func(t *testing.T, s *FileStore) auditRecord {
		t.Helper()
		lines := bytes.Split(bytes.TrimSuffix(readLog(t, s, auditLogName), []byte("\n")), []byte("\n"))
		r, err := parseAuditLine(lines[len(lines)-1])
		if err != nil {
			t.Fatalf("the last audit line %q does not parse: %v", lines[len(lines)-1], err)
		}
		return r
	}
	t.Run("a grant", func(t *testing.T) {
		s, _, u := fileLogScope(t)
		appendLogBytes(t, s, auditLogName, []byte(`{"v":1,"op":"pu`))
		if _, err := u.Put(ctx, "user/1001/other", KindOpaque, []byte("v")); err != nil {
			t.Fatalf("put over a torn audit tail: %v", err)
		}
		if r := lastLine(t, s); r.Op != "put" || r.Result != "ok" || r.Name != "other" {
			t.Fatalf("the last audit line is %+v, want put other ok", r)
		}
	})
	t.Run("a revocation past the hard cap", func(t *testing.T) {
		s, _, u := fileLogScope(t)
		s.logSoftCap, s.logHardCap = 1, 1
		appendLogBytes(t, s, auditLogName, []byte(`{"v":1,"op":"rm","scope":"user/1001"`))
		if err := u.Delete(ctx, "user/1001/token"); err != nil {
			t.Fatalf("rm over a torn audit tail past the hard cap: %v", err)
		}
		if r := lastLine(t, s); r.Op != "rm" || r.Result != "ok" {
			t.Fatalf("the last audit line is %+v, want rm ok", r)
		}
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
		if state.pastCap[1001] == 0 {
			t.Fatal("the rm line past the hard cap was not charged to uid 1001")
		}
	})
}

// BenchmarkFloorReadAtKeyBound reads, from scratch, a floor holding exactly
// the key bound's distinct keys at the default caps, and reports the heap
// the read state holds and the time one read takes: the reader's cost at
// the bound the writer never passes (docs/design/keystore.md § "Size caps").
func BenchmarkFloorReadAtKeyBound(b *testing.B) {
	s := &FileStore{logHardCap: defaultLogHardCap, logSoftCap: defaultLogSoftCap, logRevokeBudget: defaultLogRevocationBytes}
	l := newFileFloorLog(s).log
	keys := l.keyBound()
	p := filepath.Join(b.TempDir(), userFloorLogName)
	w, err := os.Create(p)
	if err != nil {
		b.Fatal(err)
	}
	bw := bufio.NewWriterSize(w, 1<<20)
	for i := range keys {
		line, err := floorLine(fmt.Sprintf("user/%d", 501+i%1000), fmt.Sprintf("k%d", i), guid(byte(i)), 1)
		if err != nil {
			b.Fatal(err)
		}
		_, _ = bw.Write(line)
	}
	if err := bw.Flush(); err != nil {
		b.Fatal(err)
	}
	if err := w.Close(); err != nil {
		b.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		b.Fatal(err)
	}
	var (
		heap uint64
		read time.Duration
	)
	b.ResetTimer()
	for b.Loop() {
		l.state = logState{}
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		start := time.Now()
		state, err := l.sync(f, st)
		read = time.Since(start)
		if err != nil || state.bad != nil || state.keys != keys {
			b.Fatalf("read the floor at its key bound: %v, %v, %d keys of %d", err, state.bad, state.keys, keys)
		}
		runtime.GC()
		runtime.ReadMemStats(&after)
		heap = after.HeapAlloc - before.HeapAlloc
		runtime.KeepAlive(state)
	}
	b.ReportMetric(float64(heap)/(1<<20), "MiB-heap")
	b.ReportMetric(read.Seconds(), "s-read")
	b.ReportMetric(float64(st.Size)/(1<<20), "MiB-file")
	b.ReportMetric(float64(keys), "keys")
}
