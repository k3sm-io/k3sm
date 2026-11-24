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
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// diffInput is a cursor over the fuzz input: each next is one byte, 0
// once the input is spent.
type diffInput struct{ b []byte }

func (d *diffInput) next() int {
	if len(d.b) == 0 {
		return 0
	}
	c := d.b[0]
	d.b = d.b[1:]
	return int(c)
}

// diffItem is one append: the floor's and the audit log's rendering of the
// same operation.
type diffItem struct{ floor, audit []byte }

// diffStream decodes d into batches of appends: live floor lines, rm
// tombstones (some naming the delivery record, which a tombstone may not),
// lines that do not parse, overlong lines, torn lines with no newline, and
// long lines that straddle the small hard cap.
func diffStream(d *diffInput) [][]diffItem {
	names := []string{"k0", "k1", "k2", "k3", deliveriesFloorName}
	var (
		out   [][]diffItem
		batch []diffItem
	)
	for len(d.b) > 0 {
		op := d.next() % 8
		uid := 1001 + d.next()%3
		scope := fmt.Sprintf("user/%d", uid)
		name := names[d.next()%len(names)]
		gen := guid(byte(d.next() % 3))
		live := appendFloorCRC(fmt.Appendf(nil, "%s %s %x %d", scope, name, gen[:], d.next()))
		live = append(live, '\n')
		audit := func(op string, pad int) []byte {
			return fmt.Appendf(nil, `{"v":1,"op":%q,"scope":%q,"name":%q,"pad":%q,"result":"ok"}`+"\n", op, scope, name, bytes.Repeat([]byte("p"), pad))
		}
		var it diffItem
		switch op {
		case 0, 1:
			it = diffItem{live, audit("put", 0)}
		case 2:
			it = diffItem{append(appendFloorCRC(fmt.Appendf(nil, "%s %s %x rm", scope, name, gen[:])), '\n'), audit("rm", 0)}
		case 3:
			n := d.next() % 40
			g := bytes.ReplaceAll(append([]byte(nil), d.b[:min(len(d.b), n)]...), []byte("\n"), []byte(" "))
			g = append(g, '\n')
			it = diffItem{g, g}
		case 4:
			long := append(bytes.Repeat([]byte("y"), maxLogLine+d.next()%64), '\n')
			it = diffItem{long, long}
		case 5:
			n := d.next()
			it = diffItem{live[:min(n, len(live)-1)], audit("put", 0)[:min(n, 60)]}
		case 6:
			// A long audit line, so one straddles the cap; for the floor a
			// live line, which straddles it as often as its offset says.
			it = diffItem{live, audit("put", 3*d.next())}
		case 7:
			out, batch = append(out, batch), nil
			continue
		}
		batch = append(batch, it)
	}
	return append(out, batch)
}

// diffLog is one log read from an in-memory file through the readAt seam.
type diffLog struct {
	l   *appendLog
	buf *[]byte
}

func newDiffLog(s *FileStore, floor bool, maxKeys int, buf *[]byte) diffLog {
	var l *appendLog
	if floor {
		l = newFileFloorLog(s).log
	} else {
		l = newFileAuditLog(s).log
	}
	l.maxKeys = maxKeys
	l.readAt = func(*os.File) io.ReaderAt { return bytes.NewReader(*buf) }
	return diffLog{l, buf}
}

func (d diffLog) sync(t *testing.T) *logState {
	t.Helper()
	d.l.mu.Lock()
	defer d.l.mu.Unlock()
	state, err := d.l.sync(nil, unix.Stat_t{Dev: 1, Ino: 1, Size: int64(len(*d.buf))})
	if err != nil {
		t.Fatalf("sync of an in-memory log: %v", err)
	}
	return state
}

// syncSeeded reads buf from scratch, seeded with the torn fragments an
// incremental reader froze (logState.frozen): a reader from scratch cannot
// know where a torn tail ended before a foreign append grew it, so it is
// told, and must then agree on everything else.
func syncSeeded(t *testing.T, s *FileStore, whole bool, maxKeys int, buf *[]byte, frozen map[int64][]byte) *logState {
	t.Helper()
	var empty []byte
	d := newDiffLog(s, whole, maxKeys, &empty)
	d.sync(t)
	d.l.state.frozen = maps.Clone(frozen)
	d.buf = buf
	d.l.readAt = func(*os.File) io.ReaderAt { return bytes.NewReader(*buf) }
	return d.sync(t)
}

// stripOffsets maps frozen offsets in b to those in stripEmptyLines(b).
func stripOffsets(b []byte, frozen map[int64][]byte) map[int64][]byte {
	out := map[int64][]byte{}
	for off, frag := range frozen {
		n := int64(0)
		for i := int64(0); i < off && i < int64(len(b)); i++ {
			if b[i] == '\n' && (i == 0 || b[i-1] == '\n') {
				n++
			}
		}
		out[off-n] = frag
	}
	return out
}

// diffClass names the kind of a bad verdict.
func diffClass(err error) string {
	for _, c := range []struct {
		err  error
		name string
	}{{errLogTorn, "torn"}, {errLogLineTooLong, "long"}, {errFloorTooManyKeys, "keys"}, {errLogTooLarge, "size"}} {
		if errors.Is(err, c.err) {
			return c.name
		}
	}
	if err != nil {
		return "parse"
	}
	return ""
}

// stripEmptyLines is b without its empty lines: a newline at its start or
// after another newline.
func stripEmptyLines(b []byte) []byte {
	var out []byte
	for i, c := range b {
		if c == '\n' && (i == 0 || b[i-1] == '\n') {
			continue
		}
		out = append(out, c)
	}
	return out
}

// FuzzLogSyncDifferential checks the incremental reader against a reading
// from scratch: after every batch of appends, sync of a log read on from
// where it stopped must agree with sync of the same bytes by a reader that
// has read nothing, on the floor's highest seqs, tombstones, key count,
// damage count and verdict, and on both logs' past-cap charges per uid and
// the revocation room they leave, under small caps, budget and key bound.
// Garbage, over-long and torn lines are skipped as damage, so the readers
// are compared on the lines after them too; a torn tail is frozen where it
// was first read, so the reader from scratch is seeded with the fragments
// the incremental one froze before the batch; an empty line (an append's
// leading newline) is benign, so the floor read without its empty lines
// must agree on keys, damage, seqs and tombstones. The seeds are committed under
// testdata/fuzz/FuzzLogSyncDifferential.
func FuzzLogSyncDifferential(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		d := &diffInput{data}
		s := &FileStore{logHardCap: int64(1 + 4*d.next()), logRevokeBudget: int64(1 + 8*d.next())}
		s.logSoftCap = s.logHardCap
		maxKeys := 1 + d.next()%8
		var floorBuf, auditBuf []byte
		incFloor, incAudit := newDiffLog(s, true, maxKeys, &floorBuf), newDiffLog(s, false, maxKeys, &auditBuf)
		probe := append([]byte(nil), d.b...)
		defer diffPrefixTaints(t, s, maxKeys, &floorBuf, &diffInput{probe})
		frozen := map[bool]map[int64][]byte{true: {}, false: {}}
		for i, batch := range diffStream(d) {
			for _, it := range batch {
				floorBuf = append(floorBuf, it.floor...)
				auditBuf = append(auditBuf, it.audit...)
			}
			for _, lg := range []struct {
				name string
				inc  diffLog
			}{{"floor", incFloor}, {"audit", incAudit}} {
				hist := frozen[lg.inc.l.floor]
				seed := maps.Clone(hist)
				got := lg.inc.sync(t)
				maps.Copy(hist, got.frozen)
				want := syncSeeded(t, s, lg.inc.l.floor, maxKeys, lg.inc.buf, seed)
				where := fmt.Sprintf("%s after batch %d (%d bytes, hard cap %d)", lg.name, i, len(*lg.inc.buf), s.logHardCap)
				if gc, wc := diffClass(got.bad), diffClass(want.bad); gc != wc {
					t.Fatalf("%s: incremental verdict %q (%v), from scratch %q (%v)", where, gc, got.bad, wc, want.bad)
				}
				if want.bad != nil {
					continue
				}
				if got.off != want.off || got.keys != want.keys || got.damaged() != want.damaged() {
					t.Fatalf("%s: incremental read to %d with %d keys and %d damaged lines, from scratch to %d with %d and %d", where, got.off, got.keys, got.damaged(), want.off, want.keys, want.damaged())
				}
				if !maps.Equal(got.maxSeq, want.maxSeq) || !maps.Equal(got.buried, want.buried) {
					t.Fatalf("%s: incremental seqs %v tombstones %v, from scratch %v %v", where, got.maxSeq, got.buried, want.maxSeq, want.buried)
				}
				if !maps.Equal(got.pastCap, want.pastCap) {
					t.Fatalf("%s: incremental past-cap charges %v, from scratch %v", where, got.pastCap, want.pastCap)
				}
				if !maps.Equal(got.share, want.share) || !maps.Equal(got.allowance, want.allowance) {
					t.Fatalf("%s: incremental share and allowance charges %v %v, from scratch %v %v", where, got.share, got.allowance, want.share, want.allowance)
				}
				if !maps.Equal(got.uidKeys, want.uidKeys) {
					t.Fatalf("%s: incremental per-uid key counts %v, from scratch %v", where, got.uidKeys, want.uidKeys)
				}
				if lg.inc.l.floor {
					// The taint set is deterministic: the incremental reader
					// and one from scratch taint the same keys and mark the
					// same unattributable damage.
					ga, gok := got.unattributedAt()
					wa, wok := want.unattributedAt()
					if !maps.Equal(got.taintNames, want.taintNames) || !maps.Equal(got.taintGens, want.taintGens) || !maps.Equal(got.taintPrefixes, want.taintPrefixes) || ga != wa || gok != wok {
						t.Fatalf("%s: incremental taint %v %v unattributable %v@%d, from scratch %v %v %v@%d", where, got.taintNames, got.taintGens, gok, ga, want.taintNames, want.taintGens, wok, wa)
					}
					for _, k := range diffKeys() {
						if got.tainted(k) != want.tainted(k) {
							t.Fatalf("%s: %+v tainted %v incrementally, %v from scratch", where, k, got.tainted(k), want.tainted(k))
						}
					}
				}
				if lg.inc.l.floor {
					// Empty lines, an append's leading newlines, are benign:
					// the floor without them reads the same.
					bare := stripEmptyLines(*lg.inc.buf)
					strip := syncSeeded(t, s, true, maxKeys, &bare, stripOffsets(*lg.inc.buf, seed))
					if diffClass(strip.bad) != "" {
						continue
					}
					if strip.keys != want.keys || strip.damaged() != want.damaged() || !maps.Equal(strip.maxSeq, want.maxSeq) || !maps.Equal(strip.buried, want.buried) {
						t.Fatalf("%s: empty lines changed the reading: %d keys and %d damaged lines with them, %d and %d without", where, want.keys, want.damaged(), strip.keys, strip.damaged())
					}
				}
				size := int64(len(*lg.inc.buf))
				for uid := uint32(1001); uid <= 1003; uid++ {
					ge, we := lg.inc.l.revokeRoom(got, size, uid, maxLogLine), lg.inc.l.revokeRoom(want, size, uid, maxLogLine)
					if (ge == nil) != (we == nil) {
						t.Fatalf("%s: uid %d revocation room incremental %v, from scratch %v", where, uid, ge, we)
					}
				}
			}
		}
	})
}

// diffKeys is every key diffStream's floor lines can name.
func diffKeys() []floorKey {
	var out []floorKey
	for uid := 1001; uid <= 1003; uid++ {
		for _, name := range []string{"k0", "k1", "k2", "k3", deliveriesFloorName} {
			for g := range 3 {
				out = append(out, floorKey{fmt.Sprintf("user/%d", uid), name, guid(byte(g))})
			}
		}
	}
	return out
}

// diffPrefixTaints checks, after the stream, that a prefix of a valid line
// for a key K, drawn from d, taints K once it reaches into K's scope's
// digits, whether it is the floor's torn last line or a line an append
// closed: by a scope or name prefix while those are partial, as K's name
// while its generation is partial, as K once it is whole. A taint set the
// stream already filled to its cap is not judged: past it, the prefix is
// unattributable.
func diffPrefixTaints(t *testing.T, s *FileStore, maxKeys int, buf *[]byte, d *diffInput) {
	t.Helper()
	if t.Failed() {
		return
	}
	k := diffKeys()[d.next()%len(diffKeys())]
	var line []byte
	if d.next()%2 == 0 && k.name != deliveriesFloorName {
		line = appendFloorCRC(fmt.Appendf(nil, "%s %s %x rm", k.scope, k.name, k.gen[:]))
	} else {
		line = appendFloorCRC(fmt.Appendf(nil, "%s %s %x %d", k.scope, k.name, k.gen[:], 1+d.next()*977))
	}
	head := len(k.scope) + 1 + len(k.name) + 1
	minScope := len("user/1")
	n := minScope + d.next()%(len(line)-minScope)
	for _, closed := range []bool{false, true} {
		b := append(append(append([]byte(nil), *buf...), '\n'), line[:n]...)
		if closed {
			if r, err := parseFloorLine(line[:n]); err == nil {
				t.Fatalf("the prefix %q of a line for %+v parses, as %+v", line[:n], k, r)
			}
			b = append(b, '\n')
		}
		st := newDiffLog(s, true, maxKeys, &b).sync(t)
		if st.bad != nil {
			return
		}
		if len(st.taintNames)+len(st.taintGens)+len(st.taintPrefixes) >= maxTaintKeys {
			return
		}
		if !st.nameTainted(k.scope, k.name) && !st.tainted(k) {
			t.Fatalf("the prefix %q (closed %v) of a line for %+v does not taint it", line[:n], closed, k)
		}
		if n >= head+2*generationSize && !st.tainted(k) {
			t.Fatalf("the prefix %q (closed %v) with a whole generation does not taint %+v", line[:n], closed, k)
		}
	}
	// One byte of the whole line flipped in place, then closed: it never
	// parses, and it taints its key or counts as unattributable.
	flip := append([]byte(nil), line...)
	flip[d.next()%len(flip)] ^= byte(1 + d.next()%255)
	if r, err := parseFloorLine(flip); err == nil {
		t.Fatalf("%q, a line for %+v with a byte flipped, parses, as %+v", flip, k, r)
	}
	b := append(append(append(append([]byte(nil), *buf...), '\n'), flip...), '\n')
	st := newDiffLog(s, true, maxKeys, &b).sync(t)
	if st.bad != nil || len(st.taintNames)+len(st.taintGens)+len(st.taintPrefixes) >= maxTaintKeys {
		return
	}
	if _, unattrib := st.unattributedAt(); !unattrib && !st.tainted(k) {
		t.Fatalf("%q, a line for %+v with a byte flipped, neither taints it nor is unattributable", flip, k)
	}
}
