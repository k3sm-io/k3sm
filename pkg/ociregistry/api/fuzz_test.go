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

package api

import (
	"crypto/sha256"
	"errors"
	"io"
	"strconv"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
)

func TestParseChunkRange(t *testing.T) {
	ok := []struct {
		in         string
		start, end int64
	}{
		{"0-0", 0, 0},
		{"0-1023", 0, 1023},
		{"1024-2047", 1024, 2047},
		{"4611686018427387904-4611686018427387904", maxOffset, maxOffset},
	}
	for _, tc := range ok {
		s, e, err := parseChunkRange(tc.in)
		if err != nil || s != tc.start || e != tc.end {
			t.Errorf("parseChunkRange(%q) = %d, %d, %v", tc.in, s, e, err)
		}
	}
	for _, in := range []string{
		"", "0", "-", "0-", "-0", "1-0", "a-b", "bytes 0-1", "bytes=0-1", " 0-1", "0-1 ", "0 -1",
		"+0-1", "0-+1", "-1-2", "01-2", "0-02", "0-1-2", "0--1", "0x1-2", "0-1/10",
		"4611686018427387905-4611686018427387905", "0-99999999999999999999", "0-9223372036854775807",
		"0-١", "0\x00-1",
	} {
		if s, e, err := parseChunkRange(in); !errors.Is(err, errBadRange) {
			t.Errorf("parseChunkRange(%q) = %d, %d, %v; want refused", in, s, e, err)
		}
	}
	for size, want := range map[int64]string{0: "0-0", 1: "0-0", 5: "0-4"} {
		if got := formatRange(size); got != want {
			t.Errorf("formatRange(%d) = %q, want %q", size, got, want)
		}
	}
}

// FuzzParseChunkRange: an accepted value is in bounds and is exactly the
// canonical spelling of what it parsed to; nothing panics.
func FuzzParseChunkRange(f *testing.F) {
	for _, s := range []string{"0-0", "0-1023", "5-4", "01-2", "bytes=0-1", "-1-2", "4611686018427387904-4611686018427387904", "9223372036854775807-9223372036854775807"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		start, end, err := parseChunkRange(s)
		if err != nil {
			if !errors.Is(err, errBadRange) {
				t.Fatalf("refusal %v is not errBadRange", err)
			}
			return
		}
		if start < 0 || start > end || end > maxOffset {
			t.Fatalf("%q parsed out of bounds: %d-%d", s, start, end)
		}
		if canon := strconv.FormatInt(start, 10) + "-" + strconv.FormatInt(end, 10); canon != s {
			t.Fatalf("%q accepted but its canonical form is %q", s, canon)
		}
	})
}

// sessionModel drives a hashState the way the upload handlers do, against a
// model of the session file, from fuzz bytes. Each operation is one byte of
// op followed by a length byte:
//
//	0: an append at the session's end through the tee, succeeding;
//	1: an append that reads the chunk through the tee but writes only part
//	   of it and fails (a client gone mid-body, a full volume);
//	2: another writer appends without the tee (a process the server does
//	   not know about);
//	3: an append refused before the body is read (an offset mismatch);
//	4: a restart, which loses the state.
//
// The invariant: whenever the state claims a digest for n bytes, n is the
// file's length and the digest is the file's sha256.
func sessionModel(t *testing.T, ops []byte) {
	st := newHashState()
	var file []byte
	chunk := func(n byte) []byte {
		b := make([]byte, int(n)%97)
		for i := range b {
			b[i] = byte(len(file) + i)
		}
		return b
	}
	for i := 0; i+1 < len(ops) && i < 400; i += 2 {
		op, n := ops[i]%5, ops[i+1]
		switch op {
		case 0:
			c := chunk(n)
			w := st.writer()
			_, _ = w.Write(c)
			file = append(file, c...)
			st.settle(int64(len(file)), nil)
		case 1:
			c := chunk(n)
			w := st.writer()
			_, _ = w.Write(c)
			file = append(file, c[:len(c)/2]...)
			st.settle(int64(len(file)), io.ErrUnexpectedEOF)
		case 2:
			file = append(file, chunk(n)...)
		case 3:
			_ = st.writer()
			st.settle(int64(len(file)), errors.New("offset mismatch"))
		case 4:
			st.lose()
		}
		if d, size, ok := st.sum(digest.SHA256); ok {
			if size != int64(len(file)) {
				// A stale claim is only safe because the store re-checks the
				// length; the model asserts the hash covers a prefix exactly.
				sum := sha256.Sum256(file[:size])
				if size > int64(len(file)) || digest.NewDigestFromBytes(digest.SHA256, sum[:]) != d {
					t.Fatalf("after op %d the state claims %s for %d bytes of %d", i/2, d, size, len(file))
				}
				continue
			}
			sum := sha256.Sum256(file)
			if digest.NewDigestFromBytes(digest.SHA256, sum[:]) != d {
				t.Fatalf("after op %d the state claims %s, the file is %x", i/2, d, sum)
			}
		}
	}
	if _, _, ok := st.sum(digest.SHA512); ok {
		t.Fatal("the state claimed a sha512 digest")
	}
}

func TestSessionHashState(t *testing.T) {
	for name, ops := range map[string][]byte{
		"appends":                      {0, 10, 0, 20, 0, 0},
		"a failed append loses it":     {0, 10, 1, 30, 0, 5},
		"another writer loses it":      {0, 10, 2, 7, 0, 5},
		"a refused append keeps it":    {0, 10, 3, 0, 0, 5},
		"a restart loses it":           {0, 10, 4, 0, 0, 5},
		"a failed empty read keeps it": {0, 10, 1, 0},
		"interleaved":                  {0, 1, 2, 2, 0, 3, 3, 3, 1, 9, 4, 0, 0, 1},
	} {
		t.Run(name, func(t *testing.T) { sessionModel(t, ops) })
	}
	// A state that survived every append is exact.
	st := newHashState()
	_, _ = st.writer().Write([]byte("abc"))
	st.settle(3, nil)
	if d, n, ok := st.sum(digest.SHA256); !ok || n != 3 || d != digest.FromString("abc") {
		t.Errorf("sum = %s, %d, %v", d, n, ok)
	}
	_, _ = st.writer().Write([]byte("x"))
	st.settle(9, nil) // the store reports more than was teed: someone else wrote
	if _, _, ok := st.sum(digest.SHA256); ok {
		t.Error("a state that does not match the session length survived")
	}
}

// FuzzSessionHashState runs the session model over arbitrary operation
// sequences.
func FuzzSessionHashState(f *testing.F) {
	f.Add([]byte{0, 10, 0, 20})
	f.Add([]byte{0, 10, 1, 30, 0, 5})
	f.Add([]byte{0, 10, 2, 7, 0, 5})
	f.Add([]byte{0, 1, 2, 2, 0, 3, 3, 3, 1, 9, 4, 0, 0, 1})
	f.Fuzz(func(t *testing.T, ops []byte) { sessionModel(t, ops) })
}

// TestSessionTable pins the table's admission and release rules.
func TestSessionTable(t *testing.T) {
	mustTime := func(sec int64) time.Time { return time.Unix(sec, 0) }
	now := mustTime(0)
	clock := func() time.Time { return now }
	tab := newSessions(2, 10*time.Second, clock)
	e1, rel1, err := tab.admit()
	if err != nil {
		t.Fatal(err)
	}
	tab.bind("a", e1)
	rel1()
	_, rel2, err := tab.admit()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := tab.admit(); !errors.Is(err, errTooManySessions) {
		t.Fatalf("a third admission = %v, want errTooManySessions", err)
	}
	rel2()
	tab.abandon()
	if tab.live() != 1 {
		t.Fatalf("live = %d after an abandoned admission, want 1", tab.live())
	}
	// A busy entry is never pruned; an idle one is.
	e, rel := tab.acquire("a")
	if e != e1 {
		t.Fatal("acquire returned a different entry for a known session")
	}
	now = mustTime(100)
	if tab.live() != 1 {
		t.Fatal("a busy entry was pruned")
	}
	rel()
	now = mustTime(200)
	if tab.live() != 0 {
		t.Fatal("an idle entry was not pruned")
	}
	// A session the server has not seen starts unhashed.
	e, rel = tab.acquire("resumed")
	if _, _, ok := e.hash.sum(digest.SHA256); ok {
		t.Error("a resumed session claims a hash")
	}
	rel()
	tab.forget("resumed")
	if tab.live() != 0 {
		t.Error("forget left the entry")
	}
}
