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
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// swappedGenerationEntry rewrites user/1001/token's generation file to
// another generation, and gives the floor a live line of a third that sorts
// first, so an rm of it names three: the floor's, the one the pointer
// authenticates, and the file's.
func swappedGenerationEntry(t *testing.T, s *FileStore, server string) (authed, floorOnly, swapped [generationSize]byte) {
	t.Helper()
	authed, floorOnly, swapped = entryGeneration(t, server, "token"), guid(0), guid(0x5A)
	p := filepath.Join(scopeDir(server, "1001"), scopeEntriesName, "token", generationName)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(hex.EncodeToString(swapped[:])+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	giveToService(t, p)
	line, err := floorLine("user/1001", "token", floorOnly, 1)
	if err != nil {
		t.Fatal(err)
	}
	appendLogBytes(t, s, userFloorLogName, line)
	return authed, floorOnly, swapped
}

// U20: an rm's burial is one write(2) of every tombstone, the generation
// the pointer authenticates first, reserved by one block reservation for
// the whole buffer.
func TestRmBurialIsOneWrite(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	authed, floorOnly, swapped := swappedGenerationEntry(t, s, server)
	l := s.userFloor.(*fileFloorLog).log
	var writes, reserves []int
	l.write = func(f *os.File, b []byte) (int, error) {
		writes = append(writes, len(b))
		return f.Write(b)
	}
	l.reserve = func(_ *os.File, n int64) error {
		reserves = append(reserves, int(n))
		return nil
	}
	before := readLog(t, s, userFloorLogName)
	err := u.Delete(ctx, "user/1001/token")
	if err != nil && !errors.Is(err, errCommitted) {
		t.Fatalf("rm of an entry with a swapped generation file: %v", err)
	}
	first, err := tombLine("user/1001", "token", authed)
	if err != nil {
		t.Fatal(err)
	}
	// The append leads with its newline (appendLines).
	want := []byte{'\n'}
	want = append(want, first...)
	for _, g := range [][generationSize]byte{floorOnly, swapped} {
		line, err := tombLine("user/1001", "token", g)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, line...)
	}
	if added := readLog(t, s, userFloorLogName)[len(before):]; !bytes.Equal(added, want) {
		t.Fatalf("the burial appended %q, want %q (the authenticated generation first)", added, want)
	}
	if len(writes) != 1 || writes[0] != len(want) {
		t.Fatalf("the burial took writes of %v bytes, want one of %d", writes, len(want))
	}
	if len(reserves) != 1 || reserves[0] != int(reserveSize(int64(len(want)))) {
		t.Fatalf("the burial took reservations of %v bytes, want one of %d", reserves, reserveSize(int64(len(want))))
	}
}

// A burial whose block reservation is refused writes nothing and refuses
// the rm; one whose single write lands short leaves a torn tail, which the
// reader skips, and refuses the rm too: never errCommitted.
func TestRmBurialWriteFailureRefuses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		inject func(l *appendLog)
		torn   bool
	}{
		{"reservation", func(l *appendLog) {
			l.reserve = func(*os.File, int64) error { return errors.New("injected reservation failure") }
		}, false},
		{"short write", func(l *appendLog) {
			l.write = func(f *os.File, b []byte) (int, error) {
				n, err := f.Write(b[:20]) // inside the first tombstone
				if err != nil {
					return n, err
				}
				return n, io.ErrShortWrite
			}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s, server, u := fileLogScope(t)
			swappedGenerationEntry(t, s, server)
			l := s.userFloor.(*fileFloorLog).log
			tc.inject(l)
			before := readLog(t, s, userFloorLogName)
			err := u.Delete(ctx, "user/1001/token")
			if err == nil || errors.Is(err, errCommitted) || !strings.Contains(err.Error(), "nothing removed") {
				t.Fatalf("rm whose burial write failed: %v, want a refusal with nothing removed", err)
			}
			if _, err := os.Lstat(filepath.Join(scopeDir(server, "1001"), scopeEntriesName, "token", currentName)); err != nil {
				t.Fatalf("the entry's pointer after the refused rm: %v, want it kept", err)
			}
			after := readLog(t, s, userFloorLogName)
			if !tc.torn && !bytes.Equal(before, after) {
				t.Fatalf("a refused reservation wrote %q", after[len(before):])
			}
			l.write, l.reserve = nil, nil
			if want := map[bool]int{false: 0, true: 1}[tc.torn]; floorDamage(t, s) != want {
				t.Fatalf("damage after the failed burial is %d, want %d", floorDamage(t, s), want)
			}
			if err := u.Delete(ctx, "user/1001/token"); err != nil && !errors.Is(err, errCommitted) {
				t.Fatalf("rm retried after the failed burial: %v", err)
			}
		})
	}
}

// A burial whose single write lands short after one whole tombstone has a
// tombstone in force: the rm is committed (errCommitted), never refused
// with "nothing removed", it is audited as a commit, the landed generation
// is buried, the fragment after it is counted damage, and a retry buries
// the rest.
func TestRmBurialShortWriteAfterWholeLineCommits(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	authed, _, _ := swappedGenerationEntry(t, s, server)
	l := s.userFloor.(*fileFloorLog).log
	l.write = func(f *os.File, b []byte) (int, error) {
		// The leading newline, one whole tombstone and a fragment.
		cut := 1 + bytes.IndexByte(b[1:], '\n') + 1 + 10
		n, err := f.Write(b[:cut])
		if err != nil {
			return n, err
		}
		return n, io.ErrShortWrite
	}
	err := u.Delete(ctx, "user/1001/token")
	if !errors.Is(err, errCommitted) || strings.Contains(err.Error(), "nothing removed") {
		t.Fatalf("rm whose burial landed one whole tombstone: %v, want errCommitted without \"nothing removed\"", err)
	}
	l.write = nil
	live, err := s.userFloor.liveGens("user/1001", "token")
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range live {
		if g == authed {
			t.Fatalf("the landed tombstone's generation is still live: %x", g)
		}
	}
	audit := bytes.Split(bytes.TrimSuffix(readLog(t, s, auditLogName), []byte("\n")), []byte("\n"))
	r, err := parseAuditLine(audit[len(audit)-1])
	if err != nil {
		t.Fatal(err)
	}
	if r.Op != "rm" || r.Result != "committed" {
		t.Fatalf("the rm was audited %+v, want a committed rm", r)
	}
	if got := floorDamage(t, s); got != 1 {
		t.Fatalf("damage after the short burial is %d, want 1 (the fragment)", got)
	}
	if err := u.Delete(ctx, "user/1001/token"); err != nil && !errors.Is(err, errCommitted) {
		t.Fatalf("rm retried after the short burial: %v", err)
	}
}
