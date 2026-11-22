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
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A burial whose fsync failed and of which no whole tombstone is visible
// in the file is not known to have landed: the rm is refused with nothing
// removed and says to run it again, never reported committed.
func TestRmBurialSyncFailureRefuses(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	fl := s.userFloor.(*fileFloorLog).log
	fl.write = func(f *os.File, b []byte) (int, error) {
		// The leading newline and a fragment of the first tombstone.
		n, err := f.Write(b[:12])
		if err != nil {
			return n, err
		}
		return n, io.ErrShortWrite
	}
	fl.fsync = func(*os.File) error { return errors.New("injected fsync failure") }
	err := u.Delete(ctx, "user/1001/token")
	fl.fsync, fl.write = nil, nil
	if err == nil || errors.Is(err, errCommitted) {
		t.Fatalf("rm whose burial fsync failed with no whole tombstone visible: %v, want a refusal", err)
	}
	for _, want := range []string{"nothing removed", "run rm again"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal %q does not say %q", err, want)
		}
	}
	if _, err := os.Stat(filepath.Join(scopeDir(server, "1001"), scopeEntriesName, "token")); err != nil {
		t.Fatalf("the refused rm removed the tree: %v", err)
	}
}

// A burial whose write landed whole and whose fsync failed has its
// tombstones visible: the reader holds them in force, so the rm is
// committed, says durability is uncertain and to run rm again, and is
// audited as a revocation. So is one whose tombstones landed after a
// foreign append between the open and the write: they are found from the
// real end of the file, not where the open saw it end.
func TestRmBurialSyncFailureVisibleCommits(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		ctx := context.Background()
		s, server, u := fileLogScope(t)
		gen := entryGeneration(t, server, "token")
		fl := s.userFloor.(*fileFloorLog).log
		if foreign {
			fl.write = func(f *os.File, b []byte) (int, error) {
				g, err := os.OpenFile(filepath.Join(s.dataRoot, userFloorLogName), os.O_WRONLY|os.O_APPEND, 0)
				if err != nil {
					return 0, err
				}
				_, err = g.Write([]byte("\nforeign line\n"))
				_ = g.Close()
				if err != nil {
					return 0, err
				}
				return f.Write(b)
			}
		}
		fl.fsync = func(*os.File) error { return errors.New("injected fsync failure") }
		err := u.Delete(ctx, "user/1001/token")
		fl.fsync, fl.write = nil, nil
		if !errors.Is(err, errCommitted) {
			t.Fatalf("foreign %v: rm whose visible burial's fsync failed: %v, want errCommitted", foreign, err)
		}
		if !strings.Contains(err.Error(), "durability uncertain; run rm again") {
			t.Fatalf("foreign %v: %q does not say durability is uncertain", foreign, err)
		}
		if _, err := s.userFloor.floor("user/1001", "token", gen); !errors.Is(err, errFloorBuried) {
			t.Fatalf("foreign %v: the floor after the burial: %v, want the generation buried", foreign, err)
		}
		audit := bytes.Split(bytes.TrimSuffix(readLog(t, s, auditLogName), []byte("\n")), []byte("\n"))
		r, err := parseAuditLine(audit[len(audit)-1])
		if err != nil {
			t.Fatal(err)
		}
		if r.Op != "rm" || r.Result != "committed" {
			t.Fatalf("foreign %v: the rm was audited %+v, want a committed rm", foreign, r)
		}
	}
}

// A burial whose write failed after a foreign append between the open and
// the write, and whose fsync succeeded, counts the tombstones it finds from
// the real end of the file: committed, not refused.
func TestRmBurialForeignAppendBeforeShortWriteCommits(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	gen := entryGeneration(t, server, "token")
	fl := s.userFloor.(*fileFloorLog).log
	fl.write = func(f *os.File, b []byte) (int, error) {
		g, err := os.OpenFile(filepath.Join(s.dataRoot, userFloorLogName), os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			return 0, err
		}
		_, err = g.Write([]byte("\nforeign line\n"))
		_ = g.Close()
		if err != nil {
			return 0, err
		}
		n, err := f.Write(b)
		if err != nil {
			return n, err
		}
		return 0, errors.New("injected write error after the bytes landed")
	}
	err := u.Delete(ctx, "user/1001/token")
	fl.write = nil
	if !errors.Is(err, errCommitted) {
		t.Fatalf("rm whose burial landed after a foreign append: %v, want errCommitted", err)
	}
	if _, err := s.userFloor.floor("user/1001", "token", gen); !errors.Is(err, errFloorBuried) {
		t.Fatalf("the floor after the burial: %v, want the generation buried", err)
	}
}
