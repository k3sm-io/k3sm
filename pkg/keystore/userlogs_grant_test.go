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
	"testing"
)

// A grant judges the floor before its first write: over a good audit log
// and a floor that is absent, unflagged, unreadable or malformed, a put and
// a deliver are refused with nothing written and no ok line, and the
// refusal is audited.
func TestGrantRefusesUntrustedFloorFirst(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spoil func(t *testing.T, s *FileStore)
		want  error
	}{
		{"absent", func(t *testing.T, s *FileStore) {
			if err := os.Remove(filepath.Join(s.dataRoot, userFloorLogName)); err != nil {
				t.Fatal(err)
			}
		}, errLogMissing},
		{"unflagged", func(t *testing.T, s *FileStore) {
			s.logFlags = func(f *os.File) (uint32, error) {
				if filepath.Base(f.Name()) == userFloorLogName {
					return 0, nil
				}
				return sfAppend, nil
			}
		}, errLogNotAppendOnly},
		{"unreadable", func(t *testing.T, s *FileStore) {
			line, err := floorLine("user/1001", "token", guid(0x77), 3)
			if err != nil {
				t.Fatal(err)
			}
			appendLogBytes(t, s, userFloorLogName, line)
			s.userFloor.(*fileFloorLog).log.readAt = func(*os.File) io.ReaderAt { return failingReaderAt{} }
		}, errLogUnreadable},
		{"malformed", func(t *testing.T, s *FileStore) {
			appendLogBytes(t, s, userFloorLogName, []byte("not a floor line\n"))
		}, errFloorLogMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s, server, u := fileLogScope(t)
			tc.spoil(t, s)
			snap := treeSnapshot(t, server)
			before := readLog(t, s, auditLogName)
			if _, err := u.Put(ctx, "user/1001/other", KindOpaque, []byte("v")); !errors.Is(err, tc.want) {
				t.Fatalf("put over a %s floor: %v, want %v", tc.name, err, tc.want)
			}
			if err := u.addDelivery(ctx, testDelivery(1)); !errors.Is(err, tc.want) {
				t.Fatalf("deliver over a %s floor: %v, want %v", tc.name, err, tc.want)
			}
			checkTreeUnchanged(t, snap, treeSnapshot(t, server))
			after := readLog(t, s, auditLogName)
			if !bytes.HasPrefix(after, before) {
				t.Fatal("the audit log was rewritten")
			}
			added := bytes.Split(bytes.TrimSuffix(after[len(before):], []byte("\n")), []byte("\n"))
			if len(added) != 2 {
				t.Fatalf("want one refusal line per grant, got %q", after[len(before):])
			}
			for _, l := range added {
				r, err := parseAuditLine(l)
				if err != nil {
					t.Fatal(err)
				}
				if r.Result == "ok" {
					t.Fatalf("a grant over a %s floor wrote an ok line: %s", tc.name, l)
				}
			}
		})
	}
}
