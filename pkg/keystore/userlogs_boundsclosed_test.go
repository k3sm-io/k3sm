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
	"time"
)

// CheckLogBounds fails closed: a log that is missing, untrusted or
// unflagged, or one that cannot be read, refuses the start step, and the
// user scope stays unstarted.
func TestCheckLogBoundsFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		inject func(t *testing.T, s *FileStore)
	}{
		{"missing floor", func(t *testing.T, s *FileStore) {
			if err := os.Remove(filepath.Join(s.dataRoot, logsDirName, userFloorLogName)); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing audit", func(t *testing.T, s *FileStore) {
			if err := os.Remove(filepath.Join(s.dataRoot, logsDirName, auditLogName)); err != nil {
				t.Fatal(err)
			}
		}},
		{"untrusted", func(t *testing.T, s *FileStore) {
			if err := os.Chmod(filepath.Join(s.dataRoot, logsDirName, userFloorLogName), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"unflagged", func(t *testing.T, s *FileStore) {
			s.logFlags = func(*os.File) (uint32, error) { return 0, nil }
		}},
		{"unreadable", func(t *testing.T, s *FileStore) {
			s.userFloor.(*fileFloorLog).log.readAt = func(*os.File) io.ReaderAt { return failingReaderAt{} }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s, _, _ := fileLogScope(t)
			tc.inject(t, s)
			if _, _, err := s.CheckLogBounds(ctx); err == nil {
				t.Fatal("CheckLogBounds passed a log it could not judge")
			}
			s.userScopesStarted.Store(false)
			if err := s.startUserScopes(ctx); err == nil {
				t.Fatal("the start step passed a log CheckLogBounds could not judge")
			}
			if s.userScopesStarted.Load() {
				t.Fatal("the user scope started after CheckLogBounds refused")
			}
		})
	}
}

// Bounded damage is skipped, not refused: CheckLogBounds passes and reports
// the count of skipped lines.
func TestCheckLogBoundsReportsDamage(t *testing.T) {
	ctx := context.Background()
	s, _, _ := fileLogScope(t)
	if n, _, err := s.CheckLogBounds(ctx); err != nil || n != 0 {
		t.Fatalf("CheckLogBounds on clean logs: %d, %v, want 0, nil", n, err)
	}
	appendLogBytes(t, s, userFloorLogName, []byte("not a floor line\n"))
	appendLogBytes(t, s, userFloorLogName, []byte("nor this\n"))
	if n, _, err := s.CheckLogBounds(ctx); err != nil || n != 2 {
		t.Fatalf("CheckLogBounds over two damaged lines: %d, %v, want 2, nil", n, err)
	}
}

// A uid whose revocation budget has less than one whole line left is
// counted, not refused: only one over its budget, which only lowered caps
// make, refuses the store open.
func TestCheckLogBoundsRefusesAtSpent(t *testing.T) {
	ctx := context.Background()
	s, _, _ := fileLogScope(t)
	size := int64(len(readLog(t, s, auditLogName)))
	s.logSoftCap, s.logHardCap = size, size
	line, err := marshalAuditLine(auditLine{op: "rm", scope: "user/1001", name: "token", result: "ok"}, time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	k := int(s.logRevokeBudget-maxAppendLine) / len(line)
	appendLogBytes(t, s, auditLogName, bytes.Repeat(line, k))
	if _, spent, err := s.CheckLogBounds(ctx); err != nil || spent != 0 {
		t.Fatalf("store open with a whole line of budget left: %d, %v", spent, err)
	}
	appendLogBytes(t, s, auditLogName, line)
	if _, spent, err := s.CheckLogBounds(ctx); err != nil || spent != 1 {
		t.Fatalf("store open with under one line of budget left: %d, %v; want 1 spent uid, no error", spent, err)
	}
	over := int(s.logRevokeBudget)/len(line) + 1 - k - 1
	appendLogBytes(t, s, auditLogName, bytes.Repeat(line, over))
	if _, _, err := s.CheckLogBounds(ctx); !errors.Is(err, errLogRevokeBudgetSpent) {
		t.Fatalf("store open with a uid over its budget: %v, want errLogRevokeBudgetSpent", err)
	}
}
