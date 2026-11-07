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

package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// rowsFixture is a store with repository app holding tags t0..t(k-1), each on
// its own manifest.
func rowsFixture(t *testing.T, k int) (*Store, ref.Name) {
	t.Helper()
	s := newStore(t)
	n := name(t, "app")
	for i := range k {
		pushTag(t, s, n, i)
	}
	return s, n
}

func pushTag(t *testing.T, s *Store, n ref.Name, i int) {
	t.Helper()
	body := []byte(`{"schemaVersion":2,"seed":` + string(rune('0'+i%10)) + `,"i":"` + string(rune('a'+i)) + `"}`)
	if _, err := s.PutManifest(context.Background(), n, ref.Reference{Tag: "t" + string(rune('a'+i))}, ispec.MediaTypeImageManifest, body); err != nil {
		t.Fatal(err)
	}
}

func checkRows(s *Store, n ref.Name) error {
	return s.WithLock(context.Background(), n, func(l *Locked) error { return l.CheckRows() })
}

// dropRows rewrites n's index.json behind the store's back with only its
// first keep rows.
func dropRows(t *testing.T, s *Store, n ref.Name, keep int) {
	t.Helper()
	dir, err := s.repoDir(n)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := readIndex(dir)
	if err != nil {
		t.Fatal(err)
	}
	idx.Manifests = idx.Manifests[:keep]
	b, err := json.Marshal(idx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, indexFile), b, fileMode); err != nil {
		t.Fatal(err)
	}
}

func TestRowCountFollowsTheStoresWrites(t *testing.T) {
	s, n := rowsFixture(t, 3)
	if err := checkRows(s, n); err != nil {
		t.Fatalf("after three pushes: %v", err)
	}
	if err := s.DeleteTag(context.Background(), n, "tb"); err != nil {
		t.Fatal(err)
	}
	dir, _ := s.repoDir(n)
	if err := s.WithLock(context.Background(), n, func(l *Locked) error { return l.SetRows(nil) }); err != nil {
		t.Fatal(err)
	}
	if err := checkRows(s, n); err != nil {
		t.Fatalf("after a tag delete and every row removed: %v", err)
	}
	rc, ok, _, err := s.recordedRows(dir)
	if err != nil || !ok || rc.Rows != 0 {
		t.Fatalf("record %+v, %v, %v; want 0 rows", rc, ok, err)
	}
}

func TestDroppedRowsStayLostThroughLaterPushes(t *testing.T) {
	s, n := rowsFixture(t, 3)
	dropRows(t, s, n, 1)
	if err := checkRows(s, n); !errors.Is(err, ErrRowsLost) {
		t.Fatalf("after two rows were dropped: %v, want ErrRowsLost", err)
	}
	pushTag(t, s, n, 7)
	if err := checkRows(s, n); !errors.Is(err, ErrRowsLost) {
		t.Fatalf("a push after the loss hid it: %v", err)
	}
	// Removing the record accepts the index as it is.
	dir, _ := s.repoDir(n)
	if err := s.removeRowCount(dir); err != nil {
		t.Fatal(err)
	}
	if err := checkRows(s, n); err != nil {
		t.Fatalf("with the record removed: %v", err)
	}
	if err := checkRows(s, n); err != nil {
		t.Fatalf("with the record rewritten: %v", err)
	}
}

// TestMissingRowCountIsWrittenAndNeverBlocks is a store from before records
// were kept, and one whose record belongs to another store id.
func TestMissingRowCountIsWrittenAndNeverBlocks(t *testing.T) {
	s, n := rowsFixture(t, 2)
	if err := os.RemoveAll(filepath.Join(s.state, rowsDir)); err != nil {
		t.Fatal(err)
	}
	if err := checkRows(s, n); err != nil {
		t.Fatalf("no record: %v", err)
	}
	dir, _ := s.repoDir(n)
	if _, ok, _, err := s.recordedRows(dir); err != nil || !ok {
		t.Fatalf("the check did not write the record: %v, %v", ok, err)
	}
	// A new store id makes the record another store's.
	dropRows(t, s, n, 1)
	if _, err := s.EnsureID(); err != nil {
		t.Fatal(err)
	}
	if err := checkRows(s, n); err != nil {
		t.Fatalf("a record for another store id: %v", err)
	}
}

// TestRowCountIsCrashSafe stops writeIndex between its two writes, as a crash
// would, and requires that the record never says more rows than the index.
func TestRowCountIsCrashSafe(t *testing.T) {
	crash := errors.New("crash")
	for _, tc := range []struct {
		name  string
		write func(s *Store, n ref.Name) error
	}{
		{"a push", func(s *Store, n ref.Name) error {
			_, err := s.PutManifest(context.Background(), n, ref.Reference{Tag: "new"}, ispec.MediaTypeImageManifest, []byte(`{"schemaVersion":2,"new":1}`))
			return err
		}},
		{"a digest delete", func(s *Store, n ref.Name) error {
			idx, err := s.Index(n)
			if err != nil {
				return err
			}
			return s.DeleteDigest(context.Background(), n, idx.Manifests[len(idx.Manifests)-1].Digest)
		}},
		{"rows removed", func(s *Store, n ref.Name) error {
			return s.WithLock(context.Background(), n, func(l *Locked) error { return l.SetRows(nil) })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, n := rowsFixture(t, 3)
			if err := s.DeleteTag(context.Background(), n, "tc"); err != nil { // leaves an untagged row
				t.Fatal(err)
			}
			ran := false
			s.rowsBetween = func() error { ran = true; return crash }
			if err := tc.write(s, n); !errors.Is(err, crash) {
				t.Fatalf("write: %v, want the crash", err)
			}
			s.rowsBetween = nil
			if !ran {
				t.Fatal("the write never reached the seam")
			}
			if err := checkRows(s, n); err != nil {
				t.Fatalf("after a crash between the writes: %v", err)
			}
		})
	}
}
