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
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAbsent: Absent is true for a deleted or never-put name, false for a
// live one, and false with an error where Current's ErrNotFound is not an
// answer about the name (no entries' directory) or the entry is damaged (a
// lost pointer). The identity it returns is Identity's, which a Put or a
// Delete leaves alone and a directory swapped in for the entries' changes.
func TestAbsent(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	if got, _, err := s.Absent(ctx, "a"); got || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Absent with no entries' directory = %v %v, want false and fs.ErrNotExist", got, err)
	}
	if id, err := s.Identity(ctx); id != "" || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Identity with no entries' directory = %q %v, want fs.ErrNotExist", id, err)
	}
	mustPut(t, s, "live", KindOpaque, []byte("live"))
	before, err := s.Identity(ctx)
	if err != nil || before == "" {
		t.Fatalf("Identity = %q %v", before, err)
	}
	mustPut(t, s, "gone", KindOpaque, []byte("gone"))
	mustPut(t, s, "lost", KindOpaque, []byte("lost"))
	if err := s.Delete(ctx, "gone"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(server, "keystore", "lost", currentName)); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name   string
		absent bool
		err    error
	}{
		{"live", false, nil},
		{"gone", true, nil},
		{"never", true, nil},
		{"lost", false, ErrCorrupt},
	} {
		got, id, err := s.Absent(ctx, c.name)
		if got != c.absent || (c.err == nil) != (err == nil) || (c.err != nil && !errors.Is(err, c.err)) {
			t.Errorf("Absent(%s) = %v %v, want %v %v", c.name, got, err, c.absent, c.err)
		}
		if err == nil && id != before {
			t.Errorf("Absent(%s) read identity %q, want %q: a Put or Delete changed it", c.name, id, before)
		}
	}
	// The entries' directory moved aside: Current reads every name as not
	// found, and Absent refuses to call that an absence.
	keystoreDir := filepath.Join(server, "keystore")
	if err := os.Rename(keystoreDir, keystoreDir+".aside"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Current(ctx, "live"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Current with the entries' directory moved aside = %v, want ErrNotFound", err)
	}
	if got, _, err := s.Absent(ctx, "live"); got || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Absent with the entries' directory moved aside = %v %v, want false and fs.ErrNotExist", got, err)
	}
	// A directory put in its place is another keystore.
	mustPut(t, s, "fresh", KindOpaque, []byte("fresh"))
	if after, err := s.Identity(ctx); err != nil || after == before {
		t.Fatalf("Identity of a recreated entries' directory = %q %v, want other than %q", after, err, before)
	}
}

// TestAbsentHoldsWhatTheFloorRecords: the floor is the witness of a delete.
// An older keystore/ restored the documented way (moved aside, a backup put
// in its place) lacks a name the live floor still records: Absent refuses
// to call that an absence. An interrupted Put is not an absence either. A
// real Delete removes the name from the floor, and then it is absent.
func TestAbsentHoldsWhatTheFloorRecords(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	ks := filepath.Join(server, "keystore")
	mustPut(t, s, "a", KindOpaque, []byte("a"))
	copyTree(t, ks, ks+".backup")
	mustPut(t, s, "b", KindOpaque, []byte("b"))
	if err := os.Rename(ks, ks+".pre-restore"); err != nil {
		t.Fatal(err)
	}
	copyTree(t, ks+".backup", ks)
	if got, _, err := s.Absent(ctx, "b"); got || !errors.Is(err, ErrFloorRecordsEntry) {
		t.Fatalf("Absent(b) after a restore without it = %v %v, want false and ErrFloorRecordsEntry", got, err)
	}
	if got, _, err := s.Absent(ctx, "never"); !got || err != nil {
		t.Fatalf("Absent(never) = %v %v, want true", got, err)
	}

	// An interrupted Put: generation and v1, no pointer, and a floor that
	// does not record that generation.
	mustPut(t, s, "half", KindOpaque, []byte("half"))
	remove(t, filepath.Join(ks, "half", currentName))
	writeFile(t, filepath.Join(ks, "half", generationName), strings.Repeat("ab", generationSize)+"\n")
	if got, _, err := s.Absent(ctx, "half"); got || !errors.Is(err, errInterruptedPut) {
		t.Fatalf("Absent(half) for an interrupted Put = %v %v, want false and the interrupted-put error", got, err)
	}

	// A real rm takes the name out of the floor.
	if err := s.Delete(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if got, _, err := s.Absent(ctx, "a"); !got || err != nil {
		t.Fatalf("Absent(a) after Delete = %v %v, want true", got, err)
	}
}
