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
	"testing"
)

// TestAbsent: Absent is true for a deleted or never-put name, false for a
// live one, and false with an error where Current's ErrNotFound is not an
// answer about the name (no entries' directory) or the entry is damaged (a
// lost pointer).
func TestAbsent(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	if got, err := s.Absent(ctx, "a"); got || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Absent with no entries' directory = %v %v, want false and fs.ErrNotExist", got, err)
	}
	mustPut(t, s, "live", KindOpaque, []byte("live"))
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
		got, err := s.Absent(ctx, c.name)
		if got != c.absent || (c.err == nil) != (err == nil) || (c.err != nil && !errors.Is(err, c.err)) {
			t.Errorf("Absent(%s) = %v %v, want %v %v", c.name, got, err, c.absent, c.err)
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
	if got, err := s.Absent(ctx, "live"); got || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Absent with the entries' directory moved aside = %v %v, want false and fs.ErrNotExist", got, err)
	}
}
