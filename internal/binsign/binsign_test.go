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

package binsign

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// fakeSigner treats a file ending in "SIGNED" as validly ad-hoc signed; Sign
// appends it in place (as codesign does) and records the path and identifier.
type fakeSigner struct {
	paths, ids []string
}

func (f *fakeSigner) Verify(_ context.Context, path string) (bool, error) {
	b, err := os.ReadFile(path)
	return err == nil && strings.HasSuffix(string(b), "SIGNED"), nil
}

func (f *fakeSigner) Sign(_ context.Context, path, identifier string) error {
	f.paths, f.ids = append(f.paths, path), append(f.ids, identifier)
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	_, _ = fh.WriteString("SIGNED")
	return fh.Close()
}

func ino(t *testing.T, p string) uint64 {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Ino
}

// TestEnsureSignedSignsATempUnderTheFinalName pins EnsureSigned: a valid ad-hoc
// binary is not touched; any other is signed as a temp, under the final base name
// as its identifier, and lands on a new inode; a symlink is refused.
func TestEnsureSignedSignsATempUnderTheFinalName(t *testing.T) {
	dir := t.TempDir()
	valid, invalid := filepath.Join(dir, "good"), filepath.Join(dir, "kube-apiserver")
	if err := os.WriteFile(valid, []byte("xSIGNED"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(invalid, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	s := &fakeSigner{}
	vIno, iIno := ino(t, valid), ino(t, invalid)
	if replaced, err := EnsureSigned(t.Context(), s, valid); err != nil || replaced || ino(t, valid) != vIno {
		t.Errorf("valid: replaced=%v err=%v, want untouched", replaced, err)
	}
	if replaced, err := EnsureSigned(t.Context(), s, invalid); err != nil || !replaced {
		t.Fatalf("invalid: replaced=%v err=%v", replaced, err)
	}
	if ino(t, invalid) == iIno {
		t.Error("the re-signed binary kept its inode")
	}
	if len(s.paths) != 1 || s.paths[0] == invalid || filepath.Dir(s.paths[0]) != dir {
		t.Errorf("signed %v, want one temp beside the binary", s.paths)
	}
	if len(s.ids) != 1 || s.ids[0] != "kube-apiserver" {
		t.Errorf("identifiers %v, want [kube-apiserver]", s.ids)
	}
	plain := filepath.Join(dir, "plain") // unsigned, so the link is not skipped as valid
	if err := os.WriteFile(plain, []byte("p"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(plain, link); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureSigned(t.Context(), &fakeSigner{}, link); err == nil {
		t.Error("EnsureSigned followed a symlink")
	}
}

// TestHealOnce pins the one-time heal: each named binary is replaced once per
// stamp (even a valid one), absent names are skipped, the marker records them,
// and a new stamp heals again.
func TestHealOnce(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(n+"SIGNED"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	s := &fakeSigner{}
	before := ino(t, filepath.Join(dir, "a"))
	if err := HealOnce(t.Context(), s, dir, "v1", "a", "b", "absent"); err != nil {
		t.Fatal(err)
	}
	if len(s.paths) != 2 || ino(t, filepath.Join(dir, "a")) == before {
		t.Errorf("first heal signed %v, want both present binaries replaced", s.paths)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, HealMarkerName)); string(b) != "a\tv1\nb\tv1\n" {
		t.Errorf("marker = %q", b)
	}
	if err := HealOnce(t.Context(), s, dir, "v1", "a", "b"); err != nil || len(s.paths) != 2 {
		t.Errorf("second heal at the same stamp signed %v (err %v), want nothing more", s.paths, err)
	}
	if err := HealOnce(t.Context(), s, dir, "v2", "a"); err != nil || len(s.paths) != 3 {
		t.Errorf("a new stamp signed %v (err %v), want one more", s.paths, err)
	}
	if err := HealOnce(t.Context(), s, dir, "bad\tstamp", "a"); err == nil {
		t.Error("a stamp with a tab was accepted")
	}
}
