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

// inspectingSigner is fakeSigner plus Inspector: a file ending in "DEVID" carries
// a valid Developer ID signature of team ABCDE12345.
type inspectingSigner struct{ fakeSigner }

func (f *inspectingSigner) Inspect(_ context.Context, path string) (Signature, error) {
	b, err := os.ReadFile(path)
	switch {
	case err != nil:
		return Signature{}, nil
	case strings.HasSuffix(string(b), "SIGNED"):
		return Signature{Valid: true, AdHoc: true}, nil
	case strings.HasSuffix(string(b), "DEVID"):
		return Signature{Valid: true, TeamID: "ABCDE12345"}, nil
	}
	return Signature{}, nil
}

func (f *inspectingSigner) Satisfies(context.Context, string, string) (bool, error) {
	return false, nil
}

// TestIdentityRule pins the identity rule: with an Inspector behind the Signer, a
// binary whose signature verifies and is not ad hoc is never re-signed or
// replaced by EnsureSigned, SignIfInvalid or HealOnce (which still records it);
// without one, the old behaviour stands.
func TestIdentityRule(t *testing.T) {
	dir := t.TempDir()
	devID := filepath.Join(dir, "kube-apiserver")
	if err := os.WriteFile(devID, []byte("xDEVID"), 0o755); err != nil {
		t.Fatal(err)
	}
	s := &inspectingSigner{}
	before := ino(t, devID)
	if err := HealOnce(t.Context(), s, dir, "v1", "kube-apiserver"); err != nil {
		t.Fatal(err)
	}
	if replaced, err := EnsureSigned(t.Context(), s, devID); err != nil || replaced {
		t.Errorf("EnsureSigned: replaced=%v err=%v, want untouched", replaced, err)
	}
	if err := SignIfInvalid(t.Context(), s, "kube-apiserver")(devID); err != nil {
		t.Fatal(err)
	}
	if len(s.paths) != 0 || ino(t, devID) != before {
		t.Errorf("signed %v: a Developer ID binary was touched", s.paths)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, HealMarkerName)); string(b) != "kube-apiserver\tv1\n" {
		t.Errorf("marker = %q, want the kept binary recorded", b)
	}
	// A plain Signer cannot tell, so it re-signs as before.
	plain := &fakeSigner{}
	if replaced, err := EnsureSigned(t.Context(), plain, devID); err != nil || !replaced {
		t.Errorf("plain signer: replaced=%v err=%v, want the old re-sign", replaced, err)
	}
}

// TestRecordHealed pins the marker-only record: present names are recorded at the
// stamp without touching them, absent names are skipped, other lines are kept.
func TestRecordHealed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, HealMarkerName), []byte("z\told\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := ino(t, filepath.Join(dir, "a"))
	if err := RecordHealed(dir, "v1", "a", "absent"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, HealMarkerName)); string(b) != "a\tv1\nz\told\n" {
		t.Errorf("marker = %q", b)
	}
	if ino(t, filepath.Join(dir, "a")) != before {
		t.Error("RecordHealed replaced a binary")
	}
	if err := RecordHealed(dir, "", "a"); err == nil {
		t.Error("an empty stamp was accepted")
	}
}

// TestParseDisplay pins the read of `codesign -dv` output.
func TestParseDisplay(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  string
		want Signature
	}{
		{"ad hoc", "Executable=/x\nIdentifier=io.k3sm.app\nCodeDirectory v=20400 size=1 flags=0x2(adhoc) hashes=1+0\nSignature=adhoc\nTeamIdentifier=not set\n",
			Signature{Valid: true, AdHoc: true, Identifier: "io.k3sm.app"}},
		{"linker-signed", "CodeDirectory v=20400 size=1 flags=0x20002(adhoc,linker-signed) hashes=1+0\nSignature=adhoc\n",
			Signature{Valid: true, AdHoc: true}},
		{"Developer ID", "CodeDirectory v=20500 size=1 flags=0x10000(runtime) hashes=1+0\nAuthority=Developer ID Application: K (ABCDE12345)\nTeamIdentifier=ABCDE12345\n",
			Signature{Valid: true, TeamID: "ABCDE12345"}},
		{"platform binary", "CodeDirectory v=20400 size=1 flags=0x0(none) hashes=5+2\nTeamIdentifier=not set\n",
			Signature{Valid: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseDisplay(tc.out); got != tc.want {
				t.Errorf("parseDisplay = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestRequirements pins the requirement texts and the Team ID gate in front of
// them: a malformed id is refused, never spliced into the text.
func TestRequirements(t *testing.T) {
	for _, id := range []string{"", "abcde12345", "ABCDE1234", `ABCDE1234"`, "ABCDE12345 or anchor apple"} {
		if _, err := TeamRequirement(id); err == nil {
			t.Errorf("TeamRequirement accepted %q", id)
		}
		if _, err := DeveloperIDRequirement(id); err == nil {
			t.Errorf("DeveloperIDRequirement accepted %q", id)
		}
	}
	req, err := TeamRequirement("ABCDE12345")
	if err != nil || req != `anchor apple generic and certificate leaf[subject.OU] = "ABCDE12345"` {
		t.Errorf("TeamRequirement = %q, %v", req, err)
	}
	dev, err := DeveloperIDRequirement("ABCDE12345")
	if err != nil || !strings.Contains(dev, "certificate leaf[field.1.2.840.113635.100.6.1.13]") ||
		!strings.Contains(dev, "certificate 1[field.1.2.840.113635.100.6.2.6]") || !strings.HasSuffix(dev, `= "ABCDE12345"`) {
		t.Errorf("DeveloperIDRequirement = %q, %v", dev, err)
	}
}
