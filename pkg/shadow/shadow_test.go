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

package shadow

import (
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/shadowset"
)

// TestManifestRoundTripAndDrift pins the manifest the installer writes and the
// status row reads: it round-trips, refuses an unknown version, parses the
// CDHash line out of real codesign output, and reports a changed or unreadable
// source as drift.
func TestManifestRoundTripAndDrift(t *testing.T) {
	t.Parallel()
	m := Manifest{Version: ManifestVersion, Sources: []Source{
		{Name: "bash", Path: "/bin/bash", CDHash: "aa"},
		{Name: "env", Path: "/usr/bin/env", CDHash: "bb"},
	}}
	b, err := Encode(m)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := Decode(b)
	if err != nil || !reflect.DeepEqual(got, m) {
		t.Fatalf("Decode = %+v, %v, want %+v", got, err, m)
	}
	if _, err := Decode([]byte(`{"version":9,"sources":[]}`)); err == nil {
		t.Fatalf("Decode accepted an unknown version")
	}

	out := []byte("Identifier=com.apple.bash\nCandidateCDHash sha256=e71e\nCDHash=E71EBF5018702DD8CED80C32718437B6A4D8F9D5\nTeamIdentifier=not set\n")
	if h, err := ParseCDHash(out); err != nil || h != "e71ebf5018702dd8ced80c32718437b6a4d8f9d5" {
		t.Fatalf("ParseCDHash = %q, %v", h, err)
	}
	if _, err := ParseCDHash([]byte("code object is not signed at all\n")); !errors.Is(err, ErrNoCDHash) {
		t.Fatalf("ParseCDHash(unsigned) err = %v, want ErrNoCDHash", err)
	}

	live := map[string]string{"/bin/bash": "aa", "/usr/bin/env": "cc"}
	d := Drift(m, func(p string) (string, error) { return live[p], nil })
	if len(d) != 1 || d[0].Source.Name != "env" || d[0].Live != "cc" {
		t.Fatalf("Drift = %+v, want env only", d)
	}
	gone := errors.New("no such file")
	d = Drift(m, func(string) (string, error) { return "", gone })
	if len(d) != 2 || !errors.Is(d[0].Err, gone) {
		t.Fatalf("Drift(unreadable) = %+v, want both with the read error", d)
	}
}

// TestCopiesAreTheSharedList pins that the set k3sm consumes is runtimed's
// shadowset list, one copy per entry in declaration order.
func TestCopiesAreTheSharedList(t *testing.T) {
	t.Parallel()
	entries := shadowset.Entries()
	got := Copies()
	if len(got) != len(entries) {
		t.Fatalf("Copies() = %d entries, want %d", len(got), len(entries))
	}
	for i, e := range entries {
		if got[i] != (Copy{Name: e.Copy, Source: e.Source}) {
			t.Errorf("copy %d = %+v, want %s from %s", i, got[i], e.Copy, e.Source)
		}
	}
}

// TestDriftReadsEachPathOnce pins that two copies made from one source cost
// one cdhash read.
func TestDriftReadsEachPathOnce(t *testing.T) {
	t.Parallel()
	m := Manifest{Version: ManifestVersion, Sources: []Source{
		{Name: "a", Path: "/usr/bin/x", CDHash: "aa"},
		{Name: "b", Path: "/usr/bin/x", CDHash: "aa"},
	}}
	reads := 0
	d := Drift(m, func(string) (string, error) { reads++; return "bb", nil })
	if reads != 1 || len(d) != 2 {
		t.Fatalf("reads = %d, drifted = %d, want 1 read and both drifted", reads, len(d))
	}
}

// TestMissing pins the older-install check: a copy of the current list absent
// from the manifest is missing only when its source is on this host.
func TestMissing(t *testing.T) {
	t.Parallel()
	all := Copies()
	var full []Source
	for _, c := range all {
		full = append(full, Source{Name: c.Name, Path: c.Source})
	}
	everywhere := func(string) bool { return true }
	for _, tc := range []struct {
		name         string
		sources      []Source
		present      func(string) bool
		wantMissing  int
		wantExpected int
	}{
		{name: "a current set", sources: full, present: everywhere, wantMissing: 0, wantExpected: len(all)},
		{name: "a set from an older install", sources: full[:4], present: everywhere, wantMissing: len(all) - 4, wantExpected: len(all)},
		{
			name:    "a source this host lacks never counts",
			sources: full[1:],
			present: func(s string) bool { return s != all[0].Source },
			// Another entry could share the absent source; count them.
			wantMissing: 0, wantExpected: len(all) - sharing(all, all[0].Source),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			missing, expected := Missing(Manifest{Version: ManifestVersion, Sources: tc.sources}, tc.present)
			if len(missing) != tc.wantMissing || expected != tc.wantExpected {
				t.Errorf("Missing = %d of %d, want %d of %d", len(missing), expected, tc.wantMissing, tc.wantExpected)
			}
		})
	}
}

func sharing(cs []Copy, source string) int {
	n := 0
	for _, c := range cs {
		if c.Source == source {
			n++
		}
	}
	return n
}

// TestCheckCopy pins the made-copy verification on the file properties and
// on real codesign output shapes.
func TestCheckCopy(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		mode  fs.FileMode
		flags uint32
		want  string
	}{
		{name: "root 0755 regular", mode: 0o755},
		{name: "symlink", mode: fs.ModeSymlink | 0o755, want: "not a regular file"},
		{name: "restricted", mode: 0o755, flags: SFRestricted, want: "SF_RESTRICTED"},
		{name: "setuid", mode: fs.ModeSetuid | 0o755, want: "setuid"},
		{name: "setgid", mode: fs.ModeSetgid | 0o755, want: "setgid"},
		{name: "group-writable", mode: 0o775, want: "group-writable"},
		{name: "world-writable", mode: 0o757, want: "world-writable"},
	} {
		t.Run("file/"+tc.name, func(t *testing.T) {
			checkErr(t, CheckCopyFile(tc.mode, tc.flags), tc.want)
		})
	}
	const adhoc = "Executable=/x\nCodeDirectory v=20400 size=1446 flags=0x2(adhoc) hashes=39+2 location=embedded\nCDHash=104d\nSignature=adhoc\n"
	const noEnts = "Executable=/x\n"
	for _, tc := range []struct {
		name, dvvv, ents, want string
	}{
		{name: "ad hoc, no entitlements", dvvv: adhoc, ents: noEnts},
		{name: "platform signature", dvvv: "CodeDirectory v=20400 size=1415 flags=0x0(none) hashes=39+2\nPlatform identifier=17\n", ents: noEnts, want: "not ad hoc"},
		{name: "hardened runtime", dvvv: strings.Replace(adhoc, "flags=0x2(adhoc)", "flags=0x10002(adhoc,runtime)", 1), ents: noEnts, want: "hardened runtime"},
		{name: "restrict", dvvv: strings.Replace(adhoc, "flags=0x2(adhoc)", "flags=0x802(adhoc,restrict)", 1), ents: noEnts, want: "restrict flag"},
		{name: "entitlements", dvvv: adhoc, ents: noEnts + "[Dict]\n\t[Key] com.apple.security.get-task-allow\n", want: "entitlements"},
		{name: "unsigned", dvvv: "/x: code object is not signed at all\n", ents: noEnts, want: "no code directory flags"},
	} {
		t.Run("signature/"+tc.name, func(t *testing.T) {
			checkErr(t, CheckCopySignature([]byte(tc.dvvv), []byte(tc.ents)), tc.want)
		})
	}
}

func checkErr(t *testing.T, err error, want string) {
	t.Helper()
	if want == "" {
		if err != nil {
			t.Errorf("err = %v, want nil", err)
		}
		return
	}
	if !errors.Is(err, ErrUnsafeCopy) || !strings.Contains(err.Error(), want) {
		t.Errorf("err = %v, want ErrUnsafeCopy naming %q", err, want)
	}
}
