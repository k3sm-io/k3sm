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

package install

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/shadow"
	"k3sm.io/runtimed/pkg/shadowset"
)

// relinkedCopies lists the Relink copies of runtimed's list, in its order.
func relinkedCopies() []string {
	var relinked []string
	for _, c := range shadow.Copies() {
		if c.Relink {
			relinked = append(relinked, c.Name)
		}
	}
	return relinked
}

// TestShadowCopiesCarryRelink pins that runtimed's Relink entries reach the
// installer, the xcodebuild copy cloned out of Xcode.app among them, and that
// every one of them is sourced from the default Xcode's developer dir, the
// only place the relink resolves a toolchain install_name_tool from.
func TestShadowCopiesCarryRelink(t *testing.T) {
	relinked := relinkedCopies()
	found := false
	for _, n := range relinked {
		if n == "xcodebuild" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Relink copies = %v, want xcodebuild among them", relinked)
	}
	for _, c := range shadow.Copies() {
		if !c.Relink {
			continue
		}
		if _, ok := developerDirOf(filepath.Dir(c.Source)); !ok {
			t.Errorf("Relink copy %s is sourced from %s, outside a developer dir", c.Name, c.Source)
		}
	}
}

func TestDeveloperDirOf(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"/Applications/Xcode.app/Contents/Developer/usr/bin", "/Applications/Xcode.app/Contents/Developer", true},
		{"/Applications/Xcode.app/Contents/Developer", "/Applications/Xcode.app/Contents/Developer", true},
		{"/usr/bin", "", false},
	} {
		got, ok := developerDirOf(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("developerDirOf(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestExecutableRpathRewritesRefusesARelativeSourceDir(t *testing.T) {
	for _, d := range []string{"usr/bin", "/a/../b", ""} {
		if _, err := executableRpathRewrites("/bin/ls", d); !errors.Is(err, errRelinkSourceDir) {
			t.Errorf("executableRpathRewrites(_, %q) = %v, want errRelinkSourceDir", d, err)
		}
	}
}

// TestCheckTrustedChain pins the source trust rule: every component root-owned,
// no symlink, not world-writable, group-writable only by wheel or admin.
func TestCheckTrustedChain(t *testing.T) {
	dir := uint32(unix.S_IFDIR | 0o755)
	file := uint32(unix.S_IFREG | 0o755)
	base := map[string]trustStat{
		"/":                 {0, 0, dir},
		"/Applications":     {0, adminGID, unix.S_IFDIR | 0o775},
		"/Applications/X":   {0, 0, dir},
		"/Applications/X/t": {0, 0, file},
	}
	run := func(over map[string]trustStat) error {
		m := map[string]trustStat{}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range over {
			m[k] = v
		}
		return checkTrustedChain("/Applications/X/t", func(p string) (trustStat, error) {
			st, ok := m[p]
			if !ok {
				return trustStat{}, fs.ErrNotExist
			}
			return st, nil
		})
	}
	if err := run(nil); err != nil {
		t.Fatalf("a root-owned chain under admin-writable /Applications was refused: %v", err)
	}
	for name, over := range map[string]map[string]trustStat{
		"user-owned bundle":   {"/Applications/X": {501, 20, dir}},
		"user-owned tool":     {"/Applications/X/t": {501, 20, file}},
		"world-writable dir":  {"/Applications/X": {0, 0, unix.S_IFDIR | 0o777}},
		"staff-writable tool": {"/Applications/X/t": {0, 20, unix.S_IFREG | 0o775}},
		"symlinked bundle":    {"/Applications/X": {0, 0, unix.S_IFLNK | 0o755}},
	} {
		if err := run(over); !errors.Is(err, errUntrustedSource) {
			t.Errorf("%s: err = %v, want errUntrustedSource", name, err)
		}
	}
	if err := checkTrustedChain("/nope", func(string) (trustStat, error) { return trustStat{}, fs.ErrNotExist }); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a missing source: err = %v, want fs.ErrNotExist", err)
	}
}

// TestShadowSetSkipsAnUntrustedRelinkSource: an Xcode a user owns gets no
// xcodebuild copy (a WARN, the install goes on), and nothing is cloned from it.
func TestShadowSetSkipsAnUntrustedRelinkSource(t *testing.T) {
	sys := newFakeSystem(t)
	sys.untrustedPaths = map[string]error{shadowset.XcodebuildSource: errUntrustedSource}
	var logs bytes.Buffer
	cfg := serverCfg(t)
	cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	if err := makeShadowSet(sys, cfg); err != nil {
		t.Fatalf("makeShadowSet: %v", err)
	}
	for _, c := range sys.calls {
		if strings.HasPrefix(c, "CloneToOwned:"+shadowset.XcodebuildSource) {
			t.Fatalf("an untrusted source was cloned: %s", c)
		}
	}
	if !strings.Contains(logs.String(), "not root-owned and protected") {
		t.Errorf("no WARN for the skipped copy:\n%s", logs.String())
	}
}

// TestShadowSetSkipsANonAppleSignedRelink: a relink refused for an untrusted
// signature drops the copy, records it as skipped (so status does not call the
// set stale), and the install goes on.
func TestShadowSetSkipsANonAppleSignedRelink(t *testing.T) {
	sys := newFakeSystem(t)
	sys.failures = map[string]error{"RelinkRpaths": fmt.Errorf("%w: not Apple-signed", errUntrustedSource)}
	cfg := serverCfg(t)
	cfg.Logger = slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	if err := makeShadowSet(sys, cfg); err != nil {
		t.Fatalf("makeShadowSet: %v", err)
	}
	var manifest []byte
	for p, b := range sys.files {
		if strings.HasSuffix(p, "/"+shadow.ManifestName) {
			manifest = b
		}
	}
	m, err := shadow.Decode(manifest)
	if err != nil {
		t.Fatalf("decode the written manifest: %v", err)
	}
	want := relinkedCopies()
	var got []string
	for _, s := range m.Skipped {
		got = append(got, s.Name)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("Skipped = %v, want every Relink copy %v", got, want)
	}
	skipped := map[string]bool{}
	for _, n := range want {
		skipped[n] = true
	}
	for _, s := range m.Sources {
		if skipped[s.Name] {
			t.Fatalf("a skipped copy (%s) is listed as a source", s.Name)
		}
	}
	if missing, _ := shadow.Missing(m, func(string) bool { return true }); len(missing) != 0 {
		t.Errorf("a skipped copy reads as missing: %+v", missing)
	}
}
