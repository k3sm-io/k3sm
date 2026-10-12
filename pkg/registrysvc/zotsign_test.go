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

package registrysvc

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// signedSuffix is what the fake codesign appends to "sign" a file; a file
// "verifies" when it ends with it.
const signedSuffix = "SIGNED"

// fakeCodesign puts a fake `codesign` first on PATH and returns a func reporting
// the paths it signed. It signs IN PLACE (an append that keeps the inode), as the
// real tool does, so a sign at a live path shows through an fd held on the file.
// The production signer (binsign.Codesign → runtimed's image package → exec
// "codesign") runs unchanged; no real codesign runs.
func fakeCodesign(t *testing.T) func() []string {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "codesign.log")
	script := `#!/bin/sh
for a in "$@"; do last=$a; done
case "$1" in
--verify)
	[ "$(/usr/bin/tail -c 6 "$last" 2>/dev/null)" = "` + signedSuffix + `" ]
	exit $?
	;;
-s)
	printf 'sign %s\n' "$last" >> "` + log + `"
	[ "$(/usr/bin/tail -c 6 "$last")" = "` + signedSuffix + `" ] || printf ` + signedSuffix + ` >> "$last"
	exit 0
	;;
esac
exit 2
`
	if err := os.WriteFile(filepath.Join(dir, "codesign"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() []string {
		b, err := os.ReadFile(log)
		if err != nil {
			return nil
		}
		var signed []string
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if p, ok := strings.CutPrefix(line, "sign "); ok {
				signed = append(signed, p)
			}
		}
		return signed
	}
}

func zotInode(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Ino
}

// isZotTemp reports whether p is an atomicfile temp beside zot: in its directory,
// named ".<base>.tmp-<digits>".
func isZotTemp(p, zot string) bool {
	if filepath.Dir(p) != filepath.Dir(zot) {
		return false
	}
	rest, ok := strings.CutPrefix(filepath.Base(p), "."+filepath.Base(zot)+".tmp-")
	return ok && rest != "" && strings.Trim(rest, "0123456789") == ""
}

// TestZotStagingNeverRewritesALiveInode is the registry's half of the rule that
// k3sm never rewrites a binary in place: macOS kills every process that maps a
// signed Mach-O rewritten while mapped. The start-time re-sign, the payload
// re-seed and the build must each put changed bytes on a NEW inode and sign only
// a temp, leave a validly signed zot untouched, and leave an fd held on the old
// file reading the old bytes.
func TestZotStagingNeverRewritesALiveInode(t *testing.T) {
	// stage writes a staged zot with content and a marker for version.
	stage := func(t *testing.T, bd, content, version string) {
		t.Helper()
		if err := os.MkdirAll(bd, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(ZotPath(bd), []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := writeZotMarker(bd, version); err != nil {
			t.Fatal(err)
		}
	}
	// replaced asserts zot is on a new inode, signed, and the held old file
	// still reads old; and that codesign saw only temps beside zot.
	replaced := func(t *testing.T, zot string, ino uint64, held *os.File, old string, signed []string) {
		t.Helper()
		if got := zotInode(t, zot); got == ino {
			t.Errorf("zot kept inode %d: it was rewritten in place", ino)
		}
		if b, _ := os.ReadFile(zot); !strings.HasSuffix(string(b), signedSuffix) {
			t.Errorf("zot holds unsigned bytes %q", b)
		}
		buf := make([]byte, len(old)+64)
		n, _ := held.ReadAt(buf, 0)
		if string(buf[:n]) != old {
			t.Errorf("the fd held on the old zot reads %q, want %q untouched", buf[:n], old)
		}
		if len(signed) != 1 || !isZotTemp(signed[0], zot) {
			t.Errorf("codesign signed %v; want exactly one temp beside %s, never the live path", signed, zot)
		}
	}
	open := func(t *testing.T, p string) *os.File {
		t.Helper()
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		return f
	}

	t.Run("start: an unsigned staged zot is re-signed on a new inode", func(t *testing.T) {
		signed := fakeCodesign(t)
		bd := filepath.Join(t.TempDir(), "bin")
		const old = "zot-unsigned"
		stage(t, bd, old, DefaultZotVersion)
		ino, held := zotInode(t, ZotPath(bd)), open(t, ZotPath(bd))
		if err := EnsureZot(t.Context(), bd, "", DefaultZotVersion); err != nil {
			t.Fatal(err)
		}
		replaced(t, ZotPath(bd), ino, held, old, signed())
	})

	t.Run("start: a validly signed zot is untouched", func(t *testing.T) {
		signed := fakeCodesign(t)
		bd := filepath.Join(t.TempDir(), "bin")
		stage(t, bd, "zot"+signedSuffix, DefaultZotVersion)
		ino := zotInode(t, ZotPath(bd))
		if err := EnsureZot(t.Context(), bd, "", DefaultZotVersion); err != nil {
			t.Fatal(err)
		}
		if got := zotInode(t, ZotPath(bd)); got != ino {
			t.Errorf("a validly signed zot was replaced (inode %d -> %d)", ino, got)
		}
		if s := signed(); len(s) != 0 {
			t.Errorf("codesign signed %v, want nothing for a valid signature", s)
		}
	})

	t.Run("re-seed: a new pin from the payload lands on a new inode", func(t *testing.T) {
		signed := fakeCodesign(t)
		bd, payload := filepath.Join(t.TempDir(), "bin"), t.TempDir()
		const old = "old-zot" + signedSuffix
		stage(t, bd, old, "v0.0.1")
		if err := writeFakeBinary(ZotPath(payload), DefaultZotVersion); err != nil {
			t.Fatal(err)
		}
		if err := writeZotMarker(payload, DefaultZotVersion); err != nil {
			t.Fatal(err)
		}
		ino, held := zotInode(t, ZotPath(bd)), open(t, ZotPath(bd))
		if err := EnsureZot(t.Context(), bd, payload, DefaultZotVersion); err != nil {
			t.Fatal(err)
		}
		replaced(t, ZotPath(bd), ino, held, old, signed())
	})

	t.Run("build: a new pin built from source lands on a new inode", func(t *testing.T) {
		signed := fakeCodesign(t)
		bd := filepath.Join(t.TempDir(), "bin")
		const old = "old-zot" + signedSuffix
		stage(t, bd, old, "v0.0.1")
		restore := fakeBuild(t, func(version, gopath string) error {
			return writeFakeBinary(filepath.Join(gopath, "bin", ZotBinaryName), version)
		})
		defer restore()
		ino, held := zotInode(t, ZotPath(bd)), open(t, ZotPath(bd))
		if err := EnsureZot(t.Context(), bd, "", DefaultZotVersion); err != nil {
			t.Fatal(err)
		}
		replaced(t, ZotPath(bd), ino, held, old, signed())
	})
}
