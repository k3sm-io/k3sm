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

package ref

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseName(t *testing.T) {
	cases := []struct {
		in   string
		want error
	}{
		{"app", nil},
		{"library/ubuntu", nil},
		{"org/team/app", nil},
		{"a.b/c__d/e--f/g_h", nil},
		{"foo.com/bar", nil},
		{"localhost/app", nil},
		{"cache.db/x", ErrReservedName},
		{"meta.db", ErrReservedName},
		{"htpasswd", ErrReservedName},
		{"config.json", ErrReservedName},
		{"push-credential.json", ErrReservedName},
		{"x/cache.db", nil},
		{"a/blobs", ErrReservedName},
		{"blobs/a", ErrReservedName},
		{"a/index.json", ErrReservedName},
		{"a/oci-layout/b", ErrReservedName},
		{"a/.uploads", ErrInvalidName},
		{".hidden", ErrInvalidName},
		{"", ErrInvalidName},
		{"App", ErrInvalidName},
		{"localhost:5000/app", ErrInvalidName},
		{"a//b", ErrInvalidName},
		{"a/", ErrInvalidName},
		{"/a", ErrInvalidName},
		{"a/../b", ErrInvalidName},
		{"a/./b", ErrInvalidName},
		{"a\\b", ErrInvalidName},
		{"a%2fb", ErrInvalidName},
		{"a b", ErrInvalidName},
		{"a\x00b", ErrInvalidName},
		{"a-", ErrInvalidName},
		{"a___b", ErrInvalidName},
		{"a:tag", ErrInvalidName},
		{"a@sha256:" + strings.Repeat("0", 64), ErrInvalidName},
		{strings.Repeat("a", 255), nil},
		{strings.Repeat("a", 256), ErrInvalidName},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			n, err := ParseName(c.in)
			if c.want == nil {
				if err != nil {
					t.Fatalf("ParseName(%q) = %v, want accepted", c.in, err)
				}
				if n.String() != c.in {
					t.Fatalf("String() = %q, want %q", n.String(), c.in)
				}
				return
			}
			if !errors.Is(err, c.want) {
				t.Fatalf("ParseName(%q) = %v, want %v", c.in, err, c.want)
			}
		})
	}
}

// lookalikes are names a case-folding or Unicode-normalising volume could map
// onto an accepted ASCII name, or that differ from one only invisibly.
var lookalikes = []string{
	"\uff41pp",                      // fullwidth a
	"\u0430pp",                      // Cyrillic a
	"\u212a8s",                      // KELVIN SIGN, folds to k
	"caf\u00e9",                     // NFC e-acute
	"cafe\u0301",                    // NFD e + combining acute
	"app ",                          // trailing space
	"app.",                          // trailing dot
	"app/",                          // trailing slash
	"apP",                           // uppercase
	"a/" + strings.Repeat("b", 254), // one component past the total cap
	strings.Repeat("c", 256),
	"app\u200b",  // zero-width space
	"\u0131mage", // dotless i, uppercases to I
	"\u017fha",   // long s, folds to s
}

func TestParseNameRefusesLookalikes(t *testing.T) {
	for _, s := range lookalikes {
		if n, err := ParseName(s); !errors.Is(err, ErrInvalidName) {
			t.Errorf("ParseName(%q) = %v, %v; want ErrInvalidName", s, n, err)
		}
	}
	for i := 0; i < 256; i++ {
		s := "a" + string(rune(i)) + "b"
		_, err := ParseName(s)
		if err == nil && !nameByte(byte(i)) {
			t.Errorf("ParseName accepted byte %#x", i)
		}
	}
}

func TestParseReference(t *testing.T) {
	hex64 := strings.Repeat("ab", 32)
	cases := []struct {
		in   string
		want error
	}{
		{"latest", nil},
		{"V1.2_x-y", nil},
		{"_x", nil},
		{strings.Repeat("t", 128), nil},
		{strings.Repeat("t", 129), ErrInvalidTag},
		{".x", ErrInvalidTag},
		{"-x", ErrInvalidTag},
		{"", ErrInvalidTag},
		{"a/b", ErrInvalidTag},
		{"sha256:" + hex64, nil},
		{"sha512:" + hex64 + hex64, nil},
		{"sha384:" + hex64 + hex64[:32], ErrInvalidDigest},
		{"sha256:" + strings.ToUpper(hex64), ErrInvalidDigest},
		{"sha256:" + hex64[:63], ErrInvalidDigest},
		{"sha256:", ErrInvalidDigest},
		{"md5:" + hex64[:32], ErrInvalidDigest},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			r, err := ParseReference(c.in)
			if c.want == nil {
				if err != nil || r.String() != c.in {
					t.Fatalf("ParseReference(%q) = %v, %v", c.in, r, err)
				}
				return
			}
			if !errors.Is(err, c.want) {
				t.Fatalf("ParseReference(%q) = %v, want %v", c.in, err, c.want)
			}
		})
	}
}

func TestParseUploadID(t *testing.T) {
	for in, ok := range map[string]bool{
		"5cfa3280-d4d1-48b9-b18e-38fbb939dd06": true,
		"5CFA3280-d4d1-48b9-b18e-38fbb939dd06": false,
		"5cfa3280d4d148b9b18e38fbb939dd06":     false,
		"../../../../../../../../../../../etc": false,
		"5cfa3280-d4d1-48b9-b18e-38fbb939dd0g": false,
		"":                                     false,
	} {
		if _, err := ParseUploadID(in); (err == nil) != ok {
			t.Errorf("ParseUploadID(%q) = %v, want ok=%v", in, err, ok)
		}
	}
}

func TestDirMapping(t *testing.T) {
	root := t.TempDir()
	n, err := ParseName("org/team/app")
	if err != nil {
		t.Fatal(err)
	}
	dir, err := n.Dir(root)
	if err != nil || dir != filepath.Join(root, "org", "team", "app") {
		t.Fatalf("Dir = %q, %v", dir, err)
	}
	back, err := NameFromDir(root, dir)
	if err != nil || back != n {
		t.Fatalf("NameFromDir = %v, %v", back, err)
	}
	if _, err := NameFromDir(root, filepath.Dir(root)); !errors.Is(err, ErrOutsideRoot) {
		t.Fatalf("NameFromDir above root = %v, want ErrOutsideRoot", err)
	}
	if _, err := (Name{}).Dir(root); err == nil {
		t.Fatal("zero Name mapped to a directory")
	}
}

func TestResolveDirRefusesSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "org"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "org", "team")); err != nil {
		t.Fatal(err)
	}
	n, _ := ParseName("org/team/app")
	if _, err := n.ResolveDir(root); !errors.Is(err, ErrSymlink) {
		t.Fatalf("ResolveDir through a symlink = %v, want ErrSymlink", err)
	}
	ok, _ := ParseName("org/other/app")
	if _, err := ok.ResolveDir(root); err != nil {
		t.Fatalf("ResolveDir of a missing path = %v, want nil", err)
	}
	linkRoot := filepath.Join(t.TempDir(), "root")
	if err := os.Symlink(root, linkRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := ok.ResolveDir(linkRoot); !errors.Is(err, ErrSymlink) {
		t.Fatalf("ResolveDir under a symlinked root = %v, want ErrSymlink", err)
	}
}
