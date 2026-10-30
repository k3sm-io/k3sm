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
	"path/filepath"
	"strings"
	"testing"
)

// nameSeeds are the corpus both name fuzzers start from: accepted names, the
// near misses the push gate's corpus refuses, and the store's reserved words.
var nameSeeds = []string{
	"app", "org/team/app", "a.b/c__d/e--f", "foo.com/bar", "localhost/app",
	"a/blobs", "a/index.json", "a/oci-layout", "a/.uploads", ".x", "cache.db",
	"meta.db/x", "App", "a//b", "a/../b", "a/./b", "../a", "a\\b", "a%2fb",
	"localhost:5000/a", "a\x00", "a-", "_a", "a/" + strings.Repeat("b", 254),
}

// FuzzParseName holds every accepted name to the mapping's contract: it maps
// under the root, back to itself, and holds no reserved or dot component.
func FuzzParseName(f *testing.F) {
	for _, s := range nameSeeds {
		f.Add(s)
	}
	root := filepath.FromSlash("/store/root")
	for _, s := range lookalikes {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, err := ParseName(s)
		if err != nil {
			return
		}
		for i := 0; i < len(s); i++ {
			if !nameByte(s[i]) {
				t.Fatalf("accepted %q with byte %#x", s, s[i])
			}
		}
		if n.String() != s || len(s) > MaxNameLength || strings.ToLower(s) != s {
			t.Fatalf("accepted %q", s)
		}
		for _, c := range n.Components() {
			if c == "" || strings.HasPrefix(c, ".") || layoutWords[c] {
				t.Fatalf("accepted %q with component %q", s, c)
			}
		}
		dir, err := n.Dir(root)
		if err != nil {
			t.Fatalf("Dir(%q) = %v", s, err)
		}
		if !strings.HasPrefix(dir, root+string(filepath.Separator)) {
			t.Fatalf("Dir(%q) = %q escapes %q", s, dir, root)
		}
		back, err := NameFromDir(root, dir)
		if err != nil || back != n {
			t.Fatalf("NameFromDir(Dir(%q)) = %v, %v", s, back, err)
		}
	})
}

// FuzzNameDirInjective checks that two different accepted names never map to
// one directory, compared case-insensitively as an APFS volume compares.
func FuzzNameDirInjective(f *testing.F) {
	for i, a := range nameSeeds {
		f.Add(a, nameSeeds[(i+1)%len(nameSeeds)])
	}
	f.Add("a/b", "a/b/")
	f.Add("a.b", "a/b")
	f.Fuzz(func(t *testing.T, a, b string) {
		na, errA := ParseName(a)
		nb, errB := ParseName(b)
		if errA != nil || errB != nil || a == b {
			return
		}
		da, _ := na.Dir("/r")
		db, _ := nb.Dir("/r")
		if strings.EqualFold(da, db) {
			t.Fatalf("%q and %q both map to %q", a, b, da)
		}
	})
}

// FuzzParseReference checks that an accepted reference is exactly one of a tag
// or a canonical digest and spells back to its input.
func FuzzParseReference(f *testing.F) {
	for _, s := range []string{
		"latest", "v1.0", "_x", ".x", "-x", "a/b", strings.Repeat("t", 129),
		"sha256:" + strings.Repeat("0", 64), "sha512:" + strings.Repeat("0", 128),
		"sha256:" + strings.Repeat("A", 64), "sha384:" + strings.Repeat("0", 96),
		"sha256+b64:abcd", "sha256:", ":", "a:b",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := ParseReference(s)
		if err != nil {
			return
		}
		if (r.Tag == "") == (r.Digest == "") || r.String() != s {
			t.Fatalf("ParseReference(%q) = %+v", s, r)
		}
		if r.Tag != "" && (len(r.Tag) > MaxTagLength || strings.ContainsAny(r.Tag, "/:@")) {
			t.Fatalf("accepted tag %q", s)
		}
	})
}

// FuzzParseUploadID checks that an accepted session id is a single path
// element.
func FuzzParseUploadID(f *testing.F) {
	f.Add("5cfa3280-d4d1-48b9-b18e-38fbb939dd06")
	f.Add("../../../../../../../../../../../etc")
	f.Add("5cfa3280-d4d1-48b9-b18e-38fbb939dd0/")
	f.Fuzz(func(t *testing.T, s string) {
		if _, err := ParseUploadID(s); err == nil && (filepath.Base(s) != s || strings.ContainsAny(s, "./\\")) {
			t.Fatalf("accepted %q", s)
		}
	})
}
