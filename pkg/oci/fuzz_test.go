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

package oci

import (
	"errors"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

// This file fuzzes pkg/oci's three trust-boundary surfaces. Every target checks
// its invariant by a DIFFERENT route than the implementation takes, so a target
// cannot pass merely by restating the code it audits:
//
//   - checkEntryName  is a "no ..-component" scan; the oracle is filepath.IsLocal.
//   - checkLinkname   tests a "../" prefix on a relative join; the oracle joins
//     under an absolute pretend-root and tests containment there.
//   - Parse           is checked against its own documented postconditions
//     (bounded input, exactly one FROM, and FROM first).
//
// The direction that matters is ACCEPT ⇒ SAFE. A rejection is always allowed to
// be stricter than the oracle: refusing a legal name costs a build, while
// accepting a traversing one is the tar-bomb these guards exist to prevent.

// FuzzCheckEntryName asserts that any entry name the builder is willing to emit
// stays inside the image root.
//
// Oracle: filepath.IsLocal reports whether a path is lexically confined to the
// directory it is relative to. It is an independent implementation — it does not
// split on "/" and look for "..", it walks the path and tracks depth — and it is
// the stdlib's own answer to this exact question.
func FuzzCheckEntryName(f *testing.F) {
	for _, seed := range []string{
		"", ".", "..", "a", "usr/bin/app", "/etc/passwd", "a/../../etc/passwd",
		"a/..", "../x", `a\b`, "a\x00b", ".wh.gone", "dir/.wh..wh..opq",
		"...", "a//b", "./a", strings.Repeat("a/", 64) + "f",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, name string) {
		err := checkEntryName(name)
		if err == nil {
			if !filepath.IsLocal(name) {
				t.Fatalf("checkEntryName(%q) accepted a name filepath.IsLocal rejects — it can escape the image root", name)
			}
			// A whiteout marker is a deletion instruction to every unpacker.
			for _, part := range strings.Split(name, "/") {
				if strings.HasPrefix(part, ".wh.") {
					t.Fatalf("checkEntryName(%q) accepted an OCI whiteout component %q", name, part)
				}
			}
			return
		}
		// Every rejection must be attributable, so a caller can distinguish a
		// hostile name from an I/O failure.
		if !errors.Is(err, ErrBadEntryName) {
			t.Fatalf("checkEntryName(%q) rejected with %v, which does not wrap ErrBadEntryName", name, err)
		}
	})
}

// FuzzCheckLinkname asserts that no accepted symlink can point outside the image
// root, including via the directory its own name sits in.
//
// It reproduces buildLayer's ORDER (layer.go:174 then :200): checkEntryName gates
// every entry, and checkLinkname only ever sees a name that already passed. That
// precondition is load-bearing, not decoration — fuzzing checkLinkname standalone
// reports ("/", "..") as an escape within seconds, because path.Dir("/") is "/"
// and path.Join("/", "..") cleans back to "/", which is neither ".." nor
// "../"-prefixed. checkEntryName rejects the absolute "/" first, so the pipeline
// never reaches it. TestCheckLinknameNeedsCheckEntryName below pins that
// dependency so a future caller cannot use the guard alone by accident.
//
// Oracle: resolve the link under an absolute pretend-root and require the result
// to remain under that root. The implementation instead tests the RELATIVE join
// for a ".."/"../" prefix; joining under an absolute root and testing containment
// is a different computation that would not share a sign or off-by-one error.
func FuzzCheckLinkname(f *testing.F) {
	for _, seed := range [][2]string{
		{"a/b", "c"}, {"a/b", "../c"}, {"a/b", "../../c"}, {"a", "../x"},
		{"a", ""}, {"a", "/etc/passwd"}, {"a", "b\x00c"}, {"a/b/c", "../../.."},
		{"a", ".."}, {"a/b", "./../../x"}, {"deep/deep/deep/f", "../../../../out"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, name, link string) {
		if checkEntryName(name) != nil {
			return // buildLayer rejects the entry before the link is ever examined
		}
		if checkLinkname(name, link) != nil {
			return // rejections are always safe
		}
		const root = "/img"
		resolved := path.Clean(path.Join(root, path.Dir(name), link))
		if resolved != root && !strings.HasPrefix(resolved, root+"/") {
			t.Fatalf("checkLinkname(%q, %q) accepted a link resolving to %q, outside %q",
				name, link, resolved, root)
		}
	})
}

// FuzzDockerfileParse asserts Parse never panics on arbitrary bytes and that a
// success satisfies the postconditions the package documents: input is bounded,
// the first instruction is FROM, and there is exactly one FROM (no multi-stage).
func FuzzDockerfileParse(f *testing.F) {
	for _, seed := range []string{
		"", "FROM scratch\n", "FROM scratch\nCOPY a b\n", "COPY a b\n",
		"FROM a\nFROM b\n", "# syntax=docker/dockerfile:1\nFROM scratch\n",
		"FROM scratch\nRUN echo hi\n", "FROM scratch\nCOPY a \\\n b\n",
		"FROM scratch\nENTRYPOINT [\"/bin/sh\"]\n", "FROM scratch\nENV a=\"unterminated\n",
		"FROM scratch\nEXPOSE 99999\n", strings.Repeat("#c\n", 512) + "FROM scratch\n",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, src string) {
		df, err := Parse(strings.NewReader(src))
		if err != nil {
			if df != nil {
				t.Fatalf("Parse returned both a Dockerfile and the error %v", err)
			}
			return
		}
		if len(df.Instructions) == 0 {
			t.Fatal("Parse succeeded with no instructions; it documents ErrMissingFrom for that")
		}
		if got := df.Instructions[0].Verb; got != VerbFrom {
			t.Fatalf("Parse succeeded with first instruction %q, want FROM", got)
		}
		froms := 0
		for _, in := range df.Instructions {
			if in.Verb == VerbFrom {
				froms++
			}
			if in.Line <= 0 {
				t.Fatalf("instruction %q reports line %d, want 1-based", in.Verb, in.Line)
			}
		}
		if froms != 1 {
			t.Fatalf("Parse accepted %d FROM instructions, want exactly 1 (multi-stage is unsupported)", froms)
		}
	})
}

// TestCheckLinknameNeedsCheckEntryName pins the precondition FuzzCheckLinkname
// relies on: checkLinkname is NOT a standalone guard. buildLayer must keep
// calling checkEntryName first (layer.go:174 before :200). If a future caller
// invokes checkLinkname alone, these are the inputs that escape.
func TestCheckLinknameNeedsCheckEntryName(t *testing.T) {
	for _, tc := range []struct{ name, link string }{
		{"/", ".."},
		{"/", "../.."},
	} {
		if err := checkLinkname(tc.name, tc.link); err != nil {
			t.Fatalf("checkLinkname(%q, %q) = %v; this test documents that it ACCEPTS "+
				"these — if that changed, delete this test and simplify FuzzCheckLinkname",
				tc.name, tc.link, err)
		}
		if err := checkEntryName(tc.name); err == nil {
			t.Fatalf("checkEntryName(%q) accepted an absolute name; the gate "+
				"FuzzCheckLinkname and buildLayer depend on is gone", tc.name)
		}
	}
}
