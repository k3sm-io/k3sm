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
	"strings"
	"testing"
)

// refTempBase is the base name of n when n is a temporary file writeFile
// makes, ".<base>.<16 lowercase hex>.tmp" with a base that is not empty,
// written apart from tempBase for FuzzStagedChild to check it against.
func refTempBase(n string) (string, bool) {
	const hexLen = 2 * tempSuffixSize
	if len(n) < len(".")+1+len(".")+hexLen+len(".tmp") || n[0] != '.' || !strings.HasSuffix(n, ".tmp") {
		return "", false
	}
	mid := n[1 : len(n)-len(".tmp")]
	hexPart, dot, base := mid[len(mid)-hexLen:], mid[len(mid)-hexLen-1], mid[:len(mid)-hexLen-1]
	if dot != '.' || base == "" {
		return "", false
	}
	for _, c := range []byte(hexPart) {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return "", false
		}
	}
	return base, true
}

// refVersion reports whether n is v<N>, N from 1 to maxVersion in canonical
// decimal.
func refVersion(n string) bool {
	d, ok := strings.CutPrefix(n, "v")
	if !ok || d == "" || len(d) > 5 || d[0] == '0' {
		return false
	}
	v := 0
	for _, c := range []byte(d) {
		if c < '0' || c > '9' {
			return false
		}
		v = v*10 + int(c-'0')
	}
	return v <= maxVersion
}

// refEntryFileCap is entryFileCap written apart: generation, current and
// v<N> with the .new sibling of the last two, each or its temporary file.
func refEntryFileCap(n string) (int64, bool) {
	if base, ok := refTempBase(n); ok {
		n = base
	}
	switch {
	case n == "generation":
		return int64(generationFileSize), true
	case n == "current", n == "current.new":
		return int64(maxRecordSize), true
	case refVersion(n), strings.HasSuffix(n, ".new") && refVersion(strings.TrimSuffix(n, ".new")):
		return int64(maxRecordSize), true
	}
	return 0, false
}

// refScopeFileCap is scopeFileCap written apart.
func refScopeFileCap(n string) (int64, bool) {
	if base, ok := refTempBase(n); ok {
		n = base
	}
	switch n {
	case "scope.key", "scope.key.new":
		return int64(maxScopeKeyRecordSize), true
	case "deliveries":
		return int64(maxDeliveriesRecordSize), true
	}
	return 0, false
}

// FuzzStagedChild (U192) drives the staged tree's entry-file allowlist,
// stagedChild, with any name under each kind of node, and checks it against
// an allowlist written apart from it: no name that is empty, "." or "..", or
// holds a slash or a NUL is ever accepted; a file is accepted under an
// entry or a user scope exactly when the store writes that name there, with
// the same cap, its temporary file included; a directory has no cap; and a
// name tempBase reads as temporary is one isTempName accepts.
func FuzzStagedChild(f *testing.F) {
	for _, n := range []string{
		"", ".", "..", "a/b", "a\x00", ".lock", ".user", "k", "k.example", "-k",
		"generation", "generation.new", "current", "current.new", "v1", "v0", "v01", "v65536", "v65537", "v1.new", "v1.new.new",
		".current.0123456789abcdef.tmp", ".current.0123456789ABCDEF.tmp", ".current.0123456789abcde.tmp", "..0123456789abcdef.tmp",
		".v2.new.fedcba9876543210.tmp", ".generation.0000000000000000.tmp",
		"scope.key", "scope.key.new", "deliveries", "entries", ".scope.key.0123456789abcdef.tmp",
		"501", "500", "0501", "2147483647", "2147483648", "+501",
	} {
		f.Add(n)
	}
	f.Fuzz(func(t *testing.T, name string) {
		bad := name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00")
		for _, parent := range []stagedKind{stagedTree, stagedEntry, stagedUsers, stagedScope, stagedScopeEntries} {
			kind, size, ok := stagedChild(parent, name)
			if !ok {
				if size != 0 || kind != 0 {
					t.Fatalf("stagedChild(%d, %q) refused it with kind %d, cap %d", parent, name, kind, size)
				}
				continue
			}
			if bad {
				t.Fatalf("stagedChild(%d, %q) accepted a name no directory entry may have", parent, name)
			}
			if kind != stagedFile && size != 0 {
				t.Fatalf("stagedChild(%d, %q) = kind %d with cap %d, want no cap on a directory", parent, name, kind, size)
			}
		}
		wantE, okE := refEntryFileCap(name)
		if kind, size, ok := stagedChild(stagedEntry, name); ok != okE || ok && (kind != stagedFile || size != wantE) {
			t.Fatalf("under an entry %q = kind %d, cap %d, %v; want a file capped at %d, %v", name, kind, size, ok, wantE, okE)
		}
		wantS, okS := refScopeFileCap(name)
		kind, size, ok := stagedChild(stagedScope, name)
		switch {
		case name == scopeEntriesName:
			if !ok || kind != stagedScopeEntries {
				t.Fatalf("under a scope %q = kind %d, %v; want the entries directory", name, kind, ok)
			}
		case ok != okS || ok && (kind != stagedFile || size != wantS):
			t.Fatalf("under a scope %q = kind %d, cap %d, %v; want a file capped at %d, %v", name, kind, size, ok, wantS, okS)
		}
		if kind, _, ok := stagedChild(stagedUsers, name); ok && (kind != stagedScope || !scopeDirName(name)) {
			t.Fatalf("under the user scopes %q = kind %d; want only a scope uid", name, kind)
		}
		if kind, _, ok := stagedChild(stagedScopeEntries, name); ok != (checkName(name) == nil) || ok && kind != stagedEntry {
			t.Fatalf("under a scope's entries %q = kind %d, %v; want an entry exactly for a valid name", name, kind, ok)
		}
		base, ok := tempBase(name)
		rb, rok := refTempBase(name)
		if ok && !isTempName(name, base) {
			t.Fatalf("tempBase(%q) = %q, which isTempName refuses", name, base)
		}
		if ok != rok || ok && base != rb {
			t.Fatalf("tempBase(%q) = %q, %v; want %q, %v", name, base, ok, rb, rok)
		}
	})
}
