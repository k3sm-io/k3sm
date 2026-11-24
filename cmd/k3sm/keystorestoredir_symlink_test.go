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

package main

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/keystore"
)

// repairCommand is a chown, chmod or chflags named in a remedy, with what
// follows it and the text before it.
var repairCommand = regexp.MustCompile(`\b(chown|chmod|chflags)\b`)

// symlinkGuard is the test ! -L <path> && a command may follow instead of
// taking -h.
var symlinkGuard = regexp.MustCompile(`test ! -L \S+ && (sudo )?$`)

// symlinkUnsafeRepairs returns every chown, chmod or chflags text names
// that would follow a symlink: one whose first argument is not -h and that
// is not preceded by test ! -L <path> &&.
func symlinkUnsafeRepairs(text string) []string {
	var bad []string
	for _, m := range repairCommand.FindAllStringIndex(text, -1) {
		rest := strings.Fields(text[m[1]:])
		if len(rest) > 0 && strings.TrimRight(rest[0], ",;)") == "-h" {
			continue
		}
		if symlinkGuard.MatchString(text[:m[0]]) {
			continue
		}
		end := min(len(text), m[1]+40)
		bad = append(bad, text[m[0]:end])
	}
	return bad
}

// TestStoreDirRepairIsSymlinkSafe: every root repair command a store
// directory remedy can name (storeDirRepair, storeDirAccessRepair over
// every denial shape dirRepairSteps reads) takes -h or is guarded by
// test ! -L, since the service user can plant a symlink at the store
// directory and a root chown, chmod or chflags that followed it would
// change whatever it points at.
func TestStoreDirRepairIsSymlinkSafe(t *testing.T) {
	const uid, gid = 270, 270
	texts := []string{storeDirRepair}
	for _, cause := range []keystore.DenialCause{keystore.DeniedParent, keystore.DeniedForeign, keystore.DeniedOwn} {
		for bits := range 1 << 5 {
			for _, owner := range []uint32{0, uid, 501} {
				for _, mode := range []fs.FileMode{0, 0o700} {
					d := keystore.DirDenial{
						Cause:       cause,
						Path:        "/var/lib/k3sm/server/keystore",
						Unreachable: bits&1 != 0,
						Immutable:   bits&2 != 0,
						ACL:         bits&4 != 0,
						ACLUnknown:  bits&8 != 0,
						Known:       bits&16 != 0,
						Owner:       owner,
						Mode:        mode,
					}
					texts = append(texts, storeDirAccessRepair(d, uid, gid))
				}
			}
		}
	}
	commands := 0
	for _, text := range texts {
		commands += len(repairCommand.FindAllString(text, -1))
		if bad := symlinkUnsafeRepairs(text); len(bad) > 0 {
			t.Errorf("a remedy names a root repair that follows a symlink, %q, in: %s", bad, text)
		}
	}
	if commands == 0 {
		t.Fatal("no remedy named a repair command: the parse found nothing to check")
	}
	if bad := symlinkUnsafeRepairs("chown 270:270 /p, then test ! -L /p && chmod 700 /p, then chmod -h -N /p"); len(bad) != 1 || !strings.HasPrefix(bad[0], "chown 270") {
		t.Fatalf("the parse itself: %q, want the one unguarded chown", bad)
	}
}
