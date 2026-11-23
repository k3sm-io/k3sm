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
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// U50: a log whose st_flags carry any bit beside SF_APPEND is refused as
// untrusted: an immutable or user append-only flag is not what install
// sets, and an owner who could set one could later clear it.
func TestLogRefusesExtraFlags(t *testing.T) {
	ctx := context.Background()
	s, _, u := fileLogScope(t)
	for _, extra := range []uint32{unix.UF_IMMUTABLE, unix.UF_APPEND, unix.SF_IMMUTABLE} {
		t.Run(fmt.Sprintf("%#x", extra), func(t *testing.T) {
			s.logFlags = func(*os.File) (uint32, error) { return sfAppend | extra, nil }
			defer func() { s.logFlags = flagged }()
			if _, _, err := u.Current(ctx, "user/1001/token"); !errors.Is(err, errLogUntrusted) {
				t.Fatalf("current over a floor flagged %#x: %v, want errLogUntrusted", sfAppend|extra, err)
			}
		})
	}
}

// U50: a data root carrying any flag beside SF_APPEND is refused.
func TestLogDataRootRefusesExtraFlags(t *testing.T) {
	ctx := context.Background()
	s, _, u := fileLogScope(t)
	if err := unix.Chflags(s.dataRoot, unix.UF_IMMUTABLE); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Chflags(s.dataRoot, 0) })
	if _, _, err := u.Current(ctx, "user/1001/token"); !errors.Is(err, errLogUntrusted) || strings.Contains(err.Error(), s.dataRoot) {
		t.Fatalf("current under a data root flagged uchg: %v, want errLogUntrusted naming no path", err)
	}
	if err := unix.Chflags(s.dataRoot, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := u.Current(ctx, "user/1001/token"); err != nil {
		t.Fatalf("current once the flag is cleared: %v", err)
	}
}

// U50: a log or data root with a non-empty extended ACL is refused: an ACL
// can grant a write the mode does not show. The ACL is a real one, written
// with chmod +a and read back through fgetattrlist on the descriptor.
func TestLogRefusesExtendedACL(t *testing.T) {
	ctx := context.Background()
	s, _, u := fileLogScope(t)
	for _, p := range []string{filepath.Join(s.dataRoot, logsDirName, floorDirName, userFloorLogName), s.dataRoot} {
		t.Run(filepath.Base(p), func(t *testing.T) {
			if out, err := exec.Command("/bin/chmod", "+a", "everyone deny delete", p).CombinedOutput(); err != nil {
				t.Fatalf("chmod +a: %v: %s", err, out)
			}
			clear := func() {
				if out, err := exec.Command("/bin/chmod", "-N", p).CombinedOutput(); err != nil {
					t.Fatalf("chmod -N: %v: %s", err, out)
				}
			}
			defer clear()
			if _, _, err := u.Current(ctx, "user/1001/token"); !errors.Is(err, errLogUntrusted) {
				t.Fatalf("current with an ACL on %s: %v, want errLogUntrusted", p, err)
			}
			clear()
			if _, _, err := u.Current(ctx, "user/1001/token"); err != nil {
				t.Fatalf("current once the ACL is removed: %v", err)
			}
		})
	}
}
