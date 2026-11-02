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

package layout

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestValidateVersionNamesMatchTable runs ValidateVersion over the shared
// table of version directory names, so this repo's rule and its sibling's
// cannot drift apart unnoticed.
func TestValidateVersionNamesMatchTable(t *testing.T) {
	checkVersionNames(t, "ValidateVersion", func(_ *testing.T, name string) bool {
		return ValidateVersion(name) == nil
	})
}

// TestCheckActivatableUsesVersionRule drives CheckActivatable, a production
// consumer of ValidateVersion, over every row of the shared table, so a
// different rule inlined there goes red even while ValidateVersion stays right.
func TestCheckActivatableUsesVersionRule(t *testing.T) {
	checkVersionNames(t, "CheckActivatable", func(t *testing.T, name string) bool {
		err := CheckActivatable(name, false)
		if err != nil && !errors.Is(err, ErrBadVersion) {
			t.Fatalf("CheckActivatable(%q, false) = %v, want nil or ErrBadVersion", name, err)
		}
		return err == nil
	})
}

// TestResolveActiveUsesVersionRule drives ResolveActive over a current link
// reading versions/<name> for every row of the shared table: the link resolves
// exactly when the table accepts the name, and to that name.
func TestResolveActiveUsesVersionRule(t *testing.T) {
	l := New("/k3sm-root")
	checkVersionNames(t, "ResolveActive(versions/<name>)", func(t *testing.T, name string) bool {
		readlink := func(link string) (string, error) {
			if link != l.Current() {
				return "", fmt.Errorf("readlink of %s, want only %s", link, l.Current())
			}
			return VersionsName + "/" + name, nil
		}
		ver, err := l.ResolveActive(readlink)
		if err != nil {
			if !errors.Is(err, ErrBadLink) {
				t.Fatalf("ResolveActive(versions/%q) = %v, want nil or ErrBadLink", name, err)
			}
			return false
		}
		if ver != name {
			t.Fatalf("ResolveActive(versions/%q) = %q, want the name itself", name, ver)
		}
		return true
	})
}

// TestIsUnknownVersionMatchesTable checks IsUnknownVersion against every row
// of the shared table: it is true exactly for the accepted unknown- rows, so a
// refused unknown- spelling, or a release name, is never taken for one.
func TestIsUnknownVersionMatchesTable(t *testing.T) {
	var accepted, refused int
	for _, c := range readVersionNames(t) {
		want := c.accept && strings.HasPrefix(c.name, "unknown-")
		if strings.HasPrefix(c.name, "unknown-") {
			if c.accept {
				accepted++
			} else {
				refused++
			}
		}
		t.Run(versionSubtest(c.name), func(t *testing.T) {
			if got := IsUnknownVersion(c.name); got != want {
				t.Errorf("version-names.txt:%d: IsUnknownVersion(%q) = %v, want %v", c.line, c.name, got, want)
			}
		})
	}
	if accepted == 0 || refused == 0 {
		t.Fatalf("the table holds %d accepted and %d refused unknown- rows; both must be non-empty", accepted, refused)
	}
}
