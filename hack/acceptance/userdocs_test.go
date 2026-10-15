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

package acceptance

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var (
	changelogHeading = regexp.MustCompile(`(?m)^## v(\d+)\.(\d+)\.(\d+)`)
	installPin       = regexp.MustCompile(`K3SM_INSTALL_VERSION=v(\d+)\.(\d+)\.(\d+)`)
)

// parseVersion converts the three captured components into a comparable triple.
func parseVersion(t *testing.T, m []string) [3]int {
	t.Helper()
	var v [3]int
	for i := range v {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			t.Fatalf("parse version component %q: %v", m[i+1], err)
		}
		v[i] = n
	}
	return v
}

func versionLess(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// TestUserDocsNameNoStaleVersionPin fails when a user page pins an install
// version older than the newest release in CHANGELOG.md, or refers to a table
// row the page does not show.
func TestUserDocsNameNoStaleVersionPin(t *testing.T) {
	root := repoRoot(t)
	changelog, err := os.ReadFile(filepath.Join(root, "CHANGELOG.md"))
	if err != nil {
		t.Fatalf("read changelog: %v", err)
	}
	var newest [3]int
	heads := changelogHeading.FindAllStringSubmatch(string(changelog), -1)
	if len(heads) == 0 {
		t.Fatal("CHANGELOG.md has no release heading")
	}
	for _, h := range heads {
		if v := parseVersion(t, h); versionLess(newest, v) {
			newest = v
		}
	}

	pages, err := filepath.Glob(filepath.Join(root, "docs", "user", "*.md"))
	if err != nil || len(pages) == 0 {
		t.Fatalf("list docs/user pages: %v (found %d)", err, len(pages))
	}
	for _, page := range pages {
		raw, err := os.ReadFile(page)
		if err != nil {
			t.Fatalf("read %s: %v", page, err)
		}
		name := filepath.Base(page)
		for _, m := range installPin.FindAllStringSubmatch(string(raw), -1) {
			if versionLess(parseVersion(t, m), newest) {
				t.Errorf("%s pins %s, older than the newest release in CHANGELOG.md", name, m[0])
			}
		}
		if strings.Contains(strings.ReplaceAll(string(raw), "`", ""), "The install row") {
			t.Errorf("%s says \"The install row\" with no table on the page", name)
		}
	}
}
