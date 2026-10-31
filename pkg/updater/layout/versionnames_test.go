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
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
)

// versionNameCase is one row of testdata/version-names.txt.
type versionNameCase struct {
	line   int
	accept bool
	name   string
}

// readVersionNames parses testdata/version-names.txt, the table of version
// directory names this repo shares byte-for-byte with its sibling; a malformed
// row fails the test rather than being skipped.
func readVersionNames(t *testing.T) []versionNameCase {
	t.Helper()
	f, err := os.Open("testdata/version-names.txt")
	if err != nil {
		t.Fatalf("open the version-name table: %v", err)
	}
	defer f.Close()
	var cases []versionNameCase
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		verdict, quoted, ok := strings.Cut(line, " ")
		if !ok || (verdict != "accept" && verdict != "refuse") {
			t.Fatalf("version-names.txt:%d: want \"accept|refuse <quoted name>\", got %q", n, line)
		}
		name, err := strconv.Unquote(quoted)
		if err != nil {
			t.Fatalf("version-names.txt:%d: unquote %s: %v", n, quoted, err)
		}
		cases = append(cases, versionNameCase{line: n, accept: verdict == "accept", name: name})
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read the version-name table: %v", err)
	}
	var accepts, refuses int
	for _, c := range cases {
		if c.accept {
			accepts++
		} else {
			refuses++
		}
	}
	if accepts == 0 || refuses == 0 {
		t.Fatalf("version-name table holds %d accepts and %d refuses; both must be non-empty", accepts, refuses)
	}
	return cases
}

// TestValidateVersionNamesMatchTable runs ValidateVersion over the shared table of version directory names, so this
// repo's rule and its sibling's cannot drift apart unnoticed.
func TestValidateVersionNamesMatchTable(t *testing.T) {
	for _, c := range readVersionNames(t) {
		t.Run(strconv.Itoa(c.line), func(t *testing.T) {
			if got := ValidateVersion(c.name) == nil; got != c.accept {
				t.Errorf("version-names.txt:%d: %s(%q) accepted=%v, the table says %v", c.line, "ValidateVersion", c.name, got, c.accept)
			}
		})
	}
}
