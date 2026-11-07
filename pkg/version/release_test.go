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

package version

import (
	"os"
	"strings"
	"testing"
)

func TestValidTag(t *testing.T) {
	for tag, want := range map[string]bool{
		"v0.1.7": true, "0.1.7": true, "v0.2.0-rc.1": true, "v1+meta_x": true,
		"": false, "-v1": false, "v1/../x": false, "v1 2": false, "v1;rm": false, "v1$(x)": false,
		"v1\n": false, string(make([]byte, 129)): false,
	} {
		if got := ValidTag(tag); got != want {
			t.Errorf("ValidTag(%q) = %v, want %v", tag, got, want)
		}
	}
}

// TestCanonicalTagCorpus holds the grammar to testdata/release-tags.txt: every
// verdict matches, every refused tag is one ValidTag would let through (so the
// grammar is what refuses it), and every canonical tag orders under
// CompareReleases, which is how a channel ranks them.
func TestCanonicalTagCorpus(t *testing.T) {
	data, err := os.ReadFile("testdata/release-tags.txt")
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for line := range strings.Lines(string(data)) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || (fields[0] != "canonical" && fields[0] != "refused") {
			t.Fatalf("malformed corpus line %q", line)
		}
		verdict, tag := fields[0], fields[1]
		counts[verdict]++
		if got := CanonicalTag(tag); got != (verdict == "canonical") {
			t.Errorf("CanonicalTag(%q) = %v, corpus says %s", tag, got, verdict)
		}
		if !ValidTag(tag) {
			t.Errorf("corpus tag %q fails ValidTag, so it proves nothing about the grammar", tag)
		}
		if verdict == "canonical" {
			if _, ok := CompareReleases(tag, "v0.0.0"); !ok {
				t.Errorf("canonical tag %q does not order under CompareReleases", tag)
			}
		}
	}
	if counts["canonical"] == 0 || counts["refused"] == 0 {
		t.Fatalf("corpus verdicts = %v, want both kinds", counts)
	}
}

// TestCanonicalTagWholeString pins what a line-based corpus cannot carry: a tag
// with a line break or a space around it is not canonical.
func TestCanonicalTagWholeString(t *testing.T) {
	for _, tag := range []string{"", "v0.3.0\n", "\nv0.3.0", "v0.3.0\nv0.3.1", " v0.3.0", "v0.3.0 "} {
		if CanonicalTag(tag) {
			t.Errorf("CanonicalTag(%q) = true", tag)
		}
	}
}

// TestCompareReleases pins semver precedence and what is not a release.
func TestCompareReleases(t *testing.T) {
	cases := []struct {
		a, b string
		cmp  int
		ok   bool
	}{
		{"v0.2.0", "0.2.0", 0, true},
		{"0.1.7", "v0.2.0", -1, true},
		{"0.10.0", "0.9.0", 1, true},
		{"v0.2.0-rc.1", "v0.2.0", -1, true},
		{"v0.2.0-rc.2", "v0.2.0-rc.10", -1, true},
		{"v0.2.0-rc.1", "v0.2.0-rc", 1, true},
		{"v0.2.0-1", "v0.2.0-alpha", -1, true},
		{"v0.2.0+build.5", "v0.2.0", 0, true},
		{"dev", "v0.2.0", 0, false},
		{"0.2.0.dirty", "v0.2.0", 0, false},
		{"v0.0.0-20261015120000-0123456789ab", "v0.2.0", 0, false},
		{"v0.2.1-0.20261015120000-0123456789ab", "v0.2.0", 0, false},
		{"0.2.1-0.20261015120000-0123456789ab.dirty", "v0.2.0", 0, false},
		{"v0.2.1-0.20261015120000-0123456789ab+dirty", "v0.2.0", 0, false},
		{"v0.2.0-rc.20261015120000", "v0.2.0", -1, true},
		{"v01.2.3", "v0.2.0", 0, false},
	}
	for _, tc := range cases {
		cmp, ok := CompareReleases(tc.a, tc.b)
		if cmp != tc.cmp || ok != tc.ok {
			t.Errorf("CompareReleases(%q, %q) = %d, %v; want %d, %v", tc.a, tc.b, cmp, ok, tc.cmp, tc.ok)
		}
	}
}

// TestCompareBuild pins the display comparison: a tagged build orders as
// CompareReleases does, a Go pseudo-version ranks by its core and prerelease
// and names its core, and a dev or dirty build, or an untagged release side,
// does not compare.
func TestCompareBuild(t *testing.T) {
	const stamp = "20261025152241-96fbff948562"
	cases := []struct {
		build, release string
		cmp            int
		untaggedOf     string
		ok             bool
	}{
		{"v0.2.0", "0.2.0", 0, "", true},
		{"0.1.7", "v0.2.0", -1, "", true},
		{"v0.2.0-rc.1", "v0.2.0", -1, "", true},
		{"v0.1.8-0." + stamp, "v0.1.7", 1, "0.1.8", true},
		{"0.1.8-0." + stamp, "v0.1.8", -1, "0.1.8", true},
		{"v0.1.8-0." + stamp, "v0.1.8-rc.1", -1, "0.1.8", true},
		{"v0.1.8-rc.1.0." + stamp, "v0.1.8-rc.1", 1, "0.1.8", true},
		{"v0.0.0-" + stamp, "v0.1.7", -1, "0.0.0", true},
		{"v0.1.8-0." + stamp + "+dirty", "v0.1.7", 0, "", false},
		{"0.1.8-0." + stamp + ".dirty", "v0.1.7", 0, "", false},
		{"v0.2.0+dirty", "v0.1.7", 0, "", false},
		{"0.2.0.dirty", "v0.1.7", 0, "", false},
		{"dev", "v0.1.7", 0, "", false},
		{"v0.1.7", "v0.1.8-0." + stamp, 0, "", false},
	}
	for _, tc := range cases {
		cmp, of, ok := CompareBuild(tc.build, tc.release)
		if cmp != tc.cmp || of != tc.untaggedOf || ok != tc.ok {
			t.Errorf("CompareBuild(%q, %q) = %d, %q, %v; want %d, %q, %v", tc.build, tc.release, cmp, of, ok, tc.cmp, tc.untaggedOf, tc.ok)
		}
	}
}

func TestNodeRelease(t *testing.T) {
	if rel, ok := NodeRelease((Info{KubeVersion: "v1.37.1", Version: "v0.2.0"}).NodeVersion()); !ok || rel != "0.2.0" {
		t.Errorf("NodeRelease = %q, %v", rel, ok)
	}
	if rel, ok := NodeRelease((Info{KubeVersion: "v1.37.1", Version: "0.2.0", Dirty: true}).NodeVersion()); !ok || rel != "0.2.0.dirty" {
		t.Errorf("dirty NodeRelease = %q, %v", rel, ok)
	}
	for _, v := range []string{"v1.37.1", "v1.37.1+k3sm.", ""} {
		if _, ok := NodeRelease(v); ok {
			t.Errorf("NodeRelease(%q) names a release", v)
		}
	}
}
