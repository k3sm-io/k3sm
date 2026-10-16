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

import "testing"

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
		{"v01.2.3", "v0.2.0", 0, false},
	}
	for _, tc := range cases {
		cmp, ok := CompareReleases(tc.a, tc.b)
		if cmp != tc.cmp || ok != tc.ok {
			t.Errorf("CompareReleases(%q, %q) = %d, %v; want %d, %v", tc.a, tc.b, cmp, ok, tc.cmp, tc.ok)
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
