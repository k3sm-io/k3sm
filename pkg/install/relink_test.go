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

package install

import (
	"errors"
	"testing"

	"k3sm.io/k3sm/pkg/shadow"
)

// TestShadowCopiesCarryRelink pins that the one Relink entry of runtimed's
// list reaches the installer: the xcodebuild copy, cloned out of Xcode.app.
func TestShadowCopiesCarryRelink(t *testing.T) {
	var relinked []string
	for _, c := range shadow.Copies() {
		if c.Relink {
			relinked = append(relinked, c.Name)
		}
	}
	if len(relinked) != 1 || relinked[0] != "xcodebuild" {
		t.Fatalf("Relink copies = %v, want [xcodebuild]", relinked)
	}
}

func TestDeveloperDirOf(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"/Applications/Xcode.app/Contents/Developer/usr/bin", "/Applications/Xcode.app/Contents/Developer", true},
		{"/Applications/Xcode.app/Contents/Developer", "/Applications/Xcode.app/Contents/Developer", true},
		{"/usr/bin", "", false},
	} {
		got, ok := developerDirOf(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("developerDirOf(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestExecutableRpathRewritesRefusesARelativeSourceDir(t *testing.T) {
	for _, d := range []string{"usr/bin", "/a/../b", ""} {
		if _, err := executableRpathRewrites("/bin/ls", d); !errors.Is(err, errRelinkSourceDir) {
			t.Errorf("executableRpathRewrites(_, %q) = %v, want errRelinkSourceDir", d, err)
		}
	}
}
