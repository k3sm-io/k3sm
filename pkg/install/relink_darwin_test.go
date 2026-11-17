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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/shadow"
	"k3sm.io/runtimed/pkg/shadowset"
)

// TestRelinkedXcodebuildCopyRuns is the B1786 relink gate on a host with the
// default Xcode: a copy of xcodebuild made the way the installer makes it (clone,
// RelinkRpaths, AdHocSign) answers -version from a directory outside the bundle,
// carries no @executable_path rpath, and passes the shadow-copy signature check
// (ad hoc, no entitlements). Without the relink the same copy cannot load
// DVTSystemPrerequisites and dyld aborts it.
func TestRelinkedXcodebuildCopyRuns(t *testing.T) {
	src := shadowset.XcodebuildSource
	if _, err := os.Stat(src); err != nil {
		t.Skipf("SKIP: no %s on this host: %v", src, err)
	}
	dst := filepath.Join(t.TempDir(), "xcodebuild")
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o755); err != nil {
		t.Fatal(err)
	}
	sys := darwinSystem{}
	dev := filepath.Dir(filepath.Dir(filepath.Dir(src)))
	run := func() ([]byte, error) {
		cmd := exec.Command(dst, "-version")
		cmd.Env = append(os.Environ(), "DEVELOPER_DIR="+dev)
		return cmd.CombinedOutput()
	}

	// Red half: signed but not relinked, the copy cannot start.
	if err := sys.AdHocSign(dst); err != nil {
		t.Fatalf("AdHocSign: %v", err)
	}
	if out, err := run(); err == nil {
		t.Fatalf("an un-relinked copy ran (%s); the relink proves nothing", out)
	}

	if err := sys.RelinkRpaths(dst, filepath.Dir(src)); err != nil {
		t.Fatalf("RelinkRpaths: %v", err)
	}
	if err := sys.AdHocSign(dst); err != nil {
		t.Fatalf("AdHocSign: %v", err)
	}
	rp, err := machoRpaths(dst)
	if err != nil {
		t.Fatal(err)
	}
	for _, slice := range rp {
		for _, r := range slice {
			if strings.HasPrefix(r, executablePathPrefix) {
				t.Errorf("rpath %q survived the relink", r)
			}
		}
	}
	out, err := run()
	if err != nil || !strings.Contains(string(out), "Xcode") {
		t.Fatalf("relinked copy -version: %v: %s", err, out)
	}
	if _, err := sys.VerifyShadowCopy(dst); err != nil {
		t.Fatalf("VerifyShadowCopy: %v", err)
	}
	if err := shadow.VerifySignature(t.Context(), dst); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
}
