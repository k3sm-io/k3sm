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
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	copyOf := func(name string) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, b, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	sys := darwinSystem{}
	dev := filepath.Dir(filepath.Dir(filepath.Dir(src)))
	run := func(p string) ([]byte, error) {
		cmd := exec.Command(p, "-version")
		cmd.Env = append(os.Environ(), "DEVELOPER_DIR="+dev)
		return cmd.CombinedOutput()
	}

	// Red half: signed but not relinked, a copy cannot start.
	red := copyOf("xcodebuild")
	if err := sys.AdHocSign(red); err != nil {
		t.Fatalf("AdHocSign: %v", err)
	}
	if out, err := run(red); err == nil {
		t.Fatalf("an un-relinked copy ran (%s); the relink proves nothing", out)
	}
	// RelinkRpaths refuses a copy that is no longer Apple-signed.
	if err := sys.RelinkRpaths(red, filepath.Dir(src)); err == nil {
		t.Fatal("RelinkRpaths edited a copy that is not Apple-signed")
	}

	// Green half: the installer's order, on a pristine clone.
	dst := copyOf("xcodebuild")
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
	out, err := run(dst)
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

// TestRelinkedAssetCatalogCopiesRun is the asset-catalog half of the relink gate:
// actool and ibtoold, copied side by side the way the installer makes them
// (clone, RelinkRpaths, AdHocSign), answer actool --version with its plist. The
// actool launcher finds ibtoold beside itself, so the pair works only together,
// and the ibtoold copy loads the bundle's frameworks only once relinked. Both
// copies drop the library-validation flag that made the originals refuse the
// path-rebase shim.
func TestRelinkedAssetCatalogCopiesRun(t *testing.T) {
	var actool, ibtoold *shadow.Copy
	for _, c := range shadow.Copies() {
		c := c
		switch c.Name {
		case "actool":
			actool = &c
		case "ibtoold":
			ibtoold = &c
		}
	}
	if actool == nil || ibtoold == nil {
		t.Skip("SKIP: runtimed's list has no actool/ibtoold copies")
	}
	for _, c := range []*shadow.Copy{actool, ibtoold} {
		if _, err := os.Stat(c.Source); err != nil {
			t.Skipf("SKIP: no %s on this host: %v", c.Source, err)
		}
	}
	sys := darwinSystem{}
	dir := t.TempDir()
	for _, c := range []*shadow.Copy{actool, ibtoold} {
		b, err := os.ReadFile(c.Source)
		if err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(dir, c.Name)
		if err := os.WriteFile(dst, b, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := sys.RelinkRpaths(dst, filepath.Dir(c.Source)); err != nil {
			t.Fatalf("RelinkRpaths %s: %v", c.Name, err)
		}
		if err := sys.AdHocSign(dst); err != nil {
			t.Fatalf("AdHocSign %s: %v", c.Name, err)
		}
		if _, err := sys.VerifyShadowCopy(dst); err != nil {
			t.Fatalf("VerifyShadowCopy %s: %v", c.Name, err)
		}
	}
	dev, _ := developerDirOf(filepath.Dir(actool.Source))
	cmd := exec.Command(filepath.Join(dir, "actool"), "--version")
	cmd.Env = append(os.Environ(), "DEVELOPER_DIR="+dev)
	out, err := cmd.CombinedOutput()
	if err != nil || strings.Contains(string(out), "Could not locate ibtoold") || !strings.Contains(string(out), "<plist") {
		t.Fatalf("the actool copy beside the ibtoold copy: %v: %s", err, out)
	}
}
