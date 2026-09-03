//go:build integration

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
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestVerifyVirtualizationEntitlementRealCodesign exercises the PRODUCTION probe
// against really-signed Mach-Os, which is the half the unit tier cannot reach:
// the unit tests fake the seam, so they pin what install does with a verdict and
// say nothing about whether the verdict is read correctly.
//
// It also binds install.VirtualizationEntitlement to its real home. The entitled
// fixture is signed with runtimed's own cmd/k3sm-vmhost/vmhost.entitlements — the
// exact plist hack/release/stage.sh signs the shipped helper with — so if that
// plist ever stopped granting the entitlement this constant names, this test goes
// red rather than the gate silently passing everything.
//
// It signs COPIES of /bin/echo rather than building a fixture: any Mach-O will do,
// the file is never executed, and depending on the Go toolchain inside the test
// would add a failure mode that has nothing to do with what is being measured.
func TestVerifyVirtualizationEntitlementRealCodesign(t *testing.T) {
	if _, err := exec.LookPath("codesign"); err != nil {
		t.Skipf("codesign unavailable: %v", err)
	}
	const machO = "/bin/echo"
	if _, err := os.Stat(machO); err != nil {
		t.Skipf("no Mach-O fixture source at %s: %v", machO, err)
	}
	entitlements := vmhostEntitlementsPlist(t)

	sys := NewDarwinSystem()
	dir := t.TempDir()

	// fixture copies machO to name and applies sign, returning the path.
	fixture := func(name string, sign ...string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		src, err := os.ReadFile(machO)
		if err != nil {
			t.Fatalf("read %s: %v", machO, err)
		}
		if err := os.WriteFile(path, src, 0o755); err != nil {
			t.Fatalf("write fixture %s: %v", path, err)
		}
		args := append(append([]string{}, sign...), path)
		if out, err := exec.Command("codesign", args...).CombinedOutput(); err != nil {
			t.Fatalf("codesign %s: %v: %s", strings.Join(args, " "), err, out)
		}
		return path
	}

	tests := []struct {
		name string
		path string
		// wantErr is "" for accept; otherwise a substring the refusal must carry.
		wantErr string
		// wantNotExist additionally requires the fs.ErrNotExist arm, the one
		// refusal install deliberately does NOT treat as an entitlement failure.
		wantNotExist bool
	}{
		{
			name:    "signed with the vmhost entitlements plist is accepted",
			path:    fixture("entitled", "--force", "--sign", "-", "--entitlements", entitlements),
			wantErr: "",
		},
		{
			name:    "ad-hoc signed without entitlements is refused",
			path:    fixture("unentitled", "--force", "--sign", "-"),
			wantErr: "grants no " + VirtualizationEntitlement,
		},
		{
			name: "unsigned is refused",
			// A plain `go build` artifact is unsigned on arm64 in exactly this way,
			// and codesign exits non-zero on it — so the probe needs no arm of its
			// own for the case the whole gate exists to catch.
			path:    fixture("unsigned", "--remove-signature"),
			wantErr: "codesign -d --entitlements -",
		},
		{
			name:         "a missing helper reports fs.ErrNotExist, not an entitlement failure",
			path:         filepath.Join(dir, "absent"),
			wantErr:      "absent",
			wantNotExist: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := sys.VerifyVirtualizationEntitlement(tc.path)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("VerifyVirtualizationEntitlement(%s) = %v, want nil", tc.path, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("VerifyVirtualizationEntitlement(%s) = nil, want an error mentioning %q", tc.path, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %v does not mention %q", err, tc.wantErr)
			}
			if got := errors.Is(err, fs.ErrNotExist); got != tc.wantNotExist {
				t.Errorf("errors.Is(err, fs.ErrNotExist) = %v, want %v (install branches on exactly this)", got, tc.wantNotExist)
			}
		})
	}
}

// vmhostEntitlementsPlist locates runtimed's cmd/k3sm-vmhost/vmhost.entitlements
// through the module graph rather than a relative path, so the test does not
// assume the four repos are checked out as siblings. It skips — never fails — when
// the module cannot be resolved: an absent toolchain is not a defect in the code
// under test.
func vmhostEntitlementsPlist(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-f", "{{.Dir}}", "k3sm.io/runtimed/cmd/k3sm-vmhost").Output()
	if err != nil {
		t.Skipf("cannot locate k3sm.io/runtimed/cmd/k3sm-vmhost: %v", err)
	}
	path := filepath.Join(strings.TrimSpace(string(out)), "vmhost.entitlements")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("no entitlements plist at %s: %v", path, err)
	}
	return path
}
