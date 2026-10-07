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

package install_test

import (
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// TestRuntimePackagesDoNotImportInstaller pins the leaf-defaults split: the
// runtime packages take shared values from pkg/defaults and must never pull
// the installer (and its privileged orchestration surface) into their
// dependency closure. The scan is the production closure (no -test, default
// build tags); the positive control on pkg/defaults keeps it from passing
// vacuously.
func TestRuntimePackagesDoNotImportInstaller(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go binary not on PATH: %v", err)
	}
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	const (
		installer = "k3sm.io/k3sm/pkg/install"
		leaf      = "k3sm.io/k3sm/pkg/defaults"
	)
	for _, pkg := range []string{
		"k3sm.io/k3sm/pkg/provider",
		"k3sm.io/k3sm/pkg/netserve",
		"k3sm.io/k3sm/pkg/dev",
	} {
		t.Run(pkg, func(t *testing.T) {
			cmd := exec.Command(goBin, "list", "-deps", "-f", "{{.ImportPath}}", pkg)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "GOFLAGS=-mod=readonly", "GOPROXY=off")
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("go list -deps %s: %v", pkg, err)
			}
			deps := strings.Fields(string(out))
			if len(deps) == 0 {
				t.Fatalf("go list -deps %s returned no packages", pkg)
			}
			if !slices.Contains(deps, leaf) {
				t.Fatalf("%s closure lacks %s; the scan is not seeing the shared leaf", pkg, leaf)
			}
			if slices.Contains(deps, installer) {
				t.Fatalf("%s depends on %s; shared leaf values belong in pkg/defaults", pkg, installer)
			}
		})
	}
}
