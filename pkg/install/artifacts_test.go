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
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/executor"
)

// TestRequiredSiblingsMatchesConfigDefaults is the anti-drift test: it asserts
// that every path Config.withDefaults derives for a given binary directory is
// also reported by RequiredSiblings. The release tooling asserts an archive's
// member set against RequiredSiblings, so if withDefaults grew a fifth artifact
// class that RequiredSiblings did not know about, the archive could omit it and
// every gate would stay green while `k3sm install` fail-fasted on a user's Mac.
func TestRequiredSiblingsMatchesConfigDefaults(t *testing.T) {
	const dir = "/tmp/build"
	cfg := Config{BinarySource: filepath.Join(dir, "k3sm"), TargetUser: "someone"}.withDefaults()

	got := make(map[string]bool)
	for _, p := range RequiredSiblings(dir) {
		got[p] = true
	}

	// Every source path withDefaults derives must be covered. PayloadSource is a
	// directory, so it is covered by its members rather than by itself.
	for _, want := range []string{cfg.ExecShimSource, cfg.PathShimSource, cfg.DNSShimSource, cfg.VMHostSource} {
		if !got[want] {
			t.Errorf("RequiredSiblings(%q) omits %q, which withDefaults requires", dir, want)
		}
	}
	for _, b := range executor.PayloadBinaries() {
		want := filepath.Join(cfg.PayloadSource, b)
		if !got[want] {
			t.Errorf("RequiredSiblings(%q) omits payload binary %q", dir, want)
		}
	}
	if n := len(RequiredSiblings(dir)); n != 4+len(executor.PayloadBinaries()) {
		t.Errorf("RequiredSiblings returned %d entries, want 4 shims + %d payload binaries", n, len(executor.PayloadBinaries()))
	}
}

// TestRequiredSiblingsRelative pins the empty-dir form the `k3sm install
// --print-required-artifacts` flag emits: relative paths a caller joins onto an
// extracted archive root. A leading separator here would make the release gate
// compare absolute paths against archive members and never match.
func TestRequiredSiblingsRelative(t *testing.T) {
	for _, p := range RequiredSiblings("") {
		if strings.HasPrefix(p, "/") {
			t.Errorf("RequiredSiblings(\"\") returned absolute path %q, want relative", p)
		}
	}
	want := []string{
		ExecShimName,
		PathShimName,
		DNSShimName,
		VMHostName,
		filepath.Join(PayloadDirName, "kube-apiserver"),
	}
	got := strings.Join(RequiredSiblings(""), "\n")
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("RequiredSiblings(\"\") = %q, missing %q", got, w)
		}
	}
}

// TestExecShimNameMatchesRuntimed guards the re-export: pkg/install must not
// drift from the constant runtimed's sandbox package resolves at exec time.
func TestExecShimNameMatchesRuntimed(t *testing.T) {
	if ExecShimName != "k3sm-execshim" {
		t.Errorf("ExecShimName = %q, want k3sm-execshim (runtimed's sandbox.ExecShimName)", ExecShimName)
	}
}

// TestVMHostNameMatchesRuntimed guards the re-export: pkg/install must not
// drift from the constant runtimed's sandbox package resolves at exec time
// (sandbox.FindVMHost).
func TestVMHostNameMatchesRuntimed(t *testing.T) {
	if VMHostName != "k3sm-vmhost" {
		t.Errorf("VMHostName = %q, want k3sm-vmhost (runtimed's sandbox.VMHostName)", VMHostName)
	}
}
