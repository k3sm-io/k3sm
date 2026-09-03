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

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/runtimed/pkg/sandbox"
)

// The release-archive layout, in one place.
//
// Install resolves every supporting artifact relative to the directory holding
// the running k3sm binary (Config.BinarySource, which cmd/k3sm sets from
// os.Executable), and there is no CLI override for any of those paths. That
// makes the layout a contract between three parties that cannot see each other:
// the installer that reads it, the release archive that must ship it, and the
// gate that proves the two agree.
//
// RequiredSiblings is that contract's single executable home. Config.withDefaults
// derives from it, artifactManifest derives from it, `k3sm install
// --print-required-artifacts` prints it, and the release tooling asserts the
// archive's member set against that output. Adding an artifact here therefore
// reddens the release gate until the archive ships it — which is the whole point.
// Do not re-type any of these names elsewhere; a second copy is the divergence
// bug the shared uninstall manifest already exists to prevent.

const (
	// ExecShimName is the basename of the Seatbelt exec helper installed beside
	// the binary. It is runtimed's constant, re-exported so callers that only
	// import pkg/install still read one definition rather than a copy.
	ExecShimName = sandbox.ExecShimName
	// VMHostName is the basename of the k3sm-vmhost VM-host helper installed
	// beside the binary (sandbox.FindVMHost's first probe). It is runtimed's
	// constant, re-exported so callers that only import pkg/install still read
	// one definition rather than a copy.
	//
	// It ships unconditionally, exactly like ExecShimName: whether a given Mac
	// can actually run vm-RuntimeClass pods is a RUNTIME question
	// (sandbox.VMBackend.Available reports false, never an install-time error,
	// when the host lacks virtualization support) — the release archive is not
	// the place that answer is decided, and withholding the helper from one
	// archive and not another would make availability depend on which archive an
	// operator happened to unpack rather than on their hardware.
	VMHostName = sandbox.VMHostName
	// VirtualizationEntitlement is the code-signing entitlement the k3sm-vmhost
	// helper must carry to create a VZVirtualMachine. Install verifies the staged
	// helper's signature grants it before copying the helper into place
	// (Config.VMHostSource), because the copy preserves the signature verbatim and
	// can therefore only propagate whatever the build produced.
	//
	// The string is stated here rather than imported because runtimed exports no Go
	// constant for it: its home is the cmd/k3sm-vmhost/vmhost.entitlements plist the
	// signing toolchain reads, and runtimed's own probe is the unexported cgo
	// Security.framework read behind sandbox.VMBackend.Available. The two are bound
	// by the integration-tier probe test, which signs its fixture with that very
	// plist and then requires this package's gate to accept the result.
	VirtualizationEntitlement = "com.apple.security.virtualization"
	// PayloadDirName is the basename of the directory holding the control-plane
	// payload (executor.PayloadBinaries) beside the binary. The launchd daemon
	// seeds its work dir from it, having neither gh nor a Go toolchain.
	PayloadDirName = "cp-payload"
)

// RequiredSiblings returns every path Install requires to exist alongside the
// k3sm binary in dir, in a stable order: the exec shim, both DYLD shims, the
// VM-host helper, and each control-plane payload binary under PayloadDirName.
//
// The k3sm binary itself is deliberately absent — it is the anchor the paths are
// derived from, not a sibling of itself. Paths are joined onto dir, so passing
// the extracted archive root yields exactly the set the archive must contain.
func RequiredSiblings(dir string) []string {
	out := []string{
		filepath.Join(dir, ExecShimName),
		filepath.Join(dir, PathShimName),
		filepath.Join(dir, DNSShimName),
		filepath.Join(dir, VMHostName),
	}
	for _, b := range executor.PayloadBinaries() {
		out = append(out, filepath.Join(dir, PayloadDirName, b))
	}
	return out
}
