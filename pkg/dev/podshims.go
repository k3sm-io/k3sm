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

package dev

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"k3sm.io/k3sm/pkg/install"
)

// The two pod-support DYLD shims `k3sm dev` must stage. Both are resolved by
// cmd/k3sm through ONE code path — resolveSiblingDylib, next to the running
// executable — so `k3sm dev` (which re-execs THIS binary out of a `go build`
// output dir) found NEITHER, and that single miss has two distinct symptoms:
//
//   - dnsShimName absent → the provider sets no DYLD insert for DNS, so an in-pod
//     lookup of a cluster Service name goes to the system resolver and NXDOMAINs
//     (macOS getaddrinfo ignores /etc/resolv.conf, so interception is the ONLY
//     mechanism); and
//   - pathShimName absent → runtimed injects no path rebase (pkg/runtime/pod.go
//     guards on PathShimPath != ""), so every ABSOLUTE volume mount path — a
//     ConfigMap at /etc/…, a Secret, an emptyDir, the projected service-account
//     token at /var/run/secrets/… — fails to resolve in-pod with ENOENT. k3sm pods
//     are native processes with no chroot or mount namespace: the files ARE on
//     disk under the pod data volume, the pod just cannot see them at the absolute
//     path without the rebase.
//
// Both names are single-sourced from pkg/install so `k3sm dev` and the installed
// layout name the SAME artifacts.
const (
	dnsShimName  = install.DNSShimName
	pathShimName = install.PathShimName
)

// DefaultPodShimDir is where `k3sm dev` stages the two pod-support DYLD shims.
//
// WHERE they are staged is load-bearing, not a free choice. A shim is loaded by
// dyld INSIDE the pod, so the POD's Seatbelt profile must be able to read it —
// and that profile's read baseline is exactly /System, /usr, /bin and /Library
// (runtimed pkg/sandbox/sbpl.go). A shim staged under the dev registry root
// (~/.k3sm/dev, beside the k3sm-execshim cache) is NOT readable there: dyld fails
// closed and every confined pod dies at exec. hack/lib/clusterup.sh hit exactly
// this and stages into /Library/k3sm-acceptance; this is the `k3sm dev` sibling,
// deliberately distinct from the real install dir (/Library/k3sm) so a dev run
// can never clobber, or be clobbered by, an installation.
const DefaultPodShimDir = "/Library/k3sm-dev"

// shimRecipe is how one pod-support dylib is produced: the module owning its C
// source and that module's build script (relative to the module root). The shims
// are plain C compiled by clang (NOT cgo), so each is built by the script the
// acceptance harness already uses (hack/lib/clusterup.sh), never by a second
// open-coded clang line.
type shimRecipe struct {
	module string
	script string
}

// shimRecipes maps a shim basename to its build recipe. Adding a third
// pod-support dylib is one entry here, not a third near-copy of the provisioner.
var shimRecipes = map[string]shimRecipe{
	dnsShimName:  {module: "k3sm.io/darwin-net", script: "hack/build-shim.sh"},
	pathShimName: {module: "k3sm.io/runtimed", script: "hack/build-pathshim.sh"},
}

// PodShimBuilder is the build+sign seam pkg/dev isolates so provisioning the
// pod-support DYLD shims is unit-testable without a real clang / codesign.
// Defined at the consumer (this package), kept small; the production
// implementation is clangPodShimBuilder, the tests inject a fake. It MIRRORS
// ExecShimBuilder, with one difference: the shim build scripts name their own
// output, so Build takes the shim name plus the output DIRECTORY.
type PodShimBuilder interface {
	// Build compiles the shim named name into outDir, producing <outDir>/<name>.
	// A non-nil error means that shim is not provisionable (an installed k3sm with
	// no workspace source, or no clang) — the caller then leaves the corresponding
	// server flag unset rather than pointing every pod's dyld at a dylib that is
	// not there.
	Build(ctx context.Context, name, outDir string) error
	// Sign ad-hoc signs the built dylib (codesign -s - -f), mirroring
	// goExecShimBuilder.Sign. Best-effort — a signing failure must not fail
	// provisioning.
	Sign(ctx context.Context, path string) error
}

// clangPodShimBuilder is the production PodShimBuilder over the owning modules'
// build scripts + `codesign`.
type clangPodShimBuilder struct{}

// NewPodShimBuilder returns the production PodShimBuilder.
func NewPodShimBuilder() PodShimBuilder { return clangPodShimBuilder{} }

// Build runs the owning module's build script with outDir, which clang-compiles
// the shim's C source into <outDir>/<name>. Like goExecShimBuilder.Build it needs
// the workspace source to resolve, and reports a plain error when it does not
// (the caller degrades, it does not crash).
func (clangPodShimBuilder) Build(ctx context.Context, name, outDir string) error {
	recipe, ok := shimRecipes[name]
	if !ok {
		return fmt.Errorf("no build recipe for pod shim %s", name)
	}
	dir, err := moduleDir(ctx, recipe.module)
	if err != nil {
		return err
	}
	script := filepath.Join(dir, recipe.script)
	if out, err := exec.CommandContext(ctx, script, outDir).CombinedOutput(); err != nil {
		return fmt.Errorf("build %s: %w: %s", name, err, out)
	}
	return nil
}

// Sign ad-hoc signs path (codesign -s - -f), best-effort (mirrors
// goExecShimBuilder.Sign).
func (clangPodShimBuilder) Sign(ctx context.Context, path string) error {
	_ = exec.CommandContext(ctx, "codesign", "-s", "-", "-f", path).Run()
	return nil
}

// moduleDir resolves a workspace module's source root via `go list -m`, so a
// build script is found through the same module resolution the execshim's
// `go build k3sm.io/runtimed/...` relies on — no assumed sibling-directory layout.
func moduleDir(ctx context.Context, module string) (string, error) {
	out, err := exec.CommandContext(ctx, "go", "list", "-m", "-f", "{{.Dir}}", module).Output()
	if err != nil {
		return "", fmt.Errorf("locate %s source: %w", module, err)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		return "", fmt.Errorf("locate %s source: go list -m reported no directory", module)
	}
	return dir, nil
}

// wantsPathShim reports whether an instance's posture can stage and use the
// path-rebase shim: the runtimed runtime (the hostprocess provider performs no
// DYLD injection at all) plus euid 0, because the shim MUST be staged under
// /Library to be inside the pod Seatbelt read baseline and only root can write
// there. Pure, so the posture gating is unit-tested without a bring-up.
func wantsPathShim(euid int, runtimeName string) bool {
	return euid == 0 && runtimeName == runtimeRuntimed
}

// wantsDNSShim reports whether an instance's posture can stage and use the
// getaddrinfo DNS shim: everything wantsPathShim needs, PLUS a live datapath —
// the rootless tier is network=none, where no per-node resolver binds the DNS
// VIP, so an injected DNS shim would point pods at nothing.
func wantsDNSShim(euid int, datapath bool, runtimeName string) bool {
	return wantsPathShim(euid, runtimeName) && datapath
}

// podShimDir is the pod-readable directory the DYLD shims are staged into,
// DefaultPodShimDir unless a test overrode it.
func (m *Manager) podShimDir() string {
	if m.shimDir != "" {
		return m.shimDir
	}
	return DefaultPodShimDir
}

// provisionPodShim stages the named pod-support dylib into the pod-readable stage
// dir and returns its absolute path, or "" when it is not provisionable. It
// MIRRORS provisionExecShim: the shim is ALWAYS rebuilt when the source is
// available (never trusted on existence alone — a cached dylib predating a shim
// change is silently skewed, and the re-sign below refreshes its mtime so the
// staleness is invisible), and a cached artifact is reused ONLY when the rebuild
// FAILS. A non-nil error is a filesystem failure (stage dir unwritable), which IS
// fatal; an unbuildable shim is not (it degrades to the pre-shim behavior —
// system-resolver DNS, host-absolute mount paths — exactly as a from-source
// `k3sm node` without the staged dylibs does).
func (m *Manager) provisionPodShim(ctx context.Context, name string) (string, error) {
	dir := m.podShimDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create pod shim stage dir %s: %w", dir, err)
	}
	// MkdirAll applies the process umask, and a restrictive one (0077) would leave
	// the dir untraversable by the pod's uid — re-assert the mode explicitly.
	if err := os.Chmod(dir, 0o755); err != nil {
		return "", fmt.Errorf("make pod shim stage dir %s traversable: %w", dir, err)
	}
	shim := filepath.Join(dir, name)

	cached := false
	if info, statErr := os.Stat(shim); statErr == nil && !info.IsDir() && info.Size() > 0 {
		cached = true
	}

	if buildErr := m.shimBuilder.Build(ctx, name, dir); buildErr != nil {
		if cached {
			fmt.Fprintf(m.out, "note: could not rebuild %s (%v); reusing the cached shim\n", name, buildErr)
			_ = m.shimBuilder.Sign(ctx, shim)
			return m.podReadable(shim)
		}
		fmt.Fprintf(m.out, "note: could not build %s: %v\n", name, buildErr)
		return "", nil
	}
	// Re-sign so a stale ad-hoc signature from a prior toolchain does not wedge the
	// load (mirrors provisionExecShim).
	_ = m.shimBuilder.Sign(ctx, shim)
	return m.podReadable(shim)
}

// podReadable makes a staged shim world-readable and returns its path. A pod runs
// at a different uid than the staging root, and dyld fails CLOSED on an unreadable
// insert — the pod dies at exec with SIGABRT, which is strictly worse than running
// without that shim's feature. So a chmod failure demotes the shim to
// not-provisioned ("" with a notice) instead of handing the server a path its pods
// cannot load.
func (m *Manager) podReadable(shim string) (string, error) {
	if err := os.Chmod(shim, 0o644); err != nil {
		fmt.Fprintf(m.out, "note: %s is not pod-readable (%v); leaving it uninjected\n", filepath.Base(shim), err)
		return "", nil
	}
	return shim, nil
}
