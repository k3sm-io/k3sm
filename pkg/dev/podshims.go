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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/defaults"
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
// Both names are single-sourced from pkg/defaults so `k3sm dev` and the installed
// layout name the SAME artifacts.
const (
	dnsShimName  = defaults.DNSShimName
	pathShimName = defaults.PathShimName
)

// DefaultPodShimDir is where a ROOT (euid 0) `k3sm dev` instance stages the two
// pod-support DYLD shims.
//
// WHERE they are staged is load-bearing, not a free choice. A shim is loaded by
// dyld INSIDE the pod, so the POD's Seatbelt profile must be able to read it, or
// dyld fails closed and every confined pod dies at exec. There are two stage
// locations, one per tier:
//
//   - Root tier: /Library/k3sm-dev (this constant). /Library is inside the pod
//     profile's read baseline (/System, /usr, /bin, /Library — runtimed
//     pkg/sandbox/sbpl.go), and only root can write there. Deliberately distinct
//     from the real install dir (/Library/k3sm) so a dev run can never clobber, or
//     be clobbered by, an installation; hack/lib/clusterup.sh stages into the
//     sibling /Library/k3sm-acceptance for the same reason.
//   - Rootless tier: <PodRootBasePrefix>-<euid>/<instance>/shims, a sibling of
//     the runtime root's pods dir (see podShimSubdir). It is outside the read
//     baseline, so the provider names the two staged FILES in every pod's
//     SandboxProfile.ExtraReadPaths (pkg/provider stampShimReadPaths). That
//     grant is only accepted for a path off runtimed's protected deny-set, which
//     is why the location is none of: under the pods root (sibling pods), under
//     /Users (so never ~/.k3sm or the k3sm-execshim dev-bin cache beside it), or
//     one of the runtime root's daemon-private subtrees.
//
// Either way the shims are regular-file copies (never symlinks) with mode 0755,
// and staging refuses a stage dir or target that is a symlink (see
// refuseSymlink).
const DefaultPodShimDir = "/Library/k3sm-dev"

// podShimSubdir is the rootless tier's stage dir name under the instance's
// runtime root (<PodRootBasePrefix>-<euid>/<instance>/shims). It must not
// collide with a runtimed work-dir subtree the pod profile denies (pods, run,
// sbpl, blobs, the image stores, log/pods, …); "shims" is none of them.
const podShimSubdir = "shims"

// podShimMode is the staged shim's file mode: world-readable so dyld can load it
// at the pod's uid, and executable like any other Mach-O image.
const podShimMode os.FileMode = 0o755

// ErrSymlinkStage reports a shim or helper stage path that is a symbolic link.
// Staging refuses to write through one: a pre-planted link would redirect a
// (possibly root) daemon's chmod and binary write into a tree the planter
// chooses.
var ErrSymlinkStage = errors.New("dev: refusing to stage through a symlink")

// refuseSymlink returns ErrSymlinkStage when path exists and is a symbolic link,
// and nil when it is absent or not a link. It checks the path itself (Lstat),
// never the link target.
func refuseSymlink(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect stage path %s: %w", path, err)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", ErrSymlinkStage, path)
	}
	return nil
}

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

// wantsPathShim reports whether an instance's posture can use the path-rebase
// shim: the runtimed runtime (the hostprocess provider performs no DYLD
// injection at all). Both tiers stage it — root into DefaultPodShimDir, rootless
// beside its runtime root — so the euid is not an input. Pure, so the posture
// gating is unit-tested without a bring-up.
func wantsPathShim(runtimeName string) bool {
	return runtimeName == runtimeRuntimed
}

// wantsDNSShim reports whether an instance's posture can use the getaddrinfo DNS
// shim: everything wantsPathShim needs, PLUS a live datapath — the rootless tier
// is network=none, where no per-node resolver binds the DNS VIP, so an injected
// DNS shim would point pods at nothing.
func wantsDNSShim(datapath bool, runtimeName string) bool {
	return wantsPathShim(runtimeName) && datapath
}

// podShimDir is the pod-readable directory instance's DYLD shims are staged
// into: DefaultPodShimDir for a root instance, <runtime root>/shims for a
// rootless one, or the test override.
func (m *Manager) podShimDir(instance string) string {
	if m.shimDir != "" {
		return m.shimDir
	}
	if m.euid == 0 {
		return DefaultPodShimDir
	}
	return filepath.Join(m.podRoot(instance), podShimSubdir)
}

// podShimParents returns, outermost first, the directories above instance's
// shim stage dir that staging may have to create: for the rootless tier the
// euid-scoped pod-root base and the instance's runtime root; otherwise just the
// stage dir's parent (/Library, or a test override's parent).
func (m *Manager) podShimParents(instance string) []string {
	if m.shimDir == "" && m.euid != 0 {
		return []string{m.podRootBaseDir(), m.podRoot(instance)}
	}
	return []string{filepath.Dir(m.podShimDir(instance))}
}

// mkdirNoFollow creates each dir in order (each one's parent must already exist
// or precede it in dirs) with perm, refusing with ErrSymlinkStage any that is a
// symlink, both before the mkdir and after it (a link planted in between makes
// Mkdir report it as existing). An existing real directory is kept as is.
//
// It exists for the rootless pod-root base, <PodRootBasePrefix>-<euid>, which
// sits under the world-writable /private/var/tmp: any local user can pre-create
// that name as a link. MkdirAll would follow it, and staging would then write
// the shim that is DYLD-injected into EVERY pod into the planter's tree.
func mkdirNoFollow(perm os.FileMode, dirs ...string) error {
	for _, d := range dirs {
		if err := refuseSymlink(d); err != nil {
			return err
		}
		if err := os.Mkdir(d, perm); err != nil && !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("create %s: %w", d, err)
		}
		if err := refuseSymlink(d); err != nil {
			return err
		}
	}
	return nil
}

// stagePodShims provisions the pod-support DYLD shims instance's posture can use
// and returns the paths to hand the node as --path-shim / --dns-shim ("" for a
// shim not wanted or not provisionable, with a notice). A non-nil error is a
// staging failure (an unwritable or symlinked stage path), which is fatal.
func (m *Manager) stagePodShims(ctx context.Context, instance string, datapath bool, runtimeName string) (pathShim, dnsShim string, err error) {
	if wantsPathShim(runtimeName) {
		pathShim, err = m.provisionPodShim(ctx, instance, pathShimName)
		if err != nil {
			return "", "", err
		}
		if pathShim == "" {
			fmt.Fprint(m.out, "NOTE: absolute volume-mount paths unavailable in-pod (no stageable path-rebase shim) — ConfigMap/Secret/emptyDir/service-account mounts will ENOENT. Run k3sm dev from the workspace for volume mounts.\n")
		}
	}
	if wantsDNSShim(datapath, runtimeName) {
		dnsShim, err = m.provisionPodShim(ctx, instance, dnsShimName)
		if err != nil {
			return "", "", err
		}
		if dnsShim == "" {
			fmt.Fprint(m.out, "NOTE: in-pod cluster DNS unavailable (no stageable getaddrinfo shim) — pods stay on the system resolver and cluster Service names NXDOMAIN. Run k3sm dev from the workspace for cluster DNS.\n")
		}
	}
	return pathShim, dnsShim, nil
}

// provisionPodShim stages the named pod-support dylib into instance's
// pod-readable stage dir and returns its absolute path, or "" when it is not
// provisionable. It MIRRORS provisionExecShim: the shim is ALWAYS rebuilt when
// the source is available (never trusted on existence alone), and a cached
// artifact is reused ONLY when the rebuild FAILS — and then with a STALE warning
// naming the build error, because the re-sign rewrites the file and refreshes its
// mtime, so nothing else would show that the cached shim may predate the source.
//
// The build runs in a fresh private temp dir inside the stage dir; the result is
// signed and made pod-readable THERE and then renamed over the target, so the
// staged file is always a regular-file copy and no chmod or write ever follows a
// link at the target path. A symlinked stage dir or target is refused outright
// (ErrSymlinkStage). A non-nil error is a filesystem failure, which IS fatal; an
// unbuildable shim is not (it degrades to the pre-shim behavior — system-resolver
// DNS, host-absolute mount paths — exactly as a from-source `k3sm node` without
// the staged dylibs does).
func (m *Manager) provisionPodShim(ctx context.Context, instance, name string) (string, error) {
	dir := m.podShimDir(instance)
	// Create the parents component by component, refusing a symlink at each, and
	// at the runtime root's own 0700 so the stage dir below does not create the
	// instance's runtime root 0755. For the rootless tier that is the euid-scoped
	// base under the world-writable /private/var/tmp and the instance's runtime
	// root (see mkdirNoFollow for why a planted link there matters).
	if err := mkdirNoFollow(0o700, m.podShimParents(instance)...); err != nil {
		return "", err
	}
	if err := refuseSymlink(dir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create pod shim stage dir %s: %w", dir, err)
	}
	// MkdirAll applies the process umask, and a restrictive one (0077) would leave
	// the dir untraversable by the pod's uid — re-assert the mode explicitly.
	if err := os.Chmod(dir, 0o755); err != nil {
		return "", fmt.Errorf("make pod shim stage dir %s traversable: %w", dir, err)
	}
	shim := filepath.Join(dir, name)
	if err := refuseSymlink(shim); err != nil {
		return "", err
	}

	cached := false
	if info, statErr := os.Lstat(shim); statErr == nil && info.Mode().IsRegular() && info.Size() > 0 {
		cached = true
	}

	buildErr, err := m.buildPodShim(ctx, name, dir, shim)
	if err != nil {
		return "", err
	}
	if buildErr != nil {
		if cached {
			fmt.Fprintf(m.out, "WARNING: %s is STALE: rebuild failed (%v); reusing the cached shim from an earlier build, which may predate the current source\n", name, buildErr)
			// The failed build may have taken a while; re-check the target right
			// before codesign rewrites it in place, so a link planted meanwhile is
			// refused rather than followed.
			if err := refuseSymlink(shim); err != nil {
				return "", err
			}
			_ = m.shimBuilder.Sign(ctx, shim)
			return m.podReadable(shim)
		}
		fmt.Fprintf(m.out, "note: could not build %s: %v\n", name, buildErr)
		return "", nil
	}
	return m.podReadable(shim)
}

// buildPodShim builds name into a fresh private temp dir under dir, signs it
// there, and renames it over shim. buildErr is a build (or build-output) failure,
// which the caller degrades; err is a filesystem failure, which is fatal.
func (m *Manager) buildPodShim(ctx context.Context, name, dir, shim string) (buildErr, err error) {
	tmp, err := os.MkdirTemp(dir, ".build-"+name+"-")
	if err != nil {
		return nil, fmt.Errorf("create pod shim build dir in %s: %w", dir, err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	if buildErr := m.shimBuilder.Build(ctx, name, tmp); buildErr != nil {
		return buildErr, nil
	}
	built := filepath.Join(tmp, name)
	info, statErr := os.Lstat(built)
	if statErr != nil {
		return fmt.Errorf("build produced no %s: %w", name, statErr), nil
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("build produced %s as %v, want a regular file", name, info.Mode().Type()), nil
	}
	// Re-sign so a stale ad-hoc signature from a prior toolchain does not wedge the
	// load (mirrors provisionExecShim). Signed before the rename so codesign never
	// writes at the shared stage path.
	_ = m.shimBuilder.Sign(ctx, built)
	if err := os.Rename(built, shim); err != nil {
		return nil, fmt.Errorf("stage %s: %w", shim, err)
	}
	return nil, nil
}

// podReadable makes a staged shim world-readable (podShimMode) and returns its
// path. A pod runs at a different uid than the staging root, and dyld fails
// CLOSED on an unreadable insert — the pod dies at exec with SIGABRT, which is
// strictly worse than running without that shim's feature. So a chmod failure
// demotes the shim to not-provisioned ("" with a notice) instead of handing the
// server a path its pods cannot load. The mode is set through a descriptor
// opened with O_NOFOLLOW, so it can never land on a link's target.
func (m *Manager) podReadable(shim string) (string, error) {
	f, err := os.OpenFile(shim, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err == nil {
		err = f.Chmod(podShimMode)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		fmt.Fprintf(m.out, "note: %s is not pod-readable (%v); leaving it uninjected\n", filepath.Base(shim), err)
		return "", nil
	}
	return shim, nil
}
