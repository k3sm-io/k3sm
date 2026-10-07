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
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// execShimName is the basename of the ad-hoc-signed Seatbelt helper the detached
// `k3sm server` needs on its PATH. It MIRRORS runtimed's sandbox.ExecShimName;
// runtimed's FindExecShim looks for this basename beside the server binary and on
// PATH. A bare `go build` dev binary ships neither, so pkg/dev provisions it into
// a shared dev-bin cache and prepends that cache to the detached server's PATH.
const execShimName = "k3sm-execshim"

// execShimPkg is the go import path of the k3sm-execshim helper's main package
// (resolved via the workspace go.work), built CGO-on so libsandbox links.
const execShimPkg = "k3sm.io/runtimed/cmd/k3sm-execshim"

// ExecShimBuilder is the build+sign seam pkg/dev isolates so provisioning the
// k3sm-execshim helper is unit-testable without a real `go build` / `codesign`.
// Defined at the consumer (this package), kept small; the production
// implementation is goExecShimBuilder, the tests inject a fake.
type ExecShimBuilder interface {
	// Build compiles the k3sm-execshim helper (CGO_ENABLED=1, workspace go.work) to
	// outPath. A non-nil error means the helper is not provisionable (e.g. an
	// installed k3sm with no workspace source) — the caller falls back to
	// hostprocess rather than crashing the dev loop.
	Build(ctx context.Context, outPath string) error
	// Sign ad-hoc signs the built Mach-O so it can exec + apply SBPL on macOS
	// (mirrors executor.signBinaries: codesign -s - -f). Best-effort — a signing
	// failure must not fail provisioning (the binary fails loudly at exec if it
	// truly cannot run).
	Sign(ctx context.Context, path string) error
}

// goExecShimBuilder is the production ExecShimBuilder over `go build` + `codesign`.
// It mirrors executor.ensureKine (CGO_ENABLED=1 go build) and
// executor.signBinaries (codesign -s - -f).
type goExecShimBuilder struct{}

// NewExecShimBuilder returns the production ExecShimBuilder.
func NewExecShimBuilder() ExecShimBuilder { return goExecShimBuilder{} }

// Build runs `go build -o outPath k3sm.io/runtimed/cmd/k3sm-execshim` with
// CGO_ENABLED=1, leaving GOWORK at the workspace default so the runtimed module
// resolves. Mirrors executor.ensureKine's cgo build.
func (goExecShimBuilder) Build(ctx context.Context, outPath string) error {
	cmd := exec.CommandContext(ctx, "go", "build", "-o", outPath, execShimPkg)
	// CGO_ENABLED=1 (libsandbox links); GOWORK is intentionally left at the
	// environment default (the workspace go.work) so k3sm.io/runtimed resolves.
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("build %s (CGO_ENABLED=1): %w: %s", execShimName, err, out)
	}
	return nil
}

// Sign ad-hoc signs path (codesign -s - -f), best-effort (mirrors
// executor.signBinaries): a signing miss on an already-valid or non-macOS host
// must not block provisioning.
func (goExecShimBuilder) Sign(ctx context.Context, path string) error {
	_ = exec.CommandContext(ctx, "codesign", "-s", "-", "-f", path).Run()
	return nil
}

// devBinDir is the shared dev-bin cache holding the provisioned k3sm-execshim
// helper — <registry root>/.bin, BESIDE the per-instance <root>/<name> dirs (the
// helper is instance-independent, so it is cached once and reused across
// instances). Prepended to a detached server's PATH so runtimed's FindExecShim →
// exec.LookPath resolves it.
func (m *Manager) devBinDir() string { return filepath.Join(m.reg.root, ".bin") }

// freshBinDir is the rootless run's per-user fallback helper dir,
// <registry root>/.bin-<euid>, used only when a fresh k3sm-execshim build exists
// but cannot be installed into the shared cache (devBinDir): a file or dir there
// is owned by someone else (typically root, left by an earlier sudo run) or is
// not writable. A root run never uses it (see rootExecShimDir).
func (m *Manager) freshBinDir() string {
	return filepath.Join(m.reg.root, ".bin-"+strconv.Itoa(m.euid))
}

// rootExecShimSubdir is the root run's helper dir under DefaultPodShimDir.
// It does not collide with the pod shims staged in DefaultPodShimDir itself,
// which are files, not a "bin" directory.
const rootExecShimSubdir = "bin"

// rootExecShimDir is where a root run (euid 0) keeps its k3sm-execshim:
// DefaultPodShimDir/bin, i.e. /Library/k3sm-dev/bin. Every ancestor of that
// path is root-owned and writable by nobody else, so the unprivileged user can
// neither replace the helper nor swap a directory above it, unlike any path
// under their home. m.rootBinDir overrides it so a test stays unprivileged.
func (m *Manager) rootExecShimDir() string {
	if m.rootBinDir != "" {
		return m.rootBinDir
	}
	return filepath.Join(DefaultPodShimDir, rootExecShimSubdir)
}

// provisionExecShim ensures a k3sm-execshim helper built from the current source
// is on hand and returns the dir holding it (prepended to the detached server's
// PATH). The helper is built (CGO_ENABLED=1, workspace go.work) into a private
// staging dir and ad-hoc signed there via the builder seam, then installed by
// rename: into the shared dev-bin cache for a rootless run, into the root-owned
// rootExecShimDir for a root run (provisionRootExecShim).
//
// The two failure modes are kept apart, because they call for opposite answers:
//
//   - The build fails (an installed k3sm with no workspace source, or no
//     toolchain): a helper cached by an earlier session is reused, but only one
//     that passes helperProblem (owned by this euid, not group/other-writable).
//     Anything else is refused and the caller falls back to hostprocess.
//   - The build succeeds but cannot be installed into the cache (the cached file
//     is owned by someone else, or the cache is not writable): the cached helper
//     is NEVER reused, since a fresh one exists and the cached one may predate
//     the current argv contract. The fresh build goes to freshBinDir instead, and
//     one note names the blocking path and the remedy.
//
// Every helper is re-checked by helperProblem right before its dir is returned.
// It returns ("", false, nil) when no trustworthy helper is available: the caller
// then falls back to hostprocess with a loud notice rather than booting a
// runtimed server that would die at `init sandbox backend`. A non-nil error is a
// filesystem failure (the dev root cannot be written, or a symlinked stage path),
// which IS fatal. Under sudo, only the registry dirs this run had to create are
// handed back to the invoking human; a helper binary never is.
func (m *Manager) provisionExecShim(ctx context.Context) (binDir string, ok bool, err error) {
	root := m.reg.root
	if err := refuseSymlink(root); err != nil {
		return "", false, err
	}
	created := missingAncestors(root)
	if mkErr := os.MkdirAll(root, 0o755); mkErr != nil {
		return "", false, fmt.Errorf("create dev root %s: %w", root, mkErr)
	}
	// The dev root (and ~/.k3sm above it) belong to the human even when a sudo
	// run creates them, or the next rootless run cannot write its registry.
	m.handBack(created...)
	if m.euid == 0 {
		return m.provisionRootExecShim(ctx)
	}

	dir := m.devBinDir()
	// The same symlink refusal as the pod-shim stage (refuseSymlink): a planted
	// link would redirect the helper write into a tree the planter chooses.
	if err := mkdirNoFollow(0o755, dir); err != nil {
		return "", false, err
	}
	shim := filepath.Join(dir, execShimName)
	if err := refuseSymlink(shim); err != nil {
		return "", false, err
	}

	cached := false
	if info, statErr := os.Lstat(shim); statErr == nil && info.Mode().IsRegular() && info.Size() > 0 {
		cached = true
	}

	// ALWAYS rebuild when the source is available, never trust the cache on
	// existence alone.
	//
	// The shim's argv is a versioned contract between it and
	// sandbox.ExecShimBackend.WrapCommand, and it has changed (the rlimit + qos
	// launch-spec tokens were inserted BEFORE the profile path). A cached shim
	// predating that change is silently skewed: the current caller's rlimit
	// sentinel lands in the old shim's profile slot, so EVERY confined pod dies
	// with `read profile -: no such file or directory` and the whole isolation
	// conformance surface goes red. Observed on a lab Mac 2026-08-27, where the
	// cache had been populated by an earlier session; the re-sign rewrites the
	// file, so even its mtime looks current and the staleness is invisible.
	//
	// The same skew is why an UNINSTALLABLE fresh build must not fall back to the
	// cache: on 2026-10-07 the source was present and only the destination was
	// root-owned (left by an earlier sudo run), the old code treated the failed
	// copy as "cannot build", reused the stale helper, and every confined pod
	// failed. Building into a private staging dir separates the two cases.
	//
	// go build is itself cached, so an up-to-date rebuild is ~a second — far
	// cheaper than the failure mode it removes.
	stage, err := os.MkdirTemp(root, ".execshim-build-")
	if err != nil {
		return "", false, fmt.Errorf("create %s build dir in %s: %w", execShimName, root, err)
	}
	defer func() { _ = os.RemoveAll(stage) }()
	built := filepath.Join(stage, execShimName)

	if buildErr := m.builder.Build(ctx, built); buildErr != nil {
		// A build failure is the honest hostprocess-fallback signal — NOT fatal
		// (an installed k3sm with no source cannot build it). A helper this user
		// cached in an earlier session is still better than no isolation at all,
		// so prefer it; it is only reached when this host cannot build one. A
		// helper someone else left is not: nothing says which source it came
		// from, and a skewed helper fails every confined pod, which is worse
		// than an honest unconfined fallback.
		if !cached {
			fmt.Fprintf(m.out, "note: could not build %s: %v\n", execShimName, buildErr)
			return "", false, nil
		}
		if problem := m.helperProblem(shim); problem != "" {
			fmt.Fprintf(m.out, "note: could not build %s (%v), and the cached %s %s; not reusing it\n", execShimName, buildErr, shim, problem)
			return "", false, nil
		}
		fmt.Fprintf(m.out, "note: could not rebuild %s (%v); reusing the cached helper\n", execShimName, buildErr)
		_ = m.builder.Sign(ctx, shim)
		return m.verifiedBinDir(dir, shim)
	}
	// Re-sign so a stale ad-hoc signature from a prior toolchain does not wedge
	// exec. Signed before the rename, so codesign never writes at the cache path.
	_ = m.builder.Sign(ctx, built)

	blocker, installErr := m.installExecShim(built, dir, shim, cached)
	if installErr == nil {
		return m.verifiedBinDir(dir, shim)
	}

	// The fresh build exists but the cache refused it. Never reuse the cached
	// helper here; install the fresh one somewhere this user owns.
	fresh := m.freshBinDir()
	freshShim := filepath.Join(fresh, execShimName)
	if err := m.installFresh(built, fresh, freshShim); err != nil {
		fmt.Fprintf(m.out, "note: built %s, but could not install it into %s (%v) or %s (%v); the cached helper is NOT reused. Remedy: %s\n",
			execShimName, blocker, installErr, fresh, err, remedyFor(blocker))
		return "", false, nil
	}
	fmt.Fprintf(m.out, "note: built %s, but %s is not writable by you (%v); using the fresh build from %s and NOT the cached helper. Remedy: %s\n",
		execShimName, blocker, installErr, freshShim, remedyFor(blocker))
	return m.verifiedBinDir(fresh, freshShim)
}

// provisionRootExecShim is provisionExecShim for a root run (euid 0, a
// `sudo k3sm dev up --datapath`). The detached server runs as root and execs the
// helper as its Seatbelt launcher, so the helper must be one the unprivileged
// user cannot replace: it is never installed into, or executed from, the user's
// devBinDir, and never handed back. It lives in rootExecShimDir, whose whole
// ancestor chain is checked (rootChainProblem): a chain that fails is refused
// (hostprocess), never repaired. The build is staged inside that dir, so no
// user-writable path ever holds the binary between build and install.
func (m *Manager) provisionRootExecShim(ctx context.Context) (string, bool, error) {
	dir := m.rootExecShimDir()
	// The same creation as the root tier's pod-shim stage under
	// DefaultPodShimDir: component by component, refusing a symlink at each.
	// The base stays 0755 (pods read the shims staged in it); the helper dir
	// needs no reader but root.
	if err := mkdirNoFollow(0o755, filepath.Dir(dir)); err != nil {
		return "", false, err
	}
	if err := mkdirNoFollow(0o700, dir); err != nil {
		return "", false, err
	}
	if problem := m.rootChainProblem(dir); problem != "" {
		fmt.Fprintf(m.out, "note: not using %s for the root %s: %s\n", dir, execShimName, problem)
		return "", false, nil
	}
	shim := filepath.Join(dir, execShimName)
	if err := refuseSymlink(shim); err != nil {
		return "", false, err
	}
	stage, err := os.MkdirTemp(dir, ".build-")
	if err != nil {
		return "", false, fmt.Errorf("create %s build dir in %s: %w", execShimName, dir, err)
	}
	defer func() { _ = os.RemoveAll(stage) }()
	built := filepath.Join(stage, execShimName)

	if buildErr := m.builder.Build(ctx, built); buildErr != nil {
		// Same reasoning as the rootless path: reuse only a helper that passes the
		// root-private check, else the honest hostprocess fallback.
		if _, statErr := os.Lstat(shim); statErr != nil {
			fmt.Fprintf(m.out, "note: could not build %s: %v\n", execShimName, buildErr)
			return "", false, nil
		}
		if problem := m.helperProblem(shim); problem != "" {
			fmt.Fprintf(m.out, "note: could not build %s (%v), and the cached %s %s; not reusing it\n", execShimName, buildErr, shim, problem)
			return "", false, nil
		}
		fmt.Fprintf(m.out, "note: could not rebuild %s (%v); reusing the cached helper\n", execShimName, buildErr)
		_ = m.builder.Sign(ctx, shim)
		return m.verifiedBinDir(dir, shim)
	}
	_ = m.builder.Sign(ctx, built)
	if err := os.Rename(built, shim); err != nil {
		fmt.Fprintf(m.out, "note: could not install %s into %s: %v\n", execShimName, shim, err)
		return "", false, nil
	}
	return m.verifiedBinDir(dir, shim)
}

// verifiedBinDir returns dir as the helper's PATH dir only if shim passes
// helperProblem at this moment, the last check before the server is handed the
// path; otherwise it is the hostprocess fallback with a note.
func (m *Manager) verifiedBinDir(dir, shim string) (string, bool, error) {
	if problem := m.helperProblem(shim); problem != "" {
		fmt.Fprintf(m.out, "note: not using %s: it %s\n", shim, problem)
		return "", false, nil
	}
	return dir, true, nil
}

// helperProblem says why path is not a helper this process may execute, or ""
// when it is: a regular file (not a link), owned by this euid, and writable by
// neither group nor other.
func (m *Manager) helperProblem(path string) string {
	st, err := m.lstatT(path)
	if err != nil {
		return fmt.Sprintf("cannot be inspected (%v)", err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return "is not a regular file"
	case int(st.Uid) != m.euid:
		return fmt.Sprintf("is owned by uid %d, not by you", st.Uid)
	case st.Mode&0o022 != 0:
		return fmt.Sprintf("is group- or other-writable (mode %#o)", st.Mode&0o777)
	}
	return ""
}

// rootChainProblem says why dir cannot hold a helper root will execute, or ""
// when it can: dir and every ancestor up to "/" is a real directory (not a
// link), owned by this euid, and writable by neither group nor other. A single
// component the user could write would let them swap everything below it.
func (m *Manager) rootChainProblem(dir string) string {
	for p := filepath.Clean(dir); ; p = filepath.Dir(p) {
		st, err := m.lstatT(p)
		if err != nil {
			return fmt.Sprintf("%s cannot be inspected (%v)", p, err)
		}
		switch {
		case st.Mode&unix.S_IFMT == unix.S_IFLNK:
			return fmt.Sprintf("%s is a symlink", p)
		case st.Mode&unix.S_IFMT != unix.S_IFDIR:
			return fmt.Sprintf("%s is not a directory", p)
		case int(st.Uid) != m.euid:
			return fmt.Sprintf("%s is owned by uid %d, not %d", p, st.Uid, m.euid)
		case st.Mode&0o022 != 0:
			return fmt.Sprintf("%s is group- or other-writable (mode %#o)", p, st.Mode&0o777)
		}
		if filepath.Dir(p) == p {
			return ""
		}
	}
}

// lstatT is unix.Lstat through the Manager's seam (m.lstat), so a test can
// present a file as root-owned without being root.
func (m *Manager) lstatT(path string) (unix.Stat_t, error) {
	var st unix.Stat_t
	lstat := m.lstat
	if lstat == nil {
		lstat = unix.Lstat
	}
	err := lstat(path, &st)
	return st, err
}

// installExecShim renames the staged build over the cached helper. It refuses
// to replace a cached file this euid does not own (a rename over it would
// discard someone else's file). On failure it returns the path that blocked the
// install: the cached file, or the cache dir when that is what refused the write.
func (m *Manager) installExecShim(built, dir, shim string, cached bool) (string, error) {
	if cached {
		if uid, trusted := m.trustedOwner(shim); !trusted {
			return shim, fmt.Errorf("owned by uid %d", uid)
		}
	}
	if err := refuseSymlink(shim); err != nil {
		return shim, err
	}
	if err := os.Rename(built, shim); err != nil {
		if uid, trusted := m.trustedOwner(dir); !trusted {
			return dir, fmt.Errorf("owned by uid %d: %w", uid, err)
		}
		if cached {
			return shim, err
		}
		return dir, err
	}
	return "", nil
}

// installFresh moves the staged build into the per-user fallback dir, refusing
// a dir or file there that is a symlink or that this euid does not own.
func (m *Manager) installFresh(built, fresh, freshShim string) error {
	if err := mkdirNoFollow(0o755, fresh); err != nil {
		return err
	}
	if uid, trusted := m.trustedOwner(fresh); !trusted {
		return fmt.Errorf("%s is owned by uid %d", fresh, uid)
	}
	if err := refuseSymlink(freshShim); err != nil {
		return err
	}
	if _, err := os.Lstat(freshShim); err == nil {
		if uid, trusted := m.trustedOwner(freshShim); !trusted {
			return fmt.Errorf("%s is owned by uid %d", freshShim, uid)
		}
	}
	if err := os.Rename(built, freshShim); err != nil {
		return fmt.Errorf("install %s: %w", freshShim, err)
	}
	return nil
}

// trustedOwner reports the owner uid of path (not following a link) and whether
// it is this process's euid. Only the euid is trusted: a root run never trusts a
// file the unprivileged user owns, because root would then execute a binary the
// user can replace. An unreadable path is untrusted, with uid -1.
func (m *Manager) trustedOwner(path string) (int, bool) {
	st, err := m.lstatT(path)
	if err != nil {
		return -1, false
	}
	return int(st.Uid), int(st.Uid) == m.euid
}

// handBack gives each path to the invoking human under sudo. It is called only
// with the registry dirs a sudo run had to create (the dev root and its missing
// ancestors), which the next rootless run must be able to write; never with a
// helper binary or the root-owned rootExecShimDir. Only a path this process's euid owns
// is touched. Outside sudo it is a no-op. Best-effort: a failure is a note, not
// fatal, because the root run itself is unaffected.
func (m *Manager) handBack(paths ...string) {
	if m.kubeMg.chownUID < 0 {
		return
	}
	chown := m.lchown
	if chown == nil {
		chown = os.Lchown
	}
	for _, p := range paths {
		if _, owned := m.trustedOwner(p); !owned {
			continue
		}
		if err := chown(p, m.kubeMg.chownUID, m.kubeMg.chownGID); err != nil {
			fmt.Fprintf(m.out, "note: could not hand %s back to %s: %v\n", p, m.kubeMg.chownUser, err)
		}
	}
}

// missingAncestors returns, outermost first, dir and those of its ancestors
// that do not exist yet — the paths a MkdirAll(dir) is about to create.
func missingAncestors(dir string) []string {
	var out []string
	for p := filepath.Clean(dir); ; p = filepath.Dir(p) {
		if _, err := os.Lstat(p); err == nil {
			break
		}
		out = append([]string{p}, out...)
		if filepath.Dir(p) == p {
			break
		}
	}
	return out
}

// remedyFor is the one-line fix for a path the invoking user cannot replace:
// remove exactly that file, or take back exactly that directory.
func remedyFor(path string) string {
	if info, err := os.Lstat(path); err == nil && info.IsDir() {
		who := strconv.Itoa(os.Getuid())
		if u, err := user.Current(); err == nil && u.Username != "" {
			who = u.Username
		}
		return fmt.Sprintf("sudo chown %s %s", who, path)
	}
	return fmt.Sprintf("sudo rm -f %s", path)
}

// withExecShimPath returns a copy of env with binDir prepended to PATH so a
// detached server's exec.LookPath("k3sm-execshim") resolves the provisioned
// helper first. A binDir that is empty (the hostprocess fallback — no helper) or
// already the first PATH element leaves env unchanged. It is a pure helper so the
// PATH-prepend wiring is unit-tested without spawning a process.
func withExecShimPath(env []string, binDir string) []string {
	if binDir == "" {
		return env
	}
	out := make([]string, len(env))
	copy(out, env)
	for i, kv := range out {
		name, val, ok := strings.Cut(kv, "=")
		if !ok || name != "PATH" {
			continue
		}
		if val == binDir || strings.HasPrefix(val, binDir+string(os.PathListSeparator)) {
			return out // already leading — don't duplicate
		}
		out[i] = "PATH=" + binDir + string(os.PathListSeparator) + val
		return out
	}
	// No PATH in env: seed one with the dev-bin dir.
	return append(out, "PATH="+binDir)
}
