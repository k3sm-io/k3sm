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

// freshBinDir is the per-user fallback helper dir, <registry root>/.bin-<euid>,
// used only when a fresh k3sm-execshim build exists but cannot be installed into
// the shared cache (devBinDir): a file or dir there is owned by someone else
// (typically root, left by an earlier sudo run) or is not writable. The euid in
// the name keeps a root run and a rootless run from sharing it.
func (m *Manager) freshBinDir() string {
	return filepath.Join(m.reg.root, ".bin-"+strconv.Itoa(m.euid))
}

// provisionExecShim ensures a k3sm-execshim helper built from the current source
// is on hand and returns the dir holding it (prepended to the detached server's
// PATH). The helper is built (CGO_ENABLED=1, workspace go.work) into a private
// staging dir and ad-hoc signed there via the builder seam, then installed into
// the shared dev-bin cache by rename.
//
// The two failure modes are kept apart, because they call for opposite answers:
//
//   - The build fails (an installed k3sm with no workspace source, or no
//     toolchain): a helper cached by an earlier session is reused, but only one
//     the invoking user owns. A helper owned by anyone else is refused and the
//     caller falls back to hostprocess (see trustedOwner).
//   - The build succeeds but cannot be installed into the cache (the cached file
//     is owned by someone else, or the cache is not writable): the cached helper
//     is NEVER reused, since a fresh one exists and the cached one may predate
//     the current argv contract. The fresh build goes to freshBinDir instead, and
//     one note names the blocking path and the remedy.
//
// It returns ("", false, nil) when no trustworthy helper is available: the caller
// then falls back to hostprocess with a loud notice rather than booting a
// runtimed server that would die at `init sandbox backend`. A non-nil error is a
// filesystem failure (the dev root cannot be written, or a symlinked stage path),
// which IS fatal. Under sudo, every path this run creates or installs is handed
// back to the invoking human (handBack), so a later rootless run can replace it.
func (m *Manager) provisionExecShim(ctx context.Context) (binDir string, ok bool, err error) {
	dir := m.devBinDir()
	// The same symlink refusal as the pod-shim stage (refuseSymlink): a root
	// `k3sm dev up --datapath` writes and signs here, and a pre-planted link would
	// redirect that write into a tree the planter chooses.
	if err := refuseSymlink(dir); err != nil {
		return "", false, err
	}
	created := missingAncestors(dir)
	if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
		return "", false, fmt.Errorf("create dev bin cache %s: %w", dir, mkErr)
	}
	m.handBack(created...)
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
	stage, err := os.MkdirTemp(m.reg.root, ".execshim-build-")
	if err != nil {
		return "", false, fmt.Errorf("create %s build dir in %s: %w", execShimName, m.reg.root, err)
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
		if uid, trusted := m.trustedOwner(shim); !trusted {
			fmt.Fprintf(m.out, "note: could not build %s (%v), and the cached %s is owned by uid %d, not by you; not reusing it\n", execShimName, buildErr, shim, uid)
			return "", false, nil
		}
		fmt.Fprintf(m.out, "note: could not rebuild %s (%v); reusing the cached helper\n", execShimName, buildErr)
		_ = m.builder.Sign(ctx, shim)
		return dir, true, nil
	}
	// Re-sign so a stale ad-hoc signature from a prior toolchain does not wedge
	// exec. Signed before the rename, so codesign never writes at the cache path.
	_ = m.builder.Sign(ctx, built)

	blocker, installErr := m.installExecShim(built, dir, shim, cached)
	if installErr == nil {
		m.handBack(dir, shim)
		return dir, true, nil
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
	m.handBack(fresh, freshShim)
	fmt.Fprintf(m.out, "note: built %s, but %s is not writable by you (%v); using the fresh build from %s and NOT the cached helper. Remedy: %s\n",
		execShimName, blocker, installErr, freshShim, remedyFor(blocker))
	return fresh, true, nil
}

// installExecShim renames the staged build over the cached helper. It refuses
// to replace a cached file the invoking user does not own (a rename over it
// would discard someone else's file). On failure it returns the path that
// blocked the install: the cached file, or the cache dir when that is what
// refused the write.
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
// a dir or file there that is a symlink or that the invoking user does not own.
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
// that owner is the invoking user: this process's euid or, under sudo, the
// SUDO_USER human a datapath run hands its artifacts back to. An unreadable
// path is untrusted, with uid -1.
func (m *Manager) trustedOwner(path string) (int, bool) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return -1, false
	}
	uid := int(st.Uid)
	return uid, uid == m.euid || (m.kubeMg.chownUID >= 0 && uid == m.kubeMg.chownUID)
}

// handBack gives each path to the invoking human under sudo, so a root
// `k3sm dev up --datapath` stops leaving root-owned files in the user's dev
// cache that a later rootless run cannot replace. Only a path this process's
// euid owns is touched (one this run created or installed); anything else is
// left alone. Outside sudo it is a no-op. Best-effort: a failure is a note, not
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
		var st unix.Stat_t
		if err := unix.Lstat(p, &st); err != nil || int(st.Uid) != m.euid {
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
// remove it, or take it back.
func remedyFor(path string) string {
	who := strconv.Itoa(os.Getuid())
	if u, err := user.Current(); err == nil && u.Username != "" {
		who = u.Username
	}
	return fmt.Sprintf("sudo rm -rf %s (or sudo chown -R %s %s)", path, who, path)
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
