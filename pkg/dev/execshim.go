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

// provisionExecShim ensures the k3sm-execshim helper exists in the shared dev-bin
// cache and returns that cache dir. A valid cached helper is reused; an absent one
// is built (CGO_ENABLED=1, workspace go.work) and ad-hoc signed via the builder
// seam. It returns ("", false, nil) when the helper is NOT provisionable (the
// build failed — e.g. an installed k3sm with no workspace source): the caller then
// falls back to hostprocess with a loud notice rather than booting a runtimed
// server that would die at `init sandbox backend`. A non-nil error is a
// filesystem failure (cache dir unwritable), which IS fatal.
func (m *Manager) provisionExecShim(ctx context.Context) (binDir string, ok bool, err error) {
	dir := m.devBinDir()
	if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
		return "", false, fmt.Errorf("create dev bin cache %s: %w", dir, mkErr)
	}
	shim := filepath.Join(dir, execShimName)

	cached := false
	if info, statErr := os.Stat(shim); statErr == nil && !info.IsDir() && info.Size() > 0 {
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
	// with `read profile -: no such file or directory` and the whole M2
	// conformance surface goes red. Observed on a lab Mac 2026-08-27, where the
	// cache had been populated by an earlier session; the re-sign below rewrites
	// the file, so even its mtime looks current and the staleness is invisible.
	//
	// go build is itself cached, so an up-to-date rebuild is ~a second — far
	// cheaper than the failure mode it removes.
	if buildErr := m.builder.Build(ctx, shim); buildErr != nil {
		// A build failure is the honest hostprocess-fallback signal — NOT fatal
		// (an installed k3sm with no source cannot build it). A helper cached by
		// an earlier session is still better than no isolation at all, so prefer
		// it; it is only reached when this host cannot build one.
		if cached {
			fmt.Fprintf(m.out, "note: could not rebuild %s (%v); reusing the cached helper\n", execShimName, buildErr)
			_ = m.builder.Sign(ctx, shim)
			return dir, true, nil
		}
		fmt.Fprintf(m.out, "note: could not build %s: %v\n", execShimName, buildErr)
		return "", false, nil
	}
	// Re-sign so a stale ad-hoc signature from a prior toolchain does not wedge exec.
	_ = m.builder.Sign(ctx, shim)
	return dir, true, nil
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
