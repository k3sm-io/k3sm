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

package registrysvc

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// The zot pin and its staging contract. The binary is accompanied by a VERSION
// MARKER for the reason pkg/executor's kine marker exists: a presence-only check
// cannot tell a correctly staged binary from one an EARLIER release built, so a
// pin change would reach fresh installs only and silently never reach the
// installed base.
const (
	// DefaultZotVersion is THE zot module version the registry child is built
	// from. v2.1.20 is the newest v2.1.x tag at the time of writing and it was
	// chosen by BUILDING it: `go install zotregistry.dev/zot/v2/cmd/zot@v2.1.20`
	// completes CGO_ENABLED=0 for darwin/arm64 out of module, and the resulting
	// binary was driven through the four behaviours this package depends on —
	// authenticated push accepted, anonymous push refused 401, anonymous pull
	// served, and the rendered config accepted by zot's STRICT loader (it
	// UnmarshalExact's the file and fails on any unknown key, so a config this
	// package renders is either exactly right or refused at boot).
	DefaultZotVersion = "v2.1.20"
	// ZotBinaryName is the staged binary's basename (in the workdir bin, in an
	// install payload, and in the release archive).
	ZotBinaryName = "zot"
	// ZotMarkerName is the basename of the version marker written beside a staged
	// zot binary. Exported so the packaging/install paths name the one file the
	// staging contract depends on rather than re-typing the string.
	ZotMarkerName = "zot.version"
	// zotBuildVariant records HOW the pinned child was built. "minimal" is the
	// plain `cmd/zot` build with NO build tags, which is zot's dist-spec-only
	// flavor: no search, metrics, scrub, sync, UI, or image-trust extensions. It
	// is part of the marker because version alone does not identify the binary —
	// the same zot tag builds a much larger registry when its extension tags are
	// passed, and the minimal flavor is what an ingest registry needs.
	zotBuildVariant = "minimal"
	// zotModulePath is the pinned `go install` target.
	zotModulePath = "zotregistry.dev/zot/v2/cmd/zot"
)

// ZotPath names the staged zot binary in a bin dir (a workdir bin or a payload
// dir); zotMarkerPath names its version marker beside it.
func ZotPath(bd string) string { return filepath.Join(bd, ZotBinaryName) }

func zotMarkerPath(bd string) string { return filepath.Join(bd, ZotMarkerName) }

// zotMarkerContent renders a marker: "<version> <variant>\n".
func zotMarkerContent(version string) string { return version + " " + zotBuildVariant + "\n" }

// readZotMarker returns the (version, variant) recorded beside a staged binary. A
// missing or unreadable marker yields ("", ""), which no target ever matches — so
// an unmarked binary always re-stages.
func readZotMarker(bd string) (version, variant string) {
	b, err := os.ReadFile(zotMarkerPath(bd))
	if err != nil {
		return "", ""
	}
	f := strings.Fields(string(b))
	switch len(f) {
	case 0:
		return "", ""
	case 1:
		return f[0], ""
	default:
		return f[0], f[1]
	}
}

// zotStaged reports whether bd holds a zot binary whose marker vouches for
// exactly (version, zotBuildVariant). The marker is written LAST and only after
// the binary is staged and signed, so "marker matches" implies "the binary beside
// it is finished".
func zotStaged(bd, version string) bool {
	if _, err := os.Stat(ZotPath(bd)); err != nil {
		return false
	}
	v, variant := readZotMarker(bd)
	return v == version && variant == zotBuildVariant
}

// writeZotMarker writes the marker atomically (temp + rename) so a crashed or
// killed boot can never leave a half-written marker vouching for the wrong bytes.
func writeZotMarker(bd, version string) error {
	tmp := zotMarkerPath(bd) + ".tmp"
	if err := os.WriteFile(tmp, []byte(zotMarkerContent(version)), 0o644); err != nil {
		return fmt.Errorf("write zot version marker: %w", err)
	}
	if err := os.Rename(tmp, zotMarkerPath(bd)); err != nil {
		return fmt.Errorf("install zot version marker: %w", err)
	}
	return nil
}

// PayloadBinaries is the registry payload set a packaged install stages beside
// the daemon. It is a slice of one today and is a function anyway, so the
// packaging paths iterate a set rather than special-casing a name — the shape
// pkg/executor.PayloadBinaries already established.
func PayloadBinaries() []string { return []string{ZotBinaryName} }

// EnsureZot builds the pinned zot into bd, ad-hoc signs it, and records the
// version marker. It is a no-op only when the marker already vouches for the
// wanted version+variant — never on mere presence.
//
// payloadDir, when non-empty, is a packaged install's staged payload: a marked
// binary there is COPIED rather than built, because a launchd daemon has no Go
// toolchain and building is not an option it has. An unmarked or absent payload
// falls through to the build, which reports its own actionable error.
func EnsureZot(ctx context.Context, bd, payloadDir, version string) error {
	if version == "" {
		version = DefaultZotVersion
	}
	if zotStaged(bd, version) {
		return signBinary(ctx, ZotPath(bd))
	}
	if err := os.MkdirAll(bd, 0o755); err != nil {
		return fmt.Errorf("create bin dir %s: %w", bd, err)
	}
	// Drop any stale marker BEFORE touching the binary: from here until the marker
	// is rewritten, the correct answer to "what is staged?" is "nothing
	// trustworthy", and an interrupted re-stage must re-stage again rather than
	// trust a marker describing bytes we did not finish writing.
	if err := os.Remove(zotMarkerPath(bd)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clear zot version marker: %w", err)
	}
	if seedZot(bd, payloadDir, version) {
		if err := signBinary(ctx, ZotPath(bd)); err != nil {
			return err
		}
		return writeZotMarker(bd, version)
	}
	if err := buildZot(ctx, bd, version); err != nil {
		return err
	}
	if err := signBinary(ctx, ZotPath(bd)); err != nil {
		return err
	}
	// LAST: the marker vouches for a staged, signed binary.
	return writeZotMarker(bd, version)
}

// seedZot copies a payload-staged zot into bd and reports whether it did.
//
// It seeds ONLY when the payload's own marker vouches for the target version.
// Trusting an unmarked payload would mean stamping "this is the new pin" onto
// bytes nobody verified: a node upgraded by replacing only the binary still has
// the previous release's payload staged, and the lie would leave it serving the
// old registry while claiming the new one. Every failure reads as "not seeded",
// so the build path — which reports a real error — owns the diagnosis.
func seedZot(bd, payloadDir, version string) bool {
	if payloadDir == "" || !zotStaged(payloadDir, version) {
		return false
	}
	if err := copyFile(ZotPath(payloadDir), ZotPath(bd)+".tmp", 0o755); err != nil {
		return false
	}
	return os.Rename(ZotPath(bd)+".tmp", ZotPath(bd)) == nil
}

// zotModuleCacheDir resolves the stable module cache the build downloads into,
// and runZotBuild runs the build itself. Both are vars so a test can assert the
// build environment and the cache's reuse across builds without fetching
// anything.
var (
	zotModuleCacheDir = hostGoModCache
	runZotBuild       = goInstallZot
)

// buildZot runs the pinned `go install` into a scratch GOPATH and copies the
// result into bd.
func buildZot(ctx context.Context, bd, version string) error {
	// `go install pkg@version` REFUSES to write a cross-compiled binary when GOBIN
	// is set, and a Go toolchain running under Rosetta on an Apple-silicon Mac
	// counts as cross-compiling for darwin/arm64. So install into a scratch GOPATH
	// and copy the result out. Cross-compiled installs land in
	// bin/<goos>_<goarch>/, native ones directly in bin/, so both are probed.
	gopath, err := os.MkdirTemp("", "k3sm-zot-gopath")
	if err != nil {
		return fmt.Errorf("zot build scratch dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(gopath) }()

	// The scratch GOPATH is thrown away with the build; the MODULE CACHE must not
	// be, or zot's whole dependency tree is downloaded and deleted again on EVERY
	// boot — a per-boot network round trip masquerading as a one-time cold-cache
	// cost.
	modCache, err := zotModuleCacheDir(ctx)
	if err != nil {
		return err
	}
	if out, err := runZotBuild(ctx, version, gopath, modCache); err != nil {
		return fmt.Errorf("build zot %s (CGO_ENABLED=0): %w (a packaged install has no Go toolchain — re-run `sudo k3sm install` so the staged payload carries this pin): %s",
			version, err, out)
	}
	goos, goarch := runtime.GOOS, runtime.GOARCH
	if v := os.Getenv("GOOS"); v != "" {
		goos = v
	}
	if v := os.Getenv("GOARCH"); v != "" {
		goarch = v
	}
	built := filepath.Join(gopath, "bin", goos+"_"+goarch, ZotBinaryName) // cross-compiled
	if _, statErr := os.Stat(built); statErr != nil {
		built = filepath.Join(gopath, "bin", ZotBinaryName) // native
	}
	// Stage through a temp name + rename so an interrupted copy cannot leave a
	// truncated binary at the real path.
	if err := copyFile(built, ZotPath(bd)+".tmp", 0o755); err != nil {
		return fmt.Errorf("stage zot binary: %w", err)
	}
	if err := os.Rename(ZotPath(bd)+".tmp", ZotPath(bd)); err != nil {
		return fmt.Errorf("install zot binary: %w", err)
	}
	return nil
}

// zotBuildEnv is the environment the pinned `go install` runs under.
//
// CGO_ENABLED=0 because nothing in the minimal zot build needs cgo and a pure-Go
// child is what keeps a C toolchain out of every k3sm artifact. GOWORK=off keeps
// the workspace's go.work out of an out-of-module install. GOBIN is CLEARED (not
// merely unset in our own env) so an ambient GOBIN cannot re-trigger the
// cross-compile refusal buildZot documents. GOMODCACHE is pinned away from the
// scratch GOPATH so the pin's modules are fetched once per machine.
func zotBuildEnv(gopath, modCache string) []string {
	return append(os.Environ(),
		"CGO_ENABLED=0", "GOWORK=off", "GOBIN=", "GOPATH="+gopath, "GOMODCACHE="+modCache)
}

// hostGoModCache returns the HOST TOOLCHAIN's own module cache (`go env
// GOMODCACHE`, which already honours an ambient GOMODCACHE or GOPATH).
//
// The host cache is chosen over a k3sm-private one deliberately: this path only
// runs where a Go toolchain exists (a packaged install seeds from its payload and
// never builds), and the host cache is shared by every work dir and every dev
// instance. The fallback covers a toolchain reporting no cache at all; it gives
// up the sharing but keeps the property that matters — the path is the same on
// the next boot.
func hostGoModCache(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "go", "env", "GOMODCACHE").Output()
	if err != nil {
		return "", fmt.Errorf("resolve the Go module cache (go env GOMODCACHE): %w", err)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		base, cerr := os.UserCacheDir()
		if cerr != nil {
			return "", fmt.Errorf("resolve a stable Go module cache: %w", cerr)
		}
		dir = filepath.Join(base, "k3sm", "gomodcache")
	}
	// Created here rather than left to the toolchain so an unwritable cache fails
	// with the path named instead of inside a `go install` diagnostic.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create Go module cache %s: %w", dir, err)
	}
	return dir, nil
}

// goInstallZot runs the pinned `go install` into the scratch GOPATH's bin,
// downloading through the stable module cache. It returns the combined output so
// a failure carries the toolchain's own diagnostic.
func goInstallZot(ctx context.Context, version, gopath, modCache string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "go", "install", zotModulePath+"@"+version)
	cmd.Env = zotBuildEnv(gopath, modCache)
	return cmd.CombinedOutput()
}

// signBinary ad-hoc signs (codesign -s - -f) a staged binary so an arm64 Mach-O
// can exec on macOS. Signing failures are tolerated — an already-valid signature
// or a non-macOS CI host must not block bring-up, and a binary that truly cannot
// run fails loudly at exec.
func signBinary(ctx context.Context, path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("stage zot: %s is absent after staging: %w", path, err)
	}
	_ = exec.CommandContext(ctx, "codesign", "-s", "-", "-f", path).Run()
	return nil
}

// copyFile copies src to dst with the given mode, replacing dst if present.
func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
