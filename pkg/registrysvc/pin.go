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
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"k3sm.io/k3sm/internal/atomicfile"
	"k3sm.io/k3sm/internal/binsign"
)

// The zot pin and its staging contract. The binary is accompanied by a VERSION
// MARKER for the reason pkg/executor's kine marker exists: a presence-only check
// cannot tell a correctly staged binary from one an EARLIER release built, so a
// pin change would reach fresh installs only and silently never reach the
// installed base.
const (
	// DefaultZotVersion is THE zot module version the registry child is built
	// from. v2.1.22 is the newest v2.1.x tag at the time of writing and it was
	// chosen by BUILDING it: `go install zotregistry.dev/zot/v2/cmd/zot@v2.1.22`
	// completes CGO_ENABLED=0 for darwin/arm64 out of module, and the resulting
	// binary was driven through the four behaviours this package depends on —
	// authenticated push accepted, anonymous push refused 401, anonymous pull
	// served, and the rendered config accepted by zot's STRICT loader (it
	// UnmarshalExact's the file and fails on any unknown key, so a config this
	// package renders is either exactly right or refused at boot).
	DefaultZotVersion = "v2.1.22"
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

// PayloadVerifier is the release signing path as zot staging consumes it: the
// daemon's one signing decision, resolved by the caller (pkg/executor's
// ReleaseVerifier), never probed here. VerifyPayloadBinary returns nil when path
// is a regular file carrying the release signature, and an error otherwise; it
// never signs or changes the file.
type PayloadVerifier interface {
	VerifyPayloadBinary(ctx context.Context, path string) error
}

// EnsureZot builds the pinned zot into bd, ad-hoc signs it, and records the
// version marker. It is a no-op only when the marker already vouches for the
// wanted version+variant — never on mere presence. It is the dev path:
// EnsureZotWith with no release verifier.
//
// payloadDir, when non-empty, is a packaged install's staged payload: a marked
// binary there is COPIED rather than built, because a launchd daemon has no Go
// toolchain and building is not an option it has. An unmarked or absent payload
// falls through to the build, which reports its own actionable error.
func EnsureZot(ctx context.Context, bd, payloadDir, version string) error {
	return EnsureZotWith(ctx, nil, bd, payloadDir, version)
}

// EnsureZotWith is EnsureZot under the caller's signing decision. A nil release
// is the dev path, exactly EnsureZot. A non-nil release is the release path (a
// Developer ID-signed k3sm): zot is the payload's copy and nothing else, verified
// with release and used byte-identical. It is never built and never signed, and a
// copy that fails verification refuses with release's error, with no fall-through
// to the dev path.
func EnsureZotWith(ctx context.Context, release PayloadVerifier, bd, payloadDir, version string) error {
	if version == "" {
		version = DefaultZotVersion
	}
	// Remove the temps a killed install left; nothing is staging zot yet.
	if err := atomicfile.ReapOrphans(bd, ZotBinaryName); err != nil {
		return fmt.Errorf("reap zot staging temps: %w", err)
	}
	if release != nil {
		return ensureShippedZot(ctx, release, bd, payloadDir, version)
	}
	if zotStaged(bd, version) {
		return ensureZotSigned(ctx, bd)
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
	if seedZot(ctx, bd, payloadDir, version) {
		return writeZotMarker(bd, version)
	}
	if err := buildZot(ctx, bd, version); err != nil {
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
//
// The copy is installed on a new inode and signed as a temp before it takes the
// name (binsign.Install), so a zot the registry is still running is never
// rewritten in place.
func seedZot(ctx context.Context, bd, payloadDir, version string) bool {
	if payloadDir == "" || !zotStaged(payloadDir, version) {
		return false
	}
	return binsign.Install(ctx, binsign.Codesign{}, ZotPath(payloadDir), ZotPath(bd), 0o755) == nil
}

// ensureShippedZot is the release path. The source is the payload's zot (the work
// dir's own copy when no payload is staged), and it must pass release before
// anything else happens. A work-dir copy with identical bytes in a trusted
// directory is verified in place and left on its inode; anything else there is
// replaced on a new inode through atomicfile, the temp verified again before it
// takes the name. The version marker is written for the verified bytes, and zot is
// recorded as healed so a later dev heal at that marker never rewrites it.
func ensureShippedZot(ctx context.Context, release PayloadVerifier, bd, payloadDir, version string) error {
	dst := ZotPath(bd)
	src := dst
	if payloadDir != "" {
		src = ZotPath(payloadDir)
	}
	if err := release.VerifyPayloadBinary(ctx, src); err != nil {
		return fmt.Errorf("stage zot: %w", err)
	}
	same := src == dst
	if !same {
		var err error
		if same, err = sameBytes(src, dst); err != nil {
			return fmt.Errorf("stage zot: compare %s with %s: %w", src, dst, err)
		}
	}
	if same {
		// Trusting a copy already in bd needs the trust atomicfile's install checks
		// give the copies it makes: nobody else may write there.
		if err := atomicfile.CheckTrustedDir(bd); err != nil {
			return fmt.Errorf("stage zot: verify %s in place: %w", dst, err)
		}
		if src != dst {
			if err := release.VerifyPayloadBinary(ctx, dst); err != nil {
				return fmt.Errorf("stage zot: %w", err)
			}
		}
	} else {
		if err := os.MkdirAll(bd, 0o755); err != nil {
			return fmt.Errorf("create bin dir %s: %w", bd, err)
		}
		if err := os.Remove(zotMarkerPath(bd)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("clear zot version marker: %w", err)
		}
		if err := atomicfile.InstallFile(src, dst, 0o755, func(tmp string) error {
			return release.VerifyPayloadBinary(ctx, tmp)
		}); err != nil {
			return fmt.Errorf("stage zot: install the shipped %s: %w", ZotBinaryName, err)
		}
	}
	if !zotStaged(bd, version) {
		if err := writeZotMarker(bd, version); err != nil {
			return err
		}
	}
	return binsign.RecordHealed(bd, strings.TrimSpace(zotMarkerContent(version)), ZotBinaryName)
}

// sameBytes reports whether the regular file b holds exactly a's bytes. An absent
// or non-regular b (a symlink above all) is never the same: it is replaced, never
// followed and never verified in place.
func sameBytes(a, b string) (bool, error) {
	li, err := os.Lstat(b)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !li.Mode().IsRegular() {
		return false, nil
	}
	ha, err := fileSHA256(a)
	if err != nil {
		return false, err
	}
	hb, err := fileSHA256(b)
	if err != nil {
		return false, err
	}
	return ha == hb, nil
}

// fileSHA256 returns the sha256 of the file at path.
func fileSHA256(path string) ([sha256.Size]byte, error) {
	var sum [sha256.Size]byte
	f, err := os.Open(path)
	if err != nil {
		return sum, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return sum, err
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
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
	// Stage on a new inode, signed as a temp before the rename: an interrupted
	// copy cannot leave a truncated binary at the real path, the real path never
	// names unsigned bytes, and a running zot's mapping is never rewritten.
	if err := binsign.Install(ctx, binsign.Codesign{}, built, ZotPath(bd), 0o755); err != nil {
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
//
// The Go variables that weaken module verification or redirect the fetch are
// DROPPED from the ambient environment and the safe values set explicitly, last,
// so they win: the checksum database stays on, the proxy is the public one, and
// GOTOOLCHAIN=local keeps a host Go older than zot's go directive from silently
// fetching a toolchain (see ErrZotGoTooOld).
func zotBuildEnv(gopath, modCache string) []string {
	env := make([]string, 0, len(os.Environ())+10)
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if slices.Contains(zotDroppedEnv, name) {
			continue
		}
		env = append(env, kv)
	}
	return append(env,
		"CGO_ENABLED=0", "GOWORK=off", "GOBIN=", "GOPATH="+gopath, "GOMODCACHE="+modCache,
		"GOSUMDB=sum.golang.org", "GOPROXY=https://proxy.golang.org,direct", "GOTOOLCHAIN=local")
}

// zotDroppedEnv lists the ambient variables that weaken verification, redirect
// module fetches or change the toolchain, removed before the pinned values are set.
var zotDroppedEnv = []string{
	"GOSUMDB", "GONOSUMDB", "GONOSUMCHECK", "GOPRIVATE", "GOINSECURE", "GOFLAGS",
	"GOPROXY", "GONOPROXY", "GOVCS", "GOTOOLCHAIN",
}

// ErrZotGoTooOld marks a zot build refused because the host Go is older than
// the pinned zot's go directive. The install runs with GOTOOLCHAIN=local, so the
// toolchain is never fetched; the operator upgrades Go or installs the packaged payload.
var ErrZotGoTooOld = errors.New("the host Go toolchain is older than the pinned zot requires (GOTOOLCHAIN=local forbids fetching one)")

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
	out, err := cmd.CombinedOutput()
	if err != nil && zotGoTooOld(out) {
		err = fmt.Errorf("%w: %w", ErrZotGoTooOld, err)
	}
	return out, err
}

// zotGoTooOld reports whether a `go install` diagnostic is the local-toolchain
// refusal ("requires go >= X (running go Y; GOTOOLCHAIN=local)").
func zotGoTooOld(out []byte) bool {
	s := string(out)
	return strings.Contains(s, "GOTOOLCHAIN=local") && strings.Contains(s, "requires go")
}

// ensureZotSigned makes sure the staged zot at path carries a valid ad-hoc
// signature so an arm64 Mach-O can exec on macOS. It runs at every start on the
// live binary, so it never writes it in place (see package binsign): HealOnce
// first replaces it once per staged version, clearing a vnode an older k3sm may
// have left poisoned by its in-place `codesign -f`, and EnsureSigned then leaves
// a validly ad-hoc-signed zot alone and signs any other as a temp copy renamed
// over it. Signing failures are tolerated (a non-macOS CI host must not block
// bring-up, and a failure leaves the file as it was); a binary that truly cannot
// run fails loudly at exec.
func ensureZotSigned(ctx context.Context, bd string) error {
	path := ZotPath(bd)
	if _, err := os.Lstat(path); err != nil {
		return fmt.Errorf("stage zot: %s is absent after staging: %w", path, err)
	}
	stamp := "unmarked"
	if b, err := os.ReadFile(zotMarkerPath(bd)); err == nil {
		if f := strings.Join(strings.Fields(string(b)), " "); f != "" {
			stamp = f
		}
	}
	_ = binsign.HealOnce(ctx, binsign.Codesign{}, bd, stamp, ZotBinaryName)
	_, _ = binsign.EnsureSigned(ctx, binsign.Codesign{}, path)
	return nil
}
