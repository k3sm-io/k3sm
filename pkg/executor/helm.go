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

package executor

import (
	"context"
	"debug/buildinfo"
	"errors"
	"fmt"
	"go/version"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"

	"k3sm.io/k3sm/pkg/helmchart"
)

// The helm binary in the payload.
//
// helm is the helm controller's Job command[0]. It is a source-built child like
// kine, etcd and zot: `k3sm payload` builds it from the pinned helm module inside
// the wrapper module pkg/helmchart/helmchild (helmchart.HelmBuildArgs, under the
// stagedChild protocol, so it lands signed beside its helmchart.HelmMarkerName
// marker); `k3sm install` stages the payload; seedBinDir copies it into the work
// dir's bin at boot (it is in PayloadBinaries), and provision re-signs it there.
//
// The version is in the binary's name, so a pin bump stages a new file beside the
// old one. The marker tells this build from any other build of the same version (a
// tarball-era helm above all): on the dev path a helm whose marker does not vouch
// for the pin and variant is not current, so seedBinDir replaces it from a payload
// whose marker does, and EnsureHelm rebuilds it in a dev shell. A daemon with no
// vouching payload keeps running the helm it has: it cannot build, and the remedy
// is a reinstall with a current payload, which the seed then takes.
//
// EnsureHelm is the dev-shell fallback, the analog of the control plane's `gh`
// re-stage: it builds only when the work dir has no staged helm AND `gh` is on
// PATH. A launchd daemon never has `gh`, so a packaged install whose payload
// lacked helm gets ErrHelmNotStaged and never builds from the daemon; a dev shell
// builds the pin.

// ErrHelmNotStaged means the work dir has no staged helm and this process may
// not build one: it is not a dev shell (no `gh` on PATH), so it is a daemon
// whose payload lacked helm. The remedy is a reinstall with a current payload.
var ErrHelmNotStaged = errors.New("helm is not staged and this process does not build it (no `gh` on PATH: not a dev shell)")

// EnsureHelm returns the path of a staged helm in binDir. On the dev path a copy
// whose marker vouches for the pin and variant is used and re-signed if needed.
// Any other copy, or none, is rebuilt only in a dev shell (`gh` on PATH, the same
// gate as the control plane's re-stage); outside one a present copy is used as it
// is (the seed owns replacing it) and an absent one is ErrHelmNotStaged, with
// nothing built.
//
// On the release path (a Developer ID-signed k3sm, see signingPolicy) helm comes
// from the signed payload only: a staged copy is verified against the Developer
// ID requirement and used byte-identical, and an absent or failing one is an
// ErrPayloadSignature. It is never built or signed there.
func EnsureHelm(ctx context.Context, binDir string) (string, error) {
	p, err := resolveSigningPolicy(ctx, slog.Default())
	if err != nil {
		return "", err
	}
	if p.release && !fileExists(helmchart.HelmPath(binDir)) {
		return "", fmt.Errorf("%w: %s is not staged; a release-signed k3sm runs only the helm its signed payload ships", ErrPayloadSignature, helmchart.HelmPath(binDir))
	}
	if err := stageHelm(ctx, p, binDir); err != nil {
		return "", err
	}
	return helmchart.HelmPath(binDir), nil
}

// stageHelm places a signed helmchart.HelmBinaryName in bd.
//
// On the release path the staged copy is the signed payload's (the seed replaces
// any other), verified in place by signHelm; it is never built. On the dev path a
// copy whose marker vouches for the pin and variant is kept and re-signed if
// needed; any other copy, or none, is rebuilt in a dev shell (`gh` on PATH). Outside
// one (a daemon), a present copy is used as it is, and an absent one is
// ErrHelmNotStaged.
func stageHelm(ctx context.Context, p signingPolicy, bd string) error {
	dst := helmchart.HelmPath(bd)
	if p.release {
		if !fileExists(dst) {
			return fmt.Errorf("%w: %s is not staged and a release-signed k3sm never builds it", ErrPayloadSignature, dst)
		}
		return signHelm(ctx, p, bd)
	}
	if helmChild().staged(bd) {
		return signHelm(ctx, p, bd)
	}
	if _, err := lookPathGh(); err != nil {
		if fileExists(dst) {
			return signHelm(ctx, p, bd)
		}
		return fmt.Errorf("%w: %s", ErrHelmNotStaged, dst)
	}
	return stageHelmBuild(ctx, bd)
}

// PayloadVouchesHelm reports whether the payload bin dir holds a helm whose marker
// vouches for the pin and variant: the predicate under which the work-dir seed takes
// the payload helm over a work-dir copy it does not vouch for. An installer uses it
// to prove the set it staged is one the seed will take.
func PayloadVouchesHelm(bd string) bool { return helmChild().staged(bd) }

// stageHelmBuild builds the pinned helm into bd under the stagedChild protocol: a
// no-op when bd's marker already vouches for the pin and variant, otherwise a
// build, signed and installed on a new inode, with the marker written last. It is
// the packaging producer's helm step (StagePayload) and EnsureHelm's dev build.
func stageHelmBuild(ctx context.Context, bd string) error {
	if err := helmchart.ValidateHelmPin(); err != nil {
		return err
	}
	if err := os.MkdirAll(bd, 0o755); err != nil {
		return fmt.Errorf("create bin dir %s: %w", bd, err)
	}
	return helmChild().ensureInto(ctx, bd)
}

// helmChild is helm's stagedChild declaration at the pin. The dev path and the
// packaging producer stage it with ensureInto (marker plus build); the release
// path's seed stages the payload's copy with ensureShipped, which reads the stamp
// from the verified bytes (helmStampFromBinary).
func helmChild() stagedChild {
	return stagedChild{
		name:      helmchart.HelmBinaryName,
		marker:    helmchart.HelmMarkerName,
		version:   helmchart.HelmVersion,
		variant:   helmchart.HelmBuildVariant,
		build:     buildHelmWrapper,
		readStamp: helmStampFromBinary,
	}
}

// helmStampFromBinary is helm's production stamp reader: the build info Go records
// in the binary, read without running it.
func helmStampFromBinary(path string) (string, string, error) {
	return recoverStamp(path, func() (string, string, error) {
		bi, err := buildinfo.ReadFile(path)
		if err != nil {
			return "", "", fmt.Errorf("read build info: %w", err)
		}
		return helmStampOf(bi)
	})
}

// helmStampOf derives helm's (version, variant) from its build info. The version is
// the helm module's (main package helmchart.HelmMainPackage, never replaced). The
// variant is helmchart.HelmBuildVariant only for the build the wrapper produces:
// CGO_ENABLED=0, -trimpath, a toolchain no older than helmchart.HelmMinGoVersion,
// and every module of helmchart.HelmRaisedModules linked at its raised version,
// unreplaced. A build that misses any of those is an error naming it, so the
// upstream tarball (an older toolchain, helm's own golang.org/x versions) is never
// taken for the pinned build. helm's -X version stamp is not checked here: the
// release build strips the symbol table (-s), so the staging script checks the
// stamped strings in the bytes instead. Pure.
func helmStampOf(bi *debug.BuildInfo) (string, string, error) {
	v, cgo, err := etcdStampOf(bi, helmchart.HelmMainPackage, helmchart.HelmModule)
	if err != nil {
		return "", "", err
	}
	if !version.IsValid(bi.GoVersion) || version.Compare(bi.GoVersion, helmchart.HelmMinGoVersion) < 0 {
		return "", "", fmt.Errorf("built with %q, older than the %s helm requires", bi.GoVersion, helmchart.HelmMinGoVersion)
	}
	if !slices.ContainsFunc(bi.Settings, func(s debug.BuildSetting) bool { return s.Key == "-trimpath" && s.Value == "true" }) {
		return "", "", errors.New("build info records no -trimpath=true")
	}
	for _, pv := range strings.Fields(helmchart.HelmRaisedModules) {
		path, want, _ := strings.Cut(pv, "@")
		i := slices.IndexFunc(bi.Deps, func(d *debug.Module) bool { return d.Path == path })
		switch {
		case i < 0:
			return "", "", fmt.Errorf("build info does not link %s (the wrapper raises it to %s)", path, want)
		case bi.Deps[i].Replace != nil:
			return "", "", fmt.Errorf("module %s is replaced by %s", path, bi.Deps[i].Replace.Path)
		case bi.Deps[i].Version != want:
			return "", "", fmt.Errorf("module %s is at %s, the wrapper raises it to %s", path, bi.Deps[i].Version, want)
		}
	}
	if cgo != "nocgo" {
		return v, cgo, nil
	}
	return v, helmchart.HelmBuildVariant, nil
}

// buildHelmWrapper materializes the wrapper module under scratch and builds helm
// from it into scratch, under etcd's build environment (CGO_ENABLED=0, GOWORK=off,
// GOFLAGS=-mod=readonly, GOTOOLCHAIN=local, the checksum database on).
func buildHelmWrapper(ctx context.Context, scratch string) (string, error) {
	src := filepath.Join(scratch, "src")
	if err := helmchart.WriteHelmWrapper(src); err != nil {
		return "", err
	}
	// The same stable module cache kine's build uses (see hostGoModCache): the
	// scratch dir dies with the build, the downloaded modules must not.
	modCache, err := kineModuleCacheDir(ctx)
	if err != nil {
		return "", err
	}
	bin := filepath.Join(scratch, helmchart.HelmBinaryName)
	cmd := exec.CommandContext(ctx, "go", helmchart.HelmBuildArgs(bin)...)
	cmd.Dir = src
	cmd.Env = etcdBuildEnv(scratch, modCache)
	if combined, err := runHelmBuild(cmd); err != nil {
		return "", fmt.Errorf("build %s (CGO_ENABLED=0): %w (a packaged install has no Go toolchain — re-run `sudo k3sm install` so the staged payload carries this pin): %s",
			helmchart.HelmBinaryName, err, combined)
	}
	return bin, nil
}

// runHelmBuild runs the prepared build command and returns its combined output. A
// var so a test can assert the command without fetching or compiling anything.
var runHelmBuild = func(cmd *exec.Cmd) ([]byte, error) { return cmd.CombinedOutput() }
