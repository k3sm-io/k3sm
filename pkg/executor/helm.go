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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"

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
// The version is in the binary's name, so in the work dir presence is the version
// marker: a pin bump stages a new file beside the old one rather than trusting it.
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

// EnsureHelm returns the path of a staged helm in binDir. A staged copy is used
// as is (see the note above on why presence suffices) and re-signed on the dev
// path. When none is staged it builds the pinned helm only in a dev shell (`gh`
// on PATH, the same gate as the control plane's re-stage); otherwise it returns
// ErrHelmNotStaged without building anything.
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
	if !fileExists(helmchart.HelmPath(binDir)) {
		if _, err := lookPathGh(); err != nil {
			return "", fmt.Errorf("%w: %s", ErrHelmNotStaged, helmchart.HelmPath(binDir))
		}
	}
	if err := stageHelm(ctx, p, binDir); err != nil {
		return "", err
	}
	return helmchart.HelmPath(binDir), nil
}

// stageHelm places a signed helmchart.HelmBinaryName in bd: an existing copy is
// kept (and made runnable under p, see signHelm), an absent one is built. The
// release path never reaches the build: EnsureHelm refuses an absent helm there
// first.
func stageHelm(ctx context.Context, p signingPolicy, bd string) error {
	dst := helmchart.HelmPath(bd)
	// Presence is trusted as the version marker because BinDir is root-owned
	// 0755 under the daemon: only root (install and the payload seed) can place
	// a file under the versioned name.
	if fileExists(dst) {
		return signHelm(ctx, p, bd)
	}
	if p.release {
		return fmt.Errorf("%w: %s is not staged and a release-signed k3sm never builds it", ErrPayloadSignature, dst)
	}
	return stageHelmBuild(ctx, bd)
}

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

// helmChild is helm's stagedChild declaration at the pin. It is staged only by
// ensureInto (the dev path and the packaging producer); the release path takes the
// payload's helm through the seed and signHelm, so it reads no stamp.
func helmChild() stagedChild {
	return stagedChild{
		name:    helmchart.HelmBinaryName,
		marker:  helmchart.HelmMarkerName,
		version: helmchart.HelmVersion,
		variant: helmchart.HelmBuildVariant,
		build:   buildHelmWrapper,
	}
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
