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
	"os"
	"os/exec"
	"path/filepath"

	"k3sm.io/k3sm/pkg/executor/etcdchild"
)

// etcd staging constants. etcd is the second stagedChild: built from source at a pin,
// staged beside a version marker, exactly like kine. etcdutl is the third: the
// offline tool `k3sm snapshot restore` runs, built from the SAME wrapper module, so
// it links exactly the etcd modules the server does.
const (
	// etcdBinaryName is the staged etcd server binary's basename.
	etcdBinaryName = "etcd"
	// EtcdMarkerName is the basename of the version marker written beside a staged
	// etcd binary. Exported so the packaging/install paths name the one file the
	// staging contract depends on rather than re-typing the string.
	EtcdMarkerName = "etcd.version"
	// etcdutlBinaryName is the staged etcdutl binary's basename.
	etcdutlBinaryName = "etcdutl"
	// EtcdutlMarkerName is the version marker written beside a staged etcdutl.
	EtcdutlMarkerName = "etcdutl.version"
	// etcdServerPackage and etcdutlPackage are what the wrapper builds: its own main
	// (upstream's server/main.go) and upstream's etcdutl main, a `tool` of the
	// wrapper module.
	etcdServerPackage = "."
	etcdutlPackage    = "go.etcd.io/etcd/etcdutl/v3"
	// etcdBuildVariant records HOW the binary was built: CGO_ENABLED=0. etcd needs no
	// cgo, and a cgo build would pull a C toolchain into the release stage.
	etcdBuildVariant = "nocgo"
)

// ErrEtcdVersionUnpinned marks a request for an etcd version the embedded wrapper
// module does not pin. The wrapper's go.sum is the lockfile for exactly one version,
// so any other version cannot be built hash-checked.
var ErrEtcdVersionUnpinned = errors.New("etcd version is not the one the embedded wrapper pins")

// etcdStaged reports whether bd holds an etcd binary whose marker vouches for exactly
// (version, etcdBuildVariant).
func etcdStaged(bd, version string) bool { return etcdChild(version).staged(bd) }

// ensureEtcdInto stages the pinned etcd into bd under the stagedChild protocol. A
// version other than DefaultEtcdVersion is refused before anything is touched.
func ensureEtcdInto(ctx context.Context, bd, version string) error {
	if version != DefaultEtcdVersion {
		return fmt.Errorf("stage etcd %s: %w (%s)", version, ErrEtcdVersionUnpinned, DefaultEtcdVersion)
	}
	return etcdChild(version).ensureInto(ctx, bd)
}

// etcdChild is etcd's stagedChild declaration at the given pin.
func etcdChild(version string) stagedChild {
	return stagedChild{
		name:    etcdBinaryName,
		marker:  EtcdMarkerName,
		version: version,
		variant: etcdBuildVariant,
		build: func(ctx context.Context, scratch string) (string, error) {
			return buildEtcdWrapper(ctx, version, scratch, etcdServerPackage, etcdBinaryName)
		},
	}
}

// etcdutlChild is etcdutl's stagedChild declaration at the given pin: the same
// wrapper module, the same variant, its own binary and marker.
func etcdutlChild(version string) stagedChild {
	return stagedChild{
		name:    etcdutlBinaryName,
		marker:  EtcdutlMarkerName,
		version: version,
		variant: etcdBuildVariant,
		build: func(ctx context.Context, scratch string) (string, error) {
			return buildEtcdWrapper(ctx, version, scratch, etcdutlPackage, etcdutlBinaryName)
		},
	}
}

// ensureEtcdutlInto stages the pinned etcdutl into bd. Like ensureEtcdInto, a version
// other than DefaultEtcdVersion is refused before anything is touched.
func ensureEtcdutlInto(ctx context.Context, bd, version string) error {
	if version != DefaultEtcdVersion {
		return fmt.Errorf("stage etcdutl %s: %w (%s)", version, ErrEtcdVersionUnpinned, DefaultEtcdVersion)
	}
	return etcdutlChild(version).ensureInto(ctx, bd)
}

// buildEtcdWrapper materializes the embedded wrapper module under scratch and builds
// pkg from it into scratch/out.
//
// `go install go.etcd.io/etcd/server/v3@<pin>` is not an option: upstream's
// server/go.mod carries monorepo-relative replace directives, which `go install
// pkg@version` refuses. The wrapper requires the server module at the pin and its
// main is upstream's own server/main.go, so the binary is the same etcd server; it
// declares etcdutl as a tool, so etcdutl is built from the same module graph and
// cannot drift to another etcd version.
func buildEtcdWrapper(ctx context.Context, version, scratch, pkg, out string) (string, error) {
	src := filepath.Join(scratch, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		return "", fmt.Errorf("etcd wrapper dir: %w", err)
	}
	for name, data := range map[string][]byte{
		"go.mod":  etcdchild.GoMod,
		"go.sum":  etcdchild.GoSum,
		"main.go": etcdchild.MainGo,
	} {
		if err := os.WriteFile(filepath.Join(src, name), data, 0o644); err != nil {
			return "", fmt.Errorf("write etcd wrapper %s: %w", name, err)
		}
	}
	// The same stable module cache kine's build uses (see hostGoModCache): the scratch
	// dir dies with the build, the downloaded modules must not.
	modCache, err := kineModuleCacheDir(ctx)
	if err != nil {
		return "", err
	}
	bin := filepath.Join(scratch, out)
	cmd := exec.CommandContext(ctx, "go", etcdBuildArgs(bin, pkg)...)
	cmd.Dir = src
	cmd.Env = etcdBuildEnv(scratch, modCache)
	if combined, err := runEtcdBuild(cmd); err != nil {
		return "", fmt.Errorf("build %s %s (CGO_ENABLED=0): %w (a packaged install has no Go toolchain — re-run `sudo k3sm install` so the staged payload carries this pin): %s",
			out, version, err, combined)
	}
	return bin, nil
}

// etcdBuildArgs is the `go build` argv for one of the wrapper's programs. -trimpath
// and -buildvcs=false keep host paths and the (absent) VCS state out of the binary;
// -mod=readonly makes the committed go.sum the only acceptable source of module
// hashes.
func etcdBuildArgs(out, pkg string) []string {
	return []string{"build", "-trimpath", "-buildvcs=false", "-mod=readonly", "-o", out, pkg}
}

// etcdBuildEnv is kineBuildEnv's environment (CGO_ENABLED=0, GOWORK=off, GOBIN
// cleared, scratch GOPATH, pinned GOMODCACHE) plus GOFLAGS=-mod=readonly and
// GOTOOLCHAIN=local. Both are SET, appended last so they win over any ambient value:
// an inherited GOFLAGS=-mod=mod could otherwise rewrite the lockfile and accept
// whatever a module proxy serves, and GOTOOLCHAIN=local keeps the build from
// downloading a different compiler on the go.mod's say-so.
func etcdBuildEnv(gopath, modCache string) []string {
	return append(kineBuildEnv(gopath, modCache), "GOFLAGS=-mod=readonly", "GOTOOLCHAIN=local")
}

// runEtcdBuild runs the prepared build command and returns its combined output. A var
// so a test can assert the command without fetching or compiling anything.
var runEtcdBuild = func(cmd *exec.Cmd) ([]byte, error) { return cmd.CombinedOutput() }
