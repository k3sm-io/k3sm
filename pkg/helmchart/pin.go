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

package helmchart

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"k3sm.io/k3sm/pkg/helmchart/helmchild"
)

// The helm pin. The Job's command[0] is this exact helm, shipped in the k3sm
// payload beside kubectl and seeded into the work dir's bin at boot.
//
// PROVENANCE. helm is BUILT from its module source at the pin, the way k3sm
// builds kine, etcd and zot, rather than taken from the upstream release
// tarball: the tarball is compiled with whatever Go release helm's maintainers
// used and links the dependency versions helm's go.mod names, so a standard
// library or golang.org/x fix reaches it only when helm cuts a release. The
// build runs inside the wrapper module in package helmchild (helm at the pin,
// golang.org/x/net raised, its go.sum the lockfile)
// under the payload toolchain, and stamps the version exactly as helm's
// Makefile does for a tagged release build: CGO_ENABLED=0, -trimpath, and
// -ldflags "-w -s -X .../internal/version.version=<tag> -X ...metadata=
// -X ...gitCommit=<the tag's commit> -X ...gitTreeState=clean".
//
// Helm 4 rather than 3: the HelmChart contract carries forceConflicts, and
// --force-conflicts exists only in Helm 4's server-side apply.
const (
	// HelmVersion is the pinned helm release.
	HelmVersion = "v4.3.1"
	// HelmGitCommit is the commit HelmVersion's tag names, which helm's release
	// build stamps into `helm version`. The module proxy records it for the tag
	// (https://proxy.golang.org/helm.sh/helm/v4/@v/v4.3.1.info, Origin.Hash).
	HelmGitCommit = "c0d08d0d6d9424d4a14febb5e8a3e51b0dd00dff"
	// HelmModule is the module helm is built from, at HelmVersion.
	HelmModule = "helm.sh/helm/v4"
	// HelmMainPackage is helm's main package, a `tool` of the wrapper module, and
	// the main package the built binary's build info records.
	HelmMainPackage = HelmModule + "/cmd/helm"
	// HelmRaisedModules names the modules the wrapper raises above the versions
	// helm's own go.mod requires, as space-separated path@version, each the first
	// release fixing a govulncheck finding reachable in the pinned helm. Helm
	// v4.3.1 requires golang.org/x/net v0.60.0, so x/net is raised to v0.62.0,
	// which fixes GO-2026-6860 and GO-2026-6866. It already requires
	// golang.org/x/crypto v0.58.0, the version x/net v0.62.0 needs, so x/crypto is
	// no longer raised. A raise is at least 14 days old when adopted unless a
	// security fix cannot wait: x/net v0.62.0 was adopted the day it was
	// published, by the same exemption hack/release/build-cp.sh records for the
	// control plane. The wrapper build itself checks no publish date. The
	// wrapper's go.mod requires exactly these versions (ValidateHelmPin), and a
	// staged helm's build info must carry them.
	HelmRaisedModules = "golang.org/x/net@v0.62.0"
	// HelmMinGoVersion is the oldest Go release a staged helm may be built with:
	// the first that fixes the standard library findings reachable in helm. The
	// payload toolchain (hack/release/lib/gochild.sh PAYLOAD_GO_VERSION) builds
	// it, and the release path refuses a helm whose build info names an older one.
	HelmMinGoVersion = "go1.27.3"
	// HelmBinaryName is the staged binary's basename (in an install payload and
	// in the work dir's bin). The version is in the name so a bump stages beside
	// the old copy instead of silently reusing it.
	HelmBinaryName = "helm-" + HelmVersion
	// HelmMarkerName is the basename of the version marker written beside a
	// built helm: "<HelmVersion> <HelmBuildVariant>". The versioned name tells
	// one helm release from another; the marker tells this build from any other
	// build of the same release (the upstream tarball above all).
	HelmMarkerName = "helm.version"
	// HelmBuildVariant records HOW the binary was built: CGO_ENABLED=0 from the
	// wrapper module, whose dependency set is the "+deps<n>" suffix. Bump the
	// suffix with every change to helmchild's go.sum, so a work dir or payload
	// built from the previous set re-stages instead of trusting its marker.
	HelmBuildVariant = "nocgo+deps3"

	// helmVersionPackage is the package helm's release build stamps.
	helmVersionPackage = HelmModule + "/internal/version"
)

// helmVersionShape matches a helm release tag (vMAJOR.MINOR.PATCH).
var helmVersionShape = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

// gitCommitShape matches a full lowercase git sha1.
var gitCommitShape = regexp.MustCompile(`^[0-9a-f]{40}$`)

// HelmPath names the staged helm binary in binDir (the work dir's bin, or a
// payload dir). The controller's Job command[0] is this path under
// executor.BinDir.
func HelmPath(binDir string) string { return filepath.Join(binDir, HelmBinaryName) }

// HelmLDFlags is the -ldflags value helm's Makefile passes for a tagged release
// build of HelmVersion.
func HelmLDFlags() string {
	return "-w -s" +
		" -X " + helmVersionPackage + ".version=" + HelmVersion +
		" -X " + helmVersionPackage + ".metadata=" +
		" -X " + helmVersionPackage + ".gitCommit=" + HelmGitCommit +
		" -X " + helmVersionPackage + ".gitTreeState=clean"
}

// HelmBuildArgs is the `go build` argv that builds helm into out, run inside the
// wrapper module WriteHelmWrapper writes. -trimpath and -buildvcs=false keep host
// paths and the (absent) VCS state out of the binary; -mod=readonly makes the
// embedded go.sum the only acceptable source of module hashes.
func HelmBuildArgs(out string) []string {
	return []string{"build", "-trimpath", "-buildvcs=false", "-mod=readonly", "-ldflags", HelmLDFlags(), "-o", out, HelmMainPackage}
}

// WriteHelmWrapper writes the wrapper module's go.mod and go.sum into dir, which
// it creates.
func WriteHelmWrapper(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("helm wrapper dir: %w", err)
	}
	for name, data := range map[string][]byte{"go.mod": helmchild.GoMod, "go.sum": helmchild.GoSum} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			return fmt.Errorf("write helm wrapper %s: %w", name, err)
		}
	}
	return nil
}

// ValidateHelmPin fails if the compiled-in pin is malformed or the wrapper module
// does not build it: a bad bump then fails `go test` instead of a build nobody
// can vouch for.
func ValidateHelmPin() error {
	return validateHelmPin(HelmVersion, HelmGitCommit, HelmBinaryName, HelmRaisedModules, helmchild.GoMod)
}

// validateHelmPin is ValidateHelmPin over explicit values, so a test can feed it
// malformed pins.
func validateHelmPin(version, commit, binary, raised string, goMod []byte) error {
	if !helmVersionShape.MatchString(version) {
		return fmt.Errorf("helm pin: version %q is not vMAJOR.MINOR.PATCH", version)
	}
	if !gitCommitShape.MatchString(commit) {
		return fmt.Errorf("helm pin: commit %q is not a 40-char lowercase git sha1", commit)
	}
	if want := "helm-" + version; binary != want {
		return fmt.Errorf("helm pin: binary name %q does not carry version %q (want %q)", binary, version, want)
	}
	reqs, tools := goModRequires(goMod)
	if got := reqs[HelmModule]; got != version {
		return fmt.Errorf("helm pin: the wrapper requires %s %q, want %s", HelmModule, got, version)
	}
	if !tools[HelmMainPackage] {
		return fmt.Errorf("helm pin: the wrapper does not declare %s as a tool", HelmMainPackage)
	}
	mods := strings.Fields(raised)
	if len(mods) == 0 {
		return fmt.Errorf("helm pin: no raised modules named")
	}
	for _, pv := range mods {
		path, ver, ok := strings.Cut(pv, "@")
		if !ok || path == "" || ver == "" {
			return fmt.Errorf("helm pin: raised module %q is not path@version", pv)
		}
		if got := reqs[path]; got != ver {
			return fmt.Errorf("helm pin: the wrapper requires %s %q, want the raised %s", path, got, ver)
		}
	}
	return nil
}

// goModRequires returns the required module versions and the tool packages a
// go.mod names. It reads only the shapes `go mod tidy` writes (single-line and
// block require and tool directives) and ignores everything else.
func goModRequires(goMod []byte) (map[string]string, map[string]bool) {
	reqs, tools := map[string]string{}, map[string]bool{}
	add := func(directive string, f []string) {
		switch {
		case directive == "require" && len(f) >= 2:
			reqs[f[0]] = f[1]
		case directive == "tool" && len(f) >= 1:
			tools[f[0]] = true
		}
	}
	block := ""
	sc := bufio.NewScanner(bytes.NewReader(goMod))
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "//")
		f := strings.Fields(line)
		switch {
		case len(f) == 0:
		case block != "":
			if f[0] == ")" {
				block = ""
			} else {
				add(block, f)
			}
		case f[0] == "require" || f[0] == "tool":
			if len(f) == 2 && f[1] == "(" {
				block = f[0]
			} else {
				add(f[0], f[1:])
			}
		}
	}
	return reqs, tools
}
