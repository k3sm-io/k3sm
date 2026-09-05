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

// Package version resolves the k3sm binary's build provenance: its own version
// (stamped by the release pipeline, or recovered from the embedded VCS build
// info in a dev build), the aligned control-plane dependency versions it was
// assembled with (Kubernetes, kine), and the release SHA of each k3sm.io module
// composed into the single binary (DESIGN §6).
//
// This package imports pkg/executor solely to read the DefaultKubeVersion /
// DefaultKineVersion pins as the single source of truth for the aligned
// versions. The edge is one-directional by contract: pkg/executor must never
// import pkg/version, so no cycle can form.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"

	"k3sm.io/k3sm/pkg/executor"
)

// Version, Commit, and Date are the build provenance stamped by the release
// pipeline (goreleaser) via:
//
//	-ldflags "-X k3sm.io/k3sm/pkg/version.Version=<tag>
//	          -X k3sm.io/k3sm/pkg/version.Commit=<sha>
//	          -X k3sm.io/k3sm/pkg/version.Date=<rfc3339>"
//
// An unstamped dev build leaves Version=="dev"; Get then recovers the values
// from runtime/debug.ReadBuildInfo (the embedded VCS metadata).
var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

// APISCommit, DarwinNetCommit, and RuntimedCommit are the sibling-module commit
// SHAs stamped by the release pipeline via the same -X mechanism, e.g.
//
//	-X k3sm.io/k3sm/pkg/version.APISCommit=<sha>
//
// They exist because build-info CANNOT supply them for a release build: k3sm's
// go.mod carries permanent filesystem `replace` directives onto the sibling
// checkouts (a lone k3sm clone cannot build), and a directory replacement has an
// empty module version, so modules() can only ever render "(devel)" for the three
// siblings. The release records four commit SHAs as provenance for a
// locally-built binary — the sibling tags are provenance markers, not consumable
// module versions — so the pipeline stamps them here and modules() prefers a
// stamped value over the "(devel)" it would otherwise report.
//
// Unstamped (every dev build) they are empty and nothing changes.
var (
	APISCommit      = ""
	DarwinNetCommit = ""
	RuntimedCommit  = ""
)

// stampedSiblingCommits maps a module path to its stamped commit SHA, empty when
// unstamped. Kept beside the vars so adding a module means touching one place.
func stampedSiblingCommits() map[string]string {
	return map[string]string{
		"k3sm.io/apis":       APISCommit,
		"k3sm.io/darwin-net": DarwinNetCommit,
		"k3sm.io/runtimed":   RuntimedCommit,
	}
}

// modulePaths are the four k3sm.io modules k3sm assembles into its single binary
// (DESIGN §6), in dependency order. Their release SHA/version is read from the
// build info: a locally-replaced module (the go.work dev build) renders its
// replacement version — honestly "(devel)" — rather than a fabricated SHA.
var modulePaths = []string{
	"k3sm.io/apis",
	"k3sm.io/darwin-net",
	"k3sm.io/runtimed",
	"k3sm.io/k3sm",
}

// ModuleRef is one assembled k3sm.io module and the SHA/version it was built from.
type ModuleRef struct {
	// Path is the module path, e.g. "k3sm.io/apis".
	Path string
	// SHA is the module's build-info version (a pseudo-version carrying the SHA
	// in a release build; "(devel)" or "unknown" in a workspace/dev build).
	SHA string
}

// Info is the resolved version provenance for the running k3sm binary.
type Info struct {
	// Version is the k3sm release version (stamped, or recovered from build info).
	Version string
	// Commit is the k3sm source revision (stamped, or vcs.revision).
	Commit string
	// Dirty reports that the VCS-recovered Commit was built from a modified
	// working tree (vcs.modified) — the SHA does not exactly identify the source.
	Dirty bool
	// Date is the build timestamp (stamped, or vcs.time).
	Date string
	// GoVersion is the toolchain that built the binary.
	GoVersion string
	// Platform is the GOOS/GOARCH the binary targets.
	Platform string
	// KubeVersion is the aligned Kubernetes control-plane version.
	KubeVersion string
	// KineVersion is the aligned kine (etcd shim) version — one pin, both postures.
	KineVersion string
	// Modules are the assembled k3sm.io modules and their release SHAs.
	Modules []ModuleRef
}

// Get resolves the running binary's version provenance. When the ldflags were
// not stamped (a dev build), it falls back to runtime/debug.ReadBuildInfo to
// recover the version, commit, and date from the embedded VCS metadata. The
// aligned Kubernetes/kine versions come from pkg/executor's pinned defaults.
func Get() Info {
	return get(Version, Commit, Date, executor.DefaultKubeVersion, executor.DefaultKineVersion, debug.ReadBuildInfo)
}

// get is the pure, testable core of Get: it derives an Info from its explicit
// inputs and an injected build-info reader, so both the stamped path and the
// ReadBuildInfo fallback are exercised deterministically — independent of the
// ambient go-test build environment (which may or may not embed VCS metadata).
func get(version, commit, date, kubeVersion, kineVersion string, readBuildInfo func() (*debug.BuildInfo, bool)) Info {
	info := Info{
		Version:     version,
		Commit:      commit,
		Date:        date,
		GoVersion:   runtime.Version(),
		Platform:    runtime.GOOS + "/" + runtime.GOARCH,
		KubeVersion: kubeVersion,
		KineVersion: kineVersion,
	}
	bi, ok := readBuildInfo()
	if !ok {
		return info
	}
	// Fallback: fill the fields the ldflags did not stamp from the embedded
	// build info. Stamped values always win (they are the release truth).
	if info.Version == "dev" || info.Version == "" {
		if v := bi.Main.Version; v != "" && v != "(devel)" {
			info.Version = v
		}
	}
	settings := make(map[string]string, len(bi.Settings))
	for _, s := range bi.Settings {
		settings[s.Key] = s.Value
	}
	if info.Commit == "" {
		info.Commit = settings["vcs.revision"]
		// The dirty marker is meaningful only for the VCS-recovered SHA: a
		// stamped Commit is release truth (built from a clean tagged tree), so
		// vcs.modified — which reflects THIS build's tree — must not taint it.
		info.Dirty = settings["vcs.modified"] == "true"
	}
	if info.Date == "" {
		info.Date = settings["vcs.time"]
	}
	info.Modules = modules(bi)
	return info
}

// modules resolves the assembled SHA/version of each k3sm.io module from the
// build-info deps (the main module from bi.Main). A locally-replaced module
// renders its replacement version rather than a fabricated SHA.
func modules(bi *debug.BuildInfo) []ModuleRef {
	byPath := map[string]*debug.Module{bi.Main.Path: &bi.Main}
	for _, dep := range bi.Deps {
		byPath[dep.Path] = dep
	}
	stamped := stampedSiblingCommits()
	refs := make([]ModuleRef, 0, len(modulePaths))
	for _, path := range modulePaths {
		ref := ModuleRef{Path: path, SHA: "unknown"}
		// A stamped sibling SHA is release truth and wins outright: build-info
		// can only report "(devel)" for a directory-replaced module, so without
		// this the four-SHA provenance record would be unreportable.
		if sha := stamped[path]; sha != "" {
			refs = append(refs, ModuleRef{Path: path, SHA: sha})
			continue
		}
		if mod, found := byPath[path]; found {
			m := mod
			if m.Replace != nil {
				m = m.Replace
			}
			if m.Version != "" {
				ref.SHA = m.Version
			} else {
				ref.SHA = "(devel)"
			}
		}
		refs = append(refs, ref)
	}
	return refs
}

// NodeVersion is the value the node reports as its kubelet version: the
// aligned Kubernetes version with the k3sm release as semver build metadata,
// the same shape k3s uses (v1.33.1+k3s1). Tools that read
// NodeInfo.KubeletVersion parse it as semver, so the k3sm part is sanitized
// into a valid build-metadata suffix: the leading "v" is dropped and any "+"
// (a dev build's "+dirty") becomes ".".
func (i Info) NodeVersion() string {
	kube := i.KubeVersion
	if !strings.HasPrefix(kube, "v") {
		kube = "v" + kube
	}
	suffix := i.Version
	if i.Dirty {
		suffix += "+dirty"
	}
	return kube + "+k3sm." + sanitizeBuildMetadata(suffix)
}

// sanitizeBuildMetadata makes s safe to append as semver build metadata after
// a "+": it drops a leading "v" (a Go pseudo-version's own prefix; the kube
// version already carries one), turns "+" into "." (semver build metadata
// cannot contain a second "+"), and replaces any remaining character outside
// [0-9A-Za-z.-] with "-".
func sanitizeBuildMetadata(s string) string {
	s = strings.TrimPrefix(s, "v")
	s = strings.ReplaceAll(s, "+", ".")
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '.', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return b.String()
}

// String renders the multi-line human-readable output for `k3sm version`.
func (i Info) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "k3sm %s\n", i.Version)
	if i.Commit != "" {
		dirty := ""
		if i.Dirty {
			dirty = " (dirty)"
		}
		fmt.Fprintf(&b, "  commit:        %s%s\n", i.Commit, dirty)
	}
	if i.Date != "" {
		fmt.Fprintf(&b, "  built:         %s\n", i.Date)
	}
	fmt.Fprintf(&b, "  go:            %s\n", i.GoVersion)
	fmt.Fprintf(&b, "  platform:      %s\n", i.Platform)
	fmt.Fprintf(&b, "  kubernetes:    %s\n", i.KubeVersion)
	// One kine pin serves both datastore postures (executor.DefaultKineVersion), so
	// the label is unqualified: it is the shim version on every node, HA or not.
	fmt.Fprintf(&b, "  kine:          %s\n", i.KineVersion)
	if len(i.Modules) > 0 {
		b.WriteString("  modules:\n")
		for _, m := range i.Modules {
			fmt.Fprintf(&b, "    %-20s %s\n", m.Path, m.SHA)
		}
	}
	return b.String()
}
