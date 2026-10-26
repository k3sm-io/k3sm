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

package version

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// ValidTag reports whether tag is a usable release tag: non-empty, at most 128
// bytes, not starting with "-", and only the characters a git version tag
// carries (install.sh's valid_tag). A tag read off the network passes this
// before it is used anywhere.
func ValidTag(tag string) bool {
	if tag == "" || len(tag) > 128 || strings.HasPrefix(tag, "-") {
		return false
	}
	for _, c := range tag {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '+', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// nodeK3smMarker separates the Kubernetes version from the k3sm release in a
// node's kubelet version (Info.NodeVersion).
const nodeK3smMarker = "+k3sm."

// NodeRelease is the k3sm release a kubelet version names: the part after
// "+k3sm." (NodeVersion's encoding), or false when it names none.
func NodeRelease(kubelet string) (string, bool) {
	_, rel, ok := strings.Cut(kubelet, nodeK3smMarker)
	return rel, ok && rel != ""
}

// semverCore is MAJOR.MINOR.PATCH, an optional prerelease, and optional build
// metadata (ignored for ordering), with an optional leading "v".
var semverCore = regexp.MustCompile(`^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z.-]+))?$`)

// pseudoPrerelease is the timestamp-revision pair of a Go pseudo-version
// prerelease (20261015120000-0123456789ab): a build of an untagged commit. It
// matches as a whole dotted identifier pair anywhere in the prerelease, so a
// dirty pseudo-version build (whose NodeVersion appends ".dirty") is untagged
// too.
var pseudoPrerelease = regexp.MustCompile(`(^|\.)\d{14}-[0-9a-f]{12}(\.|$)`)

// semver is a parsed release version.
type semver struct {
	core [3]uint64
	pre  []string
	// meta is the build metadata identifiers, ignored for ordering.
	meta []string
	// untagged marks a Go pseudo-version: a build of an untagged commit.
	untagged bool
}

// parseVersion parses a semver version, tagged or a Go pseudo-version, or
// false for anything that is neither: a "dev" build, a dirty tagged build
// (whose "+dirty" NodeVersion turns into a fourth dotted field), or garbage.
func parseVersion(s string) (semver, bool) {
	m := semverCore.FindStringSubmatch(s)
	if m == nil {
		return semver{}, false
	}
	var v semver
	for i := range 3 {
		n, err := strconv.ParseUint(m[i+1], 10, 64)
		if err != nil {
			return semver{}, false
		}
		v.core[i] = n
	}
	if m[4] != "" {
		v.pre = strings.Split(m[4], ".")
		v.untagged = pseudoPrerelease.MatchString(m[4])
	}
	if m[5] != "" {
		v.meta = strings.Split(m[5], ".")
	}
	return v, true
}

// parseRelease parses a tagged release version, or false for anything else:
// what parseVersion refuses, and a Go pseudo-version.
func parseRelease(s string) (semver, bool) {
	v, ok := parseVersion(s)
	if !ok || v.untagged {
		return semver{}, false
	}
	return v, true
}

// CompareReleases orders two release versions by semver precedence (build
// metadata ignored): -1, 0 or 1 as a sorts before, with or after b. ok is false
// when either is not a tagged release (see parseRelease), which a caller
// reports as unknown rather than as older. It is the strict comparison: a
// caller that acts on the order (a roll target, a signed index's bounds) uses
// it, never CompareBuild.
func CompareReleases(a, b string) (cmp int, ok bool) {
	va, okA := parseRelease(a)
	vb, okB := parseRelease(b)
	if !okA || !okB {
		return 0, false
	}
	return compareSemver(va, vb), true
}

// CompareBuild orders the version a binary or node was built as against a
// tagged release, for display: -1, 0 or 1 as build sorts before, with or after
// release. A Go pseudo-version ranks by its core and prerelease in semver
// order, so v0.1.8-0.<stamp>-<rev> sorts after v0.1.7 and before v0.1.8, and
// untaggedOf names its core ("0.1.8") so a caller can say it is an untagged
// build; untaggedOf is empty for a tagged build. ok is false when release is
// not a tagged release, or build is not comparable: a dev build, a build from
// a modified tree (a "dirty" identifier in a pseudo-version's prerelease or in
// any build metadata), or garbage.
func CompareBuild(build, release string) (cmp int, untaggedOf string, ok bool) {
	vb, okB := parseVersion(build)
	vr, okR := parseRelease(release)
	if !okB || !okR || slices.Contains(vb.meta, "dirty") || (vb.untagged && slices.Contains(vb.pre, "dirty")) {
		return 0, "", false
	}
	if vb.untagged {
		untaggedOf = fmt.Sprintf("%d.%d.%d", vb.core[0], vb.core[1], vb.core[2])
	}
	return compareSemver(vb, vr), untaggedOf, true
}

// compareSemver orders two parsed versions by semver precedence.
func compareSemver(a, b semver) int {
	for i := range 3 {
		if a.core[i] != b.core[i] {
			if a.core[i] < b.core[i] {
				return -1
			}
			return 1
		}
	}
	return comparePre(a.pre, b.pre)
}

// comparePre orders two prerelease lists: none sorts after any, numeric
// identifiers compare numerically and before alphanumeric ones, and a shorter
// list that is a prefix of a longer one sorts first (semver §11).
func comparePre(a, b []string) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return 1
	case len(b) == 0:
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := compareIdent(a[i], b[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}

// compareIdent orders two prerelease identifiers.
func compareIdent(a, b string) int {
	na, errA := strconv.ParseUint(a, 10, 64)
	nb, errB := strconv.ParseUint(b, 10, 64)
	switch {
	case errA == nil && errB == nil:
		switch {
		case na < nb:
			return -1
		case na > nb:
			return 1
		}
		return 0
	case errA == nil:
		return -1
	case errB == nil:
		return 1
	}
	return strings.Compare(a, b)
}
