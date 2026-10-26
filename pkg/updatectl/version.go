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

package updatectl

import (
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// nodeVersionMarker separates the Kubernetes version from the k3sm release in
// a node's kubeletVersion (pkg/version's NodeVersion: v1.37.1+k3sm.0.2.0).
const nodeVersionMarker = "+k3sm."

// buildMetadata is the k3sm part pkg/version's NodeVersion writes for tag: the
// leading "v" dropped, "+" turned into ".", and every other character outside
// [0-9A-Za-z.-] turned into "-". It mirrors that unexported sanitizer, so the
// two must change together.
func buildMetadata(tag string) string {
	s := strings.ReplaceAll(strings.TrimPrefix(tag, "v"), "+", ".")
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

// nodeRelease is the k3sm part of the node's kubeletVersion, or "" when the
// node does not report one.
func nodeRelease(n *corev1.Node) string {
	kv := n.Status.NodeInfo.KubeletVersion
	i := strings.Index(kv, nodeVersionMarker)
	if i < 0 {
		return ""
	}
	return kv[i+len(nodeVersionMarker):]
}

// onTarget reports whether the node's kubeletVersion carries tag.
func onTarget(n *corev1.Node, tag string) bool {
	rel := nodeRelease(n)
	return rel != "" && rel == buildMetadata(tag)
}

// fromRelease is the release a node runs, as the From column shows it: the
// tag form ("v" + the k3sm part) when the kubeletVersion carries one, the raw
// kubeletVersion otherwise.
func fromRelease(n *corev1.Node) string {
	if rel := nodeRelease(n); rel != "" {
		return "v" + rel
	}
	return n.Status.NodeInfo.KubeletVersion
}

// semver is a parsed MAJOR.MINOR.PATCH[-PRERELEASE] version.
type semver struct {
	num [3]int
	pre []string
}

// parseSemver parses a release such as v0.2.0 or 0.2.0-rc.1 (build metadata
// after a "+" is ignored). ok is false for anything else, a dev build's
// pseudo-version included.
func parseSemver(s string) (v semver, ok bool) {
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	core, pre, hasPre := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return semver{}, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return semver{}, false
		}
		v.num[i] = n
	}
	if hasPre {
		if pre == "" {
			return semver{}, false
		}
		v.pre = strings.Split(pre, ".")
	}
	return v, true
}

// compareSemver orders a and b by semver precedence: -1, 0 or 1.
func compareSemver(a, b semver) int {
	for i := range a.num {
		if a.num[i] != b.num[i] {
			if a.num[i] < b.num[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1 // a release outranks its prereleases
	case len(b.pre) == 0:
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		if c := comparePreID(a.pre[i], b.pre[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(a.pre) < len(b.pre):
		return -1
	case len(a.pre) > len(b.pre):
		return 1
	}
	return 0
}

// comparePreID orders two prerelease identifiers: numeric ones numerically and
// below alphanumeric ones, alphanumeric ones lexically.
func comparePreID(a, b string) int {
	an, aErr := strconv.Atoi(a)
	bn, bErr := strconv.Atoi(b)
	switch {
	case aErr == nil && bErr == nil:
		switch {
		case an < bn:
			return -1
		case an > bn:
			return 1
		}
		return 0
	case aErr == nil:
		return -1
	case bErr == nil:
		return 1
	}
	return strings.Compare(a, b)
}

// isDowngrade reports whether moving a node that runs from to target is a
// downgrade. A release that does not parse (a dev build) is never called one:
// the controller cannot order it, and refusing it would wedge every dev
// cluster.
func isDowngrade(from, target string) bool {
	f, ok := parseSemver(from)
	if !ok {
		return false
	}
	t, ok := parseSemver(target)
	if !ok {
		return false
	}
	return compareSemver(t, f) < 0
}
