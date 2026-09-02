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

package main

import (
	"fmt"
	"strings"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// parsePlatform parses an "os/arch[/variant]" selector into the wire's Platform.
//
// The empty spec yields nil, and that is the contract rather than a convenience:
// on the wire an UNSET platform means "the daemon's own host platform" for a
// pull and "the reference's single entry" for the verbs that name one, neither
// of which a zero-valued Platform would say. Sending &Platform{} would ask the
// daemon for an image whose OS is the empty string.
func parsePlatform(spec string) (*runtimev1.Platform, error) {
	if spec == "" {
		return nil, nil
	}
	parts := strings.Split(spec, "/")
	if len(parts) < 2 || len(parts) > 3 {
		return nil, fmt.Errorf("--platform %q: want os/arch or os/arch/variant, for example darwin/arm64 or linux/amd64", spec)
	}
	for _, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("--platform %q: every component must be non-empty (os/arch[/variant])", spec)
		}
	}
	p := &runtimev1.Platform{Os: parts[0], Architecture: parts[1]}
	if len(parts) == 3 {
		p.Variant = parts[2]
	}
	return p, nil
}

// platformText renders a Platform the way an operator spells one. It returns
// the empty string for an absent platform, which every caller reports as an
// absent FACT rather than as a platform-less image — the wire makes each field
// independently optional for exactly that reason.
func platformText(p *runtimev1.Platform) string {
	if p == nil {
		return ""
	}
	parts := make([]string, 0, 3)
	for _, part := range []string{p.GetOs(), p.GetArchitecture(), p.GetVariant()} {
		if part == "" {
			continue
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, "/")
}

// parsePullPolicy maps the operator's spelling onto the corev1 pull-policy enum
// the wire reuses.
//
// Both the CLI spelling (if-not-present) and the corev1 spelling (IfNotPresent)
// are accepted, because an operator reading a Pod spec and an operator reading
// this command's help have both spellings in front of them and neither is wrong.
// The empty policy stays UNSPECIFIED, which is the legacy pull-through behaviour
// in both skew directions — not a fourth policy this side invents.
func parsePullPolicy(spec string) (runtimev1.ImagePullPolicy, error) {
	switch normalizePolicy(spec) {
	case "":
		return runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_UNSPECIFIED, nil
	case "always":
		return runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS, nil
	case "ifnotpresent":
		return runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_IF_NOT_PRESENT, nil
	case "never":
		return runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER, nil
	}
	return runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_UNSPECIFIED,
		fmt.Errorf("--policy %q: want always, if-not-present or never", spec)
}

// normalizePolicy folds case and the separators the two spellings differ by.
func normalizePolicy(spec string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(spec) {
		if r == '-' || r == '_' || r == ' ' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// looksLikeDigest reports whether s is a content digest ("<algo>:<hex>") rather
// than a pull reference.
//
// The verbs that accept either have to tell them apart without asking the
// daemon, and the shapes are genuinely disjoint: a digest carries no path
// separator and no tag, its algorithm is lowercase-alphanumeric with the OCI
// separators, and its encoded part is at least 32 hex characters. A reference
// fails at least one of those — "alpine:3.20" on the hex test, "localhost:5000/x"
// on the separator, "repo@sha256:…" on the algorithm.
//
// It is deliberately conservative in one direction only: a mis-read digest is
// sent as a reference and the daemon answers NOT_FOUND naming it, which is a
// legible failure, while the reverse would silently address different content.
func looksLikeDigest(s string) bool {
	if strings.ContainsAny(s, "/@") {
		return false
	}
	algo, encoded, ok := strings.Cut(s, ":")
	if !ok || algo == "" || len(encoded) < 32 {
		return false
	}
	for _, r := range algo {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '+', r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	for _, r := range encoded {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// imageTarget fills the (reference | digest) pair the read-only verbs take. The
// wire's rule is exactly one of the two — setting both is INVALID_ARGUMENT
// rather than a precedence rule — so this returns the pair and never both.
func imageTarget(source string) (reference, digest string) {
	if looksLikeDigest(source) {
		return "", source
	}
	return source, ""
}
