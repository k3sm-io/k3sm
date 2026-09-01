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

package images

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"
)

// MirrorPrefix is the only registry namespace a mirror reference may name. Consuming an
// upstream image from anywhere else defeats the point of mirroring it.
const MirrorPrefix = "ghcr.io/k3sm-io/mirror/"

// ErrManifest is the sentinel every manifest schema failure wraps, so a caller can
// distinguish "the record is malformed" from "the record disagrees with the code"
// (ErrLockstep) or "the registry disagrees with the record" (ErrLive).
var ErrManifest = errors.New("mirror manifest")

// digestRE matches a canonical sha256 digest. Anything else — an uppercase hex digit, a
// truncated digest, another algorithm — is rejected rather than normalised: a pin is a
// byte-exact identity and a lenient parser is how two spellings of "the same" image come
// to exist.
var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Manifest is the parsed hack/images/mirror.yaml.
type Manifest struct {
	Images []Entry `json:"images"`
}

// Entry records one mirrored image: where it came from, where k3sm reads it, the
// durable tag that keeps the digest from being garbage-collected, and the per-platform
// manifest digests inside the index.
type Entry struct {
	Name      string     `json:"name"`
	Upstream  string     `json:"upstream"`
	Mirror    string     `json:"mirror"`
	Tag       string     `json:"tag"`
	Platforms []Platform `json:"platforms"`
}

// Platform is one per-arch manifest inside a mirrored index.
type Platform struct {
	// Platform is os/arch, optionally os/arch/variant.
	Platform string `json:"platform"`
	// Digest is that platform manifest's digest (NOT the index digest).
	Digest string `json:"digest"`
}

// requiredPlatforms names the arches an entry must carry. buildkit is consumed on both
// the native arm64 path and the translated amd64 path, so an index missing either is a
// pin that will fail at run time on half the fleet — assert it at rest instead.
var requiredPlatforms = map[string][]string{
	"buildkit": {"linux/arm64", "linux/amd64"},
}

// LoadManifest reads and schema-validates the mirror manifest at path.
//
// The path is a seam on purpose: the shipped manifest is one input, a mutated temp copy
// is another, and the verifier must be the same code in both cases.
func LoadManifest(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %w", ErrManifest, path, err)
	}
	var m Manifest
	// Strict: an unknown or misspelled key is a schema error, never a silently
	// ignored field that leaves a required value at its zero value.
	if err := yaml.UnmarshalStrict(raw, &m); err != nil {
		return nil, fmt.Errorf("%w: parse %s: %w", ErrManifest, path, err)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrManifest, path, err)
	}
	return &m, nil
}

// Validate enforces the entry schema documented in the manifest header.
func (m *Manifest) Validate() error {
	if len(m.Images) == 0 {
		return errors.New("no images: an empty manifest would make every lockstep check vacuous")
	}
	seen := make(map[string]bool, len(m.Images))
	for i, e := range m.Images {
		where := fmt.Sprintf("images[%d]", i)
		if e.Name == "" {
			return fmt.Errorf("%s: name is required", where)
		}
		where = fmt.Sprintf("images[%d] (%s)", i, e.Name)
		if seen[e.Name] {
			return fmt.Errorf("%s: duplicate name", where)
		}
		seen[e.Name] = true
		if e.Tag == "" {
			return fmt.Errorf("%s: tag is required — an untagged digest can be "+
				"garbage-collected by a registry retention policy", where)
		}
		upDigest, err := refDigest(e.Upstream)
		if err != nil {
			return fmt.Errorf("%s: upstream: %w", where, err)
		}
		if !strings.Contains(strings.SplitN(e.Upstream, "@", 2)[0], ":") {
			return fmt.Errorf("%s: upstream %q must carry its release tag as well as "+
				"its digest, so the pin stays human-readable", where, e.Upstream)
		}
		mirrorDigest, err := refDigest(e.Mirror)
		if err != nil {
			return fmt.Errorf("%s: mirror: %w", where, err)
		}
		if !strings.HasPrefix(e.Mirror, MirrorPrefix) {
			return fmt.Errorf("%s: mirror %q must start with %q", where, e.Mirror, MirrorPrefix)
		}
		if upDigest != mirrorDigest {
			return fmt.Errorf("%s: upstream digest %s != mirror digest %s — an index copy "+
				"preserves digests, so a divergent pair means the mirror is not this "+
				"upstream image", where, upDigest, mirrorDigest)
		}
		if len(e.Platforms) == 0 {
			return fmt.Errorf("%s: at least one platform is required", where)
		}
		plats := make(map[string]bool, len(e.Platforms))
		for j, p := range e.Platforms {
			pw := fmt.Sprintf("%s platforms[%d]", where, j)
			if err := validPlatform(p.Platform); err != nil {
				return fmt.Errorf("%s: %w", pw, err)
			}
			if plats[p.Platform] {
				return fmt.Errorf("%s: duplicate platform %s", pw, p.Platform)
			}
			plats[p.Platform] = true
			if !digestRE.MatchString(p.Digest) {
				return fmt.Errorf("%s: digest %q is not a canonical sha256 digest", pw, p.Digest)
			}
			if p.Digest == mirrorDigest {
				return fmt.Errorf("%s: platform digest equals the index digest %s — a "+
					"platform entry must name the per-arch manifest, not the index", pw, mirrorDigest)
			}
		}
		for _, want := range requiredPlatforms[e.Name] {
			if !plats[want] {
				return fmt.Errorf("%s: required platform %s is missing", where, want)
			}
		}
	}
	return nil
}

// Entry returns the entry named name.
func (m *Manifest) Entry(name string) (Entry, bool) {
	for _, e := range m.Images {
		if e.Name == name {
			return e, true
		}
	}
	return Entry{}, false
}

// Names returns every entry name, sorted, for deterministic error text.
func (m *Manifest) Names() []string {
	out := make([]string, 0, len(m.Images))
	for _, e := range m.Images {
		out = append(out, e.Name)
	}
	sort.Strings(out)
	return out
}

// refDigest extracts and validates the digest of a fully digest-pinned reference.
func refDigest(ref string) (string, error) {
	if ref == "" {
		return "", errors.New("reference is required")
	}
	at := strings.LastIndex(ref, "@")
	if at < 0 {
		return "", fmt.Errorf("%q is not digest-pinned (no @sha256:...)", ref)
	}
	d := ref[at+1:]
	if !digestRE.MatchString(d) {
		return "", fmt.Errorf("%q does not end in a canonical sha256 digest", ref)
	}
	if at == 0 {
		return "", fmt.Errorf("%q has an empty repository", ref)
	}
	return d, nil
}

// validPlatform accepts os/arch or os/arch/variant with no empty components.
func validPlatform(p string) error {
	parts := strings.Split(p, "/")
	if len(parts) < 2 || len(parts) > 3 {
		return fmt.Errorf("platform %q must be os/arch or os/arch/variant", p)
	}
	for _, c := range parts {
		if c == "" {
			return fmt.Errorf("platform %q has an empty component", p)
		}
	}
	return nil
}
