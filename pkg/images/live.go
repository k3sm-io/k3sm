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
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// ErrLive is the sentinel every registry-vs-manifest mismatch wraps.
var ErrLive = errors.New("image pin live verification")

// LiveOptions parameterises VerifyLive. Both fields exist so the verification logic can
// be proven against an in-process loopback registry; neither is used by a release run.
type LiveOptions struct {
	// Registry, when non-empty, replaces the registry host of every mirror reference.
	// It is the test seam: a fixture registry listens on 127.0.0.1:<port>, and the
	// shipped code path — not a reimplementation of it — is what gets exercised.
	Registry string
	// Insecure permits plain HTTP. Only ever set alongside a loopback Registry.
	Insecure bool
}

// VerifyLive proves that every manifest entry actually exists in the registry at the
// digest the manifest records, with the platforms it claims.
//
// The fetch is ANONYMOUS and that is load-bearing, not incidental. The property a
// release needs is "any user can pull this", and an authenticated fetch answers a
// different question — it would succeed against a private package and report green on a
// mirror nobody else can read. Never add a credential to this path.
//
// Digest verification is belt and braces: the registry client already refuses content
// whose bytes do not hash to the requested digest, and this function additionally
// asserts the returned descriptor's digest, so a client-side regression cannot quietly
// turn the check into a liveness ping.
func VerifyLive(ctx context.Context, m *Manifest, opts LiveOptions) error {
	if m == nil {
		return fmt.Errorf("%w: nil manifest", ErrLive)
	}
	if len(m.Images) == 0 {
		return fmt.Errorf("%w: no entries to verify", ErrLive)
	}
	for _, e := range m.Images {
		if err := verifyEntry(ctx, e, opts); err != nil {
			return fmt.Errorf("%w: %s: %w", ErrLive, e.Name, err)
		}
	}
	return nil
}

// VerifyLiveFile loads (and schema-validates) the manifest at path, then verifies it
// against the registry.
func VerifyLiveFile(ctx context.Context, path string, opts LiveOptions) error {
	m, err := LoadManifest(path)
	if err != nil {
		return err
	}
	return VerifyLive(ctx, m, opts)
}

func verifyEntry(ctx context.Context, e Entry, opts LiveOptions) error {
	ref, err := mirrorRef(e.Mirror, opts)
	if err != nil {
		return err
	}
	desc, err := remote.Get(ref,
		remote.WithContext(ctx),
		// Anonymous by construction — see the VerifyLive doc comment.
		remote.WithAuth(authn.Anonymous),
	)
	if err != nil {
		return fmt.Errorf("anonymous fetch of %s failed (absent, or not publicly "+
			"readable — both are release blockers): %w", ref, err)
	}
	want, err := refDigest(e.Mirror)
	if err != nil {
		return err
	}
	if got := desc.Digest.String(); got != want {
		return fmt.Errorf("registry served digest %s for %s, want %s", got, ref, want)
	}
	idx, err := desc.ImageIndex()
	if err != nil {
		return fmt.Errorf("%s is not a multi-platform index (a pin must name an index so "+
			"the puller can select a platform): %w", ref, err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return fmt.Errorf("read index manifest of %s: %w", ref, err)
	}
	have := make(map[string]string, len(im.Manifests))
	for _, d := range im.Manifests {
		if d.Platform == nil {
			continue
		}
		have[platformString(d.Platform)] = d.Digest.String()
	}
	var missing []string
	for _, p := range e.Platforms {
		got, ok := have[p.Platform]
		if !ok {
			missing = append(missing, fmt.Sprintf("%s absent from the index (index has: %s)",
				p.Platform, strings.Join(sortedKeys(have), ", ")))
			continue
		}
		if got != p.Digest {
			missing = append(missing, fmt.Sprintf("%s is present at %s, manifest records %s",
				p.Platform, got, p.Digest))
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("index %s: %s", ref, strings.Join(missing, "; "))
	}
	return nil
}

// mirrorRef parses a mirror reference, applying the registry-host override when one is
// set. The override rewrites only the host: the repository path and the digest are the
// manifest's, so a fixture cannot accidentally verify a different image.
func mirrorRef(ref string, opts LiveOptions) (name.Digest, error) {
	parsed, err := name.NewDigest(ref)
	if err != nil {
		return name.Digest{}, fmt.Errorf("parse %q: %w", ref, err)
	}
	if opts.Registry == "" && !opts.Insecure {
		return parsed, nil
	}
	rewritten := ref
	if opts.Registry != "" {
		rewritten = opts.Registry + "/" + parsed.Context().RepositoryStr() + "@" + parsed.DigestStr()
	}
	var nopts []name.Option
	if opts.Insecure {
		nopts = append(nopts, name.Insecure)
	}
	d, err := name.NewDigest(rewritten, nopts...)
	if err != nil {
		return name.Digest{}, fmt.Errorf("parse %q (registry override %q): %w", rewritten, opts.Registry, err)
	}
	return d, nil
}

func platformString(p *ggcrv1.Platform) string {
	s := p.OS + "/" + p.Architecture
	if p.Variant != "" {
		s += "/" + p.Variant
	}
	return s
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
