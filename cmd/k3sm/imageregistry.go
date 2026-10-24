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
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// errNotInRegistry reports that the cluster registry holds no manifest under
// the name or digest a verb was given.
var errNotInRegistry = errors.New("not in the cluster registry")

// clusterImage is one name in the cluster registry, spelled twice: flat is the
// registry-k3sm:6450 name a Pod spec uses and the output prints, and remote is
// the loopback spelling this Mac reaches the same registry at, the only one the
// push credential is presented to.
type clusterImage struct {
	flat   name.Reference
	remote name.Reference
}

// resolveClusterImage parses source as a cluster-registry name: a bare
// repository[:tag] or repository@digest, or the same under registry-k3sm:6450
// or a loopback spelling. A reference naming any other registry is refused with
// errForeignTag, because the tag, untag, inspect and save verbs act on the
// cluster registry alone.
//
// A bare digest names no repository, and a registry holds a manifest per
// repository, so it is refused here; tag resolves one inside its new name's
// repository instead (see imageTag).
func resolveClusterImage(source, workDir string) (clusterImage, error) {
	if looksLikeDigest(source) {
		return clusterImage{}, fmt.Errorf("%q names no repository; the cluster registry keeps a manifest per repository, so name it as <repository>@%s", source, source)
	}
	probe, err := name.ParseReference(source, name.WithDefaultRegistry(""))
	if err != nil {
		return clusterImage{}, fmt.Errorf("reference %q: %w", source, err)
	}
	reg := probe.Context().RegistryStr()
	if !isClusterRegistryHost(reg, workDir) {
		return clusterImage{}, fmt.Errorf("%q: %w (%s); these verbs act on the cluster registry, so name it as %s/%s", source, errForeignTag, reg, flatRegistryHost, probe.Context().RepositoryStr())
	}
	return clusterImageAt(probe.Context().RepositoryStr(), probe.Identifier(), workDir)
}

// clusterImageAt is the cluster image repository:identifier, where identifier
// is a tag or a digest.
func clusterImageAt(repository, identifier, workDir string) (clusterImage, error) {
	sep := ":"
	if looksLikeDigest(identifier) {
		sep = "@"
	}
	flat, err := name.ParseReference(flatRegistryHost + "/" + repository + sep + identifier)
	if err != nil {
		return clusterImage{}, fmt.Errorf("reference %s/%s%s%s: %w", flatRegistryHost, repository, sep, identifier, err)
	}
	authority, err := nodeRegistryAuthority(workDir)
	if err != nil {
		return clusterImage{}, err
	}
	rem, err := name.ParseReference(authority + "/" + repository + sep + identifier)
	if err != nil {
		return clusterImage{}, fmt.Errorf("reference %s/%s%s%s: %w", authority, repository, sep, identifier, err)
	}
	return clusterImage{flat: flat, remote: rem}, nil
}

// isTag reports whether the image is named by a tag rather than a digest.
func (c clusterImage) isTag() bool {
	_, ok := c.flat.(name.Tag)
	return ok
}

// registryOptions are the options every cluster-registry call carries: the
// deadline, and this node's push credential, resolved through the same chain
// `k3sm image push` uses.
func registryOptions(ctx context.Context, c clusterImage, workDir string) ([]remote.Option, error) {
	auth, err := registryAuth(c.remote, workDir)
	if err != nil {
		return nil, err
	}
	return []remote.Option{remote.WithContext(ctx), remote.WithAuth(auth)}, nil
}

// getClusterImage fetches the manifest c names, and when platform is set and
// the manifest is an index, the child for that platform.
func getClusterImage(c clusterImage, platform *runtimev1.Platform, workDir string, opts []remote.Option) (*remote.Descriptor, *remote.Descriptor, error) {
	desc, err := remote.Get(c.remote, opts...)
	if err != nil {
		return nil, nil, registryError("read "+c.flat.String(), err)
	}
	if platform == nil || !desc.MediaType.IsIndex() {
		if platform != nil {
			if err := checkImagePlatform(desc, platform, c); err != nil {
				return nil, nil, err
			}
		}
		return desc, nil, nil
	}
	idx, err := desc.ImageIndex()
	if err != nil {
		return nil, nil, fmt.Errorf("read the index %s: %w", c.flat, err)
	}
	m, err := idx.IndexManifest()
	if err != nil {
		return nil, nil, fmt.Errorf("parse the index %s: %w", c.flat, err)
	}
	for _, child := range m.Manifests {
		if !platformMatches(child.Platform, platform) {
			continue
		}
		at, err := clusterImageAt(c.flat.Context().RepositoryStr(), child.Digest.String(), workDir)
		if err != nil {
			return nil, nil, err
		}
		cd, err := remote.Get(at.remote, opts...)
		if err != nil {
			return nil, nil, registryError("read "+at.flat.String(), err)
		}
		return cd, desc, nil
	}
	return nil, nil, fmt.Errorf("%s: %w for %s (the index holds %s)", c.flat, errNotInRegistry, platformText(platform), indexPlatformList(m))
}

// checkImagePlatform refuses a --platform that a single-platform image does not
// have: the image would otherwise be reported or saved as the platform asked for.
func checkImagePlatform(desc *remote.Descriptor, platform *runtimev1.Platform, c clusterImage) error {
	img, err := desc.Image()
	if err != nil {
		return fmt.Errorf("read the image %s: %w", c.flat, err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return fmt.Errorf("read the config of %s: %w", c.flat, err)
	}
	p := cf.Platform()
	if !platformMatches(p, platform) {
		have := "no declared platform"
		if p != nil {
			have = p.String()
		}
		return fmt.Errorf("%s is a single-platform image (%s), not %s", c.flat, have, platformText(platform))
	}
	return nil
}

// platformMatches reports whether p is the platform want selects. An unset
// variant in want matches any variant.
func platformMatches(p *ggcrv1.Platform, want *runtimev1.Platform) bool {
	if p == nil {
		return false
	}
	if p.OS != want.GetOs() || p.Architecture != want.GetArchitecture() {
		return false
	}
	return want.GetVariant() == "" || p.Variant == want.GetVariant()
}

// indexPlatformList lists an index's platforms for an error message.
func indexPlatformList(m *ggcrv1.IndexManifest) string {
	out := ""
	for i, child := range m.Manifests {
		if i > 0 {
			out += ", "
		}
		if child.Platform == nil {
			out += "an unlabelled manifest"
			continue
		}
		out += child.Platform.String()
	}
	if out == "" {
		return "no manifests"
	}
	return out
}

// isNotFound reports whether err is the registry answering 404.
func isNotFound(err error) bool {
	var terr *transport.Error
	return errors.As(err, &terr) && terr.StatusCode == http.StatusNotFound
}

// registryError classifies a cluster-registry failure: a name the registry
// does not hold is errNotInRegistry, a refused credential is errPushAuth, and
// an unreachable registry is errPushNetwork, the sentinels push already uses.
func registryError(what string, err error) error {
	if isNotFound(err) {
		return fmt.Errorf("%s: %w", what, errNotInRegistry)
	}
	var terr *transport.Error
	if errors.As(err, &terr) {
		switch terr.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return fmt.Errorf("%s: %w: the cluster registry answered HTTP %d (point --work-dir at the control plane whose push credential you can read)", what, errPushAuth, terr.StatusCode)
		}
		return fmt.Errorf("%s: the cluster registry answered HTTP %d: %v", what, terr.StatusCode, terr)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s: the registry did not answer before the deadline (raise --timeout): %v", what, err)
	}
	return fmt.Errorf("%s: %w", what, err)
}
