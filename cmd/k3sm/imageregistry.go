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
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/darwin-net/pkg/tcpseg"

	"k3sm.io/k3sm/pkg/registrysvc"
)

// errNotInRegistry reports that the cluster registry holds no manifest under
// the name or digest a verb was given.
var errNotInRegistry = errors.New("not in the cluster registry")

// clusterImage is one name in the cluster registry, spelled twice: flat is the
// registry-k3sm:6450 name a Pod spec uses and the output prints, and remote is
// the spelling this run reaches the same registry at (registryAccess.locate),
// the only one a credential is presented to. A parsed name has no remote until
// it is located.
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
	return clusterImageAt(probe.Context().RepositoryStr(), probe.Identifier())
}

// clusterImageAt is the cluster image repository:identifier, where identifier
// is a tag or a digest.
func clusterImageAt(repository, identifier string) (clusterImage, error) {
	flat, err := name.ParseReference(flatRegistryHost + "/" + repository + identifierSep(identifier) + identifier)
	if err != nil {
		return clusterImage{}, fmt.Errorf("reference %s/%s%s%s: %w", flatRegistryHost, repository, identifierSep(identifier), identifier, err)
	}
	return clusterImage{flat: flat}, nil
}

// identifierSep is the separator a reference puts before identifier.
func identifierSep(identifier string) string {
	if looksLikeDigest(identifier) {
		return "@"
	}
	return ":"
}

// isTag reports whether the image is named by a tag rather than a digest.
func (c clusterImage) isTag() bool {
	_, ok := c.flat.(name.Tag)
	return ok
}

// registryAccess is how one run of a cluster-registry verb reaches the
// registry: the authority its names are spelled under, and the options every
// call carries. Three ways, chosen by what the verb does and what this account
// can read:
//
//   - the per-boot push credential, when this account can read it (root, or a
//     --work-dir naming a control plane it runs as): the registry's own
//     loopback listener, as before the push gate existed;
//   - for a write without it, the push gate with a builder token minted
//     through the account's kubeconfig, exactly as `k3sm image push` and
//     `k3sm build --push` write;
//   - for a read without it, the registry's loopback listener anonymously at
//     the port the server's published record names, because reads of the
//     cluster registry are anonymous everywhere.
type registryAccess struct {
	authority string
	opts      []remote.Option
}

// locate spells c's repository and identifier under a's authority.
func (a registryAccess) locate(c clusterImage) (clusterImage, error) {
	repo := c.flat.Context().RepositoryStr() + identifierSep(c.flat.Identifier()) + c.flat.Identifier()
	rem, err := name.ParseReference(a.authority + "/" + repo)
	if err != nil {
		return clusterImage{}, fmt.Errorf("reference %s/%s: %w", a.authority, repo, err)
	}
	return clusterImage{flat: c.flat, remote: rem}, nil
}

// credentialAccess is the per-boot push credential's access, when this account
// can read the credential under workDir. ok is false when it cannot, for any
// reason (none was minted there, or the file is another account's 0600 one),
// which is the caller's cue to use the account's own identity.
func credentialAccess(ctx context.Context, workDir string) (acc registryAccess, ok bool, err error) {
	if workDir == "" {
		return registryAccess{}, false, nil
	}
	if _, err := registrysvc.ReadCredential(workDir); err != nil {
		return registryAccess{}, false, nil
	}
	authority, err := nodeRegistryAuthority(workDir)
	if err != nil {
		return registryAccess{}, true, err
	}
	// registryAuth keys on the registry alone; the repository and tag only
	// make the name a reference.
	probe, err := name.NewTag(authority + "/k3sm:access")
	if err != nil {
		return registryAccess{}, true, fmt.Errorf("reference %s: %w", authority, err)
	}
	auth, err := registryAuth(probe, workDir)
	if err != nil {
		return registryAccess{}, true, err
	}
	return registryAccess{authority: authority, opts: []remote.Option{remote.WithContext(ctx), remote.WithAuth(auth)}}, true, nil
}

// registryReadAccess is how a read (inspect, save, and tag's reads) reaches the
// cluster registry: with the push credential when it is readable, else
// anonymously at the registry's loopback listener on this server. A Mac whose
// server serves no registry here is told where the read runs.
func registryReadAccess(ctx context.Context, workDir string) (registryAccess, error) {
	if acc, ok, err := credentialAccess(ctx, workDir); ok {
		return acc, err
	}
	port := localRegistryPort(workDir)
	authority := registrysvc.LoopbackAuthority(port)
	if authority == "" {
		return registryAccess{}, fmt.Errorf("%w: this Mac serves no cluster registry (no serving registry record under %s or %s); run this on the server, whose registry it reads anonymously", errNoNodeRegistry, workDir, installedServerWorkDir)
	}
	return registryAccess{authority: authority, opts: []remote.Option{remote.WithContext(ctx), remote.WithTransport(loopbackReadTransport())}}, nil
}

// loopbackReadTransport is the transport of an anonymous read at the
// registry's loopback listener: segment-clamped like every dial this CLI makes
// toward the registry (the push gate's included), and dialed through gateDial
// when a test serves the registry in process.
func loopbackReadTransport() http.RoundTripper {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = (&tcpseg.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	if gateDial != nil {
		t.DialContext = gateDial
	}
	return t
}

// registryWriteAccess is how a write (tag) reaches the cluster registry: with
// the push credential when it is readable, else through the push gate with a
// builder token minted through the account's kubeconfig, the identity every
// push already writes with. A failure to mint one carries its own remedy
// (builderTokenRemedy, or the RoleBinding an admin grants).
func registryWriteAccess(ctx context.Context, workDir string) (registryAccess, error) {
	if acc, ok, err := credentialAccess(ctx, workDir); ok {
		return acc, err
	}
	cr, err := resolveClusterRegistry(ctx, workDir)
	if err != nil {
		return registryAccess{}, err
	}
	opts, err := cr.options(ctx)
	if err != nil {
		return registryAccess{}, err
	}
	return registryAccess{authority: cr.authority, opts: opts}, nil
}

// registryDeleteAccess is how untag reaches the cluster registry: only with the
// push credential. The push gate never forwards a delete, so no builder token
// removes a tag, and without the credential this names the root run that has
// it rather than sending a request the gate refuses.
func registryDeleteAccess(ctx context.Context, workDir string) (registryAccess, error) {
	if acc, ok, err := credentialAccess(ctx, workDir); ok {
		return acc, err
	}
	return registryAccess{}, fmt.Errorf("%w: untag deletes, and the push gate a builder token writes through never forwards a delete, so untag needs the server's per-boot credential, which this account cannot read at %s; run it on the server as root: sudo k3sm image --work-dir %s untag <name>",
		errNoNodeRegistry, registrysvc.CredentialPath(workDir), installedServerWorkDir)
}

// getClusterImage fetches the manifest c names, and when platform is set and
// the manifest is an index, the child for that platform.
func getClusterImage(c clusterImage, platform *runtimev1.Platform, acc registryAccess) (*remote.Descriptor, *remote.Descriptor, error) {
	desc, err := remote.Get(c.remote, acc.opts...)
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
		at, err := clusterImageAt(c.flat.Context().RepositoryStr(), child.Digest.String())
		if err != nil {
			return nil, nil, err
		}
		if at, err = acc.locate(at); err != nil {
			return nil, nil, err
		}
		cd, err := remote.Get(at.remote, acc.opts...)
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
// does not hold is errNotInRegistry and a refused credential is errPushAuth (the
// sentinel push uses); any other status, a missed deadline (which names
// --timeout) or a transport failure is wrapped with what was being done.
func registryError(what string, err error) error {
	if isNotFound(err) {
		return fmt.Errorf("%s: %w", what, errNotInRegistry)
	}
	var terr *transport.Error
	if errors.As(err, &terr) {
		switch terr.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return fmt.Errorf("%s: %w: the cluster registry answered HTTP %d (run as root with --work-dir naming the control plane whose push credential it reads, or check that your kubeconfig may mint a registry push token)", what, errPushAuth, terr.StatusCode)
		}
		return fmt.Errorf("%s: the cluster registry answered HTTP %d: %v", what, terr.StatusCode, terr)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s: the registry did not answer before the deadline (raise --timeout): %v", what, err)
	}
	return fmt.Errorf("%s: %w", what, err)
}
