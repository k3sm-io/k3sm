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
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// registryTokenEnv overrides the docker config chain with a bearer token read
// from the environment. It exists for the non-interactive case — a lab Mac or a
// release step that holds a token but has never run `docker login`.
const registryTokenEnv = "K3SM_REGISTRY_TOKEN"

// The push failure modes an operator acts on differently. They are sentinels
// rather than message text because "the credential was refused" and "the host
// was unreachable" call for opposite responses, and a caller that has to match
// strings to tell them apart will eventually match the wrong one.
var (
	// errPushNoLayout: the path is not an OCI image layout directory.
	errPushNoLayout = errors.New("no OCI image layout to push")
	// errPushImageCount: the layout does not hold exactly one image. Mirrors the
	// one-image rule the load side already enforces on an imported layout.
	errPushImageCount = errors.New("layout does not hold exactly one image")
	// errPushAuth: the registry answered, and refused the credential.
	errPushAuth = errors.New("registry rejected the credential")
	// errPushNetwork: the registry never answered.
	errPushNetwork = errors.New("cannot reach the registry")
)

// imagePush uploads the single image in an OCI layout directory to a registry
// reference and prints the digest it now has there.
//
// THE CREDENTIAL NEVER COMES FROM ARGV AND IS NEVER STORED. It is read from the
// environment or the docker config chain at the moment of the upload, used for
// that upload, and forgotten: k3sm writes no credential file and adds nothing to
// the operator's docker config. See registryAuth for why argv is excluded.
//
// This is the one `k3sm image` subcommand that is not a client of runtimed. It
// reads a path the invoking user owns and talks to a registry as that user; the
// node's image store is not involved, so no daemon has to be running.
func imagePush(ctx context.Context, o imageOptions, out io.Writer) error {
	ref, err := name.ParseReference(o.target)
	if err != nil {
		return fmt.Errorf("target reference %q: %w", o.target, err)
	}
	img, err := layoutImage(o.layoutDir)
	if err != nil {
		return err
	}
	// Hashed from the bytes on disk rather than taken from anything the registry
	// echoed back, so the printed pin is a claim about content this process read
	// — a registry that answered with a different digest would not change it.
	digest, err := img.Digest()
	if err != nil {
		return fmt.Errorf("compute digest of the image in %s: %w", o.layoutDir, err)
	}
	auth, err := registryAuth(ref)
	if err != nil {
		return err
	}
	if err := remote.Write(ref, img, remote.WithContext(ctx), remote.WithAuth(auth)); err != nil {
		return pushError(ref, err)
	}
	// The digest is printed so the caller can pin what it just published: a tag
	// is mutable and the next push moves it, while ref@digest names these bytes
	// forever.
	fmt.Fprintf(out, "pushed %s\n  digest: %s\n  pin:    %s@%s\n", ref, digest, ref.Context().Name(), digest)
	return nil
}

// layoutImage opens an OCI image layout directory and returns the one image it
// holds.
//
// Exactly one, deliberately: an OCI layout is a multi-image container, and a
// push that silently chose the first of several would publish one image under a
// reference the operator believed named another. `k3sm build --format oci`
// writes one image per directory, so the rule costs the normal path nothing.
func layoutImage(dir string) (ggcrv1.Image, error) {
	info, err := os.Stat(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s does not exist", errPushNoLayout, dir)
		}
		return nil, fmt.Errorf("open layout %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%w: %s is not a directory (push takes the layout directory `k3sm build --format oci` writes, not a tar)", errPushNoLayout, dir)
	}
	p, err := layout.FromPath(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s has no index.json, so it is not an OCI layout", errPushNoLayout, dir)
		}
		return nil, fmt.Errorf("open layout %s: %w", dir, err)
	}
	idx, err := p.ImageIndex()
	if err != nil {
		return nil, fmt.Errorf("read the index of layout %s: %w", dir, err)
	}
	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("parse the index of layout %s: %w", dir, err)
	}
	if len(manifest.Manifests) != 1 {
		return nil, fmt.Errorf("%w: %s indexes %d of them", errPushImageCount, dir, len(manifest.Manifests))
	}
	desc := manifest.Manifests[0]
	if desc.MediaType.IsIndex() {
		return nil, fmt.Errorf("%w: %s indexes a nested image index (%s), which may name several images", errPushImageCount, dir, desc.MediaType)
	}
	img, err := p.Image(desc.Digest)
	if err != nil {
		return nil, fmt.Errorf("read image %s from layout %s: %w", desc.Digest, dir, err)
	}
	return img, nil
}

// registryAuth resolves the credential for ref.
//
// Two sources, in this order: the K3SM_REGISTRY_TOKEN environment variable, then
// the standard docker config chain (`docker login`, `crane auth login`, and the
// credential helpers those configure). argv is deliberately not a third: an
// argument is visible in `ps` to every user on the machine for as long as the
// upload runs, and it is written verbatim into the invoking shell's history
// file, so a token passed that way outlives the command that used it.
func registryAuth(ref name.Reference) (authn.Authenticator, error) {
	// Trimmed because the usual way to set this is from a file or a command
	// substitution, both of which carry the trailing newline into the value —
	// and a bearer token with a newline in it is rejected as a bad credential,
	// which reads to the operator like the wrong token rather than a stray byte.
	if token := strings.TrimSpace(os.Getenv(registryTokenEnv)); token != "" {
		return authn.FromConfig(authn.AuthConfig{RegistryToken: token}), nil
	}
	auth, err := authn.DefaultKeychain.Resolve(ref.Context())
	if err != nil {
		return nil, fmt.Errorf("resolve a credential for %s: %w", ref.Context().RegistryStr(), err)
	}
	return auth, nil
}

// pushError classifies an upload failure into the sentinel an operator can act
// on. The distinction that matters is whether the registry answered at all:
// a refused credential is fixed by supplying one, an unreachable host is not.
func pushError(ref name.Reference, err error) error {
	var terr *transport.Error
	if errors.As(err, &terr) {
		switch terr.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return fmt.Errorf("push %s: %w: %s answered HTTP %d (set %s, or log in so the docker config chain resolves that registry)",
				ref, errPushAuth, ref.Context().RegistryStr(), terr.StatusCode, registryTokenEnv)
		}
		return fmt.Errorf("push %s: %s answered HTTP %d: %v", ref, ref.Context().RegistryStr(), terr.StatusCode, terr)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("push %s: the upload did not finish before the deadline (raise --timeout): %v", ref, err)
	}
	var uerr *url.Error
	var nerr net.Error
	if errors.As(err, &uerr) || errors.As(err, &nerr) {
		return fmt.Errorf("push %s: %w at %s: %v", ref, errPushNetwork, ref.Context().RegistryStr(), err)
	}
	return fmt.Errorf("push %s: %w", ref, err)
}
