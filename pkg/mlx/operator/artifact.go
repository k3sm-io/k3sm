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

package operator

import (
	"context"
	"errors"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	"k3sm.io/k3sm/pkg/mlx"
	"k3sm.io/k3sm/pkg/registryclient"
	"k3sm.io/runtimed/pkg/artifact"
)

// ArtifactResolver resolves a reference in the cluster registry, a tag or a
// digest, to the manifest digest ("sha256:<hex>") a replica renders. With an
// empty variant the reference must name a single manifest. With a variant it
// must name an OCI image index, and the digest returned is that of the one
// entry whose io.k3sm.model.variant annotation equals variant.
type ArtifactResolver interface {
	ResolveArtifact(ctx context.Context, repository, reference, variant string) (string, error)
}

// ArtifactResolverFunc adapts a function to ArtifactResolver.
type ArtifactResolverFunc func(ctx context.Context, repository, reference, variant string) (string, error)

// ResolveArtifact calls f.
func (f ArtifactResolverFunc) ResolveArtifact(ctx context.Context, repository, reference, variant string) (string, error) {
	return f(ctx, repository, reference, variant)
}

// errNoResolver is the resolution failure of an operator built without a
// registry client: nothing changes until its configuration does, so it is
// reported and not retried.
var errNoResolver = errors.New("the mlx operator has no cluster registry client to resolve a tag; name the artifact by digest")

// RegistryResolver resolves references by reading the manifest from the
// cluster registry through c. The manifest bytes are hashed, so the digest
// returned is the one the content has, not only the one the registry
// reported.
//
// Without a variant an index is refused (spec.quantization selects one of its
// entries). With one, a single manifest is refused, and the index goes
// through the runtime's own selection (artifact.SelectVariant: its size and
// entry caps, and a refusal of no match or of several); an index body over
// artifact.MaxIndexBytes is refused before its descriptors are decoded. The
// selected manifest is then read by digest and must hash to the entry's
// digest, have its size, and be served as an OCI image manifest.
func RegistryResolver(c *registryclient.Client) ArtifactResolver {
	return ArtifactResolverFunc(func(ctx context.Context, repository, reference, variant string) (string, error) {
		// An index body over the runtime's cap is refused before its
		// descriptors are decoded; a single manifest keeps the client's cap.
		m, err := c.ManifestIndexBounded(ctx, repository, reference, artifact.MaxIndexBytes)
		if err != nil {
			if errors.Is(err, registryclient.ErrIndexTooLarge) {
				return "", fmt.Errorf("%w: %w", err, artifact.ErrManifestTooLarge)
			}
			return "", err
		}
		if variant == "" {
			if m.IsIndex() {
				return "", fmt.Errorf("%s:%s is an index (%s), not a single model manifest; set spec.quantization to select a variant: %w", repository, reference, m.MediaType, artifact.ErrVariantRequired)
			}
			return m.Digest, nil
		}
		if !m.IsIndex() {
			return "", fmt.Errorf("%s:%s is a single manifest: %w", repository, reference, artifact.ErrVariantOnManifest)
		}
		entry, err := artifact.SelectVariant(m.Raw, m.Served, variant)
		if err != nil {
			return "", fmt.Errorf("%s:%s: %w", repository, reference, err)
		}
		v, err := c.Manifest(ctx, repository, entry.Digest)
		if err != nil {
			return "", err
		}
		if v.Digest != entry.Digest || v.MediaType != registryclient.MediaTypeOCIManifest || v.Size != entry.Size {
			return "", fmt.Errorf("%s@%s reads as %s, %s of %d bytes; the index names an OCI image manifest of %d bytes: %w",
				repository, entry.Digest, v.Digest, v.MediaType, v.Size, entry.Size, artifact.ErrManifestInvalid)
		}
		return entry.Digest, nil
	})
}

// resolveArtifact sets model.Status.ResolvedArtifact to the digest every
// replica and rank of this generation renders against.
//
// A tag is resolved ONCE per metadata.generation: a recorded digest whose
// status was written at the current generation is kept, so a tag moved in the
// registry never splits one generation's replicas across two sets of bytes,
// and an operator restart does not re-resolve. Because this runs before any
// status is written, every status written at a generation carries that
// generation's resolution, which is what makes the observed generation a
// sound key for it.
//
// A reference by digest is used as is, and a reference the render will refuse
// (malformed, off the cluster registry, spec.artifact.variant) is never sent
// to the registry: the digest stays empty and the render names the refusal. A
// Hub model's digest is cleared.
//
// spec.quantization selects a variant: the reference, by tag or by digest,
// must name an OCI image index, and the digest recorded is that of the entry
// whose io.k3sm.model.variant annotation equals it, so every replica renders
// the selected manifest by digest. A refusal (no such entry, several, a
// single manifest with quantization set, an index without it) names the
// variant and is reported as InvalidSpec.
func (c *Controller) resolveArtifact(ctx context.Context, model *mlxv1alpha1.MLXModel) error {
	a := model.Spec.Artifact
	if a == nil {
		model.Status.ResolvedArtifact = ""
		return nil
	}
	if model.Status.ResolvedArtifact != "" && model.Status.ObservedGeneration == model.Generation {
		return nil
	}
	model.Status.ResolvedArtifact = ""
	ref, err := mlx.ParseArtifactReference(a.Reference, c.opts.RegistryHost)
	if err != nil || a.Variant != "" {
		return nil
	}
	variant := model.Spec.Quantization
	if ref.Digest != "" && variant == "" {
		model.Status.ResolvedArtifact = ref.Digest
		return nil
	}
	if c.artifacts == nil {
		return errNoResolver
	}
	reference := ref.Tag
	if ref.Digest != "" {
		reference = ref.Digest
	}
	digest, err := c.artifacts.ResolveArtifact(ctx, ref.Repository, reference, variant)
	if err != nil {
		if variant != "" {
			return fmt.Errorf("resolve %s variant %q (spec.quantization): %w", a.Reference, variant, err)
		}
		return fmt.Errorf("resolve %s: %w", a.Reference, err)
	}
	model.Status.ResolvedArtifact = digest
	return nil
}

// storedResolvedArtifact is status.resolvedArtifact as the object read from
// the API server holds it. The reconcile resolves into the in-memory model's
// status, so comparing the derived status with that one alone would miss a
// newly resolved digest.
func storedResolvedArtifact(raw *unstructured.Unstructured) string {
	v, _, _ := unstructured.NestedString(raw.Object, "status", "resolvedArtifact")
	return v
}
