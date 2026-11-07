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
)

// ArtifactResolver resolves a tag in the cluster registry to the manifest
// digest ("sha256:<hex>") it names now.
type ArtifactResolver interface {
	ResolveArtifact(ctx context.Context, repository, tag string) (string, error)
}

// ArtifactResolverFunc adapts a function to ArtifactResolver.
type ArtifactResolverFunc func(ctx context.Context, repository, tag string) (string, error)

// ResolveArtifact calls f.
func (f ArtifactResolverFunc) ResolveArtifact(ctx context.Context, repository, tag string) (string, error) {
	return f(ctx, repository, tag)
}

// errNoResolver is the resolution failure of an operator built without a
// registry client: nothing changes until its configuration does, so it is
// reported and not retried.
var errNoResolver = errors.New("the mlx operator has no cluster registry client to resolve a tag; name the artifact by digest")

// RegistryResolver resolves tags by reading the manifest from the cluster
// registry through c. The manifest bytes are hashed, so the digest returned is
// the one the content has, not only the one the registry reported. An index is
// refused: selecting one of its entries needs spec.artifact.variant, which is
// not supported yet.
func RegistryResolver(c *registryclient.Client) ArtifactResolver {
	return ArtifactResolverFunc(func(ctx context.Context, repository, tag string) (string, error) {
		m, err := c.Manifest(ctx, repository, tag)
		if err != nil {
			return "", err
		}
		if m.IsIndex() {
			return "", fmt.Errorf("%s:%s is an index (%s), not a single model manifest", repository, tag, m.MediaType)
		}
		return m.Digest, nil
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
// (malformed, off the cluster registry, a variant) is never sent to the
// registry: the digest stays empty and the render names the refusal. A Hub
// model's digest is cleared.
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
	if ref.Digest != "" {
		model.Status.ResolvedArtifact = ref.Digest
		return nil
	}
	if c.artifacts == nil {
		return errNoResolver
	}
	digest, err := c.artifacts.ResolveArtifact(ctx, ref.Repository, ref.Tag)
	if err != nil {
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
