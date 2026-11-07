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

package mlx

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	corev1 "k8s.io/api/core/v1"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	"k3sm.io/k3sm/pkg/registryclient"
)

// Artifact render errors. Like every render error they are returned wrapped
// with the model's namespace/name; branch with errors.Is.
var (
	// ErrInvalidArtifact is returned for a spec.artifact.reference that is
	// not host/repository:tag or host/repository@sha256:<hex>.
	ErrInvalidArtifact = errors.New("spec.artifact.reference must be <registry>/<repository>:<tag> or <registry>/<repository>@sha256:<hex>")
	// ErrForeignArtifact is returned when spec.artifact.reference names a
	// registry other than the cluster registry. The node runtime fetches the
	// volume as root; a reference a pod author could point anywhere would make
	// it contact an arbitrary host.
	ErrForeignArtifact = errors.New("spec.artifact.reference does not name the cluster registry")
	// ErrArtifactUnresolved is returned when status.resolvedArtifact holds no
	// digest for the reference (or a stale one for a digest reference). Every
	// replica and rank renders against that one digest, so rendering before it
	// is recorded could serve two different sets of bytes under one object.
	ErrArtifactUnresolved = errors.New("spec.artifact has no resolved manifest digest yet")
	// ErrArtifactConflict is returned when spec.artifact is set together with a
	// field that only means something for a Hub model: spec.model (the two are
	// exclusive), spec.revision (the digest is the pin) or spec.cache (the
	// weights arrive as a read-only image volume, never as a download into a
	// claim).
	ErrArtifactConflict = errors.New("spec.artifact is exclusive with a Hub-only field")
	// ErrArtifactVariantUnsupported is returned for a non-empty
	// spec.artifact.variant. Selecting an index entry is not implemented, and
	// ignoring the field would serve whatever the reference happens to name.
	ErrArtifactVariantUnsupported = errors.New("spec.artifact.variant is not supported yet")
)

const (
	// artifactVolumeName is the name of the image volume holding the model.
	artifactVolumeName = "model"
	// ArtifactMountPath is where the model artifact is mounted, read-only, in
	// the serving container, and the model path the engine is given.
	ArtifactMountPath = "/var/lib/mlx/model"
)

// digestPattern is the one digest form a rendered reference carries.
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ArtifactReference is a parsed spec.artifact.reference. Exactly one of Tag and
// Digest is set.
type ArtifactReference struct {
	// Host is the registry host[:port] the reference names.
	Host string
	// Repository is the repository path inside the registry.
	Repository string
	// Tag is the tag, when the reference is by tag.
	Tag string
	// Digest is the manifest digest, when the reference is by digest.
	Digest string
}

// ParseArtifactReference parses ref and checks it names registryHost. A
// reference carrying both a tag and a digest is taken by its digest, as a
// registry client does. An empty registryHost matches nothing: without the
// cluster registry's name no reference can be shown to be on it.
//
// The error wraps ErrInvalidArtifact or ErrForeignArtifact.
func ParseArtifactReference(ref, registryHost string) (ArtifactReference, error) {
	host, rest, ok := strings.Cut(ref, "/")
	if !ok || host == "" || rest == "" {
		return ArtifactReference{}, fmt.Errorf("%w: %q", ErrInvalidArtifact, ref)
	}
	if registryHost == "" || host != registryHost {
		return ArtifactReference{}, fmt.Errorf("%w: %q is not %q", ErrForeignArtifact, host, registryHost)
	}
	out := ArtifactReference{Host: host}
	if name, digest, byDigest := strings.Cut(rest, "@"); byDigest {
		if !digestPattern.MatchString(digest) {
			return ArtifactReference{}, fmt.Errorf("%w: %q", ErrInvalidArtifact, ref)
		}
		out.Digest = digest
		rest = name
		if i := strings.LastIndex(rest, ":"); i >= 0 && !strings.Contains(rest[i:], "/") {
			rest = rest[:i]
		}
	} else {
		i := strings.LastIndex(rest, ":")
		if i < 0 || strings.Contains(rest[i:], "/") || !registryclient.ValidTag(rest[i+1:]) {
			return ArtifactReference{}, fmt.Errorf("%w: %q", ErrInvalidArtifact, ref)
		}
		out.Tag = rest[i+1:]
		rest = rest[:i]
	}
	if !registryclient.ValidRepository(rest) {
		return ArtifactReference{}, fmt.Errorf("%w: %q", ErrInvalidArtifact, ref)
	}
	out.Repository = rest
	return out, nil
}

// ServedModelName is the name clients send for m: spec.model for a Hub model,
// metadata.name for an artifact model (which has no spec.model).
func ServedModelName(m *mlxv1alpha1.MLXModel) string {
	if m.Spec.Artifact != nil {
		return m.Name
	}
	return m.Spec.Model
}

// artifactVolume checks an artifact spec and builds the image volume serving
// it: the cluster registry reference pinned to status.resolvedArtifact. Any
// refusal returns a nil volume, so a caller can never fall back to the Hub.
func artifactVolume(m *mlxv1alpha1.MLXModel, opts Options) (*corev1.Volume, error) {
	a := m.Spec.Artifact
	switch {
	case m.Spec.Model != "":
		return nil, fmt.Errorf("%w: spec.model is set", ErrArtifactConflict)
	case m.Spec.Revision != "":
		return nil, fmt.Errorf("%w: spec.revision is set; the artifact digest is the pin", ErrArtifactConflict)
	case m.Spec.Cache != nil:
		return nil, fmt.Errorf("%w: spec.cache is set; the weights are a read-only image volume", ErrArtifactConflict)
	case a.Variant != "":
		return nil, fmt.Errorf("%w: %q", ErrArtifactVariantUnsupported, a.Variant)
	}
	ref, err := ParseArtifactReference(a.Reference, opts.RegistryHost)
	if err != nil {
		return nil, err
	}
	digest := m.Status.ResolvedArtifact
	if !digestPattern.MatchString(digest) || (ref.Digest != "" && ref.Digest != digest) {
		return nil, fmt.Errorf("%w: status.resolvedArtifact=%q", ErrArtifactUnresolved, digest)
	}
	return &corev1.Volume{
		Name: artifactVolumeName,
		VolumeSource: corev1.VolumeSource{
			Image: &corev1.ImageVolumeSource{
				Reference:  ref.Host + "/" + ref.Repository + "@" + digest,
				PullPolicy: corev1.PullIfNotPresent,
			},
		},
	}, nil
}

// artifactMount is the read-only mount of the artifact volume.
func artifactMount() corev1.VolumeMount {
	return corev1.VolumeMount{Name: artifactVolumeName, MountPath: ArtifactMountPath, ReadOnly: true}
}
