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

package registrysvc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/runtimed/pkg/guestartifacts"
)

// The publish retry backoff: the first wait, and the ceiling it doubles to.
const (
	guestPublishFirstBackoff = 5 * time.Second
	guestPublishMaxBackoff   = 5 * time.Minute
)

// GuestSet is the pinned guest boot pair to publish: the names, type and
// digests the runtime's guest-artifact package derives from the pin (the same
// value its worker fetches by, so the two sides cannot disagree), and where
// each layer's file is on this host.
type GuestSet struct {
	// Artifact is guestartifacts.ClusterStoreArtifact of the active pin.
	Artifact guestartifacts.StoreArtifact
	// Files maps each layer's FileName to the verified file on this host.
	Files map[string]string
}

// GuestPublished is what one successful publish did.
type GuestPublished struct {
	// Digest is the manifest digest the tag names.
	Digest digest.Digest
	// Tagged is whether this publish wrote the tag; false when the tag already
	// named the manifest.
	Tagged bool
}

// GuestPublisher publishes the server's verified guest boot pair to the
// server's own registry, so a worker can fetch it from there by the pin's
// digests instead of from the release host.
//
// The artifact is a pure function of the pin: an OCI 1.1 manifest with the
// pin's artifactType, the empty config, and the pin's raw layers, each
// carrying its file name as its org.opencontainers.image.title annotation,
// which is how the worker finds it. Publishing is idempotent: a blob the repository holds is not
// uploaded again, and a tag that already names the manifest is not rewritten.
// A file whose bytes are not the pin's is refused before any request, and the
// manifest goes last, so the tag never names a manifest whose blobs are not
// all present.
type GuestPublisher struct {
	// Access resolves, per attempt, the registry authority to publish to and
	// the go-containerregistry options (credential, transport) that reach it.
	// It is asked on every attempt because the push credential is rewritten on
	// every registry boot.
	Access func(ctx context.Context) (authority string, opts []remote.Option, err error)
	// Logger receives the retry and success records; nil is slog.Default.
	Logger *slog.Logger

	// wait blocks for d or until ctx ends and reports whether d passed; nil
	// waits on a timer. A test seam.
	wait func(ctx context.Context, d time.Duration) bool
}

// Run publishes set, retrying a failed attempt with a doubling backoff until
// one succeeds or ctx ends. It reports whether the set was published. A
// failure is logged, never returned: the server serves without the published
// pair, and only a worker that needs it is affected.
func (p GuestPublisher) Run(ctx context.Context, set GuestSet) bool {
	log := p.Logger
	if log == nil {
		log = slog.Default()
	}
	backoff := guestPublishFirstBackoff
	for {
		got, err := p.Publish(ctx, set)
		if err == nil {
			log.Info("guest boot artifacts published to the cluster registry",
				"reference", set.Artifact.Repository+":"+set.Artifact.Tag, "digest", got.Digest, "tagged", got.Tagged)
			return true
		}
		if ctx.Err() != nil {
			return false
		}
		log.Warn("guest boot artifacts not published to the cluster registry; will retry",
			"reference", set.Artifact.Repository+":"+set.Artifact.Tag, "err", err, "in", backoff)
		if !p.sleep(ctx, backoff) {
			return false
		}
		backoff = min(2*backoff, guestPublishMaxBackoff)
	}
}

// sleep waits d through the wait seam, or a timer.
func (p GuestPublisher) sleep(ctx context.Context, d time.Duration) bool {
	if p.wait != nil {
		return p.wait(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Publish makes one publish attempt of set.
func (p GuestPublisher) Publish(ctx context.Context, set GuestSet) (GuestPublished, error) {
	a := set.Artifact
	what := a.Repository + ":" + a.Tag
	if p.Access == nil {
		return GuestPublished{}, fmt.Errorf("publish %s: no registry access", what)
	}
	if len(a.Layers) == 0 {
		return GuestPublished{}, fmt.Errorf("publish %s: the artifact names no layers", what)
	}
	layers := make([]guestBlob, 0, len(a.Layers))
	for _, l := range a.Layers {
		b, err := guestLayer(l, set.Files[l.FileName])
		if err != nil {
			return GuestPublished{}, fmt.Errorf("publish %s: %w", what, err)
		}
		layers = append(layers, b)
	}
	body, err := guestManifest(a.ArtifactType, layers)
	if err != nil {
		return GuestPublished{}, err
	}
	manifestDigest := digest.FromBytes(body)

	authority, opts, err := p.Access(ctx)
	if err != nil {
		return GuestPublished{}, fmt.Errorf("publish %s: %w", what, err)
	}
	opts = append(append([]remote.Option(nil), opts...), remote.WithContext(ctx))
	tag, err := name.NewTag(a.Reference(authority))
	if err != nil {
		return GuestPublished{}, fmt.Errorf("publish %s: %w", what, err)
	}
	ref := tag.String()

	// WriteLayer HEADs each blob first and uploads only one the repository
	// lacks.
	empty := guestBlob{desc: emptyConfig(), open: func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(ispec.DescriptorEmptyJSON.Data)), nil
	}}
	for _, b := range append([]guestBlob{empty}, layers...) {
		if err := remote.WriteLayer(tag.Context(), b, opts...); err != nil {
			return GuestPublished{}, fmt.Errorf("publish %s: upload %s: %w", ref, b.desc.Digest, err)
		}
	}
	if desc, err := remote.Head(tag, opts...); err == nil && desc.Digest.String() == manifestDigest.String() {
		return GuestPublished{Digest: manifestDigest}, nil
	}
	if err := remote.Put(tag, guestRawManifest(body), opts...); err != nil {
		return GuestPublished{}, fmt.Errorf("publish %s: %w", ref, err)
	}
	return GuestPublished{Digest: manifestDigest, Tagged: true}, nil
}

// guestLayer describes the file at path as layer l, after checking its bytes
// against l's digest.
func guestLayer(l guestartifacts.StoreLayer, path string) (guestBlob, error) {
	if path == "" {
		return guestBlob{}, fmt.Errorf("guest artifact %s: no file on this host", l.FileName)
	}
	d, err := digest.Parse(l.Digest)
	if err != nil || d.Algorithm() != digest.SHA256 {
		return guestBlob{}, fmt.Errorf("guest artifact %s: digest %q is not a sha256 digest", l.FileName, l.Digest)
	}
	size, err := verifyGuestFile(path, d)
	if err != nil {
		return guestBlob{}, err
	}
	desc := ispec.Descriptor{
		MediaType:   l.MediaType,
		Digest:      d,
		Size:        size,
		Annotations: map[string]string{ispec.AnnotationTitle: l.FileName},
	}
	return guestBlob{desc: desc, open: func() (io.ReadCloser, error) { return os.Open(path) }}, nil
}

// verifyGuestFile hashes the regular file at path and returns its size, or
// an error when its bytes are not the pin's. It runs before the registry is
// contacted, so a rotted file costs no request; a file that changes after it
// is still refused, by the registry's own digest check on upload.
func verifyGuestFile(path string, want digest.Digest) (int64, error) {
	fh, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("guest artifact: %w", err)
	}
	defer fh.Close()
	fi, err := fh.Stat()
	if err != nil {
		return 0, fmt.Errorf("guest artifact: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return 0, fmt.Errorf("guest artifact %s: not a regular file", path)
	}
	h := sha256.New()
	n, err := io.Copy(h, fh)
	if err != nil {
		return 0, fmt.Errorf("guest artifact %s: %w", path, err)
	}
	if got := digest.NewDigestFromBytes(digest.SHA256, h.Sum(nil)); got != want {
		return 0, fmt.Errorf("guest artifact %s: digest %s, the pin names %s", path, got, want)
	}
	return n, nil
}

// guestManifest renders the guest artifact manifest over layers.
func guestManifest(artifactType string, layers []guestBlob) ([]byte, error) {
	m := ispec.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ispec.MediaTypeImageManifest,
		ArtifactType: artifactType,
		Config:       emptyConfig(),
	}
	for _, l := range layers {
		m.Layers = append(m.Layers, l.desc)
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("render the guest manifest: %w", err)
	}
	return b, nil
}

// emptyConfig is the OCI empty config descriptor, without its inline data so
// the manifest carries only the reference.
func emptyConfig() ispec.Descriptor {
	d := ispec.DescriptorEmptyJSON
	d.Data = nil
	return d
}

// guestBlob is one blob as go-containerregistry uploads it: raw, so its
// compressed and uncompressed forms are the same bytes.
type guestBlob struct {
	desc ispec.Descriptor
	open func() (io.ReadCloser, error)
}

func (b guestBlob) Digest() (ggcrv1.Hash, error)         { return ggcrv1.NewHash(b.desc.Digest.String()) }
func (b guestBlob) DiffID() (ggcrv1.Hash, error)         { return b.Digest() }
func (b guestBlob) Compressed() (io.ReadCloser, error)   { return b.open() }
func (b guestBlob) Uncompressed() (io.ReadCloser, error) { return b.open() }
func (b guestBlob) Size() (int64, error)                 { return b.desc.Size, nil }
func (b guestBlob) MediaType() (types.MediaType, error) {
	return types.MediaType(b.desc.MediaType), nil
}

// guestRawManifest is manifest bytes remote.Put sends verbatim.
type guestRawManifest []byte

func (m guestRawManifest) RawManifest() ([]byte, error) { return m, nil }
func (m guestRawManifest) MediaType() (types.MediaType, error) {
	return types.MediaType(ispec.MediaTypeImageManifest), nil
}
