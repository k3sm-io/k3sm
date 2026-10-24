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
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/v1/tarball"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

const (
	// archiveMetadataLimit caps the metadata document (manifest.json /
	// index.json) the CLI parses out of the archive. This is operator-supplied,
	// potentially untrusted input, so it is never read into memory unbounded.
	archiveMetadataLimit = 4 << 20

	// ociRefNameAnnotation is the OCI layout annotation carrying an image's
	// reference — what `k3sm build --format oci` and `docker buildx -o type=oci`
	// both record, and what `import` derives its reference from.
	ociRefNameAnnotation = "org.opencontainers.image.ref.name"
)

// ingestPusher is the upload `k3sm image load` and `k3sm image import` record
// through: the same path `k3sm image push` and `k3sm build` use. A seam so the
// recording is provable without a registry.
var ingestPusher imagePusher = pushBuilt

// imageIngest records an operator's archive in the cluster registry and warms
// this node's cache with it.
//
// THE REGISTRY IS THE CLUSTER'S ONE IMAGE STORE. The archive is read here, as
// the invoking user, and uploaded to this server's registry under the
// normalised registry-k3sm:6450 name, overwriting whatever that tag named
// before. The node's own store is a pull cache: the warm pull goes through the
// runtime's ordinary puller, which re-hashes every blob against its digest, so
// a Pod on this node with imagePullPolicy Never still finds the image.
func imageIngest(ctx context.Context, o imageOptions, out io.Writer, push imagePusher, warm cacheWarmer, format runtimev1.LoadImageFormat) error {
	f, err := os.Open(o.archive)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	reference, err := inspectArchive(f, format)
	f.Close()
	if err != nil {
		return fmt.Errorf("%s: %w", o.archive, err)
	}
	if o.reference != "" {
		reference = o.reference
	}
	if reference == "" {
		return fmt.Errorf("%s: the archive records no reference; pass --reference <name:tag>", o.archive)
	}
	ref, err := registryReference(reference)
	if err != nil {
		return err
	}

	b, cleanup, err := readArchive(o.archive, format)
	if err != nil {
		return fmt.Errorf("%s: %w", o.archive, err)
	}
	defer cleanup()
	if err := recordInto(ctx, ref, b, o.workDir, push, warm); err != nil {
		return err
	}
	digest, err := b.digest()
	if err != nil {
		return fmt.Errorf("compute digest: %w", err)
	}
	fmt.Fprintf(out, "%s %s\n  store:  recorded in the cluster registry as %s\n  digest: %s\n", pastTense(o.subcommand), o.archive, ref, digest)
	return nil
}

// readArchive opens the image an archive holds, for upload. A docker-save tar
// is read in place; a tarred OCI layout is unpacked into a staging directory
// first, which the returned cleanup removes. A layout whose one descriptor is
// a multi-platform index is uploaded as that whole index.
func readArchive(archive string, format runtimev1.LoadImageFormat) (built, func(), error) {
	if format == runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_DOCKER_SAVE {
		img, err := tarball.ImageFromPath(archive, nil)
		if err != nil {
			return built{}, nil, fmt.Errorf("read the docker-save archive: %w", err)
		}
		return built{image: img}, func() {}, nil
	}
	tmp, err := os.MkdirTemp("", "k3sm-import")
	if err != nil {
		return built{}, nil, fmt.Errorf("create a staging directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }
	dir := filepath.Join(tmp, "layout")
	if err := extractOCILayout(archive, dir); err != nil {
		cleanup()
		return built{}, nil, err
	}
	idx, err := layoutIndex(dir)
	if err != nil {
		cleanup()
		return built{}, nil, fmt.Errorf("read the layout: %w", err)
	}
	if idx != nil {
		return built{index: idx}, cleanup, nil
	}
	img, err := layoutImage(dir)
	if err != nil {
		cleanup()
		return built{}, nil, err
	}
	return built{image: img}, cleanup, nil
}

// pastTense renders the ingest subcommand for the result line.
func pastTense(subcommand string) string {
	if subcommand == "import" {
		return "imported"
	}
	return "loaded"
}

// inspectArchive reads the format's metadata document out of the tar stream
// and returns the reference the archive names for itself.
//
// It reads the metadata for exactly two reasons: to derive the reference the
// archive names for itself, and to refuse the archives that cannot be recorded
// faithfully under one reference. It never turns an entry name into a
// filesystem path.
func inspectArchive(r io.Reader, format runtimev1.LoadImageFormat) (string, error) {
	want, err := metadataName(format)
	if err != nil {
		return "", err
	}
	var doc []byte
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read as a tar archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || archiveEntryName(hdr.Name) != want {
			continue
		}
		if doc != nil {
			return "", fmt.Errorf("contains two %s entries", want)
		}
		doc, err = io.ReadAll(io.LimitReader(tr, archiveMetadataLimit+1))
		if err != nil {
			return "", fmt.Errorf("read %s: %w", want, err)
		}
		if len(doc) > archiveMetadataLimit {
			return "", fmt.Errorf("%s exceeds the %d-byte limit", want, archiveMetadataLimit)
		}
	}
	if doc == nil {
		return "", wrongFormatError(format, want)
	}
	return referenceFromMetadata(doc, format)
}

// metadataName is the entry each format records its image metadata in.
func metadataName(format runtimev1.LoadImageFormat) (string, error) {
	switch format {
	case runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_DOCKER_SAVE:
		return "manifest.json", nil
	case runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_OCI_LAYOUT:
		return "index.json", nil
	}
	// The CLI never asks the daemon to sniff: each subcommand IS the format
	// declaration, so an unset format here is a programming error, not input.
	return "", fmt.Errorf("no archive format was declared")
}

// archiveEntryName normalizes a tar entry name for comparison only — the result
// is never opened, joined, or created.
func archiveEntryName(name string) string {
	return strings.TrimPrefix(path.Clean(name), "./")
}

// wrongFormatError names the verb that would have worked. Handing a docker-save
// tar to `import` is the single most likely operator mistake here, and "no
// index.json" would leave them to guess.
func wrongFormatError(format runtimev1.LoadImageFormat, want string) error {
	if format == runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_OCI_LAYOUT {
		return fmt.Errorf("no %s: this is not an OCI layout; a docker-save tar loads with `k3sm image load`", want)
	}
	return fmt.Errorf("no %s: this is not a docker-save tar; an OCI layout loads with `k3sm image import`", want)
}

// dockerSaveEntry is the subset of a docker-save manifest.json entry this CLI
// reads. The daemon parses the archive properly; this side only needs the tags.
type dockerSaveEntry struct {
	RepoTags []string `json:"RepoTags"`
}

// ociIndex is the subset of an OCI layout index.json this CLI reads.
type ociIndex struct {
	Manifests []struct {
		Annotations map[string]string `json:"annotations"`
	} `json:"manifests"`
}

// referenceFromMetadata derives the reference the archive names for itself, and
// refuses the multi-image and multi-tag archives v1 cannot record faithfully.
//
// REFUSAL, NOT NARROWING: a load records ONE reference, so an archive
// carrying several would have to lose all but one. Silently dropping a tag the
// operator explicitly saved is worse than failing — they would find out when a
// Pod spec did not resolve, with nothing to connect it to the load.
func referenceFromMetadata(doc []byte, format runtimev1.LoadImageFormat) (string, error) {
	if format == runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_OCI_LAYOUT {
		var index ociIndex
		if err := json.Unmarshal(doc, &index); err != nil {
			return "", fmt.Errorf("parse index.json: %w", err)
		}
		switch len(index.Manifests) {
		case 0:
			return "", errors.New("the layout indexes no image")
		case 1:
		default:
			return "", fmt.Errorf("the layout indexes %d images; k3sm imports one image per archive",
				len(index.Manifests))
		}
		return index.Manifests[0].Annotations[ociRefNameAnnotation], nil
	}

	var entries []dockerSaveEntry
	if err := json.Unmarshal(doc, &entries); err != nil {
		return "", fmt.Errorf("parse manifest.json: %w", err)
	}
	switch len(entries) {
	case 0:
		return "", errors.New("the archive contains no image")
	case 1:
	default:
		return "", fmt.Errorf("the archive contains %d images; k3sm loads one image per archive", len(entries))
	}
	tags := entries[0].RepoTags
	if len(tags) > 1 {
		return "", fmt.Errorf("the archive tags one image with more than one tag (%s); re-save it with a single tag",
			strings.Join(tags, ", "))
	}
	if len(tags) == 0 {
		return "", nil
	}
	return tags[0], nil
}
