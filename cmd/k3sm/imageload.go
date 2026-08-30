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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"google.golang.org/grpc/codes"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

const (
	// loadChunkBytes is the payload of one stream frame. gRPC servers default to
	// a 4 MiB receive limit, so a 1 MiB chunk leaves ample headroom for framing
	// while keeping per-frame overhead negligible across a multi-GB archive.
	loadChunkBytes = 1 << 20

	// archiveMetadataLimit caps the metadata document (manifest.json /
	// index.json) the CLI parses out of the archive. This is operator-supplied,
	// potentially untrusted input, so it is never read into memory unbounded.
	archiveMetadataLimit = 4 << 20

	// ociRefNameAnnotation is the OCI layout annotation carrying an image's
	// reference — what `k3sm build --format oci` and `docker buildx -o type=oci`
	// both record, and what `import` derives its reference from.
	ociRefNameAnnotation = "org.opencontainers.image.ref.name"
)

// archiveMeta is what the CLI reads out of the operator's archive before it
// streams a single byte: the reference the archive names for itself, plus the
// advisory digest and size the first frame carries.
//
// The digest is ADVISORY on the wire and this side must not pretend otherwise:
// the daemon re-hashes every byte it receives and rejects a mismatch before its
// lease commits. Sending it buys the daemon an early reject, nothing more.
type archiveMeta struct {
	reference string
	digest    string
	size      int64
}

// imageLoad streams an operator's archive to the daemon's LoadImage RPC and
// renders what the daemon recorded.
//
// THE DAEMON IS THE SOLE STORE WRITER. This command opens the archive — the
// daemon runs as its own unprivileged uid and generally cannot read an
// operator's home — and does nothing else with it but hash it and put its bytes
// on the wire. It writes no blob, takes no lease, and records no reference.
func imageLoad(ctx context.Context, client runtimev1.ImagesClient, o imageOptions, out io.Writer, format runtimev1.LoadImageFormat) error {
	what := o.subcommand + " image"
	f, err := os.Open(o.archive)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer f.Close()

	meta, err := inspectArchive(f, format)
	if err != nil {
		return fmt.Errorf("%s: %w", o.archive, err)
	}
	reference := o.reference
	if reference == "" {
		reference = meta.reference
	}
	if reference == "" {
		return fmt.Errorf("%s: the archive records no reference; pass --reference <name:tag>", o.archive)
	}
	// The inspection pass consumed the file; the stream must start from byte 0
	// or the daemon would hash a suffix of what the first frame described.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind %s: %w", o.archive, err)
	}

	stream, err := client.LoadImage(ctx)
	if err != nil {
		return imageRPCError(what, o.socket, err)
	}

	// A Send on a client-streaming RPC reports io.EOF once the SERVER has ended
	// the call; the real status is only available from CloseAndRecv. Reporting
	// that io.EOF as the failure would hide the daemon's actual reason, so a
	// short send stops the loop and lets CloseAndRecv speak.
	done := false
	if err := stream.Send(&runtimev1.LoadImageRequest{
		Reference: reference,
		Format:    format,
		Digest:    meta.digest,
		Size:      meta.size,
	}); err != nil {
		if !errors.Is(err, io.EOF) {
			return imageRPCError(what, o.socket, err)
		}
		done = true
	}
	buf := make([]byte, loadChunkBytes)
	for !done {
		n, rerr := f.Read(buf)
		if n > 0 {
			if err := stream.Send(&runtimev1.LoadImageRequest{Chunk: buf[:n]}); err != nil {
				if !errors.Is(err, io.EOF) {
					return imageRPCError(what, o.socket, err)
				}
				break
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			return fmt.Errorf("read %s: %w", o.archive, rerr)
		}
	}

	resp, err := stream.CloseAndRecv()
	if err != nil {
		return imageRPCError(what, o.socket, err)
	}
	// The RPC can fail two ways — a transport status, and a typed in-band Status
	// on the terminal response. Both mean nothing was committed, so both have to
	// exit non-zero; only checking the first would report a rejected ingest as a
	// success.
	if st := resp.GetError(); st != nil && st.GetCode() != int32(codes.OK) {
		return fmt.Errorf("%s: the daemon rejected the archive: %s", what, st.GetMessage())
	}

	received := resp.GetReceivedBytes()
	if received < 0 {
		received = 0
	}
	fmt.Fprintf(out, "%s %s (%s)\n", pastTense(o.subcommand), o.archive, humanBytes(uint64(received)))
	if len(resp.GetImages()) == 0 {
		fmt.Fprintf(out, "%-48s %s\n", reference, "(the daemon reported no image)")
		return nil
	}
	for _, img := range resp.GetImages() {
		name := img.GetManifest().GetReference()
		if name == "" {
			name = reference
		}
		fmt.Fprintf(out, "%-48s %s\n", name, img.GetManifestDescriptor().GetDigest())
	}
	return nil
}

// pastTense renders the ingest subcommand for the result line.
func pastTense(subcommand string) string {
	if subcommand == "import" {
		return "imported"
	}
	return "loaded"
}

// inspectArchive reads the archive ONCE, hashing every byte while it pulls the
// format's metadata document out of the tar stream. One pass rather than two,
// because the alternative is reading a multi-GB file twice before a byte is sent.
//
// It reads the metadata for exactly two reasons: to derive the reference the
// archive names for itself, and to refuse the archives v1 cannot represent
// faithfully. It never turns an entry name into a filesystem path — nothing here
// extracts anything, which is what makes tar path traversal, symlink escape, and
// hardlink aliasing non-questions on this path rather than three defenses.
func inspectArchive(r io.Reader, format runtimev1.LoadImageFormat) (archiveMeta, error) {
	want, err := metadataName(format)
	if err != nil {
		return archiveMeta{}, err
	}
	h := sha256.New()
	counter := &countingWriter{}
	tee := io.TeeReader(r, io.MultiWriter(h, counter))

	var doc []byte
	tr := tar.NewReader(tee)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return archiveMeta{}, fmt.Errorf("read as a tar archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || archiveEntryName(hdr.Name) != want {
			continue
		}
		if doc != nil {
			return archiveMeta{}, fmt.Errorf("contains two %s entries", want)
		}
		doc, err = io.ReadAll(io.LimitReader(tr, archiveMetadataLimit+1))
		if err != nil {
			return archiveMeta{}, fmt.Errorf("read %s: %w", want, err)
		}
		if len(doc) > archiveMetadataLimit {
			return archiveMeta{}, fmt.Errorf("%s exceeds the %d-byte limit", want, archiveMetadataLimit)
		}
	}
	// tar stops at the end-of-archive marker, so anything after it is unread.
	// The daemon hashes the WHOLE file, so this side must too, or the advisory
	// digest would describe a prefix and every padded archive would look wrong.
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return archiveMeta{}, fmt.Errorf("read to end: %w", err)
	}
	if doc == nil {
		return archiveMeta{}, wrongFormatError(format, want)
	}

	reference, err := referenceFromMetadata(doc, format)
	if err != nil {
		return archiveMeta{}, err
	}
	return archiveMeta{
		reference: reference,
		digest:    "sha256:" + hex.EncodeToString(h.Sum(nil)),
		size:      counter.n,
	}, nil
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
// REFUSAL, NOT NARROWING: LoadImage records ONE reference, so an archive
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

// countingWriter counts the bytes written through it. It exists so the archive's
// size is the number of bytes actually hashed rather than a separate os.Stat,
// which would report a different file if the archive were replaced mid-read.
type countingWriter struct{ n int64 }

// Write implements io.Writer.
func (c *countingWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}
