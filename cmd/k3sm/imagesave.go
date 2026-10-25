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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"google.golang.org/grpc/codes"

	runtimev1 "k3sm.io/apis/runtime/v1"

	"k3sm.io/k3sm/pkg/oci"
)

// errSaveTruncated is the verdict a caller acts on differently from every other
// export failure: bytes arrived, but the archive is not the whole image. It is a
// sentinel because "the export failed" and "the export is incomplete" call for
// the same retry but for very different trust in what is already on disk.
var errSaveTruncated = errors.New("the archive arrived truncated")

// imageSave exports one image from the cluster registry as a tarred OCI image
// layout, the `docker save` analog and the exact inverse of import.
//
// An index is saved whole, every platform in one layout, unless --platform
// selects one. The layout records the cluster-registry name in its ref.name
// annotation, so `k3sm image import` of the archive records it under the same
// name.
//
// The archive is staged beside the target and renamed into place only once it
// is complete, so a failed save leaves NO file at the target: not a partial
// one, and not a previously-good one replaced by a partial one.
func imageSave(ctx context.Context, o imageOptions, out io.Writer) error {
	c, err := resolveClusterImage(o.source, o.workDir)
	if err != nil {
		return err
	}
	acc, err := registryReadAccess(ctx, o.workDir)
	if err != nil {
		return err
	}
	if c, err = acc.locate(c); err != nil {
		return err
	}
	desc, _, err := getClusterImage(c, o.platform, acc)
	if err != nil {
		return err
	}
	stage, err := os.MkdirTemp("", "k3sm-save")
	if err != nil {
		return fmt.Errorf("create a staging directory: %w", err)
	}
	defer os.RemoveAll(stage)
	dir := filepath.Join(stage, "layout")
	sink := oci.LayoutSink{Path: dir}
	if desc.MediaType.IsIndex() {
		idx, err := desc.ImageIndex()
		if err != nil {
			return fmt.Errorf("read the index %s: %w", c.flat, err)
		}
		err = sink.WriteIndex(ctx, c.flat, idx)
		if err != nil {
			return registryError("save "+c.flat.String(), err)
		}
	} else {
		img, err := desc.Image()
		if err != nil {
			return fmt.Errorf("read the image %s: %w", c.flat, err)
		}
		if err := sink.Write(ctx, c.flat, img); err != nil {
			return registryError("save "+c.flat.String(), err)
		}
	}
	n, err := writeArchiveOf(dir, o.output)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "saved %s (%s)\n", o.output, humanBytes(uint64(n)))
	fmt.Fprintf(out, "  digest: %s\n", desc.Digest)
	return nil
}

// writeArchiveOf tars the layout directory dir into path, through a sibling
// temp file renamed into place only when the tar is complete, and returns the
// archive's size.
func writeArchiveOf(dir, path string) (int64, error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".k3sm-save-*.tar")
	if err != nil {
		return 0, fmt.Errorf("create the archive in %s: %w", filepath.Dir(path), err)
	}
	staged := tmp.Name()
	committed := false
	defer func() {
		tmp.Close()
		if !committed {
			_ = os.Remove(staged)
		}
	}()
	tw := tar.NewWriter(tmp)
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil || rel == "." {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if d.IsDir() {
			hdr.Name += "/"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
	if err == nil {
		err = tw.Close()
	}
	if err != nil {
		return 0, fmt.Errorf("write the archive: %w", err)
	}
	info, err := tmp.Stat()
	if err != nil {
		return 0, fmt.Errorf("write the archive: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return 0, fmt.Errorf("write the archive: %w", err)
	}
	if err := os.Rename(staged, path); err != nil {
		return 0, fmt.Errorf("move the archive into place at %s: %w", path, err)
	}
	committed = true
	return info.Size(), nil
}

// savedArchive is what a completed export is known to be: the manifest digest
// the daemon says it exported, and the byte count both sides agreed on.
type savedArchive struct {
	digest string
	bytes  int64
}

// saveImageArchive streams a SaveImage export from this node's store into path
// and verifies it. `k3sm image push` uses it for a source named in the store.
//
// TRUNCATION IS THE FAILURE THIS FUNCTION EXISTS TO CATCH. The wire's framing
// makes it detectable and nothing else does: the server sends chunk frames and
// then exactly ONE terminal frame carrying the exported digest and the byte
// count it sent, so a stream that ends without that frame is a short archive
// that is otherwise indistinguishable from a complete one. Both checks are made
// — the terminal frame must arrive, and the bytes written must equal the count
// it reports.
//
// The archive is staged in a sibling temp file and renamed only after both
// checks pass, so a failed export leaves NO file at path: not a truncated one,
// and not a previously-good one replaced by a truncated one.
func saveImageArchive(ctx context.Context, client runtimev1.ImagesClient, req *runtimev1.SaveImageRequest, path, socket string) (savedArchive, error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".k3sm-save-*.tar")
	if err != nil {
		return savedArchive{}, fmt.Errorf("create the archive in %s: %w", dir, err)
	}
	staged := tmp.Name()
	committed := false
	defer func() {
		tmp.Close()
		if !committed {
			// A partial export is deleted rather than left for someone to find:
			// a tar that is short by one layer still opens, and the first thing
			// that would notice is a pod that cannot start.
			_ = os.Remove(staged)
		}
	}()

	saved, err := streamSaveImage(ctx, client, req, tmp, socket)
	if err != nil {
		return savedArchive{}, err
	}
	if err := tmp.Close(); err != nil {
		return savedArchive{}, fmt.Errorf("write the archive: %w", err)
	}
	if err := os.Rename(staged, path); err != nil {
		return savedArchive{}, fmt.Errorf("move the archive into place at %s: %w", path, err)
	}
	committed = true
	return saved, nil
}

// streamSaveImage drains the export stream into w and returns what the terminal
// frame reported.
func streamSaveImage(ctx context.Context, client runtimev1.ImagesClient, req *runtimev1.SaveImageRequest, w io.Writer, socket string) (savedArchive, error) {
	//lint:ignore SA1019 push's node-store source form still exports through SaveImage
	stream, err := client.SaveImage(ctx, req)
	if err != nil {
		return savedArchive{}, imageRPCError("save image", socket, err)
	}
	var (
		written  int64
		terminal *runtimev1.SaveImageResponse
	)
	for {
		frame, rerr := stream.Recv()
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return savedArchive{}, imageRPCError("save image", socket, rerr)
		}
		// A mid-transfer failure arrives as a terminal frame carrying the status
		// AND as the RPC's own error, so a client never has to infer failure from
		// a stream that merely stopped. Reporting it from the frame gets the
		// daemon's reason out even when the RPC status is the transport's.
		if st := frame.GetError(); st != nil && st.GetCode() != int32(codes.OK) {
			return savedArchive{}, fmt.Errorf("save image: the daemon could not export it: %s", st.GetMessage())
		}
		if chunk := frame.GetChunk(); len(chunk) > 0 {
			if terminal != nil {
				return savedArchive{}, errors.New("save image: the daemon sent archive bytes after the terminal frame")
			}
			n, werr := w.Write(chunk)
			written += int64(n)
			if werr != nil {
				return savedArchive{}, fmt.Errorf("write the archive: %w", werr)
			}
			continue
		}
		if terminal != nil {
			return savedArchive{}, errors.New("save image: the daemon sent two terminal frames")
		}
		terminal = frame
	}
	if terminal == nil {
		return savedArchive{}, fmt.Errorf("save image: %w — the stream ended after %d byte(s) with no terminal frame, so the export did not finish",
			errSaveTruncated, written)
	}
	if terminal.GetSentBytes() != written {
		return savedArchive{}, fmt.Errorf("save image: %w — the daemon sent %d byte(s) and %d arrived",
			errSaveTruncated, terminal.GetSentBytes(), written)
	}
	if terminal.GetDigest() == "" {
		return savedArchive{}, errors.New("save image: the terminal frame reported no digest, so there is nothing to verify the archive against")
	}
	return savedArchive{digest: terminal.GetDigest(), bytes: written}, nil
}
