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
	"os"
	"path/filepath"

	"google.golang.org/grpc/codes"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// errSaveTruncated is the verdict a caller acts on differently from every other
// export failure: bytes arrived, but the archive is not the whole image. It is a
// sentinel because "the export failed" and "the export is incomplete" call for
// the same retry but for very different trust in what is already on disk.
var errSaveTruncated = errors.New("the archive arrived truncated")

// imageSave streams one image out of the store as a tarred OCI image layout —
// the `docker save` analog and the exact inverse of load/import.
//
// THE CLIENT IS THE SOLE WRITER OF THE OPERATOR'S FILE, the mirror of the rule
// that the daemon is the sole writer of the store: the daemon runs as its own
// unprivileged uid, generally cannot write into an operator's home, and must not
// try. So the bytes come back over the stream and this side puts them on disk.
func imageSave(ctx context.Context, client runtimev1.ImagesClient, o imageOptions, out io.Writer) error {
	reference, digest := imageTarget(o.source)
	req := &runtimev1.SaveImageRequest{
		Reference: reference,
		Platform:  o.platform,
		Digest:    digest,
		Format:    runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_OCI_LAYOUT,
	}
	saved, err := saveImageArchive(ctx, client, req, o.output, o.socket)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "saved %s (%s)\n", o.output, humanBytes(uint64(saved.bytes)))
	fmt.Fprintf(out, "  digest: %s\n", saved.digest)
	return nil
}

// savedArchive is what a completed export is known to be: the manifest digest
// the daemon says it exported, and the byte count both sides agreed on.
type savedArchive struct {
	digest string
	bytes  int64
}

// saveImageArchive streams a SaveImage export into path and verifies it.
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
