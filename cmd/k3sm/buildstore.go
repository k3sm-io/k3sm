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
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
	runtimed "k3sm.io/runtimed/pkg/runtime"

	"k3sm.io/k3sm/pkg/oci"
)

// storeRecorder records a freshly built image in THIS node's image store under
// ref. It is a seam so the sink matrix — store always, artifact when asked — is
// provable without a running daemon.
type storeRecorder func(ctx context.Context, ref name.Tag, img ggcrv1.Image) error

// deliver puts a built image where the operator can use it: recorded in this
// node's image store under --tag, and — when --output was given — ADDITIONALLY
// written as a portable artifact.
//
// The store is the DEFAULT terminal state for both build paths, so `k3sm build
// -t app:dev .` is followed by naming app:dev in a Pod, with nothing in between
// and no difference between a COPY-only build and one that RUNs commands. The
// artifact keeps its old meaning exactly: a file you can carry to another node.
//
// The artifact is written FIRST. It is local and cheap, so a bad --output path
// fails before a multi-gigabyte stream is sent to the daemon; and if the store
// leg then fails, the operator holds a file `k3sm image load` can finish with.
func deliver(ctx context.Context, o buildOptions, ref name.Tag, img ggcrv1.Image, out io.Writer, record storeRecorder, engineEndpoint, enginePlatform string) error {
	if o.output != "" {
		var sink oci.Sink = oci.TarballSink{Path: o.output}
		if o.format == "oci" {
			sink = oci.LayoutSink{Path: o.output}
		}
		if err := sink.Write(ctx, ref, img); err != nil {
			return err
		}
	}
	if err := record(ctx, ref, img); err != nil {
		return err
	}

	digest, err := img.Digest()
	if err != nil {
		return fmt.Errorf("compute digest: %w", err)
	}
	fmt.Fprintf(out, "built %s\n  digest: %s\n  store:  recorded in this node's image store (kubectl run app --image=%s)\n", ref, digest, ref)
	if o.output != "" {
		fmt.Fprintf(out, "  output: %s (%s)\n", o.output, o.format)
	}
	if engineEndpoint != "" {
		fmt.Fprintf(out, "  engine: %s (%s)\n", engineEndpoint, enginePlatform)
	}
	return nil
}

// recordInStore is the production storeRecorder: it hands the image to the
// daemon over the SAME ingest RPC `k3sm image load` uses.
//
// THE DAEMON IS THE SOLE STORE WRITER (see imageLoad): this writes no blob and
// records no reference itself. It stages a docker-save tarball in a temp dir
// because the ingest is a byte stream with a format, not an in-memory handoff —
// and the staging dir is removed whether the stream succeeds or not.
//
// The ingest's own rendering is discarded: it names the temp archive, which is
// an implementation detail of this path rather than anything the operator asked
// for. deliver prints the store line instead.
func recordInStore(ctx context.Context, ref name.Tag, img ggcrv1.Image) error {
	tmp, err := os.MkdirTemp("", "k3sm-build-store-")
	if err != nil {
		return fmt.Errorf("create staging dir: %w", err)
	}
	defer os.RemoveAll(tmp)
	archive := filepath.Join(tmp, "image.tar")
	if err := (oci.TarballSink{Path: archive}).Write(ctx, ref, img); err != nil {
		return fmt.Errorf("stage %s for the image store: %w", ref, err)
	}

	ctx, cancel := context.WithTimeout(ctx, streamingTimeout)
	defer cancel()

	socket := runtimed.DefaultSocketPath
	cc, closer, err := dialRuntimed(ctx, socket)
	if err != nil {
		return fmt.Errorf("record %s in this node's image store: %w", ref, err)
	}
	if closer != nil {
		defer closer.Close()
	}
	o := imageOptions{subcommand: "load", socket: socket, archive: archive, reference: ref.String()}
	if err := imageLoad(ctx, runtimev1.NewImagesClient(cc), o, io.Discard, runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_DOCKER_SAVE); err != nil {
		return fmt.Errorf("record %s in this node's image store: %w", ref, err)
	}
	return nil
}
