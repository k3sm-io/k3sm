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
	"strings"

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

// built is what a build produced, and what delivery moves.
//
// The two image fields are not alternatives to choose between at every call
// site: image is ALWAYS the single image this node's store records and a Pod
// here can run, and index is additionally set when the build targeted several
// platforms at once — the shape --output and --push carry, and the one the store
// cannot hold. A single-platform build leaves index nil, so every existing path
// reads exactly as it did.
type built struct {
	// image is the one image the store records: the sole image of a
	// single-platform build, or the child of a multi-platform index whose
	// platform this node's runtime runs (selectStoreImage picks it).
	image ggcrv1.Image
	// index is the multi-platform index, or nil for a single-platform build.
	index ggcrv1.ImageIndex
	// platforms is what the build targeted, in the order the operator asked for.
	platforms []string
	// storePlatform is image's platform — the one the summary reports when the
	// build produced more than one.
	storePlatform string
}

// digest is the digest of what was built: the index for a multi-platform build,
// which is the reference a caller pins and the manifest a registry serves, and
// the image itself otherwise.
func (b built) digest() (ggcrv1.Hash, error) {
	if b.index != nil {
		return b.index.Digest()
	}
	return b.image.Digest()
}

// deliver puts a built image where the operator can use it: recorded in this
// node's image store under --tag, and — when they were given — ADDITIONALLY
// written as a portable artifact (--output) and uploaded to a registry (--push).
//
// The store is the DEFAULT terminal state for both build paths, so `k3sm build
// -t app:dev .` is followed by naming app:dev in a Pod, with nothing in between
// and no difference between a COPY-only build and one that RUNs commands. The
// artifact keeps its old meaning exactly: a file you can carry to another node.
// --push is a THIRD sink, not a replacement for the store: unlike `docker build
// --push`, the recording still happens, because a k3sm build's product is an
// image this node can run.
//
// THE ORDER IS ARTIFACT, STORE, PUSH, and each step earns its place. The
// artifact is local and cheap, so a bad --output path fails before a
// multi-gigabyte stream is sent to the daemon, and if the store leg then fails
// the operator holds a file `k3sm image load` can finish with. The push is LAST
// because it is the only step that can fail for a reason outside this Mac — a
// refused credential, an unreachable host — and a failure there must not cost
// the operator the build.
func deliver(ctx context.Context, o buildOptions, ref name.Tag, b built, out io.Writer, record storeRecorder, push imagePusher, engineEndpoint, enginePlatform string) error {
	if o.output != "" {
		// A multi-platform build writes the whole INDEX, which only the layout
		// format can hold — a docker-save tarball carries one image, which is why
		// --format docker is refused for such a build at parse time rather than
		// silently narrowed to one platform here.
		if b.index != nil {
			if err := (oci.LayoutSink{Path: o.output}).WriteIndex(ctx, ref, b.index); err != nil {
				return err
			}
		} else {
			var sink oci.Sink = oci.TarballSink{Path: o.output}
			if o.format == "oci" {
				sink = oci.LayoutSink{Path: o.output}
			}
			if err := sink.Write(ctx, ref, b.image); err != nil {
				return err
			}
		}
	}
	if err := record(ctx, ref, b.image); err != nil {
		return err
	}

	// The upload comes after the recording, so a target this node cannot reach
	// costs the operator an error message rather than the build. The reference it
	// landed under is returned rather than re-derived for the summary: a printed
	// target that was computed twice can disagree with the one that was pushed to.
	var target name.Tag
	if o.push {
		pushed, err := pushDelivered(ctx, o, ref, b, push)
		if err != nil {
			return err
		}
		target = pushed
	}

	digest, err := b.digest()
	if err != nil {
		return fmt.Errorf("compute digest: %w", err)
	}
	fmt.Fprintf(out, "built %s\n  digest: %s\n  store:  recorded in this node's image store (kubectl run app --image=%s)\n", ref, digest, ref)
	// The platform line appears only for a build that produced more than one,
	// where "which of these is in the store" is a question the operator now has.
	// A single-platform build's platform is the one they asked for, or the one
	// path's only target, so printing it would be noise.
	if len(b.platforms) > 1 {
		fmt.Fprintf(out, "  built:  %s (the store recorded %s)\n", strings.Join(b.platforms, ", "), b.storePlatform)
	}
	if o.output != "" {
		fmt.Fprintf(out, "  output: %s (%s)\n", o.output, o.format)
	}
	if o.push {
		fmt.Fprintf(out, "  push:   %s\n", target)
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
