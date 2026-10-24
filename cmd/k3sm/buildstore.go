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
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
	runtimed "k3sm.io/runtimed/pkg/runtime"

	"k3sm.io/k3sm/pkg/oci"
)

// storeRecorder records what a build produced in the cluster's image store,
// the server's registry, under ref: the build's tag already normalised to the
// registry's own name (registryReference). It is a seam so the sink matrix
// (store always, artifact when asked) is provable without a registry or a
// running daemon.
type storeRecorder func(ctx context.Context, ref name.Tag, b built) error

// cacheWarmer pulls ref into this node's image cache through the runtime's
// ordinary pull path. A seam so the warm step is provable without a daemon.
type cacheWarmer func(ctx context.Context, ref name.Tag) error

// built is what a build produced, and what delivery moves.
//
// image is always the single image this node runs: the sole image of a
// single-platform build, or the child of a multi-platform index whose platform
// this node's runtime runs. index is additionally set when the build targeted
// several platforms at once; the registry records the whole index, and the
// node's cache warms the child for its own platform. A single-platform build
// leaves index nil.
type built struct {
	// image is the image this node runs (selectStoreImage picks it from an
	// index).
	image ggcrv1.Image
	// index is the multi-platform index, or nil for a single-platform build.
	index ggcrv1.ImageIndex
	// platforms is what the build targeted, in the order the operator asked for.
	platforms []string
	// storePlatform is image's platform, the one this node's cache holds and the
	// summary reports when the build produced more than one.
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

// deliver puts a built image where the operator can use it: recorded in the
// cluster registry under the normalised registry-k3sm:6450 name or, for a tag
// naming another registry, pushed there (--push), and, when it was given,
// ADDITIONALLY written as a portable artifact (--output).
//
// The registry is the DEFAULT terminal state for both build paths, so `k3sm
// build -t app:dev .` is followed by naming registry-k3sm:6450/app:dev in a
// Pod, with nothing in between. Recording also warms this node's cache through
// the runtime's ordinary pull, so a Pod here with imagePullPolicy Never finds
// the image too. The node's own store is a pull cache: no build writes it
// directly.
//
// THE ORDER IS ARTIFACT, THEN THE UPLOAD. The artifact is local and cheap, so
// a bad --output path fails before anything is uploaded, and if the upload then
// fails the operator holds a file `k3sm image load` can finish with. The upload
// is the recording for a tag naming the cluster registry and the push for a tag
// naming another one; a build never does both.
//
// --no-record drops the recording and nothing else: artifact, then push, and
// the summary says the image was not recorded and how to load it.
//
// A tag naming a registry other than the cluster registry is never recorded:
// with --push the image goes to that registry only, and without it the build
// is refused (parseBuildArgs refuses it before any work; this is the same rule
// for a caller that did not parse).
func deliver(ctx context.Context, o buildOptions, ref name.Tag, b built, out io.Writer, record storeRecorder, push imagePusher, engineEndpoint, enginePlatform string) error {
	workDir := workDirFromEnv()
	foreign := tagIsForeign(o.tag, workDir)
	if foreign && !o.push && !o.noRecord {
		// registryReference renders the refusal, naming both ways forward.
		_, err := registryReference(o.tag, workDir)
		return err
	}
	recordIt := !o.noRecord && !foreign
	var recorded name.Tag
	if recordIt {
		r, err := registryReference(o.tag, workDir)
		if err != nil {
			return err
		}
		recorded = r
	}
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
	// --no-record ends the build at the artifact and the upload: neither the
	// registry nor the runtime daemon is contacted for the recording. Nor are
	// they for a foreign tag, which --push alone delivers.
	if recordIt {
		if err := record(ctx, recorded, b); err != nil {
			return err
		}
	}

	// A tag that names the cluster registry was uploaded by the recording
	// itself, so --push sends nothing a second time. Anything else, a foreign tag
	// or a --no-record build, is uploaded here, LAST, after the artifact. The
	// reference it landed under is returned rather than re-derived for the
	// summary: a printed target that was computed twice can disagree with the one
	// that was pushed to.
	var target name.Tag
	if o.push {
		if recordIt {
			target = recorded
		} else {
			pushed, err := pushDelivered(ctx, o, ref, b, push)
			if err != nil {
				return err
			}
			target = pushed
		}
	}

	digest, err := b.digest()
	if err != nil {
		return fmt.Errorf("compute digest: %w", err)
	}
	// Deliberately NOT suggesting `kubectl run` here. It cannot set the darwin
	// nodeSelector or the provider toleration, so the Pod it creates is refused
	// at admission — printing it on every successful build sent the operator
	// straight into a failure.
	fmt.Fprintf(out, "built %s\n  digest: %s\n", ref, digest)
	switch {
	case o.noRecord:
		fmt.Fprintf(out, "  store:  not recorded (--no-record); to record it in the cluster registry: %s\n", noRecordLoadHint(o))
	case foreign:
		fmt.Fprintf(out, "  store:  not recorded in the cluster registry (the tag names another registry; --push sent it there)\n")
	default:
		fmt.Fprintf(out, "  store:  recorded in the cluster registry as %s (name it in a Pod manifest)\n", recorded)
	}
	// The platform line appears only for a build that produced more than one,
	// where "which of these does this node run" is a question the operator now
	// has. The registry holds every platform; this node's cache holds its own.
	if len(b.platforms) > 1 && !recordIt {
		fmt.Fprintf(out, "  built:  %s\n", strings.Join(b.platforms, ", "))
	} else if len(b.platforms) > 1 {
		fmt.Fprintf(out, "  built:  %s (this node's cache holds %s)\n", strings.Join(b.platforms, ", "), b.storePlatform)
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

// noRecordLoadHint names the separate root step that records a --no-record build in
// the cluster registry. A docker-save tarball loads as written; an OCI layout
// directory is tarred first and imported, because `k3sm image import` takes the
// tarred layout. A push-only build wrote no artifact, so the hint names the flag
// that would.
func noRecordLoadHint(o buildOptions) string {
	switch {
	case o.output == "":
		return "write an artifact with --output, then sudo k3sm image load (docker) or sudo k3sm image import (a tarred oci layout)"
	case o.format == "oci":
		return fmt.Sprintf("tar -cf %[1]s.tar -C %[1]s . && sudo k3sm image import %[1]s.tar", o.output)
	default:
		return "sudo k3sm image load " + o.output
	}
}

// refuseRecord is the storeRecorder of a --no-record build. deliver never calls
// it; it exists so that a path that did would fail without contacting the
// registry.
func refuseRecord(_ context.Context, ref name.Tag, _ built) error {
	return fmt.Errorf("record %s: this is a --no-record build, which never records in the cluster registry", ref)
}

// recordInRegistry is the production storeRecorder: it uploads what was built
// to the cluster registry through push, the same upload path `k3sm image push`
// uses, and then warms this node's cache through warm. The control-plane state
// root is resolved the way every other registry-aware verb resolves it, so the
// recording finds exactly the push credential `k3sm image push` would.
func recordInRegistry(push imagePusher, warm cacheWarmer) storeRecorder {
	return func(ctx context.Context, ref name.Tag, b built) error {
		return recordInto(ctx, ref, b, workDirFromEnv(), push, warm)
	}
}

// recordInto uploads b to the cluster registry under ref and warms this node's
// cache with it. It is the one recording path: build, load and import all
// reach it.
//
// The upload goes to this server's registry on loopback, which is the same
// registry the flat registry-k3sm:6450 name serves: this Mac does not resolve
// that name, and does not need to. The warm pull names the flat reference,
// which the runtime maps to the same registry.
func recordInto(ctx context.Context, ref name.Tag, b built, workDir string, push imagePusher, warm cacheWarmer) error {
	target, dest, err := registryPushTarget(ctx, ref, workDir)
	if err != nil {
		return fmt.Errorf("record %s in the cluster registry: %w", ref, err)
	}
	if err := push(ctx, target, b, dest); err != nil {
		return fmt.Errorf("record %s in the cluster registry: %w", ref, err)
	}
	// A failed warm leaves the image in the registry, where every Pod that may
	// pull finds it; only imagePullPolicy Never on this node would miss it. The
	// error says so, so the operator retries the pull, not the build.
	if err := warm(ctx, ref); err != nil {
		return fmt.Errorf("image %s is in the cluster registry; warming this node's cache failed (retry with k3sm image pull %s): %w", ref, ref, err)
	}
	return nil
}

// warmNodeCache is the production cacheWarmer: it asks this node's runtime to
// pull ref through its own puller, the path a Pod-driven pull takes, with the
// Always policy so a tag this command just overwrote is fetched again.
func warmNodeCache(dial imagesDialer, socket string) cacheWarmer {
	return func(ctx context.Context, ref name.Tag) error {
		cc, closer, err := dial(ctx, socket)
		if err != nil {
			return err
		}
		if closer != nil {
			defer closer.Close()
		}
		o := imageOptions{subcommand: "pull", socket: socket, source: ref.String(), policy: runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_ALWAYS}
		return imagePull(ctx, runtimev1.NewImagesClient(cc), o, io.Discard)
	}
}

// defaultCacheWarmer warms through the default runtimed socket.
func defaultCacheWarmer() cacheWarmer {
	return warmNodeCache(dialRuntimed, runtimed.DefaultSocketPath)
}
