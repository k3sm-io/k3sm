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
	"log/slog"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"k3sm.io/runtimed/pkg/image"
)

// THE PUBLIC-IMAGE COPY. `k3sm image pull <public reference>` fills this node's
// cache and then copies the same image into the cluster registry under the name
// runtimed's PublicMirrorReference gives it, so a node that later cannot reach
// the public registry at all (a DNS failure, a refused or timed-out connection)
// pulls the cluster's copy instead. runtimed decides when the copy is read; this
// side only writes it, under the one name both sides take from that function.
//
// The copy is a convenience on top of a pull that already succeeded, so a copy
// that fails is a warning and the pull still exits 0. A reference that already
// names the cluster registry, and one whose registry carries a port, have no
// copy and get none, silently. --no-mirror skips the step.

// publicMirrorer copies the public image src into the cluster registry under
// mirror, the cluster-registry reference PublicMirrorReference named. It is a
// seam so the decision of whether and where to copy is provable without a
// registry, a kubeconfig or a network.
type publicMirrorer func(ctx context.Context, src, mirror name.Reference, workDir string) error

// pullMirrorer is the publicMirrorer `k3sm image pull` uses. A variable so the
// tests that exercise pull install a fake instead of reaching a cluster.
var pullMirrorer publicMirrorer = mirrorPublicImage

// mirrorPulled writes the cluster registry's copy of the reference o.source
// names, after the node's pull of it succeeded. It prints the copy's name to out
// when it was written and one warning to warn, naming the cause and the way
// forward, when it was not. It never fails the pull.
func mirrorPulled(ctx context.Context, o imageOptions, out, warn io.Writer, m publicMirrorer) {
	src, err := name.ParseReference(o.source)
	if err != nil {
		slog.Debug("the pulled reference does not parse, so it gets no copy in the cluster registry", "ref", o.source, "err", err)
		return
	}
	if isClusterRegistryHost(src.Context().RegistryStr(), o.workDir) {
		return
	}
	mirrorName, err := image.PublicMirrorReference(flatRegistryHost, o.source)
	if err != nil {
		slog.Debug("the pulled reference has no name in the cluster registry, so it gets no copy", "ref", o.source, "err", err)
		return
	}
	mirror, err := name.ParseReference(mirrorName)
	if err != nil {
		slog.Debug("the cluster registry's name for the pulled reference does not parse", "ref", o.source, "mirrorRef", mirrorName, "err", err)
		return
	}
	if err := m(ctx, src, mirror, o.workDir); err != nil {
		fmt.Fprintf(warn, "k3sm image pull: warning: %s is in this node's cache, but its copy in the cluster registry (%s) was not written: %v; fix that and pull again, or pass --no-mirror to skip the copy\n",
			o.source, mirrorName, err)
		return
	}
	fmt.Fprintf(out, "  mirror:   %s\n", mirrorName)
}

// mirrorPublicImage is the production publicMirrorer. It reads src from its own
// registry, the whole index when src names one, with the docker config chain's
// credential for that registry, and writes it to the cluster registry through
// the push gate with a builder token: the same write path `k3sm image push`
// takes to the cluster registry (imagePushTarget, pushImage, pushIndex).
func mirrorPublicImage(ctx context.Context, src, mirror name.Reference, workDir string) error {
	target, _, dest, err := imagePushTarget(ctx, mirror, workDir)
	if err != nil {
		return err
	}
	desc, err := remote.Get(src, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return fmt.Errorf("read %s from %s: %w", src, src.Context().RegistryStr(), err)
	}
	if desc.MediaType.IsIndex() {
		idx, err := desc.ImageIndex()
		if err != nil {
			return fmt.Errorf("read the index %s: %w", src, err)
		}
		return pushIndex(ctx, target, idx, dest)
	}
	img, err := desc.Image()
	if err != nil {
		return fmt.Errorf("read the image %s: %w", src, err)
	}
	return pushImage(ctx, target, img, dest)
}
