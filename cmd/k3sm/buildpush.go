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
	"net"
	"strconv"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"k3sm.io/k3sm/pkg/registrysvc"
)

// errNoNodeRegistry reports that `k3sm build --push` was given a BARE tag on a
// node whose ingest registry is not running, so there is no
// "localhost:<port>" for the image to go to.
//
// It is a sentinel, and the push is REFUSED rather than skipped, because the two
// silent alternatives are both worse than an error: pushing a bare tag to Docker
// Hub would publish a private image to the internet, and doing nothing would
// exit 0 on a command whose entire purpose was the upload.
var errNoNodeRegistry = errors.New("no cluster registry to push to")

// errForeignTag reports a tag that names a registry other than the cluster
// registry, on a verb that keeps the image in the cluster.
var errForeignTag = errors.New("the tag names a registry other than the cluster registry")

// imagePusher uploads what a build produced to a registry reference. It is a
// seam so the ORDER (the cluster registry first, any other registry second) and the
// wording of a failed upload are provable without a registry, a credential or a
// network.
type imagePusher func(ctx context.Context, ref name.Reference, b built, dest pushDest) error

// pushDest is how an upload reaches its registry: the cluster registry through
// the push gate with a builder token (cluster set), or any other registry
// through registryAuth's chain.
type pushDest struct {
	workDir string
	cluster *gateEndpoint
}

// options are the go-containerregistry options an upload of ref to d carries.
func (d pushDest) options(ctx context.Context, ref name.Reference) ([]remote.Option, error) {
	if d.cluster != nil {
		return d.cluster.options(ctx)
	}
	auth, err := registryAuth(ref, d.workDir)
	if err != nil {
		return nil, err
	}
	return []remote.Option{remote.WithContext(ctx), remote.WithAuth(auth)}, nil
}

// pushBuilt is the production imagePusher: it uploads a single-platform build
// through the same path `k3sm image push` uses, and a multi-platform build as
// the INDEX it is — every platform under one reference, which is what makes the
// pushed artifact indistinguishable from any other multi-arch image a puller
// selects from.
func pushBuilt(ctx context.Context, ref name.Reference, b built, dest pushDest) error {
	if b.index != nil {
		return pushIndex(ctx, ref, b.index, dest)
	}
	return pushImage(ctx, ref, b.image, dest)
}

// pushDelivered sends a built image to the registry --push names, and returns
// the reference it landed under.
//
// It runs only when the build recorded nothing: under --no-record, or for a
// tag naming another registry, which --push alone delivers. A tag naming the
// cluster registry was uploaded by the recording itself. So a failure here says
// where the image is left, at --output or nowhere, and that the build has to be
// pushed again rather than looked for in the cluster.
func pushDelivered(ctx context.Context, o buildOptions, ref name.Tag, b built, push imagePusher) (name.Tag, error) {
	// The control-plane state root is resolved the way every other
	// registry-aware verb in this binary resolves it, so `k3sm build --push`
	// finds this Mac's loopback gate exactly as `k3sm image push` would.
	workDir := workDirFromEnv()
	target, dest, err := resolvePushTarget(ctx, o.tag, workDir)
	if err != nil {
		return name.Tag{}, pushFailure(o, ref, err)
	}
	if err := push(ctx, target, b, dest); err != nil {
		return name.Tag{}, pushFailure(o, ref, err)
	}
	return target, nil
}

// pushFailure renders a push failure for a build that recorded nothing: the
// image is only at --output, if anywhere.
func pushFailure(o buildOptions, ref name.Tag, err error) error {
	why := "--no-record"
	if !o.noRecord {
		why = "the tag names another registry"
	}
	if o.output != "" {
		return fmt.Errorf("image %s was written to %s and not recorded (%s); push failed: %w", ref, o.output, why, err)
	}
	return fmt.Errorf("image %s was not recorded (%s) and has no --output; push failed: %w", ref, why, err)
}

// registryReference is the name the cluster registry records tag under:
// registry-k3sm:6450/<repository>:<tag>.
//
// A bare tag maps there, and so does a tag that already names the cluster
// registry by its flat name or by this node's loopback spelling (resolved from
// the push credential under workDir). A tag that names any
// other registry is refused with errForeignTag: the cluster registry records
// only names that are its own, so a Pod spec naming ghcr.io/... never resolves
// to a copy the cluster made behind the operator's back. --push is what sends
// such a tag to the registry it names (see deliver).
//
// The tag is parsed with an EMPTY default registry, so a bare repository gains
// no "library/" element: the image is recorded under the repository the
// operator wrote.
func registryReference(tag, workDir string) (name.Tag, error) {
	probe, err := name.NewTag(tag, name.WithDefaultRegistry(""))
	if err != nil {
		return name.Tag{}, fmt.Errorf("reference %q: %w", tag, err)
	}
	if !isClusterRegistryHost(probe.RegistryStr(), workDir) {
		return name.Tag{}, foreignTagError(tag, probe)
	}
	ref, err := name.NewTag(flatRegistryHost + "/" + probe.RepositoryStr() + ":" + probe.TagStr())
	if err != nil {
		return name.Tag{}, fmt.Errorf("record %q in the cluster registry: %w", tag, err)
	}
	return ref, nil
}

// foreignTagError renders the refusal of a tag naming another registry, with
// the two ways forward: the cluster spelling of the same repository, or
// --push, which sends the image to the registry the tag names.
func foreignTagError(tag string, probe name.Tag) error {
	return fmt.Errorf("%q: %w (%s); to keep it in the cluster, tag it %s; to send it to %s, add --push",
		tag, errForeignTag, probe.RegistryStr(), clusterSpelling(probe), probe.RegistryStr())
}

// clusterSpelling is the cluster-registry name of probe's repository and tag.
func clusterSpelling(probe name.Tag) string {
	return flatRegistryHost + "/" + probe.RepositoryStr() + ":" + probe.TagStr()
}

// isClusterRegistryHost reports whether reg, the registry part of a reference,
// names the cluster registry: no registry at all, the flat registry-k3sm:6450
// name, the loopback push gate (localhost:6451, or the port this Mac's server
// recorded for it), or this node's registry by its loopback spelling
// (localhost:<port> on the port the push credential under workDir was minted
// for). Any other loopback port is another registry on this Mac, and is
// foreign.
func isClusterRegistryHost(reg, workDir string) bool {
	if reg == "" || reg == flatRegistryHost {
		return true
	}
	gate := localGatePort(workDir)
	if gate == 0 {
		gate = defaultGatePort
	}
	for _, host := range []string{"localhost", registrysvc.LoopbackAddress} {
		if reg == net.JoinHostPort(host, strconv.Itoa(gate)) {
			return true
		}
	}
	cred, err := registrysvc.ReadCredential(workDir)
	return err == nil && cred.MatchesRegistry(reg)
}

// tagIsForeign reports whether tag names a registry other than the cluster
// registry. A tag that does not parse is not foreign; the caller's own parse
// reports it.
func tagIsForeign(tag, workDir string) bool {
	probe, err := name.NewTag(tag, name.WithDefaultRegistry(""))
	return err == nil && !isClusterRegistryHost(probe.RegistryStr(), workDir)
}

// registryPushTarget is where an upload of ref, a cluster-registry reference,
// is sent from this Mac, and how: the push gate resolveClusterRegistry finds
// (this server's loopback gate, or the server's cluster address from a
// worker), with a builder token. The Mac does not resolve registry-k3sm.
func registryPushTarget(ctx context.Context, ref name.Tag, workDir string) (name.Tag, pushDest, error) {
	cr, err := resolveClusterRegistry(ctx, workDir)
	if err != nil {
		return name.Tag{}, pushDest{}, err
	}
	target, err := name.NewTag(cr.authority + "/" + ref.RepositoryStr() + ":" + ref.TagStr())
	if err != nil {
		return name.Tag{}, pushDest{}, fmt.Errorf("push %s to the cluster registry at %s: %w", ref, cr.authority, err)
	}
	return target, pushDest{workDir: workDir, cluster: &cr}, nil
}

// pushReference parses a push target the way every push verb reads one, so
// `k3sm build --push` and `k3sm image push` cannot disagree about a bare name.
//
// It parses with an EMPTY default registry, so "this reference names no
// registry" is the PARSER's verdict rather than a second reading of the
// reference grammar: go-containerregistry treats a first component holding a
// "." or a ":" as a registry and everything else as part of a Docker Hub
// repository, and this asks it rather than re-deriving the rule. A reference
// naming no registry then names the cluster registry (isClusterRegistryHost),
// never Docker Hub, and gains no "library/" element.
func pushReference(s string) (name.Reference, error) {
	return name.ParseReference(s, name.WithDefaultRegistry(""))
}

// resolvePushTarget decides WHERE --push sends the image built under tag.
//
// A tag that names another registry goes to that registry, spelled exactly as
// it was written, with registryAuth's credential. A tag that names the cluster
// registry, by a bare name, the flat registry-k3sm:6450 name or a loopback
// spelling, goes to the cluster registry through the push gate.
func resolvePushTarget(ctx context.Context, tag, workDir string) (name.Tag, pushDest, error) {
	parsed, err := pushReference(tag)
	if err != nil {
		return name.Tag{}, pushDest{}, fmt.Errorf("--tag %q: %w", tag, err)
	}
	probe, ok := parsed.(name.Tag)
	if !ok {
		return name.Tag{}, pushDest{}, fmt.Errorf("--tag %q: a build is pushed under a tag, not a digest", tag)
	}
	switch reg := probe.RegistryStr(); {
	case reg == "":
	case isClusterRegistryHost(reg, workDir):
		ref, err := registryReference(tag, workDir)
		if err != nil {
			return name.Tag{}, pushDest{}, err
		}
		return registryPushTarget(ctx, ref, workDir)
	default:
		t, err := name.NewTag(tag)
		return t, pushDest{workDir: workDir}, err
	}
	cr, err := resolveClusterRegistry(ctx, workDir)
	if err != nil {
		return name.Tag{}, pushDest{}, err
	}
	// A PREFIX, not a parse-and-reassemble. Reassembly normalises — a bare
	// repository gains a "library/" element, an omitted tag gains ":latest" — and
	// the image would then be published under a name the operator never wrote and
	// no Pod spec of theirs names. The pull side splices for the same reason.
	target, err := name.NewTag(cr.authority + "/" + tag)
	if err != nil {
		return name.Tag{}, pushDest{}, fmt.Errorf("push %q to the cluster registry at %s: %w", tag, cr.authority, err)
	}
	return target, pushDest{workDir: workDir, cluster: &cr}, nil
}

// nodeRegistryAuthority resolves THIS node's ingest registry as a reference
// spells it — "localhost:<port>".
//
// The port comes from the per-boot push credential, which is the same file the
// credential lookup reads and the only local record of the running registry's
// address; a node whose registry is off has no such file, and that is the
// ordinary answer rather than a broken state. The loopback spelling matches the
// one the node's puller resolves a bare name against and the one the discovery
// ConfigMap publishes, so what an operator pushes to is what a Pod spec names.
func nodeRegistryAuthority(workDir string) (string, error) {
	cred, err := registrysvc.ReadCredential(workDir)
	if err != nil {
		return "", fmt.Errorf("%w: %w (the server runs its registry unless started with --registry-port 0; or give --tag a full registry reference such as registry.example.com/me/app:v1)", errNoNodeRegistry, err)
	}
	_, port, err := net.SplitHostPort(cred.Address)
	if err != nil {
		return "", fmt.Errorf("%w: its credential names the address %q, which is not host:port", errNoNodeRegistry, cred.Address)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return "", fmt.Errorf("%w: its credential names the port %q, which is not a number", errNoNodeRegistry, port)
	}
	authority := registrysvc.LoopbackAuthority(n)
	if authority == "" {
		return "", fmt.Errorf("%w: its credential names the port %d, which is out of range", errNoNodeRegistry, n)
	}
	return authority, nil
}
