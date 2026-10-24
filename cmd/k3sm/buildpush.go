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
var errNoNodeRegistry = errors.New("this node has no ingest registry to push to")

// imagePusher uploads what a build produced to a registry reference. It is a
// seam so the ORDER (the cluster registry first, any other registry second) and the
// wording of a failed upload are provable without a registry, a credential or a
// network.
type imagePusher func(ctx context.Context, ref name.Reference, b built, workDir string) error

// pushBuilt is the production imagePusher: it uploads a single-platform build
// through the same path `k3sm image push` uses, and a multi-platform build as
// the INDEX it is — every platform under one reference, which is what makes the
// pushed artifact indistinguishable from any other multi-arch image a puller
// selects from.
func pushBuilt(ctx context.Context, ref name.Reference, b built, workDir string) error {
	if b.index != nil {
		return pushIndex(ctx, ref, b.index, workDir)
	}
	return pushImage(ctx, ref, b.image, workDir)
}

// pushDelivered sends a built image on to the registry --push names, and
// returns the reference it landed under.
//
// Every failure is reported with the recording named FIRST. The build's work is
// not lost when this upload fails: the image is in the cluster registry and a
// Pod can name it right now, so the operator's next step is to retry the
// upload, not the build. An error that did not say so would read as "the build
// failed".
func pushDelivered(ctx context.Context, o buildOptions, ref name.Tag, b built, push imagePusher) (name.Tag, error) {
	// The control-plane state root is resolved the way every other
	// registry-aware verb in this binary resolves it, so `k3sm build --push`
	// finds exactly the per-boot credential `k3sm image push` would.
	workDir := workDirFromEnv()
	target, err := resolvePushTarget(o.tag, workDir)
	if err != nil {
		return name.Tag{}, pushFailure(o, ref, err)
	}
	if err := push(ctx, target, b, workDir); err != nil {
		return name.Tag{}, pushFailure(o, ref, err)
	}
	return target, nil
}

// pushFailure renders a push failure for where the build left the image: in the
// cluster registry, or, under --no-record, only at --output if anywhere.
func pushFailure(o buildOptions, ref name.Tag, err error) error {
	if !o.noRecord {
		return pushAfterStoreError(ref, err)
	}
	if o.output != "" {
		return fmt.Errorf("image %s was written to %s and not recorded (--no-record); push failed: %w", ref, o.output, err)
	}
	return fmt.Errorf("image %s was not recorded (--no-record) and has no --output; push failed: %w", ref, err)
}

// pushAfterStoreError renders a push failure that happened after the
// recording in the cluster registry succeeded.
func pushAfterStoreError(ref name.Tag, err error) error {
	return fmt.Errorf("image %s is in the cluster registry; push failed: %w", ref, err)
}

// registryReference is the name the cluster registry records tag under:
// registry-k3sm:6450/<repository>:<tag>.
//
// A bare tag maps there, and so does a tag that already names the cluster
// registry by its flat name or by this Mac's loopback spelling. A tag that
// names another registry keeps its repository path and is recorded under the
// flat name too; --push is what sends it to the registry it names.
//
// The tag is parsed with an EMPTY default registry, so a bare repository gains
// no "library/" element: the image is recorded under the repository the
// operator wrote.
func registryReference(tag string) (name.Tag, error) {
	probe, err := name.NewTag(tag, name.WithDefaultRegistry(""))
	if err != nil {
		return name.Tag{}, fmt.Errorf("reference %q: %w", tag, err)
	}
	ref, err := name.NewTag(flatRegistryHost + "/" + probe.RepositoryStr() + ":" + probe.TagStr())
	if err != nil {
		return name.Tag{}, fmt.Errorf("record %q in the cluster registry: %w", tag, err)
	}
	return ref, nil
}

// registryPushTarget is where an upload of ref, a cluster-registry reference,
// is sent from this Mac: this node's registry on loopback, which the flat name
// also serves. The Mac does not resolve registry-k3sm, and the push credential
// is presented only to the loopback spelling it was minted for.
func registryPushTarget(ref name.Tag, workDir string) (name.Tag, error) {
	authority, err := nodeRegistryAuthority(workDir)
	if err != nil {
		return name.Tag{}, err
	}
	target, err := name.NewTag(authority + "/" + ref.RepositoryStr() + ":" + ref.TagStr())
	if err != nil {
		return name.Tag{}, fmt.Errorf("push %s to this node's registry at %s: %w", ref, authority, err)
	}
	return target, nil
}

// namesClusterRegistry reports whether tag already names the cluster registry:
// a bare tag, the flat registry-k3sm:6450 name, or the loopback spelling of
// this node's registry. Recording such a tag is already the upload, so --push
// does not send it a second time.
func namesClusterRegistry(tag, workDir string) bool {
	probe, err := name.NewTag(tag, name.WithDefaultRegistry(""))
	if err != nil {
		return false
	}
	switch reg := probe.RegistryStr(); reg {
	case "", flatRegistryHost:
		return true
	default:
		cred, err := registrysvc.ReadCredential(workDir)
		return err == nil && cred.MatchesRegistry(reg)
	}
}

// resolvePushTarget decides WHERE --push sends the image built under tag.
//
// A tag that names another registry goes to that registry, spelled exactly as
// it was written. A tag that names the cluster registry, by a bare name or by
// the flat registry-k3sm:6450 name, goes to THIS node's registry on loopback,
// the same registry the flat name serves.
func resolvePushTarget(tag, workDir string) (name.Tag, error) {
	// Parsed with an EMPTY default registry, so "this reference names no
	// registry" is the PARSER's verdict rather than a second reading of the
	// reference grammar: go-containerregistry treats a first component holding a
	// "." or a ":" as a registry and everything else as part of a Docker Hub
	// repository, and this asks it rather than re-deriving the rule.
	probe, err := name.NewTag(tag, name.WithDefaultRegistry(""))
	if err != nil {
		return name.Tag{}, fmt.Errorf("--tag %q: %w", tag, err)
	}
	switch probe.RegistryStr() {
	case "":
	case flatRegistryHost:
		ref, err := registryReference(tag)
		if err != nil {
			return name.Tag{}, err
		}
		return registryPushTarget(ref, workDir)
	default:
		return name.NewTag(tag)
	}
	authority, err := nodeRegistryAuthority(workDir)
	if err != nil {
		return name.Tag{}, err
	}
	// A PREFIX, not a parse-and-reassemble. Reassembly normalises — a bare
	// repository gains a "library/" element, an omitted tag gains ":latest" — and
	// the image would then be published under a name the operator never wrote and
	// no Pod spec of theirs names. The pull side splices for the same reason.
	target, err := name.NewTag(authority + "/" + tag)
	if err != nil {
		return name.Tag{}, fmt.Errorf("push %q to this node's registry at %s: %w", tag, authority, err)
	}
	return target, nil
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
