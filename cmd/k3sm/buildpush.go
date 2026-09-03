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
// seam so the ORDER — the node's store first, the registry second — and the
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

// pushDelivered sends an image that is ALREADY recorded in this node's store on
// to a registry, and returns the reference it landed under.
//
// Every failure is reported with the store recording named FIRST. The build's
// work is not lost when an upload fails: the image is in this node's store under
// --tag and a Pod can name it right now, so the operator's next step is to retry
// the upload, not the build. An error that did not say so would read as "the
// build failed".
func pushDelivered(ctx context.Context, o buildOptions, ref name.Tag, b built, push imagePusher) (name.Tag, error) {
	// The control-plane state root is resolved the way every other
	// registry-aware verb in this binary resolves it, so `k3sm build --push`
	// finds exactly the per-boot credential `k3sm image push` would.
	workDir := workDirFromEnv()
	target, err := resolvePushTarget(o.tag, workDir)
	if err != nil {
		return name.Tag{}, pushAfterStoreError(ref, err)
	}
	if err := push(ctx, target, b, workDir); err != nil {
		return name.Tag{}, pushAfterStoreError(ref, err)
	}
	return target, nil
}

// pushAfterStoreError renders a push failure that happened after the store
// recording succeeded.
func pushAfterStoreError(ref name.Tag, err error) error {
	return fmt.Errorf("image %s is in the node store; push failed: %w", ref, err)
}

// resolvePushTarget decides WHERE --push sends the image the build recorded
// under tag.
//
// A tag that names a registry goes to that registry, spelled exactly as it was
// written. A BARE tag — one that names no registry — goes to THIS node's ingest
// registry, which is the push-side mirror of the pull side's bare-name
// resolution: a Pod naming "myapp:v1" is served from this node's registry
// first, so a build that pushes "myapp:v1" must put it there.
//
// The store entry is unaffected either way: it keeps the reference the operator
// wrote, so `kubectl run app --image=myapp:v1` resolves whether or not the push
// happened.
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
	if probe.RegistryStr() != "" {
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
		return "", fmt.Errorf("%w: %w (start the server with --registry-port, or give --tag a full registry reference such as registry.example.com/me/app:v1)", errNoNodeRegistry, err)
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
