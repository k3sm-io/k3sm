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

	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// errTagRepoint reports that `k3sm image tag` was asked to move an existing tag
// onto a different manifest without --force.
var errTagRepoint = errors.New("the tag already names another manifest")

// imageTag adds a tag to a manifest the cluster registry already holds.
//
// The new tag is an OCI distribution manifest PUT of the SAME bytes, so it
// names exactly the digest the source names: nothing is rebuilt or
// re-serialised. A source in another repository is copied into the new tag's
// repository, blobs mounted across, and still keeps its digest.
//
// It never silently re-points a tag: a new name that already names a different
// manifest is refused with errTagRepoint unless --force is given, because a
// Pod that pulls the tag next would run other content than it ran before. Build
// and load are different: they overwrite their own tag, which is what a rebuild
// means.
//
// The source is a tag, a repository@digest, or a bare digest, which names a
// manifest in the new tag's repository. --platform tags the platform's child
// of an index rather than the whole index.
//
// It writes as the caller: with the server's per-boot credential when this
// account can read it, else through the push gate with a builder token minted
// through the caller's kubeconfig, as `k3sm image push` does (registryAccess).
func imageTag(ctx context.Context, o imageOptions, out io.Writer) error {
	dst, err := resolveClusterImage(o.target, o.workDir)
	if err != nil {
		return err
	}
	if !dst.isTag() {
		return fmt.Errorf("tag %s: the new name must be a tag, not a digest", o.target)
	}
	var src clusterImage
	if looksLikeDigest(o.source) {
		src, err = clusterImageAt(dst.flat.Context().RepositoryStr(), o.source)
	} else {
		src, err = resolveClusterImage(o.source, o.workDir)
	}
	if err != nil {
		return err
	}
	acc, err := registryWriteAccess(ctx, o.workDir)
	if err != nil {
		return fmt.Errorf("tag %s: %w", dst.flat, err)
	}
	if dst, err = acc.locate(dst); err != nil {
		return err
	}
	if src, err = acc.locate(src); err != nil {
		return err
	}
	opts := acc.opts
	desc, _, err := getClusterImage(src, o.platform, acc)
	if err != nil {
		return err
	}
	if src.isTag() || o.platform != nil {
		fmt.Fprintf(out, "%s resolves to %s\n", src.flat, desc.Digest)
	}

	existing, err := remote.Head(dst.remote, opts...)
	switch {
	case err == nil && existing.Digest == desc.Digest:
		fmt.Fprintf(out, "already tagged %s\n  digest:   %s\n", dst.flat, desc.Digest)
		return nil
	case err == nil && !o.force:
		return fmt.Errorf("tag %s: %w (%s); pass --force to re-point it to %s", dst.flat, errTagRepoint, existing.Digest, desc.Digest)
	case err != nil && !isNotFound(err):
		return registryError("read "+dst.flat.String(), err)
	}

	// Within one repository the blobs are already there, so the tag is the
	// manifest PUT alone. Across repositories Push uploads what the new
	// repository lacks first, then the manifest.
	if src.flat.Context().RepositoryStr() == dst.flat.Context().RepositoryStr() {
		err = remote.Put(dst.remote, desc, opts...)
	} else if opts, err = withMountScopes(ctx, dst.remote, desc, opts); err == nil {
		err = remote.Push(dst.remote, desc, opts...)
	}
	if err != nil {
		return registryError("tag "+dst.flat.String(), err)
	}
	if existing != nil {
		fmt.Fprintf(out, "re-pointed %s from %s\n  digest:   %s\n", dst.flat, existing.Digest, desc.Digest)
		return nil
	}
	fmt.Fprintf(out, "tagged %s\n  digest:   %s\n", dst.flat, desc.Digest)
	return nil
}

// imageUntag deletes one tag from the cluster registry.
//
// IT REMOVES A NAME, NOT BYTES. The registry deletes the tag alone; the
// manifest and its blobs stay while any other tag or index names them, and the
// registry's own garbage collection reclaims what nothing names. A node that
// already pulled the image keeps its cached copy, so a running Pod is not
// harmed.
//
// It is deliberately not idempotent-by-silence: an absent tag is an error,
// because the operator asked to remove a specific name. --digest refuses the
// removal unless the tag still names that manifest.
//
// It needs the server's per-boot credential: the push gate never forwards a
// delete, so a builder token cannot remove a tag (registryDeleteAccess).
func imageUntag(ctx context.Context, o imageOptions, out io.Writer) error {
	c, err := resolveClusterImage(o.source, o.workDir)
	if err != nil {
		return err
	}
	if !c.isTag() {
		return fmt.Errorf("untag %s: name the tag to remove, not a digest", o.source)
	}
	acc, err := registryDeleteAccess(ctx, o.workDir)
	if err != nil {
		return fmt.Errorf("untag %s: %w", c.flat, err)
	}
	if c, err = acc.locate(c); err != nil {
		return err
	}
	opts := acc.opts
	desc, err := remote.Head(c.remote, opts...)
	if err != nil {
		return registryError("untag "+c.flat.String(), err)
	}
	if o.digest != "" && desc.Digest.String() != o.digest {
		return fmt.Errorf("untag %s: it names %s, not %s; nothing was removed", c.flat, desc.Digest, o.digest)
	}
	if err := remote.Delete(c.remote, opts...); err != nil {
		return registryError("untag "+c.flat.String(), err)
	}
	fmt.Fprintf(out, "untagged %s\n  digest:   %s\n", c.flat, desc.Digest)
	fmt.Fprintln(out, "(the registry reclaims content no tag names at its next garbage collection)")
	return nil
}
