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

	"google.golang.org/grpc/codes"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// imageTag records an ADDITIONAL name for content this node already holds.
//
// TagImage names its target by DIGEST and never by another tag, because roots
// are digest-pinned: a tag that named a mutable name would let a concurrent
// re-pull decide what the new tag ends up meaning. So an operator who typed a
// reference gets it resolved to a digest FIRST, here, by a read-only
// InspectImage — the resolution is explicit and visible in the output, rather
// than a step the daemon takes on the caller's behalf.
//
// The two refusals the operator will actually meet are surfaced verbatim: the
// digest is not in this store (NOT_FOUND), and the new name already resolves
// somewhere else (FAILED_PRECONDITION, which this verb never overrides — that is
// untag, then tag).
func imageTag(ctx context.Context, client runtimev1.ImagesClient, o imageOptions, out io.Writer) error {
	digest := o.source
	if !looksLikeDigest(digest) {
		resolved, err := client.InspectImage(ctx, &runtimev1.InspectImageRequest{
			Reference: o.source,
			Platform:  o.platform,
		})
		if err != nil {
			return imageRPCError(fmt.Sprintf("resolve %s to a digest", o.source), o.socket, err)
		}
		if st := resolved.GetError(); st != nil && st.GetCode() != int32(codes.OK) {
			return fmt.Errorf("resolve %s to a digest: %s", o.source, st.GetMessage())
		}
		digest = resolved.GetImage().GetManifestDescriptor().GetDigest()
		if digest == "" {
			return fmt.Errorf("resolve %s to a digest: the daemon reported no digest for it", o.source)
		}
		fmt.Fprintf(out, "%s resolves to %s\n", o.source, digest)
	}
	resp, err := client.TagImage(ctx, &runtimev1.TagImageRequest{
		Digest:    digest,
		Reference: o.target,
		Platform:  o.platform,
	})
	if err != nil {
		return imageRPCError("tag image", o.socket, err)
	}
	if st := resp.GetError(); st != nil && st.GetCode() != int32(codes.OK) {
		return fmt.Errorf("tag image: %s", st.GetMessage())
	}
	if resp.GetAlreadyPresent() {
		fmt.Fprintf(out, "already tagged %s\n", o.target)
	} else {
		fmt.Fprintf(out, "tagged %s\n", o.target)
	}
	writeImageFacts(out, resp.GetImage())
	return nil
}

// imageUntag removes ONE (reference x platform) name.
//
// IT REMOVES A NAME, NOT BYTES, and the result line says so every time: no blob
// is unlinked here, and content is reclaimed only by `k3sm image prune`, which
// re-derives reachability first. Untagging a name a running pod still pins
// leaves that pod unharmed — that is the point of separating the two verbs.
//
// It is deliberately not idempotent-by-silence: an absent name is NOT_FOUND from
// the daemon and an error here, because the operator asked to remove a specific
// name. An ambiguous untag — no --platform on a reference with several entries —
// is refused too, and removes nothing.
func imageUntag(ctx context.Context, client runtimev1.ImagesClient, o imageOptions, out io.Writer) error {
	resp, err := client.UntagImage(ctx, &runtimev1.UntagImageRequest{
		Reference: o.source,
		Platform:  o.platform,
		Digest:    o.digest,
	})
	if err != nil {
		return imageRPCError("untag image", o.socket, err)
	}
	if st := resp.GetError(); st != nil && st.GetCode() != int32(codes.OK) {
		return fmt.Errorf("untag image: %s", st.GetMessage())
	}
	fmt.Fprintf(out, "untagged %s\n", o.source)
	writeImageFacts(out, resp.GetRemoved())
	fmt.Fprintln(out, "(the content is still on disk — `k3sm image prune` reclaims what no name and no pod references)")
	return nil
}
