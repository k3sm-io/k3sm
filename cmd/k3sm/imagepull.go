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

// imagePull warms this node's store for a reference and reports what it
// resolved to.
//
// THE DAEMON DOES THE FETCHING, through its own puller — the same code path a
// pod-driven pull takes. That is the whole reason this verb is an RPC and not an
// HTTP client: a CLI that fetched for itself would have forked the daemon's
// verification story (every blob re-hashed against its digest before the lease
// commits, the disk-pressure gate, the one image index pods resolve against),
// and the forked half is the one nobody re-reads.
//
// A successful pull leaves an OPERATOR ROOT over the reference, which is why the
// image survives `k3sm image prune` until it is untagged. The result line says
// so, because "I pulled it and prune deleted it" is otherwise the report.
func imagePull(ctx context.Context, client runtimev1.ImagesClient, o imageOptions, out io.Writer) error {
	resp, err := client.PullImage(ctx, &runtimev1.PullImageRequest{
		Reference: o.source,
		Platform:  o.platform,
		Policy:    o.policy,
	})
	if err != nil {
		return imageRPCError("pull image", o.socket, err)
	}
	// Two failure channels — the transport status above and a typed in-band
	// Status here — and both mean nothing was recorded. Checking only the first
	// would report a refused pull as a success.
	if st := resp.GetError(); st != nil && st.GetCode() != int32(codes.OK) {
		return fmt.Errorf("pull image: the daemon refused: %s", st.GetMessage())
	}
	img := resp.GetImage()
	if resp.GetAlreadyPresent() {
		fmt.Fprintf(out, "up to date %s\n", o.source)
	} else {
		fmt.Fprintf(out, "pulled %s\n", o.source)
	}
	writeImageFacts(out, img)
	return nil
}

// writeImageFacts renders the digest and resolved platform of a store entry —
// the two facts every write verb's result line is about.
//
// An absent platform is an absent fact and is omitted: the reference resolved
// directly to a manifest rather than through a multi-platform index, and
// printing "unknown" would invent a claim the daemon did not make.
func writeImageFacts(out io.Writer, img *runtimev1.Image) {
	fmt.Fprintf(out, "  digest:   %s\n", img.GetManifestDescriptor().GetDigest())
	if p := platformText(img.GetManifest().GetPlatform()); p != "" {
		fmt.Fprintf(out, "  platform: %s\n", p)
	}
}
