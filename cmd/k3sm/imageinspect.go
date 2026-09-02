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
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protojson"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// imageInspect reports what this node's store knows about one image.
//
// Strictly read-only: it resolves nothing against a registry, takes no lease and
// records no root, so it can never make content reachable. The target is a
// (reference x platform) key or a manifest digest — never both, which the wire
// answers INVALID_ARGUMENT — and which one the operator typed is decided by the
// digest's shape, not by a flag.
//
// ABSENT FIELDS ARE ABSENT FACTS. The wire makes every field independently
// optional so a later daemon can report more without a wire change, and the
// table honours that by omitting a row rather than printing a placeholder: a
// config the store no longer holds (the ordinary state after a prune reclaimed
// an unrooted image's blobs) has no rows, not empty ones.
func imageInspect(ctx context.Context, client runtimev1.ImagesClient, o imageOptions, out io.Writer) error {
	reference, digest := imageTarget(o.source)
	resp, err := client.InspectImage(ctx, &runtimev1.InspectImageRequest{
		Reference: reference,
		Platform:  o.platform,
		Digest:    digest,
	})
	if err != nil {
		return imageRPCError("inspect image", o.socket, err)
	}
	if st := resp.GetError(); st != nil && st.GetCode() != int32(codes.OK) {
		return fmt.Errorf("inspect image: %s", st.GetMessage())
	}
	if o.output == "json" {
		return writeInspectJSON(out, resp)
	}
	writeInspectTable(out, resp)
	return nil
}

// writeInspectJSON prints the daemon's response verbatim, in protobuf JSON.
//
// protojson rather than encoding/json: the response is a proto message, so its
// field names, its enum spellings and its Timestamp encoding are the ones the
// wire defines. Marshalling the Go struct instead would emit XXX_ bookkeeping
// fields and a Timestamp shaped like nothing any other tool reads.
func writeInspectJSON(out io.Writer, resp *runtimev1.InspectImageResponse) error {
	// Unpopulated fields stay out: on this message an absent field means the
	// daemon reported no value for that fact, and emitting a zero would turn
	// "not reported" into "reported as empty".
	b, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(resp)
	if err != nil {
		return fmt.Errorf("render the daemon's response as JSON: %w", err)
	}
	_, err = fmt.Fprintf(out, "%s\n", b)
	return err
}

// writeInspectTable renders the human form: the facts an operator came for,
// each one omitted when the daemon did not report it.
func writeInspectTable(out io.Writer, resp *runtimev1.InspectImageResponse) {
	img := resp.GetImage()
	mfst := img.GetManifest()
	cfg := resp.GetConfig()

	row := func(label, value string) {
		if value == "" {
			return
		}
		fmt.Fprintf(out, "%-11s %s\n", label, value)
	}
	row("REFERENCE", mfst.GetReference())
	row("DIGEST", img.GetManifestDescriptor().GetDigest())
	row("MEDIATYPE", img.GetManifestDescriptor().GetMediaType())
	// The manifest's resolved platform and the config's declared platform are
	// different facts — they agree on a well-formed image, and a disagreement is
	// worth being able to see, so a divergent config platform gets its own row.
	resolved := platformText(mfst.GetPlatform())
	row("PLATFORM", resolved)
	if declared := platformText(cfg.GetPlatform()); declared != "" && declared != resolved {
		row("CONFIG-PLAT", declared)
	}
	row("INDEX", mfst.GetIndexDigest())
	if ts := cfg.GetCreated(); ts != nil {
		row("CREATED", ts.AsTime().UTC().Format(time.RFC3339))
	}
	row("USER", cfg.GetUser())
	row("WORKDIR", cfg.GetWorkingDir())
	if v := cfg.GetEntrypoint(); len(v) > 0 {
		row("ENTRYPOINT", fmt.Sprintf("%q", v))
	}
	if v := cfg.GetCmd(); len(v) > 0 {
		row("CMD", fmt.Sprintf("%q", v))
	}
	if c := mfst.GetConfig(); c.GetDigest() != "" {
		row("CONFIG", fmt.Sprintf("%s  %s", c.GetDigest(), humanBytes(descriptorBytes(c))))
	}
	layers := mfst.GetLayers()
	fmt.Fprintf(out, "%-11s %d\n", "LAYERS", len(layers))
	for _, l := range layers {
		fmt.Fprintf(out, "  %s  %s\n", l.GetDigest(), humanBytes(descriptorBytes(l)))
	}
	// The total is what the image MEASURES, never what removing it would
	// reclaim: a layer shared with another image is counted here and would
	// survive a prune. Saying so costs a line and saves an operator inferring a
	// broken prune from the arithmetic.
	fmt.Fprintf(out, "%-11s %s\n", "TOTAL", humanBytes(resp.GetTotalSizeBytes()))
	fmt.Fprintln(out, "(total counts each distinct blob once; layers shared with another image survive a prune)")
}

// descriptorBytes reads a descriptor's size as an unsigned count. A negative
// size is not a small image, it is a daemon that reported nonsense, and it is
// clamped rather than wrapped to 16 exbibytes by the conversion.
func descriptorBytes(d *runtimev1.Descriptor) uint64 {
	if d.GetSize() < 0 {
		return 0
	}
	return uint64(d.GetSize())
}
