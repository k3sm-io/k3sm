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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// rmReport is the `k3sm image rm -o json` document. DryRun is the CLI's echo
// of its own --force, not a field of the daemon's answer: the response has the
// same shape either way, and without force its lists are a plan.
type rmReport struct {
	ManifestDigest string       `json:"manifestDigest"`
	DryRun         bool         `json:"dryRun"`
	RemovedDigests []string     `json:"removedDigests"`
	Kept           []rmKeptBlob `json:"kept"`
	ReclaimedBytes uint64       `json:"reclaimedBytes"`
}

// rmKeptBlob is one target blob the eviction kept, with its reason in the
// stable machine spelling evictReasonKey returns.
type rmKeptBlob struct {
	Digest string `json:"digest"`
	Reason string `json:"reason"`
}

// rmDigestPattern is the shape rm reads as a manifest digest rather than a
// reference. It names the OCI-registered algorithms, not any `<word>:<hex>`:
// a tag that happens to be hex (a short git sha, `app:3f2a9c1`) is a
// reference, and reading it as a digest would make that image impossible to
// name. The daemon validates either spelling; the CLI only classifies.
var rmDigestPattern = regexp.MustCompile(`^sha(256|384|512):[0-9a-fA-F]+$`)

// rmTargetIsDigest reports whether target is sent as EvictImageRequest.digest.
func rmTargetIsDigest(target string) bool { return rmDigestPattern.MatchString(target) }

// imageRm evicts one image or artifact manifest from this node's cache, dry
// run unless --force. It acts on this node's cache only, never the cluster
// registry, and asks the daemon's EvictImage, which keeps everything a pod,
// a root, an ingest or another cached image still needs. Any failure is an
// error (exit 1); a partial eviction is not, and is reported.
//
// A daemon that predates EvictImage answers UNIMPLEMENTED. rm then deletes
// nothing and says to upgrade: it never falls back to PruneImages, which
// evicts every image no pod uses, not the one the operator named.
func imageRm(ctx context.Context, client runtimev1.ImagesClient, o imageOptions, out io.Writer) error {
	req := &runtimev1.EvictImageRequest{Force: o.force}
	if rmTargetIsDigest(o.source) {
		req.Digest = o.source
	} else {
		req.Reference = o.source
		req.Platform = o.platform
	}
	resp, err := client.EvictImage(ctx, req)
	if err != nil {
		return rmRPCError(o.source, o.socket, err)
	}
	report := rmReport{
		ManifestDigest: resp.GetManifestDigest(),
		DryRun:         !o.force,
		RemovedDigests: append([]string{}, resp.GetRemovedDigests()...),
		Kept:           []rmKeptBlob{},
		ReclaimedBytes: resp.GetReclaimedBytes(),
	}
	for _, k := range resp.GetKept() {
		report.Kept = append(report.Kept, rmKeptBlob{Digest: k.GetDigest(), Reason: evictReasonKey(k.GetReason())})
	}
	if o.output == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return fmt.Errorf("render the rm report: %w", err)
		}
		return nil
	}
	renderRm(out, report, resp.GetKept())
	return nil
}

// rmRPCError maps a failed EvictImage to the operator's message. Every case
// is an error, so the command exits 1.
func rmRPCError(target, socket string, err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return fmt.Errorf("rm %s: %w", target, err)
	}
	switch st.Code() {
	case codes.Unimplemented:
		return fmt.Errorf("rm %s: this node's runtimed predates image rm; nothing was evicted; upgrade the node's runtimed (k3sm install, then restart it)", target)
	case codes.NotFound:
		return fmt.Errorf("rm %s: no image entry, artifact record or released copy names %s on this node; `k3sm image prune` reclaims unnamed blobs (%s)", target, target, st.Message())
	case codes.FailedPrecondition:
		if msg, ok := rmRefusal(target, st); ok {
			return errors.New(msg)
		}
	case codes.Internal:
		// An unlink that failed, or whose re-verification refused it, is a
		// failure, not a partial success. Some blobs may already be gone.
		return fmt.Errorf("rm %s: the daemon failed: %s; some blobs may already be unlinked and the kept list is in the node log (/var/log/k3sm/server.log, or agent.log on a joined worker); a re-run converges", target, st.Message())
	}
	return imageRPCError("rm "+target, socket, err)
}

// rmRefusal is the operator's sentence for a FAILED_PRECONDITION refusal
// whose google.rpc.ErrorInfo detail (domain runtime.k3sm.io) names the case,
// read from the detail and never from the message text. The daemon attaches a
// reason and the domain only, no metadata, so the sentence names no pod; its
// message is appended as context. ok is false for a refusal with no such
// detail or with a reason this build does not know: the caller keeps the
// generic line.
func rmRefusal(target string, st *status.Status) (msg string, ok bool) {
	for _, d := range st.Details() {
		info, isInfo := d.(*errdetails.ErrorInfo)
		if !isInfo || info.GetDomain() != runtimev1.EvictErrorInfoDomain {
			continue
		}
		switch info.GetReason() {
		case runtimev1.EvictReasonImageInUse:
			return fmt.Sprintf("rm %s: a pod on this node uses %s, so nothing was evicted; retry once the pod is gone (%s)", target, target, st.Message()), true
		case runtimev1.EvictReasonReferenceAmbiguous:
			return fmt.Sprintf("rm %s: %s names more than one image on this node, so nothing was evicted; retry with --platform, or name the image by its digest (%s)", target, target, st.Message()), true
		case runtimev1.EvictReasonRootsIncomplete:
			// The contract allows this refusal after an earlier removal stage
			// already unlinked; the daemon's message then counts the blobs.
			return fmt.Sprintf("rm %s: the daemon could not read every record that protects blobs, so it refused; nothing was deleted unless its message counts unlinked blobs; check the node log (/var/log/k3sm/server.log, or agent.log on a joined worker), repair the record, and re-run (%s)", target, st.Message()), true
		}
	}
	return "", false
}

// rmKeptShown is how many kept blobs the text report lists one by one; a
// target can name thousands. -o json lists every one.
const rmKeptShown = 20

// renderRm renders an eviction as the operator's report: the manifest, each
// blob evicted (or that would be), the reclaimed bytes, the kept blobs counted
// by reason, and the first rmKeptShown kept blobs with their reason.
func renderRm(out io.Writer, r rmReport, kept []*runtimev1.EvictKeptBlob) {
	verb := "would evict"
	if !r.DryRun {
		verb = "evicted"
	}
	fmt.Fprintf(out, "image %s:\n", r.ManifestDigest)
	for _, d := range r.RemovedDigests {
		fmt.Fprintf(out, "  %s %s\n", verb, d)
	}
	fmt.Fprintf(out, "  %s %d blob(s), %s\n", verb, len(r.RemovedDigests), humanBytes(r.ReclaimedBytes))
	counts := map[runtimev1.EvictSkipReason]int{}
	for _, k := range kept {
		counts[k.GetReason()]++
	}
	reasons := make([]runtimev1.EvictSkipReason, 0, len(counts))
	for r := range counts {
		reasons = append(reasons, r)
	}
	slices.Sort(reasons)
	for _, r := range reasons {
		fmt.Fprintf(out, "  kept %d blob(s): %s\n", counts[r], evictReasonText(r))
	}
	for _, k := range kept[:min(len(kept), rmKeptShown)] {
		fmt.Fprintf(out, "  kept %s: %s\n", k.GetDigest(), evictReasonText(k.GetReason()))
	}
	if n := len(kept) - rmKeptShown; n > 0 {
		fmt.Fprintf(out, "  ... and %d more kept blob(s)\n", n)
	}
	young := counts[runtimev1.EvictSkipReason_EVICT_SKIP_REASON_YOUNG]
	if len(kept) > 0 {
		fmt.Fprintf(out, "  partial: %d of %d blob(s) kept\n", len(kept), len(kept)+len(r.RemovedDigests))
	}
	if len(r.RemovedDigests) == 0 && young > 0 && young == len(kept) {
		fmt.Fprintln(out, "  every blob is younger than the daemon's grace window (a pull may still be in flight); retry once it has passed")
	}
	if r.DryRun {
		fmt.Fprintln(out, "(dry run: nothing was deleted; pass --force to evict)")
	}
}

// evictReasonKey is a kept reason's stable machine spelling in -o json. An
// enum value this build does not know is `reason(<n>)`, never folded into a
// neighbour.
func evictReasonKey(r runtimev1.EvictSkipReason) string {
	switch r {
	case runtimev1.EvictSkipReason_EVICT_SKIP_REASON_UNSPECIFIED:
		return "unspecified"
	case runtimev1.EvictSkipReason_EVICT_SKIP_REASON_ROOTED:
		return "rooted"
	case runtimev1.EvictSkipReason_EVICT_SKIP_REASON_IN_USE:
		return "in-use"
	case runtimev1.EvictSkipReason_EVICT_SKIP_REASON_LEASED:
		return "leased"
	case runtimev1.EvictSkipReason_EVICT_SKIP_REASON_SHARED:
		return "shared"
	case runtimev1.EvictSkipReason_EVICT_SKIP_REASON_YOUNG:
		return "young"
	}
	return fmt.Sprintf("reason(%d)", int32(r))
}

// evictReasonText is a kept reason in the operator's vocabulary.
func evictReasonText(r runtimev1.EvictSkipReason) string {
	switch r {
	case runtimev1.EvictSkipReason_EVICT_SKIP_REASON_UNSPECIFIED:
		return "no reason reported"
	case runtimev1.EvictSkipReason_EVICT_SKIP_REASON_ROOTED:
		return "rooted by an artifact record or operator root"
	case runtimev1.EvictSkipReason_EVICT_SKIP_REASON_IN_USE:
		return "in use by a pod"
	case runtimev1.EvictSkipReason_EVICT_SKIP_REASON_LEASED:
		return "an ingest is in flight"
	case runtimev1.EvictSkipReason_EVICT_SKIP_REASON_SHARED:
		return "shared with another cached image"
	case runtimev1.EvictSkipReason_EVICT_SKIP_REASON_YOUNG:
		return "younger than the grace window"
	}
	return fmt.Sprintf("reason(%d)", int32(r))
}
