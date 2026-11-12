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
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// fakeEvictDaemon is fakeImagesDaemon with EvictImage served. Every other
// method keeps fakeImagesDaemon's recording, so a test can see that rm reached
// for nothing but the one eviction.
type fakeEvictDaemon struct {
	fakeImagesDaemon

	gotEvict  []*runtimev1.EvictImageRequest
	evictResp *runtimev1.EvictImageResponse
	evictErr  error
}

func (f *fakeEvictDaemon) EvictImage(_ context.Context, req *runtimev1.EvictImageRequest) (*runtimev1.EvictImageResponse, error) {
	f.gotEvict = append(f.gotEvict, req)
	if f.evictErr != nil {
		return nil, f.evictErr
	}
	return f.evictResp, nil
}

// serveRecordingImages serves fake like serveFakeImages, and records the full
// method name of every unary call that reaches the server, whatever fake
// implements.
func serveRecordingImages(t *testing.T, fake runtimev1.ImagesServer) (string, func() []string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "k3i")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "runtimed.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var mu sync.Mutex
	var calls []string
	record := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		mu.Lock()
		calls = append(calls, info.FullMethod)
		mu.Unlock()
		return handler(ctx, req)
	}
	recordStream := func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		mu.Lock()
		calls = append(calls, info.FullMethod)
		mu.Unlock()
		return handler(srv, ss)
	}
	gs := grpc.NewServer(grpc.UnaryInterceptor(record), grpc.StreamInterceptor(recordStream))
	runtimev1.RegisterImagesServer(gs, fake)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	return sock, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(calls)
	}
}

const (
	rmManifest = "sha256:" + "aa00000000000000000000000000000000000000000000000000000000000000"
	rmLayerA   = "sha256:" + "a100000000000000000000000000000000000000000000000000000000000000"
	rmLayerB   = "sha256:" + "b200000000000000000000000000000000000000000000000000000000000000"
	rmShared   = "sha256:" + "c300000000000000000000000000000000000000000000000000000000000000"
)

// evictRefusal is the daemon's FAILED_PRECONDITION refusal with the
// ErrorInfo detail the handler attaches: a reason and the domain, no metadata.
func evictRefusal(t *testing.T, domain, reason, msg string) error {
	t.Helper()
	st, err := status.New(codes.FailedPrecondition, msg).WithDetails(&errdetails.ErrorInfo{Reason: reason, Domain: domain})
	if err != nil {
		t.Fatalf("attach ErrorInfo: %v", err)
	}
	return st.Err()
}

// TestImageRmEvictsOneImage is the gate for `k3sm image rm`: it is a client of
// the daemon's EvictImage, the request names exactly the target and carries
// force only under --force, and the outcome (reclaimed bytes, each kept blob
// with its reason, a failure as a non-zero exit) reaches the operator.
func TestImageRmEvictsOneImage(t *testing.T) {
	partial := &runtimev1.EvictImageResponse{
		ManifestDigest: rmManifest,
		RemovedDigests: []string{rmLayerA, rmLayerB},
		Kept:           []*runtimev1.EvictKeptBlob{{Digest: rmShared, Reason: runtimev1.EvictSkipReason_EVICT_SKIP_REASON_SHARED}},
		ReclaimedBytes: 3 << 20,
	}
	cases := []struct {
		name string
		args []string
		resp *runtimev1.EvictImageResponse
		err  error
		// wantReq is the request the daemon must receive; nil means no
		// EvictImage call at all.
		wantReq  *runtimev1.EvictImageRequest
		wantErr  []string
		denyErr  []string
		wantOut  []string
		denyOut  []string
		wantJSON string
	}{
		{
			name:    "forced by reference evicts and prints reclaimed bytes",
			args:    []string{"rm", "--force", "ghcr.io/acme/app:v1"},
			resp:    partial,
			wantReq: &runtimev1.EvictImageRequest{Reference: "ghcr.io/acme/app:v1", Force: true},
			wantOut: []string{
				"image " + rmManifest,
				"evicted " + rmLayerA,
				"evicted 2 blob(s), 3.0 MiB",
				"kept " + rmShared + ": shared with another cached image",
				"partial: 1 of 3 blob(s) kept",
			},
			denyOut: []string{"dry run"},
		},
		{
			name:    "forced by digest sends the digest, not a reference",
			args:    []string{"rm", rmManifest, "--force"},
			resp:    &runtimev1.EvictImageResponse{ManifestDigest: rmManifest, RemovedDigests: []string{rmLayerA}, ReclaimedBytes: 2048},
			wantReq: &runtimev1.EvictImageRequest{Digest: rmManifest, Force: true},
			wantOut: []string{"evicted 1 blob(s), 2.0 KiB"},
			denyOut: []string{"partial", "dry run"},
		},
		{
			name:    "a git-sha tag is a reference, not a digest",
			args:    []string{"rm", "app:3f2a9c1", "--force"},
			resp:    &runtimev1.EvictImageResponse{ManifestDigest: rmManifest},
			wantReq: &runtimev1.EvictImageRequest{Reference: "app:3f2a9c1", Force: true},
		},
		{
			name:    "the platform rides with a reference",
			args:    []string{"rm", "app:v1", "--platform", "linux/arm64"},
			resp:    &runtimev1.EvictImageResponse{ManifestDigest: rmManifest},
			wantReq: &runtimev1.EvictImageRequest{Reference: "app:v1", Platform: &runtimev1.Platform{Os: "linux", Architecture: "arm64"}},
		},
		{
			name:    "without --force force is unset and nothing was deleted",
			args:    []string{"rm", "ghcr.io/acme/app:v1"},
			resp:    partial,
			wantReq: &runtimev1.EvictImageRequest{Reference: "ghcr.io/acme/app:v1"},
			wantOut: []string{
				"would evict " + rmLayerA,
				"would evict 2 blob(s), 3.0 MiB",
				"dry run: nothing was deleted; pass --force to evict",
			},
			denyOut: []string{"evicted "},
		},
		{
			name: "every blob young says when to retry",
			args: []string{"rm", "app:v1", "--force"},
			resp: &runtimev1.EvictImageResponse{ManifestDigest: rmManifest, Kept: []*runtimev1.EvictKeptBlob{
				{Digest: rmLayerA, Reason: runtimev1.EvictSkipReason_EVICT_SKIP_REASON_YOUNG},
				{Digest: rmLayerB, Reason: runtimev1.EvictSkipReason_EVICT_SKIP_REASON_YOUNG},
			}},
			wantReq: &runtimev1.EvictImageRequest{Reference: "app:v1", Force: true},
			wantOut: []string{"evicted 0 blob(s), 0 B", "younger than the daemon's grace window", "retry"},
		},
		{
			name:    "a blob kept because its unlink failed is a failure",
			args:    []string{"rm", "app:v1", "--force"},
			err:     status.Error(codes.Internal, "evict: unlink sha256:a1: permission denied"),
			wantReq: &runtimev1.EvictImageRequest{Reference: "app:v1", Force: true},
			wantErr: []string{"unlink sha256:a1: permission denied", "node log", "re-run"},
		},
		{
			name:    "an image no record names points at prune",
			args:    []string{"rm", rmManifest, "--force"},
			err:     status.Error(codes.NotFound, "no such manifest"),
			wantReq: &runtimev1.EvictImageRequest{Digest: rmManifest, Force: true},
			wantErr: []string{"names " + rmManifest + " on this node", "k3sm image prune"},
		},
		{
			name:    "a refusal without a detail keeps the generic line",
			args:    []string{"rm", "app:v1", "--force"},
			err:     status.Error(codes.FailedPrecondition, "index entry names no manifest digest"),
			wantReq: &runtimev1.EvictImageRequest{Reference: "app:v1", Force: true},
			wantErr: []string{"the daemon refused", "index entry names no manifest digest"},
		},
		{
			name:    "an in-use refusal says to retry once the pod is gone",
			args:    []string{"rm", "app:v1", "--force"},
			err:     evictRefusal(t, runtimev1.EvictErrorInfoDomain, runtimev1.EvictReasonImageInUse, "manifest sha256:aa: evict: image is in use by a pod"),
			wantReq: &runtimev1.EvictImageRequest{Reference: "app:v1", Force: true},
			wantErr: []string{"a pod on this node uses app:v1", "nothing was evicted", "retry once the pod is gone", "manifest sha256:aa"},
			denyErr: []string{"the daemon refused"},
		},
		{
			name:    "an ambiguous refusal says to name a platform or the digest",
			args:    []string{"rm", "app:v1", "--force"},
			err:     evictRefusal(t, runtimev1.EvictErrorInfoDomain, runtimev1.EvictReasonReferenceAmbiguous, "app:v1: index entry is ambiguous"),
			wantReq: &runtimev1.EvictImageRequest{Reference: "app:v1", Force: true},
			wantErr: []string{"app:v1 names more than one image", "nothing was evicted", "retry with --platform", "by its digest"},
			denyErr: []string{"the daemon refused"},
		},
		{
			name:    "a roots-incomplete refusal points at the daemon log",
			args:    []string{"rm", "app:v1", "--force"},
			err:     evictRefusal(t, runtimev1.EvictErrorInfoDomain, runtimev1.EvictReasonRootsIncomplete, "roots incomplete"),
			wantReq: &runtimev1.EvictImageRequest{Reference: "app:v1", Force: true},
			wantErr: []string{"could not read every record that protects blobs", "nothing was deleted", "node log", "roots incomplete"},
			denyErr: []string{"the daemon refused"},
		},
		{
			name:    "an unknown reason keeps the generic line",
			args:    []string{"rm", "app:v1", "--force"},
			err:     evictRefusal(t, runtimev1.EvictErrorInfoDomain, "SOMETHING_NEW", "a newer refusal"),
			wantReq: &runtimev1.EvictImageRequest{Reference: "app:v1", Force: true},
			wantErr: []string{"the daemon refused", "a newer refusal"},
		},
		{
			name:    "a known reason in another domain keeps the generic line",
			args:    []string{"rm", "app:v1", "--force"},
			err:     evictRefusal(t, "example.com", runtimev1.EvictReasonImageInUse, "foreign refusal"),
			wantReq: &runtimev1.EvictImageRequest{Reference: "app:v1", Force: true},
			wantErr: []string{"the daemon refused", "foreign refusal"},
		},
		{
			name:    "a short hex digest is sent as a digest and its rejection is an error",
			args:    []string{"rm", "sha256:abc", "--force"},
			err:     status.Error(codes.InvalidArgument, "evict: malformed digest \"sha256:abc\""),
			wantReq: &runtimev1.EvictImageRequest{Digest: "sha256:abc", Force: true},
			wantErr: []string{"rm sha256:abc", "malformed digest"},
		},
		{
			name: "-o json is a stable machine form",
			args: []string{"rm", "app:v1", "-o", "json"},
			resp: &runtimev1.EvictImageResponse{
				ManifestDigest: rmManifest,
				RemovedDigests: []string{rmLayerA},
				Kept: []*runtimev1.EvictKeptBlob{
					{Digest: rmShared, Reason: runtimev1.EvictSkipReason_EVICT_SKIP_REASON_SHARED},
					{Digest: rmLayerB, Reason: runtimev1.EvictSkipReason(42)},
				},
				ReclaimedBytes: 1024,
			},
			wantReq: &runtimev1.EvictImageRequest{Reference: "app:v1"},
			wantJSON: `{
  "manifestDigest": "` + rmManifest + `",
  "dryRun": true,
  "removedDigests": [
    "` + rmLayerA + `"
  ],
  "kept": [
    {
      "digest": "` + rmShared + `",
      "reason": "shared"
    },
    {
      "digest": "` + rmLayerB + `",
      "reason": "reason(42)"
    }
  ],
  "reclaimedBytes": 1024
}
`,
		},
		{
			name:     "-o json of an empty eviction keeps its lists",
			args:     []string{"rm", "app:v1", "--force", "-o", "json"},
			resp:     &runtimev1.EvictImageResponse{ManifestDigest: rmManifest},
			wantReq:  &runtimev1.EvictImageRequest{Reference: "app:v1", Force: true},
			wantJSON: "{\n  \"manifestDigest\": \"" + rmManifest + "\",\n  \"dryRun\": false,\n  \"removedDigests\": [],\n  \"kept\": [],\n  \"reclaimedBytes\": 0\n}\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeEvictDaemon{evictResp: tc.resp, evictErr: tc.err}
			sock := serveFakeImages(t, fake)

			out, err := runImageCmd(t, append([]string{"--socket", sock}, tc.args...))
			if len(tc.wantErr) > 0 {
				if err == nil {
					t.Fatalf("exit 0, want a failure; output:\n%s", out)
				}
				for _, w := range tc.wantErr {
					if !strings.Contains(err.Error(), w) {
						t.Errorf("error %q does not say %q", err, w)
					}
				}
				for _, d := range tc.denyErr {
					if strings.Contains(err.Error(), d) {
						t.Errorf("error %q says %q", err, d)
					}
				}
			} else if err != nil {
				t.Fatalf("image rm: %v", err)
			}
			if tc.wantReq == nil {
				if len(fake.gotEvict) != 0 {
					t.Fatalf("EvictImage called %d time(s), want none", len(fake.gotEvict))
				}
			} else {
				if len(fake.gotEvict) != 1 {
					t.Fatalf("EvictImage called %d time(s), want 1", len(fake.gotEvict))
				}
				got := fake.gotEvict[0]
				if got.GetReference() != tc.wantReq.GetReference() || got.GetDigest() != tc.wantReq.GetDigest() ||
					got.GetForce() != tc.wantReq.GetForce() ||
					got.GetPlatform().GetOs() != tc.wantReq.GetPlatform().GetOs() ||
					got.GetPlatform().GetArchitecture() != tc.wantReq.GetPlatform().GetArchitecture() ||
					(got.GetPlatform() == nil) != (tc.wantReq.GetPlatform() == nil) {
					t.Errorf("request = %v, want %v", got, tc.wantReq)
				}
			}
			if fake.gotPrune != nil {
				t.Errorf("rm called PruneImages: %v", fake.gotPrune)
			}
			for _, w := range tc.wantOut {
				if !strings.Contains(out, w) {
					t.Errorf("output does not say %q:\n%s", w, out)
				}
			}
			for _, d := range tc.denyOut {
				if strings.Contains(out, d) {
					t.Errorf("output says %q:\n%s", d, out)
				}
			}
			if tc.wantJSON != "" && out != tc.wantJSON {
				t.Errorf("json output:\n%s\nwant:\n%s", out, tc.wantJSON)
			}
		})
	}
}

// TestImageRmBoundsKeptListing pins the text report of a target that keeps
// many blobs: counts by reason first, then at most twenty kept blobs, then how
// many more. -o json still lists every one.
func TestImageRmBoundsKeptListing(t *testing.T) {
	resp := &runtimev1.EvictImageResponse{ManifestDigest: rmManifest, RemovedDigests: []string{rmLayerA}}
	for i := range 25 {
		reason := runtimev1.EvictSkipReason_EVICT_SKIP_REASON_SHARED
		if i >= 18 {
			reason = runtimev1.EvictSkipReason_EVICT_SKIP_REASON_ROOTED
		}
		resp.Kept = append(resp.Kept, &runtimev1.EvictKeptBlob{Digest: fmt.Sprintf("sha256:%064x", i+1), Reason: reason})
	}
	fake := &fakeEvictDaemon{evictResp: resp}
	sock := serveFakeImages(t, fake)

	out, err := runImageCmd(t, []string{"--socket", sock, "rm", "app:v1", "--force"})
	if err != nil {
		t.Fatalf("image rm: %v", err)
	}
	lines := strings.Split(out, "\n")
	blobLines, firstBlob, rootedCount, sharedCount, more := 0, -1, -1, -1, -1
	for i, l := range lines {
		switch {
		case strings.HasPrefix(l, "  kept sha256:"):
			blobLines++
			if firstBlob < 0 {
				firstBlob = i
			}
		case l == "  kept 7 blob(s): rooted by an artifact record or operator root":
			rootedCount = i
		case l == "  kept 18 blob(s): shared with another cached image":
			sharedCount = i
		case l == "  ... and 5 more kept blob(s)":
			more = i
		}
	}
	if blobLines != 20 {
		t.Errorf("%d kept-blob lines, want 20:\n%s", blobLines, out)
	}
	if rootedCount < 0 || sharedCount < 0 || more < 0 {
		t.Fatalf("missing a count or the more line:\n%s", out)
	}
	if rootedCount > firstBlob || sharedCount > firstBlob || more < firstBlob {
		t.Errorf("counts must come before the blobs and the more line after:\n%s", out)
	}
	if !strings.Contains(out, "partial: 25 of 26 blob(s) kept") {
		t.Errorf("output does not say the partial total:\n%s", out)
	}

	jsonOut, err := runImageCmd(t, []string{"--socket", sock, "rm", "app:v1", "--force", "-o", "json"})
	if err != nil {
		t.Fatalf("image rm -o json: %v", err)
	}
	var doc rmReport
	if err := json.Unmarshal([]byte(jsonOut), &doc); err != nil {
		t.Fatalf("decode json: %v\n%s", err, jsonOut)
	}
	if len(doc.Kept) != 25 {
		t.Errorf("json lists %d kept blobs, want 25", len(doc.Kept))
	}
}

// TestImageRmParse pins the argument rules rm adds: exactly one target, and a
// platform only with a reference.
func TestImageRmParse(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"no target", []string{"rm"}, "rm requires the reference (or digest)"},
		{"two targets", []string{"rm", "a:v1", "b:v1"}, "exactly one reference"},
		{"platform with a digest", []string{"rm", rmManifest, "--platform", "linux/arm64"}, "--platform"},
		{"an unknown rendering", []string{"rm", "a:v1", "-o", "yaml"}, "json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseImageArgs(tc.args, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("parse %v: err = %v, want one saying %q", tc.args, err, tc.wantErr)
			}
		})
	}
}

// TestImageRmOldDaemonDeletesNothing is the version-skew gate: a daemon that
// predates EvictImage answers UNIMPLEMENTED, and rm says so, exits non-zero, and
// never reaches for the whole-cache prune or any other method instead.
func TestImageRmOldDaemonDeletesNothing(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"forced", []string{"rm", "--force", "app:v1"}},
		{"dry run", []string{"rm", "app:v1"}},
		{"forced by digest as json", []string{"rm", rmManifest, "--force", "-o", "json"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// fakeImagesDaemon serves no EvictImage: the embedded
			// UnimplementedImagesServer answers it exactly as an older daemon does.
			fake := &fakeImagesDaemon{pruneResp: &runtimev1.PruneImagesResponse{RemovedDigests: []string{rmLayerA}}}
			sock, calls := serveRecordingImages(t, fake)

			out, err := runImageCmd(t, append([]string{"--socket", sock, "--work-dir", t.TempDir()}, tc.args...))
			if err == nil {
				t.Fatalf("an old daemon exited 0; output:\n%s", out)
			}
			for _, w := range []string{"predates image rm", "nothing was evicted", "upgrade"} {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not say %q", err, w)
				}
			}
			if out != "" {
				t.Errorf("an old daemon printed a report:\n%s", out)
			}
			if fake.gotPrune != nil {
				t.Errorf("rm fell back to PruneImages: %v", fake.gotPrune)
			}
			if got, want := calls(), []string{runtimev1.Images_EvictImage_FullMethodName}; !slices.Equal(got, want) {
				t.Errorf("calls = %v, want only %v", got, want)
			}
		})
	}
}
