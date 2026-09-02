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
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// fakeImagesDaemon is a stand-in for runtimed's Images service. It records what
// the CLI asked for, which is how the gate proves the command is an RPC CLIENT —
// the request reaches a daemon and the daemon decides — rather than a second
// implementation of prune that happens to agree.
type fakeImagesDaemon struct {
	runtimev1.UnimplementedImagesServer

	gotPrune  *runtimev1.PruneImagesRequest
	pruneResp *runtimev1.PruneImagesResponse
	pruneErr  error
	listResp  *runtimev1.ListImagesResponse
	fsResp    *runtimev1.ImageFsInfoResponse

	// LoadImage is client-streaming, so the fake keeps the metadata frame apart
	// from the concatenated payload: the gate asserts on both independently.
	loadFirst  *runtimev1.LoadImageRequest
	loadBody   []byte
	loadChunks int
	loadResp   *runtimev1.LoadImageResponse
	loadErr    error

	// The B191 verbs. Each keeps the request it was handed, because the gate's
	// claim is that the CLI is a CLIENT — the daemon decides — and the only way
	// to see that is what reached the wire.
	gotPull     *runtimev1.PullImageRequest
	pullResp    *runtimev1.PullImageResponse
	pullErr     error
	gotTag      *runtimev1.TagImageRequest
	tagResp     *runtimev1.TagImageResponse
	tagErr      error
	gotUntag    *runtimev1.UntagImageRequest
	untagResp   *runtimev1.UntagImageResponse
	untagErr    error
	gotInspect  []*runtimev1.InspectImageRequest
	inspectResp *runtimev1.InspectImageResponse
	inspectErr  error

	// SaveImage is server-streaming, so the fake scripts the frames rather than
	// a response: saveChunks are the archive frames, saveTerminal is the terminal
	// frame (nil scripts a stream that ENDS WITHOUT ONE — the truncation the
	// client must refuse).
	gotSave      *runtimev1.SaveImageRequest
	saveChunks   [][]byte
	saveTerminal *runtimev1.SaveImageResponse
	saveErr      error
}

func (f *fakeImagesDaemon) PullImage(_ context.Context, req *runtimev1.PullImageRequest) (*runtimev1.PullImageResponse, error) {
	f.gotPull = req
	if f.pullErr != nil {
		return nil, f.pullErr
	}
	return f.pullResp, nil
}

func (f *fakeImagesDaemon) TagImage(_ context.Context, req *runtimev1.TagImageRequest) (*runtimev1.TagImageResponse, error) {
	f.gotTag = req
	if f.tagErr != nil {
		return nil, f.tagErr
	}
	return f.tagResp, nil
}

func (f *fakeImagesDaemon) UntagImage(_ context.Context, req *runtimev1.UntagImageRequest) (*runtimev1.UntagImageResponse, error) {
	f.gotUntag = req
	if f.untagErr != nil {
		return nil, f.untagErr
	}
	return f.untagResp, nil
}

func (f *fakeImagesDaemon) InspectImage(_ context.Context, req *runtimev1.InspectImageRequest) (*runtimev1.InspectImageResponse, error) {
	f.gotInspect = append(f.gotInspect, req)
	if f.inspectErr != nil {
		return nil, f.inspectErr
	}
	return f.inspectResp, nil
}

// SaveImage replays the scripted frames. A nil saveTerminal ends the stream
// after the chunks, which is exactly the truncated archive the wire contract
// says a client must discard.
func (f *fakeImagesDaemon) SaveImage(req *runtimev1.SaveImageRequest, stream runtimev1.Images_SaveImageServer) error {
	f.gotSave = req
	for _, chunk := range f.saveChunks {
		if err := stream.Send(&runtimev1.SaveImageResponse{Chunk: chunk}); err != nil {
			return err
		}
	}
	if f.saveErr != nil {
		return f.saveErr
	}
	if f.saveTerminal == nil {
		return nil
	}
	return stream.Send(f.saveTerminal)
}

func (f *fakeImagesDaemon) PruneImages(_ context.Context, req *runtimev1.PruneImagesRequest) (*runtimev1.PruneImagesResponse, error) {
	f.gotPrune = req
	if f.pruneErr != nil {
		return nil, f.pruneErr
	}
	return f.pruneResp, nil
}

func (f *fakeImagesDaemon) ListImages(context.Context, *runtimev1.ListImagesRequest) (*runtimev1.ListImagesResponse, error) {
	return f.listResp, nil
}

func (f *fakeImagesDaemon) ImageFsInfo(context.Context, *runtimev1.ImageFsInfoRequest) (*runtimev1.ImageFsInfoResponse, error) {
	return f.fsResp, nil
}

// LoadImage drains the ingest stream, recording the metadata frame and every
// payload byte. It answers exactly once, at the end, as the RPC's shape requires.
func (f *fakeImagesDaemon) LoadImage(stream runtimev1.Images_LoadImageServer) error {
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if f.loadFirst == nil {
			f.loadFirst = req
			continue
		}
		f.loadChunks++
		f.loadBody = append(f.loadBody, req.GetChunk()...)
	}
	if f.loadErr != nil {
		return f.loadErr
	}
	return stream.SendAndClose(f.loadResp)
}

// serveFakeImages serves fake on a REAL unix socket and returns its path, so the
// gate exercises the production dialer (dialRuntimed) end to end rather than a
// substituted transport.
func serveFakeImages(t *testing.T, fake *fakeImagesDaemon) string {
	t.Helper()
	// t.TempDir() embeds the test name and overflows darwin's 104-byte sun_path.
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
	gs := grpc.NewServer()
	runtimev1.RegisterImagesServer(gs, fake)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	return sock
}

func runImageCmd(t *testing.T, args []string) (string, error) {
	t.Helper()
	opts, err := parseImageArgs(args, io.Discard)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var out bytes.Buffer
	err = imageCommand(ctx, opts, &out, dialRuntimed)
	return out.String(), err
}

// TestImagePruneIsAnRPCClient is the k3sm-side gate for B130b: `k3sm image
// prune` is a CLIENT of the daemon's Images service. Deletion is daemon-owned —
// no upstream runtime lets anything outside the store owner unlink, and a CLI
// walking a live store cannot be made race-free by locking, because no lock it
// holds is also held across the daemon's pull commit.
func TestImagePruneIsAnRPCClient(t *testing.T) {
	t.Run("dry run is the default and the daemon is told so", func(t *testing.T) {
		fake := &fakeImagesDaemon{pruneResp: &runtimev1.PruneImagesResponse{
			RemovedDigests: []string{"sha256:aaaa", "sha256:bbbb"},
			ReclaimedBytes: 3 << 20,
		}}
		sock := serveFakeImages(t, fake)

		out, err := runImageCmd(t, []string{"--socket", sock, "prune"})
		if err != nil {
			t.Fatalf("image prune: %v", err)
		}
		if fake.gotPrune == nil {
			t.Fatalf("the daemon was never called — the CLI did not act as a client")
		}
		if !fake.gotPrune.GetDryRun() {
			t.Errorf("dry_run = false with no --force; the default must not delete")
		}
		for _, want := range []string{"would delete sha256:aaaa", "3.0 MiB", "dry run"} {
			if !strings.Contains(out, want) {
				t.Errorf("output missing %q:\n%s", want, out)
			}
		}
	})

	t.Run("--force asks the daemon to unlink", func(t *testing.T) {
		fake := &fakeImagesDaemon{pruneResp: &runtimev1.PruneImagesResponse{
			RemovedDigests: []string{"sha256:cccc"},
			ReclaimedBytes: 1024,
		}}
		sock := serveFakeImages(t, fake)

		out, err := runImageCmd(t, []string{"--socket", sock, "prune", "--force"})
		if err != nil {
			t.Fatalf("image prune --force: %v", err)
		}
		if fake.gotPrune.GetDryRun() {
			t.Errorf("dry_run = true with --force")
		}
		if !strings.Contains(out, "deleted sha256:cccc") || strings.Contains(out, "dry run") {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	t.Run("typed skip reasons are surfaced, not swallowed", func(t *testing.T) {
		fake := &fakeImagesDaemon{pruneResp: &runtimev1.PruneImagesResponse{
			Skipped: []*runtimev1.SkippedBlob{
				{Digest: "sha256:1", Reason: runtimev1.PruneSkipReason_PRUNE_SKIP_REASON_IN_USE},
				{Digest: "sha256:2", Reason: runtimev1.PruneSkipReason_PRUNE_SKIP_REASON_IN_USE},
				{Digest: "sha256:3", Reason: runtimev1.PruneSkipReason_PRUNE_SKIP_REASON_LEASED},
			},
		}}
		sock := serveFakeImages(t, fake)

		out, err := runImageCmd(t, []string{"--socket", sock, "prune"})
		if err != nil {
			t.Fatalf("image prune: %v", err)
		}
		if !strings.Contains(out, "in use by a pod") || !strings.Contains(out, "an ingest is in flight") {
			t.Errorf("typed skip reasons not rendered:\n%s", out)
		}
		// The counts matter: an operator asking "why is my disk full" needs the
		// shape of the answer, not a wall of digests.
		if !strings.Contains(out, "in use by a pod        2") && !strings.Contains(out, "2\n") {
			t.Errorf("skip counts not rendered:\n%s", out)
		}
	})

	t.Run("the daemon's fail-closed refusal reaches the operator", func(t *testing.T) {
		fake := &fakeImagesDaemon{pruneErr: status.Error(codes.FailedPrecondition,
			"image: reachability root set is incomplete: pod \"pod-x\": no images.json")}
		sock := serveFakeImages(t, fake)

		_, err := runImageCmd(t, []string{"--socket", sock, "prune"})
		if err == nil {
			t.Fatalf("a refused prune exited 0")
		}
		if !strings.Contains(err.Error(), "the daemon refused") || !strings.Contains(err.Error(), "pod-x") {
			t.Errorf("refusal not surfaced actionably: %v", err)
		}
	})

	t.Run("an absent daemon is a legible error, not a local fallback", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "k3i")
		if err != nil {
			t.Fatalf("MkdirTemp: %v", err)
		}
		defer os.RemoveAll(dir)
		_, err = runImageCmd(t, []string{"--socket", filepath.Join(dir, "absent.sock"), "prune", "--timeout", "2s"})
		if err == nil {
			t.Fatalf("prune succeeded with no daemon listening — the CLI must never fall back to walking the store itself")
		}
		if !strings.Contains(err.Error(), "cannot reach runtimed") {
			t.Errorf("unhelpful error for an absent daemon: %v", err)
		}
	})
}

// TestImageArgParsing pins the argv contract, including the flag-ordering trap
// stdlib flag sets for anyone who writes `k3sm image prune --force`.
func TestImageArgParsing(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
		check   func(*testing.T, imageOptions)
	}{
		{name: "no subcommand", args: nil, wantErr: "exactly one subcommand"},
		{name: "two subcommands", args: []string{"prune", "ls"}, wantErr: "exactly one subcommand"},
		{name: "unknown subcommand", args: []string{"purge"}, wantErr: "unknown subcommand"},
		{name: "non-positive timeout", args: []string{"prune", "--timeout", "0"}, wantErr: "must be positive"},
		{
			name: "flags after the subcommand are accepted",
			args: []string{"prune", "--force"},
			check: func(t *testing.T, o imageOptions) {
				if o.subcommand != "prune" || !o.force {
					t.Errorf("parsed %+v; want prune with force", o)
				}
			},
		},
		{
			name: "the socket defaults to the daemon's own",
			args: []string{"ls"},
			check: func(t *testing.T, o imageOptions) {
				if o.socket == "" {
					t.Errorf("socket default is empty")
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o, err := parseImageArgs(tc.args, io.Discard)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v; want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseImageArgs: %v", err)
			}
			tc.check(t, o)
		})
	}
}

// TestImageLsAndDf covers the two read subcommands' rendering, including the
// clonefile caveat df must not omit.
func TestImageLsAndDf(t *testing.T) {
	fake := &fakeImagesDaemon{
		listResp: &runtimev1.ListImagesResponse{Images: []*runtimev1.Image{{
			Manifest: &runtimev1.ImageManifest{
				Reference: "example.test/app:v1",
				Config:    &runtimev1.Descriptor{Digest: "sha256:cfg"},
				Layers:    []*runtimev1.Descriptor{{Digest: "sha256:l1"}, {Digest: "sha256:l2"}},
			},
		}}},
		fsResp: &runtimev1.ImageFsInfoResponse{
			StoreBytes: 2 << 30,
			Filesystems: []*runtimev1.FilesystemUsage{{
				Mountpoint: "/var/lib/k3sm", UsedBytes: 1 << 30,
				CapacityBytes: 100 << 30, AvailableBytes: 40 << 30,
			}},
		},
	}
	sock := serveFakeImages(t, fake)

	out, err := runImageCmd(t, []string{"--socket", sock, "ls"})
	if err != nil {
		t.Fatalf("image ls: %v", err)
	}
	for _, want := range []string{"example.test/app:v1", "sha256:cfg", "REFERENCE"} {
		if !strings.Contains(out, want) {
			t.Errorf("ls output missing %q:\n%s", want, out)
		}
	}

	out, err = runImageCmd(t, []string{"--socket", sock, "df"})
	if err != nil {
		t.Fatalf("image df: %v", err)
	}
	for _, want := range []string{"/var/lib/k3sm", "2.0 GiB", "40.0 GiB available", "APFS clones share extents"} {
		if !strings.Contains(out, want) {
			t.Errorf("df output missing %q:\n%s", want, out)
		}
	}
}

// TestHumanBytes pins the byte rendering, which the prune summary an operator
// acts on is entirely made of.
func TestHumanBytes(t *testing.T) {
	tests := []struct {
		in   uint64
		want string
	}{
		{0, "0 B"},
		{1023, "1023 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{3 << 20, "3.0 MiB"},
		{2 << 30, "2.0 GiB"},
	}
	for _, tc := range tests {
		if got := humanBytes(tc.in); got != tc.want {
			t.Errorf("humanBytes(%d) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

// TestImageRPCErrorMapping pins that each daemon status becomes an operator
// message that names the right remedy — a refusal is not an internal error, and
// an unreachable daemon is not a missing feature.
func TestImageRPCErrorMapping(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"unimplemented", status.Error(codes.Unimplemented, "no image service"), "does not serve the image service"},
		{"refused", status.Error(codes.FailedPrecondition, "roots incomplete"), "the daemon refused"},
		{"unavailable", status.Error(codes.Unavailable, "connection refused"), "cannot reach runtimed at /sock"},
		{"plain error", errors.New("boom"), "boom"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := imageRPCError("prune images", "/sock", tc.err)
			if !strings.Contains(got.Error(), tc.want) {
				t.Errorf("imageRPCError = %v; want one containing %q", got, tc.want)
			}
		})
	}
}
