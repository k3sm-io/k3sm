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
	"archive/tar"
	"bytes"
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"

	runtimev1 "k3sm.io/apis/runtime/v1"

	"k3sm.io/k3sm/pkg/buildledger"
	"k3sm.io/k3sm/pkg/oci"
	"k3sm.io/k3sm/pkg/registrysvc"
)

// registryPushes is an imagePusher that remembers every target it was handed.
type registryPushes struct {
	targets []string
	indexes int
}

func (p *registryPushes) push(_ context.Context, ref name.Reference, b built, _ string) error {
	p.targets = append(p.targets, ref.String())
	if b.index != nil {
		p.indexes++
	}
	return nil
}

// withNodeRegistry writes this node's push credential for a registry on
// loopback port 6450 into a fresh work dir and points the build at it.
func withNodeRegistry(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(registrysvc.StateDir(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := registrysvc.WriteCredential(dir, registrysvc.Credential{
		Address: "127.0.0.1:6450", Username: "k3sm", Password: "secret",
	}); err != nil {
		t.Fatalf("write credential: %v", err)
	}
	t.Setenv("K3SM_WORK_DIR", dir)
	return dir
}

// testIndex wraps img in a one-child image index.
func testIndex(t *testing.T, img ggcrv1.Image) ggcrv1.ImageIndex {
	t.Helper()
	return mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: img})
}

// tarDir tars the directory dir, the way an operator tars a layout to import.
func tarDir(t *testing.T, dir string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil || rel == "." {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
	if err != nil {
		t.Fatalf("tar %s: %v", dir, err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

// TestBuildRecordsIntoRegistryNotNodeStore pins that the cluster registry is
// the one image store: `k3sm build`, `k3sm image load` and `k3sm image import`
// push to it under the normalised registry-k3sm:6450 name, never stream into
// this node's store with LoadImage, and then warm this node's cache through the
// runtime's ordinary pull.
func TestBuildRecordsIntoRegistryNotNodeStore(t *testing.T) {
	t.Run("build", func(t *testing.T) {
		cases := []struct {
			tag, wantPush, wantRecorded string
		}{
			{tag: "app:v1", wantPush: "localhost:6450/app:v1", wantRecorded: "registry-k3sm:6450/app:v1"},
			{tag: "localhost:6450/team/app:v2", wantPush: "localhost:6450/team/app:v2", wantRecorded: "registry-k3sm:6450/team/app:v2"},
			{tag: "registry-k3sm:6450/team/app:v3", wantPush: "localhost:6450/team/app:v3", wantRecorded: "registry-k3sm:6450/team/app:v3"},
		}
		for _, tc := range cases {
			t.Run(tc.tag, func(t *testing.T) {
				withNodeRegistry(t)
				fake := &fakeImagesDaemon{pullResp: &runtimev1.PullImageResponse{Image: &runtimev1.Image{}}}
				sock := serveFakeImages(t, fake)
				pushes := &registryPushes{}
				record := recordInRegistry(pushes.push, warmNodeCache(dialRuntimed, sock))
				ledger := buildledger.New(t.TempDir())

				ctxDir := writeCtx(t, "FROM scratch\nCOPY app /app")
				var out bytes.Buffer
				err := buildRecorded(t.Context(), ledger, buildOptions{
					dockerfile: filepath.Join(ctxDir, "Dockerfile"),
					tag:        tc.tag,
					format:     "docker",
					contextDir: ctxDir,
				}, &out, engineBuildWith, record, noPush)
				if err != nil {
					t.Fatalf("build: %v\n%s", err, out.String())
				}
				if fake.loadCalls != 0 {
					t.Errorf("build called LoadImage %d time(s); the node store must receive no load", fake.loadCalls)
				}
				if len(pushes.targets) != 1 || pushes.targets[0] != tc.wantPush {
					t.Errorf("registry pushes = %v, want exactly [%s]", pushes.targets, tc.wantPush)
				}
				if fake.pullCalls != 1 || fake.gotPull.GetReference() != tc.wantRecorded {
					t.Errorf("warm pulls = %d of %q, want one of %q", fake.pullCalls, fake.gotPull.GetReference(), tc.wantRecorded)
				}
				if !strings.Contains(out.String(), tc.wantRecorded) {
					t.Errorf("the summary does not name the registry reference %s:\n%s", tc.wantRecorded, out.String())
				}
				recs, err := ledger.List()
				if err != nil || len(recs) != 1 {
					t.Fatalf("ledger = %v, %v; want one record", recs, err)
				}
				if recs[0].Reference != tc.wantRecorded || !strings.HasPrefix(recs[0].ImageDigest, "sha256:") {
					t.Errorf("ledger records %q %q, want the registry reference %q and a digest", recs[0].Reference, recs[0].ImageDigest, tc.wantRecorded)
				}
			})
		}
	})

	t.Run("a multi-platform build pushes the whole index", func(t *testing.T) {
		withNodeRegistry(t)
		fake := &fakeImagesDaemon{pullResp: &runtimev1.PullImageResponse{Image: &runtimev1.Image{}}}
		sock := serveFakeImages(t, fake)
		pushes := &registryPushes{}
		record := recordInRegistry(pushes.push, warmNodeCache(dialRuntimed, sock))
		img, err := random.Image(64, 1)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := registryReference("app:multi")
		if err != nil {
			t.Fatal(err)
		}
		idx := testIndex(t, img)
		if err := record(t.Context(), ref, built{image: img, index: idx}); err != nil {
			t.Fatalf("record: %v", err)
		}
		if pushes.indexes != 1 {
			t.Errorf("index pushes = %d, want 1", pushes.indexes)
		}
		if fake.loadCalls != 0 {
			t.Errorf("LoadImage called %d time(s)", fake.loadCalls)
		}
	})

	t.Run("load and import", func(t *testing.T) {
		img, err := random.Image(256, 2)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		saveTar := filepath.Join(dir, "save.tar")
		if err := (oci.TarballSink{Path: saveTar}).Write(t.Context(), name.MustParseReference("example.test/app:v1").(name.Tag), img); err != nil {
			t.Fatalf("write docker-save: %v", err)
		}
		layoutDir := filepath.Join(dir, "layout")
		if err := (oci.LayoutSink{Path: layoutDir}).Write(t.Context(), name.MustParseReference("example.test/team/app:v2").(name.Tag), img); err != nil {
			t.Fatalf("write layout: %v", err)
		}
		layoutTar := writeFixture(t, tarDir(t, layoutDir))

		cases := []struct {
			verb, archive, wantPush, wantRecorded string
			extra                                 []string
		}{
			{verb: "load", archive: saveTar, wantPush: "localhost:6450/app:v1", wantRecorded: "registry-k3sm:6450/app:v1"},
			{verb: "import", archive: layoutTar, wantPush: "localhost:6450/team/app:v2", wantRecorded: "registry-k3sm:6450/team/app:v2"},
			{verb: "load", archive: saveTar, extra: []string{"--reference", "mine:pinned"}, wantPush: "localhost:6450/mine:pinned", wantRecorded: "registry-k3sm:6450/mine:pinned"},
		}
		for _, tc := range cases {
			t.Run(tc.verb+" "+tc.wantRecorded, func(t *testing.T) {
				workDir := withNodeRegistry(t)
				fake := &fakeImagesDaemon{pullResp: &runtimev1.PullImageResponse{Image: &runtimev1.Image{}}}
				sock := serveFakeImages(t, fake)
				pushes := &registryPushes{}
				old := ingestPusher
				ingestPusher = pushes.push
				t.Cleanup(func() { ingestPusher = old })

				args := append([]string{"--socket", sock, "--work-dir", workDir, tc.verb, tc.archive}, tc.extra...)
				out, err := runImageCmd(t, args)
				if err != nil {
					t.Fatalf("image %s: %v\n%s", tc.verb, err, out)
				}
				if fake.loadCalls != 0 {
					t.Errorf("image %s called LoadImage %d time(s)", tc.verb, fake.loadCalls)
				}
				if len(pushes.targets) != 1 || pushes.targets[0] != tc.wantPush {
					t.Errorf("registry pushes = %v, want exactly [%s]", pushes.targets, tc.wantPush)
				}
				if fake.pullCalls != 1 || fake.gotPull.GetReference() != tc.wantRecorded {
					t.Errorf("warm pulls = %d of %q, want one of %q", fake.pullCalls, fake.gotPull.GetReference(), tc.wantRecorded)
				}
				if !strings.Contains(out, tc.wantRecorded) {
					t.Errorf("output does not name %s:\n%s", tc.wantRecorded, out)
				}
			})
		}
	})
}
