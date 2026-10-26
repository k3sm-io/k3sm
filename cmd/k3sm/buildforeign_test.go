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
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/random"

	runtimev1 "k3sm.io/apis/runtime/v1"

	"k3sm.io/k3sm/pkg/buildledger"
	"k3sm.io/k3sm/pkg/oci"
)

// TestForeignTagRefusedWithoutPush pins the foreign-registry rule: build, load
// and import keep an image in the cluster registry, so a tag naming any other
// registry is refused unless --push sends it there, and with --push it goes
// there ONLY. A bare tag, a loopback tag and the flat registry-k3sm:6450 name
// all still mean the cluster registry.
func TestForeignTagRefusedWithoutPush(t *testing.T) {
	const foreign = "ghcr.io/org/app:v1"

	t.Run("build refuses a foreign tag at parse time", func(t *testing.T) {
		withNodeRegistry(t)
		ctxDir := writeCtx(t, "FROM scratch\nCOPY app /app")
		_, err := parseBuildArgs([]string{"-t", foreign, ctxDir}, io.Discard)
		if !errors.Is(err, errForeignTag) {
			t.Fatalf("parse err = %v, want errForeignTag", err)
		}
		// Another registry on this Mac, on a port that is not this node's
		// registry, is another registry too.
		if _, err := parseBuildArgs([]string{"-t", "localhost:5000/app:v1", ctxDir}, io.Discard); !errors.Is(err, errForeignTag) {
			t.Errorf("localhost:5000 without --push = %v, want errForeignTag", err)
		}
		for _, want := range []string{"registry-k3sm:6450/org/app:v1", "--push"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal does not name %q: %v", want, err)
			}
		}
		for _, ok := range [][]string{
			{"-t", foreign, "--push", ctxDir},
			{"-t", foreign, "--no-record", "--output", filepath.Join(t.TempDir(), "a.tar"), ctxDir},
			{"-t", "app:v1", ctxDir},
			{"-t", "localhost:6450/app:v1", ctxDir},
			{"-t", "registry-k3sm:6450/app:v1", ctxDir},
			{"-t", "localhost:5000/app:v1", "--push", ctxDir},
		} {
			if _, err := parseBuildArgs(ok, io.Discard); err != nil {
				t.Errorf("parseBuildArgs(%v) = %v, want accepted", ok, err)
			}
		}
	})

	t.Run("build refuses a foreign tag before anything is recorded", func(t *testing.T) {
		withNodeRegistry(t)
		fake := &fakeImagesDaemon{pullResp: &runtimev1.PullImageResponse{Image: &runtimev1.Image{}}}
		sock := serveFakeImages(t, fake)
		pushes := &registryPushes{}
		ctxDir := writeCtx(t, "FROM scratch\nCOPY app /app")
		var out bytes.Buffer
		err := buildRecorded(t.Context(), buildledger.New(t.TempDir()), buildOptions{
			dockerfile: filepath.Join(ctxDir, "Dockerfile"), tag: foreign, format: "docker", contextDir: ctxDir,
		}, &out, engineBuildWith, recordInRegistry(pushes.push, warmNodeCache(dialRuntimed, sock), io.Discard), pushes.push)
		if !errors.Is(err, errForeignTag) {
			t.Fatalf("build err = %v, want errForeignTag", err)
		}
		if len(pushes.targets) != 0 || fake.pullCalls != 0 {
			t.Errorf("a refused build pushed %v and warmed %d time(s)", pushes.targets, fake.pullCalls)
		}
	})

	t.Run("build --push sends a foreign tag there only", func(t *testing.T) {
		withNodeRegistry(t)
		fake := &fakeImagesDaemon{pullResp: &runtimev1.PullImageResponse{Image: &runtimev1.Image{}}}
		sock := serveFakeImages(t, fake)
		recorded := &registryPushes{}
		pushed := &registryPushes{}
		ctxDir := writeCtx(t, "FROM scratch\nCOPY app /app")
		var out bytes.Buffer
		err := buildRecorded(t.Context(), buildledger.New(t.TempDir()), buildOptions{
			dockerfile: filepath.Join(ctxDir, "Dockerfile"), tag: foreign, push: true, format: "docker", contextDir: ctxDir,
		}, &out, engineBuildWith, recordInRegistry(recorded.push, warmNodeCache(dialRuntimed, sock), io.Discard), pushed.push)
		if err != nil {
			t.Fatalf("build: %v\n%s", err, out.String())
		}
		if len(recorded.targets) != 0 {
			t.Errorf("the cluster registry received %v; a foreign --push tag must not be recorded there", recorded.targets)
		}
		if len(pushed.targets) != 1 || pushed.targets[0] != foreign {
			t.Errorf("pushes = %v, want exactly [%s]", pushed.targets, foreign)
		}
		if fake.pullCalls != 0 {
			t.Errorf("warmed this node's cache %d time(s) for an image not in the cluster registry", fake.pullCalls)
		}
		if strings.Contains(out.String(), "registry-k3sm") {
			t.Errorf("the summary names a cluster-registry copy that was never made:\n%s", out.String())
		}
	})

	t.Run("load and import refuse a foreign reference", func(t *testing.T) {
		img, err := random.Image(128, 1)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		saveTar := filepath.Join(dir, "save.tar")
		if err := (oci.TarballSink{Path: saveTar}).Write(t.Context(), name.MustParseReference(foreign).(name.Tag), img); err != nil {
			t.Fatal(err)
		}
		layoutDir := filepath.Join(dir, "layout")
		if err := (oci.LayoutSink{Path: layoutDir}).Write(t.Context(), name.MustParseReference(foreign).(name.Tag), img); err != nil {
			t.Fatal(err)
		}
		layoutTar := writeFixture(t, tarDir(t, layoutDir))
		for _, tc := range []struct{ verb, archive string }{{"load", saveTar}, {"import", layoutTar}} {
			t.Run(tc.verb, func(t *testing.T) {
				workDir := withNodeRegistry(t)
				fake := &fakeImagesDaemon{pullResp: &runtimev1.PullImageResponse{Image: &runtimev1.Image{}}}
				sock := serveFakeImages(t, fake)
				pushes := &registryPushes{}
				old := ingestPusher
				ingestPusher = pushes.push
				t.Cleanup(func() { ingestPusher = old })

				_, err := runImageCmd(t, []string{"--socket", sock, "--work-dir", workDir, tc.verb, tc.archive})
				if !errors.Is(err, errForeignTag) {
					t.Fatalf("image %s err = %v, want errForeignTag", tc.verb, err)
				}
				if !strings.Contains(err.Error(), "registry-k3sm:6450/org/app:v1") {
					t.Errorf("the refusal does not name the cluster spelling: %v", err)
				}
				if len(pushes.targets) != 0 || fake.pullCalls != 0 {
					t.Errorf("a refused %s pushed %v and warmed %d time(s)", tc.verb, pushes.targets, fake.pullCalls)
				}

				out, err := runImageCmd(t, []string{"--socket", sock, "--work-dir", workDir, tc.verb, tc.archive, "--reference", "registry-k3sm:6450/org/app:v1"})
				if err != nil {
					t.Fatalf("image %s --reference: %v\n%s", tc.verb, err, out)
				}
				if len(pushes.targets) != 1 || pushes.targets[0] != "localhost:6450/org/app:v1" {
					t.Errorf("pushes = %v, want exactly [localhost:6450/org/app:v1]", pushes.targets)
				}
			})
		}
	})
}
