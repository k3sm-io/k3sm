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
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"k3sm.io/k3sm/pkg/oci"
)

// TestParsePlatforms pins the --platform grammar, including the two shapes that
// are refused because they ask for two builders at once.
func TestParsePlatforms(t *testing.T) {
	ok := []struct {
		name string
		spec string
		want []string
	}{
		{"the native default", oci.DefaultPlatform, []string{"darwin/arm64"}},
		{"one Linux target", "linux/arm64", []string{"linux/arm64"}},
		{"a variant", "linux/arm/v7", []string{"linux/arm/v7"}},
		{"several, in the order asked for", "linux/arm64,linux/amd64", []string{"linux/arm64", "linux/amd64"}},
		{"whitespace around a comma", "linux/arm64, linux/amd64", []string{"linux/arm64", "linux/amd64"}},
	}
	for _, tc := range ok {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePlatforms(tc.spec)
			if err != nil {
				t.Fatalf("parsePlatforms(%q) = %v", tc.spec, err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("parsePlatforms(%q) = %v, want %v", tc.spec, got, tc.want)
			}
		})
	}

	bad := []struct {
		name string
		spec string
		want string
	}{
		{"an empty entry", "linux/arm64,", "empty platform"},
		{"no arch", "linux", "os/arch"},
		{"an empty component", "linux/", "os/arch"},
		{"too many components", "linux/arm64/v8/extra", "os/arch"},
		{"a duplicate", "linux/arm64,linux/arm64", "twice"},
		{"darwin mixed with linux", "darwin/arm64,linux/arm64", "one of them"},
		{"two darwin targets", "darwin/arm64,darwin/amd64", "one platform"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parsePlatforms(tc.spec)
			if err == nil {
				t.Fatalf("parsePlatforms(%q) was accepted", tc.spec)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

// TestBuildPlatformRouting is the routing matrix: which builder each
// (--platform, Dockerfile) pair reaches, and what buildx is asked to build.
//
// The load-bearing row is "a COPY-only Dockerfile with an explicit Linux
// target": the native packager copies host files into a DARWIN image and cannot
// produce a Linux one, so the target — not the Dockerfile — decides. Without
// that row a `--platform linux/arm64` build would silently return a darwin
// image, which is the divergence this matrix exists to prevent.
func TestBuildPlatformRouting(t *testing.T) {
	const copyOnly = "FROM scratch\nCOPY app /app"
	const withRun = "FROM scratch\nCOPY app /app\nRUN ./app --init"
	const multiStage = "FROM scratch\nCOPY app /app\nFROM scratch\nCOPY app /app"

	cases := []struct {
		name         string
		dockerfile   string
		platform     string
		platformSet  bool
		wantEngine   bool
		wantPlatform string
		wantErr      error
	}{
		{name: "unset + COPY-only builds natively", dockerfile: copyOnly},
		{name: "unset + RUN builds the guest platform on the engine", dockerfile: withRun,
			wantEngine: true, wantPlatform: enginePlatform},
		{name: "an explicit darwin target + COPY-only stays native", dockerfile: copyOnly,
			platform: oci.DefaultPlatform, platformSet: true},
		{name: "an explicit Linux target + COPY-only goes to the engine", dockerfile: copyOnly,
			platform: "linux/arm64", platformSet: true, wantEngine: true, wantPlatform: "linux/arm64"},
		{name: "an explicit Linux target + RUN goes to the engine", dockerfile: withRun,
			platform: "linux/arm64", platformSet: true, wantEngine: true, wantPlatform: "linux/arm64"},
		{name: "an explicit Linux target + multi-stage goes to the engine", dockerfile: multiStage,
			platform: "linux/arm64", platformSet: true, wantEngine: true, wantPlatform: "linux/arm64"},
		{name: "several Linux targets + COPY-only reach buildx as a list", dockerfile: copyOnly,
			platform: "linux/arm64,linux/amd64", platformSet: true, wantEngine: true,
			wantPlatform: "linux/arm64,linux/amd64"},
		{name: "a foreign arch + RUN is refused before the engine starts", dockerfile: withRun,
			platform: "linux/amd64", platformSet: true, wantErr: errNoEmulation},
		{name: "a foreign arch inside a list + RUN is refused too", dockerfile: withRun,
			platform: "linux/arm64,linux/amd64", platformSet: true, wantErr: errNoEmulation},
		{name: "a foreign arch + COPY-only is attempted", dockerfile: copyOnly,
			platform: "linux/amd64", platformSet: true, wantEngine: true, wantPlatform: "linux/amd64"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctxDir := writeCtx(t, tc.dockerfile)
			platforms := []string{oci.DefaultPlatform}
			if tc.platform != "" {
				parsed, err := parsePlatforms(tc.platform)
				if err != nil {
					t.Fatalf("parsePlatforms(%q): %v", tc.platform, err)
				}
				platforms = parsed
			}
			o := buildOptions{
				dockerfile:  filepath.Join(ctxDir, "Dockerfile"),
				tag:         "example.com/app:v1",
				format:      "docker",
				platforms:   platforms,
				platformSet: tc.platformSet,
				contextDir:  ctxDir,
			}

			routed := 0
			var gotPlatform string
			engine := func(_ context.Context, eo buildOptions, _ io.Writer) error {
				routed++
				p, err := engineBuildPlatform(eo)
				if err != nil {
					return err
				}
				gotPlatform = p
				return nil
			}

			err := buildWith(t.Context(), o, io.Discard, engine, noStore, noPush)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("buildWith = %v, want %v", err, tc.wantErr)
				}
				if routed != 0 {
					t.Errorf("the engine was started for a build it cannot perform")
				}
				return
			}
			if err != nil {
				t.Fatalf("buildWith: %v", err)
			}
			if tc.wantEngine {
				if routed != 1 {
					t.Fatalf("engine calls = %d, want 1", routed)
				}
				if gotPlatform != tc.wantPlatform {
					t.Errorf("buildx was asked for %q, want %q", gotPlatform, tc.wantPlatform)
				}
				return
			}
			if routed != 0 {
				t.Fatalf("engine calls = %d, want 0", routed)
			}
		})
	}

	// The refusal has to name the architecture and the reason, because "exec
	// format error" from runc twenty minutes into a build names neither.
	t.Run("the emulation refusal names the architecture and the way out", func(t *testing.T) {
		ctxDir := writeCtx(t, withRun)
		platforms, err := parsePlatforms("linux/amd64")
		if err != nil {
			t.Fatal(err)
		}
		err = buildWith(t.Context(), buildOptions{
			dockerfile:  filepath.Join(ctxDir, "Dockerfile"),
			tag:         "example.com/app:v1",
			format:      "docker",
			platforms:   platforms,
			platformSet: true,
			contextDir:  ctxDir,
		}, io.Discard, engineBuild, noStore, noPush)
		if !errors.Is(err, errNoEmulation) {
			t.Fatalf("buildWith = %v, want errNoEmulation", err)
		}
		for _, want := range []string{"amd64", "arm64", "no emulator", "cross-compiled"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal does not mention %q: %v", want, err)
			}
		}
	})

	t.Run("the darwin-on-the-engine refusal survives", func(t *testing.T) {
		// #307's named refusal: a Dockerfile the engine must build cannot be
		// asked for a darwin target, because the engine produces Linux images.
		_, err := engineBuildPlatform(buildOptions{platforms: []string{oci.DefaultPlatform}, platformSet: true})
		if err == nil {
			t.Fatal("an explicit darwin target was accepted on the engine path")
		}
	})
}

// TestSelectStoreImage pins WHICH image of a multi-platform build the node's
// store records.
//
// The choice feeds the summary's `kubectl run app --image=<tag>` line, which is
// only true for an image a Pod on this node can run — so it is the platform this
// node's Linux guests run, and a build that produced none is refused rather than
// recorded under a name that would not start.
func TestSelectStoreImage(t *testing.T) {
	t.Run("picks the platform this node runs", func(t *testing.T) {
		idx := multiPlatformIndex(t, "linux/amd64", "linux/arm64")
		img, platform, err := selectStoreImage(idx, enginePlatform)
		if err != nil {
			t.Fatalf("selectStoreImage: %v", err)
		}
		if platform != enginePlatform {
			t.Errorf("selected %q, want %q", platform, enginePlatform)
		}
		cfg, err := img.ConfigFile()
		if err != nil {
			t.Fatal(err)
		}
		if got := cfg.OS + "/" + cfg.Architecture; got != enginePlatform {
			t.Errorf("the selected image is %s, want %s", got, enginePlatform)
		}
	})

	t.Run("refuses a build with nothing this node can run", func(t *testing.T) {
		idx := multiPlatformIndex(t, "linux/amd64", "linux/arm/v7")
		_, _, err := selectStoreImage(idx, enginePlatform)
		if !errors.Is(err, errStorePlatform) {
			t.Fatalf("selectStoreImage = %v, want errStorePlatform", err)
		}
		for _, want := range []string{enginePlatform, "linux/amd64", "--output"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal does not mention %q: %v", want, err)
			}
		}
	})
}

// TestMultiPlatformDelivery pins what a multi-platform build DELIVERS: the
// index to --output and --push, one image to the store, and a summary that says
// which platform the store got.
func TestMultiPlatformDelivery(t *testing.T) {
	noDocker := t.TempDir()
	t.Setenv("HOME", noDocker)
	t.Setenv("DOCKER_CONFIG", noDocker)
	t.Setenv(registryTokenEnv, "")
	t.Setenv("K3SM_WORK_DIR", t.TempDir())

	idx := multiPlatformIndex(t, "linux/arm64", "linux/amd64")
	img, storePlatform, err := selectStoreImage(idx, enginePlatform)
	if err != nil {
		t.Fatalf("selectStoreImage: %v", err)
	}
	b := built{image: img, index: idx, platforms: []string{"linux/arm64", "linux/amd64"}, storePlatform: storePlatform}

	host, _ := startRegistry(t, "")
	target := host + "/team/app:v1"
	ref := mustTag(t, target)
	out := filepath.Join(t.TempDir(), "layout")
	store := &recordingStore{}
	var log bytes.Buffer

	o := buildOptions{tag: target, output: out, format: "oci", push: true,
		platforms: []string{"linux/arm64", "linux/amd64"}, platformSet: true}
	if err := deliver(t.Context(), o, ref, b, &log, store.record, pushBuilt, "", ""); err != nil {
		t.Fatalf("deliver: %v", err)
	}

	// The store holds ONE image, and it is the one this node's guests run.
	if len(store.calls) != 1 {
		t.Fatalf("store recordings = %v, want exactly one", store.calls)
	}
	if !strings.Contains(log.String(), "built:  linux/arm64, linux/amd64 (the store recorded linux/arm64)") {
		t.Errorf("the summary does not report the platforms and the store's pick:\n%s", log.String())
	}

	// --output carries every platform: the layout indexes the index.
	p, err := layout.FromPath(out)
	if err != nil {
		t.Fatalf("read the output layout: %v", err)
	}
	written, err := p.ImageIndex()
	if err != nil {
		t.Fatal(err)
	}
	if got := indexPlatforms(t, childIndex(t, written)); !slices.Equal(got, []string{"linux/arm64", "linux/amd64"}) {
		t.Errorf("--output holds %v, want both platforms", got)
	}

	// And so does the push: the registry serves the whole index.
	pulled := remoteIndex(t, target)
	if got := indexPlatforms(t, pulled); !slices.Equal(got, []string{"linux/arm64", "linux/amd64"}) {
		t.Errorf("the registry holds %v, want both platforms", got)
	}
	wantDigest, err := idx.Digest()
	if err != nil {
		t.Fatal(err)
	}
	gotDigest, err := pulled.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if gotDigest != wantDigest {
		t.Errorf("the registry holds index %s, want %s", gotDigest, wantDigest)
	}
}

// TestMultiPlatformFormat pins that a docker-save tarball is refused for a
// multi-platform build at PARSE time — before a build whose result it could not
// hold without dropping every platform but one.
func TestMultiPlatformFormat(t *testing.T) {
	t.Run("docker output is refused", func(t *testing.T) {
		_, err := parseBuildArgs([]string{"-t", "app:v1", "--platform", "linux/arm64,linux/amd64",
			"--output", "img.tar", "--format", "docker", "."}, io.Discard)
		if err == nil {
			t.Fatal("a multi-platform build accepted --format docker")
		}
		if !strings.Contains(err.Error(), "--format oci") {
			t.Errorf("the refusal does not name the format that works: %v", err)
		}
	})
	t.Run("oci output is accepted", func(t *testing.T) {
		o, err := parseBuildArgs([]string{"-t", "app:v1", "--platform", "linux/arm64,linux/amd64",
			"--output", "layout", "--format", "oci", "."}, io.Discard)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if len(o.platforms) != 2 {
			t.Errorf("platforms = %v, want two", o.platforms)
		}
	})
	t.Run("no --output needs no format at all", func(t *testing.T) {
		// The store and --push both carry the build without a file, so a
		// multi-platform build with neither --output nor a format is ordinary.
		if _, err := parseBuildArgs([]string{"-t", "app:v1", "--platform", "linux/arm64,linux/amd64", "."}, io.Discard); err != nil {
			t.Fatalf("parse: %v", err)
		}
	})
}

// ----------------------------------------------------------------- harness

// multiPlatformIndex builds a synthetic OCI index holding one random image per
// named platform. Synthetic on purpose: the delivery rules under test are about
// the INDEX, and a real multi-platform build needs the engine (owed live tier).
func multiPlatformIndex(t *testing.T, platforms ...string) ggcrv1.ImageIndex {
	t.Helper()
	idx := ggcrv1.ImageIndex(empty.Index)
	for _, p := range platforms {
		img, err := random.Image(256, 1)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := img.ConfigFile()
		if err != nil {
			t.Fatal(err)
		}
		cfg = cfg.DeepCopy()
		cfg.OS, cfg.Architecture = platformOS(p), platformArch(p)
		img, err = mutate.ConfigFile(img, cfg)
		if err != nil {
			t.Fatal(err)
		}
		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
			Add: img,
			Descriptor: ggcrv1.Descriptor{
				Platform: &ggcrv1.Platform{OS: platformOS(p), Architecture: platformArch(p)},
			},
		})
	}
	return idx
}

// remoteIndex fetches the index a registry serves for ref.
func remoteIndex(t *testing.T, ref string) ggcrv1.ImageIndex {
	t.Helper()
	parsed, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := remote.Index(parsed, remote.WithContext(t.Context()))
	if err != nil {
		t.Fatalf("pull back the index at %s: %v", ref, err)
	}
	return idx
}

// indexPlatforms lists the platforms an index names, in order.
func indexPlatforms(t *testing.T, idx ggcrv1.ImageIndex) []string {
	t.Helper()
	manifest, err := idx.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, d := range manifest.Manifests {
		if d.Platform == nil {
			t.Fatalf("a manifest in the index carries no platform: %+v", d)
		}
		out = append(out, d.Platform.OS+"/"+d.Platform.Architecture)
	}
	return out
}

// childIndex descends one level into a layout's single index descriptor — the
// shape a multi-platform export writes.
func childIndex(t *testing.T, idx ggcrv1.ImageIndex) ggcrv1.ImageIndex {
	t.Helper()
	manifest, err := idx.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Manifests) != 1 || !manifest.Manifests[0].MediaType.IsIndex() {
		t.Fatalf("layout does not hold exactly one index: %+v", manifest.Manifests)
	}
	child, err := idx.ImageIndex(manifest.Manifests[0].Digest)
	if err != nil {
		t.Fatal(err)
	}
	return child
}

// mustTag parses a tag or fails the test.
func mustTag(t *testing.T, s string) name.Tag {
	t.Helper()
	tag, err := name.NewTag(s)
	if err != nil {
		t.Fatal(err)
	}
	return tag
}
