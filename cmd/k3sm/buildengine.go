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
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"

	"k3sm.io/k3sm/pkg/builder"
	"k3sm.io/k3sm/pkg/oci"
)

// enginePlatform is what the build engine targets when --platform was not given.
// The engine is BuildKit in a Linux guest, so its native output is a linux image
// for the guest's own architecture — a different axis from the darwin/arm64 the
// native packager produces, and the reason the two paths cannot share a default.
const enginePlatform = "linux/arm64"

// needsBuildEngine classifies a native-parse failure: does this Dockerfile need
// a real builder, or is it simply wrong?
//
// The split is between "valid Docker this builder cannot express" and "not a
// usable Dockerfile at all". The first routes to the engine — RUN above all, but
// equally a multi-stage build, an ARG, a USER, a heredoc, an ADD of a URL or an
// auto-extracting archive: every one of them is something BuildKit does. The
// second (a malformed instruction, an unknown verb, a missing FROM) stays here
// and is reported immediately, because booting a build engine to re-derive a
// syntax error the parser already found costs minutes and answers nothing new.
func needsBuildEngine(err error) bool {
	for _, sentinel := range []error{
		oci.ErrRunUnsupported,
		oci.ErrUnsupportedInstruction,
		oci.ErrUnsupportedSyntax,
		oci.ErrRemoteSource,
		oci.ErrArchiveAutoExtract,
	} {
		if errors.Is(err, sentinel) {
			return true
		}
	}
	return false
}

// engineBuildPlatform resolves the platform — or the comma-separated platforms —
// the engine builds for, or refuses a target only the native path can serve.
func engineBuildPlatform(o buildOptions) (string, error) {
	if !o.platformSet {
		return enginePlatform, nil
	}
	for _, p := range o.targets() {
		if platformOS(p) == oci.PlatformOS {
			return "", fmt.Errorf("--platform %s is the native COPY-only path's target; this Dockerfile needs the build engine, which produces Linux images (drop --platform for %s, or keep the Dockerfile within the native subset)", p, enginePlatform)
		}
	}
	return strings.Join(o.targets(), ","), nil
}

// engineBuildArgs is the buildx argv the engine path runs. Pure, so the exact
// invocation is pinned by a test rather than discovered in a lab.
//
// --provenance=false is deliberate: buildx attaches a provenance attestation to
// an OCI export by default, which turns the exported layout into an index of an
// image PLUS its attestations. `k3sm build` promises one image under one tag —
// the same artifact the native path writes — so the attestation is declined here
// rather than silently changing the shape of what --output receives.
func engineBuildArgs(o buildOptions, platform, layoutDir string) []string {
	return []string{
		"build",
		"--file", o.dockerfile,
		"--tag", o.tag,
		"--platform", platform,
		"--provenance=false",
		"--output", "type=oci,tar=false,dest=" + layoutDir,
		o.contextDir,
	}
}

// engineBuild is the production engineBuilder: it ensures the engine is running,
// drives the bundled buildx against it, and lands the result at --output in the
// SAME shape the native path writes — same tag, same sink, same summary. What an
// operator does next (k3sm image load, a Pod naming the tag) is therefore
// independent of which engine built the image.
func engineBuild(ctx context.Context, o buildOptions, out io.Writer) error {
	ref, err := name.NewTag(o.tag)
	if err != nil {
		return fmt.Errorf("--tag %q: %w", o.tag, err)
	}
	platform, err := engineBuildPlatform(o)
	if err != nil {
		return err
	}

	setupCtx, cancel := context.WithTimeout(ctx, buildxSetupTimeout)
	sess, err := newBuildxSession(setupCtx, workDirFromEnv(), true, out)
	cancel()
	if err != nil {
		return err
	}

	tmp, err := os.MkdirTemp("", "k3sm-engine-build-")
	if err != nil {
		return fmt.Errorf("create staging dir: %w", err)
	}
	defer os.RemoveAll(tmp)
	layoutDir := filepath.Join(tmp, "layout")

	// The build itself is unbounded: it is the operator's to interrupt, and a
	// guessed deadline that fires mid-build discards every layer it earned.
	args := builder.BuildxArgs(engineBuildArgs(o, platform, layoutDir))
	if err := builder.RunBuildx(ctx, sess.bin, args, sess.env); err != nil {
		return fmt.Errorf("build through the k3sm build engine at %s: %w", sess.endpoint, err)
	}

	b, err := engineArtifact(layoutDir, strings.Split(platform, ","))
	if err != nil {
		return err
	}

	// The SAME delivery as the native path: recorded in this node's store under
	// --tag, plus the artifact when --output asked for one and the upload when
	// --push did. Sharing this is what makes "which engine built it" invisible
	// after the build.
	return deliver(ctx, o, ref, b, out, recordInStore, pushBuilt, sess.endpoint, platform)
}

// layoutIndex returns the multi-platform image index a layout's single
// top-level descriptor names, and nil when that descriptor is an image manifest
// or when the layout is not the one-descriptor shape at all.
//
// nil is not an error precisely so the two readers stay in one order: this one
// answers "is there an index to descend into", and layoutImage — the reader
// `k3sm image push` already uses — produces every refusal about a layout that
// holds the wrong number of things. Two readers with two error registers for one
// malformed layout is how a caller ends up reporting the wrong one.
func layoutIndex(dir string) (ggcrv1.ImageIndex, error) {
	p, err := layout.FromPath(dir)
	if err != nil {
		return nil, err
	}
	idx, err := p.ImageIndex()
	if err != nil {
		return nil, err
	}
	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, err
	}
	if len(manifest.Manifests) != 1 || !manifest.Manifests[0].MediaType.IsIndex() {
		return nil, nil
	}
	return idx.ImageIndex(manifest.Manifests[0].Digest)
}

// engineArtifact reads what buildx exported into layoutDir.
//
// buildx writes ONE top-level descriptor per build: an image manifest for a
// single platform, and an image INDEX when several were asked for. Both shapes
// are read here, and a single-child index is collapsed to that image, so
// "multi-platform" means what it says downstream — a build for one platform
// takes exactly the paths it always took, whatever shape the exporter chose.
func engineArtifact(layoutDir string, platforms []string) (built, error) {
	idx, err := layoutIndex(layoutDir)
	if err != nil {
		return built{}, fmt.Errorf("read the engine's output: %w", err)
	}
	if idx == nil {
		img, err := layoutImage(layoutDir)
		if err != nil {
			return built{}, fmt.Errorf("read the engine's output: %w", err)
		}
		return built{image: img, platforms: platforms, storePlatform: platforms[0]}, nil
	}
	manifest, err := idx.IndexManifest()
	if err != nil {
		return built{}, fmt.Errorf("read the engine's output: %w", err)
	}
	if len(manifest.Manifests) == 1 {
		img, err := idx.Image(manifest.Manifests[0].Digest)
		if err != nil {
			return built{}, fmt.Errorf("read the engine's output: %w", err)
		}
		return built{image: img, platforms: platforms, storePlatform: platforms[0]}, nil
	}
	img, storePlatform, err := selectStoreImage(idx, enginePlatform)
	if err != nil {
		return built{}, err
	}
	return built{image: img, index: idx, platforms: platforms, storePlatform: storePlatform}, nil
}
