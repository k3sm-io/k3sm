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

	"github.com/google/go-containerregistry/pkg/name"

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

// engineBuildPlatform resolves the platform the engine builds for, or refuses a
// target only the native path can serve.
func engineBuildPlatform(o buildOptions) (string, error) {
	if !o.platformSet {
		return enginePlatform, nil
	}
	if o.platform == oci.DefaultPlatform {
		return "", fmt.Errorf("--platform %s is the native COPY-only path's target; this Dockerfile needs the build engine, which produces Linux images (drop --platform for %s, or keep the Dockerfile within the native subset)", o.platform, enginePlatform)
	}
	return o.platform, nil
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

	img, err := layoutImage(layoutDir)
	if err != nil {
		return fmt.Errorf("read the engine's output: %w", err)
	}

	// The SAME delivery as the native path: recorded in this node's store under
	// --tag, plus the artifact when --output asked for one. Sharing this is what
	// makes "which engine built it" invisible after the build.
	return deliver(ctx, o, ref, img, out, recordInStore, sess.endpoint, platform)
}
