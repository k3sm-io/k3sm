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
	"errors"
	"fmt"
	"strings"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"

	"k3sm.io/k3sm/pkg/oci"
)

// linuxOS is the operating system of every image the build engine produces. It
// is a constant here rather than a substring of enginePlatform so the platform
// decisions below read as what they are — a question about the OS a target
// names, not a prefix match.
const linuxOS = "linux"

// engineGuestArch is the architecture of the Linux guest the build engine runs
// in, and therefore the ONLY architecture whose instructions it can execute. It
// is derived from enginePlatform so the two cannot drift: the guest is booted by
// Virtualization.framework on an Apple Silicon Mac, so it is arm64.
var engineGuestArch = platformArch(enginePlatform)

// errNoEmulation reports a build that would have to EXECUTE instructions for an
// architecture the build engine's guest cannot execute.
//
// It is a sentinel, and the build is refused before the engine is started,
// because the alternative is minutes of boot and layer work ending in runc's own
// "exec format error" — which names neither the architecture nor the reason.
var errNoEmulation = errors.New("the build engine cannot execute this architecture")

// errStorePlatform reports a multi-platform build that produced no image this
// node's runtime can run, so there is nothing for the store recording to name.
var errStorePlatform = errors.New("this build produced no image for the platform this node runs")

// parsePlatforms parses the --platform value: one target, or several separated
// by commas for a multi-platform build.
//
// The whole list is validated at PARSE time, before a single layer is read,
// because every refusal below is a decision about which builder the argv asks
// for — and an argv that asks for two builders at once is a mistake worth
// naming immediately rather than half-executing.
func parsePlatforms(spec string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, raw := range strings.Split(spec, ",") {
		p := strings.TrimSpace(raw)
		if p == "" {
			return nil, fmt.Errorf("--platform %q: an empty platform between commas", spec)
		}
		parts := strings.Split(p, "/")
		if len(parts) < 2 || len(parts) > 3 {
			return nil, fmt.Errorf("--platform %q: want os/arch[/variant], e.g. %s or %s", p, oci.DefaultPlatform, enginePlatform)
		}
		for _, part := range parts {
			if part == "" {
				return nil, fmt.Errorf("--platform %q: want os/arch[/variant], e.g. %s or %s", p, oci.DefaultPlatform, enginePlatform)
			}
		}
		if seen[p] {
			return nil, fmt.Errorf("--platform %q names %s twice", spec, p)
		}
		seen[p] = true
		out = append(out, p)
	}
	// A darwin target is the NATIVE packager and a linux target is the build
	// engine: two different builders, producing two different kinds of payload.
	// One `k3sm build` drives one of them, so a list that names both is refused
	// rather than silently resolved to whichever the router reaches first.
	darwin, linux := false, false
	for _, p := range out {
		if platformOS(p) == oci.PlatformOS {
			darwin = true
		} else {
			linux = true
		}
	}
	if darwin && linux {
		return nil, fmt.Errorf("--platform %q mixes %s with a Linux target: the native packager builds darwin images and the build engine builds Linux ones, and one build uses one of them", spec, oci.PlatformOS)
	}
	if darwin && len(out) > 1 {
		return nil, fmt.Errorf("--platform %q: the native packager builds one platform, %s", spec, oci.DefaultPlatform)
	}
	return out, nil
}

// targets is the platform list this build aims at.
//
// It defaults an EMPTY list to the native platform so a buildOptions assembled
// in code — every internal caller that does not go through argv — behaves as one
// parsed from a command line that named no --platform. The zero value is usable,
// which is what keeps "the default target" a single fact rather than one every
// caller re-supplies.
func (o buildOptions) targets() []string {
	if len(o.platforms) == 0 {
		return []string{oci.DefaultPlatform}
	}
	return o.platforms
}

// platformOS is the os component of an os/arch[/variant] platform.
func platformOS(platform string) string {
	os, _, _ := strings.Cut(platform, "/")
	return os
}

// platformArch is the arch component of an os/arch[/variant] platform, without
// the variant.
func platformArch(platform string) string {
	_, rest, _ := strings.Cut(platform, "/")
	arch, _, _ := strings.Cut(rest, "/")
	return arch
}

// enginePlatformRequested reports whether the argv EXPLICITLY asks for a
// platform only the build engine can produce.
//
// This is what makes `--platform linux/arm64` a first-class request rather than
// a property of the Dockerfile: the native packager copies host files into a
// darwin/arm64 image and cannot produce a Linux one at all, so a Linux target is
// an engine build by definition — even for a Dockerfile that only copies files
// in, which the native path would otherwise have taken.
func enginePlatformRequested(o buildOptions) bool {
	if !o.platformSet {
		return false
	}
	for _, p := range o.targets() {
		if platformOS(p) != oci.PlatformOS {
			return true
		}
	}
	return false
}

// emulationRefusal refuses, by name, the one combination the build engine
// provably cannot serve: a Dockerfile whose RUN steps would have to execute for
// an architecture other than the engine guest's own.
//
// The engine is BuildKit in an arm64 Linux guest that registers no binfmt
// handler and carries no emulator (pkg/builder/assets/entrypoint.sh installs
// none, and asserts the guest is arm64), and k3sm's Rosetta-for-Linux capability
// is advertised on the node but not wired into a guest's execution path. So
// there is nothing on this path that can run an amd64 binary, and a RUN step for
// amd64 has no way to complete.
//
// It fires ONLY on a Dockerfile the native parser rejected for RUN specifically.
// A build with no RUN step for the foreign platform needs no emulator — BuildKit
// copies files with its own worker rather than in a target-platform container,
// which is what makes a cross-compiled binary COPYed into a foreign-arch image
// an ordinary build — so those are attempted rather than pre-refused.
func emulationRefusal(o buildOptions, parseErr error) error {
	if !o.platformSet || !errors.Is(parseErr, oci.ErrRunUnsupported) {
		return nil
	}
	for _, p := range o.targets() {
		if arch := platformArch(p); arch != engineGuestArch {
			return fmt.Errorf("%w: --platform %s asks for RUN steps to execute as %s, and the engine's guest is %s with no emulator registered (build %s/%s, or COPY a cross-compiled binary in instead of RUNning the toolchain)",
				errNoEmulation, p, arch, engineGuestArch, linuxOS, engineGuestArch)
		}
	}
	return nil
}

// selectStoreImage picks the ONE image a multi-platform build records in this node's
// image store, and reports its platform.
//
// The store holds single-platform entries, and the reason the choice is not
// arbitrary is the summary line it feeds: the build tells the operator to
// `kubectl run app --image=<tag>`, and that is true only for an image a Pod on
// this node can actually run. So the pick is the platform the node's own Linux
// guests run — the engine's guest platform — and a build that produced none is
// refused rather than recorded under a name that would not start.
func selectStoreImage(idx ggcrv1.ImageIndex, want string) (ggcrv1.Image, string, error) {
	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, "", fmt.Errorf("read the build's image index: %w", err)
	}
	var built []string
	for _, desc := range manifest.Manifests {
		if desc.Platform == nil {
			continue
		}
		got := desc.Platform.OS + "/" + desc.Platform.Architecture
		built = append(built, got)
		if got != want {
			continue
		}
		img, err := idx.Image(desc.Digest)
		if err != nil {
			return nil, "", fmt.Errorf("read the %s image from the build's index: %w", got, err)
		}
		return img, got, nil
	}
	return nil, "", fmt.Errorf("%w: this node's Linux guests run %s, and the build produced %s (add %s to --platform, or use --output and --push, which carry every platform)",
		errStorePlatform, want, strings.Join(built, ", "), want)
}
