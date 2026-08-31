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

package oci

import (
	"errors"
	"fmt"

	"github.com/google/go-containerregistry/pkg/v1/empty"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
)

// ErrBasePlatform reports a FROM base whose own config declares a platform other
// than the one being built.
var ErrBasePlatform = errors.New("oci: the FROM base declares a different platform")

// BaseResolver fetches the image a named FROM refers to.
//
// It is a SEAM, and the reason is posture, not testability alone. This package
// reads the build context and nothing else — Build's contract is that it
// "performs no I/O outside the build context and the staging directory". A named
// base breaks that, because the bytes live in a registry. Rather than let the
// library open a socket on its own, the fetch is injected: cmd/k3sm supplies a
// resolver that carries the credential chain and the context deadline, and a nil
// resolver leaves the builder exactly as offline as it was before. Unit tests
// pass a fake and touch no network, which is what the repo standards require.
type BaseResolver func(ref string) (ggcrv1.Image, error)

// resolveBase returns the image to build on top of, and whether it came from a
// named reference. FROM scratch yields the platform-stamped empty base.
func resolveBase(df *Dockerfile, resolve BaseResolver) (img ggcrv1.Image, named bool, err error) {
	ref, named := df.Base()
	if !named {
		img, err = stampPlatform(empty.Image)
		return img, false, err
	}
	if resolve == nil {
		// Deliberately not a silent downgrade to scratch: a Dockerfile that says
		// FROM alpine and quietly built on nothing would produce an image that
		// looks right, has a stable digest, and is missing its whole userland.
		return nil, true, fmt.Errorf(
			"FROM %s: %w — this build was configured without a base resolver, so only FROM %s can be built",
			ref, ErrUnsupportedBase, ScratchBase)
	}
	img, err = resolve(ref)
	if err != nil {
		return nil, true, fmt.Errorf("FROM %s: resolve base: %w", ref, err)
	}
	if img == nil {
		return nil, true, fmt.Errorf("FROM %s: resolve base: %w", ref, errors.New("resolver returned no image"))
	}
	if err := checkBasePlatform(img, ref); err != nil {
		return nil, true, err
	}
	return img, true, nil
}

// checkBasePlatform refuses a base whose config contradicts the target.
//
// This is the same failure the runtime's fail-closed platform selection exists to
// prevent, moved one step earlier: a darwin/arm64 image assembled on a linux/amd64
// base is a self-consistent lie — the manifest verifies and the digest is stable —
// whose payload cannot execute. Refusing at BUILD is strictly kinder than
// refusing at pull, because the person who can fix it is standing right here.
func checkBasePlatform(img ggcrv1.Image, ref string) error {
	cfg, err := img.ConfigFile()
	if err != nil {
		return fmt.Errorf("FROM %s: read base config: %w", ref, err)
	}
	if cfg.OS == PlatformOS && cfg.Architecture == PlatformArch {
		return nil
	}
	got := cfg.OS + "/" + cfg.Architecture
	if cfg.OS == "" || cfg.Architecture == "" {
		got = "an unset os/architecture"
	}
	return fmt.Errorf(
		"FROM %s declares %s, but this build targets %s: %w — a base for another platform cannot supply a runnable %s payload",
		ref, got, DefaultPlatform, ErrBasePlatform, DefaultPlatform)
}
