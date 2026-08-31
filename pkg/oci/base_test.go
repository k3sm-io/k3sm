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

package oci_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"

	"k3sm.io/k3sm/pkg/oci"
)

// fakeBase is a base image with n layers, stamped with os/arch and the config a
// real base would carry. NOTHING here reaches the network: the BaseResolver seam
// exists so this file can prove the whole named-FROM path with a local value.
func fakeBase(t *testing.T, layers int64, os_, arch string, mutateCfg func(*ggcrv1.Config)) ggcrv1.Image {
	t.Helper()
	img, err := random.Image(256, layers)
	if err != nil {
		t.Fatalf("random.Image: %v", err)
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	cfg = cfg.DeepCopy()
	cfg.OS, cfg.Architecture = os_, arch
	if mutateCfg != nil {
		mutateCfg(&cfg.Config)
	}
	out, err := mutate.ConfigFile(img, cfg)
	if err != nil {
		t.Fatalf("stamp: %v", err)
	}
	return out
}

func buildWith(t *testing.T, dockerfile string, resolve oci.BaseResolver) (ggcrv1.Image, error) {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bin", "app"), []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	df, err := oci.Parse(strings.NewReader(dockerfile))
	if err != nil {
		return nil, err
	}
	bc, err := oci.NewContext(dir)
	if err != nil {
		t.Fatal(err)
	}
	return oci.Build(oci.Request{Dockerfile: df, Context: bc, TmpDir: t.TempDir(), BaseResolver: resolve})
}

// TestParseFromAcceptsAReference pins the parser half of the contract: a
// well-formed reference parses, and Dockerfile.Base reports it as named.
func TestParseFromAcceptsAReference(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, in, wantRef string
		wantNamed         bool
	}{
		{"scratch", "FROM scratch", "scratch", false},
		{"scratch-as-stage", "FROM scratch AS build", "scratch", false},
		{"tag", "FROM example.com/base:v1", "example.com/base:v1", true},
		{"digest", "FROM example.com/base@sha256:" + strings.Repeat("a", 64), "example.com/base@sha256:" + strings.Repeat("a", 64), true},
		{"implicit-registry", "FROM alpine:3", "alpine:3", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			df, err := oci.Parse(strings.NewReader(tc.in))
			if err != nil {
				t.Fatalf("Parse(%q) = %v, want nil", tc.in, err)
			}
			ref, named := df.Base()
			if ref != tc.wantRef || named != tc.wantNamed {
				t.Errorf("Base() = (%q, %v), want (%q, %v)", ref, named, tc.wantRef, tc.wantNamed)
			}
		})
	}
}

// TestParseFromStillRejectsMultiStage pins that accepting a reference did not
// open the door to multi-stage builds, which remain out of scope.
func TestParseFromStillRejectsMultiStage(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"FROM alpine:3\nFROM alpine:3",
		"FROM scratch\nFROM alpine:3",
		"FROM alpine:3\nCOPY --from=build a b",
	} {
		if _, err := oci.Parse(strings.NewReader(in)); !errors.Is(err, oci.ErrUnsupportedSyntax) {
			t.Errorf("Parse(%q) = %v, want ErrUnsupportedSyntax", in, err)
		}
	}
}

// TestBuildNamedBaseWithoutResolverIsRefused pins the offline posture: a named
// base with no resolver is an ERROR, never a silent downgrade to scratch. A
// downgrade would emit an image that looks built, has a stable digest, and is
// missing the entire userland the Dockerfile asked for.
func TestBuildNamedBaseWithoutResolverIsRefused(t *testing.T) {
	t.Parallel()
	_, err := buildWith(t, "FROM example.com/base:v1\nCOPY bin/app /app", nil)
	if !errors.Is(err, oci.ErrUnsupportedBase) {
		t.Fatalf("Build = %v, want ErrUnsupportedBase", err)
	}
}

// TestBuildFromBaseStacksOntoBaseLayers pins that the build APPENDS to the base
// rather than replacing it: the base's layers survive, in order, beneath ours.
func TestBuildFromBaseStacksOntoBaseLayers(t *testing.T) {
	t.Parallel()
	base := fakeBase(t, 3, "darwin", "arm64", nil)
	baseCfg, err := base.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	img, err := buildWith(t, "FROM example.com/base:v1\nCOPY bin/app /usr/local/bin/app", func(string) (ggcrv1.Image, error) {
		return base, nil
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(cfg.RootFS.DiffIDs), len(baseCfg.RootFS.DiffIDs)+1; got != want {
		t.Fatalf("diffID count = %d, want %d (base %d + one COPY)", got, want, len(baseCfg.RootFS.DiffIDs))
	}
	for i, d := range baseCfg.RootFS.DiffIDs {
		if cfg.RootFS.DiffIDs[i] != d {
			t.Errorf("diffID[%d] = %s, want the base's %s", i, cfg.RootFS.DiffIDs[i], d)
		}
	}
	// ggcr requires one non-empty history entry per diffID; a base whose history
	// was dropped would still produce a valid-looking config that no registry
	// accepts, so the count is asserted rather than eyeballed.
	nonEmpty := 0
	for _, h := range cfg.History {
		if !h.EmptyLayer {
			nonEmpty++
		}
	}
	if nonEmpty != len(cfg.RootFS.DiffIDs) {
		t.Errorf("non-empty history entries = %d, want %d (one per diffID)", nonEmpty, len(cfg.RootFS.DiffIDs))
	}
}

// TestBuildFromBaseInheritsThenOverridesConfig pins FROM's inheritance: the
// base's environment survives, and this Dockerfile's instructions win key by key.
// Dropping the base's PATH is the difference between an image that runs and one
// that cannot find its own interpreter.
func TestBuildFromBaseInheritsThenOverridesConfig(t *testing.T) {
	t.Parallel()
	base := fakeBase(t, 1, "darwin", "arm64", func(c *ggcrv1.Config) {
		c.Env = []string{"PATH=/usr/bin", "KEEP=1", "OVERRIDE=old"}
		c.Entrypoint = []string{"/base-entry"}
		c.WorkingDir = "/base"
		c.Labels = map[string]string{"base.label": "kept"}
	})
	img, err := buildWith(t, "FROM example.com/base:v1\nENV OVERRIDE=new\nCOPY bin/app /usr/local/bin/app", func(string) (ggcrv1.Image, error) {
		return base, nil
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{}
	for _, kv := range cfg.Config.Env {
		k, v, _ := strings.Cut(kv, "=")
		env[k] = v
	}
	if env["PATH"] != "/usr/bin" {
		t.Errorf("PATH = %q, want the base's /usr/bin (inheritance dropped)", env["PATH"])
	}
	if env["KEEP"] != "1" {
		t.Errorf("KEEP = %q, want the base's 1", env["KEEP"])
	}
	if env["OVERRIDE"] != "new" {
		t.Errorf("OVERRIDE = %q, want this build's new", env["OVERRIDE"])
	}
	if cfg.Config.Labels["base.label"] != "kept" {
		t.Errorf("base label dropped: %v", cfg.Config.Labels)
	}
	// Not restated by the Dockerfile, so both must survive from the base.
	if got := cfg.Config.Entrypoint; len(got) != 1 || got[0] != "/base-entry" {
		t.Errorf("Entrypoint = %v, want the base's [/base-entry]", got)
	}
	if cfg.Config.WorkingDir != "/base" {
		t.Errorf("WorkingDir = %q, want the base's /base", cfg.Config.WorkingDir)
	}
}

// TestBuildFromBaseRefusesPlatformMismatch pins the fail-closed check. Basing a
// darwin/arm64 image on a linux/amd64 layer is a self-consistent lie — the
// manifest verifies, the digest is stable, and the payload cannot execute.
func TestBuildFromBaseRefusesPlatformMismatch(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, os, arch string }{
		{"linux-amd64", "linux", "amd64"},
		{"linux-arm64", "linux", "arm64"},
		{"darwin-amd64", "darwin", "amd64"},
		{"unset", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			base := fakeBase(t, 1, tc.os, tc.arch, nil)
			_, err := buildWith(t, "FROM example.com/base:v1\nCOPY bin/app /app", func(string) (ggcrv1.Image, error) {
				return base, nil
			})
			if !errors.Is(err, oci.ErrBasePlatform) {
				t.Fatalf("Build on %s/%s = %v, want ErrBasePlatform", tc.os, tc.arch, err)
			}
		})
	}
}

// TestBuildFromBaseSurfacesResolverFailure pins that a resolver error reaches the
// caller naming the reference, rather than surfacing as a nil-image panic.
func TestBuildFromBaseSurfacesResolverFailure(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("registry unreachable")
	_, err := buildWith(t, "FROM example.com/base:v1\nCOPY bin/app /app", func(string) (ggcrv1.Image, error) {
		return nil, sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Build = %v, want the resolver's error", err)
	}
	if !strings.Contains(err.Error(), "example.com/base:v1") {
		t.Errorf("error does not name the reference: %v", err)
	}
	t.Run("nil-image-without-error", func(t *testing.T) {
		t.Parallel()
		if _, err := buildWith(t, "FROM example.com/base:v1\nCOPY bin/app /app", func(string) (ggcrv1.Image, error) {
			return nil, nil
		}); err == nil {
			t.Fatal("Build = nil error on a nil base image, want a refusal")
		}
	})
}

// scratchDigest is the digest FROM scratch produced BEFORE named bases were
// supported, captured by building this exact Dockerfile and context against
// origin/main. Reproducible digests are a documented property of this builder
// (docs/user/images.md), so the scratch path changing at all is a regression
// even when every other test still passes — the relative reproducibility test
// (A == B) cannot see a shift that moves both sides equally.
const scratchDigest = "sha256:1b772d00f8e1de055116f31993acc1745225b88baa19999e9a07cf8c33951ed7"

func TestBuildFromScratchDigestUnchanged(t *testing.T) {
	t.Parallel()
	img, err := buildWith(t, "FROM scratch\nCOPY bin/app /usr/local/bin/app\nENV A=1\nENTRYPOINT [\"/usr/local/bin/app\"]", nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	d, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if d.String() != scratchDigest {
		t.Fatalf("FROM scratch digest = %s, want %s — the scratch path must stay byte-identical", d, scratchDigest)
	}
}
