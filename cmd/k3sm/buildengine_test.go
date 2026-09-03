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
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/oci"
)

// TestNeedsBuildEngine pins the classification: a Dockerfile the native packager
// cannot EXPRESS routes to the engine; one that is not a usable Dockerfile at
// all is still refused here.
func TestNeedsBuildEngine(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		engine bool
	}{
		{"run", "FROM scratch\nRUN make", true},
		{"run mid-file", "FROM scratch\nCOPY a /a\nRUN ./a --init", true},
		{"arg", "FROM scratch\nARG VERSION=1", true},
		{"user", "FROM scratch\nUSER app", true},
		{"volume", "FROM scratch\nVOLUME /data", true},
		{"healthcheck", "FROM scratch\nHEALTHCHECK CMD /probe", true},
		{"multi-stage", "FROM scratch\nCOPY a /a\nFROM scratch", true},
		{"per-instruction flag", "FROM scratch\nCOPY --from=build /a /a", true},
		{"add a url", "FROM scratch\nADD https://example.com/a /a", true},
		{"add an archive", "FROM scratch\nADD a.tar.gz /a", true},

		{"malformed copy", "FROM scratch\nCOPY", false},
		{"unknown verb", "FROM scratch\nNOPE x", false},
		{"missing from", "ENV A=1\nFROM scratch", false},
		{"unterminated quote", "FROM scratch\nENV K=\"unclosed", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := oci.Parse(strings.NewReader(tc.in))
			if err == nil {
				t.Fatalf("the native parser accepted %q; this table is about its refusals", tc.in)
			}
			if got := needsBuildEngine(err); got != tc.engine {
				t.Errorf("needsBuildEngine(%v) = %v, want %v", err, got, tc.engine)
			}
		})
	}

	t.Run("a nil error never routes", func(t *testing.T) {
		if needsBuildEngine(nil) {
			t.Error("a successful parse must not route to the engine")
		}
	})
}

// writeCtx materialises a build context holding a Dockerfile and one file.
func writeCtx(t *testing.T, dockerfile string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app"), []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestBuildRouting pins WHICH path each Dockerfile takes, with the engine faked
// at its seam: no cluster, no VM, no network.
func TestBuildRouting(t *testing.T) {
	cases := []struct {
		name       string
		dockerfile string
		wantEngine bool
		wantErr    error
	}{
		{"copy-only builds natively", "FROM scratch\nCOPY app /app", false, nil},
		{"RUN routes to the engine", "FROM scratch\nCOPY app /app\nRUN ./app --init", true, nil},
		{"multi-stage routes to the engine", "FROM scratch\nCOPY app /app\nFROM scratch\nCOPY app /app", true, nil},
		{"a malformed Dockerfile is refused natively", "FROM scratch\nCOPY", false, oci.ErrBadInstruction},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctxDir := writeCtx(t, tc.dockerfile)
			out := filepath.Join(t.TempDir(), "img.tar")
			o := buildOptions{
				dockerfile: filepath.Join(ctxDir, "Dockerfile"),
				tag:        "example.com/app:v1",
				output:     out,
				format:     "docker",
				platforms:  []string{oci.DefaultPlatform},
				contextDir: ctxDir,
			}

			routed := 0
			var got buildOptions
			engine := func(_ context.Context, eo buildOptions, _ io.Writer) error {
				routed++
				got = eo
				return nil
			}

			err := buildWith(t.Context(), o, io.Discard, engine, noStore, noPush)
			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("buildWith = %v, want %v", err, tc.wantErr)
				}
			case err != nil:
				t.Fatalf("buildWith: %v", err)
			}

			if tc.wantEngine {
				if routed != 1 {
					t.Fatalf("engine calls = %d, want 1", routed)
				}
				if got.tag != o.tag || got.output != o.output || got.contextDir != o.contextDir || got.dockerfile != o.dockerfile {
					t.Errorf("the engine received different options: %+v", got)
				}
				if _, statErr := os.Stat(out); !errors.Is(statErr, os.ErrNotExist) {
					t.Errorf("routing wrote an artifact the engine had not produced")
				}
				return
			}

			if routed != 0 {
				t.Fatalf("engine calls = %d, want 0 — this Dockerfile must not reach the engine", routed)
			}
			if tc.wantErr == nil {
				if _, statErr := os.Stat(out); statErr != nil {
					t.Errorf("the native path wrote no artifact: %v", statErr)
				}
			}
		})
	}
}

// TestEngineBuildPlatform pins the one flag whose meaning differs per path.
func TestEngineBuildPlatform(t *testing.T) {
	t.Run("unset defaults to the guest platform", func(t *testing.T) {
		got, err := engineBuildPlatform(buildOptions{platforms: []string{oci.DefaultPlatform}})
		if err != nil || got != enginePlatform {
			t.Fatalf("engineBuildPlatform = (%q, %v), want (%q, nil)", got, err, enginePlatform)
		}
	})
	t.Run("an explicit darwin target names the constraint", func(t *testing.T) {
		_, err := engineBuildPlatform(buildOptions{platforms: []string{oci.DefaultPlatform}, platformSet: true})
		if err == nil {
			t.Fatal("expected a refusal for a darwin target on the engine path")
		}
		for _, want := range []string{oci.DefaultPlatform, "native", enginePlatform} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not mention %q", err, want)
			}
		}
	})
	t.Run("an explicit linux target passes through", func(t *testing.T) {
		got, err := engineBuildPlatform(buildOptions{platforms: []string{"linux/amd64"}, platformSet: true})
		if err != nil || got != "linux/amd64" {
			t.Fatalf("engineBuildPlatform = (%q, %v), want (linux/amd64, nil)", got, err)
		}
	})
}

// TestEngineBuildArgs pins the buildx invocation the engine path composes: the
// user's -t/-f/context reach buildx, the export is a single-image OCI layout,
// and attestations are declined so --output receives one image.
func TestEngineBuildArgs(t *testing.T) {
	o := buildOptions{
		dockerfile: "/ctx/Dockerfile.dev",
		tag:        "myapp:dev",
		contextDir: "/ctx",
	}
	args := engineBuildArgs(o, "linux/arm64", "/tmp/layout")

	if args[0] != "build" {
		t.Fatalf("args[0] = %q, want build", args[0])
	}
	if args[len(args)-1] != "/ctx" {
		t.Errorf("the context directory must be the final argument: %v", args)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"--file /ctx/Dockerfile.dev",
		"--tag myapp:dev",
		"--platform linux/arm64",
		"--provenance=false",
		"--output type=oci,tar=false,dest=/tmp/layout",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("argv %q is missing %q", joined, want)
		}
	}
}

// TestBuildShortFlags pins the docker-style short forms, which is what makes
// `k3sm build -t myapp:dev .` the one command for both paths.
func TestBuildShortFlags(t *testing.T) {
	o, err := parseBuildArgs([]string{"-t", "myapp:dev", "-f", "Dockerfile.dev", "--output", "o.tar", "/ctx"}, io.Discard)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if o.tag != "myapp:dev" {
		t.Errorf("-t did not set the tag: %q", o.tag)
	}
	if o.dockerfile != "Dockerfile.dev" {
		t.Errorf("-f did not set the Dockerfile: %q", o.dockerfile)
	}
	t.Run("platform tracks whether it was given", func(t *testing.T) {
		unset, err := parseBuildArgs([]string{"-t", "a:v1", "--output", "o.tar", "/ctx"}, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if unset.platformSet {
			t.Error("platformSet is true for an argv that never named --platform")
		}
		set, err := parseBuildArgs([]string{"-t", "a:v1", "--output", "o.tar", "--platform", "linux/amd64", "/ctx"}, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if !set.platformSet || len(set.platforms) != 1 || set.platforms[0] != "linux/amd64" {
			t.Errorf("platforms = %v, set = %v", set.platforms, set.platformSet)
		}
	})
}
