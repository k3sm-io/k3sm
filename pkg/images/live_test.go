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

package images

import (
	"context"
	"fmt"
	"log"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// fixture is an in-process OCI registry on loopback. It exists so the SHIPPED
// verification path is what gets proven — the alternative, a hand-rolled fake of
// remote.Get, would prove only that the fake agrees with the test.
//
// Loopback only: these tests reach 127.0.0.1 and nothing else. `go test ./...` makes no
// request that leaves the machine.
type fixture struct {
	host string
	// pushed maps platform -> per-platform manifest digest for the index pushed by
	// pushIndex, plus the key "index" for the index digest itself.
	pushed map[string]string
}

func startFixture(t *testing.T) *fixture {
	t.Helper()
	srv := httptest.NewServer(registry.New(registry.Logger(newTestLogger(t))))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse fixture URL %q: %v", srv.URL, err)
	}
	if h := u.Hostname(); h != "127.0.0.1" && h != "::1" && h != "localhost" {
		t.Fatalf("fixture bound to %q, want loopback — a unit test must never leave the machine", h)
	}
	return &fixture{host: u.Host, pushed: map[string]string{}}
}

// pushIndex writes a multi-platform index to repo and records every digest it produced.
func (f *fixture) pushIndex(t *testing.T, repo string, platforms ...string) {
	t.Helper()
	idx := ggcrv1.ImageIndex(empty.Index)
	for _, p := range platforms {
		parts := strings.Split(p, "/")
		img, err := random.Image(256, 1)
		if err != nil {
			t.Fatalf("build fixture image for %s: %v", p, err)
		}
		d, err := img.Digest()
		if err != nil {
			t.Fatalf("digest fixture image for %s: %v", p, err)
		}
		f.pushed[p] = d.String()
		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
			Add: img,
			Descriptor: ggcrv1.Descriptor{
				Platform: &ggcrv1.Platform{OS: parts[0], Architecture: parts[1]},
			},
		})
	}
	id, err := idx.Digest()
	if err != nil {
		t.Fatalf("digest fixture index: %v", err)
	}
	f.pushed["index"] = id.String()

	ref, err := name.NewTag(f.host+"/"+repo+":fixture", name.Insecure)
	if err != nil {
		t.Fatalf("parse fixture tag: %v", err)
	}
	if err := remote.WriteIndex(ref, idx, remote.WithAuth(authn.Anonymous)); err != nil {
		t.Fatalf("push fixture index: %v", err)
	}
}

// manifestFor writes a mirror manifest describing what pushIndex just wrote. Digests are
// content-derived, so a fixture manifest can never equal the shipped constants — which
// is precisely why the CLI skips lockstep when the registry is overridden.
func (f *fixture) manifestFor(t *testing.T, name string, indexDigest string, platforms map[string]string) string {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "images:\n  - name: %s\n", name)
	fmt.Fprintf(&b, "    upstream: docker.io/moby/%s:v1.2.3@%s\n", name, indexDigest)
	fmt.Fprintf(&b, "    mirror: %s%s@%s\n", MirrorPrefix, name, indexDigest)
	fmt.Fprintf(&b, "    tag: v1.2.3\n    platforms:\n")
	for _, p := range []string{"linux/arm64", "linux/amd64"} {
		d, ok := platforms[p]
		if !ok {
			continue
		}
		fmt.Fprintf(&b, "      - platform: %s\n        digest: %s\n", p, d)
	}
	return writeManifest(t, b.String())
}

func (f *fixture) opts() LiveOptions {
	return LiveOptions{Registry: f.host, Insecure: true}
}

func TestVerifyLiveAgainstFixture(t *testing.T) {
	f := startFixture(t)
	f.pushIndex(t, "k3sm-io/mirror/buildkit", "linux/arm64", "linux/amd64")
	idx := f.pushed["index"]

	tests := []struct {
		name    string
		build   func(t *testing.T) string
		wantErr string
	}{
		{
			name: "present at digest with both platforms",
			build: func(t *testing.T) string {
				return f.manifestFor(t, "buildkit", idx, map[string]string{
					"linux/arm64": f.pushed["linux/arm64"],
					"linux/amd64": f.pushed["linux/amd64"],
				})
			},
		},
		{
			name: "absent — a digest nothing was ever pushed at",
			build: func(t *testing.T) string {
				absent := "sha256:" + strings.Repeat("0", 64)
				return f.manifestFor(t, "buildkit", absent, map[string]string{
					"linux/arm64": f.pushed["linux/arm64"],
					"linux/amd64": f.pushed["linux/amd64"],
				})
			},
			wantErr: "anonymous fetch",
		},
		{
			name: "absent repository",
			build: func(t *testing.T) string {
				return f.manifestFor(t, "never-mirrored", idx, map[string]string{
					"linux/arm64": f.pushed["linux/arm64"],
					"linux/amd64": f.pushed["linux/amd64"],
				})
			},
			wantErr: "anonymous fetch",
		},
		{
			name: "platform recorded at the wrong per-arch digest",
			build: func(t *testing.T) string {
				return f.manifestFor(t, "buildkit", idx, map[string]string{
					"linux/arm64": f.pushed["linux/arm64"],
					"linux/amd64": "sha256:" + strings.Repeat("b", 64),
				})
			},
			wantErr: "linux/amd64 is present at",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyLiveFile(context.Background(), tc.build(t), f.opts())
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("want green, got: %v", err)
			case tc.wantErr == "":
				return
			case err == nil:
				t.Fatalf("want error containing %q, got nil", tc.wantErr)
			case !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("want error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

// TestVerifyLiveMissingPlatform proves the arch assertion is real: an index that carries
// only arm64 must fail a manifest that claims amd64 too. It needs its own index, so it
// is a separate test rather than a row above.
func TestVerifyLiveMissingPlatform(t *testing.T) {
	f := startFixture(t)
	f.pushIndex(t, "k3sm-io/mirror/buildkit", "linux/arm64")
	// Claim an amd64 the index does not carry. The schema requires both arches for
	// buildkit, so the manifest is well-formed and only the registry can refute it.
	p := f.manifestFor(t, "buildkit", f.pushed["index"], map[string]string{
		"linux/arm64": f.pushed["linux/arm64"],
		"linux/amd64": "sha256:" + strings.Repeat("c", 64),
	})
	err := VerifyLiveFile(context.Background(), p, f.opts())
	if err == nil {
		t.Fatal("want an error for a platform absent from the index, got nil")
	}
	if !strings.Contains(err.Error(), "linux/amd64 absent from the index") {
		t.Fatalf("want a missing-platform error, got: %v", err)
	}
}

// TestVerifyLiveRejectsNonIndex pins the "a pin must name an index" rule against a real
// registry: a single-platform image manifest is not a valid pin, because runtime
// platform selection has nothing to select from.
func TestVerifyLiveRejectsNonIndex(t *testing.T) {
	f := startFixture(t)
	img, err := random.Image(256, 1)
	if err != nil {
		t.Fatalf("build fixture image: %v", err)
	}
	d, err := img.Digest()
	if err != nil {
		t.Fatalf("digest fixture image: %v", err)
	}
	ref, err := name.NewTag(f.host+"/k3sm-io/mirror/buildkit:flat", name.Insecure)
	if err != nil {
		t.Fatalf("parse fixture tag: %v", err)
	}
	if err := remote.Write(ref, img, remote.WithAuth(authn.Anonymous)); err != nil {
		t.Fatalf("push fixture image: %v", err)
	}
	p := f.manifestFor(t, "buildkit", d.String(), map[string]string{
		"linux/arm64": "sha256:" + strings.Repeat("d", 64),
		"linux/amd64": "sha256:" + strings.Repeat("e", 64),
	})
	err = VerifyLiveFile(context.Background(), p, f.opts())
	if err == nil {
		t.Fatal("want an error for a pin naming a single-platform manifest, got nil")
	}
	if !strings.Contains(err.Error(), "not a multi-platform index") {
		t.Fatalf("want a not-an-index error, got: %v", err)
	}
}

// TestShippedScriptAgainstFixture drives hack/verify-image-pins.sh — the artifact a
// release actually runs — instead of only the library behind it. Without this leg the
// gate would prove the package and leave the script's flag plumbing (which is what a
// release invokes) unproven.
func TestShippedScriptAgainstFixture(t *testing.T) {
	script := filepath.Join("..", "..", "hack", "verify-image-pins.sh")
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("the shipped verifier is missing: %v", err)
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("no go toolchain on PATH: %v", err)
	}

	f := startFixture(t)
	f.pushIndex(t, "k3sm-io/mirror/buildkit", "linux/arm64", "linux/amd64")
	good := f.manifestFor(t, "buildkit", f.pushed["index"], map[string]string{
		"linux/arm64": f.pushed["linux/arm64"],
		"linux/amd64": f.pushed["linux/amd64"],
	})
	bad := f.manifestFor(t, "buildkit", "sha256:"+strings.Repeat("0", 64), map[string]string{
		"linux/arm64": f.pushed["linux/arm64"],
		"linux/amd64": f.pushed["linux/amd64"],
	})

	run := func(t *testing.T, args ...string) (string, error) {
		t.Helper()
		cmd := exec.Command("bash", append([]string{script}, args...)...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	t.Run("live green against the fixture", func(t *testing.T) {
		out, err := run(t, "--live", "--manifest", good, "--registry", f.host, "--insecure")
		if err != nil {
			t.Fatalf("want exit 0, got %v:\n%s", err, out)
		}
		if !strings.Contains(out, "ok  live") {
			t.Fatalf("want a live-ok line, got:\n%s", out)
		}
	})

	t.Run("live red when the pin is absent", func(t *testing.T) {
		out, err := run(t, "--live", "--manifest", bad, "--registry", f.host, "--insecure")
		if err == nil {
			t.Fatalf("want a non-zero exit for an absent pin, got 0:\n%s", out)
		}
	})

	t.Run("default mode is offline lockstep over the shipped manifest", func(t *testing.T) {
		out, err := run(t)
		if err != nil {
			t.Fatalf("want exit 0, got %v:\n%s", err, out)
		}
		if !strings.Contains(out, "ok  lockstep") {
			t.Fatalf("want a lockstep-ok line, got:\n%s", out)
		}
		if strings.Contains(out, "live") {
			t.Fatalf("the default mode must not run the live check:\n%s", out)
		}
	})
}

func newTestLogger(t *testing.T) *log.Logger {
	return log.New(&testWriter{t: t}, "fixture-registry: ", 0)
}

type testWriter struct{ t *testing.T }

func (w *testWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}
