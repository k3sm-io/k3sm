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
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"google.golang.org/grpc"
)

// TestImagePushOCILayout is the B189 gate: `k3sm image push <layout-dir> <ref>`
// uploads the one image a layout holds, prints the digest a caller pins with,
// takes its credential from the environment and never from argv, and tells the
// four failure modes apart.
//
// The registry is an in-process one on loopback — a real HTTP registry, not a
// stub of the push protocol, so the manifest and every blob genuinely have to
// arrive for the pull-back to validate.
func TestImagePushOCILayout(t *testing.T) {
	// The docker config chain is part of the credential contract, so the test
	// pins an empty one rather than reading whatever the developer is logged
	// into: a machine with a credential helper must not change the verdict.
	// t.Setenv forbids t.Parallel here, which is what keeps that pinning safe.
	empty := t.TempDir()
	t.Setenv("HOME", empty)
	t.Setenv("DOCKER_CONFIG", empty)

	t.Run("pushes-the-layout-and-prints-the-digest", func(t *testing.T) {
		t.Setenv(registryTokenEnv, "")
		host, probe := startRegistry(t, "")
		dir := fixtureLayout(t, "example.com/app:v1", "payload-one")
		ref := host + "/team/app:v1"

		out, err := runPush(t, dir, ref)
		if err != nil {
			t.Fatalf("push: %v", err)
		}
		want := layoutDigest(t, dir)
		if !strings.Contains(out, want) {
			t.Errorf("push printed no digest for the pushed image\ngot:\n%s\nwant it to contain %s", out, want)
		}
		if !strings.Contains(out, host+"/team/app@"+want) {
			t.Errorf("push printed no pinnable reference\ngot:\n%s", out)
		}

		// The registry must hold the manifest AND every blob, so the check pulls
		// each blob back and re-hashes the bytes it received: a manifest that
		// landed without its layers fails here rather than passing on a digest
		// match against content that was never uploaded.
		assertRegistryHolds(t, ref, want)
		if len(probe.headers()) == 0 {
			t.Fatal("the registry saw no request at all")
		}
	})

	t.Run("sends-the-env-token-as-a-bearer-credential", func(t *testing.T) {
		const token = "s3cr3t-token-value"
		t.Setenv(registryTokenEnv, "  "+token+"\n") // a token read from a file carries its newline
		host, probe := startRegistry(t, "Bearer "+token)
		dir := fixtureLayout(t, "example.com/app:v1", "payload-two")

		out, err := runPush(t, dir, host+"/team/app:v1")
		if err != nil {
			t.Fatalf("push with the env token: %v", err)
		}
		seen := probe.headers()
		authorized := 0
		for _, h := range seen {
			if h == "Bearer "+token {
				authorized++
				continue
			}
			if h != "" {
				t.Errorf("request carried an unexpected Authorization header %q", h)
			}
		}
		if authorized == 0 {
			t.Errorf("no request carried the env token as a bearer credential; headers = %q", seen)
		}
		if strings.Contains(out, token) {
			t.Error("push echoed the credential to stdout")
		}
	})

	t.Run("no-token-pushes-anonymously", func(t *testing.T) {
		t.Setenv(registryTokenEnv, "")
		host, probe := startRegistry(t, "")
		dir := fixtureLayout(t, "example.com/app:v1", "payload-three")

		if _, err := runPush(t, dir, host+"/team/app:v1"); err != nil {
			t.Fatalf("anonymous push: %v", err)
		}
		for _, h := range probe.headers() {
			if h != "" {
				t.Errorf("an anonymous push sent Authorization %q", h)
			}
		}
	})

	t.Run("the-credential-is-never-an-argument", func(t *testing.T) {
		dir := fixtureLayout(t, "example.com/app:v1", "payload-four")
		for _, flagName := range []string{"--token", "--password", "--registry-token", "--auth", "--credential", "-u"} {
			args := []string{"push", dir, "example.com/app:v1", flagName, "s3cr3t"}
			if _, err := parseImageArgs(args, io.Discard); err == nil {
				t.Errorf("parse accepted a credential argument %s: the token would be in `ps` output and the shell history", flagName)
			}
		}
		// A bare third positional is refused for the same reason.
		if _, err := parseImageArgs([]string{"push", dir, "example.com/app:v1", "s3cr3t"}, io.Discard); err == nil {
			t.Error("parse accepted a third positional argument to push")
		}
		// And no such flag is advertised, so nobody is invited to try.
		var help bytes.Buffer
		if _, err := parseImageArgs([]string{"push", "-h"}, &help); !errors.Is(err, flag.ErrHelp) {
			t.Fatalf("-h returned %v, want flag.ErrHelp", err)
		}
		for _, banned := range []string{"-token", "-password", "-credential", "-auth "} {
			if strings.Contains(help.String(), banned) {
				t.Errorf("the usage advertises a credential flag %q", banned)
			}
		}
	})

	t.Run("push-grammar", func(t *testing.T) {
		dir := fixtureLayout(t, "example.com/app:v1", "payload-five")
		if _, err := parseImageArgs([]string{"push", dir}, io.Discard); err == nil {
			t.Error("push accepted a layout with no reference")
		}
		if _, err := parseImageArgs([]string{"push"}, io.Discard); err == nil {
			t.Error("push accepted no arguments")
		}
		if _, err := parseImageArgs([]string{"push", dir, "example.com/app:v1", "--reference", "other:v2"}, io.Discard); err == nil {
			t.Error("push accepted --reference, which would give it two references")
		}
		opts, err := parseImageArgs([]string{"push", dir, "example.com/app:v1"}, io.Discard)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if opts.layoutDir != dir || opts.target != "example.com/app:v1" {
			t.Errorf("parsed layoutDir=%q target=%q", opts.layoutDir, opts.target)
		}
		// An upload streams every blob, so it inherits the streaming deadline
		// rather than the one sized for a metadata RPC.
		if opts.timeout != streamingTimeout {
			t.Errorf("push default timeout = %v, want %v", opts.timeout, streamingTimeout)
		}
	})

	t.Run("refuses-a-layout-that-is-not-one-image", func(t *testing.T) {
		t.Setenv(registryTokenEnv, "")
		host, _ := startRegistry(t, "")

		two := fixtureLayout(t, "example.com/app:v1", "payload-six")
		appendFixture(t, two, "example.com/other:v1", "payload-seven")
		_, err := runPush(t, two, host+"/team/app:v1")
		if !errors.Is(err, errPushImageCount) {
			t.Errorf("push of a two-image layout = %v, want errPushImageCount", err)
		}

		bare := t.TempDir()
		if err := os.WriteFile(filepath.Join(bare, "index.json"), []byte(`{"schemaVersion":2,"manifests":[]}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bare, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := runPush(t, bare, host+"/team/app:v1"); !errors.Is(err, errPushImageCount) {
			t.Errorf("push of an empty layout = %v, want errPushImageCount", err)
		}
	})

	t.Run("names-a-path-that-is-not-a-layout", func(t *testing.T) {
		t.Setenv(registryTokenEnv, "")
		host, _ := startRegistry(t, "")
		ref := host + "/team/app:v1"

		missing := filepath.Join(t.TempDir(), "no-such-dir")
		err := mustFailPush(t, missing, ref)
		if !errors.Is(err, errPushNoLayout) {
			t.Errorf("push of a missing directory = %v, want errPushNoLayout", err)
		}
		if !strings.Contains(err.Error(), missing) {
			t.Errorf("the error does not name the path: %v", err)
		}

		file := filepath.Join(t.TempDir(), "img.tar")
		if err := os.WriteFile(file, []byte("not a layout"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := mustFailPush(t, file, ref); !errors.Is(err, errPushNoLayout) {
			t.Errorf("push of a tar file = %v, want errPushNoLayout", err)
		}
		if err := mustFailPush(t, t.TempDir(), ref); !errors.Is(err, errPushNoLayout) {
			t.Errorf("push of a directory with no index.json = %v, want errPushNoLayout", err)
		}
	})

	t.Run("tells-a-refused-credential-from-an-unreachable-registry", func(t *testing.T) {
		dir := fixtureLayout(t, "example.com/app:v1", "payload-eight")

		t.Run("auth", func(t *testing.T) {
			t.Setenv(registryTokenEnv, "the-wrong-token")
			host, _ := startRegistry(t, "Bearer the-right-token")
			err := mustFailPush(t, dir, host+"/team/app:v1")
			if !errors.Is(err, errPushAuth) {
				t.Errorf("push with a refused credential = %v, want errPushAuth", err)
			}
			if errors.Is(err, errPushNetwork) {
				t.Error("a refused credential was reported as an unreachable registry")
			}
			if strings.Contains(err.Error(), "the-wrong-token") {
				t.Error("the error message leaks the credential")
			}
		})

		t.Run("network", func(t *testing.T) {
			t.Setenv(registryTokenEnv, "")
			err := mustFailPush(t, dir, deadAddr(t)+"/team/app:v1")
			if !errors.Is(err, errPushNetwork) {
				t.Errorf("push to a dead address = %v, want errPushNetwork", err)
			}
			if errors.Is(err, errPushAuth) {
				t.Error("an unreachable registry was reported as a refused credential")
			}
		})
	})
}

// ----------------------------------------------------------------- harness

// runPush drives the real argv grammar and the real dispatch, so the gate
// exercises what an operator types rather than the internal entry point.
func runPush(t *testing.T, dir, ref string) (string, error) {
	t.Helper()
	opts, err := parseImageArgs([]string{"push", dir, ref}, io.Discard)
	if err != nil {
		return "", err
	}
	var out bytes.Buffer
	// push must never dial runtimed: it uploads a path the invoking user owns.
	dial := func(context.Context, string) (grpc.ClientConnInterface, io.Closer, error) {
		t.Error("push dialed the runtimed socket; it is not a daemon client")
		return nil, nil, errors.New("unexpected dial")
	}
	err = imageCommand(t.Context(), opts, &out, dial)
	return out.String(), err
}

// mustFailPush runs a push that is expected to fail and returns its error.
func mustFailPush(t *testing.T, dir, ref string) error {
	t.Helper()
	out, err := runPush(t, dir, ref)
	if err == nil {
		t.Fatalf("push %s %s unexpectedly succeeded: %s", dir, ref, out)
	}
	if out != "" {
		t.Errorf("a failed push printed %q; a digest must only be printed for content that landed", out)
	}
	return err
}

// fixtureLayout builds a real OCI layout with `k3sm build --format oci`, so the
// gate pushes exactly the artifact the build verb emits.
func fixtureLayout(t *testing.T, tag, payload string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "layout")
	appendFixture(t, out, tag, payload)
	return out
}

// appendFixture adds one more built image to an existing layout directory,
// which is how the multi-image case is constructed.
func appendFixture(t *testing.T, layoutDir, tag, payload string) {
	t.Helper()
	ctxDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(ctxDir, "app"), []byte(payload), 0o755); err != nil {
		t.Fatal(err)
	}
	dockerfile := filepath.Join(ctxDir, "Dockerfile")
	if err := os.WriteFile(dockerfile, []byte("FROM scratch\nCOPY app /app\nENTRYPOINT [\"/app\"]"), 0o644); err != nil {
		t.Fatal(err)
	}
	// noStore: this fixture wants the ARTIFACT only. A build normally also
	// records the image in the node's store, which needs a running daemon this
	// test has no business requiring.
	if err := buildWith(t.Context(), buildOptions{
		dockerfile: dockerfile,
		tag:        tag,
		output:     layoutDir,
		format:     "oci",
		contextDir: ctxDir,
	}, io.Discard, engineBuild, noStore, noPush); err != nil {
		t.Fatalf("build fixture: %v", err)
	}
}

// layoutDigest is the digest of the single image in dir, derived independently
// of the push path so a broken reader cannot agree with itself.
func layoutDigest(t *testing.T, dir string) string {
	t.Helper()
	img, err := layoutImage(dir)
	if err != nil {
		t.Fatalf("read fixture layout: %v", err)
	}
	d, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return d.String()
}

// assertRegistryHolds pulls the reference back and re-hashes every blob the
// manifest names, so the assertion is that the CONTENT arrived — not merely
// that the registry accepted a manifest.
//
// The blobs are compared as they are stored, because `k3sm build --format oci`
// emits genuinely uncompressed layers under an uncompressed media type; a
// reader that assumes gzip cannot read them back.
func assertRegistryHolds(t *testing.T, ref, wantDigest string) {
	t.Helper()
	parsed, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	pulled, err := remote.Image(parsed, remote.WithContext(t.Context()))
	if err != nil {
		t.Fatalf("pull back %s: %v", ref, err)
	}
	got, err := pulled.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != wantDigest {
		t.Errorf("registry holds %s, want %s", got, wantDigest)
	}
	manifest, err := pulled.Manifest()
	if err != nil {
		t.Fatalf("read back the manifest: %v", err)
	}
	rawConfig, err := pulled.RawConfigFile()
	if err != nil {
		t.Fatalf("read back the config blob: %v", err)
	}
	configDigest, _, err := ggcrv1.SHA256(bytes.NewReader(rawConfig))
	if err != nil {
		t.Fatal(err)
	}
	if configDigest != manifest.Config.Digest {
		t.Errorf("config blob hashes to %s, manifest names %s", configDigest, manifest.Config.Digest)
	}
	layers, err := pulled.Layers()
	if err != nil {
		t.Fatalf("read back the layers: %v", err)
	}
	if len(layers) != len(manifest.Layers) {
		t.Fatalf("registry holds %d layers, manifest names %d", len(layers), len(manifest.Layers))
	}
	for i, l := range layers {
		rc, err := l.Compressed()
		if err != nil {
			t.Fatalf("fetch layer %d: %v", i, err)
		}
		blobDigest, size, err := ggcrv1.SHA256(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("hash layer %d: %v", i, err)
		}
		if blobDigest != manifest.Layers[i].Digest {
			t.Errorf("layer %d hashes to %s, manifest names %s", i, blobDigest, manifest.Layers[i].Digest)
		}
		if size != manifest.Layers[i].Size {
			t.Errorf("layer %d is %d bytes, manifest names %d", i, size, manifest.Layers[i].Size)
		}
	}
}

// authProbe fronts a real registry, recording every Authorization header and —
// when require is set — refusing anything else, so the gate can assert both
// what was sent and how a refusal is reported.
type authProbe struct {
	inner   http.Handler
	require string

	mu   sync.Mutex
	seen []string
}

func (a *authProbe) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	got := r.Header.Get("Authorization")
	a.mu.Lock()
	a.seen = append(a.seen, got)
	a.mu.Unlock()
	// The ping is always allowed so the client negotiates a basic transport and
	// the refusal lands on the upload itself, which is where a real registry
	// with a scoped token puts it.
	if a.require != "" && r.URL.Path != "/v2/" && got != a.require {
		w.Header().Set("WWW-Authenticate", `Basic realm="k3sm-test"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	a.inner.ServeHTTP(w, r)
}

func (a *authProbe) headers() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.seen...)
}

// startRegistry runs an in-process registry on loopback and returns its
// host:port. Loopback is what makes the reference resolve over http.
func startRegistry(t *testing.T, require string) (string, *authProbe) {
	t.Helper()
	// The registry's own logging is discarded: a t.Log-backed writer would be
	// written to by connections the server has not finished closing when the
	// test ends, which panics.
	probe := &authProbe{inner: registry.New(registry.Logger(log.New(io.Discard, "", 0))), require: require}
	srv := httptest.NewServer(probe)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host, probe
}

// deadAddr returns a loopback address with nothing listening on it.
func deadAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}
