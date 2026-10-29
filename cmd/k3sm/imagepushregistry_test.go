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
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"k3sm.io/k3sm/pkg/registryclient"
	"k3sm.io/k3sm/pkg/registryclient/registrytest"
	"k3sm.io/k3sm/pkg/registrysvc"
)

// TestImagePushFromClusterRegistry is the gate for pushing an image `k3sm
// build` recorded: it is in the cluster registry, not in this node's store, and
// push must find it there by the name image ls and inspect show, as they do.
//
// The cluster registry is the in-repo fake behind the test push gate, and it
// refuses an upload query carrying a key the distribution specification does
// not name, as the real gate does, so a mount the client spells the
// go-containerregistry way would fail here as it would on a node.
func TestImagePushFromClusterRegistry(t *testing.T) {
	empty := t.TempDir()
	t.Setenv("HOME", empty)
	t.Setenv("DOCKER_CONFIG", empty)
	t.Setenv(registryTokenEnv, "")

	darwin := registryclient.Platform{OS: "darwin", Architecture: "arm64"}
	base, app := []byte("base layer"), []byte("app layer")
	digestOf := func(t *testing.T, reg *registrytest.Registry, repo, tag string) string {
		t.Helper()
		d, ok := reg.Manifest(repo, tag)
		if !ok {
			t.Fatalf("the registry holds no %s:%s", repo, tag)
		}
		return d
	}

	setup := func(t *testing.T) (reg *registrytest.Registry, sock, workDir string) {
		t.Helper()
		reg = registrytest.New()
		reg.AcceptWrites = true
		reg.Image("stockkitty-darwin", "abc123", darwin, base, app)
		inner := reg.Handler()
		g := startGateRegistryWith(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Query().Has("origin") {
				http.Error(w, "the request path or query is not one this registry accepts", http.StatusBadRequest)
				return
			}
			inner.ServeHTTP(w, r)
		}))
		clusterAPIFor(t, g)
		workDir = asServer(t, g.port)
		// The per-boot credential root reads, which makes 127.0.0.1:6450 a
		// cluster-registry spelling, the one the build's own hint prints.
		if err := os.MkdirAll(registrysvc.StateDir(workDir), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := registrysvc.WriteCredential(workDir, registrysvc.Credential{Address: "127.0.0.1:6450", Username: "k3sm", Password: "secret"}); err != nil {
			t.Fatal(err)
		}
		fake := &fakeImagesDaemon{saveErr: status.Error(codes.NotFound, "image: no such image in the local index")}
		return reg, serveFakeImages(t, fake), workDir
	}
	push := func(t *testing.T, sock, workDir, src, dst string) (string, error) {
		t.Helper()
		return runImageCmd(t, []string{"--socket", sock, "--work-dir", workDir, "push", src, dst})
	}

	t.Run("a registry-held image is copied to another repository by mount", func(t *testing.T) {
		reg, sock, workDir := setup(t)
		want := digestOf(t, reg, "stockkitty-darwin", "abc123")
		out, err := push(t, sock, workDir, "stockkitty-darwin:abc123", "127.0.0.1:6450/team/stockkitty:v1")
		if err != nil {
			t.Fatalf("push: %v", err)
		}
		if !strings.Contains(out, "pushed registry-k3sm:6450/team/stockkitty:v1") || !strings.Contains(out, want) {
			t.Errorf("push output = %q, want the flat name and digest %s", out, want)
		}
		if got := digestOf(t, reg, "team/stockkitty", "v1"); got != want {
			t.Errorf("team/stockkitty:v1 = %s, want %s", got, want)
		}
		mounted := map[string]bool{}
		for _, w := range reg.Writes() {
			switch w.Op {
			case "upload":
				t.Errorf("blob %s was sent to %s again; the same registry mounts it", w.Digest, w.Repository)
			case "mount":
				if w.From != "stockkitty-darwin" {
					t.Errorf("blob %s mounted from %q, want stockkitty-darwin", w.Digest, w.From)
				}
				mounted[w.Digest] = true
			}
		}
		for _, l := range [][]byte{base, app} {
			if d := sha(l); !mounted[d] || !reg.HasBlob("team/stockkitty", d) {
				t.Errorf("layer %s was not mounted into team/stockkitty", d)
			}
		}
	})

	t.Run("the same repository and tag copies nothing", func(t *testing.T) {
		reg, sock, workDir := setup(t)
		for _, dst := range []string{"127.0.0.1:6450/stockkitty-darwin:abc123", "registry-k3sm:6450/stockkitty-darwin:abc123", "stockkitty-darwin:abc123"} {
			out, err := push(t, sock, workDir, "stockkitty-darwin:abc123", dst)
			if err != nil {
				t.Fatalf("push to %s: %v", dst, err)
			}
			if !strings.Contains(out, "is already in the cluster registry") {
				t.Errorf("push to %s printed %q, want it to say the image is already there", dst, out)
			}
		}
		if w := reg.Writes(); len(w) != 0 {
			t.Errorf("a push onto its own name wrote %v", w)
		}
	})

	t.Run("a blob the destination has is not sent again", func(t *testing.T) {
		reg, sock, workDir := setup(t)
		reg.Image("team/stockkitty", "old", darwin, base)
		if _, err := push(t, sock, workDir, "registry-k3sm:6450/stockkitty-darwin:abc123", "registry-k3sm:6450/team/stockkitty:v1"); err != nil {
			t.Fatalf("push: %v", err)
		}
		for _, w := range reg.Writes() {
			if w.Digest == sha(base) && w.Op != "manifest" {
				t.Errorf("the base layer the destination holds was written again: %+v", w)
			}
		}
		if !reg.HasBlob("team/stockkitty", sha(app)) {
			t.Errorf("the app layer did not arrive")
		}
	})

	t.Run("an image in neither store names both places", func(t *testing.T) {
		reg, sock, workDir := setup(t)
		out, err := push(t, sock, workDir, "missing:v9", "registry-k3sm:6450/team/missing:v9")
		if err == nil {
			t.Fatalf("push of an image nobody holds succeeded: %s", out)
		}
		for _, want := range []string{"not in this node's store", "no such image in the local index", "not in the cluster registry", "registry-k3sm:6450/missing:v9"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error = %v, want it to say %q", err, want)
			}
		}
		if w := reg.Writes(); len(w) != 0 {
			t.Errorf("a failed push wrote %v", w)
		}
	})
}

// sha is the sha256 digest of b, as a registry names a blob.
func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
