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
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"k3sm.io/k3sm/pkg/registryclient"
	"k3sm.io/k3sm/pkg/registryclient/registrytest"
	"k3sm.io/k3sm/pkg/registrysvc"
)

// TestImagePushFromClusterRegistry is the gate for pushing an image `k3sm
// build` recorded: it is in the cluster registry, not in this node's store, and
// push must find it there by the name image ls and inspect show, as they do.
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
		reg.Image("myapp-darwin", "abc123", darwin, base, app)
		g := startGateRegistryWith(t, reg.Handler())
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
		want := digestOf(t, reg, "myapp-darwin", "abc123")
		out, err := push(t, sock, workDir, "myapp-darwin:abc123", "127.0.0.1:6450/team/myapp:v1")
		if err != nil {
			t.Fatalf("push: %v", err)
		}
		if !strings.Contains(out, "pushed registry-k3sm:6450/team/myapp:v1") || !strings.Contains(out, want) {
			t.Errorf("push output = %q, want the flat name and digest %s", out, want)
		}
		if got := digestOf(t, reg, "team/myapp", "v1"); got != want {
			t.Errorf("team/myapp:v1 = %s, want %s", got, want)
		}
		mounted := map[string]bool{}
		for _, w := range reg.Writes() {
			switch w.Op {
			case "upload":
				t.Errorf("blob %s was sent to %s again; the same registry mounts it", w.Digest, w.Repository)
			case "mount":
				if w.From != "myapp-darwin" {
					t.Errorf("blob %s mounted from %q, want myapp-darwin", w.Digest, w.From)
				}
				mounted[w.Digest] = true
			}
		}
		for _, l := range [][]byte{base, app} {
			if d := sha(l); !mounted[d] || !reg.HasBlob("team/myapp", d) {
				t.Errorf("layer %s was not mounted into team/myapp", d)
			}
		}
	})

	t.Run("the same repository and tag copies nothing", func(t *testing.T) {
		reg, sock, workDir := setup(t)
		for _, dst := range []string{"127.0.0.1:6450/myapp-darwin:abc123", "registry-k3sm:6450/myapp-darwin:abc123", "myapp-darwin:abc123"} {
			out, err := push(t, sock, workDir, "myapp-darwin:abc123", dst)
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
		reg.Image("team/myapp", "old", darwin, base)
		if _, err := push(t, sock, workDir, "registry-k3sm:6450/myapp-darwin:abc123", "registry-k3sm:6450/team/myapp:v1"); err != nil {
			t.Fatalf("push: %v", err)
		}
		for _, w := range reg.Writes() {
			if w.Digest == sha(base) && w.Op != "manifest" {
				t.Errorf("the base layer the destination holds was written again: %+v", w)
			}
		}
		if !reg.HasBlob("team/myapp", sha(app)) {
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

// TestImagePushMountHasNoTokenRefreshRace is the gate for a push that mounts
// several layers from another repository of the same registry. The writer
// asks for the source repository's pull scope the first time it mounts from
// it, and that refresh replaces the HTTP client every concurrent layer upload
// reads. Each path must give the writer that scope before any layer upload
// runs, so no refresh (a /v2/ ping) ever happens while a blob request is in
// flight, and every layer must still arrive by mount. Under -race the overlap
// is also the data race itself.
func TestImagePushMountHasNoTokenRefreshRace(t *testing.T) {
	darwin := registryclient.Platform{OS: "darwin", Architecture: "arm64"}
	linux := registryclient.Platform{OS: "linux", Architecture: "arm64"}
	layersOf := func(prefix string) [][]byte {
		var ls [][]byte
		for i := range 6 {
			ls = append(ls, []byte(fmt.Sprintf("%s layer %d", prefix, i)))
		}
		return ls
	}
	cases := []struct {
		name string
		// seed fills the registry and returns the source repository and the
		// layers that must be mounted from it.
		seed func(reg *registrytest.Registry) (string, [][]byte)
		args []string
	}{{
		name: "image push",
		seed: func(reg *registrytest.Registry) (string, [][]byte) {
			ls := layersOf("image")
			reg.Image("myapp-darwin", "abc123", darwin, ls...)
			return "myapp-darwin", ls
		},
		args: []string{"push", "myapp-darwin:abc123", "127.0.0.1:6450/team/myapp:v1"},
	}, {
		name: "index push",
		seed: func(reg *registrytest.Registry) (string, [][]byte) {
			dl, ll := layersOf("darwin"), layersOf("linux")
			a := reg.Image("myapp", "darwin", darwin, dl...)
			b := reg.Image("myapp", "linux", linux, ll...)
			reg.Index("myapp", "multi", a, b)
			return "myapp", append(dl, ll...)
		},
		args: []string{"push", "myapp:multi", "127.0.0.1:6450/team/myapp:v1"},
	}, {
		name: "cross-repository tag",
		seed: func(reg *registrytest.Registry) (string, [][]byte) {
			ls := layersOf("tag")
			reg.Image("myapp-darwin", "abc123", darwin, ls...)
			return "myapp-darwin", ls
		},
		args: []string{"tag", "myapp-darwin:abc123", "registry-k3sm:6450/team/myapp:v1"},
	}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			empty := t.TempDir()
			t.Setenv("HOME", empty)
			t.Setenv("DOCKER_CONFIG", empty)
			t.Setenv(registryTokenEnv, "")

			reg := registrytest.New()
			reg.AcceptWrites = true
			from, layers := tc.seed(reg)
			watch := &refreshWatch{inner: reg.Handler()}
			g := startGateRegistryWith(t, watch)
			clusterAPIFor(t, g)
			args := tc.args
			if tc.args[0] == "tag" {
				// Tag writes as an ordinary account, through the gate with a
				// builder token.
				asCredentiallessServer(t, 16450, g.port)
			} else {
				workDir := asServer(t, g.port)
				if err := os.MkdirAll(registrysvc.StateDir(workDir), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := registrysvc.WriteCredential(workDir, registrysvc.Credential{Address: "127.0.0.1:6450", Username: "k3sm", Password: "secret"}); err != nil {
					t.Fatal(err)
				}
				sock := serveFakeImages(t, &fakeImagesDaemon{saveErr: status.Error(codes.NotFound, "image: no such image in the local index")})
				args = append([]string{"--socket", sock, "--work-dir", workDir}, tc.args...)
			}
			if out, err := runImageCmd(t, args); err != nil {
				t.Fatalf("%s: %v\n%s", tc.args[0], err, out)
			}
			if n := watch.overlaps(); n != 0 {
				t.Errorf("the writer refreshed its token %d time(s) while a layer upload was in flight; the mount source's pull scope must be in place before the uploads start", n)
			}
			mounts := watch.mountsInto("team/myapp")
			for _, l := range layers {
				d := sha(l)
				if got := mounts[d]; got != from {
					t.Errorf("layer %s: mount request from %q, want ?mount=%s&from=%s", d, got, d, from)
				}
				if !reg.HasBlob("team/myapp", d) {
					t.Errorf("layer %s was not mounted into team/myapp", d)
				}
			}
			for _, w := range reg.Writes() {
				if w.Op == "upload" {
					t.Errorf("blob %s was sent to %s again; the same registry mounts it", w.Digest, w.Repository)
				}
			}
		})
	}
}

// refreshWatch counts the /v2/ pings (each one a writer building a new
// transport, the token refresh) that arrive while a blob request is in
// flight. The first blob request is held, so a refresh any other concurrent
// layer upload triggers lands inside it.
type refreshWatch struct {
	inner http.Handler

	mu       sync.Mutex
	held     bool
	inFlight int
	overlap  int
	// mounts maps repository to digest to the from parameter of each
	// blob mount request (POST .../blobs/uploads/?mount=<digest>&from=<repo>).
	mounts map[string]map[string]string
}

func (r *refreshWatch) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	switch {
	case req.URL.Path == "/v2/" || req.URL.Path == "/v2":
		r.mu.Lock()
		if r.inFlight > 0 {
			r.overlap++
		}
		r.mu.Unlock()
	case strings.Contains(req.URL.Path, "/blobs/"):
		r.mu.Lock()
		if q := req.URL.Query(); req.Method == http.MethodPost && q.Get("mount") != "" {
			repo := strings.TrimSuffix(strings.TrimPrefix(req.URL.Path, "/v2/"), "/blobs/uploads/")
			if r.mounts == nil {
				r.mounts = map[string]map[string]string{}
			}
			if r.mounts[repo] == nil {
				r.mounts[repo] = map[string]string{}
			}
			r.mounts[repo][q.Get("mount")] = q.Get("from")
		}
		r.inFlight++
		hold := !r.held
		r.held = true
		r.mu.Unlock()
		defer func() {
			r.mu.Lock()
			r.inFlight--
			r.mu.Unlock()
		}()
		if hold {
			time.Sleep(300 * time.Millisecond)
		}
	}
	r.inner.ServeHTTP(w, req)
}

func (r *refreshWatch) mountsInto(repo string) map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]string{}
	for d, from := range r.mounts[repo] {
		out[d] = from
	}
	return out
}

func (r *refreshWatch) overlaps() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.overlap
}

// sha is the sha256 digest of b, as a registry names a blob.
func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
