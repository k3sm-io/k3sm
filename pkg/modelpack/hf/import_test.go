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

package hf

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	artifactv1 "k3sm.io/apis/artifact/v1"

	"k3sm.io/k3sm/pkg/modelpack"
	"k3sm.io/k3sm/pkg/registryclient/registrytest"
)

const (
	commitA = "1111111111111111111111111111111111111111"
	commitB = "2222222222222222222222222222222222222222"
)

// registryHost is the test registry's host, served through hostTransport.
const registryHost = "registry.test"

// testRegistry is a writable in-process registry that counts the bytes sent
// to it in blob uploads.
type testRegistry struct {
	reg         *registrytest.Registry
	transport   hostTransport
	uploadBytes atomic.Int64
	pushes      atomic.Int32
}

func newTestRegistry(t *testing.T) *testRegistry {
	t.Helper()
	r := &testRegistry{reg: registrytest.New()}
	r.reg.AcceptWrites = true
	r.transport = hostTransport{registryHost: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet && req.Method != http.MethodHead && strings.Contains(req.URL.Path, "/blobs/") {
			req.Body = struct {
				io.Reader
				io.Closer
			}{io.TeeReader(req.Body, &countWriter{n: &r.uploadBytes}), req.Body}
		}
		r.reg.Handler().ServeHTTP(w, req)
	})}
	return r
}

// countWriter adds what it is written to n.
type countWriter struct{ n *atomic.Int64 }

func (c *countWriter) Write(p []byte) (int, error) { c.n.Add(int64(len(p))); return len(p), nil }

// push is an ImportOptions.Push into the registry, as `k3sm model push`
// pushes: modelpack.Push.
func (r *testRegistry) push(t *testing.T, repo string) func(context.Context, *modelpack.Artifact) error {
	t.Helper()
	ref, err := name.ParseReference(registryHost + "/" + repo + ":latest")
	if err != nil {
		t.Fatal(err)
	}
	return func(ctx context.Context, a *modelpack.Artifact) error {
		r.pushes.Add(1)
		return modelpack.Push(ctx, ref, a, remote.WithTransport(r.transport))
	}
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func mustRef(t *testing.T, s string) Ref {
	t.Helper()
	r, err := ParseRef(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestImportPinsCommit: a branch is resolved to its commit once, every later
// request (the listing and each file) names that commit and never the
// branch, so a branch that moves mid-import changes nothing, and the
// manifest records the source and the commit.
func TestImportPinsCommit(t *testing.T) {
	hub := newFakeHub(t)
	hub.addCommit("main", commitA, tinyModel("a")...)
	hub.addCommit("", commitB, tinyModel("b")...)
	hub.moveAfterResolve["main"] = commitB
	reg := newTestRegistry(t)

	res, err := hub.client(t).Import(testContext(t), mustRef(t, "hf://acme/tiny-model@main"), ImportOptions{
		ScratchDir: t.TempDir(),
		Push:       reg.push(t, "models/acme/tiny-model"),
	})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if res.Commit != commitA {
		t.Errorf("Commit = %s, want %s (the commit main named when it was resolved)", res.Commit, commitA)
	}
	for _, p := range hub.paths() {
		if strings.Contains(p, "/revision/") || strings.HasPrefix(p, "/blobs/") {
			continue
		}
		if !strings.Contains(p, "/"+commitA) || strings.Contains(p, "main") || strings.Contains(p, commitB) {
			t.Errorf("request %s does not name the pinned commit %s alone", p, commitA)
		}
	}

	var m ispec.Manifest
	if err := json.Unmarshal(res.Artifact.Manifest, &m); err != nil {
		t.Fatal(err)
	}
	if got := m.Annotations[ispec.AnnotationRevision]; got != commitA {
		t.Errorf("manifest %s = %q, want %s", ispec.AnnotationRevision, got, commitA)
	}
	if got := m.Annotations[ispec.AnnotationSource]; got != "hf://acme/tiny-model" {
		t.Errorf("manifest %s = %q, want hf://acme/tiny-model", ispec.AnnotationSource, got)
	}
	if m.ArtifactType != artifactv1.ArtifactTypeModel {
		t.Errorf("artifactType = %q, want %q", m.ArtifactType, artifactv1.ArtifactTypeModel)
	}
	for _, l := range m.Layers {
		if l.Annotations[artifactv1.AnnotationFilepath] == "config.json" {
			if !reg.reg.HasBlob("models/acme/tiny-model", l.Digest.String()) {
				t.Errorf("config.json blob %s not pushed", l.Digest)
			}
			if want := sha256Hex(tinyModel("a")[2].data); l.Digest.Encoded() != want {
				t.Errorf("config.json is %s, want commit %s's %s", l.Digest, commitA, want)
			}
		}
	}
	if got, ok := reg.reg.Manifest("models/acme/tiny-model", "latest"); !ok || got != res.Artifact.Digest.String() {
		t.Errorf("registry tag latest = %q (%v), want %s", got, ok, res.Artifact.Digest)
	}

	t.Run("a commit revision must come back as itself", func(t *testing.T) {
		res, err := hub.client(t).Import(testContext(t), mustRef(t, "hf://acme/tiny-model@"+commitB), ImportOptions{ScratchDir: t.TempDir()})
		if err != nil {
			t.Fatalf("Import at a commit: %v", err)
		}
		if res.Commit != commitB {
			t.Errorf("Commit = %s, want %s", res.Commit, commitB)
		}
	})
}

// TestImportVerifiesLFSSha256: an LFS file is checked against the sha256 the
// listing names, and that sha256 is its layer digest. One flipped byte, or a
// redirect whose X-Linked-Etag contradicts the listing, refuses the import
// before anything is pushed.
func TestImportVerifiesLFSSha256(t *testing.T) {
	t.Run("clean import: the Hub's sha256 is the layer digest", func(t *testing.T) {
		hub := newFakeHub(t)
		hub.addCommit("main", commitA, tinyModel("a")...)
		res, err := hub.client(t).Import(testContext(t), mustRef(t, "hf://acme/tiny-model"), ImportOptions{ScratchDir: t.TempDir()})
		if err != nil {
			t.Fatalf("Import: %v", err)
		}
		want := sha256Hex(tinyModel("a")[4].data)
		for _, l := range res.Artifact.Layers {
			if l.Path == "model.safetensors" && l.Descriptor.Digest.Encoded() != want {
				t.Errorf("model.safetensors layer = %s, want sha256:%s", l.Descriptor.Digest, want)
			}
		}
	})
	for _, tc := range []struct {
		name  string
		setup func(*fakeHub)
		want  string
	}{
		{"one corrupted byte", func(h *fakeHub) { h.corrupt["model.safetensors"] = true }, "sha256"},
		{"redirect etag contradicts the listing", func(h *fakeHub) { h.badEtag = `"` + strings.Repeat("ab", 32) + `"` }, "redirect"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hub := newFakeHub(t)
			hub.addCommit("main", commitA, tinyModel("a")...)
			tc.setup(hub)
			reg := newTestRegistry(t)
			_, err := hub.client(t).Import(testContext(t), mustRef(t, "hf://acme/tiny-model@main"), ImportOptions{
				ScratchDir: t.TempDir(),
				Push:       reg.push(t, "models/acme/tiny-model"),
			})
			if !errors.Is(err, ErrHashMismatch) {
				t.Fatalf("Import = %v, want ErrHashMismatch", err)
			}
			if !strings.Contains(err.Error(), "model.safetensors") || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name the file and the %s check", err, tc.want)
			}
			if n := reg.pushes.Load(); n != 0 {
				t.Errorf("Push called %d times after a refused file, want 0", n)
			}
			if w := reg.reg.Writes(); len(w) != 0 {
				t.Errorf("registry got writes %+v after a refused file", w)
			}
		})
	}
}

// TestImportVerifiesGitBlobForSmallFiles: a small (non-LFS) file is checked
// against its git blob id, sha1("blob <len>\x00" + bytes), the Hub's only
// commitment for it, and pushed under its computed sha256.
func TestImportVerifiesGitBlobForSmallFiles(t *testing.T) {
	// The git blob id is git's own: `printf 'hello\n' | git hash-object --stdin`.
	if got := gitBlobID([]byte("hello\n")); got != "ce013625030ba8dba906f756967f9e9ca394464a" {
		t.Fatalf("fixture git blob id of hello\\n = %s, want git's ce013625...", got)
	}

	hub := newFakeHub(t)
	hub.addCommit("main", commitA, tinyModel("a")...)
	res, err := hub.client(t).Import(testContext(t), mustRef(t, "hf://acme/tiny-model"), ImportOptions{ScratchDir: t.TempDir()})
	if err != nil {
		t.Fatalf("clean Import: %v", err)
	}
	for _, l := range res.Artifact.Layers {
		if l.Path == "hello.txt" && l.Descriptor.Digest.Encoded() != sha256Hex([]byte("hello\n")) {
			t.Errorf("hello.txt layer = %s, want its sha256", l.Descriptor.Digest)
		}
	}

	for _, p := range []string{"config.json", "tokenizer/tokenizer.json"} {
		t.Run("corrupted "+p, func(t *testing.T) {
			hub := newFakeHub(t)
			hub.addCommit("main", commitA, tinyModel("a")...)
			hub.corrupt[p] = true
			reg := newTestRegistry(t)
			_, err := hub.client(t).Import(testContext(t), mustRef(t, "hf://acme/tiny-model"), ImportOptions{
				ScratchDir: t.TempDir(),
				Push:       reg.push(t, "models/acme/tiny-model"),
			})
			if !errors.Is(err, ErrHashMismatch) || !strings.Contains(err.Error(), "git blob id") || !strings.Contains(err.Error(), p) {
				t.Fatalf("Import = %v, want ErrHashMismatch naming %s and its git blob id", err, p)
			}
			if n := reg.pushes.Load(); n != 0 {
				t.Errorf("Push called %d times, want 0", n)
			}
		})
	}

	t.Run("a --sha256 the file does not match refuses", func(t *testing.T) {
		hub := newFakeHub(t)
		hub.addCommit("main", commitA, tinyModel("a")...)
		_, err := hub.client(t).Import(testContext(t), mustRef(t, "hf://acme/tiny-model"), ImportOptions{
			ScratchDir: t.TempDir(),
			SHA256:     map[string]string{"config.json": strings.Repeat("0", 64)},
		})
		if !errors.Is(err, ErrHashMismatch) || !strings.Contains(err.Error(), "--sha256") {
			t.Fatalf("Import = %v, want ErrHashMismatch naming --sha256", err)
		}
	})
}

// TestImportIsIdempotent: importing the same commit twice uploads zero bytes
// the second time (every blob is already there, and the tag already names
// the manifest) and yields the same digest.
func TestImportIsIdempotent(t *testing.T) {
	hub := newFakeHub(t)
	hub.addCommit("main", commitA, tinyModel("a")...)
	reg := newTestRegistry(t)
	opts := ImportOptions{ScratchDir: t.TempDir(), Push: reg.push(t, "models/acme/tiny-model")}

	first, err := hub.client(t).Import(testContext(t), mustRef(t, "hf://acme/tiny-model@main"), opts)
	if err != nil {
		t.Fatalf("first Import: %v", err)
	}
	firstBytes, firstWrites := reg.uploadBytes.Load(), len(reg.reg.Writes())
	if firstBytes == 0 {
		t.Fatal("the first import uploaded nothing")
	}

	second, err := hub.client(t).Import(testContext(t), mustRef(t, "hf://acme/tiny-model@main"), opts)
	if err != nil {
		t.Fatalf("second Import: %v", err)
	}
	if got := reg.uploadBytes.Load() - firstBytes; got != 0 {
		t.Errorf("second import uploaded %d bytes, want 0", got)
	}
	if w := reg.reg.Writes()[firstWrites:]; len(w) != 0 {
		t.Errorf("second import wrote %+v, want nothing", w)
	}
	if first.Artifact.Digest != second.Artifact.Digest {
		t.Errorf("digests differ: %s then %s", first.Artifact.Digest, second.Artifact.Digest)
	}
}

// TestImportRefusesGatedRepoLegibly: a gated repository is refused with
// ErrGatedRepo and a message that names it and says why, before any file is
// listed or downloaded when the Hub says so up front, and at the first
// download when only the download says so. Nothing is pushed.
func TestImportRefusesGatedRepoLegibly(t *testing.T) {
	for _, tc := range []struct {
		name          string
		setup         func(*fakeHub)
		noFileRequest bool
	}{
		{"gated in the model info", func(h *fakeHub) { h.gated = "manual" }, true},
		{"gated at download", func(h *fakeHub) { h.gatedDownloads = true }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hub := newFakeHub(t)
			hub.addCommit("main", commitA, tinyModel("a")...)
			tc.setup(hub)
			reg := newTestRegistry(t)
			_, err := hub.client(t).Import(testContext(t), mustRef(t, "hf://acme/tiny-model"), ImportOptions{
				ScratchDir: t.TempDir(),
				Push:       reg.push(t, "models/acme/tiny-model"),
			})
			if !errors.Is(err, ErrGatedRepo) {
				t.Fatalf("Import = %v, want ErrGatedRepo", err)
			}
			if msg := err.Error(); !strings.Contains(msg, "acme/tiny-model") || !strings.Contains(msg, "gated") {
				t.Errorf("error %q does not name the repository and say it is gated", msg)
			}
			if tc.noFileRequest {
				for _, p := range hub.paths() {
					if !strings.Contains(p, "/revision/") {
						t.Errorf("request %s after the Hub said the repository is gated", p)
					}
				}
			}
			if n := reg.pushes.Load(); n != 0 {
				t.Errorf("Push called %d times, want 0", n)
			}
		})
	}
}
