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

package registrysvc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

const (
	manifestType = ispec.MediaTypeImageManifest
	indexType    = ispec.MediaTypeImageIndex
)

// layoutRepo writes a repository by hand, as the registry server leaves it:
// the given index.json rows and the given blobs, every blob age old.
func layoutRepo(t *testing.T, workDir, repo string, index any, blobs map[string][]byte, age time.Duration) {
	t.Helper()
	dir := filepath.Join(StateDir(workDir), filepath.FromSlash(repo))
	if err := os.MkdirAll(filepath.Join(dir, "blobs", "sha256"), 0o700); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for dg, body := range blobs {
		p := filepath.Join(dir, "blobs", "sha256", strings.TrimPrefix(dg, "sha256:"))
		if err := os.WriteFile(p, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ageBlobs(t, workDir, repo, age, keys(blobs)...)
}

// ageBlobs sets the mtime of the named blobs of repo to age ago.
func ageBlobs(t *testing.T, workDir, repo string, age time.Duration, digests ...string) {
	t.Helper()
	when := time.Now().Add(-age)
	for _, dg := range digests {
		p := filepath.Join(StateDir(workDir), filepath.FromSlash(repo), "blobs", "sha256", strings.TrimPrefix(dg, "sha256:"))
		if err := os.Chtimes(p, when, when); err != nil {
			t.Fatal(err)
		}
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func digestOf(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// row is an index.json row for body, tagged when tag is set.
func row(body []byte, mediaType, tag string) map[string]any {
	e := map[string]any{"mediaType": mediaType, "digest": digestOf(body), "size": len(body)}
	if tag != "" {
		e["annotations"] = map[string]string{ispec.AnnotationRefName: tag}
	}
	return e
}

func idx(rows ...map[string]any) map[string]any {
	return map[string]any{"schemaVersion": 2, "manifests": rows}
}

// manifestBody is a distinct image manifest body.
func manifestBody(seed string) []byte {
	return fmt.Appendf(nil, `{"schemaVersion":2,"mediaType":%q,"annotations":{"seed":%q}}`, manifestType, seed)
}

// indexBody is an image index naming children.
func indexBody(t *testing.T, children ...[]byte) []byte {
	t.Helper()
	var ds []ispec.Descriptor
	for _, c := range children {
		ds = append(ds, ispec.Descriptor{MediaType: manifestType, Digest: digest.FromBytes(c), Size: int64(len(c))})
	}
	b, err := json.Marshal(ispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: indexType, Manifests: ds})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func digests(ms []StoredManifest) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.Digest)
	}
	return out
}

func TestPruneGraceIsTheGCDelay(t *testing.T) {
	d, err := time.ParseDuration(gcDelay)
	if err != nil || d != PruneGrace {
		t.Errorf("PruneGrace = %v, gcDelay = %q (%v): they must agree", PruneGrace, gcDelay, err)
	}
}

func TestPlanRepositoryFailsClosed(t *testing.T) {
	old := 2 * time.Hour
	a, b := manifestBody("a"), manifestBody("b")
	da, db := digestOf(a), digestOf(b)

	t.Run("a missing manifest blob keeps every untagged manifest", func(t *testing.T) {
		wd := t.TempDir()
		layoutRepo(t, wd, "r", idx(row(a, manifestType, "v1"), row(b, manifestType, "")), map[string][]byte{db: b}, old)
		p := PlanRepository(wd, "r", time.Now())
		if len(p.Delete) != 0 || len(p.Kept) != 1 || p.Kept[0].Reason != KeepUnreadable {
			t.Errorf("plan = %+v; want %s kept as unreadable", p, db)
		}
	})

	t.Run("a body that is not the row's digest keeps every untagged manifest", func(t *testing.T) {
		wd := t.TempDir()
		r := row(b, manifestType, "")
		layoutRepo(t, wd, "r", idx(row(a, manifestType, ""), r), map[string][]byte{da: a}, old)
		// Overwrite b's blob path with a's bytes: same size, wrong content.
		p := filepath.Join(StateDir(wd), "r", "blobs", "sha256", strings.TrimPrefix(db, "sha256:"))
		if err := os.WriteFile(p, a, 0o600); err != nil {
			t.Fatal(err)
		}
		ageBlobs(t, wd, "r", old, db)
		if plan := PlanRepository(wd, "r", time.Now()); len(plan.Delete) != 0 {
			t.Errorf("delete = %v; want nothing from a repository with a corrupt manifest", digests(plan.Delete))
		}
	})

	t.Run("a digest that is no digest makes the repository unreadable", func(t *testing.T) {
		wd := t.TempDir()
		layoutRepo(t, wd, "r", idx(map[string]any{"mediaType": manifestType, "digest": "sha256:../../etc", "size": 1}), nil, old)
		p := PlanRepository(wd, "r", time.Now())
		if len(p.Delete) != 0 || len(p.Unreadable) != 1 {
			t.Errorf("plan = %+v; want the repository unreadable", p)
		}
	})

	t.Run("an unparsable index makes the repository unreadable", func(t *testing.T) {
		wd := t.TempDir()
		layoutRepo(t, wd, "r", "not an index", nil, old)
		if p := PlanRepository(wd, "r", time.Now()); len(p.Unreadable) != 1 {
			t.Errorf("plan = %+v; want the repository unreadable", p)
		}
	})

	t.Run("a name that is no repository name is unreadable", func(t *testing.T) {
		if p := PlanRepository(t.TempDir(), "../r", time.Now()); len(p.Unreadable) != 1 {
			t.Errorf("plan = %+v; want the repository unreadable", p)
		}
	})
}

func TestRepositoriesFindsNestedLayoutsOnly(t *testing.T) {
	wd := t.TempDir()
	layoutRepo(t, wd, "a", idx(), nil, 0)
	layoutRepo(t, wd, "team/b", idx(), nil, 0)
	// A layout-shaped directory inside a repository's blobs is never a
	// repository, and the server's own files at the root are not either.
	layoutRepo(t, wd, "a/blobs/fake", idx(), nil, 0)
	if err := WriteCredential(wd, Credential{Address: "127.0.0.1:6450", Username: "k3sm", Password: "x"}); err != nil {
		t.Fatal(err)
	}
	got, err := Repositories(wd)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "a" || got[1] != "team/b" {
		t.Errorf("repositories = %v; want [a team/b]", got)
	}
}

// TestPruneThroughTheStore pins prune's plan as read through the store, and
// its deletes as API calls the server makes, so the server is the only writer.
func TestPruneThroughTheStore(t *testing.T) {
	old := 2 * time.Hour

	t.Run("a tagged digest is never deleted, whatever other rows it has", func(t *testing.T) {
		wd := t.TempDir()
		a, b := manifestBody("a"), manifestBody("b")
		layoutRepo(t, wd, "r", idx(row(a, manifestType, ""), row(a, manifestType, "v1"), row(b, manifestType, "")),
			map[string][]byte{digestOf(a): a, digestOf(b): b}, old)
		p := PlanRepository(wd, "r", time.Now())
		if got := digests(p.Delete); len(got) != 1 || got[0] != digestOf(b) {
			t.Errorf("delete = %v; want only %s (a delete by digest would drop v1)", got, digestOf(b))
		}
		if len(p.Kept) != 0 {
			t.Errorf("kept = %+v; a tagged manifest is in neither list", p.Kept)
		}
	})

	t.Run("an untagged index is deleted before the manifests it names", func(t *testing.T) {
		wd := t.TempDir()
		c1, c2, lone := manifestBody("c1"), manifestBody("c2"), manifestBody("lone")
		ix := indexBody(t, c1, c2)
		// The children and the lone manifest come first in index.json, as a
		// multi-platform push leaves them: children before their index.
		layoutRepo(t, wd, "r", idx(row(c1, manifestType, ""), row(lone, manifestType, ""), row(c2, manifestType, ""), row(ix, indexType, "")),
			map[string][]byte{digestOf(c1): c1, digestOf(c2): c2, digestOf(lone): lone, digestOf(ix): ix}, old)
		p := PlanRepository(wd, "r", time.Now())
		got := digests(p.Delete)
		want := []string{digestOf(ix), digestOf(c1), digestOf(lone), digestOf(c2)}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("delete = %v; want the index first, then the manifests in index order: %v", got, want)
		}
	})

	t.Run("planning writes nothing", func(t *testing.T) {
		wd := t.TempDir()
		a := manifestBody("a")
		layoutRepo(t, wd, "r", idx(row(a, manifestType, "")), map[string][]byte{digestOf(a): a}, old)
		ip := filepath.Join(StateDir(wd), "r", "index.json")
		before, err := os.ReadFile(ip)
		if err != nil {
			t.Fatal(err)
		}
		fiBefore, _ := os.Stat(ip)
		if _, err := PlanPrune(wd, time.Now()); err != nil {
			t.Fatal(err)
		}
		after, _ := os.ReadFile(ip)
		fiAfter, _ := os.Stat(ip)
		if string(before) != string(after) || !fiBefore.ModTime().Equal(fiAfter.ModTime()) {
			t.Error("planning rewrote index.json")
		}
		ents, err := os.ReadDir(wd)
		if err != nil {
			t.Fatal(err)
		}
		if len(ents) != 1 || ents[0].Name() != "registry" {
			t.Errorf("work dir holds %v after planning; want only the registry", ents)
		}
	})

	t.Run("a prune concurrent with a push does not lose the pushed tag", func(t *testing.T) {
		pruneConcurrentWithPush(t, old)
	})
}

// pruneConcurrentWithPush runs prune rounds (plan, then a DELETE per planned
// manifest through a fake registry API backed by the store) while a pusher
// writes multi-platform images through the same store: each push puts its
// child untagged, then the index that names it under a new tag. Both index.json
// writers are the server's own operations under the store's lock; prune only
// reads. At the end every pushed tag must resolve to the index pushed under it,
// every child must still be held, and the old untagged manifests must be gone.
func pruneConcurrentWithPush(t *testing.T, old time.Duration) {
	wd := t.TempDir()
	st, err := store.OpenWorkDir(wd)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	repo, err := ref.ParseName("app")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Init(ctx, repo); err != nil {
		t.Fatal(err)
	}

	// The seed: one old tagged image and old untagged leftovers.
	base := manifestBody("base")
	if _, err := st.PutManifest(ctx, repo, ref.Reference{Tag: "base"}, manifestType, base); err != nil {
		t.Fatal(err)
	}
	var stale []string
	for i := range 8 {
		b := manifestBody(fmt.Sprintf("stale-%d", i))
		if _, err := st.PutManifest(ctx, repo, ref.Reference{Digest: digest.FromBytes(b)}, manifestType, b); err != nil {
			t.Fatal(err)
		}
		stale = append(stale, digestOf(b))
	}
	ageBlobs(t, wd, "app", old, append([]string{digestOf(base)}, stale...)...)

	cred := Credential{Username: "k3sm", Password: "prune-test-secret"}
	srv := httptest.NewServer(fakeDeleteAPI(t, st, cred))
	defer srv.Close()
	apiDelete := func(m StoredManifest, c Credential) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, srv.URL+"/v2/"+m.Repository+"/manifests/"+m.Digest, nil)
		if err != nil {
			return err
		}
		req.SetBasicAuth(c.Username, c.Password)
		resp, err := srv.Client().Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusAccepted, http.StatusNotFound: // NotFound: an earlier round took it
			return nil
		default:
			return fmt.Errorf("DELETE %s: %s", m.Digest, resp.Status)
		}
	}

	// The fake API answers only the push credential.
	if err := apiDelete(StoredManifest{Repository: "app", Digest: stale[0]}, Credential{Username: "k3sm", Password: "wrong"}); err == nil {
		t.Fatal("the fake API took a DELETE without the push credential")
	}

	const pushes = 40
	type pushed struct{ tag, index, child string }
	results := make(chan pushed, pushes)
	pushErr := make(chan error, 1)
	done := make(chan struct{})
	children, indexes := make([][]byte, pushes), make([][]byte, pushes)
	for i := range pushes {
		children[i] = manifestBody(fmt.Sprintf("child-%d", i))
		indexes[i] = indexBody(t, children[i])
	}
	go func() {
		defer close(done)
		for i := range pushes {
			child := children[i]
			if _, err := st.PutManifest(ctx, repo, ref.Reference{Digest: digest.FromBytes(child)}, manifestType, child); err != nil {
				pushErr <- err
				return
			}
			ix := indexes[i]
			tag := fmt.Sprintf("v%d", i)
			if _, err := st.PutManifest(ctx, repo, ref.Reference{Tag: tag}, indexType, ix); err != nil {
				pushErr <- err
				return
			}
			results <- pushed{tag: tag, index: digestOf(ix), child: digestOf(child)}
		}
	}()

	var wg sync.WaitGroup
	var pruneErrs []error
	var rounds int
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			plan, err := PlanPrune(wd, time.Now())
			if err != nil {
				pruneErrs = append(pruneErrs, err)
				return
			}
			for _, m := range plan.Delete {
				if err := apiDelete(m, cred); err != nil {
					pruneErrs = append(pruneErrs, err)
				}
			}
			rounds++
		}
	}()
	<-done
	wg.Wait()
	close(results)
	select {
	case err := <-pushErr:
		t.Fatalf("push: %v", err)
	default:
	}
	if len(pruneErrs) > 0 {
		t.Fatalf("prune: %v", errors.Join(pruneErrs...))
	}
	// One round after the pushes, so the stale manifests are gone however the
	// rounds above interleaved.
	plan, err := PlanPrune(wd, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range plan.Delete {
		if err := apiDelete(m, cred); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("%d prune rounds ran during %d pushes", rounds, pushes)

	n := 0
	for p := range results {
		n++
		d, err := st.Resolve(repo, ref.Reference{Tag: p.tag})
		if err != nil {
			t.Errorf("pushed tag %s is lost: %v", p.tag, err)
			continue
		}
		if d.Digest.String() != p.index {
			t.Errorf("tag %s names %s; want the pushed index %s", p.tag, d.Digest, p.index)
		}
		if _, _, err := st.Manifest(repo, ref.Reference{Digest: digest.Digest(p.child)}); err != nil {
			t.Errorf("child %s of %s is gone: %v", p.child, p.tag, err)
		}
	}
	if n != pushes {
		t.Fatalf("%d pushes finished; want %d", n, pushes)
	}
	if _, err := st.Resolve(repo, ref.Reference{Tag: "base"}); err != nil {
		t.Errorf("the old tagged image is gone: %v", err)
	}
	for _, dg := range stale {
		if _, err := st.Resolve(repo, ref.Reference{Digest: digest.Digest(dg)}); !errors.Is(err, store.ErrManifestUnknown) {
			t.Errorf("stale untagged %s survived the prune: %v", dg, err)
		}
	}
}

// fakeDeleteAPI is the registry server's manifest DELETE, as far as prune uses
// it: basic auth with the push credential, then a delete by digest the store
// makes under its own lock.
func fakeDeleteAPI(t *testing.T, st *store.Store, cred Credential) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != cred.Username || p != cred.Password {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		rest, ok := strings.CutPrefix(r.URL.Path, "/v2/")
		repoPart, dgPart, found := strings.Cut(rest, "/manifests/")
		if r.Method != http.MethodDelete || !ok || !found {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		n, err := ref.ParseName(repoPart)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		d, err := ref.ParseDigest(dgPart)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch err := st.DeleteDigest(r.Context(), n, d); {
		case errors.Is(err, store.ErrManifestUnknown):
			w.WriteHeader(http.StatusNotFound)
		case err != nil:
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusAccepted)
		}
	})
}
