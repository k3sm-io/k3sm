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

package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// referrerOf pushes an artifact manifest in repo naming subject, with its own
// config blob, and returns the manifest body and the config digest.
func (f *fixture) referrerOf(t *testing.T, repo string, subject []byte, seed string) ([]byte, digest.Digest) {
	t.Helper()
	cfg := []byte(seed)
	cd := f.pushBlob(t, repo, cfg)
	m := ispec.Manifest{
		MediaType: ispec.MediaTypeImageManifest, ArtifactType: "application/vnd.example.sig",
		Config:  ispec.Descriptor{MediaType: ispec.MediaTypeEmptyJSON, Digest: cd, Size: int64(len(cfg))},
		Layers:  []ispec.Descriptor{},
		Subject: &ispec.Descriptor{MediaType: ispec.MediaTypeImageManifest, Digest: dg(subject), Size: int64(len(subject))},
	}
	m.SchemaVersion = 2
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	want(t, f.pushManifest(t, repo, dg(body).String(), ispec.MediaTypeImageManifest, body), http.StatusCreated, "")
	return body, cd
}

// imageBlobs returns the config and layer digests of manifest body.
func imageBlobs(t *testing.T, body []byte) []digest.Digest {
	t.Helper()
	var m ispec.Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	ds := []digest.Digest{m.Config.Digest}
	for _, l := range m.Layers {
		ds = append(ds, l.Digest)
	}
	return ds
}

// TestReadPathsAfterReap pins what every registry read path answers once one
// sweep has reaped content, with the referrers view warm before the sweep and
// cold (a second server over the swept store) after it. In "app" the sweep
// reaps an untagged image past the grace and keeps a tagged one. A signature
// is kept while its subject is (gc makePlan), so the tagged image keeps its
// signature and the reaped one's goes with it. "gone" was emptied by a DELETE, so the sweep reaps its
// blobs (older than its index, which lifts the half brake) and drops its layout.
//
//   - referrers of a reaped subject: 200 with an empty list, the spec's answer
//     for an unknown subject, warm or cold, and the signature and its config
//     answer 404; the reaped subject's row is never read again;
//   - tag list: the tagged name only; of the dropped repository, 404 NAME_UNKNOWN;
//   - catalog: "app" only, once the layout of "gone" is removed;
//   - GET and HEAD of a reaped manifest: 404 MANIFEST_UNKNOWN (HEAD no body);
//   - GET and HEAD of a reaped manifest's config and layer: 404 BLOB_UNKNOWN,
//     and of the kept image's blobs: 200.
//
// The store and gc tests pin what the sweep keeps; the manifest 404 framing
// is pinned by TestManifestReapedMidReadAnswers404OnEveryPath.
func TestReadPathsAfterReap(t *testing.T) {
	const grace = time.Hour
	f := newFixture(t)
	old := time.Now().Add(-2 * grace)

	keptImg := f.image(t, "app", "kept", "kept-layer")
	keptSig, keptSigCfg := f.referrerOf(t, "app", keptImg, "kept-sig-cfg")
	reapedImg := f.image(t, "app", "", "reaped-layer")
	reapedSig, reapedSigCfg := f.referrerOf(t, "app", reapedImg, "reaped-sig-cfg")
	goneImg := f.image(t, "gone", "", "gone-layer")
	// "gone" was emptied by a client DELETE long ago: its blobs and index are
	// old, so the sweep reaps the blobs and then the empty layout.
	want(t, f.do(http.MethodDelete, "/v2/gone/manifests/"+dg(goneImg).String(), nil), http.StatusAccepted, "")

	reapedBlobs := append(imageBlobs(t, reapedImg), reapedSigCfg)
	f.age(t, "app", old, append([]digest.Digest{dg(reapedImg), dg(reapedSig), dg(keptSig), keptSigCfg}, reapedBlobs...)...)
	goneBlobs := imageBlobs(t, goneImg)
	f.age(t, "gone", old.Add(-grace), append([]digest.Digest{dg(goneImg)}, goneBlobs...)...)
	if err := os.Chtimes(filepath.Join(f.root, "gone", "index.json"), old, old); err != nil {
		t.Fatal(err)
	}

	referrers := func(f *fixture, repo string, subject []byte) []digest.Digest {
		t.Helper()
		w := f.do(http.MethodGet, "/v2/"+repo+"/referrers/"+dg(subject).String(), nil)
		want(t, w, http.StatusOK, "")
		var idx ispec.Index
		if err := json.Unmarshal(w.Body.Bytes(), &idx); err != nil || idx.Manifests == nil {
			t.Fatalf("referrers %s: %v", w.Body.String(), err)
		}
		var ds []digest.Digest
		for _, d := range idx.Manifests {
			ds = append(ds, d.Digest)
		}
		return ds
	}
	// Warm the view of both subjects, so the sweep reaps rows it holds.
	if got := referrers(f, "app", reapedImg); !slices.Equal(got, []digest.Digest{dg(reapedSig)}) {
		t.Fatalf("referrers before the sweep %v, want the signature", got)
	}
	if got := referrers(f, "app", keptImg); !slices.Equal(got, []digest.Digest{dg(keptSig)}) {
		t.Fatalf("referrers of the kept image before the sweep %v", got)
	}

	deletingSweep(t, f.deletingCollector(t, grace))

	var reads []digest.Digest
	for _, srv := range []struct {
		name string
		f    *fixture
	}{{"warm", f}, {"cold", f.clone(t)}} {
		srv.f.srv.referrerRead = func(d digest.Digest) { reads = append(reads, d) }
		t.Run(srv.name, func(t *testing.T) {
			f := srv.f
			t.Run("referrers of a reaped subject go with it", func(t *testing.T) {
				if got := referrers(f, "app", reapedImg); len(got) != 0 {
					t.Errorf("referrers %v, want none", got)
				}
			})
			t.Run("referrers of a kept subject remain", func(t *testing.T) {
				if got := referrers(f, "app", keptImg); !slices.Equal(got, []digest.Digest{dg(keptSig)}) {
					t.Errorf("referrers %v, want the kept signature", got)
				}
			})
			t.Run("tag list", func(t *testing.T) {
				if tags, _ := f.tagsOf(t, "app", ""); !slices.Equal(tags, []string{"kept"}) {
					t.Errorf("tags %v, want [kept]", tags)
				}
				want(t, f.do(http.MethodGet, "/v2/gone/tags/list", nil), http.StatusNotFound, codeNameUnknown)
			})
			t.Run("catalog", func(t *testing.T) {
				w := f.do(http.MethodGet, "/v2/_catalog", nil)
				want(t, w, http.StatusOK, "")
				var c struct {
					Repositories []string `json:"repositories"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil || !slices.Equal(c.Repositories, []string{"app"}) {
					t.Errorf("catalog %s (%v), want [app]", w.Body.String(), err)
				}
			})
			t.Run("manifests", func(t *testing.T) {
				for _, m := range []struct {
					repo string
					body []byte
				}{{"app", reapedImg}, {"app", reapedSig}, {"gone", goneImg}} {
					p := "/v2/" + m.repo + "/manifests/" + dg(m.body).String()
					code := codeManifestUnknown
					if m.repo == "gone" {
						code = codeNameUnknown
					}
					want(t, f.do(http.MethodGet, p, nil), http.StatusNotFound, code)
					if w := f.do(http.MethodHead, p, nil); w.Code != http.StatusNotFound || w.Body.Len() != 0 {
						t.Errorf("HEAD %s: %d with %d body bytes", p, w.Code, w.Body.Len())
					}
				}
				want(t, f.do(http.MethodGet, "/v2/app/manifests/"+dg(keptSig).String(), nil), http.StatusOK, "")
				want(t, f.do(http.MethodGet, "/v2/app/manifests/kept", nil), http.StatusOK, "")
			})
			t.Run("blobs", func(t *testing.T) {
				for _, b := range []struct {
					repo string
					d    digest.Digest
					live bool
				}{
					{"app", reapedBlobs[0], false}, {"app", reapedBlobs[1], false}, {"app", reapedSigCfg, false},
					{"gone", goneBlobs[0], false}, {"gone", goneBlobs[1], false},
					{"app", imageBlobs(t, keptImg)[0], true}, {"app", imageBlobs(t, keptImg)[1], true},
				} {
					p := "/v2/" + b.repo + "/blobs/" + b.d.String()
					for _, method := range []string{http.MethodGet, http.MethodHead} {
						w := f.do(method, p, nil)
						switch {
						case b.live:
							want(t, w, http.StatusOK, "")
						case method == http.MethodGet:
							want(t, w, http.StatusNotFound, codeBlobUnknown)
						default:
							if w.Code != http.StatusNotFound || w.Body.Len() != 0 {
								t.Errorf("HEAD %s: %d with %d body bytes", p, w.Code, w.Body.Len())
							}
						}
					}
				}
			})
		})
	}
	for _, d := range reads {
		if d == dg(reapedImg) {
			t.Errorf("the referrers view read the reaped manifest %s after the sweep", d)
		}
	}
}
