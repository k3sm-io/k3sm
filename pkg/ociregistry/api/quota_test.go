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
	"strconv"
	"strings"
	"testing"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	artifactv1 "k3sm.io/apis/artifact/v1"
)

// quotaModels is the model quota the tests configure, in bytes.
const quotaModels = 100

func withModelQuota(c *Config) {
	c.Quota = map[string]int64{artifactv1.ArtifactTypeModel: quotaModels}
}

// model pushes one blob per layer to repo and PUTs a model manifest naming
// them, at reference ("" for by digest), and returns the response and body.
// claim, when not negative, is the size every layer descriptor states instead
// of the layer's real size.
func (f *fixture) model(t *testing.T, repo, reference string, claim int64, layers ...string) (int, []byte, string) {
	t.Helper()
	cfg := []byte(`{}`)
	cd := f.pushBlob(t, repo, cfg)
	m := ispec.Manifest{
		MediaType:    ispec.MediaTypeImageManifest,
		ArtifactType: artifactv1.ArtifactTypeModel,
		Config:       ispec.Descriptor{MediaType: artifactv1.MediaTypeModelConfig, Digest: cd, Size: int64(len(cfg))},
	}
	m.SchemaVersion = 2
	for _, l := range layers {
		size := int64(len(l))
		if claim >= 0 {
			size = claim
		}
		m.Layers = append(m.Layers, ispec.Descriptor{MediaType: artifactv1.MediaTypeModelWeight, Digest: f.pushBlob(t, repo, []byte(l)), Size: size})
	}
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if reference == "" {
		reference = dg(body).String()
	}
	w := f.pushManifest(t, repo, reference, ispec.MediaTypeImageManifest, body)
	return w.Code, body, w.Body.String()
}

// wantQuotaRefusal fails unless code and resp are the quota refusal.
func wantQuotaRefusal(t *testing.T, code int, resp string) {
	t.Helper()
	if code != http.StatusForbidden {
		t.Fatalf("status %d, want 403; body %s", code, resp)
	}
	var eb errorBody
	if err := json.Unmarshal([]byte(resp), &eb); err != nil || len(eb.Errors) != 1 {
		t.Fatalf("error body %s: %v", resp, err)
	}
	e := eb.Errors[0]
	if e.Code != codeDenied || e.Message != msgQuotaExceeded {
		t.Fatalf("error %s %q, want %s %q", e.Code, e.Message, codeDenied, msgQuotaExceeded)
	}
	if e.Detail["artifactType"] != artifactv1.ArtifactTypeModel || e.Detail["quota"] != strconv.Itoa(quotaModels) {
		t.Fatalf("detail %v, want the artifact type and the quota", e.Detail)
	}
}

// TestQuotaRefusesPushOverLimit: a manifest PUT that would take its artifact
// type's usage past the configured quota is refused with 403 DENIED and a fixed
// message naming the quota, and writes no row. The usage is the stored layers'
// real sizes, not what a descriptor claims; another type is not limited; a
// manifest DELETE gives the room back; and a server started over the store
// counts what it holds.
func TestQuotaRefusesPushOverLimit(t *testing.T) {
	t.Run("a push past the quota is refused and writes no row", func(t *testing.T) {
		f := newFixture(t, withModelQuota)
		if code, _, resp := f.model(t, "models/a", "v1", -1, strings.Repeat("a", 60)); code != http.StatusCreated {
			t.Fatalf("first model: %d %s", code, resp)
		}
		code, body, resp := f.model(t, "models/b", "v1", -1, strings.Repeat("b", 60))
		wantQuotaRefusal(t, code, resp)
		for _, r := range f.rows(t, "models/b") {
			if r.Digest == dg(body) {
				t.Fatalf("a refused push wrote row %s", r.Digest)
			}
		}
		// An image is another artifact type, with no quota.
		f.image(t, "apps/app", "v1", strings.Repeat("i", 500))
	})
	t.Run("the real layer size counts, not the descriptor's claim", func(t *testing.T) {
		f := newFixture(t, withModelQuota)
		code, _, resp := f.model(t, "models/a", "v1", 1, strings.Repeat("a", quotaModels+1))
		wantQuotaRefusal(t, code, resp)
	})
	t.Run("a delete gives the room back", func(t *testing.T) {
		f := newFixture(t, withModelQuota)
		code, first, resp := f.model(t, "models/a", "", -1, strings.Repeat("a", 60))
		if code != http.StatusCreated {
			t.Fatalf("first model: %d %s", code, resp)
		}
		code, _, resp = f.model(t, "models/b", "v1", -1, strings.Repeat("b", 60))
		wantQuotaRefusal(t, code, resp)
		want(t, f.do(http.MethodDelete, "/v2/models/a/manifests/"+dg(first).String(), nil), http.StatusAccepted, "")
		if code, _, resp := f.model(t, "models/b", "v1", -1, strings.Repeat("b", 60)); code != http.StatusCreated {
			t.Fatalf("after the delete: %d %s", code, resp)
		}
	})
	t.Run("a restarted server counts what the store holds", func(t *testing.T) {
		f := newFixture(t, withModelQuota)
		if code, _, resp := f.model(t, "models/a", "v1", -1, strings.Repeat("a", 60)); code != http.StatusCreated {
			t.Fatalf("first model: %d %s", code, resp)
		}
		g := fixtureOver(t, f.workDir(), withModelQuota)
		code, _, resp := g.model(t, "models/b", "v1", -1, strings.Repeat("b", 60))
		wantQuotaRefusal(t, code, resp)
	})
	t.Run("a quota that is not positive or names no type is refused", func(t *testing.T) {
		for _, q := range []map[string]int64{{artifactv1.ArtifactTypeModel: 0}, {artifactv1.ArtifactTypeModel: -1}, {"": 10}} {
			st := newFixture(t).st
			if _, err := New(Config{Store: st, Authorize: AllowAll, GCGrace: 1, Quota: q}); err == nil {
				t.Errorf("New with quota %v: no error, want a refusal", q)
			}
		}
	})
}

// TestQuotaCountsDedupedBlobOnce: a layer two manifests of the same type name,
// in one repository or two, counts once against the quota, and so does a
// manifest pushed again under another tag, both as the server counts pushes
// and as a server started over the store counts what it holds.
func TestQuotaCountsDedupedBlobOnce(t *testing.T) {
	shared := strings.Repeat("s", 60)
	f := newFixture(t, withModelQuota)
	if code, _, resp := f.model(t, "models/a", "v1", -1, shared); code != http.StatusCreated {
		t.Fatalf("first model: %d %s", code, resp)
	}
	// 60 shared + 10 new = 70, not 130.
	if code, _, resp := f.model(t, "models/b", "v1", -1, shared, strings.Repeat("n", 10)); code != http.StatusCreated {
		t.Fatalf("a model sharing a layer across repositories: %d %s", code, resp)
	}
	if code, _, resp := f.model(t, "models/a", "v2", -1, shared); code != http.StatusCreated {
		t.Fatalf("the same model under a second tag: %d %s", code, resp)
	}
	check := func(t *testing.T, g *fixture) {
		t.Helper()
		code, _, resp := g.model(t, "models/c", "v1", -1, strings.Repeat("x", 31))
		wantQuotaRefusal(t, code, resp)
		if code, _, resp := g.model(t, "models/c", "v1", -1, strings.Repeat("y", 30)); code != http.StatusCreated {
			t.Fatalf("a model filling the quota exactly: %d %s", code, resp)
		}
	}
	// A clone is a server started over a copy of the store.
	t.Run("restarted", func(t *testing.T) { check(t, f.clone(t, withModelQuota)) })
	t.Run("live", func(t *testing.T) { check(t, f) })
}
