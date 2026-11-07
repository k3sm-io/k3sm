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
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// subjectBody is a manifest naming subject, with a large annotation so its cost
// in the view shows.
func subjectBody(subject string) []byte {
	return fmt.Appendf(nil, `{"schemaVersion":2,"artifactType":"application/vnd.example.sig","subject":{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":%q,"size":2},"annotations":{"pad":%q}}`,
		subject, strings.Repeat("x", 4096))
}

// TestReferrerEntrySubject: a subject that is not a canonical digest contributes
// nothing, like a body that does not decode.
func TestReferrerEntrySubject(t *testing.T) {
	good := digest.FromString("subject").String()
	for _, tc := range []struct{ name, subject string }{
		{"empty", ""},
		{"a tag", "latest"},
		{"a short hex", "sha256:abc"},
		{"upper case hex", "sha256:" + strings.ToUpper(strings.TrimPrefix(good, "sha256:"))},
		{"an unknown algorithm", "md5:d41d8cd98f00b204e9800998ecf8427e"},
		{"an algorithm the registry does not serve", "sha384:" + strings.Repeat("a", 96)},
		{"a path", "sha256:../../etc/passwd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := entryOf(ispec.Descriptor{MediaType: ispec.MediaTypeImageManifest}, subjectBody(tc.subject))
			if e.subject != "" || e.size != 64 || e.desc.ArtifactType != "" || e.desc.Annotations != nil {
				t.Errorf("subject %q size %d artifactType %q annotations %d", e.subject, e.size, e.desc.ArtifactType, len(e.desc.Annotations))
			}
		})
	}
	t.Run("a canonical digest is a subject", func(t *testing.T) {
		for _, s := range []string{good, "sha512:" + strings.Repeat("a", 128)} {
			e := entryOf(ispec.Descriptor{MediaType: ispec.MediaTypeImageManifest}, subjectBody(s))
			if e.subject.String() != s || e.size <= 4096 || e.desc.ArtifactType != "application/vnd.example.sig" {
				t.Errorf("%s: subject %q size %d artifactType %q", s, e.subject, e.size, e.desc.ArtifactType)
			}
		}
	})
}

// TestReferrersMalformedSubjectCost: a malformed subject adds no referrer and
// costs the cache one row's floor, whatever its annotations weigh.
func TestReferrersMalformedSubjectCost(t *testing.T) {
	f := newFixture(t)
	subject := f.image(t, "app", "v1", "l")
	bad := subjectBody("sha256:abc")
	good := subjectBody(dg(subject).String())
	f.addRows(t, "app", [][]byte{bad, good})
	w := f.do(http.MethodGet, "/v2/app/referrers/"+dg(subject).String(), nil)
	want(t, w, 200, "")
	var out ispec.Index
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Manifests) != 1 || out.Manifests[0].Digest != dg(good) {
		t.Fatalf("referrers %v", out.Manifests)
	}
	v := f.srv.refs.view("app")
	if e := v.entries[dg(bad)]; e.subject != "" || e.size != 64 {
		t.Errorf("the malformed subject's entry: subject %q size %d", e.subject, e.size)
	}
	if _, ok := v.bySubject["sha256:abc"]; ok {
		t.Error("the malformed subject has a list of its own")
	}
	f.srv.refs.mu.Lock()
	defer f.srv.refs.mu.Unlock()
	if n := int64(entryOf(ispec.Descriptor{}, good).size); v.bytes >= 2*n {
		t.Errorf("%d bytes accounted, want well under two referrers of %d", v.bytes, n)
	}
}

// TestReferrerEntryIgnoresManifests: the scan does not decode a body's manifests
// list, so an index stays a referrer without it being read and a stray value in
// that field of an image manifest does not hide the manifest's subject.
func TestReferrerEntryIgnoresManifests(t *testing.T) {
	subject := digest.FromString("subject").String()
	for _, tc := range []struct{ name, manifests string }{
		{"an index's list", `[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"` + subject + `","size":2}]`},
		{"a value that is not a list", `5`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Appendf(nil, `{"schemaVersion":2,"manifests":%s,"subject":{"digest":%q,"size":2}}`, tc.manifests, subject)
			if e := entryOf(ispec.Descriptor{}, body); e.subject.String() != subject {
				t.Errorf("subject %q, want %s", e.subject, subject)
			}
		})
	}
}
