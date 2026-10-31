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
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// maxPage is the most entries one catalog or tag-list page returns; a larger
// n is answered with maxPage entries and a Link to the rest.
const maxPage = 10000

// pageOf applies n and last to sorted, unique items: the entries after last
// (an exclusive cursor, so it survives the deletion of the entry it names), at
// most n of them. It reports whether more remain and the page size used.
// validLast checks the cursor's grammar.
func pageOf(items []string, q url.Values, validLast func(string) error) (page []string, more bool, n int, err error) {
	n = -1
	if v, ok := q["n"]; ok {
		if len(v) != 1 || !digitsOnly(v[0]) || len(v[0]) > 9 {
			return nil, false, 0, errorf(http.StatusBadRequest, codePaginationInvalid, "n must be a non-negative integer")
		}
		n, _ = strconv.Atoi(v[0]) // at most nine digits
		n = min(n, maxPage)
	}
	if v, ok := q["last"]; ok {
		if len(v) != 1 {
			return nil, false, 0, errorf(http.StatusBadRequest, codePaginationInvalid, "last given more than once")
		}
		if err := validLast(v[0]); err != nil {
			return nil, false, 0, err
		}
		i, found := slices.BinarySearch(items, v[0])
		if found {
			i++
		}
		items = items[i:]
	}
	if n < 0 {
		return items, false, -1, nil
	}
	if len(items) > n {
		return items[:n], n > 0, n, nil
	}
	return items, false, n, nil
}

func digitsOnly(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// setNextLink sets the Link header pointing at the page after last.
func setNextLink(w http.ResponseWriter, path string, n int, last string) {
	q := url.Values{"n": {strconv.Itoa(n)}, "last": {last}}
	w.Header().Set("Link", "<"+path+"?"+q.Encode()+`>; rel="next"`)
}

func writeJSON(w http.ResponseWriter, r *http.Request, contentType string, v any) {
	b, err := compactJSON(v)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(b) // the client went away
	}
}

// catalog is GET /v2/_catalog: every repository the caller may read, sorted.
func (s *Server) catalog(w http.ResponseWriter, r *http.Request) {
	if !s.allow(w, r, VerbRead, ref.Name{}) {
		return
	}
	repos, err := s.st.Repositories()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	names := make([]string, 0, len(repos))
	for _, n := range repos {
		if s.authorize == nil || s.authorize(r, VerbRead, n) == nil {
			names = append(names, n.String())
		}
	}
	page, more, n, err := pageOf(names, r.URL.Query(), func(v string) error {
		_, err := ref.ParseName(v)
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if more {
		setNextLink(w, "/v2/_catalog", n, page[len(page)-1])
	}
	writeJSON(w, r, "application/json", struct {
		Repositories []string `json:"repositories"`
	}{page})
}

// tags is GET /v2/<name>/tags/list.
func (s *Server) tags(w http.ResponseWriter, r *http.Request, n ref.Name) {
	if !s.allow(w, r, VerbRead, n) {
		return
	}
	all, err := s.st.Tags(n)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	page, more, size, err := pageOf(all, r.URL.Query(), func(v string) error {
		_, err := ref.ParseTag(v)
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if more {
		setNextLink(w, "/v2/"+n.String()+"/tags/list", size, page[len(page)-1])
	}
	if page == nil {
		page = []string{}
	}
	writeJSON(w, r, "application/json", struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}{n.String(), page})
}

// referrerDoc is what the referrers scan reads from each manifest.
type referrerDoc struct {
	MediaType    string             `json:"mediaType"`
	ArtifactType string             `json:"artifactType"`
	Config       *ispec.Descriptor  `json:"config"`
	Subject      *ispec.Descriptor  `json:"subject"`
	Annotations  map[string]string  `json:"annotations"`
	Manifests    []ispec.Descriptor `json:"manifests"`
}

// referrers is GET /v2/<name>/referrers/<digest>: a live scan of the
// repository's manifests for those whose subject is digest, optionally
// filtered by artifactType. An unknown repository or subject is an empty
// index. No referrers tag is ever written.
func (s *Server) referrers(w http.ResponseWriter, r *http.Request, n ref.Name) {
	d, err := ref.ParseDigest(mux.Vars(r)["digest"])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !s.allow(w, r, VerbRead, n) {
		return
	}
	filter := r.URL.Query()["artifactType"]
	out := ispec.Index{MediaType: ispec.MediaTypeImageIndex, Manifests: []ispec.Descriptor{}}
	out.SchemaVersion = 2
	idx, err := s.st.Index(n)
	if err != nil && !errors.Is(err, store.ErrRepositoryUnknown) {
		s.fail(w, r, err)
		return
	}
	seen := map[digest.Digest]bool{}
	for _, row := range idx.Manifests {
		if seen[row.Digest] || !manifestTypes[row.MediaType] {
			continue
		}
		seen[row.Digest] = true
		body, err := s.readManifestBlob(n, row)
		if err != nil {
			s.log.Warn("registry referrers scan skipped an unreadable manifest", "repository", n.String(), "digest", row.Digest.String(), "err", err)
			continue
		}
		var doc referrerDoc
		if json.Unmarshal(body, &doc) != nil || doc.Subject == nil || doc.Subject.Digest != d {
			continue
		}
		at := doc.ArtifactType
		if at == "" && doc.Config != nil {
			at = doc.Config.MediaType
		}
		if len(filter) > 0 && !slices.Contains(filter, at) {
			continue
		}
		out.Manifests = append(out.Manifests, ispec.Descriptor{
			MediaType: row.MediaType, Digest: row.Digest, Size: row.Size,
			ArtifactType: at, Annotations: doc.Annotations,
		})
	}
	if len(filter) > 0 {
		w.Header().Set("OCI-Filters-Applied", "artifactType")
	}
	writeJSON(w, r, ispec.MediaTypeImageIndex, out)
}
