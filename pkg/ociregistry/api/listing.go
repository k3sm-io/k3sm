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
	"errors"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// maxPage is the most entries one catalog or tag-list page returns; a larger
// n is answered with maxPage entries and a Link to the rest.
const maxPage = 10000

// defaultCatalogPage is the catalog page size when the request names no n.
// The distribution spec lets a registry page an unbounded catalog request, and
// a client follows the Link.
const defaultCatalogPage = 1000

// catalogVisits is the visit budget of a catalog page of n entries: four
// visits an entry, and at least 1,000.
func catalogVisits(n int) int { return max(4*n, 1000) }

// catalogCeilingFactor is the hard ceiling of one catalog walk, as a multiple
// of its visit budget, capped at catalogCeilingMax visits so a large n cannot
// raise it. A walk that reaches min(catalogCeilingFactor*catalogVisits(n),
// catalogCeilingMax) visits without filling its page or finding a readable
// name to end it on stops and answers 503 with no Link and no Retry-After,
// rather than walking a run of denied names without bound.
const catalogCeilingFactor = 64

// catalogCeilingMax is the absolute ceiling of one catalog walk in visits,
// whatever n the request names.
const catalogCeilingMax = 64000

// errCatalogCeiling is a catalog walk stopped at its hard ceiling (503).
var errCatalogCeiling = errors.New("catalog walk reached its visit ceiling")

// parsePage reads n and last from q. n is def when absent and at most most;
// a negative def means no limit. validLast checks the cursor's grammar.
func parsePage(q url.Values, def, most int, validLast func(string) error) (n int, last string, err error) {
	n = def
	if v, ok := q["n"]; ok {
		if len(v) != 1 || !digitsOnly(v[0]) || len(v[0]) > 9 {
			return 0, "", errorf(http.StatusBadRequest, codePaginationInvalid, "n must be a non-negative integer")
		}
		n, _ = strconv.Atoi(v[0]) // at most nine digits
		n = min(n, most)
	}
	if v, ok := q["last"]; ok {
		if len(v) != 1 {
			return 0, "", errorf(http.StatusBadRequest, codePaginationInvalid, "last given more than once")
		}
		if err := validLast(v[0]); err != nil {
			return 0, "", err
		}
		last = v[0]
	}
	return n, last, nil
}

// pageOf applies n and last to sorted, unique items: the entries after last
// (an exclusive cursor, so it survives the deletion of the entry it names), at
// most n of them. It reports whether more remain and the page size used.
// validLast checks the cursor's grammar.
func pageOf(items []string, q url.Values, validLast func(string) error) (page []string, more bool, n int, err error) {
	n, last, err := parsePage(q, -1, maxPage, validLast)
	if err != nil {
		return nil, false, 0, err
	}
	if _, ok := q["last"]; ok {
		i, found := slices.BinarySearch(items, last)
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

// catalog is GET /v2/_catalog: the repositories the caller may read, sorted,
// one page at a time. A request without n gets defaultCatalogPage entries and
// n is capped at maxPage. The store walk stops once the page is full and skips
// every subtree before the cursor, so a page never costs the whole root.
//
// Every repository the walk visits, readable or denied, counts against a visit
// budget of catalogVisits(n). Once it is spent the page ends early, at the
// next readable name, with a Link whose cursor is that name. The cursor is
// always a name the caller may read and was sent in the page: a denied name,
// or any string placed between denied names, would tell the caller where
// names it may not see sort, so it is never used. The cost of that choice is
// that a run of denied names after the budget is spent is still walked, up to
// the next readable name or the end of the store, but never past the hard
// ceiling of catalogCeilingFactor times the budget or catalogCeilingMax
// visits, whichever is lower: a walk that would visit more answers
// errCatalogCeiling with no Link. The walk also stops as soon as the
// request's context is done.
func (s *Server) catalog(w http.ResponseWriter, r *http.Request) {
	if !s.allow(w, r, VerbRead, ref.Name{}) {
		return
	}
	n, last, err := parsePage(r.URL.Query(), s.catalogPage, s.catalogMax, func(v string) error {
		_, err := ref.ParseName(v)
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	page := []string{}
	more := false
	if n > 0 {
		budget, visits := catalogVisits(n), 0
		ceiling := min(s.catalogCeil*budget, s.catalogCap)
		var stop error
		err = s.st.WalkRepositories(last, func(rn ref.Name) bool {
			if err := r.Context().Err(); err != nil {
				stop = err // the client went away
				return false
			}
			if visits >= ceiling {
				if len(page) == n {
					more = true // a full page, and a name after it
				} else {
					stop = errCatalogCeiling
				}
				return false
			}
			visits++
			if s.catalogVisited != nil {
				s.catalogVisited()
			}
			if s.authorize(r, VerbRead, rn) != nil {
				return true
			}
			if len(page) == n {
				more = true
				return false
			}
			page = append(page, rn.String())
			if visits >= budget && len(page) < n {
				more = true // the next page may be empty
				return false
			}
			return true
		})
		if err == nil {
			err = stop
		}
		if err != nil {
			s.fail(w, r, err)
			return
		}
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

// referrers is GET /v2/<name>/referrers/<digest>: the repository's manifests
// whose subject is digest, optionally filtered by artifactType, sorted by
// digest and paged (n, an exclusive last digest, and a Link to the next page).
// The answer comes from a cached view of the repository (refcache.go) that is
// rebuilt when index.json changes. An unknown repository or subject is an
// empty index. No referrers tag is ever written.
func (s *Server) referrers(w http.ResponseWriter, r *http.Request, n ref.Name) {
	d, err := ref.ParseDigest(mux.Vars(r)["digest"])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !s.allow(w, r, VerbRead, n) {
		return
	}
	q := r.URL.Query()
	size, last, err := parsePage(q, s.refPage, s.refPage, func(v string) error {
		_, err := ref.ParseDigest(v)
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if len(q["artifactType"]) > maxArtifactTypes {
		s.fail(w, r, errorf(http.StatusBadRequest, codeUnsupported, "at most 8 artifactType values"))
		return
	}
	filter := map[string]bool{}
	for _, at := range q["artifactType"] {
		filter[at] = true
	}
	all, err := s.referrersOf(r, n, d)
	if err != nil {
		if errors.Is(err, errReferrersBusy) {
			w.Header().Set("Retry-After", "1")
		}
		s.fail(w, r, err)
		return
	}
	out := ispec.Index{MediaType: ispec.MediaTypeImageIndex, Manifests: []ispec.Descriptor{}}
	out.SchemaVersion = 2
	i := 0
	if last != "" {
		i, _ = slices.BinarySearchFunc(all, last, func(e refEntry, t string) int { return strings.Compare(e.desc.Digest.String(), t) })
		if i < len(all) && all[i].desc.Digest.String() == last {
			i++
		}
	}
	more, used := false, 0
	for ; i < len(all) && size > 0; i++ {
		e := all[i]
		if len(filter) > 0 && !filter[e.desc.ArtifactType] {
			continue
		}
		if len(out.Manifests) == size || (len(out.Manifests) > 0 && used+e.size > s.refPageBytes) {
			more = true
			break
		}
		out.Manifests = append(out.Manifests, e.desc)
		used += e.size
	}
	if more {
		v := url.Values{"n": {strconv.Itoa(size)}, "last": {out.Manifests[len(out.Manifests)-1].Digest.String()}}
		if len(filter) > 0 {
			v["artifactType"] = slices.Sorted(maps.Keys(filter))
		}
		w.Header().Set("Link", "</v2/"+n.String()+"/referrers/"+d.String()+"?"+v.Encode()+`>; rel="next"`)
	}
	if len(filter) > 0 {
		w.Header().Set("OCI-Filters-Applied", "artifactType")
	}
	writeJSON(w, r, ispec.MediaTypeImageIndex, out)
}
