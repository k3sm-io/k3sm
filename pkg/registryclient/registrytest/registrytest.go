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

// Package registrytest is an in-memory OCI distribution registry for tests: the
// catalog, tag lists, manifests and blobs a registryclient reads, served from
// content a test builds with Image and Index. It is read-only unless
// AcceptWrites is set, when it also takes blob uploads (chunked and
// monolithic), cross-repository blob mounts and manifest pushes, and records
// each in Writes.
package registrytest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"

	"k3sm.io/k3sm/pkg/registryclient"
)

// Registry is the fake. Build content with Image and Index, then serve
// Handler. It is safe for concurrent use.
type Registry struct {
	// PageSize, when positive, paginates the catalog and tag lists with a
	// Link header, the way a real registry does past its page limit.
	PageSize int

	// AcceptWrites, when set, serves the push endpoints too. Unset, every
	// method but GET and HEAD is refused 405.
	AcceptWrites bool

	// OmitHeadDigest, when set, answers a manifest HEAD without the
	// Docker-Content-Digest header, the way a registry that does not report
	// it would.
	OmitHeadDigest bool

	// HeadDigest, when set, is the Docker-Content-Digest a manifest HEAD
	// reports instead of the true one, the way a lying or racing registry
	// would.
	HeadDigest string

	mu       sync.Mutex
	repos    map[string]*repo
	uploads  map[string][]byte // upload id -> bytes so far
	nextID   int
	writes   []Write
	requests map[RequestClass]int
}

// The request classes Requests counts by.
const (
	ClassCatalog        = "catalog"
	ClassTags           = "tags"
	ClassManifestTag    = "manifest-by-tag"
	ClassManifestDigest = "manifest-by-digest"
	ClassBlob           = "blob"
	ClassOther          = "other"
)

// RequestClass is a request's method and the kind of endpoint it named.
type RequestClass struct {
	Method string
	Class  string
}

// Requests returns how many requests of method to the class of endpoint the
// registry has served (any answer, found or not).
func (r *Registry) Requests(method, class string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.requests[RequestClass{Method: method, Class: class}]
}

// ResetRequests zeroes the request counts.
func (r *Registry) ResetRequests() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = map[RequestClass]int{}
}

// classify names the kind of endpoint path is.
func classify(path string) string {
	switch {
	case path == "/v2/_catalog":
		return ClassCatalog
	case strings.HasSuffix(path, "/tags/list"):
		return ClassTags
	case strings.Contains(path, "/manifests/"):
		if strings.HasPrefix(path[strings.LastIndex(path, "/manifests/")+len("/manifests/"):], "sha256:") {
			return ClassManifestDigest
		}
		return ClassManifestTag
	case strings.Contains(path, "/blobs/"):
		return ClassBlob
	}
	return ClassOther
}

// Write is one write the registry took: Op is "mount" (a blob mounted from
// From), "upload" (a blob whose bytes were sent) or "manifest".
type Write struct {
	Op         string
	Repository string
	Digest     string
	From       string
}

// Writes returns the writes taken so far, in order.
func (r *Registry) Writes() []Write {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Write(nil), r.writes...)
}

// Manifest returns the manifest digest tag names in repository, and whether
// the tag exists.
func (r *Registry) Manifest(repository, tag string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rp, ok := r.repos[repository]
	if !ok {
		return "", false
	}
	d, ok := rp.tags[tag]
	return d, ok
}

// HasBlob reports whether repository holds the blob digest.
func (r *Registry) HasBlob(repository, digest string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	rp, ok := r.repos[repository]
	if !ok {
		return false
	}
	_, ok = rp.blobs[digest]
	return ok
}

type repo struct {
	tags      map[string]string // tag -> manifest digest
	manifests map[string]stored // digest -> body
	blobs     map[string][]byte // digest -> bytes
}

type stored struct {
	mediaType string
	body      []byte
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{repos: map[string]*repo{}, uploads: map[string][]byte{}, requests: map[RequestClass]int{}}
}

func (r *Registry) repo(name string) *repo {
	rp, ok := r.repos[name]
	if !ok {
		rp = &repo{tags: map[string]string{}, manifests: map[string]stored{}, blobs: map[string][]byte{}}
		r.repos[name] = rp
	}
	return rp
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Image stores a single-platform image (a config recording platform, and one
// layer per entry of layers) in repository, tags it when tag is non-empty, and
// returns its manifest descriptor with Platform set, ready to be an index
// child.
func (r *Registry) Image(repository, tag string, platform registryclient.Platform, layers ...[]byte) registryclient.Descriptor {
	r.mu.Lock()
	defer r.mu.Unlock()
	rp := r.repo(repository)
	cfg, _ := json.Marshal(map[string]any{
		"os": platform.OS, "architecture": platform.Architecture, "variant": platform.Variant,
		"rootfs": map[string]any{"type": "layers"},
	})
	cfgDesc := registryclient.Descriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: digestOf(cfg), Size: int64(len(cfg))}
	rp.blobs[cfgDesc.Digest] = cfg
	ls := make([]registryclient.Descriptor, 0, len(layers))
	for _, l := range layers {
		d := registryclient.Descriptor{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: digestOf(l), Size: int64(len(l))}
		rp.blobs[d.Digest] = l
		ls = append(ls, d)
	}
	body, _ := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": registryclient.MediaTypeOCIManifest,
		"config": cfgDesc, "layers": ls,
	})
	d := registryclient.Descriptor{MediaType: registryclient.MediaTypeOCIManifest, Digest: digestOf(body), Size: int64(len(body))}
	rp.manifests[d.Digest] = stored{mediaType: d.MediaType, body: body}
	if tag != "" {
		rp.tags[tag] = d.Digest
	}
	p := platform
	d.Platform = &p
	return d
}

// Index stores an image index over children (each from Image, in the same
// repository) and tags it, returning its descriptor.
func (r *Registry) Index(repository, tag string, children ...registryclient.Descriptor) registryclient.Descriptor {
	r.mu.Lock()
	defer r.mu.Unlock()
	rp := r.repo(repository)
	body, _ := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": registryclient.MediaTypeOCIIndex, "manifests": children,
	})
	d := registryclient.Descriptor{MediaType: registryclient.MediaTypeOCIIndex, Digest: digestOf(body), Size: int64(len(body))}
	rp.manifests[d.Digest] = stored{mediaType: d.MediaType, body: body}
	if tag != "" {
		rp.tags[tag] = d.Digest
	}
	return d
}

// StoreManifestAt stores body as repository's manifest under digest without
// checking that it hashes to it, so a test can serve content that does not
// match the digest it is read by.
func (r *Registry) StoreManifestAt(repository, digest, mediaType string, body []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.repo(repository).manifests[digest] = stored{mediaType: mediaType, body: body}
}

// Handler serves the registry's read endpoints, and its write endpoints when
// AcceptWrites is set.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(r.serve)
}

func (r *Registry) serve(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.requests[RequestClass{Method: req.Method, Class: classify(req.URL.Path)}]++
	r.mu.Unlock()
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		if !r.AcceptWrites {
			http.Error(w, "read-only", http.StatusMethodNotAllowed)
			return
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		r.serveWrite(w, req)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	path := req.URL.Path
	switch {
	case path == "/v2/" || path == "/v2":
		w.WriteHeader(http.StatusOK)
	case path == "/v2/_catalog":
		names := make([]string, 0, len(r.repos))
		for n := range r.repos {
			names = append(names, n)
		}
		r.page(w, req, "repositories", names)
	case strings.HasSuffix(path, "/tags/list"):
		rp, ok := r.repos[strings.TrimSuffix(strings.TrimPrefix(path, "/v2/"), "/tags/list")]
		if !ok {
			http.NotFound(w, req)
			return
		}
		tags := make([]string, 0, len(rp.tags))
		for t := range rp.tags {
			tags = append(tags, t)
		}
		r.page(w, req, "tags", tags)
	case strings.Contains(path, "/manifests/"):
		i := strings.LastIndex(path, "/manifests/")
		rp, ok := r.repos[strings.TrimPrefix(path[:i], "/v2/")]
		if !ok {
			http.NotFound(w, req)
			return
		}
		ref := path[i+len("/manifests/"):]
		if d, ok := rp.tags[ref]; ok {
			ref = d
		}
		m, ok := rp.manifests[ref]
		if !ok {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", m.mediaType)
		switch {
		case req.Method == http.MethodHead && r.OmitHeadDigest:
		case req.Method == http.MethodHead && r.HeadDigest != "":
			w.Header().Set("Docker-Content-Digest", r.HeadDigest)
		default:
			w.Header().Set("Docker-Content-Digest", ref)
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(m.body)))
		if req.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(m.body)
	case strings.Contains(path, "/blobs/"):
		i := strings.LastIndex(path, "/blobs/")
		rp, ok := r.repos[strings.TrimPrefix(path[:i], "/v2/")]
		if !ok {
			http.NotFound(w, req)
			return
		}
		b, ok := rp.blobs[path[i+len("/blobs/"):]]
		if !ok {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		_, _ = w.Write(b)
	default:
		http.NotFound(w, req)
	}
}

// serveWrite serves the push endpoints: POST starts an upload (or mounts, or
// takes a monolithic upload), PATCH appends to one, PUT finishes one or stores
// a manifest. The caller holds mu.
func (r *Registry) serveWrite(w http.ResponseWriter, req *http.Request) {
	path := req.URL.Path
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	q := req.URL.Query()
	switch {
	case req.Method == http.MethodPost && strings.HasSuffix(path, "/blobs/uploads/"):
		name := strings.TrimSuffix(strings.TrimPrefix(path, "/v2/"), "/blobs/uploads/")
		if mount, from := q.Get("mount"), q.Get("from"); mount != "" && from != "" {
			if src, ok := r.repos[from]; ok {
				if b, ok := src.blobs[mount]; ok {
					r.repo(name).blobs[mount] = b
					r.writes = append(r.writes, Write{Op: "mount", Repository: name, Digest: mount, From: from})
					w.Header().Set("Location", "/v2/"+name+"/blobs/"+mount)
					w.WriteHeader(http.StatusCreated)
					return
				}
			}
		}
		if d := q.Get("digest"); d != "" {
			r.commitBlob(w, name, d, body)
			return
		}
		r.nextID++
		id := strconv.Itoa(r.nextID)
		r.uploads[id] = body
		r.uploadLocation(w, name, id, http.StatusAccepted)
	case req.Method == http.MethodPatch && strings.Contains(path, "/blobs/uploads/"):
		name, id := splitUpload(path)
		prev, ok := r.uploads[id]
		if !ok {
			http.NotFound(w, req)
			return
		}
		r.uploads[id] = append(prev, body...)
		r.uploadLocation(w, name, id, http.StatusAccepted)
	case req.Method == http.MethodPut && strings.Contains(path, "/blobs/uploads/"):
		name, id := splitUpload(path)
		prev, ok := r.uploads[id]
		if !ok {
			http.NotFound(w, req)
			return
		}
		delete(r.uploads, id)
		r.commitBlob(w, name, q.Get("digest"), append(prev, body...))
	case req.Method == http.MethodPut && strings.Contains(path, "/manifests/"):
		i := strings.LastIndex(path, "/manifests/")
		name, ref := strings.TrimPrefix(path[:i], "/v2/"), path[i+len("/manifests/"):]
		d := digestOf(body)
		if strings.HasPrefix(ref, "sha256:") && ref != d {
			http.Error(w, "digest mismatch", http.StatusBadRequest)
			return
		}
		rp := r.repo(name)
		rp.manifests[d] = stored{mediaType: req.Header.Get("Content-Type"), body: body}
		if !strings.HasPrefix(ref, "sha256:") {
			rp.tags[ref] = d
		}
		r.writes = append(r.writes, Write{Op: "manifest", Repository: name, Digest: d})
		w.Header().Set("Docker-Content-Digest", d)
		w.Header().Set("Location", "/v2/"+name+"/manifests/"+d)
		w.WriteHeader(http.StatusCreated)
	default:
		http.Error(w, "unsupported", http.StatusMethodNotAllowed)
	}
}

// commitBlob stores body as repository's blob digest when the bytes hash to it.
func (r *Registry) commitBlob(w http.ResponseWriter, repository, digest string, body []byte) {
	if digest == "" || digestOf(body) != digest {
		http.Error(w, "digest mismatch", http.StatusBadRequest)
		return
	}
	r.repo(repository).blobs[digest] = body
	r.writes = append(r.writes, Write{Op: "upload", Repository: repository, Digest: digest})
	w.Header().Set("Location", "/v2/"+repository+"/blobs/"+digest)
	w.Header().Set("Docker-Content-Digest", digest)
	w.WriteHeader(http.StatusCreated)
}

// uploadLocation answers an upload step with where the next one goes.
func (r *Registry) uploadLocation(w http.ResponseWriter, repository, id string, code int) {
	n := len(r.uploads[id])
	w.Header().Set("Location", "/v2/"+repository+"/blobs/uploads/"+url.PathEscape(id))
	w.Header().Set("Docker-Upload-UUID", id)
	w.Header().Set("Range", fmt.Sprintf("0-%d", max(n-1, 0)))
	w.WriteHeader(code)
}

// splitUpload splits /v2/<name>/blobs/uploads/<id> into its name and id.
func splitUpload(path string) (name, id string) {
	i := strings.LastIndex(path, "/blobs/uploads/")
	return strings.TrimPrefix(path[:i], "/v2/"), path[i+len("/blobs/uploads/"):]
}

// page writes one sorted page of items under key, honouring last= and
// emitting a Link header when more remain.
func (r *Registry) page(w http.ResponseWriter, req *http.Request, key string, items []string) {
	sort.Strings(items)
	if last := req.URL.Query().Get("last"); last != "" {
		i := sort.SearchStrings(items, last)
		if i < len(items) && items[i] == last {
			i++
		}
		items = items[i:]
	}
	if r.PageSize > 0 && len(items) > r.PageSize {
		items = items[:r.PageSize]
		next := *req.URL
		q := next.Query()
		q.Set("last", items[len(items)-1])
		next.RawQuery = q.Encode()
		w.Header().Set("Link", fmt.Sprintf(`<%s>; rel="next"`, next.RequestURI()))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{key: items})
}

// PushTo copies every repository the fake holds into the registry h serves,
// through its push endpoints: each blob by a monolithic upload, each manifest
// by digest (image manifests before indexes), then each tag. A test uses it to
// run the same content against a real registry server in process.
func (r *Registry) PushTo(h http.Handler) error {
	r.mu.Lock()
	type manifest struct {
		repo, digest string
		m            stored
	}
	type blob struct {
		repo, digest string
		b            []byte
	}
	var blobs []blob
	var images, indexes []manifest
	var tags []manifest
	names := make([]string, 0, len(r.repos))
	for name := range r.repos {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		rp := r.repos[name]
		for d, b := range rp.blobs {
			blobs = append(blobs, blob{name, d, b})
		}
		for d, m := range rp.manifests {
			if strings.Contains(m.mediaType, "index") || strings.Contains(m.mediaType, "list") {
				indexes = append(indexes, manifest{name, d, m})
			} else {
				images = append(images, manifest{name, d, m})
			}
		}
		for tag, d := range rp.tags {
			tags = append(tags, manifest{name, tag, rp.manifests[d]})
		}
	}
	r.mu.Unlock()
	do := func(method, path, contentType string, body []byte, want int) error {
		req, err := http.NewRequest(method, "http://registry.test"+path, strings.NewReader(string(body)))
		if err != nil {
			return err
		}
		req.ContentLength = int64(len(body))
		req.Header.Set("Content-Type", contentType)
		rec := &recorder{header: http.Header{}}
		h.ServeHTTP(rec, req)
		if rec.status != want {
			return fmt.Errorf("%s %s: status %d, want %d: %s", method, path, rec.status, want, rec.body.String())
		}
		return nil
	}
	for _, b := range blobs {
		if err := do(http.MethodPost, "/v2/"+b.repo+"/blobs/uploads/?digest="+b.digest, "application/octet-stream", b.b, http.StatusCreated); err != nil {
			return err
		}
	}
	for _, m := range append(images, indexes...) {
		if err := do(http.MethodPut, "/v2/"+m.repo+"/manifests/"+m.digest, m.m.mediaType, m.m.body, http.StatusCreated); err != nil {
			return err
		}
	}
	for _, m := range tags {
		if err := do(http.MethodPut, "/v2/"+m.repo+"/manifests/"+m.digest, m.m.mediaType, m.m.body, http.StatusCreated); err != nil {
			return err
		}
	}
	return nil
}

// recorder is a minimal http.ResponseWriter for PushTo.
type recorder struct {
	header http.Header
	status int
	body   strings.Builder
}

func (w *recorder) Header() http.Header { return w.header }

func (w *recorder) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
}

func (w *recorder) Write(b []byte) (int, error) {
	w.WriteHeader(http.StatusOK)
	return w.body.Write(b)
}
