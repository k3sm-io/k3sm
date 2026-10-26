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

// Package registrytest is an in-memory, read-only OCI distribution registry for
// tests: the catalog, tag lists, manifests and blobs a registryclient reads,
// served from content a test builds with Image and Index.
package registrytest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
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

	mu    sync.Mutex
	repos map[string]*repo
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
func New() *Registry { return &Registry{repos: map[string]*repo{}} }

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

// Handler serves the registry's read endpoints.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(r.serve)
}

func (r *Registry) serve(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		http.Error(w, "read-only", http.StatusMethodNotAllowed)
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
		w.Header().Set("Docker-Content-Digest", ref)
		w.Header().Set("Content-Length", strconv.Itoa(len(m.body)))
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
		_, _ = w.Write(b)
	default:
		http.NotFound(w, req)
	}
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
