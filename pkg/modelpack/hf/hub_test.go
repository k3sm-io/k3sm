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
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// hubFile is one file of a commit in the fake Hub.
type hubFile struct {
	path string
	data []byte
	lfs  bool
}

// The fake Hub's hosts. They resolve only through the fixture's transport.
const (
	hubHost = "hub.test"
	cdnHost = "cdn.test"
)

// fakeHub is an in-process Hub: the revision, tree and resolve endpoints on
// one host, and the LFS CDN the resolve redirects to on another, served
// through hostTransport with no socket. It records every request path so a
// test can see what was asked for.
type fakeHub struct {
	t         *testing.T
	transport hostTransport

	mu       sync.Mutex // guards every field below
	repo     string
	branches map[string]string
	commits  map[string][]hubFile
	gated    any
	// gatedDownloads answers every resolve with the Hub's GatedRepo 401.
	gatedDownloads bool
	// moveAfterResolve repoints a branch at another commit once its
	// revision has been answered.
	moveAfterResolve map[string]string
	// corrupt serves the file at this path with one byte flipped.
	corrupt map[string]bool
	// badEtag sends this X-Linked-Etag on the redirect of every LFS file.
	badEtag string
	// cutOnce ends the first transfer of a path after this many bytes.
	cutOnce map[string]int64
	// redirectTo, when set, is where every LFS resolve redirects.
	redirectTo string
	pageSize   int
	requests   []string
}

func newFakeHub(t *testing.T) *fakeHub {
	t.Helper()
	h := &fakeHub{
		t:                t,
		repo:             "acme/tiny-model",
		branches:         map[string]string{},
		commits:          map[string][]hubFile{},
		gated:            false,
		moveAfterResolve: map[string]string{},
		corrupt:          map[string]bool{},
		cutOnce:          map[string]int64{},
		pageSize:         2,
	}
	h.transport = hostTransport{hubHost: http.HandlerFunc(h.serveAPI), cdnHost: http.HandlerFunc(h.serveCDN)}
	return h
}

// client is a Client of h that may be redirected to h's CDN.
func (h *fakeHub) client(t *testing.T) *Client {
	t.Helper()
	c, err := NewClient(Options{
		Endpoint:      "https://" + hubHost,
		Transport:     h.transport,
		RedirectHosts: []string{cdnHost},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// addCommit stores files as commit and points branch at it.
func (h *fakeHub) addCommit(branch, commit string, files ...hubFile) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.commits[commit] = files
	if branch != "" {
		h.branches[branch] = commit
	}
}

// paths returns the requests recorded so far.
func (h *fakeHub) paths() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.requests)
}

func (h *fakeHub) record(r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.requests = append(h.requests, r.URL.EscapedPath())
}

func gitBlobID(b []byte) string {
	s := sha1.New()
	fmt.Fprintf(s, "blob %d\x00", len(b))
	s.Write(b)
	return hex.EncodeToString(s.Sum(nil))
}

func sha256Hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func hubError(w http.ResponseWriter, code int, xcode, msg string) {
	w.Header().Set("X-Error-Code", xcode)
	w.Header().Set("X-Error-Message", msg)
	http.Error(w, msg, code)
}

func (h *fakeHub) serveAPI(w http.ResponseWriter, r *http.Request) {
	h.record(r)
	h.mu.Lock()
	defer h.mu.Unlock()
	p := r.URL.EscapedPath()
	repoAPI := "/api/models/" + h.repo + "/"
	switch {
	case strings.HasPrefix(p, repoAPI+"revision/"):
		rev, _ := url.PathUnescape(strings.TrimPrefix(p, repoAPI+"revision/"))
		commit, ok := h.branches[rev]
		if !ok {
			if _, isCommit := h.commits[rev]; !isCommit {
				hubError(w, http.StatusNotFound, "RevisionNotFound", "Invalid rev id: "+rev)
				return
			}
			commit = rev
		}
		if to, ok := h.moveAfterResolve[rev]; ok {
			h.branches[rev] = to
			delete(h.moveAfterResolve, rev)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": h.repo, "sha": commit, "gated": h.gated, "private": false})
	case strings.HasPrefix(p, repoAPI+"tree/"):
		commit := strings.TrimPrefix(p, repoAPI+"tree/")
		files, ok := h.commits[commit]
		if !ok {
			hubError(w, http.StatusNotFound, "RevisionNotFound", "Invalid rev id: "+commit)
			return
		}
		if r.URL.Query().Get("recursive") != "true" {
			http.Error(w, "want recursive", http.StatusBadRequest)
			return
		}
		entries := h.entries(files)
		start, _ := strconv.Atoi(r.URL.Query().Get("cursor"))
		end := min(start+h.pageSize, len(entries))
		if end < len(entries) {
			next := *r.URL
			q := next.Query()
			q.Set("cursor", strconv.Itoa(end))
			next.RawQuery = q.Encode()
			w.Header().Set("Link", `<https://`+r.Host+next.RequestURI()+`>; rel="next"`)
		}
		_ = json.NewEncoder(w).Encode(entries[start:end])
	case strings.HasPrefix(p, "/"+h.repo+"/resolve/"):
		commit, fp, _ := strings.Cut(strings.TrimPrefix(p, "/"+h.repo+"/resolve/"), "/")
		if h.gatedDownloads {
			hubError(w, http.StatusUnauthorized, "GatedRepo", "Access to model "+h.repo+" is restricted. You must have access to it and be authenticated to access it. Please log in.")
			return
		}
		for _, f := range h.commits[commit] {
			if f.path != fp {
				continue
			}
			w.Header().Set("X-Repo-Commit", commit)
			if f.lfs {
				sum := sha256Hex(f.data)
				etag := `"` + sum + `"`
				if h.badEtag != "" {
					etag = h.badEtag
				}
				w.Header().Set("X-Linked-Etag", etag)
				w.Header().Set("X-Linked-Size", strconv.Itoa(len(f.data)))
				to := "https://" + cdnHost + "/blobs/" + sum
				if h.redirectTo != "" {
					to = h.redirectTo // sent verbatim, hostile bytes and all
				}
				w.Header().Set("Location", to)
				w.WriteHeader(http.StatusFound)
				return
			}
			w.Header().Set("ETag", `"`+gitBlobID(f.data)+`"`)
			h.serveBytes(w, r, f)
			return
		}
		hubError(w, http.StatusNotFound, "EntryNotFound", "no such file")
	default:
		hubError(w, http.StatusUnauthorized, "RepoNotFound", "Repository Not Found")
	}
}

// entries is the tree listing of files, with a directory entry for every
// directory, as the Hub lists them.
func (h *fakeHub) entries(files []hubFile) []map[string]any {
	var out []map[string]any
	dirs := map[string]bool{}
	for _, f := range files {
		if i := strings.LastIndex(f.path, "/"); i > 0 && !dirs[f.path[:i]] {
			dirs[f.path[:i]] = true
			out = append(out, map[string]any{"type": "directory", "oid": strings.Repeat("d", 40), "size": 0, "path": f.path[:i]})
		}
		e := map[string]any{"type": "file", "size": len(f.data), "path": f.path, "oid": gitBlobID(f.data)}
		if f.lfs {
			e["oid"] = gitBlobID([]byte("version https://git-lfs.github.com/spec/v1\noid sha256:" + sha256Hex(f.data)))
			e["lfs"] = map[string]any{"oid": sha256Hex(f.data), "size": len(f.data), "pointerSize": 134}
		}
		out = append(out, e)
	}
	return out
}

func (h *fakeHub) serveCDN(w http.ResponseWriter, r *http.Request) {
	h.record(r)
	h.mu.Lock()
	sum := strings.TrimPrefix(r.URL.Path, "/blobs/")
	var found *hubFile
	for _, files := range h.commits {
		for i := range files {
			if files[i].lfs && sha256Hex(files[i].data) == sum {
				found = &files[i]
			}
		}
	}
	if found == nil {
		h.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	f := *found
	cut, cutting := h.cutOnce[f.path]
	delete(h.cutOnce, f.path)
	h.mu.Unlock()
	if cutting && r.Header.Get("Range") == "" {
		w.Header().Set("Content-Length", strconv.Itoa(len(f.data)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(f.data[:cut])
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler) // drop the connection mid-body
	}
	h.mu.Lock()
	h.serveBytes(w, r, f)
	h.mu.Unlock()
}

// serveBytes serves f, Range requests included, with one byte flipped when
// the test asked for it. The caller holds h.mu.
func (h *fakeHub) serveBytes(w http.ResponseWriter, r *http.Request, f hubFile) {
	data := f.data
	if h.corrupt[f.path] {
		data = bytes.Clone(data)
		data[len(data)/2] ^= 0x01
	}
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(data))
}

// tinyModel is a small safetensors model: an LFS weight file, small JSON
// and tokenizer files, a nested file, and the .gitattributes every Hub
// repository has.
func tinyModel(salt string) []hubFile {
	weights := make([]byte, 256<<10)
	for i := range weights {
		weights[i] = byte(i*7 + len(salt))
	}
	copy(weights, salt)
	return []hubFile{
		{path: ".gitattributes", data: []byte("*.safetensors filter=lfs diff=lfs merge=lfs -text\n")},
		{path: "README.md", data: []byte("# tiny " + salt + "\n")},
		{path: "config.json", data: []byte(`{"model_type":"llama","quantization":"q4-` + salt + `"}`)},
		{path: "hello.txt", data: []byte("hello\n")},
		{path: "model.safetensors", data: weights, lfs: true},
		{path: "tokenizer/tokenizer.json", data: []byte(`{"version":"1.0","salt":"` + salt + `"}`)},
	}
}
