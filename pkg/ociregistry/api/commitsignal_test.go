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
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
)

// signalAnswer is one response, with its upload session's random id taken out.
type signalAnswer struct {
	Status int
	Header http.Header
	Body   string
}

// signalPush drives one way of pushing a blob and records every answer.
type signalPush struct {
	f       *fixture
	t       *testing.T
	ids     []string
	answers []signalAnswer
}

// do records one request's answer and returns its raw Location.
func (p *signalPush) do(method, path string, body []byte) string {
	p.t.Helper()
	w := p.f.do(method, path, body, "Content-Type", "application/octet-stream")
	if id := w.Header().Get("Docker-Upload-UUID"); id != "" {
		p.ids = append(p.ids, id)
	}
	blank := func(s string) string {
		for _, id := range p.ids {
			s = strings.ReplaceAll(s, id, "<id>")
		}
		return s
	}
	h := w.Header().Clone()
	for _, vs := range h {
		for i := range vs {
			vs[i] = blank(vs[i])
		}
	}
	p.answers = append(p.answers, signalAnswer{w.Code, h, blank(w.Body.String())})
	return w.Header().Get("Location")
}

// TestCommitGivesNoCrossRepositorySignal pins that the push path does not look
// across repositories: dedupe is a pass that runs later. With another repository
// holding the blob or not, every way of pushing it answers the same status,
// headers and body; the commit leaves the pushed blob on an inode of its own; and
// it reads nothing of the other repository.
//
// What it cannot see is a bare lstat of a path already known, which moves no
// access time. Finding that path takes a listing, and a listing does move it.
func TestCommitGivesNoCrossRepositorySignal(t *testing.T) {
	const target, holder = "team/target", "other/holder"
	layer := "layer bytes that two repositories push without a mount"
	body := []byte(layer)
	d := dg(body)
	blob := "/v2/" + target + "/blobs/" + d.String()
	uploads := "/v2/" + target + "/blobs/uploads/"
	withDigest := func(loc string) string { return loc + "?digest=" + d.String() }

	shapes := []struct {
		name string
		push func(p *signalPush)
	}{
		{"monolithic", func(p *signalPush) {
			p.do(http.MethodPost, withDigest(uploads), body)
		}},
		{"session, then a whole PUT", func(p *signalPush) {
			p.do(http.MethodPut, withDigest(p.do(http.MethodPost, uploads, nil)), body)
		}},
		{"chunk, then the rest in the PUT", func(p *signalPush) {
			loc := p.do(http.MethodPatch, p.do(http.MethodPost, uploads, nil), body[:9])
			p.do(http.MethodPut, withDigest(loc), body[9:])
		}},
		{"chunk, then an empty PUT", func(p *signalPush) {
			loc := p.do(http.MethodPatch, p.do(http.MethodPost, uploads, nil), body)
			p.do(http.MethodPut, withDigest(loc), nil)
		}},
		{"mount naming no source, then a PUT", func(p *signalPush) {
			p.do(http.MethodPut, withDigest(p.do(http.MethodPost, uploads+"?mount="+d.String(), nil)), body)
		}},
		{"mount from a repository without it, then a PUT", func(p *signalPush) {
			p.do(http.MethodPut, withDigest(p.do(http.MethodPost, uploads+"?mount="+d.String()+"&from=nowhere/empty", nil)), body)
		}},
	}

	// The same other repository in both stores, but for the one blob.
	hit, miss := newFixture(t), newFixture(t)
	hit.image(t, holder, "v1", layer)
	miss.image(t, holder, "v1", strings.ToUpper(layer))

	run := func(t *testing.T, store *fixture, shape func(*signalPush), after func(*fixture)) []signalAnswer {
		t.Helper()
		f := store.clone(t)
		watched := watchRepository(t, f.root, holder)
		p := &signalPush{f: f, t: t}
		p.do(http.MethodHead, blob, nil)
		shape(p)
		watched.check(t)
		after(f)
		p.do(http.MethodHead, blob, nil)
		p.do(http.MethodGet, blob, nil)
		return p.answers
	}

	for _, tc := range shapes {
		t.Run(tc.name, func(t *testing.T) {
			unshared := func(f *fixture) {
				t.Helper()
				pushed := lstatBlob(t, f.root, target, d)
				if n := pushed.Sys().(*syscall.Stat_t).Nlink; n != 1 {
					t.Errorf("the pushed blob has %d links, want an inode of its own", n)
				}
				// Only the store where the other repository holds this blob has a path here.
				if other, err := os.Lstat(blobFile(f.root, holder, d)); err == nil {
					if os.SameFile(pushed, other) {
						t.Error("the commit shared an inode with the other repository")
					}
					if n := other.Sys().(*syscall.Stat_t).Nlink; n != 1 {
						t.Errorf("the other repository's blob has %d links after the commit", n)
					}
				}
			}
			got := run(t, hit, tc.push, unshared)
			wanted := run(t, miss, tc.push, unshared)
			if !reflect.DeepEqual(got, wanted) {
				t.Errorf("another repository holding the blob changed the answers:\nheld: %+v\nnot:  %+v", got, wanted)
			}
			if last := got[len(got)-1]; last.Status != http.StatusOK || last.Body != layer {
				t.Errorf("the pushed blob reads %d %q", last.Status, last.Body)
			}
		})
	}
}

// blobFile is the path of blob d in repo under root.
func blobFile(root, repo string, d digest.Digest) string {
	return filepath.Join(root, repo, "blobs", d.Algorithm().String(), d.Encoded())
}

func lstatBlob(t *testing.T, root, repo string, d digest.Digest) os.FileInfo {
	t.Helper()
	fi, err := os.Lstat(blobFile(root, repo, d))
	if err != nil {
		t.Fatal(err)
	}
	return fi
}

// repositoryWatch notices a read of a repository, or a listing of the store root,
// by access time. An access time older than a day moves on the next read, even on
// a volume that updates it lazily.
type repositoryWatch struct {
	paths []string
	mtime map[string]time.Time
	at    time.Time
}

// watchRepository sets every path of repo, and the root, to a long-past access
// time and keeps each mtime as it was.
func watchRepository(t *testing.T, root, repo string) *repositoryWatch {
	t.Helper()
	w := &repositoryWatch{
		paths: []string{root},
		mtime: map[string]time.Time{},
		at:    time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	// Each directory down to the repository: a walk would list each of them.
	for p := filepath.Join(root, repo); p != root; p = filepath.Dir(p) {
		w.paths = append(w.paths, p)
	}
	err := filepath.WalkDir(filepath.Join(root, repo), func(p string, _ fs.DirEntry, err error) error {
		if err == nil && p != filepath.Join(root, repo) {
			w.paths = append(w.paths, p)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range w.paths {
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		w.mtime[p] = fi.ModTime()
		if err := os.Chtimes(p, w.at, fi.ModTime()); err != nil {
			t.Fatal(err)
		}
	}
	return w
}

// check fails for a path read since the watch began, then proves that a read here
// would have shown: a volume that never moves an access time proves nothing, and
// says so.
func (w *repositoryWatch) check(t *testing.T) {
	t.Helper()
	var file string
	for _, p := range w.paths {
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		if !fileAtime(fi).Equal(w.at) {
			t.Errorf("the push read %s", p)
		}
		// A root gains an entry for a new repository; everything else stays put.
		if p != w.paths[0] && !fi.ModTime().Equal(w.mtime[p]) {
			t.Errorf("the push wrote %s", p)
		}
		if fi.Mode().IsRegular() {
			file = p
		}
	}
	if file == "" {
		t.Fatal("the watch holds no file")
	}
	if _, err := os.ReadFile(file); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(file)
	if err != nil {
		t.Fatal(err)
	}
	if fileAtime(fi).Equal(w.at) {
		t.Log("this volume does not move access times, so the no-read check proved nothing")
	}
}
