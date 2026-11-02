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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/gc"
)

// blobFile is the path of blob d in repo.
func (f *fixture) blobFile(repo string, d digest.Digest) string {
	return filepath.Join(f.root, repo, "blobs", d.Algorithm().String(), d.Encoded())
}

// age sets the mtime of each blob in ds to at.
func (f *fixture) age(t *testing.T, repo string, at time.Time, ds ...digest.Digest) {
	t.Helper()
	for _, d := range ds {
		if err := os.Chtimes(f.blobFile(repo, d), at, at); err != nil {
			t.Fatal(err)
		}
	}
}

// deletingCollector is a collector over f's store that started two grace
// periods ago and has already run its report-only first sweep, so its next
// sweep deletes.
func (f *fixture) deletingCollector(t *testing.T, grace time.Duration) *gc.Collector {
	t.Helper()
	start := time.Now().Add(-2 * grace)
	now := func() time.Time { return start }
	c, err := gc.New(f.st, gc.Options{Grace: grace, Now: func() time.Time { return now() }, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	now = time.Now
	if err := os.WriteFile(filepath.Join(f.st.StateDir(), gc.MarkerName), []byte("ran\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestManifestHeadKeepsTheChildForTheIndexPut pins the server contract between
// a client pushing an index and the online garbage collector: the client HEADs
// each child manifest by digest, skips the push of every child the HEAD finds,
// and PUTs the index. A sweep that runs between the HEAD and the PUT must not
// reap a child the HEAD reported present, however old and untagged it was,
// and the PUT must answer 201 with the child kept. Without the HEAD the same
// sweep reaps the child, so the test is not vacuous; the index PUT is then
// still accepted, because an index never requires its children, and names a
// child the registry no longer holds: the dangling index the HEAD prevents.
func TestManifestHeadKeepsTheChildForTheIndexPut(t *testing.T) {
	const grace = time.Hour
	for _, tc := range []struct {
		name string
		head bool
	}{
		{"a HEAD hit by digest survives the sweep", true},
		{"without a HEAD the sweep reaps the child", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			// A tagged image keeps half of the repository referenced, so the
			// sweep's half-repository brake does not hold.
			f.image(t, "app", "kept", "kept-layer")
			child := f.image(t, "app", "", "child-layer")
			cd := dg(child)
			var m ispec.Manifest
			if err := json.Unmarshal(child, &m); err != nil {
				t.Fatal(err)
			}
			// The child and its blobs are left from an index push that never
			// PUT its index, two grace periods ago.
			f.age(t, "app", time.Now().Add(-2*grace), cd, m.Config.Digest, m.Layers[0].Digest)
			c := f.deletingCollector(t, grace)

			if tc.head {
				w := f.do(http.MethodHead, "/v2/app/manifests/"+cd.String(), nil)
				want(t, w, http.StatusOK, "")
				if got := w.Header().Get("Docker-Content-Digest"); got != cd.String() {
					t.Fatalf("HEAD Docker-Content-Digest %q, want %s", got, cd)
				}
			}
			if _, err := c.Sweep(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !tc.head {
				want(t, f.do(http.MethodGet, "/v2/app/manifests/"+cd.String(), nil), http.StatusNotFound, codeManifestUnknown)
			}

			f.index(t, "app", "v1", child)
			if !tc.head {
				want(t, f.do(http.MethodGet, "/v2/app/manifests/"+cd.String(), nil), http.StatusNotFound, codeManifestUnknown)
				return
			}
			want(t, f.do(http.MethodGet, "/v2/app/manifests/"+cd.String(), nil), http.StatusOK, "")
			for _, d := range []digest.Digest{m.Config.Digest, m.Layers[0].Digest} {
				want(t, f.do(http.MethodHead, "/v2/app/blobs/"+d.String(), nil), http.StatusOK, "")
			}
			// The child is now named by a tagged index, so a later sweep keeps
			// it at any age.
			f.age(t, "app", time.Now().Add(-2*grace), cd)
			if _, err := c.Sweep(context.Background()); err != nil {
				t.Fatal(err)
			}
			want(t, f.do(http.MethodGet, "/v2/app/manifests/"+cd.String(), nil), http.StatusOK, "")
		})
	}
}

// TestManifestReadsThatWriteNothing pins the reads that leave a manifest's
// mtime alone: a HEAD by tag (a tagged row is kept at any age) and a GET by
// tag or by digest (a pull). Only a HEAD by digest touches.
func TestManifestReadsThatWriteNothing(t *testing.T) {
	old := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	for _, tc := range []struct {
		name    string
		method  string
		byTag   bool
		touches bool
	}{
		{"HEAD by tag", http.MethodHead, true, false},
		{"GET by tag", http.MethodGet, true, false},
		{"GET by digest", http.MethodGet, false, false},
		{"HEAD by digest", http.MethodHead, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			body := f.image(t, "app", "v1", "layer")
			d := dg(body)
			f.age(t, "app", old, d)
			reference := d.String()
			if tc.byTag {
				reference = "v1"
			}
			want(t, f.do(tc.method, "/v2/app/manifests/"+reference, nil), http.StatusOK, "")
			fi, err := os.Stat(f.blobFile("app", d))
			if err != nil {
				t.Fatal(err)
			}
			if touched := !fi.ModTime().Equal(old); touched != tc.touches {
				t.Errorf("mtime %s after %s (was %s), touched %v, want %v", fi.ModTime(), tc.name, old, touched, tc.touches)
			}
		})
	}
}

// TestManifestHeadAfterReapAnswers404 pins the answer of a HEAD by digest
// whose manifest a sweep reaps after the read and before the touch: the touch
// finds the manifest gone, and the HEAD answers 404 MANIFEST_UNKNOWN, never a
// 200 (the client would skip the push of a manifest the registry no longer
// holds) and never a 500. A HEAD answer carries no body, so the code is read
// from the server's refusal log record.
func TestManifestHeadAfterReapAnswers404(t *testing.T) {
	const grace = time.Hour
	var logs bytes.Buffer
	f := newFixture(t, func(c *Config) {
		c.Logger = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	// A tagged image keeps half of the repository referenced, so the sweep's
	// half-repository brake does not hold.
	f.image(t, "app", "kept", "kept-layer")
	child := f.image(t, "app", "", "child-layer")
	cd := dg(child)
	f.age(t, "app", time.Now().Add(-2*grace), cd)
	c := f.deletingCollector(t, grace)
	reaped := false
	f.srv.manifestRead = func() {
		if _, err := c.Sweep(context.Background()); err != nil {
			t.Error(err)
		}
		if _, err := os.Stat(f.blobFile("app", cd)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("the sweep kept the manifest %s: stat %v", cd, err)
		}
		reaped = true
	}
	logs.Reset()
	w := f.do(http.MethodHead, "/v2/app/manifests/"+cd.String(), nil)
	if !reaped {
		t.Fatal("the HEAD did not reach the seam between the read and the touch")
	}
	want(t, w, http.StatusNotFound, "")
	var codes []string
	dec := json.NewDecoder(&logs)
	for dec.More() {
		var rec struct {
			Msg    string `json:"msg"`
			Method string `json:"method"`
			Code   string `json:"code"`
		}
		if err := dec.Decode(&rec); err != nil {
			t.Fatal(err)
		}
		if rec.Method == http.MethodHead && rec.Code != "" {
			codes = append(codes, rec.Code)
		}
	}
	if len(codes) != 1 || codes[0] != codeManifestUnknown {
		t.Fatalf("HEAD answered codes %v, want [%s]", codes, codeManifestUnknown)
	}
}

// lockedBuffer is a log sink the server goroutine writes and the test reads.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.b.Reset()
}

// refusalCodes returns the error codes of the refusal records logged for
// requests of method.
func (l *lockedBuffer) refusalCodes(t *testing.T, method string) []string {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	var codes []string
	dec := json.NewDecoder(bytes.NewReader(l.b.Bytes()))
	for dec.More() {
		var rec struct {
			Method string `json:"method"`
			Code   string `json:"code"`
		}
		if err := dec.Decode(&rec); err != nil {
			t.Fatal(err)
		}
		if rec.Method == method && rec.Code != "" {
			codes = append(codes, rec.Code)
		}
	}
	return codes
}

// hasRow reports whether repo's index.json has a row for d.
func (f *fixture) hasRow(t *testing.T, repo string, d digest.Digest) bool {
	t.Helper()
	for _, r := range f.rows(t, repo) {
		if r.Digest == d {
			return true
		}
	}
	return false
}

// fileGone fails unless the manifest file of d in repo is absent.
func (f *fixture) fileGone(t *testing.T, repo string, d digest.Digest) {
	t.Helper()
	if _, err := os.Stat(f.blobFile(repo, d)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the manifest file %s is still there: stat %v", d, err)
	}
}

// reapState is the state a reaped-manifest read meets.
type reapState int

const (
	// reapedAfterTouchRead is a HEAD by digest whose manifest a real sweep
	// reaps between the read and the touch (the manifestRead seam).
	reapedAfterTouchRead reapState = iota
	// rowReadBeforeSweep is a read that found the row in index.json before
	// a real sweep reaped the row and then the file. The store reads the row
	// and the file inside one call with no seam between them, so the state
	// is made by running the sweep and putting back the index.json the read
	// saw: the row present, the file as the sweep left it.
	rowReadBeforeSweep
	// indexNamesMissingFile is a tagged row whose file is gone. The sweep
	// never makes it (it reaps untagged rows only, rows before blobs); it is
	// a store whose index names a file it does not hold.
	indexNamesMissingFile
	// afterSweep is a read after a real sweep reaped the row and the file.
	afterSweep
)

type reapedCase struct {
	name   string
	method string
	state  reapState
}

var reapedCases = []reapedCase{
	{"HEAD by digest, reaped between the read and the touch", http.MethodHead, reapedAfterTouchRead},
	{"HEAD by digest, row read before a sweep reaped the file", http.MethodHead, rowReadBeforeSweep},
	{"GET by digest, row read before a sweep reaped the file", http.MethodGet, rowReadBeforeSweep},
	{"HEAD by tag, index names a missing file", http.MethodHead, indexNamesMissingFile},
	{"GET by tag, index names a missing file", http.MethodGet, indexNamesMissingFile},
	{"HEAD by digest, after a sweep reaped the row and the file", http.MethodHead, afterSweep},
	{"GET by digest, after a sweep reaped the row and the file", http.MethodGet, afterSweep},
}

// reapedAnswer is what a reaped-manifest read answered.
type reapedAnswer struct {
	resp  *http.Response
	body  []byte
	codes []string // the refusal codes logged for the request's method
}

// reapedServe serves one request to f's server and returns the response and
// its body.
type reapedServe func(t *testing.T, f *fixture, r *http.Request) (*http.Response, []byte)

// serveInProcess serves r through f's handler with a response recorder, so the
// answer is what the handler wrote, before net/http frames it.
func serveInProcess(t *testing.T, f *fixture, r *http.Request) (*http.Response, []byte) {
	t.Helper()
	w := f.serve(r)
	return w.Result(), w.Body.Bytes()
}

// readReaped sets up tc's state in a fresh store, serves one read of the
// manifest with serve and returns the answer.
func readReaped(t *testing.T, tc reapedCase, serve reapedServe) reapedAnswer {
	t.Helper()
	const grace = time.Hour
	logs := &lockedBuffer{}
	f := newFixture(t, func(c *Config) {
		c.Logger = slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	// A tagged image keeps half of the repository referenced, so the
	// sweep's half-repository brake does not hold.
	f.image(t, "app", "kept", "kept-layer")
	tag := ""
	if tc.state == indexNamesMissingFile {
		tag = "v1"
	}
	cd := dg(f.image(t, "app", tag, "child-layer"))
	reference := cd.String()
	if tag != "" {
		reference = tag
	}
	if !f.hasRow(t, "app", cd) {
		t.Fatalf("no index row for %s after its push", cd)
	}
	reaped := false
	switch tc.state {
	case reapedAfterTouchRead:
		f.age(t, "app", time.Now().Add(-2*grace), cd)
		c := f.deletingCollector(t, grace)
		f.srv.manifestRead = func() {
			if !f.hasRow(t, "app", cd) {
				t.Errorf("no index row for %s at the read", cd)
			}
			if _, err := c.Sweep(context.Background()); err != nil {
				t.Error(err)
			}
			f.fileGone(t, "app", cd)
			reaped = true
		}
	case rowReadBeforeSweep:
		indexPath := filepath.Join(f.root, "app", "index.json")
		seen, err := os.ReadFile(indexPath)
		if err != nil {
			t.Fatal(err)
		}
		f.age(t, "app", time.Now().Add(-2*grace), cd)
		if _, err := f.deletingCollector(t, grace).Sweep(context.Background()); err != nil {
			t.Fatal(err)
		}
		if f.hasRow(t, "app", cd) {
			t.Fatalf("the sweep kept the row of %s", cd)
		}
		f.fileGone(t, "app", cd)
		if err := os.WriteFile(indexPath, seen, 0o600); err != nil {
			t.Fatal(err)
		}
		if !f.hasRow(t, "app", cd) {
			t.Fatalf("no index row for %s after restoring the index the read saw", cd)
		}
		reaped = true
	case indexNamesMissingFile:
		if err := os.Remove(f.blobFile("app", cd)); err != nil {
			t.Fatal(err)
		}
		if !f.hasRow(t, "app", cd) {
			t.Fatalf("no index row for %s after the file removal", cd)
		}
		reaped = true
	case afterSweep:
		f.age(t, "app", time.Now().Add(-2*grace), cd)
		if _, err := f.deletingCollector(t, grace).Sweep(context.Background()); err != nil {
			t.Fatal(err)
		}
		if f.hasRow(t, "app", cd) {
			t.Fatalf("the sweep kept the row of %s", cd)
		}
		f.fileGone(t, "app", cd)
		reaped = true
	}

	logs.reset()
	resp, body := serve(t, f, httptest.NewRequest(tc.method, "/v2/app/manifests/"+reference, nil))
	if !reaped {
		t.Fatal("the manifest was not reaped before the read answered")
	}
	return reapedAnswer{resp: resp, body: body, codes: logs.refusalCodes(t, tc.method)}
}

// TestManifestReapedMidReadAnswers404OnEveryPath pins the answer for a
// manifest that is gone when a read reaches it, on every manifest read path
// and in every state a reaped manifest can be met in: the row read before a
// sweep removed the row and the file, a tagged row whose file is missing, and
// both gone after the sweep. Each read answers 404, a GET with one
// MANIFEST_UNKNOWN error in its body, a HEAD with no body, and none sends a
// Docker-Content-Digest. The handler sets no Content-Length on the refusal,
// so net/http frames it from what is written: a stale manifest length cannot
// reach the client. The framing a client sees on the wire is pinned by
// TestManifestReapedMidReadFramingOnTheWire, behind the integration tag.
func TestManifestReapedMidReadAnswers404OnEveryPath(t *testing.T) {
	for _, tc := range reapedCases {
		t.Run(tc.name, func(t *testing.T) {
			a := readReaped(t, tc, serveInProcess)
			if a.resp.StatusCode != http.StatusNotFound {
				t.Fatalf("status %d, want 404; body %s", a.resp.StatusCode, a.body)
			}
			if got := a.resp.Header.Get("Docker-Content-Digest"); got != "" {
				t.Errorf("Docker-Content-Digest %q on a 404", got)
			}
			if cl := a.resp.Header.Get("Content-Length"); cl != "" {
				t.Errorf("the handler set Content-Length %s on a refusal", cl)
			}
			switch tc.method {
			case http.MethodGet:
				var eb errorBody
				if err := json.Unmarshal(a.body, &eb); err != nil || len(eb.Errors) != 1 || eb.Errors[0].Code != codeManifestUnknown {
					t.Errorf("error body %s, want code %s", a.body, codeManifestUnknown)
				}
			case http.MethodHead:
				if len(a.body) != 0 {
					t.Errorf("HEAD answered a %d-byte body", len(a.body))
				}
			}
		})
	}
}

// TestManifestHeadReapedAnswersManifestUnknownCode pins the code a HEAD of a
// reaped manifest answers, in every state the HEAD can meet it in. A HEAD
// answer carries no body, so the code is read from the server's refusal log
// record. The states where the row is found and the file is not reach the
// handler as the store's BLOB_UNKNOWN; the handler answers them as
// MANIFEST_UNKNOWN, since what the client asked for is a manifest. The state
// after the sweep has no row and is MANIFEST_UNKNOWN from the lookup.
func TestManifestHeadReapedAnswersManifestUnknownCode(t *testing.T) {
	for _, tc := range reapedCases {
		if tc.method != http.MethodHead {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			a := readReaped(t, tc, serveInProcess)
			if a.resp.StatusCode != http.StatusNotFound {
				t.Fatalf("status %d, want 404", a.resp.StatusCode)
			}
			if len(a.codes) != 1 || a.codes[0] != codeManifestUnknown {
				t.Fatalf("HEAD answered codes %v, want [%s]", a.codes, codeManifestUnknown)
			}
		})
	}
}
