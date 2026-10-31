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
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// entries returns how many entries the table holds, confirmed or not.
func (t *sessions) entries() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.prune()
	return len(t.m)
}

// reservedSlots returns the slots admitted but not yet bound.
func (t *sessions) reservedSlots() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.reserved
}

// clock is a settable test clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// paced is a body of unknown length that hands out per bytes on each read and
// advances the clock by step after each.
type paced struct {
	c     *clock
	left  int
	per   int
	step  time.Duration
	reads int
}

func (p *paced) Read(b []byte) (int, error) {
	if p.left == 0 {
		return 0, io.EOF
	}
	n := min(p.per, p.left, len(b))
	for i := range n {
		b[i] = 'x'
	}
	p.left -= n
	p.reads++
	p.c.advance(p.step)
	return n, nil
}

// chunked is a request whose body length is unknown.
func chunked(method, path string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, path, io.NopCloser(body))
	r.ContentLength = -1
	return r
}

// newSessionLoc opens an upload session and returns its Location.
func (f *fixture) newSessionLoc(t *testing.T) string {
	t.Helper()
	w := f.do(http.MethodPost, "/v2/app/blobs/uploads/", nil)
	want(t, w, http.StatusAccepted, "")
	return w.Header().Get("Location")
}

// sessionSize returns the on-disk length of the session at loc.
func (f *fixture) sessionSize(t *testing.T, loc string) int64 {
	t.Helper()
	n, err := ref.ParseName("app")
	if err != nil {
		t.Fatal(err)
	}
	size, err := f.st.UploadSize(context.Background(), n, loc[strings.LastIndex(loc, "/")+1:])
	if err != nil {
		t.Fatal(err)
	}
	return size
}

// noUploads fails unless app holds no upload session.
func (f *fixture) noUploads(t *testing.T) {
	t.Helper()
	n, _ := ref.ParseName("app")
	ups, err := f.st.Uploads(n)
	if err != nil || len(ups) != 0 {
		t.Fatalf("uploads %v, %v; want none", ups, err)
	}
}

// TestRequestLimits pins the per-request bounds: the fail-closed authorizer,
// the upload size cap, the free-space checks, the body progress and duration
// bounds, the write deadlines, release on a panic and the session table's
// handling of ids it has not confirmed.
func TestRequestLimits(t *testing.T) {
	t.Run("New refuses a nil Authorizer", func(t *testing.T) {
		st, err := store.OpenWorkDir(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := New(Config{Store: st}); err == nil {
			t.Fatal("New allowed a server without an Authorizer")
		}
	})
	t.Run("an oversized chunked body is refused and leaves no byte past the cap", func(t *testing.T) {
		f := newFixture(t, func(c *Config) { c.MaxUploadSize = 8 })
		loc := f.newSessionLoc(t)
		want(t, f.do(http.MethodPatch, loc, []byte("abcdef")), http.StatusAccepted, "")
		want(t, f.serve(chunked(http.MethodPatch, loc, strings.NewReader("ghijk"))), http.StatusRequestEntityTooLarge, codeSizeInvalid)
		if got := f.sessionSize(t, loc); got != 6 {
			t.Fatalf("session holds %d bytes after a refused chunk, want 6", got)
		}
		want(t, f.serve(chunked(http.MethodPatch, loc, strings.NewReader("gh"))), http.StatusAccepted, "")
		want(t, f.serve(chunked(http.MethodPatch, loc, strings.NewReader("i"))), http.StatusRequestEntityTooLarge, codeSizeInvalid)
		if got := f.sessionSize(t, loc); got != 8 {
			t.Fatalf("session holds %d bytes, want the 8-byte cap", got)
		}
		// The session still commits what it holds.
		want(t, f.do(http.MethodPut, loc+"?digest="+dg([]byte("abcdefgh")).String(), nil), http.StatusCreated, "")
		// A known length over the cap is refused before a session exists.
		big := []byte("123456789")
		want(t, f.do(http.MethodPost, "/v2/app/blobs/uploads/?digest="+dg(big).String(), big), http.StatusRequestEntityTooLarge, codeSizeInvalid)
		loc = f.newSessionLoc(t)
		want(t, f.do(http.MethodPatch, loc, big), http.StatusRequestEntityTooLarge, codeSizeInvalid)
		want(t, f.serve(chunked(http.MethodPut, loc+"?digest="+dg(big).String(), bytes.NewReader(big))), http.StatusRequestEntityTooLarge, codeSizeInvalid)
		if got := f.sessionSize(t, loc); got != 0 {
			t.Fatalf("session holds %d bytes after refused chunks, want 0", got)
		}
	})
	t.Run("a Content-Length above free space answers 507 before any write", func(t *testing.T) {
		f := newFixture(t, func(c *Config) {
			c.MinFreeSpace = 1000
			c.FreeSpace = func() (uint64, error) { return 1010, nil }
		})
		loc := f.newSessionLoc(t)
		body := []byte("eleven byte")
		w := f.do(http.MethodPatch, loc, body)
		want(t, w, http.StatusInsufficientStorage, codeSizeInvalid)
		if strings.ContainsAny(w.Body.String(), "0123456789") {
			t.Errorf("the 507 body tells byte counts: %s", w.Body.String())
		}
		if got := f.sessionSize(t, loc); got != 0 {
			t.Fatalf("session holds %d bytes after a 507, want 0", got)
		}
		want(t, f.do(http.MethodPut, loc+"?digest="+dg(body).String(), body), http.StatusInsufficientStorage, codeSizeInvalid)
		want(t, f.do(http.MethodDelete, loc, nil), http.StatusNoContent, "")
		want(t, f.do(http.MethodPost, "/v2/app/blobs/uploads/?digest="+dg(body).String(), body), http.StatusInsufficientStorage, codeSizeInvalid)
		f.noUploads(t)
		// Ten bytes fit exactly.
		ten := body[:10]
		want(t, f.do(http.MethodPost, "/v2/app/blobs/uploads/?digest="+dg(ten).String(), ten), http.StatusCreated, "")
	})
	t.Run("free space falling mid-stream answers 507", func(t *testing.T) {
		var mu sync.Mutex
		calls := 0
		f := newFixture(t, func(c *Config) {
			c.MinFreeSpace = 1000
			c.FreeSpace = func() (uint64, error) {
				mu.Lock()
				defer mu.Unlock()
				calls++
				if calls > 2 { // the session start and the chunk's own check
					return 999, nil
				}
				return 1 << 30, nil
			}
		})
		f.srv.spaceEvery = 4
		loc := f.newSessionLoc(t)
		c := &clock{t: time.Unix(0, 0)}
		w := f.serve(chunked(http.MethodPatch, loc, &paced{c: c, left: 64, per: 4}))
		want(t, w, http.StatusInsufficientStorage, codeSizeInvalid)
		if got := f.sessionSize(t, loc); got >= 64 {
			t.Fatalf("session took the whole body (%d bytes) after space ran out", got)
		}
		// A monolithic upload that runs out of space leaves no session.
		mu.Lock()
		calls = 1 // the start's check passes, the first streamed check fails
		mu.Unlock()
		want(t, f.do(http.MethodDelete, loc, nil), http.StatusNoContent, "")
		body := bytes.Repeat([]byte("y"), 64)
		want(t, f.do(http.MethodPost, "/v2/app/blobs/uploads/?digest="+dg(body).String(), body), http.StatusInsufficientStorage, codeSizeInvalid)
		f.noUploads(t)
	})
	t.Run("a trickling body answers 408", func(t *testing.T) {
		c := &clock{t: time.Unix(0, 0)}
		f := newFixture(t, func(cfg *Config) { cfg.Now = c.now })
		loc := f.newSessionLoc(t)
		// One byte every ten seconds passes the idle bound but not the
		// minimum progress of a window.
		body := &paced{c: c, left: 1 << 20, per: 1, step: 10 * time.Second}
		want(t, f.serve(chunked(http.MethodPatch, loc, body)), http.StatusRequestTimeout, codeBlobUploadInvalid)
		if body.reads > 7 {
			t.Errorf("the trickle was read %d times past its first window", body.reads)
		}
		// A body that keeps the pace is not cut, however long it runs.
		steady := &paced{c: c, left: 4 * DefaultBodyMinBytes, per: 32 << 10, step: 6 * time.Second}
		loc = f.newSessionLoc(t)
		want(t, f.serve(chunked(http.MethodPatch, loc, steady)), http.StatusAccepted, "")
	})
	t.Run("a body still arriving after the upload timeout answers 408", func(t *testing.T) {
		c := &clock{t: time.Unix(0, 0)}
		f := newFixture(t, func(cfg *Config) {
			cfg.Now = c.now
			cfg.UploadTimeout = time.Hour
			cfg.BodyWindow = 24 * time.Hour
		})
		loc := f.newSessionLoc(t)
		body := &paced{c: c, left: 1 << 20, per: 1 << 10, step: 25 * time.Minute}
		want(t, f.serve(chunked(http.MethodPatch, loc, body)), http.StatusRequestTimeout, codeBlobUploadInvalid)
		if body.reads != 3 {
			t.Errorf("the body was read %d times, want 3 (the third read passes the hour)", body.reads)
		}
	})
	t.Run("write deadlines are set per request and sized from the blob", func(t *testing.T) {
		c := &clock{t: time.Unix(1000, 0)}
		f := newFixture(t, func(cfg *Config) {
			cfg.Now = c.now
			cfg.ResponseTimeout = time.Minute
			cfg.UploadTimeout = time.Hour
			cfg.MinWriteRate = 1 << 10
		})
		var mu sync.Mutex
		var last []time.Time
		f.srv.setWriteDeadline = func(_ http.ResponseWriter, t time.Time) {
			mu.Lock()
			last = append(last, t)
			mu.Unlock()
		}
		got := func() []time.Time {
			mu.Lock()
			defer mu.Unlock()
			out := last
			last = nil
			return out
		}
		base := c.now()
		want(t, f.do(http.MethodGet, "/v2/", nil), http.StatusOK, "")
		if g := got(); len(g) != 1 || !g[0].Equal(base.Add(time.Minute)) {
			t.Errorf("version check deadlines %v", g)
		}
		blob := bytes.Repeat([]byte("z"), 10<<10)
		d := f.pushBlob(t, "app", blob)
		if g := got(); len(g) != 1 || !g[0].Equal(base.Add(time.Minute+time.Hour)) {
			t.Errorf("upload deadlines %v", g)
		}
		w := f.do(http.MethodGet, "/v2/app/blobs/"+d.String(), nil)
		want(t, w, http.StatusOK, "")
		if g := got(); len(g) != 2 || !g[1].Equal(base.Add(time.Minute+10*time.Second)) {
			t.Errorf("blob GET deadlines %v, want the last at +1m10s", g)
		}
		if w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("blob GET X-Content-Type-Options %q", w.Header().Get("X-Content-Type-Options"))
		}
		if f.srv.writeWindow(1<<62) != 30*24*time.Hour {
			t.Errorf("a huge blob's window %v is not clamped", f.srv.writeWindow(1<<62))
		}
	})
	t.Run("a panic leaves no busy entry or reserved slot", func(t *testing.T) {
		f := newFixture(t, func(c *Config) { c.MaxSessions = 1 })
		clean := func(stage string) {
			t.Helper()
			if live, ent, res := f.srv.sessions.live(), f.srv.sessions.entries(), f.srv.sessions.reservedSlots(); live != 0 || ent != 0 || res != 0 {
				t.Fatalf("after a panic %s: live %d, entries %d, reserved %d", stage, live, ent, res)
			}
		}
		f.srv.sessionAdmitted = func() { panic("admit bug") }
		want(t, f.do(http.MethodPost, "/v2/app/blobs/uploads/", nil), http.StatusInternalServerError, codeUnavailable)
		clean("before the session existed")
		f.srv.sessionAdmitted = nil
		f.srv.chunkAppending = func() { panic("append bug") }
		body := []byte("mono")
		want(t, f.do(http.MethodPost, "/v2/app/blobs/uploads/?digest="+dg(body).String(), body), http.StatusInternalServerError, codeUnavailable)
		clean("in a monolithic upload")
		f.noUploads(t)
		// The one slot is free, and an entry a PATCH panicked in is not left
		// locked.
		f.srv.chunkAppending = nil
		loc := f.newSessionLoc(t)
		f.srv.chunkAppending = func() { panic("append bug") }
		want(t, f.do(http.MethodPatch, loc, []byte("a")), http.StatusInternalServerError, codeUnavailable)
		f.srv.chunkAppending = nil
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() { done <- f.do(http.MethodPatch, loc, []byte("a")) }()
		select {
		case w := <-done:
			want(t, w, http.StatusAccepted, "")
		case <-time.After(30 * time.Second):
			t.Fatal("a PATCH after a panicked one never got the session")
		}
	})
	t.Run("an id the store does not hold leaves nothing in the table", func(t *testing.T) {
		f := newFixture(t, func(c *Config) { c.MaxSessions = 1 })
		ghost := "/v2/app/blobs/uploads/00000000-0000-4000-8000-000000000000"
		want(t, f.do(http.MethodPatch, ghost, []byte("a")), http.StatusNotFound, codeBlobUploadUnknown)
		want(t, f.do(http.MethodPut, ghost+"?digest="+dg([]byte("a")).String(), nil), http.StatusNotFound, codeBlobUploadUnknown)
		want(t, f.do(http.MethodDelete, ghost, nil), http.StatusNotFound, codeBlobUploadUnknown)
		if n := f.srv.sessions.entries(); n != 0 {
			t.Fatalf("%d entries left by an unknown id", n)
		}
		// The one slot is still free.
		f.newSessionLoc(t)
	})
	t.Run("a manifest GET is not sniffable", func(t *testing.T) {
		f := newFixture(t)
		cfgBlob := f.pushBlob(t, "app", []byte("{}"))
		m := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"` + cfgBlob.String() + `","size":2},"layers":[]}`)
		want(t, f.pushManifest(t, "app", "v1", "application/vnd.oci.image.manifest.v1+json", m), http.StatusCreated, "")
		w := f.do(http.MethodGet, "/v2/app/manifests/v1", nil)
		want(t, w, http.StatusOK, "")
		if w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Content-Length") != strconv.Itoa(len(m)) {
			t.Errorf("manifest GET headers %v", w.Header())
		}
	})
}
