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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// parkedBody brings first, then blocks until release, then brings rest. parked
// closes when the first read has happened: the server's reservation precedes
// that read.
type parkedBody struct {
	first, rest []byte
	parked      chan struct{}
	release     chan struct{}
	once        sync.Once
	failWith    error
	panicWith   any
}

func newParked(first, rest int) *parkedBody {
	return &parkedBody{first: bytes.Repeat([]byte("p"), first), rest: bytes.Repeat([]byte("q"), rest), parked: make(chan struct{}), release: make(chan struct{})}
}

func (b *parkedBody) Read(p []byte) (int, error) {
	if len(b.first) > 0 {
		n := copy(p, b.first)
		b.first = b.first[n:]
		b.once.Do(func() { close(b.parked) })
		return n, nil
	}
	<-b.release
	if b.panicWith != nil {
		panic(b.panicWith)
	}
	if b.failWith != nil {
		return 0, b.failWith
	}
	if len(b.rest) == 0 {
		return 0, io.EOF
	}
	n := copy(p, b.rest)
	b.rest = b.rest[n:]
	return n, nil
}

// TestUploadSpaceIsHeldInAggregate proves bodies in flight reserve free space
// together, where each used to be checked alone and N of them could undershoot
// the floor by N times the check interval. FreeSpace is constant here, as it
// is while the writers have not yet delivered their bytes.
func TestUploadSpaceIsHeldInAggregate(t *testing.T) {
	const kept, spare = 1000, 100
	newF := func(t *testing.T) *fixture {
		f := newFixture(t, func(c *Config) {
			c.MinFreeSpace = kept
			c.FreeSpace = func() (uint64, error) { return kept + spare, nil }
		})
		f.srv.spaceEvery = 60
		return f
	}
	// park starts a PATCH of body on a new session and waits for its first
	// read; the returned channel gives its answer.
	park := func(t *testing.T, f *fixture, body *parkedBody, length int64) <-chan *httptest.ResponseRecorder {
		t.Helper()
		loc := f.newSessionLoc(t)
		r := chunked(http.MethodPatch, loc, body)
		r.ContentLength = length
		answer := make(chan *httptest.ResponseRecorder, 1)
		go func() { answer <- f.serve(r) }()
		<-body.parked
		return answer
	}
	small := func(t *testing.T, f *fixture) *httptest.ResponseRecorder {
		t.Helper()
		return f.serve(chunked(http.MethodPatch, f.newSessionLoc(t), strings.NewReader("tiny")))
	}

	t.Run("bodies of unknown length share the room", func(t *testing.T) {
		f := newF(t)
		body := newParked(10, 0)
		answer := park(t, f, body, -1)
		// 60 are held of the 100 to spare, so a second body cannot take 60.
		want(t, small(t, f), http.StatusInsufficientStorage, codeSizeInvalid)
		close(body.release)
		want(t, <-answer, http.StatusAccepted, "")
		want(t, small(t, f), http.StatusAccepted, "")
	})
	t.Run("a known length is held whole and refused before a byte is written", func(t *testing.T) {
		f := newF(t)
		body := newParked(10, 50)
		answer := park(t, f, body, 60)
		loc := f.newSessionLoc(t)
		want(t, f.do(http.MethodPatch, loc, bytes.Repeat([]byte("k"), 60)), http.StatusInsufficientStorage, codeSizeInvalid)
		if got := f.sessionSize(t, loc); got != 0 {
			t.Fatalf("the refused chunk left %d bytes", got)
		}
		// What is left of the room still fits.
		want(t, f.do(http.MethodPatch, loc, bytes.Repeat([]byte("k"), 40)), http.StatusAccepted, "")
		close(body.release)
		want(t, <-answer, http.StatusAccepted, "")
	})
	t.Run("a finished body holds nothing", func(t *testing.T) {
		f := newF(t)
		body := newParked(50, 10)
		answer := park(t, f, body, 60)
		close(body.release)
		want(t, <-answer, http.StatusAccepted, "")
		want(t, f.do(http.MethodPatch, f.newSessionLoc(t), bytes.Repeat([]byte("k"), spare)), http.StatusAccepted, "")
	})
	t.Run("a body of exactly the room finishes, across a re-check and its EOF", func(t *testing.T) {
		f := newF(t)
		want(t, f.do(http.MethodPatch, f.newSessionLoc(t), bytes.Repeat([]byte("k"), spare)), http.StatusAccepted, "")
	})
	for _, tc := range []struct {
		name string
		arm  func(*parkedBody)
	}{
		{"a body that fails gives its share back", func(b *parkedBody) { b.failWith = fmt.Errorf("client gone") }},
		{"a body that panics gives its share back", func(b *parkedBody) { b.panicWith = "reader bug" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newF(t)
			body := newParked(10, 0)
			tc.arm(body)
			answer := park(t, f, body, -1)
			close(body.release)
			if w := <-answer; w.Code < 400 {
				t.Fatalf("status %d", w.Code)
			}
			want(t, small(t, f), http.StatusAccepted, "")
		})
	}
}

// TestBodyFloorWindow pins what the request body floor counts: a wait before
// the first read (the session's lock) is not the client's, the overall deadline
// still runs through it, and windows are consecutive, as the doc now says.
func TestBodyFloorWindow(t *testing.T) {
	setup := func(t *testing.T) (*clock, *Server) {
		c := &clock{t: time.Unix(1000, 0)}
		f := newFixture(t, func(cfg *Config) {
			cfg.Now = c.now
			cfg.BodyWindow = time.Minute
			cfg.BodyMinBytes = 4
			cfg.UploadTimeout = time.Hour
		})
		return c, f.srv
	}
	body := func(s *Server, data string) io.Reader {
		return s.body(httptest.NewRecorder(), httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(data)))
	}
	t.Run("a wait before the first read is not charged to the window", func(t *testing.T) {
		c, s := setup(t)
		b := body(s, "abcdef")
		c.advance(10 * time.Minute)
		if _, err := b.Read(make([]byte, 4)); err != nil {
			t.Fatalf("first read after a lock wait = %v", err)
		}
	})
	t.Run("the overall deadline still runs through that wait", func(t *testing.T) {
		c, s := setup(t)
		b := body(s, "abcdef")
		c.advance(time.Hour)
		if _, err := b.Read(make([]byte, 4)); err != errRequestTooLong {
			t.Fatalf("read past the upload timeout = %v", err)
		}
	})
	t.Run("a window short of its minimum fails", func(t *testing.T) {
		c, s := setup(t)
		b := body(s, "abcdef")
		if _, err := b.Read(make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		c.advance(time.Minute)
		if _, err := b.Read(make([]byte, 1)); err != errBodyTooSlow {
			t.Fatalf("read after a short window = %v", err)
		}
	})
	t.Run("a burst then silence is the documented slack", func(t *testing.T) {
		c, s := setup(t)
		b := body(s, "abcdefgh")
		if _, err := b.Read(make([]byte, 4)); err != nil {
			t.Fatal(err)
		}
		c.advance(5 * time.Minute) // BodyIdle's read deadline needs a real connection
		if _, err := b.Read(make([]byte, 1)); err != nil {
			t.Fatalf("read after a satisfied window = %v", err)
		}
		c.advance(time.Minute)
		if _, err := b.Read(make([]byte, 1)); err != errBodyTooSlow {
			t.Fatalf("the window after the slack is not held to its minimum: %v", err)
		}
	})
}

// TestCommitForgetsTheSessionOnAPanic proves a commit that panics leaves no
// entry holding a session slot, whether or not the blob made it in, and that a
// commit that fails keeps the session's entry for the retry.
func TestCommitForgetsTheSessionOnAPanic(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.MaxSessions = 1 })
	loc := f.newSessionLoc(t)
	blob := []byte("committed")
	f.srv.uploadCommitting = func() { panic("commit bug") }
	want(t, f.do(http.MethodPut, loc+"?digest="+dg(blob).String(), blob), http.StatusInternalServerError, codeUnavailable)
	f.srv.uploadCommitting = nil
	if ent := f.srv.sessions.entries(); ent != 0 {
		t.Fatalf("%d entries after the panic", ent)
	}
	want(t, f.do(http.MethodHead, "/v2/app/blobs/"+dg(blob).String(), nil), http.StatusOK, "")

	retry := f.newSessionLoc(t) // the one slot is free
	wrong := dg([]byte("something else"))
	want(t, f.do(http.MethodPut, retry+"?digest="+wrong.String(), blob), http.StatusBadRequest, codeDigestInvalid)
	if ent := f.srv.sessions.entries(); ent != 1 {
		t.Fatalf("%d entries after a failed commit, want the session's one", ent)
	}
}

// TestBlobFloor proves a blob GET has a progress floor over a real socket: a
// reader that stalls is cut within ResponseTimeout, far short of the time the
// blob's size allows, and a reader that keeps going gets every byte, the
// deadline moving across chunks.
func TestBlobFloor(t *testing.T) {
	const size = 32 << 20
	blob := bytes.Repeat([]byte("0123456789abcdef"), size/16)
	serve := func(t *testing.T, timeout time.Duration) (*httptest.Server, string) {
		f := newFixture(t, func(c *Config) {
			c.ResponseTimeout = timeout
			c.MinWriteRate = 1 << 20 // the blob's size alone allows 32 s
		})
		d := f.pushBlob(t, "app", blob)
		ts := httptest.NewServer(f.srv)
		t.Cleanup(ts.Close)
		return ts, "/v2/app/blobs/" + d.String()
	}
	t.Run("a reader that stalls is cut", func(t *testing.T) {
		ts, path := serve(t, 300*time.Millisecond)
		c, err := net.Dial("tcp", ts.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: registry\r\n\r\n", path); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Second)
		_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, _ := io.Copy(io.Discard, c) // a reset is the expected end, as is a clean close
		if n >= size {
			t.Fatalf("read %d of %d bytes after a 2 s stall under a 300 ms floor; the stall was not cut", n, size)
		}
	})
	t.Run("a reader that keeps going gets every byte", func(t *testing.T) {
		ts, path := serve(t, 30*time.Second)
		for _, tc := range []struct {
			name, rng string
			status    int
			want      []byte
		}{
			{"whole", "", http.StatusOK, blob},
			{"range", "bytes=1-", http.StatusPartialContent, blob[1:]},
		} {
			t.Run(tc.name, func(t *testing.T) {
				r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+path, nil)
				if err != nil {
					t.Fatal(err)
				}
				if tc.rng != "" {
					r.Header.Set("Range", tc.rng)
				}
				resp, err := ts.Client().Do(r)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				if resp.StatusCode != tc.status {
					t.Fatalf("status %d", resp.StatusCode)
				}
				h := sha256.New()
				if _, err := io.Copy(h, resp.Body); err != nil {
					t.Fatal(err)
				}
				wantSum := sha256.Sum256(tc.want)
				if got := hex.EncodeToString(h.Sum(nil)); got != hex.EncodeToString(wantSum[:]) {
					t.Fatalf("body hash %s", got)
				}
			})
		}
	})
}

// TestCatalogAsksOncePerVisit pins the choice that the Authorizer hook keeps no
// list form: the catalog asks once for the catalog itself and once for each
// repository it visits, so the visit budget bounds the hook's calls.
func TestCatalogAsksOncePerVisit(t *testing.T) {
	var asks, visits atomic.Int64
	f := newFixture(t, func(c *Config) {
		c.Authorize = func(_ *http.Request, _ Verb, _ ref.Name) error {
			asks.Add(1)
			return nil
		}
	})
	f.srv.catalogVisited = func() { visits.Add(1) }
	names := make([]string, 0, 2000)
	for i := range 2000 {
		names = append(names, fmt.Sprintf("r%04d", i))
	}
	layRepos(t, f.root, names)
	want(t, f.do(http.MethodGet, "/v2/_catalog", nil), http.StatusOK, "")
	if asks.Load() != visits.Load()+1 {
		t.Fatalf("%d asks for %d visits; want one per visit and one for the catalog", asks.Load(), visits.Load())
	}
	if visits.Load() > int64(catalogVisits(defaultCatalogPage)) {
		t.Fatalf("%d visits, over the budget of a default page", visits.Load())
	}
}
