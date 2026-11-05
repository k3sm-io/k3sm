//go:build integration

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
	"testing"
	"time"
)

// TestBlobFloor proves a blob GET has a progress floor over a real socket: a
// reader that stalls is cut within ResponseTimeout, far short of the time the
// blob's size allows, and a reader that keeps going gets every byte, the
// deadline moving across chunks.
func TestBlobFloor(t *testing.T) {
	const size = 32 << 20
	blob := bytes.Repeat([]byte("0123456789abcdef"), size/16)
	// returned receives once for each request the server has finished with.
	serve := func(t *testing.T, timeout time.Duration, returned chan<- struct{}) (*httptest.Server, string) {
		f := newFixture(t, func(c *Config) {
			c.ResponseTimeout = timeout
			c.MinWriteRate = 1 << 20 // the blob's size alone allows 32 s
		})
		d := f.pushBlob(t, "app", blob)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() { returned <- struct{}{} }()
			f.srv.ServeHTTP(w, r)
		}))
		t.Cleanup(ts.Close)
		return ts, "/v2/app/blobs/" + d.String()
	}
	t.Run("a reader that stalls is cut", func(t *testing.T) {
		returned := make(chan struct{}, 1)
		ts, path := serve(t, 300*time.Millisecond, returned)
		c, err := net.Dial("tcp", ts.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: registry\r\n\r\n", path); err != nil {
			t.Fatal(err)
		}
		// The reader has read nothing. The bound sits well under the 32 s the
		// blob's size allows, so a floor taken from the size alone fails here.
		bound := time.NewTimer(10 * time.Second)
		defer bound.Stop()
		select {
		case <-returned:
		case <-bound.C:
			t.Fatal("the server still held a stalled reader after 10 s under a 300 ms floor")
		}
		_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, _ := io.Copy(io.Discard, c) // a reset is the expected end, as is a clean close
		if n >= size {
			t.Fatalf("read %d of %d bytes after the server gave up on the stall; the stall was not cut", n, size)
		}
	})
	t.Run("a reader that keeps going gets every byte", func(t *testing.T) {
		ts, path := serve(t, 30*time.Second, make(chan struct{}, 2))
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
