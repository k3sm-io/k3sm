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
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// serveOnWire serves r through an HTTP server on a loopback socket, so the
// answer is what a client reads, framed by net/http.
func serveOnWire(t *testing.T, f *fixture, r *http.Request) (*http.Response, []byte) {
	t.Helper()
	hs := httptest.NewServer(f.srv)
	t.Cleanup(hs.Close)
	out, err := http.NewRequest(r.Method, hs.URL+r.URL.RequestURI(), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hs.Client().Do(out)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return resp, body
}

// TestManifestReapedMidReadFramingOnTheWire pins the framing a client sees
// for a reaped-manifest read: a GET's Content-Length is the error body's
// length, and a HEAD sends no Content-Length (a HEAD's Content-Length would
// claim the size of a body the matching GET does not send).
func TestManifestReapedMidReadFramingOnTheWire(t *testing.T) {
	for _, tc := range reapedCases {
		t.Run(tc.name, func(t *testing.T) {
			a := readReaped(t, tc, serveOnWire)
			if a.resp.StatusCode != http.StatusNotFound {
				t.Fatalf("status %d, want 404; body %s", a.resp.StatusCode, a.body)
			}
			cl := a.resp.Header.Get("Content-Length")
			switch tc.method {
			case http.MethodGet:
				if cl != strconv.Itoa(len(a.body)) {
					t.Errorf("Content-Length %q, error body is %d bytes", cl, len(a.body))
				}
			case http.MethodHead:
				if len(a.body) != 0 {
					t.Errorf("HEAD answered a %d-byte body", len(a.body))
				}
				if cl != "" {
					t.Errorf("Content-Length %s on a bodiless 404", cl)
				}
			}
		})
	}
}
