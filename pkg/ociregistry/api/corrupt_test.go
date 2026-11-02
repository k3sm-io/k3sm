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
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
)

// TestManifestCorruptOnDiskAnswers5xxNoDigestHeader pins the answer for a
// stored manifest whose bytes no longer match its index row: a fault of the
// registry's storage, not of the request. GET and HEAD, by digest and by tag,
// answer 500 with a code that does not blame the client's digest, send no
// manifest bytes and no Docker-Content-Digest, and log the fault at Error
// naming the digest.
func TestManifestCorruptOnDiskAnswers5xxNoDigestHeader(t *testing.T) {
	corrupt := map[string]func([]byte) []byte{
		"truncated": func(b []byte) []byte { return b[:len(b)/2] },
		"byte flipped": func(b []byte) []byte {
			c := bytes.Clone(b)
			c[len(c)/2] ^= 0x01
			return c
		},
	}
	for name, mangle := range corrupt {
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			f := newFixture(t, func(c *Config) {
				c.Logger = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			})
			body := f.image(t, "app", "v1", "layer")
			d := dg(body)
			p := f.blobFile("app", d)
			if err := os.WriteFile(p, mangle(body), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				for _, reference := range []string{d.String(), "v1"} {
					logs.Reset()
					w := f.do(method, "/v2/app/manifests/"+reference, nil)
					if w.Code != http.StatusInternalServerError {
						t.Fatalf("%s %s: status %d, want 500; body %s", method, reference, w.Code, w.Body.String())
					}
					if method == http.MethodGet {
						want(t, w, http.StatusInternalServerError, codeUnavailable)
					} else if w.Body.Len() != 0 {
						t.Errorf("HEAD %s: body %q, want none", reference, w.Body.String())
					}
					if bytes.Contains(w.Body.Bytes(), body[:len(body)/2]) {
						t.Errorf("%s %s: the body carries the stored manifest bytes", method, reference)
					}
					if h := w.Header().Get("Docker-Content-Digest"); h != "" {
						t.Errorf("%s %s: Docker-Content-Digest %q, want none", method, reference, h)
					}
					var errorRecords int
					dec := json.NewDecoder(&logs)
					for dec.More() {
						var rec struct {
							Level string `json:"level"`
							Code  string `json:"code"`
							Err   string `json:"err"`
						}
						if err := dec.Decode(&rec); err != nil {
							t.Fatal(err)
						}
						if rec.Level == slog.LevelError.String() && rec.Code == codeUnavailable && strings.Contains(rec.Err, d.String()) {
							errorRecords++
						}
					}
					if errorRecords != 1 {
						t.Errorf("%s %s: %d Error records naming %s, want 1; logs %s", method, reference, errorRecords, d, logs.String())
					}
				}
			}
		})
	}
}
