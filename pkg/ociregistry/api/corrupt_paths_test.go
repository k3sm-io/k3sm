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
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
)

// TestMountOfCorruptSourceAnswers5xxNoDigestHeader: a cross-repository mount
// whose stored source fails its digest is a storage fault, not a request
// fault: 500 UNAVAILABLE, no Docker-Content-Digest, and the destination keeps
// what it had. The source is hashed when the destination already holds another
// inode for the digest (a fresh mount trusts the stored blob as it stands).
func TestMountOfCorruptSourceAnswers5xxNoDigestHeader(t *testing.T) {
	f := newFixture(t)
	d := f.pushBlob(t, "src", []byte("shared blob body"))
	if err := os.WriteFile(f.blobFile("src", d), []byte("shared blob bodY"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.pushBlob(t, "dst", []byte("shared blob body"))
	if err := os.WriteFile(f.blobFile("dst", d), []byte("shared blob bodZ"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := f.do(http.MethodPost, "/v2/dst/blobs/uploads/?mount="+d.String()+"&from=src", nil)
	want(t, w, http.StatusInternalServerError, codeUnavailable)
	if h := w.Header().Get("Docker-Content-Digest"); h != "" {
		t.Errorf("Docker-Content-Digest %q, want none", h)
	}
	a, _ := os.Stat(f.blobFile("src", d))
	b, _ := os.Stat(f.blobFile("dst", d))
	if os.SameFile(a, b) {
		t.Error("the corrupt source replaced the destination blob")
	}
}

// TestReferrersScanClassesCorruptManifestPermanent: a corrupt manifest is
// omitted from a whole (200) answer and not read again while index.json is
// unchanged, rather than answering busy for ever.
func TestReferrersScanClassesCorruptManifestPermanent(t *testing.T) {
	f := newFixture(t)
	subject := f.image(t, "app", "v1", "l")
	good, bad := referrerBody(subject, "application/vnd.example.sig", 1), referrerBody(subject, "application/vnd.example.sig", 2)
	f.addRows(t, "app", [][]byte{good, bad})
	if err := os.WriteFile(f.blobFile("app", dg(bad)), bad[:len(bad)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	reads := map[digest.Digest]int{}
	f.srv.referrerRead = func(d digest.Digest) { reads[d]++ }
	path := "/v2/app/referrers/" + dg(subject).String()
	for i := range 2 {
		w := f.do(http.MethodGet, path, nil)
		want(t, w, http.StatusOK, "")
		if i == 0 && !strings.Contains(w.Body.String(), dg(good).String()) {
			t.Fatalf("the intact referrer is missing: %s", w.Body.String())
		}
		if strings.Contains(w.Body.String(), dg(bad).String()) {
			t.Fatalf("request %d lists the corrupt manifest", i)
		}
	}
	if reads[dg(bad)] != 1 {
		t.Errorf("the corrupt manifest was read %d times, want 1", reads[dg(bad)])
	}
}
