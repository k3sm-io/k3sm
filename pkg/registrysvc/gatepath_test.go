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

package registrysvc

import (
	"net/url"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// TestClassify pins the classifier row by row: the write shapes it admits and
// the repository it reads out of each, and the spellings it refuses.
func TestClassify(t *testing.T) {
	for _, tc := range classifyCorpus() {
		t.Run(tc.method+" "+tc.path+"?"+tc.query, func(t *testing.T) {
			r := classify(tc.method, tc.path, tc.query)
			if r.op != tc.op {
				t.Fatalf("op = %s, want %s", r.op, tc.op)
			}
			if !r.op.isWrite() {
				return
			}
			if r.repo != tc.repo || r.from != tc.from || r.query != tc.fwdQuery || r.path != tc.path {
				t.Errorf("route = %+v, want repo %q from %q query %q path %q", r, tc.repo, tc.from, tc.fwdQuery, tc.path)
			}
		})
	}
}

// classifyCase is one row of the classifier's corpus.
type classifyCase struct {
	method, path, query string
	op                  gateOp
	repo, from          string
	fwdQuery            string
}

// classifyCorpus is the classifier's corpus, also fed to the registry server by
// TestGateAndServerAgree.
func classifyCorpus() []classifyCase {
	d := "sha256:" + strings.Repeat("a", 64)
	return []classifyCase{
		{"GET", "/v2/", "", opRead, "", "", ""},
		{"GET", "/v2/_catalog", "n=10", opRead, "", "", ""},
		{"HEAD", "/v2/a/b/manifests/v1", "", opRead, "", "", ""},
		{"GET", "/v2/a/blobs/" + d, "", opRead, "", "", ""},
		{"GET", "/v2/a/blobs/uploads/u-1", "", opUploadStatus, "a", "", ""},
		{"GET", "/v2/a/blobs/uploads/u-1", "_state=abc", opUploadStatus, "a", "", "_state=abc"},
		{"GET", "/v2/a/blobs//uploads/u-1", "", opInvalid, "", "", ""},
		{"GET", "/v2/a/blobs/x/../uploads/u", "", opInvalid, "", "", ""},
		{"GET", "/v2/a/Blobs/Uploads/u", "", opInvalid, "", "", ""},
		{"GET", `/v2/a/blobs\uploads/u`, "", opInvalid, "", "", ""},
		{"POST", "/v2/a/b/blobs/uploads/", "", opUploadStart, "a/b", "", ""},
		{"POST", "/v2/a/blobs/uploads/", "digest=" + url.QueryEscape(d), opUploadStart, "a", "", "digest=" + url.QueryEscape(d)},
		{"POST", "/v2/a/blobs/uploads/", "mount=" + d + "&from=a/c", opUploadStart, "a", "a/c", "from=a%2Fc&mount=" + url.QueryEscape(d)},
		{"POST", "/v2/a/blobs/uploads/", "mount=" + d + "&from=a/c&digest=" + d, opInvalid, "", "", ""},
		{"POST", "/v2/a/blobs/uploads/", "mount=" + d, opInvalid, "", "", ""},
		{"POST", "/v2/a/blobs/uploads/", "from=a/c", opInvalid, "", "", ""},
		{"POST", "/v2/a/blobs/uploads/", "from=A/c&mount=" + d, opInvalid, "", "", ""},
		{"POST", "/v2/a/blobs/uploads/", "digest=sha256:short", opInvalid, "", "", ""},
		{"POST", "/v2/a/blobs/uploads/", "digest=", opInvalid, "", "", ""},
		{"POST", "/v2/a/blobs/uploads/", "digest", opInvalid, "", "", ""},
		{"POST", "/v2/a/blobs/uploads/", "&", opInvalid, "", "", ""},
		{"POST", "/v2/a/blobs/uploads", "", opRefused, "", "", ""},
		{"POST", "/v2/a/blobs/uploads/x", "", opRefused, "", "", ""},
		{"POST", "/v2/blobs/uploads/", "", opRefused, "", "", ""},
		{"POST", "/v3/a/blobs/uploads/", "", opRefused, "", "", ""},
		{"POST", "/v2/_zot/ext/mgmt", "", opRefused, "", "", ""},
		{"PATCH", "/v2/a/blobs/uploads/u-1", "", opUploadChunk, "a", "", ""},
		{"PATCH", "/v2/a/blobs/uploads/U-1", "", opInvalid, "", "", ""},
		{"PATCH", "/v2/a/manifests/v1", "", opRefused, "", "", ""},
		{"PUT", "/v2/a/blobs/uploads/u-1", "digest=" + d, opUploadFinish, "a", "", "digest=" + url.QueryEscape(d)},
		{"PUT", "/v2/a/blobs/uploads/u-1", "digest=" + d + "&_state=s", opUploadFinish, "a", "", "_state=s&digest=" + url.QueryEscape(d)},
		{"PUT", "/v2/a/b/c/manifests/latest", "", opManifestPut, "a/b/c", "", ""},
		{"PUT", "/v2/a/manifests/" + d, "", opManifestPut, "a", "", ""},
		{"PUT", "/v2/a/manifests/V1_RC", "", opManifestPut, "a", "", ""},
		{"PUT", "/v2/a/manifests/.v1", "", opInvalid, "", "", ""},
		{"PUT", "/v2/a/manifests/" + strings.Repeat("t", 129), "", opInvalid, "", "", ""},
		{"PUT", "/v2/a/manifests/v1", "x=1", opInvalid, "", "", ""},
		{"PUT", "/v2/a/tags/list", "", opRefused, "", "", ""},
		{"PUT", "/v2/a__b/c-d.e/manifests/v1", "", opManifestPut, "a__b/c-d.e", "", ""},
		{"PUT", "/v2/a___b/manifests/v1", "", opInvalid, "", "", ""},
		{"PUT", "/v2/a-/manifests/v1", "", opInvalid, "", "", ""},
		{"PUT", "/v2/a/uploads/manifests/v1", "", opManifestPut, "a/uploads", "", ""},
		{"PUT", "/v2/manifests/manifests/v1", "", opManifestPut, "manifests", "", ""},
		{"POST", "/v2/a/manifests/blobs/uploads/", "", opUploadStart, "a/manifests", "", ""},
		{"POST", "/v2/a/blobs/uploads/", "mount=" + d + "&from=a/uploads", opUploadStart, "a", "a/uploads", "from=a%2Fuploads&mount=" + url.QueryEscape(d)},
		{"PUT", "/v2/a/blobs/manifests/v1", "", opInvalid, "", "", ""},
		{"PUT", "/v2/index.json/manifests/v1", "", opInvalid, "", "", ""},
		{"PUT", "/v2/a/index.json/manifests/v1", "", opInvalid, "", "", ""},
		{"PUT", "/v2/oci-layout/b/manifests/v1", "", opInvalid, "", "", ""},
		{"PUT", "/v2/a/.uploads/manifests/v1", "", opInvalid, "", "", ""},
		{"PUT", "/v2/cache.db/manifests/v1", "", opInvalid, "", "", ""},
		{"PUT", "/v2/htpasswd/a/manifests/v1", "", opInvalid, "", "", ""},
		{"PUT", "/v2/a/htpasswd/manifests/v1", "", opManifestPut, "a/htpasswd", "", ""},
		{"POST", "/v2/a/blobs/uploads/", "mount=" + d + "&from=a/index.json", opInvalid, "", "", ""},
		{"POST", "/v2/index.json/blobs/uploads/", "", opInvalid, "", "", ""},
		{"PUT", "/v2/" + strings.Repeat("a", 256) + "/manifests/v1", "", opInvalid, "", "", ""},
		{"PUT", "/v2/a/%2e%2e/manifests/v1", "", opInvalid, "", "", ""},
		{"PUT", "/v2/a/manifests/v1\x00", "", opInvalid, "", "", ""},
		{"PUT", "/v2/a b/manifests/v1", "", opInvalid, "", "", ""},
		{"PUT", "/v2/a/manifests/v1/", "", opRefused, "", "", ""},
		{"DELETE", "/v2/a/manifests/v1", "", opRefused, "", "", ""},
		{"DELETE", "/v2/a/blobs/uploads/u-1", "", opRefused, "", "", ""},
		{"OPTIONS", "/v2/", "", opRefused, "", "", ""},
		{"CONNECT", "/v2/", "", opRefused, "", "", ""},
	}
}

// FuzzClassify asserts the classifier's invariants on arbitrary input: it never
// panics, every write it admits names a repository the shared validator accepts,
// forwards exactly the path it parsed, carries no byte
// that could be decoded or cleaned into another path, and re-parses to itself.
func FuzzClassify(f *testing.F) {
	d := "sha256:" + strings.Repeat("a", 64)
	for _, s := range [][3]string{
		{"POST", "/v2/a/blobs/uploads/", "mount=" + d + "&from=a/b"},
		{"PUT", "/v2/a/manifests/v1", ""},
		{"PATCH", "/v2/a/b/blobs/uploads/x", "_state=q"},
		{"GET", "/v2/a/blobs/%75ploads/x", ""},
		{"PUT", "/v2/a/../b/manifests/v1", ""},
		{"DELETE", "/v2/a/manifests/v1", ""},
		{"PUT", "/v2/a/index.json/manifests/v1", ""},
		{"PUT", "/v2/a/uploads/manifests/v1", ""},
		{"POST", "/v2/a/blobs/uploads/", "mount=" + d + "&from=%61"},
	} {
		f.Add(s[0], s[1], s[2])
	}
	f.Fuzz(func(t *testing.T, method, path, query string) {
		r := classify(method, path, query)
		if r.op == opRead && onUploadPath(path) {
			t.Fatalf("an upload path was classified as an anonymous read: %q", path)
		}
		if !r.op.isWrite() {
			return
		}
		if method == "DELETE" {
			t.Fatalf("DELETE classified as %s", r.op)
		}
		if _, err := ref.ParseName(r.repo); err != nil || r.path != path || !cleanPath(r.path) {
			t.Fatalf("admitted %q as %+v: %v", path, r, err)
		}
		if dec, err := url.PathUnescape(r.path); err != nil || dec != r.path {
			t.Fatalf("admitted a path that decodes differently: %q", r.path)
		}
		if r.from != "" {
			if _, err := ref.ParseName(r.from); err != nil {
				t.Fatalf("admitted a mount source %q: %v", r.from, err)
			}
		}
		if again := classify(method, r.path, r.query); again != r {
			t.Fatalf("the forwarded request re-classifies as %+v, want %+v", again, r)
		}
	})
}

// isWrite reports whether op must be authenticated and authorized.
func (o gateOp) isWrite() bool { return o >= opUploadStart }
