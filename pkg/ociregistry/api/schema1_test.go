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
	"testing"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// TestPutManifestRejectsDockerSchema1 pins that the server stores no Docker
// schema1 manifest: not under its own media types, which are not on the
// allowlist, and not as a schema1 body under an allowed type, which fails the
// schemaVersion check. The garbage collector relies on this, since it cannot
// follow a schema1 body's fsLayers.
func TestPutManifestRejectsDockerSchema1(t *testing.T) {
	f := newFixture(t)
	layer := f.pushBlob(t, "app", []byte("schema1 layer"))
	body := []byte(`{"schemaVersion":1,"name":"app","tag":"v1","architecture":"arm64","fsLayers":[{"blobSum":"` + layer.String() + `"}],"history":[{"v1Compatibility":"{}"}]}`)
	for _, tc := range []struct {
		mediaType string
		status    int
	}{
		{"application/vnd.docker.distribution.manifest.v1+json", http.StatusUnsupportedMediaType},
		{"application/vnd.docker.distribution.manifest.v1+prettyjws", http.StatusUnsupportedMediaType},
		{mediaTypeDockerManifest, http.StatusBadRequest},
		{ispec.MediaTypeImageManifest, http.StatusBadRequest},
	} {
		t.Run(tc.mediaType, func(t *testing.T) {
			want(t, f.pushManifest(t, "app", "v1", tc.mediaType, body), tc.status, codeManifestInvalid)
			want(t, f.pushManifest(t, "app", dg(body).String(), tc.mediaType, body), tc.status, codeManifestInvalid)
		})
	}
	want(t, f.do(http.MethodGet, "/v2/app/manifests/v1", nil), http.StatusNotFound, "")
	want(t, f.do(http.MethodGet, "/v2/app/manifests/"+dg(body).String(), nil), http.StatusNotFound, "")
}
