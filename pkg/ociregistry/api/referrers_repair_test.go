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
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// TestReferrersRecoverAfterCorruptManifestRepair: a referrer whose blob is
// corrupted drops out of the referrers list, and comes back once the blob is
// repaired on disk, though index.json never changed.
func TestReferrersRecoverAfterCorruptManifestRepair(t *testing.T) {
	f := newFixture(t)
	subject := f.image(t, "app", "v1", "layer")
	sd := dg(subject)
	cfg := f.pushBlob(t, "app", []byte("cfg"))
	m := ispec.Manifest{
		MediaType: ispec.MediaTypeImageManifest, ArtifactType: "application/vnd.example.sig",
		Config:  ispec.Descriptor{MediaType: ispec.MediaTypeEmptyJSON, Digest: cfg, Size: 3},
		Layers:  []ispec.Descriptor{},
		Subject: &ispec.Descriptor{MediaType: ispec.MediaTypeImageManifest, Digest: sd, Size: int64(len(subject))},
	}
	m.SchemaVersion = 2
	sig, _ := json.Marshal(m)
	gd := dg(sig)
	if w := f.pushManifest(t, "app", gd.String(), ispec.MediaTypeImageManifest, sig); w.Code != http.StatusCreated {
		t.Fatalf("push referrer: %d %s", w.Code, w.Body.String())
	}
	list := func() string {
		w := f.do(http.MethodGet, "/v2/app/referrers/"+sd.String(), nil)
		if w.Code != http.StatusOK {
			t.Fatalf("referrers: %d %s", w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	if !strings.Contains(list(), gd.String()) {
		t.Fatal("referrer missing before corruption")
	}
	p := f.blobFile("app", gd)
	if err := os.WriteFile(p, sig[:len(sig)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	// A fresh view reads the corrupt blob; the cached one would still list it.
	f.srv.refs = newReferrerCache()
	if got := list(); strings.Contains(got, gd.String()) {
		t.Fatalf("corrupt referrer listed: %s", got)
	}
	if err := os.WriteFile(p, sig, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := list(); !strings.Contains(got, gd.String()) {
		t.Fatalf("repaired referrer still omitted: %s", got)
	}
}
