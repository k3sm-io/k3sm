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

package registryclient_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/registryclient"
	"k3sm.io/k3sm/pkg/registryclient/registrytest"
)

// storeAt stores body under its digest with mediaType and returns the digest.
func storeAt(reg *registrytest.Registry, repository, mediaType string, body []byte) string {
	sum := sha256.Sum256(body)
	d := "sha256:" + hex.EncodeToString(sum[:])
	reg.StoreManifestAt(repository, d, mediaType, body)
	return d
}

// TestManifestIndexBoundedRefusesALargeIndexBeforeDecoding: a body over the
// index limit is refused with ErrIndexTooLarge when it is served as an
// index, or with no type at all, even when it is not valid JSON (so it was
// never decoded); a large body served as a single manifest is read as
// Manifest reads it; and an index within the limit is read.
func TestManifestIndexBoundedRefusesALargeIndexBeforeDecoding(t *testing.T) {
	const limit = 1024
	reg := registrytest.New()
	c := newClient(t, reg.Handler(), registryclient.Options{})
	ctx := context.Background()

	garbage := []byte("{" + strings.Repeat("x", 2*limit))
	for _, mt := range []string{registryclient.MediaTypeOCIIndex, ""} {
		d := storeAt(reg, "models/m", mt, garbage)
		if _, err := c.ManifestIndexBounded(ctx, "models/m", d, limit); !errors.Is(err, registryclient.ErrIndexTooLarge) {
			t.Errorf("served as %q: err = %v, want ErrIndexTooLarge", mt, err)
		}
	}

	big, _ := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": registryclient.MediaTypeOCIManifest,
		"config":      map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:" + strings.Repeat("a", 64), "size": 2},
		"layers":      []any{},
		"annotations": map[string]string{"pad": strings.Repeat("p", 2*limit)},
	})
	d := storeAt(reg, "models/m", registryclient.MediaTypeOCIManifest, big)
	if m, err := c.ManifestIndexBounded(ctx, "models/m", d, limit); err != nil || m.Digest != d || m.IsIndex() {
		t.Errorf("large single manifest = %+v, %v; want it read", m.Digest, err)
	}

	small, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": registryclient.MediaTypeOCIIndex, "manifests": []any{}})
	d = storeAt(reg, "models/m", registryclient.MediaTypeOCIIndex, small)
	if m, err := c.ManifestIndexBounded(ctx, "models/m", d, limit); err != nil || !m.IsIndex() {
		t.Errorf("small index = %+v, %v; want it read", m, err)
	}
}
