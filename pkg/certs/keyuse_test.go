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

package certs_test

import (
	"encoding/json"
	"strings"
	"testing"

	updatesv1alpha1 "k3sm.io/apis/updates/v1alpha1"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/update"
)

// TestManifestAndPayloadDecodersAreDisjoint pins the property the update
// signer's one key rests on while both of its signatures cover a bare sha256
// of the signed bytes (see UpdateSigner.SignManifest): a payload annotation
// never parses as a payload manifest, and a payload manifest never parses as
// a payload annotation, so a signature over one cannot be replayed as the
// other.
func TestManifestAndPayloadDecodersAreDisjoint(t *testing.T) {
	const sum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	payload, err := update.EncodePayload(update.Payload{
		Version: "v0.3.0", URL: "https://github.com/k3sm-io/k3sm/releases/download/v0.3.0/k3sm_0.3.0_darwin_arm64.tar.gz",
		SHA256: sum, Signature: updatesv1alpha1.UpdateSignatureRequired, AllowDowngrade: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := json.Marshal(certs.PayloadManifest{
		Version: "v0.3.0", KubeMinor: "1.35", CompatibleFrom: "v0.2.0", RequiresInstaller: true, ArchiveSHA256: sum,
		Members: []certs.PayloadMember{{Path: "LICENSE", SHA256: sum, Kind: certs.PayloadData}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Each is accepted by its own decoder, so the refusals below are not a
	// fixture that neither decoder would take.
	if _, err := update.ParsePayload(string(payload)); err != nil {
		t.Fatalf("the payload fixture is refused by its own decoder: %v", err)
	}
	if _, err := certs.ParsePayloadManifest(manifest); err != nil {
		t.Fatalf("the manifest fixture is refused by its own decoder: %v", err)
	}

	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"a payload annotation", string(payload)},
		{"a minimal payload annotation", `{"version":"v0.3.0","url":"","sha256":"` + sum + `","signature":""}`},
		{"the keys the two share, alone", `{"version":"v0.3.0"}`},
	} {
		t.Run("the manifest decoder refuses "+tc.name, func(t *testing.T) {
			if _, err := certs.ParsePayloadManifest([]byte(tc.raw)); err == nil {
				t.Fatalf("ParsePayloadManifest accepted %s", tc.raw)
			}
		})
	}
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"a payload manifest", string(manifest)},
		{"a manifest's keys over a payload's", strings.TrimSuffix(string(payload), "}") + `,"members":[]}`},
	} {
		t.Run("the payload decoder refuses "+tc.name, func(t *testing.T) {
			if _, err := update.ParsePayload(tc.raw); err == nil {
				t.Fatalf("ParsePayload accepted %s", tc.raw)
			}
		})
	}
}
