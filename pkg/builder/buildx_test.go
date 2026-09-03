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

package builder

import (
	"strings"
	"testing"
)

// TestBuildxPinIsWellFormed pins the compiled-in buildx pin: it must always
// validate, and its URL must name the version and the asset. A malformed bump is
// caught here, not by a pod that fetches an unverifiable binary an hour into a
// build.
func TestBuildxPinIsWellFormed(t *testing.T) {
	t.Run("compiled_pin_validates", func(t *testing.T) {
		if err := ValidateBuildxPin(); err != nil {
			t.Fatalf("compiled buildx pin is invalid: %v", err)
		}
	})
	t.Run("url_names_version_and_asset", func(t *testing.T) {
		u := BuildxURL()
		if !strings.Contains(u, BuildxVersion) {
			t.Errorf("BuildxURL()=%q does not contain version %q", u, BuildxVersion)
		}
		if !strings.HasSuffix(u, BuildxAsset) {
			t.Errorf("BuildxURL()=%q does not end in asset %q", u, BuildxAsset)
		}
	})
	t.Run("asset_is_guest_arch_arm64", func(t *testing.T) {
		if !strings.HasSuffix(BuildxAsset, ".linux-arm64") {
			t.Errorf("BuildxAsset=%q must be linux-arm64 (buildx matches the GUEST arch)", BuildxAsset)
		}
	})
}

// TestValidatePin exercises the pure validation core across well-formed and
// malformed pins, on both the guest (linux-arm64) and host (darwin-arm64) axes —
// the platform argument is what stops a bump from pinning one arch's asset name
// against the other arch's digest.
func TestValidatePin(t *testing.T) {
	good := "de05dccd47932eb9fd6e63781ab29d2b0b2c834bbdd19b51d7ea452b1fe378d3"
	cases := []struct {
		name     string
		version  string
		asset    string
		sha      string
		platform string
		wantErr  bool
	}{
		{"valid", "v0.17.1", "buildx-v0.17.1.linux-arm64", good, "linux-arm64", false},
		{"valid host", "v0.17.1", "buildx-v0.17.1.darwin-arm64", good, "darwin-arm64", false},
		{"empty version", "", "buildx-.linux-arm64", good, "linux-arm64", true},
		{"short sha", "v0.17.1", "buildx-v0.17.1.linux-arm64", "abcd", "linux-arm64", true},
		{"uppercase sha", "v0.17.1", "buildx-v0.17.1.linux-arm64", strings.ToUpper(good), "linux-arm64", true},
		{"asset version mismatch", "v0.17.1", "buildx-v0.16.0.linux-arm64", good, "linux-arm64", true},
		{"asset wrong arch", "v0.17.1", "buildx-v0.17.1.linux-amd64", good, "linux-arm64", true},
		{"guest asset under host platform", "v0.17.1", "buildx-v0.17.1.linux-arm64", good, "darwin-arm64", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePin(tc.version, tc.asset, tc.sha, tc.platform)
			if tc.wantErr != (err != nil) {
				t.Fatalf("validatePin(%q,%q,%q,%q) err=%v, wantErr=%v", tc.version, tc.asset, tc.sha, tc.platform, err, tc.wantErr)
			}
		})
	}
}
