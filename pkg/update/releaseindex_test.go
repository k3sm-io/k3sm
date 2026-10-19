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

package update

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const releaseIndexDir = "testdata/release-index"

func readReleaseIndexFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(releaseIndexDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestReleaseIndexSchemaGolden pins the k3sm-release-index/v1 contract the app
// vendors: the golden document decodes and re-encodes to the same bytes (so a
// field added, dropped or reordered is a visible change here), every red
// fixture is refused for its own reason, and the host pin fixture is exactly
// AllowedHosts.
func TestReleaseIndexSchemaGolden(t *testing.T) {
	golden := readReleaseIndexFixture(t, "index.json")
	ix, err := ParseReleaseIndex(golden)
	if err != nil {
		t.Fatalf("the golden index is refused: %v", err)
	}
	if ix.Schema != ReleaseIndexSchema || ix.Context != ReleaseIndexContext || ix.Tag != "v0.2.0" ||
		ix.App.ShortVersion != "0.2.0" || ix.App.Image.Size != 123456789 ||
		ix.K3sm.Archive != "k3sm_0.2.0_darwin_arm64.tar.gz" {
		t.Errorf("the golden index decoded to %+v", ix)
	}
	again, err := json.MarshalIndent(ix, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(append(again, '\n'), golden) {
		t.Errorf("the golden index does not re-encode to its own bytes; the schema and the fixture disagree:\n%s", again)
	}

	t.Run("red fixtures", func(t *testing.T) {
		for _, tc := range []struct{ file, reason string }{
			{"red-unknown-field.json", `unknown field "channel"`},
			{"red-foreign-host.json", `"example.com" is not one of`},
			{"red-rc-tag.json", "not a final release tag"},
		} {
			t.Run(tc.file, func(t *testing.T) {
				_, err := ParseReleaseIndex(readReleaseIndexFixture(t, tc.file))
				if !errors.Is(err, ErrReleaseIndex) || !strings.Contains(err.Error(), tc.reason) {
					t.Errorf("got %v, want ErrReleaseIndex naming %q", err, tc.reason)
				}
			})
		}
	})

	t.Run("oversized", func(t *testing.T) {
		// Valid JSON padded past the cap with whitespace: refused on size,
		// before the decoder runs.
		raw := append(bytes.Repeat([]byte(" "), MaxReleaseIndexBytes+1-len(golden)), golden...)
		_, err := ParseReleaseIndex(raw)
		if !errors.Is(err, ErrReleaseIndex) || !strings.Contains(err.Error(), "byte cap") {
			t.Errorf("got %v, want the size cap", err)
		}
		if _, err := ParseReleaseIndex(raw[1:]); err != nil {
			t.Errorf("a document of exactly %d bytes is refused: %v", MaxReleaseIndexBytes, err)
		}
	})

	t.Run("host pins", func(t *testing.T) {
		want, err := json.MarshalIndent(AllowedHosts, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if got := readReleaseIndexFixture(t, "allowed-hosts.json"); !bytes.Equal(got, append(want, '\n')) {
			t.Errorf("allowed-hosts.json is\n%s\nbut AllowedHosts encodes as\n%s", got, want)
		}
	})
}

// TestParseReleaseIndexRefuses mutates the golden document one field at a time.
func TestParseReleaseIndexRefuses(t *testing.T) {
	golden := string(readReleaseIndexFixture(t, "index.json"))
	for _, tc := range []struct{ name, from, to string }{
		{"schema v2", `"k3sm-release-index/v1"`, `"k3sm-release-index/v2"`},
		{"other context", `"io.k3sm.release-index/v1"`, `"io.k3sm.other/v1"`},
		{"no context", `"context": "io.k3sm.release-index/v1",`, ``},
		{"build metadata tag", `"tag": "v0.2.0"`, `"tag": "v0.2.0+x"`},
		{"tag without v", `"tag": "v0.2.0"`, `"tag": "0.2.0"`},
		{"tag leading zero", `"tag": "v0.2.0"`, `"tag": "v0.02.0"`},
		{"issuedAt with offset", `2026-11-02T18:04:11Z`, `2026-11-02T18:04:11+01:00`},
		{"issuedAt fractional", `2026-11-02T18:04:11Z`, `2026-11-02T18:04:11.5Z`},
		{"issuedAt impossible date", `2026-11-02T18:04:11Z`, `2026-02-30T18:04:11Z`},
		{"minimumMacOS word", `"26.0"`, `"Tahoe"`},
		{"minimumMacOS four parts", `"26.0"`, `"26.0.0.1"`},
		{"other bundle id", `"io.k3sm.app"`, `"io.k3sm.app2"`},
		{"shortVersion mismatch", `"shortVersion": "0.2.0"`, `"shortVersion": "0.2.1"`},
		{"image name mismatch", `"name": "k3sm_0.2.0_darwin_arm64.dmg"`, `"name": "k3sm_0.2.0_darwin_amd64.dmg"`},
		{"http url", `"url": "https://github.com/`, `"url": "http://github.com/`},
		{"url with user", `"url": "https://github.com/`, `"url": "https://u@github.com/`},
		{"url with port", `"url": "https://github.com/`, `"url": "https://github.com:8443/`},
		{"url with query", `k3sm_0.2.0_darwin_arm64.dmg",
      "sha256"`, `k3sm_0.2.0_darwin_arm64.dmg?x=1",
      "sha256"`},
		{"url another asset", `/v0.2.0/k3sm_0.2.0_darwin_arm64.dmg"`, `/v0.2.0/other.dmg"`},
		{"image sha too long", `"sha256": "`, `"sha256": "A`},
		{"zero size", `123456789`, `0`},
		{"negative size", `123456789`, `-1`},
		{"oversized image", `123456789`, `536870913`},
		{"archive mismatch", `"k3sm_0.2.0_darwin_arm64.tar.gz"`, `"k3sm_0.1.0_darwin_arm64.tar.gz"`},
		{"short archive sha", `"archiveSHA256": "`, `"archiveSHA256": "ab`},
		{"missing payload manifest", `"payloadManifestSHA256": `, `"x": `},
		{"second value", golden, golden + "{}\n"},
		{"null document", golden, "null"},
		{"duplicated key overrides", `"tag": "v0.2.0",`, `"tag": "v0.2.0", "tag": "v0.2.0-rc.1",`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mut := strings.Replace(golden, tc.from, tc.to, 1)
			if mut == golden {
				t.Fatalf("the mutation %q matched nothing", tc.from)
			}
			if _, err := ParseReleaseIndex([]byte(mut)); !errors.Is(err, ErrReleaseIndex) {
				t.Errorf("got %v, want ErrReleaseIndex", err)
			}
		})
	}
}
