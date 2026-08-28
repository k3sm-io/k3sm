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

package images

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// goodManifest is the shape every negative case below mutates exactly one field of, so
// each case proves one rule rather than "something in here is wrong".
const goodManifest = `images:
  - name: buildkit
    upstream: docker.io/moby/buildkit:v1.2.3@sha256:1111111111111111111111111111111111111111111111111111111111111111
    mirror: ghcr.io/k3sm-io/mirror/buildkit@sha256:1111111111111111111111111111111111111111111111111111111111111111
    tag: v1.2.3
    platforms:
      - platform: linux/arm64
        digest: sha256:2222222222222222222222222222222222222222222222222222222222222222
      - platform: linux/amd64
        digest: sha256:3333333333333333333333333333333333333333333333333333333333333333
`

func writeManifest(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "mirror.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture manifest: %v", err)
	}
	return p
}

func TestLoadManifestSchema(t *testing.T) {
	tests := []struct {
		name string
		body string
		// wantErr is a substring of the expected failure; "" means the manifest
		// must LOAD, which is what keeps every negative case honest (they all
		// start from a body that is known-good).
		wantErr string
	}{
		{
			name: "the good manifest loads",
			body: goodManifest,
		},
		{
			name:    "empty manifest is rejected, not treated as trivially consistent",
			body:    "images: []\n",
			wantErr: "no images",
		},
		{
			name:    "unknown key is a schema error, not a silently ignored field",
			body:    strings.Replace(goodManifest, "    tag: v1.2.3", "    tagg: v1.2.3", 1),
			wantErr: "parse",
		},
		{
			name:    "missing name",
			body:    strings.Replace(goodManifest, "  - name: buildkit\n", "  - \n", 1),
			wantErr: "name is required",
		},
		{
			name:    "missing tag — an untagged digest can be garbage-collected",
			body:    strings.Replace(goodManifest, "    tag: v1.2.3\n", "", 1),
			wantErr: "tag is required",
		},
		{
			name: "upstream not digest-pinned",
			body: strings.Replace(goodManifest,
				"upstream: docker.io/moby/buildkit:v1.2.3@sha256:1111111111111111111111111111111111111111111111111111111111111111",
				"upstream: docker.io/moby/buildkit:v1.2.3", 1),
			wantErr: "not digest-pinned",
		},
		{
			name: "upstream digest-only, no tag",
			body: strings.Replace(goodManifest,
				"upstream: docker.io/moby/buildkit:v1.2.3@sha256:",
				"upstream: docker.io/moby/buildkit@sha256:", 1),
			wantErr: "must carry its release tag",
		},
		{
			name: "mirror outside the k3sm mirror namespace",
			body: strings.Replace(goodManifest,
				"mirror: ghcr.io/k3sm-io/mirror/buildkit@",
				"mirror: docker.io/moby/buildkit@", 1),
			wantErr: "must start with",
		},
		{
			name: "upstream and mirror index digests diverge",
			body: strings.Replace(goodManifest,
				"mirror: ghcr.io/k3sm-io/mirror/buildkit@sha256:1111111111111111111111111111111111111111111111111111111111111111",
				"mirror: ghcr.io/k3sm-io/mirror/buildkit@sha256:4444444444444444444444444444444444444444444444444444444444444444", 1),
			wantErr: "!= mirror digest",
		},
		{
			name:    "uppercase hex digest is not canonical",
			body:    strings.Replace(goodManifest, "sha256:2222", "sha256:AAAA", 1),
			wantErr: "not a canonical sha256 digest",
		},
		{
			name:    "truncated digest",
			body:    strings.Replace(goodManifest, "sha256:2222222222222222222222222222222222222222222222222222222222222222", "sha256:2222", 1),
			wantErr: "not a canonical sha256 digest",
		},
		{
			name: "no platforms",
			body: strings.Replace(goodManifest, `    platforms:
      - platform: linux/arm64
        digest: sha256:2222222222222222222222222222222222222222222222222222222222222222
      - platform: linux/amd64
        digest: sha256:3333333333333333333333333333333333333333333333333333333333333333
`, "    platforms: []\n", 1),
			wantErr: "at least one platform",
		},
		{
			name: "buildkit missing linux/amd64 — the translated path would break at run time",
			body: strings.Replace(goodManifest, `      - platform: linux/amd64
        digest: sha256:3333333333333333333333333333333333333333333333333333333333333333
`, "", 1),
			wantErr: "required platform linux/amd64 is missing",
		},
		{
			name: "buildkit missing linux/arm64 — the native path would break at run time",
			body: strings.Replace(goodManifest, `      - platform: linux/arm64
        digest: sha256:2222222222222222222222222222222222222222222222222222222222222222
`, "", 1),
			wantErr: "required platform linux/arm64 is missing",
		},
		{
			name:    "duplicate platform",
			body:    strings.Replace(goodManifest, "platform: linux/amd64", "platform: linux/arm64", 1),
			wantErr: "duplicate platform",
		},
		{
			name:    "malformed platform string",
			body:    strings.Replace(goodManifest, "platform: linux/arm64", "platform: arm64", 1),
			wantErr: "must be os/arch",
		},
		{
			name: "a platform digest equal to the index digest is a copy-paste, not a platform",
			body: strings.Replace(goodManifest,
				"digest: sha256:2222222222222222222222222222222222222222222222222222222222222222",
				"digest: sha256:1111111111111111111111111111111111111111111111111111111111111111", 1),
			wantErr: "equals the index digest",
		},
		{
			name:    "duplicate entry name",
			body:    goodManifest + strings.TrimPrefix(goodManifest, "images:\n"),
			wantErr: "duplicate name",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadManifest(writeManifest(t, tc.body))
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("want load, got error: %v", err)
			case tc.wantErr == "":
				return
			case err == nil:
				t.Fatalf("want error containing %q, got nil", tc.wantErr)
			case !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("want error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

func TestLoadManifestMissingFile(t *testing.T) {
	_, err := LoadManifest(filepath.Join(t.TempDir(), "absent.yaml"))
	if err == nil {
		t.Fatal("want an error for an absent manifest, got nil")
	}
	if !strings.Contains(err.Error(), "read") {
		t.Fatalf("want a read error, got: %v", err)
	}
}
