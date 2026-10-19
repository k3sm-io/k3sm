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
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const releaseIndexDir = "testdata/release-index"

var updateReleaseIndexReds = flag.Bool("update-release-index", false, "rewrite testdata/release-index/red-*.json from releaseIndexReds")

func readReleaseIndexFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(releaseIndexDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// replace is a mutation that swaps the first from for to, and fails the test
// when from is absent so a stale mutation cannot pass vacuously.
func replace(from, to string) func(t *testing.T, s string) string {
	return func(t *testing.T, s string) string {
		t.Helper()
		if !strings.Contains(s, from) {
			t.Fatalf("the mutation %q matched nothing", from)
		}
		return strings.Replace(s, from, to, 1)
	}
}

func appendText(tail string) func(t *testing.T, s string) string {
	return func(_ *testing.T, s string) string { return s + tail }
}

const (
	goldenImageSHA = `"sha256": "6105d6cc76af400325e94d588ce511be5bfdbb73b437dc51eca43917d7a43e3d"`
	goldenURL      = `"https://github.com/k3sm-io/k3sm/releases/download/v0.2.0/k3sm_0.2.0_darwin_arm64.dmg"`
)

// releaseIndexReds is the refusal corpus: each entry is one change to the
// golden document, committed as testdata/release-index/red-<name>.json so the
// app's decoder runs the same set, and the reason the refusal must name.
var releaseIndexReds = []struct {
	name   string
	mutate func(t *testing.T, s string) string
	reason string
}{
	{"unknown-field", replace(`"minimumMacOS": "26.0",`, `"minimumMacOS": "26.0",`+"\n"+`  "channel": "stable",`), `unknown key "channel"`},
	{"case-variant-key", replace(`"tag": "v0.2.0"`, `"Tag": "v0.2.0"`), `unknown key "Tag"`},
	{"case-variant-duplicate", replace(`"tag": "v0.2.0",`, `"tag": "v0.2.0", "TAG": "v0.2.1",`), `unknown key "TAG"`},
	{"case-variant-nested-key", replace(`"bundleID"`, `"bundleId"`), `unknown key "bundleId"`},
	{"duplicate-key", replace(`"tag": "v0.2.0",`, `"tag": "v0.2.0", "tag": "v0.2.0",`), `duplicate key "tag"`},
	{"duplicate-nested-sha256", replace(goldenImageSHA, `"sha256": "`+strings.Repeat("0", 64)+`", `+goldenImageSHA), `duplicate key "sha256"`},
	{"array-value", replace(`"minimumMacOS": "26.0"`, `"minimumMacOS": ["26.0"]`), "holds an array"},
	{"not-an-object", func(*testing.T, string) string { return "[]\n" }, "not a JSON object"},
	{"null-document", func(*testing.T, string) string { return "null\n" }, "not a JSON object"},
	{"trailing-garbage", appendText("garbage\n"), "trailing data"},
	{"trailing-brace", appendText("}\n"), "trailing data"},
	{"second-value", appendText("{}\n"), "trailing data"},
	{"truncated", func(_ *testing.T, s string) string { return s[:len(s)/2] }, "not a valid document"},
	{"schema-v2", replace(`"k3sm-release-index/v1"`, `"k3sm-release-index/v2"`), "schema is not"},
	{"other-context", replace(`"io.k3sm.release-index/v1"`, `"io.k3sm.other/v1"`), "context is not"},
	{"no-context", replace(`"context": "io.k3sm.release-index/v1",`, ``), "context is not"},
	{"rc-tag", func(t *testing.T, s string) string {
		s = strings.ReplaceAll(s, "v0.2.0", "v0.2.0-rc.1")
		s = strings.ReplaceAll(s, "0.2.0_darwin", "0.2.0-rc.1_darwin")
		return replace(`"shortVersion": "0.2.0"`, `"shortVersion": "0.2.0-rc.1"`)(t, s)
	}, "not a final release tag"},
	{"build-metadata-tag", replace(`"tag": "v0.2.0"`, `"tag": "v0.2.0+x"`), "not a final release tag"},
	{"tag-without-v", replace(`"tag": "v0.2.0"`, `"tag": "0.2.0"`), "not a final release tag"},
	{"tag-leading-zero", replace(`"tag": "v0.2.0"`, `"tag": "v0.02.0"`), "not a final release tag"},
	{"issued-at-offset", replace(`2026-11-02T18:04:11Z`, `2026-11-02T18:04:11+01:00`), "issuedAt is not"},
	{"issued-at-fractional", replace(`2026-11-02T18:04:11Z`, `2026-11-02T18:04:11.5Z`), "issuedAt is not"},
	{"issued-at-impossible-date", replace(`2026-11-02T18:04:11Z`, `2026-02-30T18:04:11Z`), "issuedAt is not"},
	{"minimum-macos-word", replace(`"26.0"`, `"Tahoe"`), "minimumMacOS is not"},
	{"minimum-macos-four-parts", replace(`"26.0"`, `"26.0.0.1"`), "minimumMacOS is not"},
	{"other-bundle-id", replace(`"io.k3sm.app"`, `"io.k3sm.app2"`), "bundleID is not"},
	{"short-version-mismatch", replace(`"shortVersion": "0.2.0"`, `"shortVersion": "0.2.1"`), "shortVersion is not"},
	{"image-name-mismatch", replace(`"name": "k3sm_0.2.0_darwin_arm64.dmg"`, `"name": "k3sm_0.2.0_darwin_amd64.dmg"`), "image name is not"},
	{"foreign-host", replace(`https://github.com/`, `https://example.com/`), "image url is not"},
	{"redirect-host-as-url", replace(`https://github.com/`, `https://objects.githubusercontent.com/`), "image url is not"},
	{"uppercase-host", replace(`https://github.com/`, `https://GitHub.com/`), "image url is not"},
	{"foreign-repo", replace(`github.com/k3sm-io/k3sm/`, `github.com/someone/k3sm/`), "image url is not"},
	{"url-other-tag", replace(`/download/v0.2.0/`, `/download/v0.1.0/`), "image url is not"},
	{"url-dot-dot", replace(`/download/v0.2.0/`, `/download/v0.1.0/../v0.2.0/`), "image url is not"},
	{"url-port-443", replace(`https://github.com/`, `https://github.com:443/`), "image url is not"},
	{"url-empty-port", replace(`https://github.com/`, `https://github.com:/`), "image url is not"},
	{"url-http", replace(`https://github.com/`, `http://github.com/`), "image url is not"},
	{"url-user", replace(`https://github.com/`, `https://u@github.com/`), "image url is not"},
	{"url-query", replace(goldenURL, strings.TrimSuffix(goldenURL, `"`)+`?x=1"`), "image url is not"},
	{"url-fragment", replace(goldenURL, strings.TrimSuffix(goldenURL, `"`)+`#x"`), "image url is not"},
	{"url-other-asset", replace(`/v0.2.0/k3sm_0.2.0_darwin_arm64.dmg"`, `/v0.2.0/other.dmg"`), "image url is not"},
	{"image-sha-too-long", replace(`"sha256": "`, `"sha256": "a`), "image sha256 is not"},
	{"image-sha-uppercase", replace(`"sha256": "6105d6cc`, `"sha256": "6105D6CC`), "image sha256 is not"},
	{"image-zero-size", replace(`123456789`, `0`), "image size 0 is outside"},
	{"image-negative-size", replace(`123456789`, `-1`), "image size -1 is outside"},
	{"image-oversized", replace(`123456789`, `536870913`), "image size 536870913 is outside"},
	{"archive-mismatch", replace(`"k3sm_0.2.0_darwin_arm64.tar.gz"`, `"k3sm_0.1.0_darwin_arm64.tar.gz"`), "archive is not"},
	{"archive-sha-short", replace(`"archiveSHA256": "`, `"archiveSHA256": "ab`), "archiveSHA256 is not"},
	{"payload-manifest-missing", func(t *testing.T, s string) string {
		i := strings.Index(s, `,`+"\n"+`    "payloadManifestSHA256"`)
		j := strings.Index(s, "\n  }\n}")
		if i < 0 || j < i {
			t.Fatal("the golden has no payloadManifestSHA256 to drop")
		}
		return s[:i] + s[j:]
	}, "payloadManifestSHA256 is not"},
}

// TestReleaseIndexSchemaGolden pins the k3sm-release-index/v1 contract the app
// vendors: the golden document decodes and re-encodes to the same bytes (so a
// field added, dropped or reordered is a visible change here), every committed
// red fixture is exactly its mutation of the golden and is refused for its own
// reason, no red fixture is uncommitted or stray, an index over the size cap
// is refused, and the host pin fixture is exactly AllowedHosts.
func TestReleaseIndexSchemaGolden(t *testing.T) {
	golden := readReleaseIndexFixture(t, "index.json")
	ix, err := ParseReleaseIndex(golden)
	if err != nil {
		t.Fatalf("the golden index is refused: %v", err)
	}
	if ix.Schema != ReleaseIndexSchema || ix.Context != ReleaseIndexContext || ix.Tag != "v0.2.0" ||
		ix.App.ShortVersion != "0.2.0" || ix.App.Image.Size != 123456789 ||
		ix.App.Image.URL != strings.Trim(goldenURL, `"`) || ix.K3sm.Archive != "k3sm_0.2.0_darwin_arm64.tar.gz" {
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
		var want []string
		for _, tc := range releaseIndexReds {
			file := "red-" + tc.name + ".json"
			want = append(want, file)
			t.Run(tc.name, func(t *testing.T) {
				red := []byte(tc.mutate(t, string(golden)))
				path := filepath.Join(releaseIndexDir, file)
				if *updateReleaseIndexReds {
					if err := os.WriteFile(path, red, 0o644); err != nil {
						t.Fatal(err)
					}
				}
				if got := readReleaseIndexFixture(t, file); !bytes.Equal(got, red) {
					t.Fatalf("%s is not its mutation of index.json; rerun with -update-release-index", file)
				}
				_, err := ParseReleaseIndex(red)
				if !errors.Is(err, ErrReleaseIndex) || !strings.Contains(err.Error(), tc.reason) {
					t.Errorf("got %v, want ErrReleaseIndex naming %q", err, tc.reason)
				}
			})
		}
		got, err := filepath.Glob(filepath.Join(releaseIndexDir, "red-*.json"))
		if err != nil {
			t.Fatal(err)
		}
		for i := range got {
			got[i] = filepath.Base(got[i])
		}
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("the committed red fixtures are %v, the corpus is %v", got, want)
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

// TestParseReleaseIndexAcceptsEscapedKeys shows the key check runs on decoded
// key text: a JSON escape spelling a schema key exactly is that key.
func TestParseReleaseIndexAcceptsEscapedKeys(t *testing.T) {
	golden := string(readReleaseIndexFixture(t, "index.json"))
	if _, err := ParseReleaseIndex([]byte(strings.Replace(golden, `"tag"`, `"tag"`, 1))); err != nil {
		t.Errorf("an escaped exact key is refused: %v", err)
	}
}
