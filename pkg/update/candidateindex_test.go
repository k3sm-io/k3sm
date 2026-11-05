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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const (
	candidateIndexDir = "testdata/release-index-rc"
	// candidateRequestedTag is the tag every document in the corpus is read
	// at, as the app reads one at its own release path.
	candidateRequestedTag = "v0.3.0-rc.2"
	// v1GoldenSHA256 pins the bytes of the stable golden: the candidate schema
	// is a sibling document and leaves v1 exactly as it was.
	v1GoldenSHA256 = "d8008b48c5d2a781fc744cef2fd7d1bd05c8f9568a0e9eba46f058e408bf12bd"
)

func readCandidateIndexFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(candidateIndexDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// asCandidate rewrites the golden document whole to another candidate, leaving
// a document that is valid in itself for that tag.
func asCandidate(rc string) func(t *testing.T, s string) string {
	return func(t *testing.T, s string) string {
		t.Helper()
		if !strings.Contains(s, "rc.2") {
			t.Fatal("the golden has no rc.2 to rewrite")
		}
		return strings.ReplaceAll(s, "rc.2", rc)
	}
}

// candidateIndexReds is the candidate refusal corpus: each entry is one change
// to the golden document, committed as testdata/release-index-rc/red-<name>.json
// so the app's decoder runs the same set, and the reason the refusal must name.
// Every file is refused when read at candidateRequestedTag.
var candidateIndexReds = []struct {
	name   string
	mutate func(t *testing.T, s string) string
	reason string
}{
	// The other decoder's document, and each half of its domain separation.
	{"stable-document", func(t *testing.T, _ string) string {
		return string(readReleaseIndexFixture(t, "index.json"))
	}, "schema is not k3sm-release-index-rc/v1"},
	{"stable-schema", replace(`"k3sm-release-index-rc/v1"`, `"k3sm-release-index/v1"`), "schema is not k3sm-release-index-rc/v1"},
	{"stable-context", replace(`"io.k3sm.release-index-rc/v1"`, `"io.k3sm.release-index/v1"`), "context is not io.k3sm.release-index-rc/v1"},
	{"schema-v2", replace(`"k3sm-release-index-rc/v1"`, `"k3sm-release-index-rc/v2"`), "schema is not"},
	{"other-context", replace(`"io.k3sm.release-index-rc/v1"`, `"io.k3sm.other/v1"`), "context is not"},
	{"no-context", replace(`  "context": "io.k3sm.release-index-rc/v1",`+"\n", ``), "context is not"},

	// A document valid for another candidate, read at this one's path.
	{"replayed-older-candidate", asCandidate("rc.1"), "tag v0.3.0-rc.1 is not the requested v0.3.0-rc.2"},
	{"replayed-newer-candidate", asCandidate("rc.3"), "tag v0.3.0-rc.3 is not the requested v0.3.0-rc.2"},

	// The tag's grammar.
	{"final-tag", func(_ *testing.T, s string) string { return strings.ReplaceAll(s, "-rc.2", "") }, "not a release candidate tag"},
	{"rc-leading-zero", asCandidate("rc.02"), "not a release candidate tag"},
	{"rc-five-digits", asCandidate("rc.10000"), "not a release candidate tag"},
	{"rc-no-number", asCandidate("rc"), "not a release candidate tag"},
	{"rc-two-numbers", asCandidate("rc.2.1"), "not a release candidate tag"},
	{"rc-uppercase", asCandidate("RC.2"), "not a release candidate tag"},
	{"beta-tag", asCandidate("beta.2"), "not a release candidate tag"},
	{"build-metadata-tag", replace(`"tag": "v0.3.0-rc.2"`, `"tag": "v0.3.0-rc.2+x"`), "not a release candidate tag"},
	{"tag-without-v", replace(`"tag": "v0.3.0-rc.2"`, `"tag": "0.3.0-rc.2"`), "not a release candidate tag"},
	{"tag-leading-zero", replace(`"tag": "v0.3.0-rc.2"`, `"tag": "v0.03.0-rc.2"`), "not a release candidate tag"},

	// The floor is a final release at or below the tag: a candidate's own final
	// is above it, and a candidate is never a floor.
	{"minimum-supported-tag-own-final", replace(`"minimumSupportedTag": "v0.2.0"`, `"minimumSupportedTag": "v0.3.0"`), "minimumSupportedTag v0.3.0 is above tag v0.3.0-rc.2"},
	{"minimum-supported-tag-above-tag", replace(`"minimumSupportedTag": "v0.2.0"`, `"minimumSupportedTag": "v0.4.0"`), "minimumSupportedTag v0.4.0 is above tag v0.3.0-rc.2"},
	{"minimum-supported-tag-rc", replace(`"minimumSupportedTag": "v0.2.0"`, `"minimumSupportedTag": "v0.3.0-rc.1"`), "minimumSupportedTag is not a final release tag"},
	{"minimum-supported-tag-missing", replace(`  "minimumSupportedTag": "v0.2.0",`+"\n", ``), "minimumSupportedTag is not a final release tag"},

	// The short version is the core; the asset names carry the whole version.
	{"short-version-with-suffix", replace(`"shortVersion": "0.3.0"`, `"shortVersion": "0.3.0-rc.2"`), "shortVersion is not 0.3.0"},
	{"short-version-other-core", replace(`"shortVersion": "0.3.0"`, `"shortVersion": "0.3.1"`), "shortVersion is not 0.3.0"},
	{"image-name-core-only", replace(`"name": "k3sm_0.3.0-rc.2_darwin_arm64.dmg"`, `"name": "k3sm_0.3.0_darwin_arm64.dmg"`), "image name is not k3sm_0.3.0-rc.2_darwin_arm64.dmg"},
	{"archive-core-only", replace(`"k3sm_0.3.0-rc.2_darwin_arm64.tar.gz"`, `"k3sm_0.3.0_darwin_arm64.tar.gz"`), "archive is not k3sm_0.3.0-rc.2_darwin_arm64.tar.gz"},
	{"archive-other-candidate", replace(`"k3sm_0.3.0-rc.2_darwin_arm64.tar.gz"`, `"k3sm_0.3.0-rc.1_darwin_arm64.tar.gz"`), "archive is not k3sm_0.3.0-rc.2_darwin_arm64.tar.gz"},

	// The image URL is the one its tag and name determine.
	{"url-other-candidate", replace(`/download/v0.3.0-rc.2/`, `/download/v0.3.0-rc.1/`), "image url is not"},
	{"url-final-tag", replace(`/download/v0.3.0-rc.2/`, `/download/v0.3.0/`), "image url is not"},
	{"url-latest", replace(`/releases/download/v0.3.0-rc.2/`, `/releases/latest/download/`), "image url is not"},
	{"foreign-host", replace(`https://github.com/`, `https://example.com/`), "image url is not"},
	{"redirect-host-as-url", replace(`https://github.com/`, `https://objects.githubusercontent.com/`), "image url is not"},
	{"foreign-repo", replace(`github.com/k3sm-io/k3sm/`, `github.com/someone/k3sm/`), "image url is not"},
	{"url-query", replace(`_darwin_arm64.dmg",`+"\n"+`      "sha256"`, `_darwin_arm64.dmg?x=1",`+"\n"+`      "sha256"`), "image url is not"},

	// The strict decoding the two documents share.
	{"unknown-field", replace(`"minimumMacOS": "26.0",`, `"minimumMacOS": "26.0",`+"\n"+`  "channel": "rc",`), `unknown key "channel"`},
	{"case-variant-key", replace(`"tag": "v0.3.0-rc.2"`, `"Tag": "v0.3.0-rc.2"`), `unknown key "Tag"`},
	{"duplicate-key", replace(`"tag": "v0.3.0-rc.2",`, `"tag": "v0.3.0-rc.2", "tag": "v0.3.0-rc.1",`), `duplicate key "tag"`},
	{"array-value", replace(`"minimumMacOS": "26.0"`, `"minimumMacOS": ["26.0"]`), "holds an array"},
	{"not-an-object", func(*testing.T, string) string { return "[]\n" }, "not a JSON object"},
	{"trailing-garbage", appendText("garbage\n"), "trailing data"},
	{"second-value", appendText("{}\n"), "trailing data"},
	{"truncated", func(_ *testing.T, s string) string { return s[:len(s)/2] }, "not a valid document"},
	{"issued-at-offset", replace(`2026-11-05T12:30:45Z`, `2026-11-05T12:30:45+01:00`), "issuedAt is not"},
	{"minimum-macos-word", replace(`"26.0"`, `"Tahoe"`), "minimumMacOS is not"},
	{"other-bundle-id", replace(`"io.k3sm.app"`, `"io.k3sm.app2"`), "bundleID is not"},
	{"image-sha-uppercase", replace(`"sha256": "7c1f0a55`, `"sha256": "7C1F0A55`), "image sha256 is not"},
	{"image-zero-size", replace(`123456789`, `0`), "image size 0 is outside"},
	{"archive-sha-short", replace(`"archiveSHA256": "`, `"archiveSHA256": "ab`), "archiveSHA256 is not"},
	{"payload-manifest-sha-short", replace(`"payloadManifestSHA256": "`, `"payloadManifestSHA256": "ab`), "payloadManifestSHA256 is not"},
}

// TestCandidateIndexSchemaGolden pins the k3sm-release-index-rc/v1 contract the
// app reads: the golden document decodes at its own tag and re-encodes to the
// same bytes, every committed red fixture is exactly its mutation of the golden
// and is refused for its own reason, no red fixture is uncommitted or stray,
// each decoder refuses the other's document, and a document valid for one
// candidate is refused at another's path.
func TestCandidateIndexSchemaGolden(t *testing.T) {
	golden := readCandidateIndexFixture(t, "index.json")
	ix, err := ParseCandidateIndex(golden, candidateRequestedTag)
	if err != nil {
		t.Fatalf("the golden candidate index is refused: %v", err)
	}
	if ix.Schema != CandidateIndexSchema || ix.Context != CandidateIndexContext || ix.Tag != candidateRequestedTag ||
		ix.MinimumSupportedTag != "v0.2.0" || ix.App.ShortVersion != "0.3.0" || ix.App.Image.Size != 123456789 ||
		ix.App.Image.Name != "k3sm_0.3.0-rc.2_darwin_arm64.dmg" ||
		ix.App.Image.URL != ReleaseDownloadURL(candidateRequestedTag, "k3sm_0.3.0-rc.2_darwin_arm64.dmg") ||
		ix.K3sm.Archive != "k3sm_0.3.0-rc.2_darwin_arm64.tar.gz" {
		t.Errorf("the golden candidate index decoded to %+v", ix)
	}
	again, err := json.MarshalIndent(ix, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(append(again, '\n'), golden) {
		t.Errorf("the golden candidate index does not re-encode to its own bytes:\n%s", again)
	}

	t.Run("red fixtures", func(t *testing.T) {
		var want []string
		for _, tc := range candidateIndexReds {
			file := "red-" + tc.name + ".json"
			want = append(want, file)
			t.Run(tc.name, func(t *testing.T) {
				red := []byte(tc.mutate(t, string(golden)))
				path := filepath.Join(candidateIndexDir, file)
				if *updateReleaseIndexReds {
					if err := os.WriteFile(path, red, 0o644); err != nil {
						t.Fatal(err)
					}
				}
				if got := readCandidateIndexFixture(t, file); !bytes.Equal(got, red) {
					t.Fatalf("%s is not its mutation of index.json; rerun with -update-release-index", file)
				}
				_, err := ParseCandidateIndex(red, candidateRequestedTag)
				if !errors.Is(err, ErrReleaseIndex) || !strings.Contains(err.Error(), tc.reason) {
					t.Errorf("got %v, want ErrReleaseIndex naming %q", err, tc.reason)
				}
			})
		}
		got, err := filepath.Glob(filepath.Join(candidateIndexDir, "red-*.json"))
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

	t.Run("each decoder refuses the other's document", func(t *testing.T) {
		stable := readReleaseIndexFixture(t, "index.json")
		if _, err := ParseCandidateIndex(stable, "v0.2.0"); !errors.Is(err, ErrReleaseIndex) ||
			!strings.Contains(err.Error(), "schema is not "+CandidateIndexSchema) {
			t.Errorf("the candidate decoder on the stable golden: got %v", err)
		}
		if _, err := ParseReleaseIndex(golden); !errors.Is(err, ErrReleaseIndex) ||
			!strings.Contains(err.Error(), "schema is not "+ReleaseIndexSchema) {
			t.Errorf("the stable decoder on the candidate golden: got %v", err)
		}
		// With both strings swapped, the kind still decides the tag grammar.
		swapped := strings.NewReplacer(CandidateIndexSchema, ReleaseIndexSchema, CandidateIndexContext, ReleaseIndexContext).Replace(string(golden))
		if _, err := ParseReleaseIndex([]byte(swapped)); !errors.Is(err, ErrReleaseIndex) ||
			!strings.Contains(err.Error(), "not a final release tag") {
			t.Errorf("the stable decoder on a candidate under v1's strings: got %v", err)
		}
	})

	t.Run("a valid rc.1 document at the rc.2 path refuses", func(t *testing.T) {
		rc1 := []byte(asCandidate("rc.1")(t, string(golden)))
		if _, err := ParseCandidateIndex(rc1, "v0.3.0-rc.1"); err != nil {
			t.Fatalf("the rc.1 document is not valid at its own path: %v", err)
		}
		got, err := ParseCandidateIndex(rc1, "v0.3.0-rc.2")
		if !errors.Is(err, ErrReleaseIndex) || !strings.Contains(err.Error(), "is not the requested") {
			t.Errorf("got %v, want a refusal naming the requested tag", err)
		}
		if got != (ReleaseIndex{}) {
			t.Errorf("a refusal returned a document: %+v", got)
		}
	})

	t.Run("the requested tag has no default", func(t *testing.T) {
		for _, requested := range []string{"", "v0.3.0", "v0.3.0-rc.1", "latest"} {
			if _, err := ParseCandidateIndex(golden, requested); !errors.Is(err, ErrReleaseIndex) {
				t.Errorf("requested %q: got %v", requested, err)
			}
		}
	})

	t.Run("candidate numbers", func(t *testing.T) {
		for _, rc := range []string{"rc.0", "rc.1", "rc.10", "rc.9999"} {
			tag := "v0.3.0-" + rc
			if _, err := ParseCandidateIndex([]byte(asCandidate(rc)(t, string(golden))), tag); err != nil {
				t.Errorf("%s is refused: %v", tag, err)
			}
		}
	})

	t.Run("oversized", func(t *testing.T) {
		raw := append(bytes.Repeat([]byte(" "), MaxReleaseIndexBytes+1-len(golden)), golden...)
		_, err := ParseCandidateIndex(raw, candidateRequestedTag)
		if !errors.Is(err, ErrReleaseIndex) || !strings.Contains(err.Error(), "byte cap") {
			t.Errorf("got %v, want the size cap", err)
		}
	})

	t.Run("the stable golden keeps its bytes", func(t *testing.T) {
		sum := sha256.Sum256(readReleaseIndexFixture(t, "index.json"))
		if got := hex.EncodeToString(sum[:]); got != v1GoldenSHA256 {
			t.Errorf("testdata/release-index/index.json hashes %s; a change to the format is a new schema string", got)
		}
		if ReleaseIndexSchema != "k3sm-release-index/v1" || ReleaseIndexContext != "io.k3sm.release-index/v1" {
			t.Errorf("the v1 strings moved: %s, %s", ReleaseIndexSchema, ReleaseIndexContext)
		}
	})
}
