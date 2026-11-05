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
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"k3sm.io/k3sm/pkg/version"
)

// The release index is the document a release publishes to say which app and
// k3sm build make up its version set. A final release publishes the stable
// document and a release candidate the candidate document, its sibling: one key
// tree, its own schema and context strings. docs/design/release-index.md is the
// contract for both: the fields, their grammar and bounds, and who reads each
// one. The document is signed by the release; ParseReleaseIndex and
// ParseCandidateIndex decode content a signature check has already accepted and
// never verify a signature themselves.
const (
	// ReleaseIndexSchema names the document format and its version.
	ReleaseIndexSchema = "k3sm-release-index/v1"
	// ReleaseIndexContext is the fixed domain-separation string inside the
	// signed content, so a signature over any other document the same
	// identity signs never reads as a release index.
	ReleaseIndexContext = "io.k3sm.release-index/v1"
	// CandidateIndexSchema names the candidate document's format and version.
	CandidateIndexSchema = "k3sm-release-index-rc/v1"
	// CandidateIndexContext is the candidate document's domain-separation
	// string, so a signature over a candidate document never reads as a stable
	// index, and the reverse.
	CandidateIndexContext = "io.k3sm.release-index-rc/v1"
	// MaxReleaseIndexBytes caps the document before it is parsed.
	MaxReleaseIndexBytes = 64 << 10
	// MaxReleaseImageBytes caps the disk image size an index may name.
	MaxReleaseImageBytes = 512 << 20
	// ReleaseAppBundleID is the only bundle identifier an index may name.
	ReleaseAppBundleID = "io.k3sm.app"
	// releaseIssuedAtLayout is the one form issuedAt takes: UTC, whole seconds.
	releaseIssuedAtLayout = "2006-01-02T15:04:05Z"
)

// ErrReleaseIndex is the base error of every release index refusal.
var ErrReleaseIndex = errors.New("release index refused")

// ReleaseIndex is one k3sm-release-index/v1 or k3sm-release-index-rc/v1
// document: exactly one release and the version set it ships.
type ReleaseIndex struct {
	// Schema is ReleaseIndexSchema or CandidateIndexSchema.
	Schema string `json:"schema"`
	// Context is ReleaseIndexContext or CandidateIndexContext.
	Context string `json:"context"`
	// IssuedAt is when the release wrote the index, in UTC whole seconds.
	IssuedAt string `json:"issuedAt"`
	// Tag is the release tag: vMAJOR.MINOR.PATCH on the stable document,
	// vMAJOR.MINOR.PATCH-rc.N on the candidate document.
	Tag string `json:"tag"`
	// MinimumMacOS is the lowest macOS release the set runs on, MAJOR[.MINOR[.PATCH]].
	MinimumMacOS string `json:"minimumMacOS"`
	// MinimumSupportedTag is the oldest final release the project still
	// supports, vMAJOR.MINOR.PATCH, at or below Tag. It is the floor the
	// app's go-back is to honour (docs/design/release-index.md), and a later
	// index can raise it. ParseReleaseIndex checks its grammar only.
	MinimumSupportedTag string `json:"minimumSupportedTag"`
	// App is the app half of the set.
	App ReleaseIndexApp `json:"app"`
	// K3sm is the k3sm half of the set.
	K3sm ReleaseIndexK3sm `json:"k3sm"`
}

// ReleaseIndexApp names the app build of the set.
type ReleaseIndexApp struct {
	// BundleID is ReleaseAppBundleID.
	BundleID string `json:"bundleID"`
	// ShortVersion is the app's CFBundleShortVersionString: Tag without its v
	// and without any -rc.N suffix, because that key takes only a plain x.y.z.
	ShortVersion string `json:"shortVersion"`
	// Image is the signed, notarized disk image.
	Image ReleaseIndexImage `json:"image"`
}

// ReleaseIndexImage names the app's disk image release asset.
type ReleaseIndexImage struct {
	// Name is k3sm_<version>_darwin_arm64.dmg, <version> being Tag without its v.
	Name string `json:"name"`
	// URL is ReleaseDownloadURL(Tag, Name), exactly.
	URL string `json:"url"`
	// SHA256 is the image's lowercase hex sha256.
	SHA256 string `json:"sha256"`
	// Size is the image's size in bytes, 1 to MaxReleaseImageBytes.
	Size int64 `json:"size"`
}

// ReleaseDownloadURL is the one URL an index may name for a release asset: the
// k3sm-io/k3sm release download of name under tag, on github.com with no port.
// The other AllowedHosts are hosts a fetch may be redirected to, never the URL
// an index names.
func ReleaseDownloadURL(tag, name string) string {
	return "https://github.com/k3sm-io/k3sm/releases/download/" + tag + "/" + name
}

// ReleaseIndexK3sm names the k3sm build of the set.
type ReleaseIndexK3sm struct {
	// Archive is k3sm_<version>_darwin_arm64.tar.gz, <version> being Tag without its v.
	Archive string `json:"archive"`
	// ArchiveSHA256 is the archive's lowercase hex sha256.
	ArchiveSHA256 string `json:"archiveSHA256"`
	// PayloadManifestSHA256 is the lowercase hex sha256 of the build set's
	// PAYLOAD-SHA256 manifest.
	PayloadManifestSHA256 string `json:"payloadManifestSHA256"`
}

var (
	// finalTag is a final release tag: no pre-release, no build metadata.
	finalTag = regexp.MustCompile(`^v(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)
	// candidateTag is a release candidate tag: a final tag and -rc.N.
	candidateTag = regexp.MustCompile(`^v(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})-rc\.(0|[1-9][0-9]{0,3})$`)
	// macOSVersion is MAJOR[.MINOR[.PATCH]], each at most three digits.
	macOSVersion = regexp.MustCompile(`^[1-9][0-9]{0,2}(\.(0|[1-9][0-9]{0,2})){0,2}$`)
)

// releaseIndexKind is what separates the two documents: the strings each
// carries and the tag each may name. The parser takes one with no default, so
// a reader always says which document it expects.
type releaseIndexKind struct {
	schema, context string
	tag             *regexp.Regexp
	tagGrammar      string
}

var (
	stableIndexKind = releaseIndexKind{
		schema: ReleaseIndexSchema, context: ReleaseIndexContext,
		tag: finalTag, tagGrammar: "a final release tag vMAJOR.MINOR.PATCH",
	}
	candidateIndexKind = releaseIndexKind{
		schema: CandidateIndexSchema, context: CandidateIndexContext,
		tag: candidateTag, tagGrammar: "a release candidate tag vMAJOR.MINOR.PATCH-rc.N",
	}
)

// ParseReleaseIndex decodes one stable release index and checks every field
// against its grammar. It refuses a document over MaxReleaseIndexBytes before
// parsing it; a key that is not a schema key in exact case, or that appears
// twice in one object; anything after the one JSON object; a schema or context
// other than the v1 constants; a tag that is not a final release; a minimum
// supported tag that is not a final release or is above the tag; and an image
// URL other than the release download URL of that tag and image name.
func ParseReleaseIndex(raw []byte) (ReleaseIndex, error) {
	return parseIndex(raw, stableIndexKind)
}

// ParseCandidateIndex decodes one candidate release index read at the release
// of tag. It refuses everything ParseReleaseIndex does, with
// CandidateIndexSchema and CandidateIndexContext as the required strings and a
// release candidate as the required tag, and it refuses a document that names
// any tag but the requested one, so a document valid for one candidate is never
// accepted at another's path. The minimum supported tag is still a final
// release, at or below the candidate, which puts the candidate's own final above it.
func ParseCandidateIndex(raw []byte, tag string) (ReleaseIndex, error) {
	ix, err := parseIndex(raw, candidateIndexKind)
	if err != nil {
		return ReleaseIndex{}, err
	}
	if ix.Tag != tag {
		return ReleaseIndex{}, fmt.Errorf("%w: tag %s is not the requested %s", ErrReleaseIndex, ix.Tag, tag)
	}
	return ix, nil
}

// parseIndex is the one decoder behind both documents.
func parseIndex(raw []byte, kind releaseIndexKind) (ReleaseIndex, error) {
	if len(raw) > MaxReleaseIndexBytes {
		return ReleaseIndex{}, fmt.Errorf("%w: %d bytes, over the %d byte cap", ErrReleaseIndex, len(raw), MaxReleaseIndexBytes)
	}
	// encoding/json keeps the last of two equal keys and matches keys without
	// regard to case, so the keys are checked on the token stream first.
	if err := checkReleaseIndexKeys(raw); err != nil {
		return ReleaseIndex{}, fmt.Errorf("%w: %w", ErrReleaseIndex, err)
	}
	var ix ReleaseIndex
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ix); err != nil {
		return ReleaseIndex{}, fmt.Errorf("%w: not a valid document: %w", ErrReleaseIndex, err)
	}
	if err := dec.Decode(&json.RawMessage{}); !errors.Is(err, io.EOF) {
		return ReleaseIndex{}, fmt.Errorf("%w: trailing data after the document", ErrReleaseIndex)
	}
	if err := ix.check(kind); err != nil {
		return ReleaseIndex{}, fmt.Errorf("%w: %w", ErrReleaseIndex, err)
	}
	return ix, nil
}

// releaseIndexKeys is the key tree both documents share: each object's keys, mapped to the keys
// of the object that key holds (nil for a scalar).
type releaseIndexKeys map[string]releaseIndexKeys

var releaseIndexSchemaKeys = releaseIndexKeys{
	"schema": nil, "context": nil, "issuedAt": nil, "tag": nil, "minimumMacOS": nil, "minimumSupportedTag": nil,
	"app": {
		"bundleID": nil, "shortVersion": nil,
		"image": {"name": nil, "url": nil, "sha256": nil, "size": nil},
	},
	"k3sm": {"archive": nil, "archiveSHA256": nil, "payloadManifestSHA256": nil},
}

// checkReleaseIndexKeys walks the token stream of one top-level object and
// refuses a key that is not in releaseIndexSchemaKeys at its place, in exact
// case, a key repeated within one object, and any array. The walk is at most
// three objects deep, because no other key admits an object.
func checkReleaseIndexKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("not a valid document: %w", err)
	}
	if tok != json.Delim('{') {
		return errors.New("the document is not a JSON object")
	}
	return walkReleaseIndexObject(dec, releaseIndexSchemaKeys)
}

// walkReleaseIndexObject consumes an object's members and its closing brace,
// its opening brace already read.
func walkReleaseIndexObject(dec *json.Decoder, keys releaseIndexKeys) error {
	seen := make(map[string]bool, len(keys))
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("not a valid document: %w", err)
		}
		key, _ := tok.(string)
		sub, known := keys[key]
		switch {
		case !known:
			return fmt.Errorf("unknown key %q", key)
		case seen[key]:
			return fmt.Errorf("duplicate key %q", key)
		}
		seen[key] = true
		if tok, err = dec.Token(); err != nil {
			return fmt.Errorf("not a valid document: %w", err)
		}
		switch tok {
		case json.Delim('{'):
			if err := walkReleaseIndexObject(dec, sub); err != nil {
				return err
			}
		case json.Delim('['):
			return fmt.Errorf("key %q holds an array", key)
		}
	}
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("not a valid document: %w", err)
	}
	return nil
}

// check applies the field grammar of kind; parseIndex wraps its error.
func (ix ReleaseIndex) check(kind releaseIndexKind) error {
	switch {
	case ix.Schema != kind.schema:
		return fmt.Errorf("schema is not %s", kind.schema)
	case ix.Context != kind.context:
		return fmt.Errorf("context is not %s", kind.context)
	case !version.ValidTag(ix.Tag) || !kind.tag.MatchString(ix.Tag):
		return fmt.Errorf("tag is not %s", kind.tagGrammar)
	case !macOSVersion.MatchString(ix.MinimumMacOS):
		return errors.New("minimumMacOS is not MAJOR[.MINOR[.PATCH]]")
	case !version.ValidTag(ix.MinimumSupportedTag) || !finalTag.MatchString(ix.MinimumSupportedTag):
		return errors.New("minimumSupportedTag is not a final release tag vMAJOR.MINOR.PATCH")
	}
	// Both tags matched their grammar, so both parse and the comparison is defined.
	if c, ok := version.CompareReleases(ix.MinimumSupportedTag, ix.Tag); !ok || c > 0 {
		return fmt.Errorf("minimumSupportedTag %s is above tag %s", ix.MinimumSupportedTag, ix.Tag)
	}
	t, err := time.Parse(releaseIssuedAtLayout, ix.IssuedAt)
	if err != nil || t.Format(releaseIssuedAtLayout) != ix.IssuedAt {
		return errors.New("issuedAt is not a UTC time YYYY-MM-DDTHH:MM:SSZ")
	}
	// The whole version names the assets; the core is the app's short version.
	// The tag matched its grammar, so the only hyphen starts an -rc.N suffix.
	full := strings.TrimPrefix(ix.Tag, "v")
	core, _, _ := strings.Cut(full, "-")
	if err := ix.App.check(ix.Tag, core, full); err != nil {
		return fmt.Errorf("app: %w", err)
	}
	if err := ix.K3sm.check(full); err != nil {
		return fmt.Errorf("k3sm: %w", err)
	}
	return nil
}

func (a ReleaseIndexApp) check(tag, core, full string) error {
	switch {
	case a.BundleID != ReleaseAppBundleID:
		return fmt.Errorf("bundleID is not %s", ReleaseAppBundleID)
	case a.ShortVersion != core:
		return fmt.Errorf("shortVersion is not %s", core)
	}
	im := a.Image
	switch {
	case im.Name != "k3sm_"+full+"_darwin_arm64.dmg":
		return fmt.Errorf("image name is not k3sm_%s_darwin_arm64.dmg", full)
	case !isSHA256Hex(im.SHA256):
		return errors.New("image sha256 is not a lowercase hex sha256")
	case im.Size < 1 || im.Size > MaxReleaseImageBytes:
		return fmt.Errorf("image size %d is outside 1 to %d bytes", im.Size, MaxReleaseImageBytes)
	}
	if want := ReleaseDownloadURL(tag, im.Name); im.URL != want {
		return fmt.Errorf("image url is not %s", want)
	}
	return nil
}

func (k ReleaseIndexK3sm) check(full string) error {
	switch {
	case k.Archive != "k3sm_"+full+"_darwin_arm64.tar.gz":
		return fmt.Errorf("archive is not k3sm_%s_darwin_arm64.tar.gz", full)
	case !isSHA256Hex(k.ArchiveSHA256):
		return errors.New("archiveSHA256 is not a lowercase hex sha256")
	case !isSHA256Hex(k.PayloadManifestSHA256):
		return errors.New("payloadManifestSHA256 is not a lowercase hex sha256")
	}
	return nil
}
