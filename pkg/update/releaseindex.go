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

// The release index is the document a final release publishes to say which
// app and k3sm build make up its version set. docs/design/release-index.md is
// its contract: the fields, their grammar and bounds, and who reads each one.
// The document is signed by the release; ParseReleaseIndex decodes content a
// signature check has already accepted and never verifies a signature itself.
const (
	// ReleaseIndexSchema names the document format and its version.
	ReleaseIndexSchema = "k3sm-release-index/v1"
	// ReleaseIndexContext is the fixed domain-separation string inside the
	// signed content, so a signature over any other document the same
	// identity signs never reads as a release index.
	ReleaseIndexContext = "io.k3sm.release-index/v1"
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

// ReleaseIndex is one k3sm-release-index/v1 document: exactly one final
// release and the version set it ships.
type ReleaseIndex struct {
	// Schema is ReleaseIndexSchema.
	Schema string `json:"schema"`
	// Context is ReleaseIndexContext.
	Context string `json:"context"`
	// IssuedAt is when the release wrote the index, in UTC whole seconds.
	IssuedAt string `json:"issuedAt"`
	// Tag is the final release tag, vMAJOR.MINOR.PATCH.
	Tag string `json:"tag"`
	// MinimumMacOS is the lowest macOS release the set runs on, MAJOR[.MINOR[.PATCH]].
	MinimumMacOS string `json:"minimumMacOS"`
	// MinimumSupportedTag is the oldest final release the project still
	// supports, vMAJOR.MINOR.PATCH, at or below Tag. The app refuses to go
	// back to a release below it, and a later index can raise it.
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
	// ShortVersion is the app's CFBundleShortVersionString: Tag without its v.
	ShortVersion string `json:"shortVersion"`
	// Image is the signed, notarized disk image.
	Image ReleaseIndexImage `json:"image"`
}

// ReleaseIndexImage names the app's disk image release asset.
type ReleaseIndexImage struct {
	// Name is k3sm_<version>_darwin_arm64.dmg.
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
	// Archive is k3sm_<version>_darwin_arm64.tar.gz.
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
	// macOSVersion is MAJOR[.MINOR[.PATCH]], each at most three digits.
	macOSVersion = regexp.MustCompile(`^[1-9][0-9]{0,2}(\.(0|[1-9][0-9]{0,2})){0,2}$`)
)

// ParseReleaseIndex decodes one release index and checks every field against
// its grammar. It refuses a document over MaxReleaseIndexBytes before parsing
// it; a key that is not a schema key in exact case, or that appears twice in
// one object; anything after the one JSON object; a schema or context other
// than the v1 constants; a tag that is not a final release; a minimum supported
// tag that is not a final release or is above the tag; and an image URL other
// than the release download URL of that tag and image name.
func ParseReleaseIndex(raw []byte) (ReleaseIndex, error) {
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
	if err := ix.check(); err != nil {
		return ReleaseIndex{}, fmt.Errorf("%w: %w", ErrReleaseIndex, err)
	}
	return ix, nil
}

// releaseIndexKeys is the v1 key tree: each object's keys, mapped to the keys
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

// check applies the field grammar; ParseReleaseIndex wraps its error.
func (ix ReleaseIndex) check() error {
	switch {
	case ix.Schema != ReleaseIndexSchema:
		return fmt.Errorf("schema is not %s", ReleaseIndexSchema)
	case ix.Context != ReleaseIndexContext:
		return fmt.Errorf("context is not %s", ReleaseIndexContext)
	case !version.ValidTag(ix.Tag) || !finalTag.MatchString(ix.Tag):
		return errors.New("tag is not a final release tag vMAJOR.MINOR.PATCH")
	case !macOSVersion.MatchString(ix.MinimumMacOS):
		return errors.New("minimumMacOS is not MAJOR[.MINOR[.PATCH]]")
	case !version.ValidTag(ix.MinimumSupportedTag) || !finalTag.MatchString(ix.MinimumSupportedTag):
		return errors.New("minimumSupportedTag is not a final release tag vMAJOR.MINOR.PATCH")
	}
	// Both tags matched finalTag, so both parse and the comparison is defined.
	if c, ok := version.CompareReleases(ix.MinimumSupportedTag, ix.Tag); !ok || c > 0 {
		return fmt.Errorf("minimumSupportedTag %s is above tag %s", ix.MinimumSupportedTag, ix.Tag)
	}
	t, err := time.Parse(releaseIssuedAtLayout, ix.IssuedAt)
	if err != nil || t.Format(releaseIssuedAtLayout) != ix.IssuedAt {
		return errors.New("issuedAt is not a UTC time YYYY-MM-DDTHH:MM:SSZ")
	}
	core := strings.TrimPrefix(ix.Tag, "v")
	if err := ix.App.check(ix.Tag, core); err != nil {
		return fmt.Errorf("app: %w", err)
	}
	if err := ix.K3sm.check(core); err != nil {
		return fmt.Errorf("k3sm: %w", err)
	}
	return nil
}

func (a ReleaseIndexApp) check(tag, core string) error {
	switch {
	case a.BundleID != ReleaseAppBundleID:
		return fmt.Errorf("bundleID is not %s", ReleaseAppBundleID)
	case a.ShortVersion != core:
		return fmt.Errorf("shortVersion is not %s", core)
	}
	im := a.Image
	switch {
	case im.Name != "k3sm_"+core+"_darwin_arm64.dmg":
		return fmt.Errorf("image name is not k3sm_%s_darwin_arm64.dmg", core)
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

func (k ReleaseIndexK3sm) check(core string) error {
	switch {
	case k.Archive != "k3sm_"+core+"_darwin_arm64.tar.gz":
		return fmt.Errorf("archive is not k3sm_%s_darwin_arm64.tar.gz", core)
	case !isSHA256Hex(k.ArchiveSHA256):
		return errors.New("archiveSHA256 is not a lowercase hex sha256")
	case !isSHA256Hex(k.PayloadManifestSHA256):
		return errors.New("payloadManifestSHA256 is not a lowercase hex sha256")
	}
	return nil
}
