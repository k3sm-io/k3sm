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
	"net/url"
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
	// URL is the https download URL on an AllowedHosts host, ending in Name.
	URL string `json:"url"`
	// SHA256 is the image's lowercase hex sha256.
	SHA256 string `json:"sha256"`
	// Size is the image's size in bytes, 1 to MaxReleaseImageBytes.
	Size int64 `json:"size"`
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
// it, an unknown field, a second JSON value, a schema or context other than
// the v1 constants, a tag that is not a final release, an image URL off the
// AllowedHosts pin set, and an image over MaxReleaseImageBytes.
func ParseReleaseIndex(raw []byte) (ReleaseIndex, error) {
	if len(raw) > MaxReleaseIndexBytes {
		return ReleaseIndex{}, fmt.Errorf("%w: %d bytes, over the %d byte cap", ErrReleaseIndex, len(raw), MaxReleaseIndexBytes)
	}
	var ix ReleaseIndex
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ix); err != nil {
		return ReleaseIndex{}, fmt.Errorf("%w: not a valid document: %w", ErrReleaseIndex, err)
	}
	if _, err := dec.Token(); err == nil {
		return ReleaseIndex{}, fmt.Errorf("%w: more than one JSON value", ErrReleaseIndex)
	}
	if err := ix.check(); err != nil {
		return ReleaseIndex{}, fmt.Errorf("%w: %w", ErrReleaseIndex, err)
	}
	return ix, nil
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
	}
	t, err := time.Parse(releaseIssuedAtLayout, ix.IssuedAt)
	if err != nil || t.Format(releaseIssuedAtLayout) != ix.IssuedAt {
		return errors.New("issuedAt is not a UTC time YYYY-MM-DDTHH:MM:SSZ")
	}
	core := strings.TrimPrefix(ix.Tag, "v")
	if err := ix.App.check(core); err != nil {
		return fmt.Errorf("app: %w", err)
	}
	if err := ix.K3sm.check(core); err != nil {
		return fmt.Errorf("k3sm: %w", err)
	}
	return nil
}

func (a ReleaseIndexApp) check(core string) error {
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
	u, err := url.Parse(im.URL)
	if err != nil {
		return errors.New("image url does not parse")
	}
	if err := checkURL(u); err != nil {
		return fmt.Errorf("image url: %w", err)
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || !strings.HasSuffix(u.EscapedPath(), "/"+im.Name) {
		return errors.New("image url carries a query or fragment, or does not end in the image name")
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
