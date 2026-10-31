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

package updatectl

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"k3sm.io/k3sm/pkg/certs"
)

// DefaultReleaseBase is the GitHub Releases root the release index is read
// from, the same default install.sh uses.
const DefaultReleaseBase = "https://github.com/k3sm-io/k3sm/releases"

// maxChecksumsBytes bounds the checksums file read. A goreleaser checksums
// file is a few hundred bytes; anything near this bound is not one.
const maxChecksumsBytes = 1 << 20

// ErrRelease marks a definitive release-index failure: the tag is unusable,
// the release or its checksums file does not exist, or the checksums file
// names no darwin/arm64 archive (a 404, 403 or 410 included). Retrying cannot fix it, so the roll fails.
// Every other resolve error (the network, a 5xx) is transient and retried.
var ErrRelease = errors.New("release cannot be resolved")

// Release is a resolved target: the tag, the darwin/arm64 archive's URL and
// its sha256 from the release's checksums file.
type Release struct {
	// Version is the release tag as the Update names it.
	Version string
	// URL is the darwin/arm64 archive's download URL.
	URL string
	// SHA256 is the archive's lowercase hex sha256.
	SHA256 string
	// Pinned is set by PinnedResolver when SHA256 equals the release pin for
	// Version.
	Pinned bool
}

// Resolver resolves a release tag to its darwin/arm64 archive.
type Resolver interface {
	// Resolve reads the release index for tag and returns its archive and the
	// archive's sha256. A definitive failure wraps ErrRelease.
	Resolve(ctx context.Context, tag string) (Release, error)
	// AssetURL is the archive URL for tag, without any network access. The
	// controller rebuilds a node's payload from status.resolved with it after
	// a restart, so the release is resolved only once.
	AssetURL(tag string) (string, error)
	// Manifest reads the release's payload manifest (certs.PayloadManifest
	// JSON, unsigned as published), at most certs.MaxPayloadManifestBytes.
	// The controller checks it against the resolved archive and signs it. A
	// definitive failure (no such asset) wraps ErrRelease.
	Manifest(ctx context.Context, tag string) ([]byte, error)
}

// HTTPResolver reads the release index over HTTP, the way install.sh does: the
// archive k3sm_<version>_darwin_arm64.tar.gz and the checksums file
// k3sm_<version>_checksums.txt under <base>/download/<tag>/. It never executes
// or unpacks anything; the tag and the checksum are data.
type HTTPResolver struct {
	// Base is the releases root. Empty means DefaultReleaseBase.
	Base string
	// Client is the HTTP client. nil means a client with a 30s timeout.
	Client *http.Client
}

// names returns the normalized tag (with its leading "v"), the archive name
// and the checksums file name for tag, refusing a tag install.sh would refuse.
func names(tag string) (vtag, archive, checksums string, err error) {
	if !validTag(tag) {
		return "", "", "", fmt.Errorf("%w: unusable release tag %q", ErrRelease, tag)
	}
	ver := strings.TrimPrefix(tag, "v")
	if ver == "" {
		return "", "", "", fmt.Errorf("%w: empty release version in tag %q", ErrRelease, tag)
	}
	return "v" + ver, "k3sm_" + ver + "_darwin_arm64.tar.gz", "k3sm_" + ver + "_checksums.txt", nil
}

// ManifestAssetName is the release asset that carries the payload manifest
// of tag's darwin/arm64 archive: k3sm_<version>_darwin_arm64.manifest.json,
// beside the archive under <base>/download/<tag>/.
func ManifestAssetName(tag string) (string, error) {
	_, archive, _, err := names(tag)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(archive, ".tar.gz") + ".manifest.json", nil
}

// validTag is install.sh's valid_tag: non-empty, no leading "-", and only
// [A-Za-z0-9.+_-], so a tag is safe as a URL path segment.
func validTag(tag string) bool {
	if tag == "" || strings.HasPrefix(tag, "-") {
		return false
	}
	for _, r := range tag {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '+', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

func (r HTTPResolver) base() string {
	if r.Base == "" {
		return DefaultReleaseBase
	}
	return strings.TrimSuffix(r.Base, "/")
}

// AssetURL implements Resolver.
func (r HTTPResolver) AssetURL(tag string) (string, error) {
	vtag, archive, _, err := names(tag)
	if err != nil {
		return "", err
	}
	return r.base() + "/download/" + vtag + "/" + archive, nil
}

// Resolve implements Resolver.
func (r HTTPResolver) Resolve(ctx context.Context, tag string) (Release, error) {
	vtag, archive, checksums, err := names(tag)
	if err != nil {
		return Release{}, err
	}
	client := r.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	sumsURL := r.base() + "/download/" + vtag + "/" + checksums
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sumsURL, nil)
	if err != nil {
		return Release{}, fmt.Errorf("build checksums request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return Release{}, fmt.Errorf("fetch %s: %w", sumsURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return Release{}, fmt.Errorf("%w: %s: not found (has release %s been published?)", ErrRelease, sumsURL, vtag)
	case resp.StatusCode == http.StatusForbidden, resp.StatusCode == http.StatusGone:
		// A refused or withdrawn release does not come back by retrying.
		return Release{}, fmt.Errorf("%w: %s: http %d", ErrRelease, sumsURL, resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return Release{}, fmt.Errorf("fetch %s: http %d", sumsURL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxChecksumsBytes+1))
	if err != nil {
		return Release{}, fmt.Errorf("read %s: %w", sumsURL, err)
	}
	if len(body) > maxChecksumsBytes {
		return Release{}, fmt.Errorf("%w: %s is larger than %d bytes", ErrRelease, sumsURL, maxChecksumsBytes)
	}
	sum, err := checksumFor(body, archive)
	if err != nil {
		return Release{}, fmt.Errorf("%s: %w", sumsURL, err)
	}
	url, _ := r.AssetURL(tag) // names already accepted tag
	return Release{Version: tag, URL: url, SHA256: sum}, nil
}

// Manifest implements Resolver.
func (r HTTPResolver) Manifest(ctx context.Context, tag string) ([]byte, error) {
	vtag, _, _, err := names(tag)
	if err != nil {
		return nil, err
	}
	name, _ := ManifestAssetName(tag) // names already accepted tag
	client := r.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	u := r.base() + "/download/" + vtag + "/" + name
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("build manifest request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", u, err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotFound, resp.StatusCode == http.StatusForbidden, resp.StatusCode == http.StatusGone:
		return nil, fmt.Errorf("%w: %s: http %d (release %s publishes no payload manifest)", ErrRelease, u, resp.StatusCode, vtag)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("fetch %s: http %d", u, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, certs.MaxPayloadManifestBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", u, err)
	}
	if len(body) > certs.MaxPayloadManifestBytes {
		return nil, fmt.Errorf("%w: %s is larger than %d bytes", ErrRelease, u, certs.MaxPayloadManifestBytes)
	}
	return body, nil
}

// checksumFor returns the sha256 the checksums file records for archive: the
// line whose second field IS the archive name (an exact field match, as
// install.sh's awk does). A missing entry, a malformed digest, or two
// different digests for the one name is a definitive failure.
func checksumFor(body []byte, archive string) (string, error) {
	var found string
	sc := bufio.NewScanner(bytes.NewReader(body))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 2 || f[1] != archive {
			continue
		}
		if !isSHA256Hex(f[0]) {
			return "", fmt.Errorf("%w: malformed sha256 for %s", ErrRelease, archive)
		}
		if found != "" && found != f[0] {
			return "", fmt.Errorf("%w: two different sha256 entries for %s", ErrRelease, archive)
		}
		found = f[0]
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("%w: read checksums: %w", ErrRelease, err)
	}
	if found == "" {
		return "", fmt.Errorf("%w: checksums file has no entry for %s", ErrRelease, archive)
	}
	return found, nil
}

// isSHA256Hex reports whether s is 64 lowercase hex digits.
func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
