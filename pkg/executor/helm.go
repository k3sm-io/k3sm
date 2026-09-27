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

package executor

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"k3sm.io/k3sm/pkg/helmchart"
)

// The helm binary in the payload.
//
// helm is the helm controller's Job command[0]. Like kubectl it is a pinned
// third-party binary staged beside the control plane, and it travels the same
// path: `k3sm payload` downloads the pinned tarball, verifies it against
// helmchart.HelmSHA256 BEFORE anything else touches it, extracts the one binary
// as helmchart.HelmBinaryName, and signs it; `k3sm install` stages the payload;
// seedBinDir copies it into the work dir's bin at boot (it is in
// PayloadBinaries), and provision re-signs it there.
//
// The version is in the binary's name, so presence IS the version marker: a pin
// bump stages a new file beside the old one rather than trusting it.
//
// EnsureHelm is the dev-shell fallback, the analog of the control plane's `gh`
// re-stage: it downloads only when the work dir has no staged helm AND `gh` is
// on PATH. A launchd daemon never has `gh`, so a packaged install whose payload
// lacked helm gets ErrHelmNotStaged and never reaches the network from the
// daemon; a dev shell (which has `gh`) fetches and verifies the pin.

// helmTarballURL and helmTarballSHA256 are the pinned download. They are vars so
// a test can point them at a local server and its bytes' digest.
var (
	helmTarballURL    = helmchart.HelmURL()
	helmTarballSHA256 = helmchart.HelmSHA256
)

// maxHelmTarballBytes bounds the download, so a server that streams without end
// cannot fill the disk; a truncated stream then fails the digest check. The
// release tarball is about 20 MB. A var so a test can lower it.
var maxHelmTarballBytes int64 = 256 << 20

// maxHelmBinaryBytes bounds the extracted binary, so a tarball whose member
// claims an absurd size cannot fill the disk. helm v4.3.0 is about 63 MB.
const maxHelmBinaryBytes = 512 << 20

// ErrHelmDigestMismatch means the downloaded helm tarball is not the pinned
// bytes. Fatal by design, as ErrPayloadDigestMismatch is for the control plane.
var ErrHelmDigestMismatch = errors.New("helm tarball digest mismatch")

// ErrHelmNotStaged means the work dir has no staged helm and this process may
// not download one: it is not a dev shell (no `gh` on PATH), so it is a daemon
// whose payload lacked helm. The remedy is a reinstall with a current payload.
var ErrHelmNotStaged = errors.New("helm is not staged and this process does not download it (no `gh` on PATH: not a dev shell)")

// EnsureHelm returns the path of a staged helm in binDir. A staged copy is used
// as is (see the note above on why presence suffices) and re-signed. When none
// is staged it downloads and verifies the pinned release only in a dev shell
// (`gh` on PATH, the same gate as the control plane's re-stage); otherwise it
// returns ErrHelmNotStaged without touching the network.
func EnsureHelm(ctx context.Context, binDir string) (string, error) {
	if !fileExists(helmchart.HelmPath(binDir)) {
		if _, err := lookPathGh(); err != nil {
			return "", fmt.Errorf("%w: %s", ErrHelmNotStaged, helmchart.HelmPath(binDir))
		}
	}
	if err := stageHelm(ctx, binDir, false); err != nil {
		return "", err
	}
	return helmchart.HelmPath(binDir), nil
}

// stageHelm places a verified, signed helmchart.HelmBinaryName in bd. With
// force false an existing copy is kept; with force true (the packaging path,
// whose bytes are about to be published) it is always re-downloaded and
// re-verified.
func stageHelm(ctx context.Context, bd string, force bool) error {
	if err := helmchart.ValidateHelmPin(); err != nil {
		return err
	}
	dst := helmchart.HelmPath(bd)
	// Presence is trusted as the version marker because BinDir is root-owned
	// 0755 under the daemon: only root (install and the payload seed) can place
	// a file under the versioned name.
	if !force && fileExists(dst) {
		return signBinaries(ctx, bd, []string{helmchart.HelmBinaryName})
	}
	if err := os.MkdirAll(bd, 0o755); err != nil {
		return fmt.Errorf("create bin dir %s: %w", bd, err)
	}
	tgz, err := os.CreateTemp(bd, ".helm-download-*")
	if err != nil {
		return fmt.Errorf("stage helm download in %s: %w", bd, err)
	}
	defer func() { _ = os.Remove(tgz.Name()) }()
	defer func() { _ = tgz.Close() }()

	sum, err := downloadHashed(ctx, tgz, helmTarballURL)
	if err != nil {
		return err
	}
	if sum != helmTarballSHA256 {
		return fmt.Errorf("%w: %s from %s has sha256 %s, want %s", ErrHelmDigestMismatch, helmchart.HelmAsset, helmTarballURL, sum, helmTarballSHA256)
	}
	if _, err := tgz.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind helm tarball: %w", err)
	}
	tmp := dst + ".tmp"
	if err := extractMember(tgz, helmchart.HelmTarballMember, tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("install %s: %w", dst, err)
	}
	return signBinaries(ctx, bd, []string{helmchart.HelmBinaryName})
}

// downloadHashed streams url into w and returns the lowercase hex sha256 of the
// bytes written, taken on the way to disk. At most maxHelmTarballBytes are read;
// a longer body is truncated there and so fails the caller's digest check.
func downloadHashed(ctx context.Context, w io.Writer, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("request %s: %w", url, err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch %s: unexpected status %s", url, resp.Status)
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(resp.Body, maxHelmTarballBytes)); err != nil {
		return "", fmt.Errorf("download %s: %w", url, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// extractMember writes the regular file member of the gzipped tar r to dst
// (0755). It is an error when the member is absent, not a regular file, or
// larger than maxHelmBinaryBytes. Only the one named member is read, so no
// path in the archive is ever joined onto the file system.
func extractMember(r io.Reader, member, dst string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("open helm tarball: %w", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("helm tarball carries no %s", member)
		}
		if err != nil {
			return fmt.Errorf("read helm tarball: %w", err)
		}
		if filepath.Clean(hdr.Name) != member {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return fmt.Errorf("helm tarball member %s is not a regular file", member)
		}
		if hdr.Size > maxHelmBinaryBytes {
			return fmt.Errorf("helm tarball member %s is %d bytes, over the %d limit", member, hdr.Size, maxHelmBinaryBytes)
		}
		out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
		if err != nil {
			return fmt.Errorf("create %s: %w", dst, err)
		}
		if _, err := io.Copy(out, io.LimitReader(tr, maxHelmBinaryBytes)); err != nil {
			_ = out.Close()
			return fmt.Errorf("extract %s: %w", member, err)
		}
		return out.Close()
	}
}
