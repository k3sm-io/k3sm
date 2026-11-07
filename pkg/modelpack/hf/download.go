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

package hf

import (
	"context"
	"crypto/sha1" // the git blob id is sha1 by definition
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"
)

// maxAttempts is how many times one file's transfer is tried, each attempt
// resuming where the last stopped.
const maxAttempts = 5

// copyBufferBytes is the size of the buffer a transfer copies through.
const copyBufferBytes = 1 << 20

var (
	// ErrHashMismatch is a file whose bytes are not the ones the Hub's
	// listing (or the caller) names.
	ErrHashMismatch = errors.New("content does not match its hash")
	// ErrSizeMismatch is a transfer that delivers more or fewer bytes than
	// the listing names.
	ErrSizeMismatch = errors.New("content does not match its listed size")
)

// file is one file to download: the listing's entry and, when the caller
// knows it, the sha256 the content must also have.
type file struct {
	Entry
	sha256 string
}

// verifier hashes a file's bytes as they arrive, and checks them against
// the commitments for it at the end.
type verifier struct {
	f    file
	sum  hash.Hash // sha256 of the content
	blob hash.Hash // git blob id, for a small file
}

func newVerifier(f file) *verifier {
	v := &verifier{f: f}
	v.reset()
	return v
}

// reset starts the hashes over, for a transfer that restarts from byte 0.
func (v *verifier) reset() {
	v.sum = sha256.New()
	v.blob = nil
	if v.f.LFS == nil {
		v.blob = sha1.New()
		fmt.Fprintf(v.blob, "blob %d\x00", v.f.Size)
	}
}

func (v *verifier) Write(p []byte) (int, error) {
	v.sum.Write(p)
	if v.blob != nil {
		v.blob.Write(p)
	}
	return len(p), nil
}

// check compares the hashes with the listing: the LFS sha256, or the git
// blob id, and the caller's sha256 when given.
func (v *verifier) check() error {
	got := hex.EncodeToString(v.sum.Sum(nil))
	if v.f.LFS != nil && got != v.f.LFS.OID {
		return fmt.Errorf("%s: sha256 %s, the Hub names %s: %w", v.f.Path, got, v.f.LFS.OID, ErrHashMismatch)
	}
	if v.blob != nil {
		if blob := hex.EncodeToString(v.blob.Sum(nil)); blob != v.f.OID {
			return fmt.Errorf("%s: git blob id %s, the Hub names %s: %w", v.f.Path, blob, v.f.OID, ErrHashMismatch)
		}
	}
	if v.f.sha256 != "" && got != v.f.sha256 {
		return fmt.Errorf("%s: sha256 %s, --sha256 names %s: %w", v.f.Path, got, v.f.sha256, ErrHashMismatch)
	}
	return nil
}

// download fetches f at commit into root, at f.Path, and verifies it. The
// file is created new (O_EXCL, O_NOFOLLOW) under root, which no path can
// leave. A transfer that breaks is resumed with a Range request, up to
// maxAttempts in all; a response that contradicts the listing ends it.
func (c *Client) download(ctx context.Context, root *os.Root, repo, commit string, f file) error {
	if dir := path.Dir(f.Path); dir != "." {
		if err := root.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	out, err := root.OpenFile(f.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", f.Path, err)
	}
	defer out.Close()

	v := newVerifier(f)
	u := c.url("/" + repoPath(repo) + "/resolve/" + commit + "/" + escapePath(f.Path))
	buf := make([]byte, copyBufferBytes)
	var written int64
	for attempt := 1; ; attempt++ {
		pos, retry, err := c.transfer(ctx, u, commit, f, written, out, v, buf)
		written = pos
		if err == nil {
			break
		}
		if !retry || ctx.Err() != nil {
			return err
		}
		if attempt == maxAttempts {
			return fmt.Errorf("%s: gave up after %d attempts: %w", f.Path, maxAttempts, err)
		}
	}
	if written != f.Size {
		return fmt.Errorf("%s: %d bytes, the Hub lists %d: %w", f.Path, written, f.Size, ErrSizeMismatch)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("write %s: %w", f.Path, err)
	}
	return v.check()
}

// transfer runs one attempt: it asks for f from byte offset (the whole file
// when 0), checks the response against the listing, and appends the body to
// out. It returns how many bytes out now holds, whether a failure may be
// retried, and the failure. A server that ignores the Range starts the file
// over from byte 0.
func (c *Client) transfer(ctx context.Context, u *url.URL, commit string, f file, offset int64, out *os.File, v *verifier, buf []byte) (int64, bool, error) {
	h := http.Header{"Accept-Encoding": {"identity"}}
	if offset > 0 {
		h.Set("Range", "bytes="+strconv.FormatInt(offset, 10)+"-")
	}
	resp, first, err := c.get(ctx, u, h)
	if err != nil {
		return offset, !errors.Is(err, ErrRedirectRefused), fmt.Errorf("download %s: %w", f.Path, err)
	}
	defer resp.Body.Close()
	if err := checkHop(f, commit, first, resp); err != nil {
		return offset, false, err
	}
	switch {
	case resp.StatusCode == http.StatusOK && offset > 0:
		if err := restart(out, v); err != nil {
			return offset, false, err
		}
		offset = 0
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusPartialContent && offset > 0:
		want := fmt.Sprintf("bytes %d-%d/%d", offset, f.Size-1, f.Size)
		if got := resp.Header.Get("Content-Range"); got != want {
			return offset, false, fmt.Errorf("download %s: Content-Range %q, want %q: %w", f.Path, cleanMessage(got), want, ErrBadResponse)
		}
	case resp.StatusCode >= 500:
		return offset, true, statusError("download "+f.Path, resp)
	default:
		return offset, false, statusError("download "+f.Path, resp)
	}
	n, retry, err := copyBody(f, offset, resp, out, v, buf)
	return offset + n, retry, err
}

// checkHop checks the headers the Hub sends on a resolve against the
// listing, for any it sets: the commit, the content's sha256 (on an LFS
// file's redirect), and the content encoding, which must be none.
func checkHop(f file, commit string, first hop, resp *http.Response) error {
	for _, c := range []string{first.repoCommit, resp.Header.Get("X-Repo-Commit")} {
		if c != "" && c != commit {
			return fmt.Errorf("download %s: the Hub served commit %q, not %s: %w", f.Path, cleanMessage(c), commit, ErrBadResponse)
		}
	}
	if f.LFS != nil {
		etag := first.linkedEtag
		if !first.seen {
			etag = resp.Header.Get("X-Linked-Etag")
		}
		if etag != "" {
			e := strings.Trim(strings.TrimPrefix(etag, "W/"), `"`)
			if !isLowerHex(e, 64) {
				return fmt.Errorf("download %s: X-Linked-Etag %q is not a sha256: %w", f.Path, cleanMessage(etag), ErrBadResponse)
			}
			if e != f.LFS.OID {
				return fmt.Errorf("download %s: the Hub's redirect names sha256 %s, the listing %s: %w", f.Path, e, f.LFS.OID, ErrHashMismatch)
			}
		}
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && !strings.EqualFold(ce, "identity") {
		return fmt.Errorf("download %s: Content-Encoding %q: %w", f.Path, cleanMessage(ce), ErrBadResponse)
	}
	return nil
}

// restart truncates out and starts v over.
func restart(out *os.File, v *verifier) error {
	if err := out.Truncate(0); err != nil {
		return fmt.Errorf("restart %s: %w", v.f.Path, err)
	}
	if _, err := out.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("restart %s: %w", v.f.Path, err)
	}
	v.reset()
	return nil
}

// copyBody appends resp's body to out from offset, refusing a declared or
// actual length other than the listing's. A body that breaks is retryable;
// one that runs long is not.
func copyBody(f file, offset int64, resp *http.Response, out *os.File, v *verifier, buf []byte) (int64, bool, error) {
	remain := f.Size - offset
	if resp.ContentLength >= 0 && resp.ContentLength != remain {
		return 0, false, fmt.Errorf("download %s: Content-Length %d, want %d: %w", f.Path, resp.ContentLength, remain, ErrSizeMismatch)
	}
	w := io.MultiWriter(out, v)
	n, err := io.CopyBuffer(w, io.LimitReader(resp.Body, remain), buf)
	if err != nil {
		return n, true, fmt.Errorf("download %s: %w", f.Path, err)
	}
	if n < remain {
		return n, true, fmt.Errorf("download %s: %w after %d of %d bytes", f.Path, io.ErrUnexpectedEOF, offset+n, f.Size)
	}
	var one [1]byte
	if m, _ := resp.Body.Read(one[:]); m > 0 {
		return n, false, fmt.Errorf("download %s: more than %d bytes: %w", f.Path, f.Size, ErrSizeMismatch)
	}
	return n, false, nil
}

// escapePath escapes each component of a validated path.
func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}
