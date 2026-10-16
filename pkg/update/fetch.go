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
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// MaxArchiveBytes bounds the release archive a node downloads.
const MaxArchiveBytes int64 = 512 << 20

// DownloadTimeout bounds one archive download, well inside the controller's
// 30-minute node timeout so the install that follows has room to finish.
const DownloadTimeout = 10 * time.Minute

// maxRedirects bounds the redirects one fetch follows.
const maxRedirects = 5

// Fetcher fetches the release archive at a URL CheckURL accepted. The caller
// closes the body and bounds what it reads.
type Fetcher interface {
	Fetch(ctx context.Context, rawURL string) (io.ReadCloser, error)
}

// HTTPFetcher is the production Fetcher: a plain GET that follows at most
// five redirects, every one of them to a URL its Pin admits, and refuses a
// response that is not 200 or announces more than MaxArchiveBytes.
type HTTPFetcher struct {
	// Pin judges the URL and every redirect; the zero pin is AllowedHosts.
	Pin HostPin
	// Client is the HTTP client; nil uses a fresh client with the redirect
	// policy and a DownloadTimeout bound. A supplied client's own redirect
	// policy is replaced for the fetch.
	Client *http.Client
}

// Fetch implements Fetcher.
func (f HTTPFetcher) Fetch(ctx context.Context, rawURL string) (io.ReadCloser, error) {
	if err := f.Pin.CheckRaw(rawURL); err != nil {
		return nil, err
	}
	c := http.Client{Timeout: DownloadTimeout}
	if f.Client != nil {
		c = *f.Client
	}
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("%w: more than %d redirects", ErrRefused, maxRedirects)
		}
		return f.Pin.Check(req.URL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build the archive request: %w", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		// A redirect the policy refused arrives wrapped in a *url.Error, and
		// still matches ErrRefused through it.
		return nil, fmt.Errorf("fetch the archive: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("fetch the archive: http %s", resp.Status)
	}
	// The redirect policy judged every hop; this binds the bytes to the last.
	if resp.Request != nil && resp.Request.URL != nil {
		if err := f.Pin.Check(resp.Request.URL); err != nil {
			_ = resp.Body.Close()
			return nil, err
		}
	}
	if resp.ContentLength > MaxArchiveBytes {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%w: the archive is %d bytes, more than %d", ErrRefused, resp.ContentLength, MaxArchiveBytes)
	}
	return resp.Body, nil
}
