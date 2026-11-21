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
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// DefaultEndpoint is the Hub.
const DefaultEndpoint = "https://huggingface.co"

// DefaultRedirectHosts are the hosts beside the endpoint's own that a
// download may be redirected to: the Hub's published LFS and Xet CDN hosts.
// A redirect anywhere else, or to anything but https, is refused.
var DefaultRedirectHosts = []string{
	"cdn-lfs.huggingface.co",
	"cdn-lfs-us-1.huggingface.co",
	"cdn-lfs-eu-1.huggingface.co",
	"cdn-lfs.hf.co",
	"cdn-lfs-us-1.hf.co",
	"cdn-lfs-eu-1.hf.co",
	"cas-bridge.xethub.hf.co",
}

// Bounds on what one response may make the client read or follow.
const (
	maxInfoBytes      = 1 << 20
	maxErrorBodyBytes = 64 << 10
	maxHeaderBytes    = 64 << 10
	maxRedirects      = 5
	maxErrorMessage   = 200
)

// The transport's timeouts. A transfer has no overall deadline (a large
// file takes as long as it takes); connecting, the TLS handshake and the
// wait for response headers are bounded.
const (
	dialTimeout           = 30 * time.Second
	tlsHandshakeTimeout   = 30 * time.Second
	responseHeaderTimeout = time.Minute
	idleConnTimeout       = 90 * time.Second
)

// Sentinel errors a caller can branch on with errors.Is.
var (
	// ErrGatedRepo is a repository that asks users to accept terms first.
	// The import is anonymous, so it cannot fetch one.
	ErrGatedRepo = errors.New("the repository is gated")
	// ErrRepoNotFound is a repository the Hub does not show to an anonymous
	// caller: it does not exist, or it is private.
	ErrRepoNotFound = errors.New("repository not found (or private)")
	// ErrRevisionNotFound is a revision the repository does not have.
	ErrRevisionNotFound = errors.New("revision not found")
	// ErrDisabled is a repository the Hub has disabled.
	ErrDisabled = errors.New("the repository is disabled")
	// ErrBadResponse is a response the client does not recognise: an
	// unexpected status, a malformed answer, or a header that contradicts
	// the listing.
	ErrBadResponse = errors.New("unrecognised Hub response")
	// ErrRedirectRefused is a redirect to a scheme other than https, or to
	// a host that is neither the endpoint's nor a listed CDN host.
	ErrRedirectRefused = errors.New("redirect refused")
)

// Options configures a Client. The zero value talks to the Hub through
// DefaultTransport.
type Options struct {
	// Endpoint is the Hub's base URL; DefaultEndpoint when empty. It must be
	// https with no path, query or user.
	Endpoint string
	// Transport carries the requests; DefaultTransport() when nil. The
	// client sends each request with RoundTrip and follows redirects itself,
	// so every Location, however malformed, meets its checks.
	Transport http.RoundTripper
	// RedirectHosts are the hosts (host or host:port) a request may be
	// redirected to besides the endpoint's own; DefaultRedirectHosts when
	// nil.
	RedirectHosts []string
	// UserAgent is sent on every request; "k3sm" when empty.
	UserAgent string
}

// Client is an anonymous Hub client.
type Client struct {
	base          *url.URL
	rt            http.RoundTripper
	redirectHosts []string
	userAgent     string
	// freeSpace measures the space left on the file system holding a
	// directory; statfsFree, or a test's fake.
	freeSpace func(dir string) (uint64, error)
}

// DefaultTransport is a transport with every phase before the body bounded:
// connect, TLS handshake (TLS 1.2 or later) and the wait for headers, and
// response headers capped at 64 KiB.
func DefaultTransport() *http.Transport {
	d := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy:                  http.ProxyFromEnvironment,
		DialContext:            d.DialContext,
		ForceAttemptHTTP2:      true,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    tlsHandshakeTimeout,
		ResponseHeaderTimeout:  responseHeaderTimeout,
		IdleConnTimeout:        idleConnTimeout,
		MaxResponseHeaderBytes: maxHeaderBytes,
	}
}

// NewClient returns a Client for o.
func NewClient(o Options) (*Client, error) {
	ep := o.Endpoint
	if ep == "" {
		ep = DefaultEndpoint
	}
	base, err := url.Parse(ep)
	if err != nil {
		return nil, fmt.Errorf("hub endpoint %q: %w", ep, err)
	}
	if base.Scheme != "https" || base.Host == "" || base.User != nil || (base.Path != "" && base.Path != "/") || base.RawQuery != "" || base.Fragment != "" {
		return nil, fmt.Errorf("hub endpoint %q: want https://<host> with no path, query or user", ep)
	}
	base.Path = ""
	t := o.Transport
	if t == nil {
		t = DefaultTransport()
	}
	hosts := o.RedirectHosts
	if hosts == nil {
		hosts = DefaultRedirectHosts
	}
	ua := o.UserAgent
	if ua == "" {
		ua = "k3sm"
	}
	return &Client{
		base:          base,
		rt:            t,
		redirectHosts: slices.Clone(hosts),
		userAgent:     ua,
		freeSpace:     statfsFree,
	}, nil
}

// url is the endpoint joined with the already-escaped path p.
func (c *Client) url(p string) *url.URL {
	u := *c.base
	u.RawPath = p
	if unescaped, err := url.PathUnescape(p); err == nil {
		u.Path = unescaped
	}
	return &u
}

// repoPath is the escaped "<org>/<name>" of repo, which ParseRef validated.
func repoPath(repo string) string {
	org, name, _ := strings.Cut(repo, "/")
	return url.PathEscape(org) + "/" + url.PathEscape(name)
}

// redirectAllowed reports whether a redirect to u may be followed.
func (c *Client) redirectAllowed(u *url.URL) bool {
	if u.Scheme != "https" || u.User != nil || u.Host == "" {
		return false
	}
	host := strings.TrimSuffix(u.Host, ":443")
	return host == strings.TrimSuffix(c.base.Host, ":443") || slices.Contains(c.redirectHosts, host)
}

// hop is a redirect response's headers the caller checks: the Hub puts the
// content's sha256 and the commit on its resolve redirect.
type hop struct {
	linkedEtag string
	repoCommit string
	seen       bool
}

// get sends a GET for u with header, following up to maxRedirects redirects
// to allowed https URLs. It returns the final response, which the caller
// closes, and the first redirect's headers.
func (c *Client) get(ctx context.Context, u *url.URL, header http.Header) (*http.Response, hop, error) {
	var first hop
	for n := 0; ; n++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, first, fmt.Errorf("request %s: %w", u.Redacted(), err)
		}
		for k, v := range header {
			req.Header[k] = slices.Clone(v)
		}
		req.Header.Set("User-Agent", c.userAgent)
		resp, err := c.rt.RoundTrip(req)
		if err != nil {
			return nil, first, fmt.Errorf("GET %s: %w", u.Redacted(), err)
		}
		switch resp.StatusCode {
		case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		default:
			return resp, first, nil
		}
		loc := resp.Header.Get("Location")
		if !first.seen {
			first = hop{seen: true, linkedEtag: resp.Header.Get("X-Linked-Etag"), repoCommit: resp.Header.Get("X-Repo-Commit")}
		}
		drain(resp)
		if n == maxRedirects {
			return nil, first, fmt.Errorf("%s: more than %d redirects: %w", u.Redacted(), maxRedirects, ErrRedirectRefused)
		}
		next, err := u.Parse(loc)
		if err != nil || loc == "" {
			return nil, first, fmt.Errorf("%s: redirect to %q: %w", u.Redacted(), cleanMessage(loc), ErrRedirectRefused)
		}
		if !c.redirectAllowed(next) {
			return nil, first, fmt.Errorf("%s: redirect to %q, which is neither https on the Hub nor a listed CDN host: %w", u.Redacted(), cleanMessage(next.Scheme+"://"+next.Host), ErrRedirectRefused)
		}
		u = next
	}
}

// drain reads and discards a bounded amount of resp's body and closes it, so
// the connection can be reused without trusting the body's length.
func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBodyBytes)) // best effort; the close below is what matters
	resp.Body.Close()
}

// statusError is the error for a non-success response, closing its body.
// The Hub names the cause in X-Error-Code; a known code maps to its
// sentinel, and the message it sends is shown cut to printable ASCII.
func statusError(what string, resp *http.Response) error {
	defer drain(resp)
	msg := cleanMessage(resp.Header.Get("X-Error-Message"))
	if msg != "" {
		msg = ": " + msg
	}
	var cause error
	switch resp.Header.Get("X-Error-Code") {
	case "GatedRepo":
		cause = ErrGatedRepo
	case "RepoNotFound":
		cause = ErrRepoNotFound
	case "RevisionNotFound":
		cause = ErrRevisionNotFound
	case "DisabledRepo":
		cause = ErrDisabled
	default:
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			cause = fmt.Errorf("the Hub refused an anonymous caller (gated, private or missing): %w", ErrBadResponse)
		case http.StatusNotFound:
			cause = fmt.Errorf("not found: %w", ErrBadResponse)
		case http.StatusTooManyRequests:
			cause = fmt.Errorf("rate limited, try again later: %w", ErrBadResponse)
		default:
			cause = ErrBadResponse
		}
	}
	return fmt.Errorf("%s: HTTP %d%s: %w", what, resp.StatusCode, msg, cause)
}

// cleanMessage is s cut to maxErrorMessage printable ASCII bytes, so a
// server message cannot write control sequences to a terminal.
func cleanMessage(s string) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < maxErrorMessage; i++ {
		if c := s[i]; c >= 0x20 && c < 0x7f {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// readBounded reads resp's body, refusing more than limit bytes.
func readBounded(what string, resp *http.Response, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: more than %d bytes: %w", what, limit, ErrBadResponse)
	}
	return b, nil
}

// revisionInfo is the part of the Hub's model info an import reads.
type revisionInfo struct {
	ID       string          `json:"id"`
	SHA      string          `json:"sha"`
	Gated    json.RawMessage `json:"gated"`
	Disabled bool            `json:"disabled"`
}

// Resolve asks the Hub for ref's revision and returns its 40-hex commit. A
// gated or disabled repository is refused here, before anything is listed
// or downloaded, and a commit revision must come back as itself.
func (c *Client) Resolve(ctx context.Context, ref Ref) (string, error) {
	what := "resolve " + ref.String()
	resp, _, err := c.get(ctx, c.url("/api/models/"+repoPath(ref.Repo)+"/revision/"+url.PathEscape(ref.Revision)), http.Header{"Accept": {"application/json"}})
	if err != nil {
		return "", fmt.Errorf("%s: %w", what, err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", statusError(what, resp)
	}
	b, err := readBounded(what, resp, maxInfoBytes)
	resp.Body.Close()
	if err != nil {
		return "", err
	}
	var info revisionInfo
	if err := json.Unmarshal(b, &info); err != nil {
		return "", fmt.Errorf("%s: %w: %v", what, ErrBadResponse, err)
	}
	if info.ID != "" && !strings.EqualFold(info.ID, ref.Repo) {
		return "", fmt.Errorf("%s: the Hub answered for %q; import it by that name: %w", what, cleanMessage(info.ID), ErrBadResponse)
	}
	if gated, err := isGated(info.Gated); err != nil {
		return "", fmt.Errorf("%s: %w", what, err)
	} else if gated {
		return "", fmt.Errorf("%s: %w: accept its terms on the Hub and download it yourself; k3sm imports anonymously and never sends a token", what, ErrGatedRepo)
	}
	if info.Disabled {
		return "", fmt.Errorf("%s: %w", what, ErrDisabled)
	}
	if !isCommit(info.SHA) {
		return "", fmt.Errorf("%s: commit %q is not 40 lowercase hex digits: %w", what, cleanMessage(info.SHA), ErrBadResponse)
	}
	if isCommit(ref.Revision) && info.SHA != ref.Revision {
		return "", fmt.Errorf("%s: the Hub answered with commit %s: %w", what, info.SHA, ErrBadResponse)
	}
	return info.SHA, nil
}

// isGated reads the info's gated field: absent or false is open, true or a
// gating mode ("auto", "manual") is gated, anything else is unrecognised.
func isGated(raw json.RawMessage) (bool, error) {
	if len(raw) == 0 {
		return false, nil
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b, nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil && s != "" {
		return true, nil
	}
	return false, fmt.Errorf("gated is %.40q: %w", raw, ErrBadResponse)
}

// Tree lists every entry of repo at commit, following the listing's pages.
// The pages together are bounded by MaxTreeBytes, MaxTreeEntries and
// maxTreePages, and a next page must be on the endpoint at the same path.
func (c *Client) Tree(ctx context.Context, repo, commit string) ([]Entry, error) {
	if !isCommit(commit) {
		return nil, fmt.Errorf("list %s: %q is not a commit", repo, commit)
	}
	what := "list " + Scheme + repo + "@" + commit
	treePath := "/api/models/" + repoPath(repo) + "/tree/" + commit
	u := c.url(treePath)
	u.RawQuery = "recursive=true&expand=false"
	var all []Entry
	var read int64
	for page := 0; ; page++ {
		if page == maxTreePages {
			return nil, fmt.Errorf("%s: more than %d pages: %w", what, maxTreePages, ErrBadListing)
		}
		resp, _, err := c.get(ctx, u, http.Header{"Accept": {"application/json"}})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", what, err)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, statusError(what, resp)
		}
		link := resp.Header.Get("Link")
		b, err := readBounded(what, resp, MaxTreeBytes-read)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("%w (%w)", err, ErrBadListing)
		}
		read += int64(len(b))
		entries, err := parseTree(b, MaxTreeEntries-len(all))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", what, err)
		}
		all = append(all, entries...)
		next, err := nextLink(link)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", what, err)
		}
		if next == "" {
			return all, nil
		}
		nu, err := u.Parse(next)
		if err != nil || nu.Scheme != "https" || nu.Host != c.base.Host || nu.EscapedPath() != treePath || nu.User != nil {
			return nil, fmt.Errorf("%s: next page %q is not this listing on the Hub: %w", what, cleanMessage(next), ErrBadListing)
		}
		u = nu
	}
}
