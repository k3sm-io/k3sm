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

package registryclient

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// The media types a manifest read accepts, in the order the Accept header lists
// them. An index is listed first so a multi-platform tag is returned whole
// rather than resolved to one platform by the registry.
const (
	MediaTypeOCIIndex        = "application/vnd.oci.image.index.v1+json"
	MediaTypeOCIManifest     = "application/vnd.oci.image.manifest.v1+json"
	MediaTypeDockerList      = "application/vnd.docker.distribution.manifest.list.v2+json"
	MediaTypeDockerManifest  = "application/vnd.docker.distribution.manifest.v2+json"
	acceptManifests          = MediaTypeOCIIndex + ", " + MediaTypeDockerList + ", " + MediaTypeOCIManifest + ", " + MediaTypeDockerManifest
	contentDigestHeader      = "Docker-Content-Digest"
	defaultRequestTimeout    = 10 * time.Second
	maxManifestBytes         = 4 << 20
	maxConfigBytes           = 1 << 20
	maxListBytes             = 4 << 20
	maxPages                 = 1000
	maxIndexDepth            = 2
	pageSize                 = 1000
	unknownPlatformComponent = "unknown"
)

// Sentinel errors a caller can branch on with errors.Is.
var (
	// ErrNotFound is a 404 from the registry: the repository, tag or manifest
	// does not exist (or no longer does — a tag deleted between the tag list
	// and the manifest read).
	ErrNotFound = errors.New("not found in the registry")
	// ErrUnauthorized is a 401 or 403: the registry refuses an anonymous read.
	ErrUnauthorized = errors.New("the registry refuses an anonymous read")
	// ErrDigestMismatch is a manifest whose bytes do not hash to the digest it
	// was requested by or the one the registry reported for it.
	ErrDigestMismatch = errors.New("manifest bytes do not match their digest")
)

// Options configure a Client. The zero value is a plain-HTTP-capable client
// with the default per-request timeout and the system trust store.
type Options struct {
	// Timeout bounds each request, headers and body together. Zero is 10s.
	Timeout time.Duration
	// RootCAs, when set, is the trust store for an https base URL.
	RootCAs *x509.CertPool
	// Transport replaces the HTTP transport; a test passes an in-process
	// handler's. When set, RootCAs is ignored.
	Transport http.RoundTripper
}

// Client reads one registry anonymously. It is safe for concurrent use.
type Client struct {
	base *url.URL
	http *http.Client
}

// New returns a Client for the registry at base, an http or https URL with no
// path ("http://127.0.0.1:6450").
func New(base string, opts Options) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("parse registry URL %q: %w", base, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("registry URL %q: scheme must be http or https", base)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("registry URL %q has no host", base)
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("registry URL %q: a path is not supported", base)
	}
	u.Path, u.RawQuery, u.Fragment = "", "", ""
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultRequestTimeout
	}
	rt := opts.Transport
	if rt == nil {
		// The registry is a cluster component, never reached through the
		// operator's HTTP proxy, so Proxy stays nil. This is built here rather
		// than cloned from http.DefaultTransport, which is shared global state.
		t := &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		}
		if opts.RootCAs != nil {
			t.TLSClientConfig = &tls.Config{RootCAs: opts.RootCAs, MinVersion: tls.VersionTLS12}
		}
		rt = t
	}
	return &Client{
		base: u,
		http: &http.Client{
			Timeout:   timeout,
			Transport: rt,
			// A registry read never needs a redirect off its own host; one is
			// refused rather than followed.
			CheckRedirect: func(req *http.Request, _ []*http.Request) error {
				if req.URL.Host != u.Host {
					return fmt.Errorf("refusing a redirect to another host %q", req.URL.Host)
				}
				return nil
			},
		},
	}, nil
}

// Host is the registry's host:port, as the client dials it.
func (c *Client) Host() string { return c.base.Host }

// Descriptor is an OCI content descriptor.
type Descriptor struct {
	MediaType string    `json:"mediaType,omitempty"`
	Digest    string    `json:"digest"`
	Size      int64     `json:"size"`
	Platform  *Platform `json:"platform,omitempty"`
}

// Platform is an OCI platform.
type Platform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
}

// String renders os/arch[/variant].
func (p Platform) String() string {
	s := p.OS + "/" + p.Architecture
	if p.Variant != "" {
		s += "/" + p.Variant
	}
	return s
}

// Manifest is a manifest or an index as read from the registry. Exactly one of
// Config (a manifest) and Manifests (an index) is set.
type Manifest struct {
	// Digest is the digest of the bytes read, verified.
	Digest string
	// MediaType is the manifest's own media type.
	MediaType string
	// Size is the byte length of the manifest body.
	Size      int64
	Config    *Descriptor
	Layers    []Descriptor
	Manifests []Descriptor
}

// IsIndex reports whether m is an image index (a manifest list).
func (m Manifest) IsIndex() bool {
	return m.MediaType == MediaTypeOCIIndex || m.MediaType == MediaTypeDockerList
}

// repositoryPattern is the distribution spec's repository name grammar. A name
// from the catalog is checked against it before it is put in a URL path, so a
// hostile catalog cannot steer a read at another endpoint.
var repositoryPattern = regexp.MustCompile(`^[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*)*$`)

// tagPattern is the distribution spec's tag grammar.
var tagPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)

// digestPattern accepts the sha256 digests this client can verify.
var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// ValidRepository reports whether name is a well-formed repository name.
func ValidRepository(name string) bool {
	return len(name) <= 255 && repositoryPattern.MatchString(name)
}

// ValidTag reports whether tag is a well-formed tag.
func ValidTag(tag string) bool { return tagPattern.MatchString(tag) }

// Catalog lists every repository, following pagination.
func (c *Client) Catalog(ctx context.Context) ([]string, error) {
	var out []string
	err := c.paginate(ctx, "/v2/_catalog", func(body []byte) error {
		var page struct {
			Repositories []string `json:"repositories"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("decode the catalog: %w", err)
		}
		out = append(out, page.Repositories...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Tags lists a repository's tags, following pagination. A repository with no
// tags (every manifest untagged) yields an empty list.
func (c *Client) Tags(ctx context.Context, repository string) ([]string, error) {
	if !ValidRepository(repository) {
		return nil, fmt.Errorf("invalid repository name %q", repository)
	}
	var out []string
	err := c.paginate(ctx, "/v2/"+repository+"/tags/list", func(body []byte) error {
		var page struct {
			Tags []string `json:"tags"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("decode the tag list of %s: %w", repository, err)
		}
		out = append(out, page.Tags...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Manifest reads a manifest or index by tag or digest. The bytes are hashed and
// must match the digest asked for (a digest reference) and the digest the
// registry reported (Docker-Content-Digest), whichever are present.
func (c *Client) Manifest(ctx context.Context, repository, reference string) (Manifest, error) {
	if !ValidRepository(repository) {
		return Manifest{}, fmt.Errorf("invalid repository name %q", repository)
	}
	byDigest := digestPattern.MatchString(reference)
	if !byDigest && !ValidTag(reference) {
		return Manifest{}, fmt.Errorf("invalid tag or digest %q", reference)
	}
	resp, body, err := c.get(ctx, c.endpoint("/v2/"+repository+"/manifests/"+reference), acceptManifests, maxManifestBytes)
	if err != nil {
		return Manifest{}, fmt.Errorf("read manifest %s:%s: %w", repository, reference, err)
	}
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if byDigest && digest != reference {
		return Manifest{}, fmt.Errorf("manifest %s@%s hashes to %s: %w", repository, reference, digest, ErrDigestMismatch)
	}
	if reported := resp.Header.Get(contentDigestHeader); reported != "" && reported != digest {
		return Manifest{}, fmt.Errorf("manifest %s:%s is reported as %s but hashes to %s: %w", repository, reference, reported, digest, ErrDigestMismatch)
	}
	var raw struct {
		MediaType string       `json:"mediaType"`
		Config    *Descriptor  `json:"config"`
		Layers    []Descriptor `json:"layers"`
		Manifests []Descriptor `json:"manifests"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest %s:%s: %w", repository, reference, err)
	}
	mt := mediaTypeOf(resp.Header.Get("Content-Type"))
	if mt == "" || mt == "application/json" {
		mt = raw.MediaType
	}
	if mt == "" {
		// An OCI document may omit mediaType; its shape is then the answer.
		mt = MediaTypeOCIManifest
		if raw.Manifests != nil {
			mt = MediaTypeOCIIndex
		}
	}
	m := Manifest{Digest: digest, MediaType: mt, Size: int64(len(body))}
	switch mt {
	case MediaTypeOCIIndex, MediaTypeDockerList:
		m.Manifests = raw.Manifests
	case MediaTypeOCIManifest, MediaTypeDockerManifest:
		if raw.Config == nil {
			return Manifest{}, fmt.Errorf("manifest %s:%s has no config descriptor", repository, reference)
		}
		m.Config, m.Layers = raw.Config, raw.Layers
	default:
		return Manifest{}, fmt.Errorf("manifest %s:%s has unsupported media type %q", repository, reference, mt)
	}
	return m, nil
}

// ConfigPlatform reads an image config blob and returns the platform it
// records. The blob is re-hashed against its digest.
func (c *Client) ConfigPlatform(ctx context.Context, repository string, config Descriptor) (Platform, error) {
	if !ValidRepository(repository) {
		return Platform{}, fmt.Errorf("invalid repository name %q", repository)
	}
	if !digestPattern.MatchString(config.Digest) {
		return Platform{}, fmt.Errorf("config of %s has an unverifiable digest %q", repository, config.Digest)
	}
	_, body, err := c.get(ctx, c.endpoint("/v2/"+repository+"/blobs/"+config.Digest), "", maxConfigBytes)
	if err != nil {
		return Platform{}, fmt.Errorf("read config %s@%s: %w", repository, config.Digest, err)
	}
	sum := sha256.Sum256(body)
	if got := "sha256:" + hex.EncodeToString(sum[:]); got != config.Digest {
		return Platform{}, fmt.Errorf("config %s@%s hashes to %s: %w", repository, config.Digest, got, ErrDigestMismatch)
	}
	var p Platform
	if err := json.Unmarshal(body, &p); err != nil {
		return Platform{}, fmt.Errorf("decode config %s@%s: %w", repository, config.Digest, err)
	}
	return p, nil
}

// Image is one tag's content as the registry holds it.
type Image struct {
	Repository string
	Tag        string
	// Digest is what the tag points at: the index digest for a
	// multi-platform image, else the manifest's.
	Digest string
	// Platforms are the os/arch[/variant] the image runs on, in the index's
	// order. Attestation entries (unknown/unknown) are not platforms.
	Platforms []string
	// SizeBytes is the sum of the image's distinct config and layer blobs,
	// across every manifest the tag reaches.
	SizeBytes int64
	// Blobs is every distinct blob the tag reaches, manifests included, by
	// digest with its size: the input to a registry-wide byte count that must
	// not count a shared layer twice.
	Blobs map[string]int64
}

// Describe reads what a tag points at: its digest, its platforms, its size and
// every blob it reaches.
func (c *Client) Describe(ctx context.Context, repository, tag string) (Image, error) {
	img := Image{Repository: repository, Tag: tag, Blobs: map[string]int64{}}
	top, err := c.Manifest(ctx, repository, tag)
	if err != nil {
		return Image{}, err
	}
	img.Digest = top.Digest
	content := map[string]int64{}
	if err := c.walk(ctx, repository, top, nil, 0, &img, content); err != nil {
		return Image{}, err
	}
	for _, size := range content {
		img.SizeBytes += size
	}
	return img, nil
}

// walk accumulates m's blobs, and its children's when m is an index. platform
// is the platform the parent index declared for m, nil at the top.
func (c *Client) walk(ctx context.Context, repository string, m Manifest, platform *Platform, depth int, img *Image, content map[string]int64) error {
	img.Blobs[m.Digest] = m.Size
	if m.IsIndex() {
		if depth >= maxIndexDepth {
			return fmt.Errorf("image %s:%s nests indexes deeper than %d", repository, img.Tag, maxIndexDepth)
		}
		for _, child := range m.Manifests {
			cm, err := c.Manifest(ctx, repository, child.Digest)
			if err != nil {
				return err
			}
			if err := c.walk(ctx, repository, cm, child.Platform, depth+1, img, content); err != nil {
				return err
			}
		}
		return nil
	}
	img.Blobs[m.Config.Digest] = m.Config.Size
	content[m.Config.Digest] = m.Config.Size
	for _, l := range m.Layers {
		img.Blobs[l.Digest] = l.Size
		content[l.Digest] = l.Size
	}
	if platform == nil {
		p, err := c.ConfigPlatform(ctx, repository, *m.Config)
		if err != nil {
			return err
		}
		platform = &p
	}
	if platform.OS == unknownPlatformComponent || platform.OS == "" {
		return nil // an attestation manifest, or a config naming no platform
	}
	s := platform.String()
	for _, have := range img.Platforms {
		if have == s {
			return nil
		}
	}
	img.Platforms = append(img.Platforms, s)
	return nil
}

// paginate GETs path and every page its Link headers name, handing each body
// to page.
func (c *Client) paginate(ctx context.Context, path string, page func([]byte) error) error {
	next := c.endpoint(path)
	q := next.Query()
	q.Set("n", fmt.Sprint(pageSize))
	next.RawQuery = q.Encode()
	for i := 0; next != nil; i++ {
		if i >= maxPages {
			return fmt.Errorf("%s: more than %d pages", path, maxPages)
		}
		resp, body, err := c.get(ctx, next, "application/json", maxListBytes)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		if err := page(body); err != nil {
			return err
		}
		next, err = c.nextLink(next, resp.Header.Get("Link"))
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
	}
	return nil
}

// nextLink returns the rel="next" target of a Link header, resolved against
// the current URL, or nil when there is none. A link to another host is an
// error: a registry's pagination never leaves the registry.
func (c *Client) nextLink(current *url.URL, header string) (*url.URL, error) {
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		start, end := strings.Index(part, "<"), strings.Index(part, ">")
		if start != 0 || end < 0 {
			continue
		}
		if !strings.Contains(strings.ReplaceAll(part[end+1:], " ", ""), `rel="next"`) {
			continue
		}
		ref, err := url.Parse(part[start+1 : end])
		if err != nil {
			return nil, fmt.Errorf("parse the next-page link: %w", err)
		}
		u := current.ResolveReference(ref)
		if u.Host != c.base.Host || u.Scheme != c.base.Scheme {
			return nil, fmt.Errorf("refusing a next-page link to %s", u.Host)
		}
		return u, nil
	}
	return nil, nil
}

// endpoint is the base URL with path.
func (c *Client) endpoint(path string) *url.URL {
	u := *c.base
	u.Path = path
	return &u
}

// get performs one anonymous GET and reads at most limit bytes of body. A
// non-200 answer is an error; 404 and 401/403 map to the sentinels.
func (c *Client) get(ctx context.Context, u *url.URL, accept string, limit int64) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, nil, ErrNotFound
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, nil, ErrUnauthorized
	case resp.StatusCode != http.StatusOK:
		return nil, nil, fmt.Errorf("registry answered %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read the response body: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, nil, fmt.Errorf("response body exceeds %d bytes", limit)
	}
	return resp, body, nil
}

// mediaTypeOf strips parameters from a Content-Type value.
func mediaTypeOf(contentType string) string {
	mt, _, _ := strings.Cut(contentType, ";")
	return strings.TrimSpace(mt)
}
