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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"k3sm.io/k3sm/pkg/status"
	"k3sm.io/k3sm/pkg/version"
)

// DefaultBaseURL is the release index install.sh reads.
const DefaultBaseURL = "https://github.com/k3sm-io/k3sm/releases"

// DefaultTimeout bounds every request a check makes to the release index.
const DefaultTimeout = 15 * time.Second

// maxIndexBytes caps how much of a release index response is read: one page
// of a hundred releases with their notes is well under it.
const maxIndexBytes = 8 << 20

// Inputs is what a check reads. Every field but Installed is optional.
type Inputs struct {
	// BaseURL is the release index, DefaultBaseURL when empty. The canonical
	// github.com/<owner>/<repo>/releases maps to its api.github.com form for the
	// releases API; any other URL (a mirror, a test server) is queried at
	// BaseURL itself, as install.sh does.
	BaseURL string
	// HTTP is the client the index is read with; nil is a plain client.
	HTTP *http.Client
	// Timeout bounds the index reads, DefaultTimeout when zero.
	Timeout time.Duration
	// Kube lists the cluster's Nodes; nil reports no nodes.
	Kube kubernetes.Interface
	// Installed is the running binary's version (version.Get()).
	Installed version.Info
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// Release is the latest release as the index describes it.
type Release struct {
	Tag string `json:"tag"`
	// Published is the publication time, RFC 3339; empty when the releases API
	// did not answer.
	Published string `json:"published,omitempty"`
	// KubeVersion is the Kubernetes version the release ships, read from its
	// notes; empty when they do not say.
	KubeVersion string `json:"kubeVersion,omitempty"`
}

// Node is one Node and how its k3sm compares with the latest release.
type Node struct {
	Name string `json:"name"`
	// Version is status.nodeInfo.kubeletVersion as the node reports it.
	Version string `json:"version"`
	// State is status.UpdateCurrent, UpdateBehind, UpdateAhead or
	// UpdateUnknown.
	State string `json:"state"`
}

// Report is the answer of one check. Its JSON is `k3sm update check -o json`.
type Report struct {
	CheckedAt time.Time `json:"checkedAt"`
	Latest    Release   `json:"latest"`
	// Installed is this binary's version, InstalledDirty whether it was built
	// from a modified tree, and InstalledState how it compares.
	Installed      string `json:"installed"`
	InstalledDirty bool   `json:"installedDirty,omitempty"`
	InstalledState string `json:"installedState,omitempty"`
	// Nodes is every Node, sorted by name; empty when no cluster was asked.
	Nodes []Node `json:"nodes"`
}

// Record is the report as `k3sm status` reads it, with err (the check's
// failure, nil when it finished) as its error text, control-stripped and
// clipped to status.UpdateErrorMax bytes.
func (r Report) Record(err error) status.UpdateRecord {
	rec := status.UpdateRecord{
		CheckedAt:      r.CheckedAt,
		Latest:         r.Latest.Tag,
		Published:      r.Latest.Published,
		KubeVersion:    r.Latest.KubeVersion,
		Installed:      r.Installed,
		InstalledDirty: r.InstalledDirty,
		InstalledState: r.InstalledState,
	}
	if err != nil {
		rec.Error = status.ClipText(err.Error(), status.UpdateErrorMax)
	}
	for _, n := range r.Nodes {
		rec.Nodes = append(rec.Nodes, status.UpdateNode{Name: n.Name, Version: n.Version, State: n.State})
	}
	return rec
}

// Check resolves the latest release, then compares this binary and every Node
// with it. The error says why a step failed; the report carries what was
// learned before it.
func Check(ctx context.Context, in Inputs) (Report, error) {
	now := time.Now
	if in.Now != nil {
		now = in.Now
	}
	rep := Report{CheckedAt: now().UTC(), Installed: in.Installed.Version, InstalledDirty: in.Installed.Dirty, Nodes: []Node{}}
	rel, err := Latest(ctx, in)
	if err != nil {
		return rep, fmt.Errorf("resolve the latest release: %w", err)
	}
	rep.Latest = rel
	rep.InstalledState = installedState(in.Installed, rel.Tag)
	if in.Kube == nil {
		return rep, nil
	}
	list, err := in.Kube.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return rep, fmt.Errorf("list nodes: %w", err)
	}
	for _, n := range list.Items {
		v := n.Status.NodeInfo.KubeletVersion
		rep.Nodes = append(rep.Nodes, Node{Name: n.Name, Version: v, State: status.NodeReleaseState(v, rel.Tag)})
	}
	sort.Slice(rep.Nodes, func(i, j int) bool { return rep.Nodes[i].Name < rep.Nodes[j].Name })
	return rep, nil
}

// Latest resolves the latest release the way install.sh does: the stable
// channel through the index's `latest` redirect, which skips prereleases;
// when that lands on no tag (before the first stable release), the newest
// non-draft release of any kind by publication time. The same fallback applies
// when the stable lookup fails for a reason other than a malformed tag or a
// refused redirect, in which case a failure of the fallback reports both
// errors. A stable release, once
// one exists, therefore always wins.
func Latest(ctx context.Context, in Inputs) (Release, error) {
	timeout := in.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	base := strings.TrimRight(in.BaseURL, "/")
	if base == "" {
		base = DefaultBaseURL
	}
	r := reader{client: noDowngrade(in.HTTP), base: base, ua: "k3sm/" + in.Installed.Version}

	tag, stableErr := r.stableTag(ctx)
	if errors.Is(stableErr, errBadTag) || errors.Is(stableErr, errRedirectPin) {
		return Release{}, stableErr
	}
	if tag == "" {
		rel, err := r.newestAny(ctx)
		if err != nil {
			return Release{}, errors.Join(stableErr, err)
		}
		if rel.Tag == "" {
			return Release{}, errors.Join(stableErr, fmt.Errorf("no k3sm release found at %s", base))
		}
		return rel, nil
	}
	// The tag is known; its date and notes are a second read, and a failure
	// there (an API rate limit) leaves them empty rather than losing the tag.
	rel, err := r.byTag(ctx, tag)
	if err != nil || rel.Tag != tag {
		return Release{Tag: tag}, nil
	}
	return rel, nil
}

// reader reads one release index.
type reader struct {
	client *http.Client
	base   string
	ua     string
}

// noDowngrade copies c (nil: a plain client) with a redirect policy that never
// leaves https for http.
func noDowngrade(c *http.Client) *http.Client {
	out := &http.Client{}
	if c != nil {
		cp := *c
		out = &cp
	}
	next := out.CheckRedirect
	out.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 0 && via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
			return fmt.Errorf("refusing a redirect from https to %s", req.URL.Redacted())
		}
		if next != nil {
			return next(req, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	return out
}

// apiBase is the releases API for the index: api.github.com for the canonical
// GitHub URL, the index itself otherwise.
func (r reader) apiBase() string {
	if rest, ok := strings.CutPrefix(r.base, "https://github.com/"); ok {
		return "https://api.github.com/repos/" + rest
	}
	return r.base
}

// stableTag follows the index's `latest` redirect and returns the tag it lands
// on, or "" when it lands anywhere but a /tag/<tag> page.
func (r reader) stableTag(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, r.base+"/latest", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", r.ua)
	resp, err := r.client.Do(req)
	if err != nil {
		return "", err
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("%s/latest: %s", r.base, resp.Status)
	}
	return pinnedTag(r.base, resp.Request.URL)
}

// pinnedTag is the tag the `latest` redirect landed on, held to the index it
// was asked of: the final URL must be on the base URL's host, and its path the
// base path itself (no stable release yet: "") or <base path>/tag/<tag>
// (for DefaultBaseURL, /k3sm-io/k3sm/releases/tag/). Anywhere else is refused,
// so a redirect cannot hand the check another repository's tag.
func pinnedTag(base string, final *url.URL) (string, error) {
	b, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(final.Host, b.Host) {
		return "", fmt.Errorf("%w to another host: %s", errRedirectPin, final.Redacted())
	}
	basePath := strings.TrimRight(b.Path, "/")
	if strings.TrimRight(final.Path, "/") == basePath {
		return "", nil
	}
	escaped, ok := strings.CutPrefix(final.EscapedPath(), basePath+"/tag/")
	if !ok || escaped == "" || strings.Contains(escaped, "/") {
		return "", fmt.Errorf("%w outside %s/tag/: %s", errRedirectPin, basePath, final.Redacted())
	}
	tag, err := url.PathUnescape(escaped)
	if err != nil {
		return "", err
	}
	if !ValidTag(tag) {
		return "", fmt.Errorf("%w %q", errBadTag, tag)
	}
	return tag, nil
}

// errRedirectPin is a `latest` redirect that left the index (pinnedTag).
var errRedirectPin = errors.New("refusing the latest-release redirect")

// errBadTag is a stable tag outside ValidTag. It is final, as in install.sh:
// the stable channel answered, and with something no release can be.
var errBadTag = errors.New("refusing an unusable release tag")

// apiRelease is the slice of the GitHub release JSON a check reads.
type apiRelease struct {
	TagName     string     `json:"tag_name"`
	Draft       bool       `json:"draft"`
	PublishedAt *time.Time `json:"published_at"`
	Body        string     `json:"body"`
}

// release converts an API release, or false when it is unusable.
func (a apiRelease) release() (Release, bool) {
	if a.Draft || a.PublishedAt == nil || !ValidTag(a.TagName) {
		return Release{}, false
	}
	return Release{
		Tag:         a.TagName,
		Published:   a.PublishedAt.UTC().Format(time.RFC3339),
		KubeVersion: kubeVersionFrom(a.Body),
	}, true
}

// byTag reads one release from the releases API.
func (r reader) byTag(ctx context.Context, tag string) (Release, error) {
	var a apiRelease
	if err := r.getJSON(ctx, r.apiBase()+"/tags/"+url.PathEscape(tag), &a); err != nil {
		return Release{}, err
	}
	rel, ok := a.release()
	if !ok {
		return Release{}, fmt.Errorf("release %s is not published", tag)
	}
	return rel, nil
}

// newestAny is the newest published release of any kind, prereleases included,
// chosen by publication time because the list is not ordered newest-first. One
// page of a hundred, as install.sh reads.
func (r reader) newestAny(ctx context.Context) (Release, error) {
	var list []apiRelease
	if err := r.getJSON(ctx, r.apiBase()+"?per_page=100", &list); err != nil {
		return Release{}, err
	}
	var best Release
	var bestAt time.Time
	for _, a := range list {
		rel, ok := a.release()
		if ok && a.PublishedAt.After(bestAt) {
			best, bestAt = rel, *a.PublishedAt
		}
	}
	return best, nil
}

// getJSON GETs u and decodes at most maxIndexBytes of it into v.
func (r reader) getJSON(ctx context.Context, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", r.ua)
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", resp.Request.URL.Redacted(), resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxIndexBytes)).Decode(v); err != nil {
		return fmt.Errorf("decode %s: %w", resp.Request.URL.Redacted(), err)
	}
	return nil
}

// ValidTag reports whether tag is a usable release tag (version.ValidTag,
// install.sh's valid_tag).
func ValidTag(tag string) bool { return version.ValidTag(tag) }

// kubeVersionNote is how release notes name the Kubernetes version a release
// ships ("The control plane runs Kubernetes v1.37.1"). k3sm publishes no
// separate asset manifest, so the notes are the only source.
var kubeVersionNote = regexp.MustCompile(`runs Kubernetes (v\d+\.\d+\.\d+)\b`)

// kubeVersionFrom is the Kubernetes version body names, or "".
func kubeVersionFrom(body string) string {
	if m := kubeVersionNote.FindStringSubmatch(body); m != nil {
		return m[1]
	}
	return ""
}

// installedState compares this binary's version with tag. A binary built from
// a modified tree is not the release, whatever it is stamped, so it compares
// as unknown, like a dev build.
func installedState(v version.Info, tag string) string {
	if v.Dirty {
		return status.UpdateUnknown
	}
	return status.ReleaseState(v.Version, tag)
}
