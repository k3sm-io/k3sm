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
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"

	updatesv1alpha1 "k3sm.io/apis/updates/v1alpha1"
)

// listing is a fake paged release index. It serves the `latest` redirect to
// stable, so a test can tell a channel read from a stable one (latestReads), and
// pages of the list by number, each page but the last naming the next in a Link
// header shaped like GitHub's, whose target is not the URL asked for.
type listing struct {
	stable string
	pages  [][]map[string]any
	// failPage answers that page (1-based) with a 503 when non-zero.
	failPage int
	// link, when set, replaces the Link header of every page.
	link string
	// more says the last page has a next page too.
	more bool
}

// serve is the listing's client, a count of `latest` reads and the pages read.
func (l listing) serve(t *testing.T) (c *http.Client, latestReads *int, pagesRead *[]int) {
	t.Helper()
	latestReads, pagesRead = new(int), new([]int)
	mux := http.NewServeMux()
	mux.HandleFunc(indexPath+"/latest", func(w http.ResponseWriter, r *http.Request) {
		*latestReads++
		http.Redirect(w, r, indexPath+"/tag/"+l.stable, http.StatusFound)
	})
	mux.HandleFunc(indexPath+"/tag/", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc(indexPath+"/tags/", func(w http.ResponseWriter, r *http.Request) {
		tag := strings.TrimPrefix(r.URL.Path, indexPath+"/tags/")
		for _, p := range l.pages {
			for _, rel := range p {
				if rel["tag_name"] == tag {
					_ = json.NewEncoder(w).Encode(rel)
					return
				}
			}
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc(indexPath, func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("per_page"); got != "100" {
			t.Errorf("listing read with per_page=%q", got)
		}
		page := 1
		if p := r.URL.Query().Get("page"); p != "" {
			var err error
			if page, err = strconv.Atoi(p); err != nil {
				t.Errorf("page = %q", p)
			}
		}
		*pagesRead = append(*pagesRead, page)
		if page == l.failPage {
			http.Error(w, "rate limited", http.StatusServiceUnavailable)
			return
		}
		switch {
		case l.link != "":
			w.Header().Set("Link", l.link)
		case page < len(l.pages) || l.more:
			w.Header().Set("Link", fmt.Sprintf(`<https://index.test/repositories/1/releases?per_page=100&page=%d>; rel="next", <https://index.test/repositories/1/releases?per_page=100&page=9>; rel="last"`, page+1))
		}
		var list []map[string]any
		if page >= 1 && page <= len(l.pages) {
			list = l.pages[page-1]
		}
		if list == nil {
			list = []map[string]any{}
		}
		_ = json.NewEncoder(w).Encode(list)
	})
	return handlerClient(mux), latestReads, pagesRead
}

// published is a published release of tag, dated by day so a test can order the
// listing by date independently of version.
func published(tag string, day int) map[string]any {
	return rel(tag, fmt.Sprintf("2026-10-%02dT00:00:00Z", day), false, "")
}

// corpusTags is the tags of testdata/release-tags.txt with the given verdict.
func corpusTags(t *testing.T, verdict string) []string {
	t.Helper()
	data, err := os.ReadFile("../version/testdata/release-tags.txt")
	if err != nil {
		t.Fatal(err)
	}
	var tags []string
	for line := range strings.Lines(string(data)) {
		if f := strings.Fields(line); len(f) == 2 && f[0] == verdict {
			tags = append(tags, f[1])
		}
	}
	if len(tags) == 0 {
		t.Fatalf("the corpus has no %s tags", verdict)
	}
	return tags
}

// TestLatestOffersCandidateOnlyOnRcChannel pins the channel's one decision: rc
// offers the highest of the finals and candidates by semver precedence, read from
// the whole listing, and stable never offers a candidate. Every failure on rc is
// a named one that never reads the stable redirect, which is the fallback it must
// not take.
func TestLatestOffersCandidateOnlyOnRcChannel(t *testing.T) {
	latest := func(t *testing.T, ch updatesv1alpha1.UpdateChannel, l listing) (Release, error, int, []int) {
		t.Helper()
		c, latestReads, pagesRead := l.serve(t)
		got, err := Latest(context.Background(), Inputs{BaseURL: indexURL + indexPath, HTTP: c, Channel: ch})
		return got, err, *latestReads, *pagesRead
	}
	rc := updatesv1alpha1.UpdateChannelRC
	offers := func(t *testing.T, l listing, want string) {
		t.Helper()
		got, err, latestReads, _ := latest(t, rc, l)
		if err != nil {
			t.Fatalf("Latest on rc: %v", err)
		}
		if got.Tag != want {
			t.Errorf("Latest on rc = %q, want %q", got.Tag, want)
		}
		if latestReads != 0 {
			t.Errorf("rc read the stable redirect %d times", latestReads)
		}
	}
	refuses := func(t *testing.T, l listing, want error) {
		t.Helper()
		got, err, latestReads, _ := latest(t, rc, l)
		if !errors.Is(err, want) {
			t.Errorf("Latest on rc: err = %v, want %v", err, want)
		}
		if got != (Release{}) {
			t.Errorf("a refused listing answered %+v", got)
		}
		if latestReads != 0 {
			t.Errorf("a failed listing fell back to the stable redirect %d times", latestReads)
		}
	}

	t.Run("rc.9 and rc.10 order", func(t *testing.T) {
		offers(t, listing{pages: [][]map[string]any{{
			published("v0.3.0-rc.9", 20), published("v0.3.0-rc.10", 10), published("v0.3.0-rc.2", 15),
		}}}, "v0.3.0-rc.10")
	})
	t.Run("final over its candidates", func(t *testing.T) {
		offers(t, listing{pages: [][]map[string]any{{
			published("v0.3.0-rc.2", 20), published("v0.3.0", 10), published("v0.3.0-rc.1", 5),
		}}}, "v0.3.0")
	})
	t.Run("a candidate of the next version over the final", func(t *testing.T) {
		offers(t, listing{pages: [][]map[string]any{{
			published("v0.3.0", 20), published("v0.4.0-rc.1", 10),
		}}}, "v0.4.0-rc.1")
	})
	t.Run("a listing newest-first by date but not by version", func(t *testing.T) {
		offers(t, listing{pages: [][]map[string]any{{
			published("v0.2.4", 28), published("v0.2.3", 25), published("v0.3.0-rc.1", 20), published("v0.2.2", 15),
		}}}, "v0.3.0-rc.1")
	})
	t.Run("the highest on a later page", func(t *testing.T) {
		offers(t, listing{pages: [][]map[string]any{
			{published("v0.2.4", 28)}, {published("v0.2.3", 25)}, {published("v0.3.0-rc.1", 20)},
		}}, "v0.3.0-rc.1")
	})
	t.Run("the release carries its date and notes", func(t *testing.T) {
		c, _, _ := listing{pages: [][]map[string]any{{
			rel("v0.3.0-rc.1", "2026-10-10T00:00:00Z", false, "The control plane runs Kubernetes v1.38.0."),
		}}}.serve(t)
		got, err := Latest(context.Background(), Inputs{BaseURL: indexURL + indexPath, HTTP: c, Channel: rc})
		want := Release{Tag: "v0.3.0-rc.1", Published: "2026-10-10T00:00:00Z", KubeVersion: "v1.38.0"}
		if err != nil || got != want {
			t.Errorf("Latest = %+v, %v, want %+v", got, err, want)
		}
	})
	t.Run("a draft and an unpublished candidate are dropped", func(t *testing.T) {
		offers(t, listing{pages: [][]map[string]any{{
			rel("v0.9.0-rc.1", "2026-10-28T00:00:00Z", true, ""),
			rel("v0.8.0-rc.1", "", false, ""),
			published("v0.3.0-rc.1", 10),
		}}}, "v0.3.0-rc.1")
	})
	t.Run("other grammars refused", func(t *testing.T) {
		for _, tag := range corpusTags(t, "refused") {
			t.Run(tag, func(t *testing.T) {
				offers(t, listing{pages: [][]map[string]any{{published(tag, 28), published("v0.3.0", 10)}}}, "v0.3.0")
			})
		}
	})
	t.Run("every canonical tag is offered", func(t *testing.T) {
		for _, tag := range corpusTags(t, "canonical") {
			t.Run(tag, func(t *testing.T) {
				offers(t, listing{pages: [][]map[string]any{{published(tag, 28)}}}, tag)
			})
		}
	})
	t.Run("pseudo-version and -dev never chosen", func(t *testing.T) {
		for _, tag := range []string{
			"v0.9.1-0.20261015120000-0123456789ab",
			"v0.9.1-rc.1.0.20261015120000-0123456789ab",
			"v0.9.0-dev",
			"dev",
		} {
			t.Run(tag, func(t *testing.T) {
				offers(t, listing{pages: [][]map[string]any{{published(tag, 28), published("v0.3.0-rc.1", 10)}}}, "v0.3.0-rc.1")
				refuses(t, listing{pages: [][]map[string]any{{published(tag, 28)}}}, errNoChannelRelease)
			})
		}
	})
	t.Run("a failed list is a named error", func(t *testing.T) {
		final := published("v0.2.4", 28)
		t.Run("the first page", func(t *testing.T) {
			refuses(t, listing{stable: "v0.2.4", failPage: 1, pages: [][]map[string]any{{final}}}, errChannelList)
		})
		t.Run("a later page, whatever the earlier ones held", func(t *testing.T) {
			refuses(t, listing{stable: "v0.2.4", failPage: 2, pages: [][]map[string]any{{final}, {final}}}, errChannelList)
		})
		t.Run("a Link header it cannot read", func(t *testing.T) {
			refuses(t, listing{stable: "v0.2.4", link: `<https://index.test/?page=2; rel="next"`, pages: [][]map[string]any{{final}}}, errChannelList)
		})
		t.Run("the body is not a list", func(t *testing.T) {
			c := handlerClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"message":"API rate limit exceeded"}`))
			}))
			if _, err := Latest(context.Background(), Inputs{BaseURL: indexURL + indexPath, HTTP: c, Channel: rc}); !errors.Is(err, errChannelList) {
				t.Errorf("err = %v, want %v", err, errChannelList)
			}
		})
		t.Run("the failure says what failed", func(t *testing.T) {
			_, err, _, _ := latest(t, rc, listing{failPage: 1})
			if err == nil || !strings.Contains(err.Error(), "503") {
				t.Errorf("err = %v, want the status", err)
			}
		})
	})
	t.Run("no release on the channel is a named error", func(t *testing.T) {
		refuses(t, listing{stable: "v0.2.4", pages: [][]map[string]any{{}}}, errNoChannelRelease)
	})
	t.Run("the five-page cap is a named failure", func(t *testing.T) {
		page := []map[string]any{published("v0.3.0-rc.1", 10)}
		l := listing{pages: [][]map[string]any{page, page, page, page, page}, more: true}
		refuses(t, l, errChannelPageCap)
		if _, _, _, read := latest(t, rc, l); len(read) != maxListPages || read[0] != 1 || read[maxListPages-1] != maxListPages {
			t.Errorf("pages read = %v, want 1 through %d", read, maxListPages)
		}
	})
	t.Run("a listing that ends on page five answers", func(t *testing.T) {
		page := []map[string]any{published("v0.2.0", 10)}
		offers(t, listing{pages: [][]map[string]any{page, page, page, page, {published("v0.3.0-rc.1", 5)}}}, "v0.3.0-rc.1")
	})
	t.Run("a next page never comes from the Link target", func(t *testing.T) {
		c, _, _ := listing{link: `<https://elsewhere.test/evil?page=2>; rel="next"`, pages: [][]map[string]any{{published("v0.3.0", 10)}}}.serve(t)
		base := c.Transport
		c.Transport = roundTripper(func(req *http.Request) (*http.Response, error) {
			if req.URL.Host != "index.test" {
				t.Errorf("the listing read %s", req.URL)
			}
			return base.RoundTrip(req)
		})
		if _, err := Latest(context.Background(), Inputs{BaseURL: indexURL + indexPath, HTTP: c, Channel: rc}); !errors.Is(err, errChannelPageCap) {
			t.Errorf("err = %v, want %v", err, errChannelPageCap)
		}
	})
	t.Run("an unknown channel is a named failure", func(t *testing.T) {
		for _, ch := range []updatesv1alpha1.UpdateChannel{"beta", "RC", "Stable", " rc"} {
			got, err, latestReads, pagesRead := latest(t, ch, listing{stable: "v0.2.4", pages: [][]map[string]any{{published("v0.2.4", 28)}}})
			if !errors.Is(err, errUnknownChannel) || got != (Release{}) {
				t.Errorf("channel %q: Latest = %+v, %v", ch, got, err)
			}
			if latestReads != 0 || len(pagesRead) != 0 {
				t.Errorf("channel %q read the index: latest %d, pages %v", ch, latestReads, pagesRead)
			}
		}
	})
	t.Run("stable never offers a candidate", func(t *testing.T) {
		for _, ch := range []updatesv1alpha1.UpdateChannel{"", updatesv1alpha1.UpdateChannelStable} {
			got, err, latestReads, pagesRead := latest(t, ch, listing{stable: "v0.2.4", pages: [][]map[string]any{{
				published("v0.3.0-rc.1", 28), published("v0.2.4", 10),
			}}})
			if err != nil || got.Tag != "v0.2.4" {
				t.Errorf("channel %q: Latest = %+v, %v", ch, got, err)
			}
			if latestReads != 1 || len(pagesRead) != 0 {
				t.Errorf("channel %q: latest reads %d, pages %v, want the redirect alone", ch, latestReads, pagesRead)
			}
		}
	})
}

// TestLinkHasNext pins the Link header reading: what names a next page, what does
// not, and that anything unreadable is an error rather than the end of a listing.
func TestLinkHasNext(t *testing.T) {
	cases := []struct {
		name    string
		values  []string
		want    bool
		wantErr bool
	}{
		{name: "no header"},
		{name: "empty value", values: []string{""}},
		{name: "GitHub's middle page", values: []string{`<https://api.github.com/repositories/1/releases?per_page=100&page=1>; rel="prev", <https://api.github.com/repositories/1/releases?per_page=100&page=3>; rel="next", <https://api.github.com/repositories/1/releases?per_page=100&page=5>; rel="last"`}, want: true},
		{name: "GitHub's last page", values: []string{`<https://api.github.com/repositories/1/releases?page=4>; rel="prev", <https://api.github.com/repositories/1/releases?page=1>; rel="first"`}},
		{name: "an unquoted relation", values: []string{`<u>; rel=next`}, want: true},
		{name: "case does not matter", values: []string{`<u>; REL="NEXT"`}, want: true},
		{name: "one of several relations", values: []string{`<u>; rel="last next"`}, want: true},
		{name: "after another parameter", values: []string{`<u>; title="a, b; rel=next"; rel="next"`}, want: true},
		{name: "an escape in a quoted parameter", values: []string{`<u>; title="a\"b"; rel="next"`}, want: true},
		{name: "a second header line", values: []string{`<u>; rel="prev"`, `<v>; rel="next"`}, want: true},
		{name: "next only in the target", values: []string{`<u?rel="next">; rel="prev"`}},
		{name: "next only in another parameter", values: []string{`<u>; title="rel=next"; rel="prev"`}},
		{name: "a later rel is ignored", values: []string{`<u>; rel="prev"; rel="next"`}},
		{name: "another relation with next in its name", values: []string{`<u>; rel="nextish"`}},
		{name: "a parameter with no value", values: []string{`<u>; crossorigin; rel="next"`}, want: true},
		{name: "no angle bracket", values: []string{`u; rel="next"`}, wantErr: true},
		{name: "an unended target", values: []string{`<u; rel="next"`}, wantErr: true},
		{name: "junk after the target", values: []string{`<u> rel="next"`}, wantErr: true},
		{name: "a parameter with no name", values: []string{`<u>; ; rel="next"`}, wantErr: true},
		{name: "an unended quoted parameter", values: []string{`<u>; rel="next`}, wantErr: true},
		{name: "a quoted parameter ending in an escape", values: []string{`<u>; rel="next\`}, wantErr: true},
		{name: "an empty list element", values: []string{`<u>; rel="prev",, <v>; rel="next"`}, wantErr: true},
		{name: "one bad line among good ones", values: []string{`<u>; rel="next"`, `junk`}, wantErr: true},
		{name: "over the size limit", values: []string{`<` + strings.Repeat("x", maxLinkHeaderBytes) + `>; rel="next"`}, wantErr: true},
		{name: "over the size limit across lines", values: []string{strings.Repeat(" ", maxLinkHeaderBytes), `<u>; rel="next"`}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := linkHasNext(tc.values)
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Errorf("linkHasNext = %v, %v; want %v, error %v", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

// FuzzLinkHasNext holds the scanner over a header a server chose: it ends, never
// panics, an error never comes with an answer, and a header over the limit errors.
func FuzzLinkHasNext(f *testing.F) {
	for _, seed := range []string{
		"",
		`<https://api.github.com/repositories/1/releases?page=2>; rel="next", <https://api.github.com/repositories/1/releases?page=5>; rel="last"`,
		`<u>; rel=next`,
		`<u>; title="a\"b, c"; rel="next"`,
		`<u>; rel="next\`,
		`<u>; rel="next`,
		`<u`,
		`<u>;`,
		`<u>;=`,
		`<u>; a=`,
		`<u>,,`,
		"<u>\t;\trel\t=\tnext\t,\t",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, header string) {
		next, err := linkHasNext([]string{header})
		if err != nil && next {
			t.Errorf("linkHasNext(%q) answered with an error: %v", header, err)
		}
		if len(header) > maxLinkHeaderBytes && err == nil {
			t.Errorf("linkHasNext accepted a %d byte header over the %d byte limit", len(header), maxLinkHeaderBytes)
		}
		over := strings.Repeat(" ", maxLinkHeaderBytes+1) + header
		if next, err := linkHasNext([]string{over}); err == nil || next {
			t.Errorf("linkHasNext over the limit = %v, %v; want an error", next, err)
		}
	})
}
