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
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	updatesv1alpha1 "k3sm.io/apis/updates/v1alpha1"
	"k3sm.io/k3sm/pkg/version"
)

const (
	// maxListPages bounds how far a channel listing reads: five pages of a
	// hundred releases. One date-ordered page can hide the highest version
	// behind a burst of newer entries, so the listing reads to its end, and a
	// listing longer than this fails rather than answers from part of it.
	maxListPages = 5
	// maxLinkHeaderBytes bounds the Link header a listing page may carry. A page
	// names at most four relations, so a real one is far under it.
	maxLinkHeaderBytes = 8 << 10
)

var (
	// errUnknownChannel is a channel that is neither stable nor rc.
	errUnknownChannel = errors.New("refusing an unknown update channel")
	// errChannelList is a channel listing that could not be read to its end. It
	// never falls back to the stable answer, because that would offer a cluster
	// on rc a release its channel did not choose.
	errChannelList = errors.New("the rc channel's release listing failed")
	// errChannelPageCap is a listing with more to read at maxListPages.
	errChannelPageCap = errors.New("the rc channel's release listing did not end")
	// errNoChannelRelease is a listing that held no release the channel offers.
	errNoChannelRelease = errors.New("no k3sm release on the rc channel")
)

// newestOnChannel is the highest release the rc channel offers: of the published
// finals and candidates in the listing, the highest by semver precedence, never
// by publication time, so a final outranks its own candidates. The listing is
// untrusted discovery and adds no authority: it chooses only what is offered, and
// whatever guards a tag on the stable channel still guards this one.
//
// A next page is asked of the same index by number. The Link header only says
// that there is one, so a response never chooses the URL read next.
func (r reader) newestOnChannel(ctx context.Context) (Release, error) {
	var best Release
	for page := 1; page <= maxListPages; page++ {
		u := r.apiBase() + "?per_page=100"
		if page > 1 {
			u += "&page=" + strconv.Itoa(page)
		}
		var list []apiRelease
		hdr, err := r.getJSONHeader(ctx, u, &list)
		if err != nil {
			return Release{}, fmt.Errorf("%w: %w", errChannelList, err)
		}
		for _, a := range list {
			rel, ok := a.release()
			if !ok || !version.CanonicalTag(rel.Tag) {
				continue
			}
			if best.Tag == "" {
				best = rel
			} else if c, ok := version.CompareReleases(rel.Tag, best.Tag); ok && c > 0 {
				best = rel
			}
		}
		more, err := linkHasNext(hdr.Values("Link"))
		if err != nil {
			return Release{}, fmt.Errorf("%w: page %d: %w", errChannelList, page, err)
		}
		if !more {
			if best.Tag == "" {
				return Release{}, fmt.Errorf("%w at %s", errNoChannelRelease, r.base)
			}
			return best, nil
		}
	}
	return Release{}, fmt.Errorf("%w within %d pages at %s", errChannelPageCap, maxListPages, r.base)
}

// checkChannel refuses a channel other than stable (or empty, which means
// stable) and rc.
func checkChannel(ch updatesv1alpha1.UpdateChannel) error {
	switch ch {
	case "", updatesv1alpha1.UpdateChannelStable, updatesv1alpha1.UpdateChannelRC:
		return nil
	}
	return fmt.Errorf("%w %q", errUnknownChannel, ch)
}

// linkHasNext reports whether the Link header values (RFC 8288) carry a link
// whose relation types include next. A header it cannot read is an error, never
// "no next page", because that would answer from part of a listing.
func linkHasNext(values []string) (bool, error) {
	size := 0
	for _, v := range values {
		size += len(v)
	}
	if size > maxLinkHeaderBytes {
		return false, fmt.Errorf("a Link header of %d bytes is over the %d byte limit", size, maxLinkHeaderBytes)
	}
	found := false
	for _, v := range values {
		next, err := linkValueHasNext(v)
		if err != nil {
			return false, fmt.Errorf("malformed Link header: %w", err)
		}
		found = found || next
	}
	return found, nil
}

// linkValueHasNext scans one Link header value: a comma-separated list of
// <target> followed by ;-separated parameters. Only the first rel parameter of a
// link counts, as RFC 8288 says. The target is skipped, never used.
func linkValueHasNext(s string) (bool, error) {
	found := false
	for {
		s = strings.TrimLeft(s, " \t")
		if s == "" {
			return found, nil
		}
		if s[0] != '<' {
			return false, errors.New("a link does not start with <")
		}
		end := strings.IndexByte(s, '>')
		if end < 0 {
			return false, errors.New("a link target does not end with >")
		}
		s = s[end+1:]
		seenRel := false
		for {
			s = strings.TrimLeft(s, " \t")
			if s == "" || s[0] == ',' {
				break
			}
			if s[0] != ';' {
				return false, errors.New("a link parameter does not start with ;")
			}
			var name, value string
			var err error
			name, value, s, err = linkParam(s[1:])
			if err != nil {
				return false, err
			}
			if !seenRel && strings.EqualFold(name, "rel") {
				seenRel = true
				found = found || slices.ContainsFunc(strings.Fields(value), func(rel string) bool {
					return strings.EqualFold(rel, "next")
				})
			}
		}
		if s != "" {
			s = s[1:]
		}
	}
}

// linkParam scans one name[=value] link parameter, the value a token or a quoted
// string, and returns what follows it.
func linkParam(s string) (name, value, rest string, err error) {
	s = strings.TrimLeft(s, " \t")
	end := strings.IndexAny(s, "=;, \t")
	if end < 0 {
		end = len(s)
	}
	name, s = s[:end], strings.TrimLeft(s[end:], " \t")
	if name == "" {
		return "", "", "", errors.New("a link parameter has no name")
	}
	if !strings.HasPrefix(s, "=") {
		return name, "", s, nil
	}
	s = strings.TrimLeft(s[1:], " \t")
	if !strings.HasPrefix(s, `"`) {
		end = strings.IndexAny(s, ";, \t")
		if end < 0 {
			end = len(s)
		}
		return name, s[:end], s[end:], nil
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '"':
			return name, b.String(), s[i+1:], nil
		case '\\':
			i++
			if i == len(s) {
				return "", "", "", errors.New("a quoted link parameter ends in an escape")
			}
		}
		b.WriteByte(s[i])
	}
	return "", "", "", errors.New("a quoted link parameter does not end")
}
