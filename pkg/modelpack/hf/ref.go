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
	"errors"
	"fmt"
	"strings"
)

// Scheme is the prefix of a Hub reference.
const Scheme = "hf://"

// DefaultRevision is the revision a reference without one resolves.
const DefaultRevision = "main"

// Bounds on a reference, the Hub's own: a repository id part is at most 96
// bytes, and a git ref name is kept to 255.
const (
	maxRepoPartBytes = 96
	maxRevisionBytes = 255
)

// ErrBadReference is a string that is not hf://<org>/<name>[@<revision>].
var ErrBadReference = errors.New("not a Hugging Face reference hf://<org>/<name>[@<revision>]")

// Ref names a Hub model repository at a revision.
type Ref struct {
	// Repo is <org>/<name>, as the Hub spells it.
	Repo string
	// Revision is a branch, a tag or a commit; DefaultRevision when the
	// reference names none.
	Revision string
}

// String is the reference in hf:// form.
func (r Ref) String() string { return Scheme + r.Repo + "@" + r.Revision }

// ParseRef parses hf://<org>/<name>[@<revision>]. The repository id follows
// the Hub's rules ([A-Za-z0-9._-] parts that neither start nor end with "."
// or "-", no "--" or "..", at most 96 bytes a part); the revision is
// [A-Za-z0-9._/-] with no empty, "." or ".." component.
func ParseRef(s string) (Ref, error) {
	rest, ok := strings.CutPrefix(s, Scheme)
	if !ok {
		return Ref{}, fmt.Errorf("%q: %w", s, ErrBadReference)
	}
	repo, rev, hasRev := strings.Cut(rest, "@")
	if !hasRev {
		rev = DefaultRevision
	}
	org, name, ok := strings.Cut(repo, "/")
	if !ok || !validRepoPart(org) || !validRepoPart(name) {
		return Ref{}, fmt.Errorf("%q: the repository must be <org>/<name>: %w", s, ErrBadReference)
	}
	if !validRevision(rev) {
		return Ref{}, fmt.Errorf("%q: revision %q: %w", s, rev, ErrBadReference)
	}
	return Ref{Repo: repo, Revision: rev}, nil
}

func validRepoPart(p string) bool {
	if p == "" || len(p) > maxRepoPartBytes || strings.Contains(p, "--") || strings.Contains(p, "..") {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '_':
		case c == '.' || c == '-':
			if i == 0 || i == len(p)-1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func validRevision(r string) bool {
	if r == "" || len(r) > maxRevisionBytes {
		return false
	}
	for c := range strings.SplitSeq(r, "/") {
		if c == "" || c == "." || c == ".." {
			return false
		}
		for i := 0; i < len(c); i++ {
			b := c[i]
			if !('a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' || '0' <= b && b <= '9' || b == '.' || b == '_' || b == '-') {
				return false
			}
		}
	}
	return true
}

// isCommit reports whether s is a full 40-hex lowercase commit id.
func isCommit(s string) bool { return isLowerHex(s, 40) }

// isLowerHex reports whether s is exactly n lowercase hex digits.
func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !('0' <= s[i] && s[i] <= '9' || 'a' <= s[i] && s[i] <= 'f') {
			return false
		}
	}
	return true
}
