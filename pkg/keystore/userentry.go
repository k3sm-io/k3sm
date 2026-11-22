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

package keystore

import (
	"fmt"
	"strconv"
	"strings"

	keyentry "k3sm.io/apis/keystore/entry"
)

// This file is the store's entry resolver: docs/design/keystore.md § "User
// scope", "Scope strings and names". The grammar lives once, in
// k3sm.io/apis/keystore/entry; the store adds only the short-name input form.

// maxShortNameLen bounds a short name, the longest macOS account name.
const maxShortNameLen = 255

// Resolved is an input resolved to an API entry.
type Resolved struct {
	// Entry is the scope-qualified entry, system/<name> or user/<uid>/<name>.
	Entry keyentry.Entry
	// Note states a short-name resolution, "resolved user/alice to
	// user/501", for the caller to print so a script sees what it bound to.
	// It is empty when the input named the uid.
	Note string
}

// ParseEntry parses s as an API entry: system/<name> or user/<uid>/<name>,
// with the shared grammar. A short name is not an API entry (ResolveEntry
// takes it). Any failure matches ErrInvalidName, and the error never repeats
// s, since an entry name can be private to its owner.
func ParseEntry(s string) (keyentry.Entry, error) {
	e, err := keyentry.Parse(s)
	if err != nil {
		return keyentry.Entry{}, fmt.Errorf("%w: %w", ErrInvalidName, err)
	}
	// The grammar is the authority; the store's own checks must agree with
	// it, and a disagreement refuses rather than seal under a name or scope
	// the store would not have accepted.
	if checkName(e.Name) != nil {
		return keyentry.Entry{}, fmt.Errorf("%w: the name part is not a valid entry name", ErrInvalidName)
	}
	if e.Scope == keyentry.ScopeUser && checkScope(userScopeOf(e.UID)) != nil {
		return keyentry.Entry{}, fmt.Errorf("%w: the uid is not a user scope", ErrInvalidName)
	}
	return e, nil
}

// ResolveEntry parses CLI input as an entry. Beside the API forms it takes
// user/<shortname>/<name>, resolving the short name through the uid
// resolver, and states the result in Resolved.Note. An all-digit second
// segment is always a uid, never a short name, even when an account of that
// name exists, so user/1000/x names uid 1000 on every input path. A short
// name that does not resolve, or resolves to root (uid 0, which has no user
// scope), is refused, matching ErrInvalidName.
func ResolveEntry(input string) (Resolved, error) {
	if rest, ok := strings.CutPrefix(input, userScopePrefix); ok {
		seg, name, found := strings.Cut(rest, "/")
		if found && seg != "" && !allDigits(seg) {
			if !shortName(seg) {
				return Resolved{}, fmt.Errorf("%w: the second segment is neither a uid nor a short name", ErrInvalidName)
			}
			uid, err := resolveUID(seg)
			if err != nil {
				return Resolved{}, fmt.Errorf("%w: user %s does not resolve to a uid: %w", ErrInvalidName, seg, err)
			}
			if uid == 0 {
				return Resolved{}, fmt.Errorf("%w: user %s is root, which has no user scope", ErrInvalidName, seg)
			}
			e, err := ParseEntry(userScopeOf(uid) + "/" + name)
			if err != nil {
				return Resolved{}, err
			}
			return Resolved{Entry: e, Note: "resolved user/" + seg + " to " + userScopeOf(uid)}, nil
		}
	}
	e, err := ParseEntry(input)
	if err != nil {
		return Resolved{}, err
	}
	return Resolved{Entry: e}, nil
}

// userScopeOf is uid's scope string, user/<uid>.
func userScopeOf(uid uint32) string {
	return userScopePrefix + strconv.FormatUint(uint64(uid), 10)
}

// allDigits reports whether s is non-empty ASCII digits.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// shortName reports whether s may be looked up as a macOS short name: 1 to
// maxShortNameLen bytes of ASCII letters, digits, '_', '.' and '-', not
// beginning with '-' or '.'. It is a bound on what reaches getpwnam, not
// the account grammar, which the directory service owns.
func shortName(s string) bool {
	if s == "" || len(s) > maxShortNameLen || s[0] == '-' || s[0] == '.' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '_' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}
