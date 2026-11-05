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

// Package ref is the one validator of registry repository names, tags, digests
// and upload session ids, and the one mapping from a repository name to its
// directory in the store.
//
// The name, tag and digest grammar is github.com/distribution/reference's (the
// grammar Docker and containerd parse with) and go-digest's; this package wraps
// it with the refusals the on-disk store needs:
//
//   - a repository name is the distribution specification's path-only form:
//     lowercase components, no registry host and no port;
//   - no component may be a word of the OCI image layout a repository directory
//     holds (blobs, index.json, oci-layout, .uploads) or start with a dot, so a
//     nested repository can never be read as part of its parent's layout;
//   - the first component may not be a file the store root holds (cache.db,
//     meta.db, config.json, htpasswd, push-credential.json);
//   - a digest is sha256 or sha512 in its canonical lowercase form.
//
// The mapping is injective because an accepted name is lowercase (so a
// case-insensitive volume cannot fold two names together), carries no dot or
// empty segment, and joins its components with the path separator; Name.Dir
// checks that the result stays under the root, and Name.ResolveDir refuses a
// symlink anywhere between the root and the repository directory.
package ref

import (
	// sha512 registers with crypto so go-digest accepts sha512 digests (the
	// push gate accepts both algorithms).
	_ "crypto/sha512"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
)

// Limits from the distribution specification.
const (
	// MaxNameLength is the longest repository name accepted.
	MaxNameLength = reference.RepositoryNameTotalLengthMax
	// MaxTagLength is the longest tag accepted.
	MaxTagLength = 128
)

// Sentinel errors. Every refusal wraps exactly one of them.
var (
	// ErrInvalidName is a repository name outside the grammar.
	ErrInvalidName = errors.New("invalid repository name")
	// ErrReservedName is a grammatical repository name that would collide with
	// the store's own files.
	ErrReservedName = errors.New("reserved repository name")
	// ErrInvalidTag is a tag outside the grammar.
	ErrInvalidTag = errors.New("invalid tag")
	// ErrInvalidDigest is a digest outside the accepted forms.
	ErrInvalidDigest = errors.New("invalid digest")
	// ErrInvalidUploadID is an upload session id that is not a lowercase UUID.
	ErrInvalidUploadID = errors.New("invalid upload id")
	// ErrOutsideRoot is a path that does not stay under the store root.
	ErrOutsideRoot = errors.New("path outside the store root")
	// ErrSymlink is a symlink found inside the store.
	ErrSymlink = errors.New("symlink inside the store")
)

// layoutWords are the entries an OCI image layout directory holds. A repository
// component spelled as one would name a part of its parent repository.
var layoutWords = map[string]bool{
	"blobs":      true,
	"index.json": true,
	"oci-layout": true,
	".uploads":   true,
}

// rootWords are the files the store root holds beside the repositories: zot's
// databases, which are kept for a rollback, and the registry's own credential
// and configuration files.
var rootWords = map[string]bool{
	"cache.db":             true,
	"meta.db":              true,
	"config.json":          true,
	"htpasswd":             true,
	"push-credential.json": true,
}

// anchorDomain prefixes a name before it is handed to the reference grammar, so
// the grammar can only read the whole name as the path: a name that parses with
// this domain and exactly itself as the path is a path-only repository name.
const anchorDomain = "localhost"

// Name is a validated repository name. The zero Name is not valid; obtain one
// from ParseName.
type Name struct {
	s string
}

// ParseName validates s as a repository name.
func ParseName(s string) (Name, error) {
	if s == "" || len(s) > MaxNameLength {
		return Name{}, fmt.Errorf("%w: length %d", ErrInvalidName, len(s))
	}
	named, err := reference.WithName(anchorDomain + "/" + s)
	if err != nil || reference.Domain(named) != anchorDomain || reference.Path(named) != s {
		return Name{}, fmt.Errorf("%w: %q", ErrInvalidName, s)
	}
	// The grammar above is the reference library's; the guarantee the
	// mapping's injectivity rests on (no byte a case-insensitive or
	// normalising volume could fold) is asserted here, in this package.
	for i := 0; i < len(s); i++ {
		if !nameByte(s[i]) {
			return Name{}, fmt.Errorf("%w: byte %#x in %q", ErrInvalidName, s[i], s)
		}
	}
	comps := strings.Split(s, "/")
	for _, c := range comps {
		if layoutWords[c] || strings.HasPrefix(c, ".") {
			return Name{}, fmt.Errorf("%w: component %q of %q", ErrReservedName, c, s)
		}
	}
	if rootWords[comps[0]] {
		return Name{}, fmt.Errorf("%w: %q names a file of the store root", ErrReservedName, s)
	}
	return Name{s: s}, nil
}

// nameByte reports whether b may appear in a repository name: lowercase ASCII
// letters, digits, and the separators '.', '_', '-' and '/'.
func nameByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '.' || b == '_' || b == '-' || b == '/'
}

// String returns the name as it is spelled on the wire.
func (n Name) String() string { return n.s }

// IsZero reports whether n is the zero Name.
func (n Name) IsZero() bool { return n.s == "" }

// Components returns the name's slash-separated components.
func (n Name) Components() []string { return strings.Split(n.s, "/") }

// Dir returns the repository's directory under root. It touches no filesystem.
func (n Name) Dir(root string) (string, error) {
	if n.IsZero() {
		return "", fmt.Errorf("%w: empty", ErrInvalidName)
	}
	root = filepath.Clean(root)
	p := filepath.Join(append([]string{root}, n.Components()...)...)
	if err := within(root, p); err != nil {
		return "", err
	}
	return p, nil
}

// ResolveDir is Dir that also refuses a symlink at, or anywhere below, root on
// the way to the repository directory. Components that do not exist yet are
// fine: the store creates them.
func (n Name) ResolveDir(root string) (string, error) {
	p, err := n.Dir(root)
	if err != nil {
		return "", err
	}
	if err := NoSymlinks(root, p); err != nil {
		return "", err
	}
	return p, nil
}

// NoSymlinks checks every existing path element from root down to p (root
// included) and refuses a symlink among them. p must be under root.
func NoSymlinks(root, p string) error {
	root = filepath.Clean(root)
	p = filepath.Clean(p)
	if err := within(root, p); err != nil {
		return err
	}
	rel, _ := filepath.Rel(root, p)
	cur := root
	elems := []string{}
	if rel != "." {
		elems = strings.Split(rel, string(filepath.Separator))
	}
	for i := -1; i < len(elems); i++ {
		if i >= 0 {
			cur = filepath.Join(cur, elems[i])
		}
		fi, err := os.Lstat(cur)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("stat %s: %w", cur, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s", ErrSymlink, cur)
		}
	}
	return nil
}

// NameFromDir is Dir's inverse: the repository name whose directory is dir.
func NameFromDir(root, dir string) (Name, error) {
	root = filepath.Clean(root)
	dir = filepath.Clean(dir)
	if err := within(root, dir); err != nil {
		return Name{}, err
	}
	rel, _ := filepath.Rel(root, dir)
	return ParseName(filepath.ToSlash(rel))
}

// within checks that p is root or below it, lexically.
func within(root, p string) error {
	rel, err := filepath.Rel(root, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("%w: %s", ErrOutsideRoot, p)
	}
	return nil
}

// tagAnchor is the name a tag is checked against; any valid name would do.
var tagAnchor, _ = reference.WithName(anchorDomain + "/tag")

// ParseTag validates s as a tag: [A-Za-z0-9_][A-Za-z0-9_.-]{0,127}.
func ParseTag(s string) (string, error) {
	if s == "" || len(s) > MaxTagLength {
		return "", fmt.Errorf("%w: length %d", ErrInvalidTag, len(s))
	}
	if _, err := reference.WithTag(tagAnchor, s); err != nil {
		return "", fmt.Errorf("%w: %q", ErrInvalidTag, s)
	}
	return s, nil
}

// ParseDigest validates s as a sha256 or sha512 digest in canonical form.
func ParseDigest(s string) (digest.Digest, error) {
	d, err := digest.Parse(s)
	if err != nil || d.String() != s {
		return "", fmt.Errorf("%w: %q", ErrInvalidDigest, s)
	}
	switch d.Algorithm() {
	case digest.SHA256, digest.SHA512:
		return d, nil
	default:
		return "", fmt.Errorf("%w: algorithm %q", ErrInvalidDigest, d.Algorithm())
	}
}

// Reference is a manifest reference: exactly one of Tag and Digest is set.
type Reference struct {
	Tag    string
	Digest digest.Digest
}

// String returns the reference as spelled on the wire.
func (r Reference) String() string {
	if r.Digest != "" {
		return r.Digest.String()
	}
	return r.Tag
}

// ParseReference validates s as a tag or, when it holds a colon, a digest.
func ParseReference(s string) (Reference, error) {
	if strings.Contains(s, ":") {
		d, err := ParseDigest(s)
		if err != nil {
			return Reference{}, err
		}
		return Reference{Digest: d}, nil
	}
	t, err := ParseTag(s)
	if err != nil {
		return Reference{}, err
	}
	return Reference{Tag: t}, nil
}

// ParseUploadID validates s as an upload session id: a lowercase UUID in its
// 8-4-4-4-12 form, which is what the store mints and what zot left.
func ParseUploadID(s string) (string, error) {
	if len(s) != 36 {
		return "", fmt.Errorf("%w: %q", ErrInvalidUploadID, s)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return "", fmt.Errorf("%w: %q", ErrInvalidUploadID, s)
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return "", fmt.Errorf("%w: %q", ErrInvalidUploadID, s)
			}
		}
	}
	return s, nil
}
