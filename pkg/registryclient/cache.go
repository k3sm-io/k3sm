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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// platformPattern is the os/arch[/variant] form a cached platform must have:
// anything else (a control character, an empty part) marks a damaged entry.
var platformPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)?$`)

// Description is what a top-level manifest or index digest describes: the
// part of an Image that depends only on the content, never on the tag that
// names it.
type Description struct {
	Digest    string           `json:"digest"`
	Platforms []string         `json:"platforms"`
	SizeBytes int64            `json:"sizeBytes"`
	Blobs     map[string]int64 `json:"blobs"`
}

// valid reports whether desc is a well-formed description of digest. A cache
// entry that is not is ignored and the digest described afresh.
func (desc Description) valid(digest string) bool {
	if desc.Digest != digest || desc.SizeBytes < 0 {
		return false
	}
	if _, ok := desc.Blobs[digest]; !ok {
		return false
	}
	for d, size := range desc.Blobs {
		if !digestPattern.MatchString(d) || size < 0 {
			return false
		}
	}
	for _, p := range desc.Platforms {
		if !platformPattern.MatchString(p) {
			return false
		}
	}
	return true
}

// DescriptionCache keeps descriptions by repository and digest across
// listings. Load reports a miss for anything it cannot read; Store is best
// effort.
type DescriptionCache interface {
	Load(repository, digest string) (Description, bool)
	Store(repository, digest string, desc Description) error
}

// descriptionFileVersion versions a DirCache entry; an entry of another
// version is a miss.
const descriptionFileVersion = 1

// maxDescriptionBytes bounds a DirCache entry read.
const maxDescriptionBytes = 4 << 20

// DirCache is a DescriptionCache in a directory, one file per repository and
// digest: <dir>/<repository>@<digest>.json, the repository's slashes as
// directories. Directories are 0700 and files 0600, each written to a
// temporary file and renamed into place, so a reader never sees half an entry.
// It is safe for concurrent use.
type DirCache struct {
	dir string
}

// OpenDirCache opens the cache for the registry at host (host:port) under
// root, creating <root>/<host>.
func OpenDirCache(root, host string) (*DirCache, error) {
	if root == "" {
		return nil, errors.New("no cache directory")
	}
	if host == "" || host == "." || host == ".." || strings.ContainsAny(host, "/\\\x00") {
		return nil, fmt.Errorf("registry host %q is not a cache directory name", host)
	}
	dir := filepath.Join(root, host)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create the description cache: %w", err)
	}
	return &DirCache{dir: dir}, nil
}

// path is the entry for repository@digest, or false when either is not
// well-formed (and so cannot be a path inside the cache).
func (c *DirCache) path(repository, digest string) (string, bool) {
	if !ValidRepository(repository) || !digestPattern.MatchString(digest) {
		return "", false
	}
	return filepath.Join(c.dir, filepath.FromSlash(repository)+"@"+digest+".json"), true
}

// descriptionFile is a DirCache entry.
type descriptionFile struct {
	Version int `json:"version"`
	Description
}

// Load reads repository@digest's entry. A missing, unreadable or undecodable
// entry, or one of another version, is a miss.
func (c *DirCache) Load(repository, digest string) (Description, bool) {
	p, ok := c.path(repository, digest)
	if !ok {
		return Description{}, false
	}
	f, err := os.Open(p)
	if err != nil {
		return Description{}, false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxDescriptionBytes+1))
	if err != nil || len(b) > maxDescriptionBytes {
		return Description{}, false
	}
	var e descriptionFile
	if err := json.Unmarshal(b, &e); err != nil || e.Version != descriptionFileVersion {
		return Description{}, false
	}
	return e.Description, true
}

// Store writes repository@digest's entry, replacing any there.
func (c *DirCache) Store(repository, digest string, desc Description) error {
	p, ok := c.path(repository, digest)
	if !ok {
		return fmt.Errorf("%s@%s is not a cacheable reference", repository, digest)
	}
	b, err := json.Marshal(descriptionFile{Version: descriptionFileVersion, Description: desc})
	if err != nil {
		return err
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".description-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op once the rename has moved it
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}
