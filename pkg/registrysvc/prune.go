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

package registrysvc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// The registry half of `k3sm image prune`: which untagged manifests in this
// server's registry may be deleted.
//
// THE PLAN READS ZOT'S STORAGE AND NEVER WRITES IT. zot keeps every repository
// as an OCI image layout under StateDir, and its index.json lists every manifest
// the repository holds, tagged or not; the dist-spec API has no way to list the
// untagged ones, and the pinned minimal zot serves no search extension. The
// deletion itself is a DELETE through zot's own API with this node's push
// credential, so zot updates its own index and its GC reclaims the blobs.

// pruneIndexLimit caps index.json and every manifest the plan reads. zot wrote
// them, but a bounded read costs nothing and an unbounded one is a footgun.
const pruneIndexLimit = 16 << 20

// PruneGrace is how old an untagged manifest must be before prune deletes it.
// It equals zot's own GC delay (gcDelay, pinned equal by a test), for the same
// reason: a multi-platform push uploads its per-platform manifests untagged
// BEFORE the index that names them, and a prune that deleted them in that
// window would fail the push.
const PruneGrace = time.Hour

// KeepReason says why an untagged manifest is not deleted.
type KeepReason string

// The reasons an untagged manifest survives a prune.
const (
	// KeepChildOfKept is a manifest a kept image index names: the per-platform
	// half of a multi-platform image.
	KeepChildOfKept KeepReason = "named by a kept index"
	// KeepReferrer is a manifest whose subject is kept: a signature, an SBOM or
	// another OCI referrer of an image that stays.
	KeepReferrer KeepReason = "referrer of a kept manifest"
	// KeepRecent is younger than PruneGrace, so it may belong to a push in flight.
	KeepRecent KeepReason = "younger than the grace period"
	// KeepUnreadable sits in a repository the plan could not read completely.
	// Without every manifest it cannot tell what a tagged index names, so it
	// deletes nothing there.
	KeepUnreadable KeepReason = "repository not fully readable"
)

// StoredManifest is one manifest in one repository of the registry.
type StoredManifest struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
	MediaType  string `json:"mediaType"`
	Size       int64  `json:"size"`
}

// KeptManifest is an untagged manifest the plan keeps, with the reason.
type KeptManifest struct {
	StoredManifest
	Reason KeepReason `json:"reason"`
}

// PrunePlan is what a prune would delete from the registry and which untagged
// manifests it keeps. Tagged manifests are never in either list.
type PrunePlan struct {
	// Delete lists, per repository, image indexes before plain manifests: zot
	// refuses to delete a manifest an index in the same repository still names.
	Delete []StoredManifest
	Kept   []KeptManifest
	// Unreadable lists the repositories whose index.json could not be read, so
	// nothing in them is listed or deleted.
	Unreadable []string
}

// PlanPrune reads the registry under workDir and plans the deletion of every
// untagged manifest nothing kept depends on, as of now.
func PlanPrune(workDir string, now time.Time) (PrunePlan, error) {
	repos, err := Repositories(workDir)
	if err != nil {
		return PrunePlan{}, err
	}
	var plan PrunePlan
	for _, repo := range repos {
		p := PlanRepository(workDir, repo, now)
		plan.Delete = append(plan.Delete, p.Delete...)
		plan.Kept = append(plan.Kept, p.Kept...)
		plan.Unreadable = append(plan.Unreadable, p.Unreadable...)
	}
	return plan, nil
}

// Repositories lists the repositories zot stores under workDir, sorted. A
// repository is a directory holding both oci-layout and index.json.
func Repositories(workDir string) ([]string, error) {
	root := StateDir(workDir)
	var repos []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		// A repository's blobs and zot's upload staging hold no repositories.
		// A repository literally named "blobs" or ".uploads" is skipped too,
		// which deletes nothing there: the safe direction.
		if p != root && (d.Name() == "blobs" || d.Name() == ".uploads") {
			return filepath.SkipDir
		}
		if isRegular(filepath.Join(p, "oci-layout")) && isRegular(filepath.Join(p, "index.json")) {
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			repos = append(repos, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list the registry's repositories under %s: %w", root, err)
	}
	sort.Strings(repos)
	return repos, nil
}

func isRegular(p string) bool {
	fi, err := os.Lstat(p)
	return err == nil && fi.Mode().IsRegular()
}

// digestPattern is the only digest shape the plan turns into a blob path. A
// digest is read from a file and then joined into a path, so anything else
// (a "..", a slash, an algorithm zot does not write) makes the repository
// unreadable rather than being opened.
var digestPattern = regexp.MustCompile(`^(sha256:[a-f0-9]{64}|sha512:[a-f0-9]{128})$`)

// ociDescriptor is the subset of an OCI descriptor the plan reads.
type ociDescriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations"`
}

// ociManifestLinks is the subset of a manifest or index that links it to other
// manifests: an index's children and a referrer's subject.
type ociManifestLinks struct {
	MediaType string          `json:"mediaType"`
	Manifests []ociDescriptor `json:"manifests"`
	Subject   *ociDescriptor  `json:"subject"`
}

// refNameAnnotation is how zot's index.json marks a tag on a manifest entry.
const refNameAnnotation = "org.opencontainers.image.ref.name"

// errUnreadable marks a repository the plan must not delete from.
var errUnreadable = errors.New("repository not fully readable")

// PlanRepository plans one repository. It never fails: a repository it cannot
// read completely keeps all its untagged manifests under KeepUnreadable.
func PlanRepository(workDir, repo string, now time.Time) PrunePlan {
	dir := filepath.Join(StateDir(workDir), filepath.FromSlash(repo))
	entries, err := readIndex(dir)
	if err != nil {
		return PrunePlan{Unreadable: []string{repo}}
	}
	type entry struct {
		m      StoredManifest
		tagged bool
	}
	byDigest := map[string]*entry{}
	var order []string
	for _, d := range entries {
		e, ok := byDigest[d.Digest]
		if !ok {
			e = &entry{m: StoredManifest{Repository: repo, Digest: d.Digest, MediaType: d.MediaType, Size: d.Size}}
			byDigest[d.Digest] = e
			order = append(order, d.Digest)
		}
		// zot's delete by digest drops EVERY entry with that digest, tags
		// included, so one tagged entry makes the whole digest tagged.
		if d.Annotations[refNameAnnotation] != "" {
			e.tagged = true
		}
	}
	untagged := func(reason KeepReason) PrunePlan {
		var p PrunePlan
		for _, dg := range order {
			if e := byDigest[dg]; !e.tagged {
				p.Kept = append(p.Kept, KeptManifest{StoredManifest: e.m, Reason: reason})
			}
		}
		return p
	}

	links := map[string]ociManifestLinks{}
	kept := map[string]KeepReason{}
	for _, dg := range order {
		l, err := readLinks(dir, dg)
		if err != nil {
			return untagged(KeepUnreadable)
		}
		links[dg] = l
		e := byDigest[dg]
		if e.tagged {
			kept[dg] = ""
			continue
		}
		fi, err := os.Stat(blobPath(dir, dg))
		if err != nil {
			return untagged(KeepUnreadable)
		}
		if now.Sub(fi.ModTime()) < PruneGrace {
			kept[dg] = KeepRecent
		}
	}
	// Propagate to a fixpoint: a kept index keeps its children, a kept
	// manifest keeps its referrers, and each newly kept one may keep more.
	for changed := true; changed; {
		changed = false
		for _, dg := range order {
			if _, ok := kept[dg]; ok {
				for _, c := range links[dg].Manifests {
					if _, ok := kept[c.Digest]; !ok {
						if _, inRepo := byDigest[c.Digest]; inRepo {
							kept[c.Digest] = KeepChildOfKept
							changed = true
						}
					}
				}
				continue
			}
			if s := links[dg].Subject; s != nil {
				if _, ok := kept[s.Digest]; ok {
					kept[dg] = KeepReferrer
					changed = true
				}
			}
		}
	}

	var p PrunePlan
	var indexes, others []StoredManifest
	for _, dg := range order {
		e := byDigest[dg]
		if e.tagged {
			continue
		}
		if reason, ok := kept[dg]; ok {
			p.Kept = append(p.Kept, KeptManifest{StoredManifest: e.m, Reason: reason})
			continue
		}
		if len(links[dg].Manifests) > 0 {
			indexes = append(indexes, e.m)
		} else {
			others = append(others, e.m)
		}
	}
	p.Delete = append(indexes, others...)
	return p
}

// readIndex reads a repository's index.json and validates every digest in it.
func readIndex(dir string) ([]ociDescriptor, error) {
	b, err := readBounded(filepath.Join(dir, "index.json"))
	if err != nil {
		return nil, err
	}
	var idx struct {
		Manifests []ociDescriptor `json:"manifests"`
	}
	if err := json.Unmarshal(b, &idx); err != nil {
		return nil, fmt.Errorf("%w: parse index.json: %w", errUnreadable, err)
	}
	for _, d := range idx.Manifests {
		if !digestPattern.MatchString(d.Digest) {
			return nil, fmt.Errorf("%w: index.json names digest %q", errUnreadable, d.Digest)
		}
	}
	return idx.Manifests, nil
}

// readLinks reads one manifest blob for its children and subject.
func readLinks(dir, digest string) (ociManifestLinks, error) {
	b, err := readBounded(blobPath(dir, digest))
	if err != nil {
		return ociManifestLinks{}, err
	}
	var l ociManifestLinks
	if err := json.Unmarshal(b, &l); err != nil {
		return ociManifestLinks{}, fmt.Errorf("%w: parse manifest %s: %w", errUnreadable, digest, err)
	}
	return l, nil
}

// blobPath is where zot stores a blob of a repository. digest has already
// matched digestPattern.
func blobPath(dir, digest string) string {
	alg, hex, _ := strings.Cut(digest, ":")
	return filepath.Join(dir, "blobs", alg, hex)
}

func readBounded(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUnreadable, err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, pruneIndexLimit+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %w", errUnreadable, p, err)
	}
	if len(b) > pruneIndexLimit {
		return nil, fmt.Errorf("%w: %s exceeds %d bytes", errUnreadable, p, pruneIndexLimit)
	}
	return b, nil
}
