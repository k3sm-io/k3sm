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
	"time"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// The registry half of `k3sm image prune`: which untagged manifests in this
// server's registry may be deleted.
//
// THE PLAN READS THE STORE AND NEVER WRITES IT. Every repository is an OCI
// image layout under StateDir, and its index.json lists every manifest the
// repository holds, tagged or not; the dist-spec API has no way to list the
// untagged ones. The plan reads that layout only through pkg/ociregistry/store,
// opened read-only, so the registry has one parser of its own layout. The
// deletion itself is a DELETE through the registry's API with this node's
// push credential, so the server stays the only writer: it updates its own
// index under its own lock, and its GC reclaims the blobs.

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
	// KeepTaggedSincePlan is a planned manifest a push tagged after the plan
	// was read. A delete by digest would drop that tag.
	KeepTaggedSincePlan KeepReason = "tagged since the plan"
	// GoneSincePlan is a planned manifest no longer in its repository when its
	// delete comes up, or whose repository is gone: something else deleted it.
	// Prune sends no DELETE for it and does not count it as one of its own
	// deletions.
	GoneSincePlan KeepReason = "already gone since the plan"
	// KeepChangedSincePlan is a planned manifest whose conditional DELETE the
	// registry refused: the repository changed between the re-check and the
	// delete, so the re-check's verdict no longer holds.
	KeepChangedSincePlan KeepReason = "repository changed at delete"
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

// Repositories lists the repositories the store under workDir holds, sorted.
func Repositories(workDir string) ([]string, error) {
	r, err := store.OpenReader(StateDir(workDir))
	if err != nil {
		return nil, fmt.Errorf("list the registry's repositories: %w", err)
	}
	names, err := r.Repositories()
	if err != nil {
		return nil, fmt.Errorf("list the registry's repositories under %s: %w", r.Root(), err)
	}
	repos := make([]string, 0, len(names))
	for _, n := range names {
		repos = append(repos, n.String())
	}
	return repos, nil
}

// manifestLinks is the subset of a manifest or index that links it to other
// manifests: an index's children and a referrer's subject.
type manifestLinks struct {
	Manifests []ispec.Descriptor `json:"manifests"`
	Subject   *ispec.Descriptor  `json:"subject"`
}

// errUnreadable marks a repository the plan must not delete from.
var errUnreadable = errors.New("repository not fully readable")

// PlanRepository plans one repository. It never fails: a repository it cannot
// read completely keeps all its untagged manifests under KeepUnreadable, and
// one the store no longer holds (deleted since it was listed) plans nothing.
func PlanRepository(workDir, repo string, now time.Time) PrunePlan {
	return planRepository(workDir, repo, now).plan
}

// repoPlan is one read of a repository: its plan, every digest its index holds
// mapped to whether any row tags it, and the index state the plan was made
// from (store.IndexState). present is nil, and err says why, when the index
// itself could not be read.
type repoPlan struct {
	plan    PrunePlan
	present map[string]bool
	state   string
	err     error
}

// planRepository is PlanRepository that also returns what the plan was read
// from.
func planRepository(workDir, repo string, now time.Time) repoPlan {
	unreadable := func(err error) repoPlan {
		// A repository the store no longer holds has nothing to plan; it is
		// gone, not unreadable.
		if errors.Is(err, store.ErrRepositoryUnknown) {
			return repoPlan{err: err}
		}
		return repoPlan{plan: PrunePlan{Unreadable: []string{repo}}, err: err}
	}
	n, err := ref.ParseName(repo)
	if err != nil {
		return unreadable(err)
	}
	r, err := store.OpenReader(StateDir(workDir))
	if err != nil {
		return unreadable(err)
	}
	idx, err := r.Index(n)
	if err != nil {
		return unreadable(err)
	}
	state, err := store.IndexState(idx.Manifests)
	if err != nil {
		return unreadable(err)
	}
	type entry struct {
		m      StoredManifest
		tagged bool
	}
	byDigest := map[string]*entry{}
	var order []string
	for _, d := range idx.Manifests {
		// A digest is read from a file and then resolved to a blob path, so
		// anything but a canonical sha256 or sha512 digest makes the whole
		// repository unreadable rather than being opened.
		if _, err := ref.ParseDigest(d.Digest.String()); err != nil {
			return unreadable(err)
		}
		dg := d.Digest.String()
		e, ok := byDigest[dg]
		if !ok {
			e = &entry{m: StoredManifest{Repository: repo, Digest: dg, MediaType: d.MediaType, Size: d.Size}}
			byDigest[dg] = e
			order = append(order, dg)
		}
		// A delete by digest drops EVERY row with that digest, tags included,
		// so one tagged row makes the whole digest tagged.
		if d.Annotations[ispec.AnnotationRefName] != "" {
			e.tagged = true
		}
	}
	present := make(map[string]bool, len(byDigest))
	for dg, e := range byDigest {
		present[dg] = e.tagged
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

	links := map[string]manifestLinks{}
	kept := map[string]KeepReason{}
	for _, dg := range order {
		l, modTime, err := readManifest(r, n, dg)
		if err != nil {
			return repoPlan{plan: untagged(KeepUnreadable), present: present, state: state}
		}
		links[dg] = l
		if byDigest[dg].tagged {
			kept[dg] = ""
			continue
		}
		if now.Sub(modTime) < PruneGrace {
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
					cd := c.Digest.String()
					if _, ok := kept[cd]; !ok {
						if _, inRepo := byDigest[cd]; inRepo {
							kept[cd] = KeepChildOfKept
							changed = true
						}
					}
				}
				continue
			}
			if s := links[dg].Subject; s != nil {
				if _, ok := kept[s.Digest.String()]; ok {
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
	return repoPlan{plan: p, present: present, state: state}
}

// Recheck re-plans the repository of a planned manifest from its current
// state, immediately before that manifest's delete. It returns why the
// manifest must now be kept, or "" and the repository state (store.IndexState)
// the fresh plan was read from, which the caller's DELETE names as its
// condition (DeleteManifest).
//
// A plan goes stale while its deletes run. A push may tag a planned digest (a
// delete by digest drops every row with it, the new tag too), re-push it into
// the grace period, or tag an index that names it or that it refers to. So
// Recheck does not test the digest alone: it runs the same planning
// PlanRepository runs, keep closure included, and the digest may go only if
// it is still in that fresh plan's delete set. Otherwise the reason is the
// fresh plan's own (KeepChildOfKept, KeepReferrer, KeepRecent), or
// KeepTaggedSincePlan for a digest now tagged, or GoneSincePlan for a digest
// no longer in the index or a repository no longer in the store, which the
// caller skips rather than deletes, or KeepUnreadable for anything else it
// cannot read.
//
// The state closes the window between this re-check and the DELETE: a
// registry that honours If-Match refuses the delete once any row of the
// repository has changed, so a push landing in between is never lost. Each
// call re-reads every manifest of the repository, so a prune of n planned
// manifests reads the repository n times.
func Recheck(workDir string, m StoredManifest, now time.Time) (KeepReason, string) {
	rp := planRepository(workDir, m.Repository, now)
	if rp.present == nil {
		if errors.Is(rp.err, store.ErrRepositoryUnknown) {
			return GoneSincePlan, ""
		}
		return KeepUnreadable, ""
	}
	tagged, ok := rp.present[m.Digest]
	switch {
	case !ok:
		return GoneSincePlan, ""
	case tagged:
		return KeepTaggedSincePlan, ""
	}
	for _, d := range rp.plan.Delete {
		if d.Digest == m.Digest {
			return "", rp.state
		}
	}
	for _, k := range rp.plan.Kept {
		if k.Digest == m.Digest {
			return k.Reason, ""
		}
	}
	// An untagged digest in the index is always in one of the two lists; keep
	// it should that ever not hold.
	return KeepUnreadable, ""
}

// readManifest reads one manifest through the store, which checks its body
// against the index row's digest and size, and returns its links and the
// modification time of its blob.
func readManifest(r *store.Reader, n ref.Name, dg string) (manifestLinks, time.Time, error) {
	d, err := ref.ParseDigest(dg)
	if err != nil {
		return manifestLinks{}, time.Time{}, fmt.Errorf("%w: %w", errUnreadable, err)
	}
	_, body, err := r.Manifest(n, ref.Reference{Digest: d})
	if err != nil {
		return manifestLinks{}, time.Time{}, fmt.Errorf("%w: %w", errUnreadable, err)
	}
	var l manifestLinks
	if err := json.Unmarshal(body, &l); err != nil {
		return manifestLinks{}, time.Time{}, fmt.Errorf("%w: parse manifest %s: %w", errUnreadable, dg, err)
	}
	f, err := r.OpenBlob(n, d)
	if err != nil {
		return manifestLinks{}, time.Time{}, fmt.Errorf("%w: %w", errUnreadable, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return manifestLinks{}, time.Time{}, fmt.Errorf("%w: stat manifest %s: %w", errUnreadable, dg, err)
	}
	return l, fi.ModTime(), nil
}
