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

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	runtimev1 "k3sm.io/apis/runtime/v1"

	"k3sm.io/k3sm/pkg/registrysvc"
)

// pruneReport is the `k3sm image prune -o json` document: what the prune
// deleted, or would delete, from the cluster registry and from this node's
// cache. The field names are the contract the app reads.
type pruneReport struct {
	DryRun   bool                `json:"dryRun"`
	Registry registryPruneResult `json:"registry"`
	Cache    cachePruneResult    `json:"cache"`
}

// registryPruneResult is the registry half of a prune.
type registryPruneResult struct {
	// Name is the registry's cluster name, the one Pod specs use.
	Name string `json:"name"`
	// Skipped says why this node pruned no registry: it runs none. It is empty
	// when the registry was planned.
	Skipped string `json:"skipped,omitempty"`
	// Manifests are the untagged manifests deleted, or that would be.
	Manifests []registrysvc.StoredManifest `json:"manifests"`
	// Kept are the untagged manifests the prune keeps, each with its reason.
	Kept []registrysvc.KeptManifest `json:"kept"`
	// Unreadable are repositories whose index could not be read; nothing in
	// them is touched.
	Unreadable []string `json:"unreadable,omitempty"`
	// Failed are deletions the registry refused, under --force.
	Failed []failedManifest `json:"failed,omitempty"`
}

// failedManifest is a deletion the registry refused.
type failedManifest struct {
	registrysvc.StoredManifest
	Error string `json:"error"`
}

// cachePruneResult is the node-cache half of a prune, as runtimed answered it.
type cachePruneResult struct {
	Blobs          []string       `json:"blobs"`
	ReclaimedBytes uint64         `json:"reclaimedBytes"`
	Kept           map[string]int `json:"kept,omitempty"`
}

// manifestDeleter deletes one manifest by digest from a registry. It is the
// seam the force path is proved through without a zot.
type manifestDeleter func(ctx context.Context, ref name.Digest, auth authn.Authenticator) error

// deleteManifest is the production manifestDeleter: a dist-spec DELETE.
var deleteManifest manifestDeleter = func(ctx context.Context, ref name.Digest, auth authn.Authenticator) error {
	return remote.Delete(ref, remote.WithAuth(auth), remote.WithContext(ctx))
}

// errPruneIncomplete reports that some registry deletions failed. Everything
// else the prune did stands, and the report lists what failed.
var errPruneIncomplete = errors.New("some untagged manifests were not deleted")

// imagePrune prunes the cluster registry's untagged manifests and evicts
// this node's cache, dry run unless --force.
//
// The registry half runs only on the server whose registry it is: it reads
// zot's storage under the work dir to find untagged manifests, and deletes
// each through zot's API on loopback with this node's push credential, the
// one identity zot lets delete. The in-pod push gate still refuses DELETE;
// nothing about who may delete changes. zot's GC reclaims the blobs a
// deleted manifest held on its next sweep.
//
// The cache half is runtimed's PruneImages, which keeps everything a pod
// uses. It runs FIRST, so a daemon that cannot be reached or refuses fails the
// command before any registry manifest is deleted.
func imagePrune(ctx context.Context, client runtimev1.ImagesClient, o imageOptions, out io.Writer, del manifestDeleter, now time.Time) error {
	report := pruneReport{
		DryRun: !o.force,
		Registry: registryPruneResult{
			Name:      flatRegistryHost,
			Manifests: []registrysvc.StoredManifest{},
			Kept:      []registrysvc.KeptManifest{},
		},
		Cache: cachePruneResult{Blobs: []string{}},
	}

	cred, skipped, err := pruneCredential(o.workDir)
	if err != nil {
		return err
	}
	report.Registry.Skipped = skipped

	resp, err := client.PruneImages(ctx, &runtimev1.PruneImagesRequest{DryRun: !o.force})
	if err != nil {
		return imageRPCError("prune images", o.socket, err)
	}
	report.Cache.Blobs = append(report.Cache.Blobs, resp.GetRemovedDigests()...)
	report.Cache.ReclaimedBytes = resp.GetReclaimedBytes()
	if counts := skipCounts(resp.GetSkipped()); len(counts) > 0 {
		report.Cache.Kept = counts
	}

	var failed int
	if skipped == "" {
		failed, err = pruneRegistry(ctx, o, cred, &report.Registry, del, now)
		if err != nil {
			return err
		}
	}

	if o.output == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return fmt.Errorf("render the prune report: %w", err)
		}
	} else {
		renderPrune(out, report)
	}
	if failed > 0 {
		return fmt.Errorf("prune %s: %w (%d failed; see the report)", flatRegistryHost, errPruneIncomplete, failed)
	}
	return nil
}

// pruneCredential reads this node's push credential. A node with none runs
// no registry: the cluster registry is pruned on the server that runs it, so
// this node's prune skips that half and says so. Any other failure (most often
// a caller who is not the control plane's user) is an error, not a skip: a
// silent skip would read as "the registry had nothing to prune".
func pruneCredential(workDir string) (registrysvc.Credential, string, error) {
	if workDir == "" {
		return registrysvc.Credential{}, "no control-plane work dir: this node runs no registry", nil
	}
	cred, err := registrysvc.ReadCredential(workDir)
	if errors.Is(err, registrysvc.ErrNoCredential) {
		return registrysvc.Credential{}, "this node runs no registry; prune the cluster registry on the server that runs it", nil
	}
	if err != nil {
		return registrysvc.Credential{}, "", fmt.Errorf("prune %s: %w (run as the control plane's user, or point --work-dir at its state root)", flatRegistryHost, err)
	}
	return cred, "", nil
}

// pruneRegistry plans each repository and, under --force, deletes its
// untagged manifests. It returns how many deletions failed.
//
// Each repository is planned IMMEDIATELY before its deletions, not once up
// front, because zot's delete by digest drops every tag on that digest: a tag
// pushed onto an untagged manifest between plan and delete must take it out
// of the plan. The window that remains is the one between the read and the
// DELETE.
func pruneRegistry(ctx context.Context, o imageOptions, cred registrysvc.Credential, res *registryPruneResult, del manifestDeleter, now time.Time) (int, error) {
	repos, err := registrysvc.Repositories(o.workDir)
	if err != nil {
		return 0, fmt.Errorf("prune %s: %w", flatRegistryHost, err)
	}
	var authority string
	auth := authn.FromConfig(authn.AuthConfig{Username: cred.Username, Password: cred.Password})
	if o.force {
		if authority, err = nodeRegistryAuthority(o.workDir); err != nil {
			return 0, fmt.Errorf("prune %s: %w", flatRegistryHost, err)
		}
	}
	failed := 0
	for _, repo := range repos {
		plan := registrysvc.PlanRepository(o.workDir, repo, now)
		res.Kept = append(res.Kept, plan.Kept...)
		res.Unreadable = append(res.Unreadable, plan.Unreadable...)
		for _, m := range plan.Delete {
			if !o.force {
				res.Manifests = append(res.Manifests, m)
				continue
			}
			ref, err := name.NewDigest(authority + "/" + m.Repository + "@" + m.Digest)
			if err == nil {
				err = del(ctx, ref, auth)
			}
			if err != nil {
				res.Failed = append(res.Failed, failedManifest{StoredManifest: m, Error: err.Error()})
				failed++
				continue
			}
			res.Manifests = append(res.Manifests, m)
		}
	}
	return failed, nil
}

// renderPrune renders a prune report as the operator's table.
func renderPrune(out io.Writer, r pruneReport) {
	verb := "would delete"
	if !r.DryRun {
		verb = "deleted"
	}
	reg := r.Registry
	fmt.Fprintf(out, "registry %s:\n", reg.Name)
	switch {
	case reg.Skipped != "":
		fmt.Fprintf(out, "  skipped: %s\n", reg.Skipped)
	default:
		for _, m := range reg.Manifests {
			fmt.Fprintf(out, "  %s %s@%s (untagged)\n", verb, m.Repository, m.Digest)
		}
		for _, m := range reg.Failed {
			fmt.Fprintf(out, "  could not delete %s@%s: %s\n", m.Repository, m.Digest, m.Error)
		}
		fmt.Fprintf(out, "  %s %d untagged manifest(s); the registry's garbage collection reclaims their layers on its next sweep\n", verb, len(reg.Manifests))
		if len(reg.Kept) > 0 {
			counts := map[string]int{}
			for _, k := range reg.Kept {
				counts[string(k.Reason)]++
			}
			fmt.Fprintln(out, "  kept untagged:")
			renderCounts(out, counts, "    ")
		}
		for _, repo := range reg.Unreadable {
			fmt.Fprintf(out, "  unreadable, left alone: %s\n", repo)
		}
	}

	fmt.Fprintln(out, "node cache:")
	if len(r.Cache.Blobs) == 0 {
		fmt.Fprintln(out, "  nothing to reclaim: every blob in the cache is referenced.")
	}
	for _, d := range r.Cache.Blobs {
		fmt.Fprintf(out, "  %s %s\n", verb, d)
	}
	fmt.Fprintf(out, "  %s %d blob(s), %s\n", verb, len(r.Cache.Blobs), humanBytes(r.Cache.ReclaimedBytes))
	// Kept blobs are summarized by REASON rather than listed one per line: an
	// operator asking "why is my disk still full" needs the shape of the answer,
	// and a store with thousands of layers would otherwise bury it.
	if len(r.Cache.Kept) > 0 {
		fmt.Fprintln(out, "  kept:")
		renderCounts(out, r.Cache.Kept, "    ")
	}
	if r.DryRun {
		fmt.Fprintln(out, "(dry run — pass --force to delete)")
	}
}

// renderCounts prints reason counts in a stable order.
func renderCounts(out io.Writer, counts map[string]int, indent string) {
	reasons := make([]string, 0, len(counts))
	for r := range counts {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	for _, r := range reasons {
		fmt.Fprintf(out, "%s%-28s %d\n", indent, r, counts[r])
	}
}
