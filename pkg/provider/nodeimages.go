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

package provider

import (
	"cmp"
	"context"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"k3sm.io/runtimed/pkg/image"
)

// nodeStatusMaxImages caps how many images the node reports in
// Node.status.images. It is the kubelet's default for --node-status-max-images
// (50): the list is sorted largest first and truncated, so the images a
// scheduler's image-locality scoring most wants to see survive the cap, and the
// Node object stays a bounded size on a node that holds hundreds of images.
const nodeStatusMaxImages = 50

// nodeStatusMaxNamesPerImage caps the names one image entry carries. It is the
// kubelet's MaxNamesPerImageInNodeStatus (5), applied after the digest names
// and before the tags, exactly as the kubelet orders them.
const nodeStatusMaxNamesPerImage = 5

// ImageInventory is an OPTIONAL Runtime capability: a Runtime backed by a local
// image store that can say what that store holds. The node-status loop reads it
// to publish Node.status.images, the field a kubelet fills from its container
// runtime's image list.
//
// The runtimed runtime implements it; HostProcess does not — it has no image
// store, so a node running it reports no images, which is the truthful answer.
// Defining it here, at the consumer, keeps the core Runtime seam small, the same
// pattern as StatsSource and HealthReporter.
type ImageInventory interface {
	// ImageIndexSnapshot returns every image the store records, one entry per
	// (reference x platform).
	ImageIndexSnapshot(ctx context.Context) ([]image.IndexEntry, error)
}

// nodeImages reduces the image index to the kubelet's Node.status.images shape.
//
// The index is keyed by reference, so one image held under two tags is two
// entries; the kubelet reports it once, with every name. Entries are therefore
// grouped by the digest a tag resolved to (the multi-platform index digest when
// the reference went through one, else the manifest's own), and each group
// becomes one ContainerImage whose names are its digest references
// (repository@digest) followed by its tag references, capped at
// nodeStatusMaxNamesPerImage. An entry recorded without a digest cannot be
// grouped by one and stands alone under its own reference.
//
// sizeBytes is the image's manifest total (manifest, config and each distinct
// layer). The result is sorted by size, largest first, ties by first name so the
// order is stable across refreshes, and truncated to limit entries (limit < 0 keeps
// every entry, as --node-status-max-images=-1 does).
func nodeImages(entries []image.IndexEntry, limit int) []corev1.ContainerImage {
	type group struct {
		digests, tags map[string]bool
		size          int64
	}
	groups := make(map[string]*group)
	var order []string
	for _, e := range entries {
		ref := e.Reference
		if ref == "" || !publishableReference(ref) {
			continue
		}
		digest := e.Manifest.GetIndexDigest()
		if digest == "" {
			digest = e.Descriptor.GetDigest()
		}
		key := "digest:" + digest
		if digest == "" {
			key = "ref:" + ref
		}
		g, ok := groups[key]
		if !ok {
			g = &group{digests: make(map[string]bool), tags: make(map[string]bool)}
			groups[key] = g
			order = append(order, key)
		}
		if strings.Contains(ref, "@") {
			g.digests[ref] = true
		} else {
			g.tags[ref] = true
		}
		if wellFormedDigest(digest) {
			g.digests[referenceRepository(ref)+"@"+digest] = true
		}
		g.size = max(g.size, e.TotalSize())
	}

	out := make([]corev1.ContainerImage, 0, len(order))
	for _, key := range order {
		g := groups[key]
		names := append(sortedKeys(g.digests), sortedKeys(g.tags)...)
		if len(names) > nodeStatusMaxNamesPerImage {
			names = names[:nodeStatusMaxNamesPerImage]
		}
		out = append(out, corev1.ContainerImage{Names: names, SizeBytes: g.size})
	}
	slices.SortStableFunc(out, func(a, b corev1.ContainerImage) int {
		if c := cmp.Compare(b.SizeBytes, a.SizeBytes); c != 0 {
			return c
		}
		return cmp.Compare(a.Names[0], b.Names[0])
	})
	if limit >= 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// publishableReference reports whether ref may be published in
// Node.status.images, which anyone who can read nodes can read.
//
// The index keys are references the go-containerregistry parser accepted
// (name.ParseReference) at pull or load, recorded as the caller spelled them,
// not rewritten to a canonical form: a short "alpine@sha256:…" stays short. The
// parser refuses credentials in a reference, so this is defence in depth for
// a record written by any other path. An '@' in an image reference may only
// introduce a digest at its end, so a reference whose text after its first
// '@' is not a well-formed sha256 or sha512 digest carries userinfo
// ("user:pass@registry/app") and is dropped, never published.
func publishableReference(ref string) bool {
	at := strings.IndexByte(ref, '@')
	if at < 0 {
		return true
	}
	return wellFormedDigest(ref[at+1:])
}

// wellFormedDigest reports whether d is "sha256:" with 64 lowercase hex digits
// or "sha512:" with 128, the two algorithms the OCI image spec registers.
func wellFormedDigest(d string) bool {
	alg, hex, ok := strings.Cut(d, ":")
	if !ok {
		return false
	}
	switch {
	case alg == "sha256" && len(hex) == 64, alg == "sha512" && len(hex) == 128:
	default:
		return false
	}
	for _, c := range hex {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// referenceRepository strips the tag and any digest from an image reference,
// leaving the repository a digest reference is formed from. A colon counts as a
// tag separator only after the last slash, so a registry port survives.
func referenceRepository(ref string) string {
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndexByte(ref, ':'); i > strings.LastIndexByte(ref, '/') {
		ref = ref[:i]
	}
	return ref
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
