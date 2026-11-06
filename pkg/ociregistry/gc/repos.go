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

package gc

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/opencontainers/go-digest"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// RepositoriesReport is what SweepRepositories did.
type RepositoriesReport struct {
	Report
	// BlobBytes is the total size of the blobs in Objects that the sweep
	// reaped (none in a report-only sweep). A blob whose inode another
	// repository still links gives its space back only when the last link
	// goes, so this is what the swept repositories stopped holding, which can
	// be more than the volume got back.
	BlobBytes int64
}

// SweepRepositories runs one collection over the named repositories only, on
// Sweep's terms: no sweep within one grace period of the collector's start,
// the same grace, the same mark and locked pass under each repository's lock,
// and the same brakes. A repository the marker does not name as reviewed is
// only reported on (Reviewing and WouldReap), as Sweep would; this sweep
// never adds one to the marker, which stays Sweep's to grow. A name the store
// does not hold, or that is given twice, is skipped. A repository stopped by a
// brake or an error is listed in Stopped or Failed and named in the returned
// error; the others are still swept.
//
// It runs one at a time with Sweep. When it reaps a repository's layout it
// takes that name out of the marker, as Sweep does for a name that left the
// store, so a repository pushed again under it is reported on before it is
// swept.
func (c *Collector) SweepRepositories(ctx context.Context, names []ref.Name) (RepositoriesReport, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now := c.now(); now.Before(c.start.Add(c.grace)) {
		return RepositoriesReport{}, fmt.Errorf("%w: started %s, grace %s", ErrTooSoon, c.start.Format(time.RFC3339), c.grace)
	}
	id, _, err := c.s.ID()
	if err != nil {
		return RepositoriesReport{Report: Report{ReportOnly: true}}, fmt.Errorf("gc: %w", err)
	}
	reviewed, err := readReviewed(filepath.Join(c.s.StateDir(), MarkerName), id, c.s.Root(), c.log)
	if err != nil {
		return RepositoriesReport{Report: Report{ReportOnly: true}}, err
	}
	held, err := c.s.Repositories()
	if err != nil {
		return RepositoriesReport{}, err
	}
	present := make(map[string]bool, len(held))
	for _, n := range held {
		present[n.String()] = true
	}
	var rep RepositoriesReport
	var errs []error
	swept := map[string]bool{}
	removed := map[string]bool{}
	for _, n := range names {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		name := n.String()
		if swept[name] || !present[name] {
			continue
		}
		swept[name] = true
		sizes := c.blobSizes(n)
		review := !reviewed[name]
		objs, err := c.sweepRepo(ctx, n, review)
		if review {
			rep.Reviewing = append(rep.Reviewing, name)
			rep.WouldReap = append(rep.WouldReap, objs...)
		} else {
			rep.Objects = append(rep.Objects, objs...)
			for _, o := range objs {
				switch o.Kind {
				case KindBlob:
					rep.BlobBytes += sizes[digest.Digest(o.Name)]
				case KindRepository:
					removed[name] = true
				}
			}
		}
		if err != nil {
			if errors.Is(err, ErrMassDelete) {
				rep.Stopped = append(rep.Stopped, name)
			} else {
				rep.Failed = append(rep.Failed, name)
			}
			errs = append(errs, fmt.Errorf("gc %s: %w", n, err))
		}
	}
	rep.ReportOnly = len(swept) > 0 && len(rep.Reviewing) == len(swept)
	if rep.ReportOnly {
		rep.Objects = rep.WouldReap
	}
	if len(removed) > 0 {
		next := maps.Clone(reviewed)
		maps.DeleteFunc(next, func(name string, _ bool) bool { return removed[name] })
		if err := writeReviewed(c.s, c.now(), next); err != nil {
			errs = append(errs, fmt.Errorf("%w: a repository pushed again under %s is swept before it is reported on until the marker is rewritten",
				err, joinNames(removed)))
		}
	}
	return rep, errors.Join(errs...)
}

// blobSizes maps each blob n holds now to its size. A blob's name is its
// content's digest, so the size it has before a sweep is the size it had when
// the sweep removed it. A listing that fails maps nothing, and the blobs a
// sweep then reaps count no bytes.
func (c *Collector) blobSizes(n ref.Name) map[digest.Digest]int64 {
	cont, err := c.s.Contents(n)
	if err != nil {
		return nil
	}
	sizes := make(map[digest.Digest]int64, len(cont.Blobs))
	for _, b := range cont.Blobs {
		sizes[b.Digest] = b.Size
	}
	return sizes
}

// joinNames lists a set of repository names, sorted, for a message.
func joinNames(set map[string]bool) string {
	return strings.Join(slices.Sorted(maps.Keys(set)), ", ")
}
