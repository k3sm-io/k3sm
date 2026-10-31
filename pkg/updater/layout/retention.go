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

package layout

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

var (
	// ErrStagingFull reports a request to stage a version while another
	// staged version is already kept: the tree keeps current, previous and one
	// staged version, so a fourth staged version is refused.
	ErrStagingFull = errors.New("a staged version is already kept; a fourth staged version is refused")
	// ErrStageRetained reports a request to stage a version the tree already
	// keeps as current, as previous or for a running pod: staging writes into
	// versions/<ver>/, which those versions are still running from.
	ErrStageRetained = errors.New("the version is current, previous or in use by a running pod and cannot be staged")
	// ErrUnresolvedPodPath reports a pod path, or the versions directory
	// itself, whose symlinks could not be resolved. The versions such a path
	// names are unknown, so a caller that receives it must not prune.
	ErrUnresolvedPodPath = errors.New("pod path cannot be resolved")
)

// KeepReason says why a prune keeps a version directory.
type KeepReason string

// The reasons a version is kept, in the order Reasons reports them.
const (
	KeepCurrent  KeepReason = "current"
	KeepPrevious KeepReason = "previous"
	KeepStaging  KeepReason = "staging"
	KeepInUse    KeepReason = "in use by pods"
)

// Retained is what a prune must keep. Current, Previous and Staged are the
// versions the tree's links and the updater's journal name; any may be empty.
// InUse is the set of versions the node's running pods were started under: a
// pod's DYLD shims and shadow directory are captured at pod start as paths
// inside versions/<ver>/, so the directory must outlive the flips that move
// <ver> past previous for as long as such a pod runs.
type Retained struct {
	Current  string
	Previous string
	Staged   string
	InUse    []string
}

// Reasons returns every reason r keeps ver, in the order current, previous,
// staging, in use by pods; nil when r does not keep it.
func (r Retained) Reasons(ver string) []KeepReason {
	if ver == "" {
		return nil
	}
	var out []KeepReason
	if ver == r.Current {
		out = append(out, KeepCurrent)
	}
	if ver == r.Previous {
		out = append(out, KeepPrevious)
	}
	if ver == r.Staged {
		out = append(out, KeepStaging)
	}
	if slices.Contains(r.InUse, ver) {
		out = append(out, KeepInUse)
	}
	return out
}

// Kept is a version directory a prune keeps and every reason it keeps it, for
// a status surface that shows why a version persists.
type Kept struct {
	Version string
	Reasons []KeepReason
}

// PrunePlan is the outcome of PlanPrune. Remove lists the version directories
// a prune removes; Keep lists every valid version directory present that it
// keeps, with its reasons. Both are sorted by version name.
type PrunePlan struct {
	Remove []string
	Keep   []Kept
}

// PlanPrune plans a prune over present (the names read from the versions
// directory): every valid version name r does not retain is removed, and every
// one it retains is kept with its reasons. A name that is not a valid version
// directory name, a temporary or partial name included, appears in neither
// list: the prune removes only what it recognises and leaves the rest for a
// person.
func PlanPrune(present []string, r Retained) PrunePlan {
	names := slices.Clone(present)
	slices.Sort(names)
	names = slices.Compact(names)
	var plan PrunePlan
	for _, ver := range names {
		if ValidateVersion(ver) != nil {
			continue
		}
		if reasons := r.Reasons(ver); len(reasons) > 0 {
			plan.Keep = append(plan.Keep, Kept{Version: ver, Reasons: reasons})
			continue
		}
		plan.Remove = append(plan.Remove, ver)
	}
	return plan
}

// CheckStage reports whether ver may be staged. Staging the version already
// staged is allowed (a retry). Staging the current or previous version, or a
// version a running pod uses, is ErrStageRetained: staging rewrites
// versions/<ver>/, which those are running from. Staging any other version
// while one is staged is ErrStagingFull. Versions kept only because a running
// pod uses them do not count toward the limit: they are retained, never
// staged, so a long-running pod never blocks the next update.
//
// The InUse set is read after this decision is taken, so it can be stale: a
// pod that starts under ver after the report was read re-pins it, and the
// prune that follows the next commit reads a fresh report.
func CheckStage(r Retained, ver string) error {
	if err := ValidateVersion(ver); err != nil {
		return err
	}
	if ver != r.Staged {
		if reasons := r.Reasons(ver); len(reasons) > 0 {
			return fmt.Errorf("stage %s (%s): %w", ver, joinReasons(reasons), ErrStageRetained)
		}
	}
	if r.Staged != "" && r.Staged != ver {
		return fmt.Errorf("stage %s while %s is staged: %w", ver, r.Staged, ErrStagingFull)
	}
	return nil
}

func joinReasons(reasons []KeepReason) string {
	s := make([]string, len(reasons))
	for i, r := range reasons {
		s[i] = string(r)
	}
	return strings.Join(s, ", ")
}

// EvalSymlinks resolves every symlink in a path, as filepath.EvalSymlinks
// does. It is the seam PodVersions reads the tree through.
type EvalSymlinks func(path string) (string, error)

// PodVersions returns, sorted and without duplicates, the versions the given
// pod paths name: each path a running pod was started with (a DYLD shim, the
// shadow directory) that lies inside root/versions/<ver>/ with a valid <ver>
// contributes <ver>. A relative path, or one outside the versions directory,
// contributes nothing.
//
// Each absolute path is resolved with eval and then cleaned before the check,
// and compared against the resolved versions directory, so a path spelled
// through a symlink (current, previous, or a link above root) names the
// version it really lies in. The prefix is compared without regard to case,
// because the default APFS volume is case-insensitive and a differently cased
// spelling names the same directory; on a case-sensitive volume this can only
// keep more, never less.
//
// A path that cannot be resolved is never silently dropped: the versions of
// every other path are still returned, and the error joins one
// ErrUnresolvedPodPath per such path (or one for the versions directory, in
// which case no path is checked). The caller must not prune when the error is
// non-nil, since an unresolved path may name any version. The node passes the
// paths of its running pods and reports the result as Retained.InUse.
func (l Layout) PodVersions(paths []string, eval EvalSymlinks) ([]string, error) {
	dir, err := eval(l.VersionsDir())
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w: %w", l.VersionsDir(), ErrUnresolvedPodPath, err)
	}
	prefix := filepath.Clean(dir) + string(filepath.Separator)
	var out []string
	var errs []error
	for _, p := range paths {
		if !filepath.IsAbs(p) {
			continue
		}
		resolved, err := eval(p)
		if err != nil {
			errs = append(errs, fmt.Errorf("resolve %s: %w: %w", p, ErrUnresolvedPodPath, err))
			continue
		}
		resolved = filepath.Clean(resolved)
		if len(resolved) <= len(prefix) || !strings.EqualFold(resolved[:len(prefix)], prefix) {
			continue
		}
		ver, _, _ := strings.Cut(resolved[len(prefix):], string(filepath.Separator))
		if ValidateVersion(ver) == nil {
			out = append(out, ver)
		}
	}
	slices.Sort(out)
	return slices.Compact(out), errors.Join(errs...)
}
