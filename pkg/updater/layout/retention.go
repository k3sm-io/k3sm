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

// ErrStagingFull reports a request to stage a version while another staged
// version is already kept: the tree keeps current, previous and one staged
// version, so a fourth staged version is refused.
var ErrStagingFull = errors.New("a staged version is already kept; a fourth staged version is refused")

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

// keeps reports whether r retains ver.
func (r Retained) keeps(ver string) bool {
	return ver == r.Current || ver == r.Previous || ver == r.Staged || slices.Contains(r.InUse, ver)
}

// PlanPrune returns, sorted, the entries of present (the names read from the
// versions directory) that a prune removes: every valid version name r does
// not retain. A name that is not a valid version directory name, a temporary
// or partial name included, is never returned: the prune removes only what it
// recognises and leaves the rest for a person.
func PlanPrune(present []string, r Retained) []string {
	var out []string
	for _, ver := range present {
		if ValidateVersion(ver) != nil || r.keeps(ver) {
			continue
		}
		out = append(out, ver)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// CheckStage reports whether ver may be staged. Staging the version already
// staged is allowed (a retry); staging any other version while one is staged
// is ErrStagingFull. Versions kept only because a running pod uses them do not
// count toward the limit: they are retained, never staged, so a long-running
// pod never blocks the next update.
func CheckStage(r Retained, ver string) error {
	if err := ValidateVersion(ver); err != nil {
		return err
	}
	if r.Staged != "" && r.Staged != ver {
		return fmt.Errorf("stage %s while %s is staged: %w", ver, r.Staged, ErrStagingFull)
	}
	return nil
}

// PodVersions returns, sorted and without duplicates, the versions the given
// pod paths name: each path a running pod was started with (a DYLD shim, the
// shadow directory) that lies inside root/versions/<ver>/ with a valid <ver>
// contributes <ver>. A relative path, a path through current or previous, or
// one outside the versions directory contributes nothing. The node passes the
// paths of its running pods and reports the result as Retained.InUse.
func (l Layout) PodVersions(paths []string) []string {
	prefix := l.VersionsDir() + string(filepath.Separator)
	var out []string
	for _, p := range paths {
		if !filepath.IsAbs(p) {
			continue
		}
		rest, ok := strings.CutPrefix(filepath.Clean(p), prefix)
		if !ok {
			continue
		}
		ver, _, _ := strings.Cut(rest, string(filepath.Separator))
		if ValidateVersion(ver) == nil {
			out = append(out, ver)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}
