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
	"fmt"
	"path/filepath"
)

// Op is the kind of one step of a flip plan.
type Op int

const (
	// OpRemoveStale removes Path if it exists: a temporary link a crashed
	// flip left behind, which would make the symlink step fail.
	OpRemoveStale Op = iota + 1
	// OpSymlink creates the symlink Path with the content Target.
	OpSymlink
	// OpRename renames Path over Target in one rename(2), which replaces an
	// existing Target atomically.
	OpRename
)

// String returns the step kind's name.
func (o Op) String() string {
	switch o {
	case OpRemoveStale:
		return "remove-stale"
	case OpSymlink:
		return "symlink"
	case OpRename:
		return "rename"
	}
	return fmt.Sprintf("Op(%d)", int(o))
}

// Step is one filesystem operation of a flip plan.
type Step struct {
	// Op is what the step does.
	Op Op
	// Path is the name the step removes, creates or renames.
	Path string
	// Target is the symlink content (OpSymlink) or the rename destination
	// (OpRename); empty for OpRemoveStale.
	Target string
}

// PlanFlip returns the steps that make to the current version and from the
// previous one. Each link is replaced the same way: a stale temporary name is
// removed, a new symlink is created under the temporary name, and it is
// renamed over the live name, so a reader sees the old link or the new one,
// never neither. current is flipped first; previous follows only when from is
// not empty (a first activation has no previous). The links are relative
// (versions/<ver>), so the tree keeps working when it is read under another
// root. A flip to the version already current is ErrNoChange.
func (l Layout) PlanFlip(from, to string) ([]Step, error) {
	if err := ValidateVersion(to); err != nil {
		return nil, fmt.Errorf("flip to: %w", err)
	}
	if from != "" {
		if err := ValidateVersion(from); err != nil {
			return nil, fmt.Errorf("flip from: %w", err)
		}
	}
	if from == to {
		return nil, fmt.Errorf("flip to %s: %w", to, ErrNoChange)
	}
	steps := replaceLink(l.Current(), filepath.Join(VersionsName, to))
	if from != "" {
		steps = append(steps, replaceLink(l.Previous(), filepath.Join(VersionsName, from))...)
	}
	return steps, nil
}

// replaceLink is the three steps that atomically point link at target.
func replaceLink(link, target string) []Step {
	tmp := link + TempSuffix
	return []Step{
		{Op: OpRemoveStale, Path: tmp},
		{Op: OpSymlink, Path: tmp, Target: target},
		{Op: OpRename, Path: tmp, Target: link},
	}
}
