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

package hf

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"
)

// ScratchPrefix starts the name of every scratch directory an import
// creates, so a leftover one is easy to find and to sweep.
const ScratchPrefix = "k3sm-hf-import-"

// StaleScratchAge is how long a scratch directory must have gone with no
// change anywhere inside it before an import sweeps it as abandoned. A live
// import writes all the time, and stops after two minutes without
// progress, so nothing live is that quiet.
const StaleScratchAge = 24 * time.Hour

// maxSweepWalk bounds the entries inspected inside one candidate. A
// candidate with more is left alone rather than judged on part of it.
const maxSweepWalk = 10_000

// errSweepWalkBound ends the walk of a candidate past maxSweepWalk.
var errSweepWalkBound = errors.New("too many entries to judge")

// sweepScratch removes, from parent, every directory named ScratchPrefix*
// that uid owns and in which nothing has changed for StaleScratchAge before
// now. It works through an os.Root on parent, never follows a symbolic link
// (a link with the prefix is left alone), and skips anything it cannot
// judge. It returns the names removed and the failures, which are not
// fatal to the import.
func sweepScratch(parent string, now time.Time, uid int) ([]string, []error) {
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, nil // MkdirTemp reports an unusable parent
	}
	defer root.Close()
	d, err := root.Open(".")
	if err != nil {
		return nil, []error{err}
	}
	entries, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return nil, []error{fmt.Errorf("list %s: %w", parent, err)}
	}
	var removed []string
	var errs []error
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, ScratchPrefix) {
			continue
		}
		fi, err := root.Lstat(name)
		if err != nil || !fi.IsDir() {
			continue // gone, a link, or a file: not ours to remove
		}
		if owner, ok := fileOwner(fi); !ok || owner != uid {
			continue
		}
		newest, err := newestChange(root, name)
		if err != nil || now.Sub(newest) < StaleScratchAge {
			continue
		}
		if err := root.RemoveAll(name); err != nil {
			errs = append(errs, fmt.Errorf("remove leftover %s: %w", name, err))
			continue
		}
		removed = append(removed, name)
	}
	return removed, errs
}

// newestChange is the latest modification time of name and everything
// under it, read with lstat, within maxSweepWalk entries.
func newestChange(root *os.Root, name string) (time.Time, error) {
	var newest time.Time
	n := 0
	err := fs.WalkDir(root.FS(), name, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if n++; n > maxSweepWalk {
			return errSweepWalkBound
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if t := info.ModTime(); t.After(newest) {
			newest = t
		}
		return nil
	})
	return newest, err
}
