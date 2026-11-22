//go:build darwin

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

package keystore

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// maxFlagDepth bounds how deep clearUserFlags descends into an entry
// directory. Put writes no subdirectory, so anything deeper was planted, and
// RemoveAll reports what it cannot remove.
const maxFlagDepth = 8

// clearUserFlags clears the BSD user flags (UF_SETTABLE: uchg, uappnd and the
// rest) on name under root and, for a directory, on everything in it, so a
// flag the service user set on its own files does not make Delete's removal
// fail: unlink of a uchg file fails even for root, and root may clear user
// flags. Each file is opened without following a symlink and changed through
// its descriptor (Fchflags), so a symlink swapped in never redirects the
// change outside the entry. It is best effort: what it cannot open or clear
// is left for the removal to report. System flags (SF_*) are never touched.
func clearUserFlags(root *os.Root, name string) {
	clearUserFlagsAt(root, name, maxFlagDepth)
}

func clearUserFlagsAt(root *os.Root, name string, depth int) {
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close() // read-only
		return
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Flags&unix.UF_SETTABLE != 0 {
		_ = unix.Fchflags(int(f.Fd()), int(st.Flags&^unix.UF_SETTABLE))
	}
	_ = f.Close() // read-only
	if !fi.IsDir() || depth == 0 {
		return
	}
	sub, err := root.OpenRoot(name)
	if err != nil {
		return
	}
	defer func() { _ = sub.Close() }() // read-only
	// The directory opened must be the one whose flags were cleared.
	if opened, err := sub.Stat("."); err != nil || !os.SameFile(fi, opened) {
		return
	}
	names, err := readDirNames(sub, maxDirNames)
	if err != nil {
		return
	}
	for _, n := range names {
		clearUserFlagsAt(sub, n, depth-1)
	}
}
