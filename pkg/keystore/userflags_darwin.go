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
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// maxFlagDepth bounds how deep clearUserFlags descends into an entry
// directory. Put writes no subdirectory, so anything deeper was planted, and
// RemoveAll reports what it cannot remove.
const maxFlagDepth = 8

const (
	// ufNoUnlink is UF_NOUNLINK (uunlnk): 0x10 in the BSD header, commented
	// out in Darwin's, so x/sys has no name for it.
	ufNoUnlink = 0x10
	// userLockingFlags are the owner's flags that keep a file from being
	// changed, appended to only, or removed: uchg, uappnd and uunlnk. No
	// other flag is ever cleared, and system flags (SF_*) never are.
	userLockingFlags = unix.UF_IMMUTABLE | unix.UF_APPEND | ufNoUnlink
)

// clearUserFlags clears the user locking flags (userLockingFlags) on
// keystore/ itself (the directory the root handle opens, which the service
// user owns), on name under it and, for a
// directory, on everything in it, so a flag the service user set on its own
// files does not make Delete's removal fail: unlink of a uchg file, or of
// any name in a uchg directory, fails even for root, and root may clear user
// flags. Delete calls it only after the removal answered EPERM, as
// pkg/install's removeTreeFlagged does. Each file is opened without
// following a symlink and changed through its descriptor (Fchflags), so a
// symlink swapped in never redirects the change outside the entry. A file is
// left alone, and returned in skipped, unless the service user (uid) owns
// it, and, for anything but a directory, unless it has one link: a hard
// link shares its flags with every other name of the file, which may be
// outside the keystore. What it cannot open is left for the removal to
// report.
func clearUserFlags(root *os.Root, name string, uid uint32) (skipped []string) {
	if why := clearFlagsAt(root, ".", uid); why != "" {
		skipped = append(skipped, "keystore/ itself "+why)
	}
	return clearUserFlagsAt(root, name, name, uid, maxFlagDepth, skipped)
}

// clearFlagsAt clears the locking flags of name in root, refusing (a reason)
// a file the service user does not own or a non-directory with another link.
func clearFlagsAt(root *os.Root, name string, uid uint32) string {
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }() // read-only
	return clearFlagsOf(f, uid)
}

// clearFlagsOf clears f's locking flags, judged on f.
func clearFlagsOf(f *os.File, uid uint32) string {
	fi, err := f.Stat()
	if err != nil {
		return ""
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Flags&userLockingFlags == 0 {
		return ""
	}
	switch {
	case st.Uid != uid:
		return fmt.Sprintf("has a locking flag (flags %#x) and is owned by uid %d, not the service user, so it is not cleared", st.Flags, st.Uid)
	case !fi.IsDir() && st.Nlink != 1:
		return fmt.Sprintf("is a hard link (%d links) with a locking flag (flags %#x) that its other names share, so it is not cleared", st.Nlink, st.Flags)
	}
	if err := unix.Fchflags(int(f.Fd()), int(st.Flags&^userLockingFlags)); err != nil {
		return fmt.Sprintf("has a locking flag (flags %#x) that could not be cleared: %v", st.Flags, err)
	}
	return ""
}

func clearUserFlagsAt(root *os.Root, name, path string, uid uint32, depth int, skipped []string) []string {
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return skipped
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close() // read-only
		return skipped
	}
	if why := clearFlagsOf(f, uid); why != "" {
		skipped = append(skipped, path+" "+why)
	}
	_ = f.Close() // read-only
	if !fi.IsDir() || depth == 0 {
		return skipped
	}
	sub, err := root.OpenRoot(name)
	if err != nil {
		return skipped
	}
	defer func() { _ = sub.Close() }() // read-only
	// The directory opened must be the one whose flags were cleared.
	if opened, err := sub.Stat("."); err != nil || !os.SameFile(fi, opened) {
		return skipped
	}
	names, err := readDirNames(sub, maxDirNames)
	if err != nil {
		return skipped
	}
	for _, n := range names {
		skipped = clearUserFlagsAt(sub, n, path+"/"+n, uid, depth-1, skipped)
	}
	return skipped
}
