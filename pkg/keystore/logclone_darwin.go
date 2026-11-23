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

import "golang.org/x/sys/unix"

// cloneOwnerless is clonefile's CLONE_NOOWNERCOPY: the clone is the
// caller's, not the source's owner's.
const cloneOwnerless = 0x0002

// cloneFileAt clones the file open at src as name in the directory dir
// (fclonefileat, never following a symlink at name, the clone the
// caller's). Measured as root on 2026-11-23 (U195): cloning a service
// user's SF_APPEND file is allowed, and the clone keeps the flag, mode
// 0600 and the whole file; its owner is the caller's with
// CLONE_NOOWNERCOPY. The flag blocks a read-write open and fchown until
// fchflags clears it, which a read-only descriptor may do.
// It is a variable so a test can refuse it and drive the copy.
var cloneFileAt = func(src, dir int, name string) error {
	return unix.Fclonefileat(src, dir, name, unix.CLONE_NOFOLLOW|cloneOwnerless)
}
