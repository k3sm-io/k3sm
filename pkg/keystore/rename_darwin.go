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

// renameExcl renames from, in the directory fromDir, to to, in the directory
// toDir, refusing (EEXIST) when anything is at to, a symlink included:
// renameatx_np with RENAME_EXCL, one atomic step with no window between the
// check and the rename.
func renameExcl(fromDir int, from string, toDir int, to string) error {
	return unix.RenameatxNp(fromDir, from, toDir, to, unix.RENAME_EXCL)
}

// renameSwap exchanges from in fromDir with to in toDir atomically
// (renameatx_np RENAME_SWAP): both must exist.
func renameSwap(fromDir int, from string, toDir int, to string) error {
	return unix.RenameatxNp(fromDir, from, toDir, to, unix.RENAME_SWAP)
}
