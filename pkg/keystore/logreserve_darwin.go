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

	"golang.org/x/sys/unix"
)

// reserveLogBlocks reserves n bytes of blocks past f's physical end with
// fcntl(F_PREALLOCATE), all or nothing (F_ALLOCATEALL), so the write that
// follows on the same descriptor cannot run out of space part way.
func reserveLogBlocks(f *os.File, n int64) error {
	fst := unix.Fstore_t{
		Flags:   unix.F_ALLOCATEALL,
		Posmode: unix.F_PEOFPOSMODE,
		Length:  n,
	}
	return unix.FcntlFstore(f.Fd(), unix.F_PREALLOCATE, &fst)
}
