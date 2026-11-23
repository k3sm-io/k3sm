//go:build !darwin

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
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// fileFlags is the chflags flag source. Off darwin no file carries
// SF_APPEND, so every log is refused as not append-only.
func fileFlags(*os.File) (uint32, error) {
	return 0, errors.New("file flags are read on darwin only")
}

// fdFlags is the st_flags source for a directory. Off darwin there are no
// file flags.
func fdFlags(int) (uint32, error) { return 0, nil }

// fdHasACL reports an extended ACL. Off darwin it is not read, and every log
// is refused all the same (fileFlags).
func fdHasACL(int) (bool, error) { return false, nil }

// statFlags is st's st_flags. Off darwin there are no file flags.
func statFlags(*unix.Stat_t) uint32 { return 0 }

// clearFdFlags is never called off darwin: no file carries a flag
// (statFlags is 0).
func clearFdFlags(int) error { return nil }
