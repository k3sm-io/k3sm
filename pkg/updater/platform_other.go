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

package updater

import (
	"errors"
	"os"
	"syscall"
)

// deniedFlags is empty where there are no BSD flags to read.
const deniedFlags = 0

// fullFsync refuses: F_FULLFSYNC exists only on macOS, the one platform the
// updater activates on.
func fullFsync(*os.File) error { return errors.ErrUnsupported }

func statFlags(*syscall.Stat_t) uint32 { return 0 }

func fdHasACL(uintptr) (bool, error) { return false, errors.ErrUnsupported }

func sysctlBootID() (string, error) { return "", errors.ErrUnsupported }
