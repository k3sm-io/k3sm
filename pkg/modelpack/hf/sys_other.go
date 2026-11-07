//go:build !darwin && !linux

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
	"io/fs"
)

// statfsFree cannot measure free space here, so the import refuses rather
// than guess.
func statfsFree(string) (uint64, error) {
	return 0, errors.New("free space is not measurable on this platform")
}

// fileOwner cannot read an owner here, so no leftover is swept.
func fileOwner(fs.FileInfo) (int, bool) { return 0, false }
