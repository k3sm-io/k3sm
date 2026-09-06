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

package dataroot

import (
	"io/fs"
	"os"

	"golang.org/x/sys/unix"
)

// OSFS is the production FS: the real filesystem. Its zero value is usable.
type OSFS struct{}

// Stat implements FS.
func (OSFS) Stat(path string) (fs.FileInfo, error) { return os.Stat(path) }

// Statfs implements FS.
func (OSFS) Statfs(path string, st *unix.Statfs_t) error { return unix.Statfs(path, st) }

// ReadFile implements FS.
func (OSFS) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

// ReadDir implements FS.
func (OSFS) ReadDir(path string) ([]fs.DirEntry, error) { return os.ReadDir(path) }
