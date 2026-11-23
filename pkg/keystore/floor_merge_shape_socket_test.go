//go:build integration

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
	"path/filepath"
	"syscall"
	"testing"
)

// TestChownStagedRefusesSocket is TestChownStagedRefusesShape's socket case.
// It binds a real AF_UNIX socket to plant one in the staged tree, so it runs
// in the integration tier; the untagged FIFO case covers the same refusal of
// a non-regular file.
func TestChownStagedRefusesSocket(t *testing.T) {
	s, server := newTestStore(t)
	stageRecipe(t, s, server, 0)
	plant := func(t *testing.T, s *FileStore) {
		// A socket's path is bounded: bind it in a short directory and
		// rename it into place.
		dir, err := os.MkdirTemp("", "ks")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.RemoveAll(dir) }()
		fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = syscall.Close(fd) }()
		if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: filepath.Join(dir, "s")}); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(filepath.Join(dir, "s"), stagePath(s, stagedTreeName, "k", "v9")); err != nil {
			t.Fatal(err)
		}
	}
	plant(t, s)
	wantShapeRefused(t, s, "k/v9")
}
