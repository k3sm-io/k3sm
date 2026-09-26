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

package install

import (
	"fmt"
	"os"
	"path/filepath"
)

// Executable returns the path of the running k3sm binary with every symlink
// resolved, so the directory it names is the one RequiredSiblings was laid out
// in.
//
// On Darwin os.Executable reports the path AS INVOKED (dyld's executable_path),
// not the link target: unlike Linux's /proc/self/exe it does not follow a
// symlink. Invoked through the /usr/local/bin/k3sm symlink that Install itself
// creates, a bare filepath.Dir(os.Executable()) therefore names /usr/local/bin,
// where none of the siblings live. Every sibling lookup must go through this
// function (or ExecutableDir) instead.
//
// If the symlinks cannot be resolved the unresolved path is returned rather than
// an error: the caller then fails exactly as it would have before, at the
// sibling it cannot find, which names the missing file.
func Executable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve own binary path: %w", err)
	}
	return resolveExecutable(exe), nil
}

// ExecutableDir returns the directory holding the running k3sm binary after
// symlink resolution: the directory to pass to RequiredSiblings, and the one
// every sibling helper (the exec shim, the DYLD shims, the VM host, the
// control-plane payload) is looked up in. See Executable for why the plain
// os.Executable directory is wrong on Darwin.
func ExecutableDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve own binary path: %w", err)
	}
	return resolveExecutableDir(exe), nil
}

// resolveExecutable follows every symlink in exe, falling back to exe unchanged
// when resolution fails (a dangling link, a path removed since exec).
func resolveExecutable(exe string) string {
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		return real
	}
	return exe
}

// resolveExecutableDir is the directory of resolveExecutable(exe).
func resolveExecutableDir(exe string) string {
	return filepath.Dir(resolveExecutable(exe))
}
