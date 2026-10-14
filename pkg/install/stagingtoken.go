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
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"strings"
)

// stagedTokenMode is the only mode a --from-staging token file may carry.
const stagedTokenMode fs.FileMode = 0o600

// ErrStagedTokenUntrusted reports a --token-file that fails the strict rules
// a --from-staging install applies to it.
var ErrStagedTokenUntrusted = errors.New("the --token-file is not a trusted staged token file")

// redacted is what a secretToken prints and logs as.
const redacted = "[redacted]"

// secretToken holds a join token read from a staged token file. Every way of
// printing or logging it yields a fixed redaction, so neither a %v or %+v of a
// Config nor a slog attribute can carry the token. Config holds it by pointer,
// so a dump of the Config shows only an address.
type secretToken struct{ value string }

// String redacts.
func (secretToken) String() string { return redacted }

// GoString redacts.
func (secretToken) GoString() string { return redacted }

// Format redacts under every verb.
func (secretToken) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// LogValue redacts.
func (secretToken) LogValue() slog.Value { return slog.StringValue(redacted) }

// readStagedToken applies the strict --from-staging rules to the token file:
// a direct child of dir, opened without following a symlink, a regular file
// owned by root with mode exactly 0600 and one link. It is read once and
// unlinked straight after the read, whatever the read found, so no refusal
// below and no later failure can leave it behind. Neither the bytes nor any
// part of them appear in an error.
func readStagedToken(sfs StagingFS, dir, path string) (*secretToken, error) {
	refuse := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrStagedTokenUntrusted, fmt.Sprintf(format, a...))
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) != dir {
		return nil, refuse("%s is not a file directly inside %s", path, dir)
	}
	raw, e, readErr := sfs.ReadTokenFile(path)
	if err := sfs.RemoveFile(path); err != nil {
		return nil, refuse("remove %s after reading it: %v", path, err)
	}
	switch {
	case errors.Is(readErr, ErrNotRegularFile):
		return nil, refuse("%s is not a regular file", path)
	case readErr != nil:
		return nil, fmt.Errorf("%w: read %s: %w", ErrStagedTokenUntrusted, path, readErr)
	case e.UID != 0:
		return nil, refuse("%s is owned by uid %d, not root", path, e.UID)
	case e.Mode.Perm() != stagedTokenMode || e.Mode&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0:
		return nil, refuse("%s is mode %04o, not %04o", path, e.Mode.Perm(), stagedTokenMode)
	case e.Nlink != 1:
		return nil, refuse("%s has %d links, not 1", path, e.Nlink)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return nil, refuse("%s is empty", path)
	}
	return &secretToken{value: token}, nil
}

// DiscardStagedToken is the best-effort unlink of a staged token file on a
// refusal that comes before the token is read: a bad flag, the root check, the
// staged directory failing its own checks. It never reads the file. It unlinks
// path only when path is a clean absolute path inside a direct child of root,
// no component down to that child is a symlink or a non-directory, and path
// itself lstats as a regular file. Any doubt, or any failure, leaves the file
// where it is (the copy-out removes its whole staging directory on exit).
func DiscardStagedToken(sfs StagingFS, root, path string) {
	root = filepath.Clean(root)
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return
	}
	dir := filepath.Dir(path)
	if filepath.Dir(dir) != root || dir == root {
		return
	}
	if _, err := lstatComponents(sfs, dir); err != nil {
		return
	}
	e, err := sfs.Lstat(path)
	if err != nil || !e.Mode.IsRegular() {
		return
	}
	_ = sfs.RemoveFile(path) // best effort: the copy-out's own cleanup is the backstop
}
