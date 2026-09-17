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

package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
)

// The join token as a FILE, and why `k3sm agent` grew a second way to be given
// one.
//
// A token on an argv is public. `ps` shows it to every account on the Mac, and
// a supervised agent's argv lives in a root-owned 0644 LaunchDaemon plist that
// anyone can read — so the installed daemon can be told WHERE its token is, but
// must never be told what it is. An environment variable is better and still
// not good: it is inherited by every child the agent spawns.
//
// A file is the shape that fits how a join token is actually used. It is
// TTL-bounded and needed exactly once — a node that has joined starts from its
// stored credential — so the operator writes it, installs, and deletes it once
// the node is Ready. The mode check below is what makes the file worth
// preferring; without it, "the token is in a file" would only mean the
// credential sat readable on disk instead of readable in `ps`.

// tokenFileMask is the permission bits a join-token file may not carry: any
// group or other access at all. It is the mode ssh(1) enforces on a private
// key, for the same reason — the file IS the credential for as long as it
// exists, so a group-readable copy is a credential shared with a group.
const tokenFileMask fs.FileMode = 0o077

// applyTokenFile resolves --token-file into the token the agent will present,
// and reports whether the named file was ABSENT.
//
// The precedence is --token-file > --token > $K3SM_TOKEN, and it is total while
// the file exists: a named file wins over both, including over a token merely
// inherited from the environment of whatever supervises the process. That
// ordering is the point of the flag — an operator who put the token in a file
// has said where the credential is, and a stale K3SM_TOKEN in a launchd session
// or a shell profile must not quietly outrank it.
//
// A MISSING file is not an error, and that is the whole difference between this
// agent surviving its own documentation and not. The token is needed for the
// FIRST join only, the file is read at EVERY start, and an operator is told to
// delete it once the node is Ready — so the ordinary steady state of a joined
// worker is a --token-file pointing at nothing. Treating that as terminal would
// turn the recommended cleanup into a daemon that never starts again. The
// absence contributes no token (and leaves any --token/$K3SM_TOKEN alone: there
// is nothing to outrank it with), the caller says so once at Info, and the
// start plan decides from the stored credential exactly as it does when no
// token was mentioned at all.
//
// A file that IS there and cannot be used — unreadable, empty, or readable by
// its group or by other accounts — stays terminal. It names a credential the
// operator believes is in play, and starting past it would silently ignore what
// they configured.
func applyTokenFile(opts *agentOptions) (absent bool, err error) {
	return resolveTokenFile(opts.tokenFile, &opts.token)
}

// resolveTokenFile is applyTokenFile's body, taking the path and the token to
// fill rather than the agent's options struct, because BOTH node roles are given
// their credential this way and there must be exactly one reader of it.
//
// `k3sm server` reads its static admin token through this too (server.go). Its
// file is not the operator's but the installer's: a 0600 copy staged in the
// server work dir, named on the daemon's argv as a path so the system:masters
// bearer token is not published by the plist, by `ps`, or by launchd. Every
// sentence of applyTokenFile's contract above holds unchanged for it — the
// precedence, the non-terminal absence, and the terminal refusal of a file that
// is there and cannot be used.
//
// The message vocabulary stays the agent's ("join token file"), because it is
// the same class of file holding the same class of credential and a second
// phrasing would mean a second reader.
func resolveTokenFile(path string, token *string) (absent bool, err error) {
	if path == "" {
		return false, nil
	}
	value, err := readJoinTokenFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return true, nil
	case err != nil:
		return false, err
	}
	*token = value
	return false, nil
}

// missingTokenFileNote adds the absent token file to a terminal start error.
//
// The two facts belong in one sentence. "No stored node credential and no join
// token" is true but incomplete on a machine whose daemon was installed with a
// --token-file: the operator can see the flag on the argv and has no reason to
// suspect the file behind it is what is missing, so the error names the path
// and what to do about it.
func missingTokenFileNote(err error, path string) error {
	if path == "" {
		return err
	}
	return fmt.Errorf("%w — and the join token file %s is not there: write the token `k3sm token create` printed on the server into it (mode 0600, owned by this daemon's user), or re-run `sudo k3sm install --agent --token-file <your file>` on this Mac", err, path)
}

// readJoinTokenFile reads and trims the join token at path, refusing a file any
// account but its owner can read. A path that does not exist returns an error
// satisfying errors.Is(err, fs.ErrNotExist), which applyTokenFile reads as a
// POSTURE (no token) rather than as a failure.
//
// The mode is read from the OPEN FILE rather than from the path, so the bytes
// that are returned are the bytes that were judged: a stat-then-open would
// decide about one file and read another if the path were replaced in between.
//
// An empty file is an error rather than an empty token. A daemon handed one
// would report "no credential and no token" on a machine where the operator can
// see a token file sitting right there, which is the least useful place for
// this to surface.
func readJoinTokenFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		// Wrapped with %w so the not-exist arm survives for applyTokenFile.
		return "", fmt.Errorf("read the join token file: %w", err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("inspect the join token file %s: %w", path, err)
	}
	if perm := info.Mode().Perm(); perm&tokenFileMask != 0 {
		return "", fmt.Errorf("the join token file %s is mode %#o: a join token is a credential, so the file must not be readable by its group or by other accounts — `chmod 600 %s`", path, perm, path)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("read the join token file %s: %w", path, err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("the join token file %s is empty: write the token `k3sm token create` printed on the server into it, or drop --token-file on a node that has already joined", path)
	}
	return token, nil
}
