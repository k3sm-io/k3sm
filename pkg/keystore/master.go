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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

const (
	// masterName and masterFingerprintName are the master pair, in the master
	// directory.
	masterName            = "master"
	masterFingerprintName = "master.sha256"
	// masterNextName and masterNextFingerprintName are the pair a Rewrap
	// writes beside the master and swaps over it last; present only while a
	// Rewrap is in progress or after one crashed.
	masterNextName            = "master.next"
	masterNextFingerprintName = "master.next.sha256"
	// userScopesName is the name in the entries' directory reserved for user
	// scopes. Nothing creates it yet.
	userScopesName = ".user"
	// masterSize is the master key's size.
	masterSize = 32
	// fingerprintFileSize is the fingerprint file's size: hex SHA-256 and a
	// newline.
	fingerprintFileSize = 2*sha256.Size + 1
)

// errFingerprintMissing reports a master that passed its own checks with no
// fingerprint file beside it: the state a mint interrupted between its two
// writes leaves.
var errFingerprintMissing = errors.New("the master fingerprint file is missing")

// masterFingerprint is the content of the fingerprint file for master.
func masterFingerprint(master []byte) string {
	sum := sha256.Sum256(master)
	return hex.EncodeToString(sum[:]) + "\n"
}

// openMasterDir opens the master directory inside cred/, both checked as
// openDir checks a directory, creating them with create set. The master
// directory is opened relative to cred/, never by its full path, because the
// service user owns server/ and could replace cred/ with a symlink.
func (s *FileStore) openMasterDir(create bool) (*os.Root, error) {
	cred, err := s.openDir(filepath.Dir(s.masterDir), create)
	if err != nil {
		return nil, err
	}
	defer func() { _ = cred.Close() }() // the master directory is opened; cred/ is done with
	return s.openSubdir(cred, filepath.Base(s.masterDir), create)
}

// loadMaster opens the master pair and returns the keys derived from it. A
// master directory or master file that is absent is ErrMasterMissing; one that
// fails a check is ErrMasterUntrusted. When a master.next that agrees with its
// fingerprint is present (a Rewrap crashed), its keys are the fallback a
// reader opens a record under once the master's do not authenticate it; a
// master.next that does not agree is no fallback, and the reader then reports
// such a record as ErrCorrupt.
func (s *FileStore) loadMaster() (keys, error) {
	root, err := s.openMasterDir(false)
	if errors.Is(err, fs.ErrNotExist) {
		return keys{}, ErrMasterMissing
	}
	if err != nil {
		return keys{}, fmt.Errorf("%w: %w", ErrMasterUntrusted, err)
	}
	defer func() { _ = root.Close() }() // read-only; nothing to flush
	master, err := s.readMaster(root)
	if err != nil {
		return keys{}, err
	}
	k, err := deriveKeys(master, s.scope)
	clear(master) // only the derived keys are kept
	if err != nil {
		return keys{}, err
	}
	if next, nerr := s.readNext(root); nerr == nil {
		nk, derr := deriveKeys(next, s.scope)
		clear(next)
		if derr == nil {
			k.next = &nk
		}
	}
	return k, nil
}

// loadMasterLocked is loadMaster for a verb that holds the exclusive lock:
// it first completes a master swap a crashed Rewrap left half done (see
// finishSwap). A missing or untrusted master directory is loadMaster's to
// report.
func (s *FileStore) loadMasterLocked() (keys, error) {
	if root, err := s.openMasterDir(false); err == nil {
		_, ferr := s.finishSwap(root)
		_ = root.Close() // the rename is fsynced by finishSwap
		if ferr != nil {
			return keys{}, fmt.Errorf("complete an interrupted master swap: %w", ferr)
		}
	}
	return s.loadMaster()
}

// readMaster reads the master file and checks it, on the descriptor the bytes
// came from: a regular file reached without following a symlink, owned by the
// store's uid, mode 0600, 32 bytes, and matching the fingerprint file. The
// fingerprint detects a wrong file, not tampering: whoever can replace the
// master can replace its fingerprint too.
//
// A master that matches master.next.sha256 instead is trusted too: a Rewrap
// that crashed between its two master renames leaves the new key in master,
// the old fingerprint in master.sha256 and the new one in master.next.sha256
// (docs/design/keystore.md § "Master file trust").
//
// On a refusal the bytes read are cleared before it returns; on success the
// caller clears them once it has derived the keys.
func (s *FileStore) readMaster(root *os.Root) ([]byte, error) {
	raw, err := s.readKeyFile(root, masterName)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrMasterMissing
	}
	if err != nil {
		return nil, err
	}
	if err := matchFingerprint(root, masterFingerprintName, raw); err != nil {
		if matchFingerprint(root, masterNextFingerprintName, raw) == nil {
			return raw, nil
		}
		clear(raw)
		return nil, err
	}
	return raw, nil
}

// readNext reads master.next with readMaster's checks against
// master.next.sha256 alone. An absent master.next is an error matching
// fs.ErrNotExist; any other refusal is ErrMasterUntrusted.
func (s *FileStore) readNext(root *os.Root) ([]byte, error) {
	raw, err := s.readKeyFile(root, masterNextName)
	if err != nil {
		return nil, err
	}
	if err := matchFingerprint(root, masterNextFingerprintName, raw); err != nil {
		clear(raw)
		return nil, fmt.Errorf("%s: %w", masterNextName, err)
	}
	return raw, nil
}

// readKeyFile reads the key file name and checks it on the descriptor the
// bytes came from: a regular file reached without following a symlink, owned
// by the store's uid, mode 0600, 32 bytes. An absent file is an error
// matching fs.ErrNotExist; any other refusal is ErrMasterUntrusted, with the
// bytes read cleared.
func (s *FileStore) readKeyFile(root *os.Root, name string) (_ []byte, err error) {
	// The deferred clear reads raw, not the result, which a refusal's return
	// sets to nil before deferred calls run.
	raw, fi, err := readFile(root, name, masterSize)
	defer func() {
		if err != nil {
			clear(raw)
		}
	}()
	if errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMasterUntrusted, err)
	}
	if err := s.checkOwned(fi, fileMode); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrMasterUntrusted, name, err)
	}
	if fi.Mode().Perm() != fileMode {
		return nil, fmt.Errorf("%w: %s: mode %04o, want %04o", ErrMasterUntrusted, name, fi.Mode().Perm(), fileMode)
	}
	if len(raw) != masterSize {
		return nil, fmt.Errorf("%w: %s: %d bytes, want %d", ErrMasterUntrusted, name, len(raw), masterSize)
	}
	return raw, nil
}

// matchFingerprint refuses, as ErrMasterUntrusted, key unless the fingerprint
// file fpName records it. A missing file also matches errFingerprintMissing.
func matchFingerprint(root *os.Root, fpName string, key []byte) error {
	recorded, _, err := readFile(root, fpName, fingerprintFileSize)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %w", ErrMasterUntrusted, errFingerprintMissing)
	}
	if err != nil {
		return fmt.Errorf("%w: the fingerprint file: %w", ErrMasterUntrusted, err)
	}
	if string(recorded) != masterFingerprint(key) {
		return fmt.Errorf("%w: it does not match %s", ErrMasterUntrusted, fpName)
	}
	return nil
}

// finishSwap completes the master swap a Rewrap that crashed between its two
// renames leaves: with no master.next, a master.next.sha256 that the master
// matches is renamed over master.sha256, and the directory fsynced. It reports
// whether it did. Any other state is left as it is: a master that does not
// read is loadMaster's to report, and a master.next.sha256 the master does not
// match is Rewrap's to judge. The caller holds the exclusive lock; a reader
// only trusts such a master (readMaster) and writes nothing.
func (s *FileStore) finishSwap(root *os.Root) (bool, error) {
	if _, err := root.Lstat(masterNextName); !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	if _, err := root.Lstat(masterNextFingerprintName); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	raw, err := s.readKeyFile(root, masterName)
	if err != nil {
		return false, nil
	}
	defer clear(raw)
	if matchFingerprint(root, masterNextFingerprintName, raw) != nil {
		return false, nil
	}
	if err := root.Rename(masterNextFingerprintName, masterFingerprintName); err != nil {
		return false, err
	}
	if err := syncDir(root); err != nil {
		return false, err
	}
	return true, s.step("rename " + masterNextFingerprintName)
}

// masterForPut returns the keys a Put seals under, minting the master if this
// is the keystore's first entry. entries is the open entries' directory, and
// the caller holds the exclusive lock, so two first Puts cannot mint two
// masters.
//
// A master is minted only while the entries' directory holds no name an entry
// could have, complete or not, and no userScopesName: with entries and no master, every entry would
// be unreadable under a new one, so that is ErrMasterMissing, never a repair.
// Without entries, two states are minted over, because an interrupted first
// Put leaves them and nothing was sealed under them: no master file, and a
// master that passed every check but has no fingerprint file. A master that
// fails any check of its own is refused, entries or not.
func (s *FileStore) masterForPut(entries *os.Root) (keys, error) {
	k, err := s.loadMasterLocked()
	if err == nil {
		return k, nil
	}
	if !errors.Is(err, ErrMasterMissing) && !errors.Is(err, errFingerprintMissing) {
		return keys{}, err
	}
	names, rerr := readDirNames(entries, maxDirNames)
	if rerr != nil {
		return keys{}, rerr
	}
	// The name reserved for user scopes counts whatever its type: records
	// under it would be unreadable under a new master as well.
	for _, n := range names {
		if n == userScopesName || checkName(n) == nil {
			return keys{}, err
		}
	}
	return s.mintMaster()
}

// mintMaster mints a master from the store's entropy source and writes the
// pair: the stale fingerprint removed first, then the master, then its
// fingerprint, so an interruption leaves no fingerprint, never one that
// vouches for a key that was not written.
func (s *FileStore) mintMaster() (keys, error) {
	// A scope the keys could not be derived under is refused before anything
	// is created for it.
	if err := checkScope(s.scope); err != nil {
		return keys{}, err
	}
	root, err := s.openMasterDir(true)
	if err != nil {
		return keys{}, fmt.Errorf("%w: %w", ErrMasterUntrusted, err)
	}
	defer func() { _ = root.Close() }() // writes are fsynced by writeFile
	master := make([]byte, masterSize)
	defer clear(master) // only the derived keys outlive the mint
	if err := s.readRandom(master); err != nil {
		return keys{}, fmt.Errorf("mint the keystore master: %w", err)
	}
	if err := root.Remove(masterFingerprintName); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return keys{}, fmt.Errorf("remove the stale master fingerprint: %w", err)
	}
	if err := s.writeFile(root, masterName, master); err != nil {
		return keys{}, err
	}
	if err := s.writeFile(root, masterFingerprintName, []byte(masterFingerprint(master))); err != nil {
		return keys{}, err
	}
	return deriveKeys(master, s.scope)
}
