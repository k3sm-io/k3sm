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
// fails a check is ErrMasterUntrusted.
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
	return deriveKeys(master), nil
}

// readMaster reads the master file and checks it, on the descriptor the bytes
// came from: a regular file reached without following a symlink, owned by the
// store's uid, mode 0600, 32 bytes, and matching the fingerprint file. The
// fingerprint detects a wrong file, not tampering: whoever can replace the
// master can replace its fingerprint too.
func (s *FileStore) readMaster(root *os.Root) ([]byte, error) {
	master, fi, err := readFile(root, masterName, masterSize)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrMasterMissing
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMasterUntrusted, err)
	}
	if err := s.checkOwned(fi, fileMode); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMasterUntrusted, err)
	}
	if fi.Mode().Perm() != fileMode {
		return nil, fmt.Errorf("%w: mode %04o, want %04o", ErrMasterUntrusted, fi.Mode().Perm(), fileMode)
	}
	if len(master) != masterSize {
		return nil, fmt.Errorf("%w: %d bytes, want %d", ErrMasterUntrusted, len(master), masterSize)
	}
	recorded, _, err := readFile(root, masterFingerprintName, fingerprintFileSize)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %w", ErrMasterUntrusted, errFingerprintMissing)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: the fingerprint file: %w", ErrMasterUntrusted, err)
	}
	if string(recorded) != masterFingerprint(master) {
		return nil, fmt.Errorf("%w: it does not match %s", ErrMasterUntrusted, masterFingerprintName)
	}
	return master, nil
}

// masterForPut returns the keys a Put seals under, minting the master if this
// is the keystore's first entry. entries is the open entries' directory, and
// the caller holds the exclusive lock, so two first Puts cannot mint two
// masters.
//
// A master is minted only while the entries' directory holds no name an entry
// could have, complete or not: with entries and no master, every entry would
// be unreadable under a new one, so that is ErrMasterMissing, never a repair.
// Without entries, two states are minted over, because an interrupted first
// Put leaves them and nothing was sealed under them: no master file, and a
// master that passed every check but has no fingerprint file. A master that
// fails any check of its own is refused, entries or not.
func (s *FileStore) masterForPut(entries *os.Root) (keys, error) {
	k, err := s.loadMaster()
	if err == nil {
		return k, nil
	}
	if !errors.Is(err, ErrMasterMissing) && !errors.Is(err, errFingerprintMissing) {
		return keys{}, err
	}
	names, rerr := readDirNames(entries)
	if rerr != nil {
		return keys{}, rerr
	}
	for _, n := range names {
		if checkName(n) == nil {
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
	root, err := s.openMasterDir(true)
	if err != nil {
		return keys{}, fmt.Errorf("%w: %w", ErrMasterUntrusted, err)
	}
	defer func() { _ = root.Close() }() // writes are fsynced by writeFile
	master := make([]byte, masterSize)
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
	return deriveKeys(master), nil
}
