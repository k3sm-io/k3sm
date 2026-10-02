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

package executor

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"sigs.k8s.io/yaml"
)

// Secrets encryption at rest is opt-in, auto-keyed and decided once: at the
// install that creates the cluster. The whole state is two files in the
// control plane's credential directory, written together by the installer
// before the first start and never by anything else:
//
//   - the apiserver EncryptionConfiguration, which carries the key, and
//   - a fingerprint file holding the hex SHA-256 of that key.
//
// The pair is the marker. A start that finds neither runs with encryption off;
// a start that finds both, agreeing, passes --encryption-provider-config; every
// other combination is refused, because each one means a datastore whose
// Secrets were (or were not) written under a key this start cannot vouch for.
// Nothing outside the work dir (no argument record, no flag on the daemon's
// argv) decides enablement.
//
// The provider is secretbox (XSalsa20-Poly1305 with a 32-byte key and a random
// 192-bit nonce per write). k3s offers it beside its default, aescbc. aescbc is
// marked not recommended upstream (it is open to padding-oracle attacks), and
// aesgcm with a random nonce is bounded to a write count that only a key
// rotation can reset, which this release does not ship. secretbox has neither
// limit.

const (
	// EncryptionProviderName is the one provider k3sm configures.
	EncryptionProviderName = "secretbox"
	// encryptionKeyName is the name of the single key in the provider's list.
	encryptionKeyName = "key1"
	// EncryptionKeySize is the secretbox key length in bytes.
	EncryptionKeySize = 32
	// credSubdir is the control plane's credential directory under the work dir.
	credSubdir = "cred"
	// encryptionConfigName and encryptionFingerprintName are the two files of
	// the pair, both in the credential directory.
	encryptionConfigName      = "encryption-config.yaml"
	encryptionFingerprintName = "encryption-config.sha256"
	// encryptionConfigKind and encryptionConfigAPIVersion are the apiserver's
	// EncryptionConfiguration type.
	encryptionConfigKind       = "EncryptionConfiguration"
	encryptionConfigAPIVersion = "apiserver.config.k8s.io/v1"
)

// CredDir returns the control plane's credential directory for a work dir.
func CredDir(workDir string) string { return filepath.Join(workDir, credSubdir) }

// EncryptionConfigPath returns where the EncryptionConfiguration lives.
func EncryptionConfigPath(workDir string) string {
	return filepath.Join(CredDir(workDir), encryptionConfigName)
}

// EncryptionFingerprintPath returns where the key's fingerprint lives.
func EncryptionFingerprintPath(workDir string) string {
	return filepath.Join(CredDir(workDir), encryptionFingerprintName)
}

// The refusals. Each names the next step, because the operator who meets one
// has a control plane that is not coming up and needs to know what to do.
var (
	// ErrEncryptionAgent refuses the option on a worker install.
	ErrEncryptionAgent = errors.New("secrets encryption is a control-plane option: a worker holds no datastore; install without --secrets-encryption")
	// ErrEncryptionHA refuses the option alongside a server join or an external
	// datastore. Every server of such a cluster would need the same key, and
	// this release does not distribute one.
	ErrEncryptionHA = errors.New("secrets encryption is not supported with a server join or an external datastore in this release: every server would need the same key, and k3sm does not distribute one; install without --secrets-encryption, or without the join/datastore endpoint")
	// ErrEncryptionExistingDatastore refuses enabling over a datastore that
	// already exists. Its Secrets are stored unencrypted, and moving them under
	// a key is a migration this release does not perform.
	ErrEncryptionExistingDatastore = errors.New("secrets encryption can only be enabled at a fresh install: this data root already holds a datastore, and migrating an existing datastore is not supported in this release")
	// ErrEncryptionConfigWithoutFingerprint refuses a start that finds the
	// configuration but not its fingerprint: the configuration was placed by
	// hand (only the installer writes the pair), which is the unsupported
	// existing-datastore migration.
	ErrEncryptionConfigWithoutFingerprint = errors.New("the secrets encryption configuration is present without its fingerprint: only `k3sm install --secrets-encryption` on a fresh data root enables encryption, and migrating an existing datastore is not supported in this release; remove the configuration file, or restore the fingerprint file from the backup taken with state.db")
	// ErrEncryptionKeyMissing refuses a start that finds the fingerprint but
	// not the configuration: the datastore's Secrets were written under a key
	// that is gone.
	ErrEncryptionKeyMissing = errors.New("secrets encryption was enabled on this data root but the key file is missing: every Secret in the datastore is unreadable without it; restore the key file from the backup taken with state.db")
	// ErrEncryptionFingerprintMismatch refuses a start whose configuration
	// holds a different key from the one the fingerprint records.
	ErrEncryptionFingerprintMismatch = errors.New("the secrets encryption key does not match the fingerprint recorded when encryption was enabled: the datastore's Secrets were written under another key; restore the key file from the backup taken with state.db")
	// ErrEncryptionConfigInvalid refuses a configuration that is not the shape
	// k3sm writes (one resource, one secretbox provider, one 32-byte key).
	ErrEncryptionConfigInvalid = errors.New("the secrets encryption configuration is not the one k3sm writes; restore the key file from the backup taken with state.db")
)

// encryptionConfig is the subset of the apiserver's EncryptionConfiguration
// that k3sm writes and reads back.
type encryptionConfig struct {
	Kind       string                       `json:"kind"`
	APIVersion string                       `json:"apiVersion"`
	Resources  []encryptionResourceSettings `json:"resources"`
}

type encryptionResourceSettings struct {
	Resources []string             `json:"resources"`
	Providers []encryptionProvider `json:"providers"`
}

// encryptionProvider holds exactly one provider. Identity and the other
// providers are listed so a configuration naming one is recognised, and then
// refused, rather than silently decoded as empty.
type encryptionProvider struct {
	Secretbox *encryptionKeys `json:"secretbox,omitempty"`
	Identity  *struct{}       `json:"identity,omitempty"`
	AESCBC    *encryptionKeys `json:"aescbc,omitempty"`
	AESGCM    *encryptionKeys `json:"aesgcm,omitempty"`
	KMS       *struct{}       `json:"kms,omitempty"`
}

type encryptionKeys struct {
	Keys []encryptionKey `json:"keys"`
}

type encryptionKey struct {
	Name   string `json:"name"`
	Secret string `json:"secret"`
}

// MintEncryptionKey reads a fresh key from r. Production passes
// crypto/rand.Reader; a short read is an error, never a short key.
func MintEncryptionKey(r io.Reader) ([]byte, error) {
	key := make([]byte, EncryptionKeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("read %d bytes of key material: %w", EncryptionKeySize, err)
	}
	return key, nil
}

// RenderEncryptionConfig returns the EncryptionConfiguration for key: the
// secrets resource under a single secretbox provider and NO identity provider,
// so the apiserver neither writes nor reads a plaintext Secret.
func RenderEncryptionConfig(key []byte) ([]byte, error) {
	if len(key) != EncryptionKeySize {
		return nil, fmt.Errorf("secretbox key is %d bytes, want %d", len(key), EncryptionKeySize)
	}
	cfg := encryptionConfig{
		Kind:       encryptionConfigKind,
		APIVersion: encryptionConfigAPIVersion,
		Resources: []encryptionResourceSettings{{
			Resources: []string{"secrets"},
			Providers: []encryptionProvider{{
				Secretbox: &encryptionKeys{Keys: []encryptionKey{{
					Name:   encryptionKeyName,
					Secret: base64.StdEncoding.EncodeToString(key),
				}}},
			}},
		}},
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("render the encryption configuration: %w", err)
	}
	return out, nil
}

// EncryptionConfigKey parses a configuration and returns its key, refusing
// (ErrEncryptionConfigInvalid) anything but the shape RenderEncryptionConfig
// writes.
func EncryptionConfigKey(config []byte) ([]byte, error) {
	var cfg encryptionConfig
	// The parse error is deliberately not wrapped: its text can quote the
	// offending line, and that line may be the key.
	if err := yaml.UnmarshalStrict(config, &cfg); err != nil {
		return nil, fmt.Errorf("%w: it does not parse", ErrEncryptionConfigInvalid)
	}
	if cfg.Kind != encryptionConfigKind || cfg.APIVersion != encryptionConfigAPIVersion {
		return nil, fmt.Errorf("%w: kind %q apiVersion %q", ErrEncryptionConfigInvalid, cfg.Kind, cfg.APIVersion)
	}
	if len(cfg.Resources) != 1 || len(cfg.Resources[0].Resources) != 1 || cfg.Resources[0].Resources[0] != "secrets" {
		return nil, fmt.Errorf("%w: want exactly the secrets resource", ErrEncryptionConfigInvalid)
	}
	providers := cfg.Resources[0].Providers
	if len(providers) != 1 {
		return nil, fmt.Errorf("%w: want exactly one provider, found %d", ErrEncryptionConfigInvalid, len(providers))
	}
	p := providers[0]
	if p.Secretbox == nil || p.Identity != nil || p.AESCBC != nil || p.AESGCM != nil || p.KMS != nil {
		return nil, fmt.Errorf("%w: want exactly one %s provider", ErrEncryptionConfigInvalid, EncryptionProviderName)
	}
	if len(p.Secretbox.Keys) != 1 {
		return nil, fmt.Errorf("%w: want exactly one key, found %d", ErrEncryptionConfigInvalid, len(p.Secretbox.Keys))
	}
	key, err := base64.StdEncoding.DecodeString(p.Secretbox.Keys[0].Secret)
	if err != nil || len(key) != EncryptionKeySize {
		return nil, fmt.Errorf("%w: the key does not decode to %d bytes", ErrEncryptionConfigInvalid, EncryptionKeySize)
	}
	return key, nil
}

// EncryptionKeyFingerprint is the hex SHA-256 of key, the content of the
// fingerprint file (plus a trailing newline).
func EncryptionKeyFingerprint(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])
}

// EncryptionStartInputs are the facts the start-time verdict is made from.
type EncryptionStartInputs struct {
	ConfigPresent      bool
	FingerprintPresent bool
	// FingerprintMatches is meaningful only when both files are present.
	FingerprintMatches bool
	// HA is a server join or an external datastore endpoint.
	HA bool
}

// DecideEncryptionAtStart is the start-time verdict: whether this start passes
// --encryption-provider-config, or the refusal that stops it.
func DecideEncryptionAtStart(in EncryptionStartInputs) (enabled bool, err error) {
	switch {
	case !in.ConfigPresent && !in.FingerprintPresent:
		return false, nil
	case in.ConfigPresent && !in.FingerprintPresent:
		return false, ErrEncryptionConfigWithoutFingerprint
	case !in.ConfigPresent:
		return false, ErrEncryptionKeyMissing
	case !in.FingerprintMatches:
		return false, ErrEncryptionFingerprintMismatch
	case in.HA:
		return false, ErrEncryptionHA
	}
	return true, nil
}

// EncryptionInstallInputs are the facts the install-time verdict is made from.
type EncryptionInstallInputs struct {
	// Requested is --secrets-encryption on this install.
	Requested bool
	// Agent is a worker install.
	Agent bool
	// HA is a carried server join or datastore endpoint.
	HA bool
	// DatastoreResidue is any state.db* entry (the database, its WAL and
	// shared-memory files, the kine pin stamp, a backup) in the db directory,
	// or a leftover external-datastore .pgpass in the work dir.
	DatastoreResidue bool
	// Existing is the pair already on disk, as the start verdict reads it.
	Existing EncryptionStartInputs
}

// EncryptionInstallAction is what an install does with the pair.
type EncryptionInstallAction int

const (
	// EncryptionLeave touches nothing: the option was not requested.
	EncryptionLeave EncryptionInstallAction = iota
	// EncryptionKeep keeps the existing pair, never re-minting it.
	EncryptionKeep
	// EncryptionMint writes a fresh pair.
	EncryptionMint
)

// DecideEncryptionAtInstall is the install-time verdict. Every refusal is
// decided from reads alone, so a caller that acts on it only after it returns
// has written nothing when it refuses.
func DecideEncryptionAtInstall(in EncryptionInstallInputs) (EncryptionInstallAction, error) {
	if !in.Requested {
		return EncryptionLeave, nil
	}
	if in.Agent {
		return EncryptionLeave, ErrEncryptionAgent
	}
	if in.HA {
		return EncryptionLeave, ErrEncryptionHA
	}
	if in.DatastoreResidue {
		if in.Existing.ConfigPresent || in.Existing.FingerprintPresent {
			return EncryptionLeave, fmt.Errorf("%w (secrets encryption is already set up on this data root; reinstall without --secrets-encryption to keep it as it is)", ErrEncryptionExistingDatastore)
		}
		return EncryptionLeave, ErrEncryptionExistingDatastore
	}
	existing := in.Existing
	existing.HA = false
	if existing.ConfigPresent || existing.FingerprintPresent {
		if _, err := DecideEncryptionAtStart(existing); err != nil {
			return EncryptionLeave, err
		}
		return EncryptionKeep, nil
	}
	return EncryptionMint, nil
}

// IsDatastoreResidue reports whether a db-directory entry name is part of, or
// derived from, a single-node datastore.
func IsDatastoreResidue(name string) bool {
	return strings.HasPrefix(name, "state.db")
}

// EncryptionStore is the file access the encryption pair needs. ReadFile and
// ReadDir report an absent path with an error matching fs.ErrNotExist.
type EncryptionStore interface {
	ReadFile(path string) ([]byte, error)
	ReadDir(path string) ([]string, error)
	WriteFile(path string, contents []byte) error
}

// ReadEncryptionStartInputs reads the pair under workDir. A configuration that
// cannot be parsed is ErrEncryptionConfigInvalid; any read error other than
// absence is returned as is.
func ReadEncryptionStartInputs(store EncryptionStore, workDir string, ha bool) (EncryptionStartInputs, error) {
	in := EncryptionStartInputs{HA: ha}
	config, err := store.ReadFile(EncryptionConfigPath(workDir))
	switch {
	case err == nil:
		in.ConfigPresent = true
	case !errors.Is(err, fs.ErrNotExist):
		return in, fmt.Errorf("read the secrets encryption configuration: %w", err)
	}
	fingerprint, err := store.ReadFile(EncryptionFingerprintPath(workDir))
	switch {
	case err == nil:
		in.FingerprintPresent = true
	case !errors.Is(err, fs.ErrNotExist):
		return in, fmt.Errorf("read the secrets encryption fingerprint: %w", err)
	}
	if in.ConfigPresent && in.FingerprintPresent {
		key, err := EncryptionConfigKey(config)
		if err != nil {
			return in, err
		}
		in.FingerprintMatches = strings.TrimSpace(string(fingerprint)) == EncryptionKeyFingerprint(key)
	}
	return in, nil
}

// EncryptionAtStart reads the pair and returns the configuration path to pass
// the apiserver ("" when encryption is off), or the refusal.
func EncryptionAtStart(store EncryptionStore, workDir string, ha bool) (string, error) {
	in, err := ReadEncryptionStartInputs(store, workDir, ha)
	if err != nil {
		return "", err
	}
	enabled, err := DecideEncryptionAtStart(in)
	if err != nil || !enabled {
		return "", err
	}
	return EncryptionConfigPath(workDir), nil
}

// EncryptionInstallRequest is what an install asks of the pair.
type EncryptionInstallRequest struct {
	Requested bool
	Agent     bool
	HA        bool
}

// PlanEncryptionAtInstall reads what the install-time verdict needs and decides
// it. It writes nothing. A request without the option reads nothing either.
func PlanEncryptionAtInstall(store EncryptionStore, workDir string, req EncryptionInstallRequest) (EncryptionInstallAction, error) {
	in := EncryptionInstallInputs{Requested: req.Requested, Agent: req.Agent, HA: req.HA}
	if !req.Requested || req.Agent || req.HA {
		return DecideEncryptionAtInstall(in)
	}
	names, err := store.ReadDir(dbDir(workDir))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return EncryptionLeave, fmt.Errorf("inspect the datastore directory %s: %w", dbDir(workDir), err)
	}
	for _, n := range names {
		if IsDatastoreResidue(n) {
			in.DatastoreResidue = true
			break
		}
	}
	// A leftover external-datastore credential is residue too: it is what
	// requireLocalDatastore treats as decisive for "this node had a datastore".
	switch _, err := store.ReadFile(pgPassPath(workDir)); {
	case err == nil:
		in.DatastoreResidue = true
	case !errors.Is(err, fs.ErrNotExist):
		return EncryptionLeave, fmt.Errorf("inspect %s: %w", pgPassPath(workDir), err)
	}
	existing, err := ReadEncryptionStartInputs(store, workDir, false)
	if err != nil {
		return EncryptionLeave, err
	}
	in.Existing = existing
	return DecideEncryptionAtInstall(in)
}

// ApplyEncryptionAtInstall carries out an EncryptionMint action: it mints a key
// from entropy and writes the configuration, then the fingerprint. Writing the
// fingerprint last means an interrupted install leaves at most a configuration
// without a fingerprint, which the next start refuses and the next install
// with the option refuses too, rather than a fingerprint that vouches for a
// key that was never written. Every other action writes nothing.
func ApplyEncryptionAtInstall(store EncryptionStore, workDir string, action EncryptionInstallAction, entropy io.Reader) error {
	if action != EncryptionMint {
		return nil
	}
	key, err := MintEncryptionKey(entropy)
	if err != nil {
		return err
	}
	config, err := RenderEncryptionConfig(key)
	if err != nil {
		return err
	}
	if err := store.WriteFile(EncryptionConfigPath(workDir), config); err != nil {
		return fmt.Errorf("write the secrets encryption configuration: %w", err)
	}
	if err := store.WriteFile(EncryptionFingerprintPath(workDir), []byte(EncryptionKeyFingerprint(key)+"\n")); err != nil {
		return fmt.Errorf("write the secrets encryption fingerprint: %w", err)
	}
	return nil
}

// OSEncryptionStore is the EncryptionStore over the local filesystem: files at
// 0600 in a 0700 credential directory, written temp-and-rename so a reader
// never sees a partial file. It is for a process that already runs as the
// owner of the work dir; the installer, which runs as root and must hand the
// files to the service user, uses its own store.
type OSEncryptionStore struct{}

// ReadFile reads path.
func (OSEncryptionStore) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

// ReadDir lists the entry names of path.
func (OSEncryptionStore) ReadDir(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}

// WriteFile writes contents at path, mode 0600, creating the parent at 0700.
func (OSEncryptionStore) WriteFile(path string, contents []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".k3sm-*")
	if err != nil {
		return fmt.Errorf("create a temp file in %s: %w", dir, err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }() // a no-op once the rename succeeded
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod %s: %w", name, err)
	}
	if _, err := io.Copy(tmp, bytes.NewReader(contents)); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", name, err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("rename %s to %s: %w", name, path, err)
	}
	return nil
}
