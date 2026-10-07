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
	"crypto/rand"
	"fmt"
	"io/fs"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/executor"
)

const (
	// EncryptionFileMode is the mode of both files of the secrets encryption
	// pair: the configuration holds the key, so only the service user reads it.
	EncryptionFileMode fs.FileMode = 0o600
	// EncryptionCredDirMode is the mode of the credential directory holding the
	// pair.
	EncryptionCredDirMode fs.FileMode = 0o700
	// clusterInitFlag and serverJoinFlag are `k3sm server`'s two embedded-etcd
	// HA role flags, read off the carried arguments.
	clusterInitFlag = "cluster-init"
	serverJoinFlag  = "server-join"
)

// encryptionStore is the executor's EncryptionStore over the install seams:
// reads through the O_NOFOLLOW regular-file read and the read-only data-root
// filesystem, and writes handed to the service user through
// WriteServiceUserFile (temp-and-rename, owner and mode bound to the open
// descriptor).
type encryptionStore struct {
	sys  System
	fsys dataroot.FS
	uid  uint32
}

func (s encryptionStore) ReadFile(path string) ([]byte, error) { return s.sys.ReadRegularFile(path) }

func (s encryptionStore) Lstat(path string) (fs.FileMode, uint32, error) {
	e, err := s.sys.Owner(path)
	if err != nil {
		return 0, 0, err
	}
	mode := e.Mode.Perm()
	switch e.Kind {
	case EntryRegular:
	case EntryDir:
		mode |= fs.ModeDir
	case EntrySymlink:
		mode |= fs.ModeSymlink
	default:
		mode |= fs.ModeIrregular
	}
	return mode, uint32(e.UID), nil
}

func (s encryptionStore) ReadDir(path string) ([]string, error) {
	entries, err := s.fsys.ReadDir(path)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}

func (s encryptionStore) WriteFile(path string, contents []byte) error {
	return s.sys.WriteServiceUserFile(path, contents, s.uid, EncryptionFileMode, EncryptionCredDirMode)
}

// carriesEtcdPosture reports whether the carried `k3sm server` arguments select
// the embedded-etcd HA posture — --cluster-init or --server-join, in any spelling
// (single or double dash, bare or =true; an explicit =false does not count).
func carriesEtcdPosture(args []string) bool {
	return boolFlagSet(args, clusterInitFlag) || boolFlagSet(args, serverJoinFlag)
}

// preflightSecretsEncryption decides what this install does with the secrets
// encryption pair. It reads and never writes, so it runs before the first
// write of the install: a refusal leaves the Mac exactly as it was.
// serverArgs is the carried argument set preflightServerArgs returned.
func preflightSecretsEncryption(sys System, cfg Config, serverArgs []string) (executor.EncryptionInstallAction, error) {
	probe := cfg
	probe.ExtraServerArgs = serverArgs
	action, err := executor.PlanEncryptionAtInstall(
		encryptionStore{sys: sys, fsys: cfg.DataRootFS},
		cfg.serverWorkDir(),
		executor.EncryptionInstallRequest{
			Requested: cfg.SecretsEncryption,
			Agent:     cfg.Role == RoleAgent,
			HA:        cfg.Role == RoleServer && carriesEtcdPosture(probe.resolvedExtraServerArgs()),
		})
	if err != nil {
		return executor.EncryptionLeave, fmt.Errorf("install: --secrets-encryption: %w", err)
	}
	return action, nil
}

// stageSecretsEncryption carries out the preflight's action once the service
// uid is known. It logs the key file's path, never its content.
func stageSecretsEncryption(sys System, cfg Config, uid uint32, action executor.EncryptionInstallAction) error {
	wd := cfg.serverWorkDir()
	switch action {
	case executor.EncryptionKeep:
		cfg.Logger.Info("secrets encryption is already set up on this data root; keeping its key", "path", executor.EncryptionConfigPath(wd))
		return nil
	case executor.EncryptionMint:
	default:
		return nil
	}
	entropy := cfg.KeyEntropy
	if entropy == nil {
		entropy = rand.Reader
	}
	if err := executor.ApplyEncryptionAtInstall(encryptionStore{sys: sys, fsys: cfg.DataRootFS, uid: uid}, wd, action, entropy); err != nil {
		return fmt.Errorf("install: --secrets-encryption: %w", err)
	}
	cfg.Logger.Info("enabled secrets encryption at rest (provider "+executor.EncryptionProviderName+"); back this file up with state.db: without it every Secret is unreadable",
		"path", executor.EncryptionConfigPath(wd))
	return nil
}
