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
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"k3sm.io/k3sm/pkg/bootstrap"
)

// meshKeyRef is the bare file name THIS role stores its wireguard private key
// under, in both copies. It is an accessor rather than a branch at each use so
// no code path can provision one role's identity under the other's name.
func (c Config) meshKeyRef() string {
	if c.Role == RoleAgent {
		return MeshKeyRefAgent
	}
	return MeshKeyRefServer
}

// meshKeyWorkPath is the role's WORK-DIR copy of that key: the file `k3sm
// server`/`k3sm agent` loads (or, on a node this installer never reached,
// mints) as the unprivileged service user, inside the same state tree that
// role's token is staged in.
func (c Config) meshKeyWorkPath() string {
	if c.Role == RoleAgent {
		return filepath.Join(c.DataRoot, agentWorkSubdir, MeshKeyRefAgent)
	}
	return filepath.Join(c.serverWorkDir(), MeshKeyRefServer)
}

// meshKeyHelperPath is the ROOT-ONLY copy of that key, inside MeshKeyDir.
//
// The directory is the MeshKeyDir constant rather than a derivation from this
// Config's data root, deliberately and for the same reason VMRunDir is: the
// netd plist this very install renders puts that constant on the helper's
// `--mesh-key-dir` argv, so provisioning anywhere else would write a key at a
// path netd is not reading.
func (c Config) meshKeyHelperPath() string { return filepath.Join(MeshKeyDir, c.meshKeyRef()) }

// readMeshKey reads one copy of this node's wireguard identity and returns
// (nil, nil) when that copy does not exist — the only absence this step treats
// as a posture rather than a failure.
//
// Everything else is refused, and refused LOUDLY. The work-dir copy sits in a
// directory the service user owns, so a file there is not automatically this
// node's identity — it is whatever the last writer put there; the root-only
// copy is held to the same checks so one reader serves both. Two things are therefore checked before any byte is copied anywhere:
// the path is a regular file that was opened without following a symlink, and
// the bytes decode as a usable Curve25519 private key. what names the copy in
// the error, so the operator is told which of the two to look at.
//
// The validation is not decoration. The whole step exists to copy one file's
// bytes into a root-only file netd hands to wireguard; bytes that are not a key
// would fail there, at mesh bring-up, as an opaque device error on a node that
// installed cleanly.
func readMeshKey(sys System, path, what string) ([]byte, error) {
	b, err := sys.ReadRegularFile(path)
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	default:
		return nil, fmt.Errorf("install: read the %s mesh key %s: %w", what, path, err)
	}
	if _, err := bootstrap.WireguardPublicKey(string(b)); err != nil {
		return nil, fmt.Errorf("install: the %s mesh key %s is not a usable wireguard private key: %w "+
			"(remove it only if you accept that this node's mesh identity changes and every peer must re-learn it)", what, path, err)
	}
	return b, nil
}

// provisionMeshKey makes this node's wireguard identity exist, in both places
// it has to exist, before either daemon starts — for whichever role is being
// installed.
//
// The WORK-DIR copy is the source of truth whenever it exists, because the node
// daemon is what owns the identity: it loads that file on every start and
// derives the public key its MeshPeer advertises from it, so a key minted
// anywhere else would have to agree with it byte for byte or rotate the node's
// identity. This step reads it and copies exactly its bytes into MeshKeyDir.
//
// When it does NOT exist the root-only copy is consulted before anything is
// minted, and if it holds a usable key the work-dir copy is RESTORED from it.
// That order is the point: the two copies are one identity, and a node whose
// work dir was wiped (a data-root repair, a hand-deleted file) still has every
// peer holding the public half of the key in the key dir. Minting there would
// silently orphan the node — its MeshPeer would advertise a public key no peer's
// AllowedIPs carries, and the mesh would stay dark on an install that reported
// success. A key is minted ONLY when neither copy exists, and then both are
// written from the same bytes: the work-dir one through the service-user seam,
// so the daemon finds it and never mints a second, different key of its own.
//
// The step exists at all because the daemon's own best-effort write into
// MeshKeyDir cannot work in the posture k3sm ships: that directory is
// root-owned, the daemon runs as _k3sm, and until this step existed a fresh
// install did not create it — so a worker in helper mode asked netd for a key
// ref that resolved to nothing and the mesh never came up. Provisioning is the
// privileged installer's job because only the privileged installer can do it.
//
// A re-run is a no-op when the two copies already agree, and a REPAIR when they
// do not: a root-only copy that differs, or that is unusable while the work dir
// holds a good key, is overwritten from the work dir (logged), because a stale
// copy is a key netd would hand wireguard while the node advertises the public
// half of a different one. An unusable copy with NO work-dir key to repair from
// is a hard failure — see readMeshKey.
//
// MeshKeyDir sits directly under the root-owned data root (OwnershipOf), so no
// unprivileged principal owns any component of its path: the root-only copy is
// protected in its confidentiality AND against being renamed or unlinked by the
// service user. The work-dir copy is still the service user's, so every read
// below is O_NOFOLLOW and type-checked, and every write is a temp-and-rename.
//
// Before any of that, a key an older build left in LegacyMeshKeyDir is moved
// into MeshKeyDir (migrateLegacyMeshKeys), so an upgrade reads the identity
// the node already has rather than finding the new directory empty.
func provisionMeshKey(sys System, cfg Config, uid uint32) error {
	if err := sys.EnsureMeshKeyDir(MeshKeyDir, MeshKeyDirMode); err != nil {
		return fmt.Errorf("install: ensure the root-only mesh key dir %s: %w", MeshKeyDir, err)
	}
	if err := migrateLegacyMeshKeys(sys, cfg.Logger); err != nil {
		return err
	}
	workPath, helperPath := cfg.meshKeyWorkPath(), cfg.meshKeyHelperPath()
	work, err := readMeshKey(sys, workPath, "work-dir")
	if err != nil {
		return err
	}
	helper, herr := readMeshKey(sys, helperPath, "root-only")
	if herr != nil {
		// A root-only copy that cannot be read or is not a key is repairable
		// EXACTLY when the work dir holds the identity to repair it from.
		// Otherwise it is the only thing standing between this node and a new
		// identity, and overwriting it is the one outcome that cannot be undone.
		if work == nil {
			return herr
		}
		cfg.Logger.Warn("the root-only mesh key is unusable; re-provisioning it from this node's work-dir key", "path", helperPath, "err", herr)
		helper = nil
	}

	key := work
	switch {
	case key != nil:
		// The node's own copy decides; nothing is minted or restored.
	case helper != nil:
		// Restore rather than mint: these bytes are the identity every peer
		// already knows this node by.
		key = helper
		workDirMode := ServerTokenDirMode
		if cfg.Role == RoleAgent {
			workDirMode = AgentTokenDirMode
		}
		if err := sys.WriteServiceUserFile(workPath, key, uid, MeshKeyFileMode, workDirMode); err != nil {
			return fmt.Errorf("install: restore this node's mesh key at %s: %w", workPath, err)
		}
		cfg.Logger.Info("restored this node's mesh key into the daemon's work dir from the root-only copy (the identity its peers already know)",
			"path", workPath, "source", helperPath, "keyRef", cfg.meshKeyRef())
	default:
		priv, pub, gerr := bootstrap.GenerateWireguardKey()
		if gerr != nil {
			return fmt.Errorf("install: mint this node's mesh key: %w", gerr)
		}
		key = []byte(priv)
		// The work dir IS the directory this role's token is staged in, so its
		// mode is read from that decision rather than restated under a third name.
		workDirMode := ServerTokenDirMode
		if cfg.Role == RoleAgent {
			workDirMode = AgentTokenDirMode
		}
		if werr := sys.WriteServiceUserFile(workPath, key, uid, MeshKeyFileMode, workDirMode); werr != nil {
			return fmt.Errorf("install: write this node's mesh key at %s: %w", workPath, werr)
		}
		// The PUBLIC half is logged and the private half never is: the public key
		// is what every peer programs into its wireguard device, so having it in
		// the install log is what makes a mesh that did not come up diagnosable.
		cfg.Logger.Info("minted this node's wireguard identity (neither copy existed)", "path", workPath, "keyRef", cfg.meshKeyRef(), "publicKey", pub)
	}

	if helper != nil && bytes.Equal(helper, key) {
		return nil
	}
	if helper != nil {
		cfg.Logger.Info("the root-only mesh key did not match this node's identity; re-provisioning it from the work dir", "path", helperPath)
	}
	if err := sys.WriteRootOnlyFile(helperPath, key, MeshKeyFileMode); err != nil {
		return fmt.Errorf("install: provision the root-only mesh key at %s: %w", helperPath, err)
	}
	cfg.Logger.Info("provisioned this node's mesh key for the netd helper (root-only; the daemon passes netd the ref, never the key)",
		"path", helperPath, "keyRef", cfg.meshKeyRef())
	return nil
}
