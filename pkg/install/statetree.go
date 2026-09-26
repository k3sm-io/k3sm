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
	"io/fs"
	"path/filepath"

	"k3sm.io/runtimed/pkg/sandbox"
)

// The state tree's ownership, in one table.
//
// k3s keeps every private key under its data dir, and that works for k3s
// because root owns the whole tree. k3sm splits privilege: the node daemons run
// as the unprivileged service user and must be able to write their own state,
// while the root netd helper reads this node's wireguard private key. On macOS
// the right to unlink or rename an entry is the PARENT directory's write bit,
// so a key directory sitting anywhere under a service-user-owned directory is a
// key directory the service user can remove or replace, whatever its own mode.
//
// The faithful translation of k3s's layout is therefore this table:
//
//	/var/lib/k3sm          root:wheel 0755  (k3s's data-dir mode)
//	/var/lib/k3sm/keys     root:wheel 0700  (the mesh keys + the node identity)
//	/var/lib/k3sm/<tree>   service user     (every tree an unprivileged daemon writes)
//
// Because the root is root-owned, the service user can no longer create a
// top-level directory of its own, so every tree it writes is named here and
// created by root: by `k3sm install`, and by netd when it heals a root an older
// build left service-user-owned. No unprivileged principal owns any component
// of the path to the keys, so nothing but root can unlink or rename them.
//
// This table is the ONLY statement of which level gets which owner and mode.
// The installer's ensure steps and netd's start-time alignment both read it; a
// second literal in either would let the two answers drift, which is how the
// data root came to be chowned to the service user in two places.

// StateRootMode and StateRootGID are the data root's own ownership: root, group
// wheel, 0755 (world-traversable, as k3s's data dir is).
const (
	StateRootMode fs.FileMode = 0o755
	StateRootGID  int         = 0
)

// ServiceTreeMode and ServiceTreeGID are the default ownership of a
// service-user tree directly under the data root: group staff (the service
// user's primary group), 0750. A tree whose owning code already decided a
// tighter mode (the run dir, the two work dirs, the daemon-private stores)
// carries that mode in the table instead.
//
// They are NOT the data root's ownership, which is StateRootMode/StateRootGID:
// the root is root's, and only the trees under it are the service user's.
const (
	ServiceTreeMode fs.FileMode = 0o750
	ServiceTreeGID  int         = 20
)

// RunDirMode is the run dir's mode: the service user's alone, because it holds
// the daemons' control sockets.
const RunDirMode fs.FileMode = 0o700

// LibraryMode is the service user's home-Library mode, the macOS convention
// for ~/Library: the user's alone.
const LibraryMode fs.FileMode = 0o700

// serviceTreePrivateMode is the mode of the daemon-private stores the runtime
// already creates 0700 (the image index, the operator record, the ingest
// staging dir, the SBPL staging dir and the two reap stores). Pre-creating them
// at the same mode means the installer changes their owner and nothing else.
const serviceTreePrivateMode fs.FileMode = 0o700

// meshKeySubdir is the key directory's leaf name. It is spelled once, so the
// new location (under the data root) and the legacy one (under the run dir)
// cannot come to name different leaves.
const meshKeySubdir = "keys"

// StatePrincipal is who owns a level of the state tree.
type StatePrincipal int

const (
	// PrincipalRoot is uid 0. It is the zero value on purpose: a level nobody
	// classified is root's, which fails closed (the service user cannot write
	// it) rather than open.
	PrincipalRoot StatePrincipal = iota
	// PrincipalServiceUser is the unprivileged service user the node daemons
	// run as, whose uid is only known at run time.
	PrincipalServiceUser
)

// StateOwnership is one level's owner, group and mode.
type StateOwnership struct {
	// Principal is who owns the level.
	Principal StatePrincipal
	// GID is the numeric group.
	GID int
	// Mode is the permission bits.
	Mode fs.FileMode
}

// UID resolves the principal to a numeric uid, given the service user's.
func (o StateOwnership) UID(serviceUID int) int {
	if o.Principal == PrincipalServiceUser {
		return serviceUID
	}
	return 0
}

// StateLevel is one directory of the state tree, named by its path relative
// to the data root ("." is the root itself).
type StateLevel string

// The two root-owned levels. Every other level is a service-user tree.
const (
	// StateRoot is the data root itself.
	StateRoot StateLevel = "."
	// StateKeys is the root-only mesh key directory (MeshKeyDir).
	StateKeys StateLevel = meshKeySubdir
	// StateRun is the service user's run dir: the daemons' control sockets.
	StateRun StateLevel = sandbox.RunSubdir
	// StateLibrary is the service user's home-Library (<home>/Library): the
	// data root is _k3sm's home, and macOS writes per-user state there.
	StateLibrary StateLevel = "Library"
)

// Path joins the level onto a data root.
func (l StateLevel) Path(dataRoot string) string {
	return filepath.Join(dataRoot, string(l))
}

// stateLevel is one row of the table.
type stateLevel struct {
	level StateLevel
	own   StateOwnership
}

// stateTree is the table, in apply order: the root first (so that by the time
// any child is touched no unprivileged principal can rename it), then the
// keys, then every service-user tree.
//
// The service-user trees are every directory an unprivileged daemon creates
// directly under the data root today: the run dir, the control-plane and
// node-agent work dirs, and the runtime's own trees under its work dir, which
// on a stock install IS the data root (executor.RuntimeRoot). The runtime's
// names are taken from its exported constants so a rename there cannot leave a
// directory here that nothing writes.
var stateTree = func() []stateLevel {
	root := StateOwnership{Principal: PrincipalRoot, GID: StateRootGID, Mode: StateRootMode}
	keys := StateOwnership{Principal: PrincipalRoot, GID: StateRootGID, Mode: MeshKeyDirMode}
	svc := func(mode fs.FileMode) StateOwnership {
		return StateOwnership{Principal: PrincipalServiceUser, GID: ServiceTreeGID, Mode: mode}
	}
	return []stateLevel{
		{StateRoot, root},
		{StateKeys, keys},
		{StateRun, svc(RunDirMode)},
		// The service user's home-Library. The data root IS _k3sm's home, and
		// macOS seeds <home>/Library (Caches, Containers, Keychains, Logs, ...)
		// the first time a framework running as that user asks for it; the
		// home-Library convention is the user's own 0700.
		{StateLibrary, svc(LibraryMode)},
		{StateLevel(sandbox.ServerSubdir), svc(ServerTokenDirMode)},
		{StateLevel(agentWorkSubdir), svc(AgentTokenDirMode)},
		// The per-pod rootfs parent and the PersistentVolume parent.
		{StateLevel(podsSubdir), svc(ServiceTreeMode)},
		{StateLevel(storageSubdir), svc(ServiceTreeMode)},
		// The image store and the guest-artifact cache.
		{StateLevel(sandbox.BlobsSubdir), svc(ServiceTreeMode)},
		{StateLevel(sandbox.ImageUnpackedSubdir), svc(ServiceTreeMode)},
		{StateLevel(sandbox.ImageSnapshotsSubdir), svc(ServiceTreeMode)},
		{StateLevel(sandbox.GuestArtifactsSubdir), svc(ServiceTreeMode)},
		{StateLevel(sandbox.ImageIndexSubdir), svc(serviceTreePrivateMode)},
		{StateLevel(sandbox.ImageOperatorSubdir), svc(serviceTreePrivateMode)},
		{StateLevel(sandbox.ImageIngestSubdir), svc(serviceTreePrivateMode)},
		// The daemon-private SBPL staging dir and the two reap stores.
		{StateLevel(sandbox.ProfileSubdir), svc(serviceTreePrivateMode)},
		{StateLevel(sandbox.PodReapSubdir), svc(serviceTreePrivateMode)},
		{StateLevel(sandbox.VMReapSubdir), svc(serviceTreePrivateMode)},
	}
}()

// podsSubdir and storageSubdir are the runtime's per-pod rootfs parent and
// PersistentVolume parent. runtimed spells both as literals rather than
// exported constants, so they are spelled once here.
const (
	podsSubdir    = "pods"
	storageSubdir = "storage"
)

// OwnershipOf reports the owner, group and mode the table assigns level, and
// false for a level the table does not name.
func OwnershipOf(level StateLevel) (StateOwnership, bool) {
	for _, row := range stateTree {
		if row.level == level {
			return row.own, true
		}
	}
	return StateOwnership{}, false
}

// StateLevels returns every level in the table, in apply order (the root
// first). The slice is freshly allocated.
func StateLevels() []StateLevel {
	out := make([]StateLevel, 0, len(stateTree))
	for _, row := range stateTree {
		out = append(out, row.level)
	}
	return out
}

// ServiceLevels returns the service-user levels only, in apply order. The
// slice is freshly allocated.
func ServiceLevels() []StateLevel {
	var out []StateLevel
	for _, row := range stateTree {
		if row.own.Principal == PrincipalServiceUser {
			out = append(out, row.level)
		}
	}
	return out
}

// LegacyMeshKeyFiles returns the paths of the three files an older build kept
// under dataRoot's run dir (the two roles' mesh keys and the node identity),
// so netd can warn about a layout the installer has not migrated yet. Only
// these names count: the legacy directory existing, or holding anything else,
// is not a layout k3sm has to migrate.
func LegacyMeshKeyFiles(dataRoot string) []string {
	dir := filepath.Join(StateRun.Path(dataRoot), meshKeySubdir)
	var out []string
	for _, leaf := range legacyKeyLeaves() {
		out = append(out, filepath.Join(dir, leaf))
	}
	return out
}
