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
	"path/filepath"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/netdsvc"
)

// artifactKind classifies a manifest entry so install/uninstall can perform the
// right operation (a launchd daemon tears down differently from a plain file).
type artifactKind int

const (
	// kindFile is a single root-owned file (e.g. the k3sm binary).
	kindFile artifactKind = iota
	// kindDir is a directory tree (e.g. the InstallDir sweep, DataRoot, LogDir).
	kindDir
	// kindDaemon is a launchd job: a compound of a Label AND its plistPath, torn
	// down as Bootout(label) THEN RemoveAll(plistPath) so the two never diverge.
	kindDaemon
	// kindServiceUser is the _k3sm no-login system user.
	kindServiceUser
	// kindKubeconfig is the admin kubeconfig written into the human's ~/.kube/config.
	kindKubeconfig
	// kindSymlink is a symlink whose target is another manifest artifact; laid
	// down after its target, removed only when it still points at that target.
	kindSymlink
)

// disposition is what uninstall does with an artifact install laid down.
type disposition int

const (
	// dispRemove is torn down on uninstall (the two plists; the InstallDir tree).
	dispRemove disposition = iota
	// dispInstallDirCovered lives under InstallDir and is removed by the single
	// RemoveAll(InstallDir) sweep — never individually (that would double-remove).
	dispInstallDirCovered
	// dispPreserve is installed but kept on uninstall: DataRoot (kine state.db +
	// mesh keys — nuking it loses data on reinstall), the human kubeconfig (may
	// hold other clusters), the _k3sm user, LogDir.
	dispPreserve
)

// artifact is one thing install lays down. Every path is derived from a Config
// accessor/const — never a re-hardcoded /Library/... literal (a third copy of a
// path is the same divergence bug this manifest exists to prevent). A daemon binds its Label and
// plistPath into one entry so a booted-out label can never leave a leaked
// KeepAlive plist (the original leak).
type artifact struct {
	kind  artifactKind
	disp  disposition
	path  string // file/dir/plist path; empty for kindServiceUser/kindKubeconfig
	label string // launchd label for kindDaemon; empty otherwise
	user  string // user name for kindServiceUser/kindKubeconfig; empty otherwise
	// target is what a kindSymlink entry points at — itself a manifest path, so
	// the link and its target cannot name different files. Empty otherwise.
	target string
	// assertExists records whether the path is expected on disk today. It is
	// false for the forward-declared cp-payload items (the /Library/k3sm/bin tree
	// + relocated k3sm-netd): the packaging follow-up owns moving cp/kine off
	// DataRoot into InstallDir, so those paths do not exist yet. The manifest
	// proves the disposition (InstallDir-covered), not on-disk presence — that
	// follow-up lights them up with no manifest change.
	assertExists bool
	// oneshot marks a kindDaemon that RUNS AND EXITS rather than staying up
	// (io.k3sm.datavol). It changes two things and nothing else: the restart
	// sequence waits for the job to be LOADED rather than for a live pid, and
	// the post-restart verification does not demand a pid it was never going to
	// have.
	oneshot bool
}

// artifactManifest is the single source of truth for what install lays down and
// how uninstall tears it down. It is a pure func(Config) — hermetic and testable
// — deriving every path from the existing Config accessors/consts. Both Install
// (lay-down order + plist paths) and Uninstall (reverse-order teardown) consume
// it, closing the divergence between the two hardcoded lists that leaked the
// plists. Order is install order; uninstall walks it in reverse.
func artifactManifest(cfg Config) []artifact {
	cfg = cfg.withDefaults()
	items := []artifact{
		// The _k3sm service user — created before the server daemon can resolve it.
		// Preserved: its home is DataRoot; removing it orphans the data root.
		{kind: kindServiceUser, disp: dispPreserve, user: cfg.ServiceUser},

		// The InstallDir tree — the single RemoveAll(InstallDir) sweep on uninstall.
		{kind: kindDir, disp: dispRemove, path: cfg.InstallDir, assertExists: true},
		// The k3sm binary copied into InstallDir — covered by the sweep, not
		// removed individually.
		{kind: kindFile, disp: dispInstallDirCovered, path: cfg.installedBinary(), assertExists: true},
		// The `k3sm` launcher symlink in LinkDir pointing at that binary. It sits
		// immediately after its target so install order lays the target down
		// first, and so the reverse uninstall walk removes the link BEFORE the
		// InstallDir sweep deletes what it points at (a link removed after its
		// target would be judged against a path that no longer exists).
		{kind: kindSymlink, disp: dispRemove, path: cfg.installedLink(), target: cfg.installedBinary(), assertExists: true},
		// The k3sm-execshim Seatbelt helper beside it (sandbox.FindExecShim's
		// first probe) — the runtimed backend the server plist hardcodes cannot
		// boot without it. Covered by the InstallDir sweep.
		{kind: kindFile, disp: dispInstallDirCovered, path: cfg.installedExecShim(), assertExists: true},
		// The path-rebase DYLD shim beside the binary (runtimedConfig resolves it
		// next to the executable) — injected into a mounting pod so an absolute
		// volume mount resolves under the pod data volume. Covered by the sweep.
		{kind: kindFile, disp: dispInstallDirCovered, path: cfg.installedPathShim(), assertExists: true},
		// The getaddrinfo DNS shim beside the binary — injected into each pod so an
		// in-pod cluster-name lookup reaches the per-node resolver. Covered by the sweep.
		{kind: kindFile, disp: dispInstallDirCovered, path: cfg.installedDNSShim(), assertExists: true},
		// The k3sm-vmhost VM-host helper beside the binary (sandbox.FindVMHost's
		// first probe) — vm-RuntimeClass pods cannot boot without it. Covered by
		// the sweep.
		{kind: kindFile, disp: dispInstallDirCovered, path: cfg.installedVMHost(), assertExists: true},
		// The control-plane payload staged into InstallDir/bin (the daemon boot
		// seeds its workdir from it — no gh/go under launchd). Covered by the sweep.
	}
	// Ranged over executor.PayloadBinaries() — the same source Install copies from
	// — so a new payload binary cannot be installed without also being uninstalled
	// (the manifest test asserts install ⊆ uninstall coverage).
	for _, b := range executor.PayloadBinaries() {
		items = append(items, artifact{kind: kindFile, disp: dispInstallDirCovered, path: filepath.Join(cfg.InstallDir, "bin", b), assertExists: true})
	}
	// The kine version marker rides beside the kine binary it describes: it is what tells
	// the daemon's work-dir seed which kine pin+variant was staged, so a pin change reaches
	// an already-booted node instead of being masked by the old binary's mere presence.
	// assertExists is false — an archive produced before markers existed still installs, and
	// the seed falls back to rebuilding rather than trusting bytes nothing vouched for.
	items = append(items, artifact{kind: kindFile, disp: dispInstallDirCovered, path: filepath.Join(cfg.InstallDir, "bin", executor.KineMarkerName), assertExists: false})
	// The etcd version marker rides beside the etcd binary on exactly the kine marker's
	// terms (the work-dir seed replaces a stale etcd only from a payload it vouches for).
	items = append(items, artifact{kind: kindFile, disp: dispInstallDirCovered, path: filepath.Join(cfg.InstallDir, "bin", executor.EtcdMarkerName), assertExists: false})
	// The control-plane version marker rides beside the four kube binaries on the same
	// terms: it is what lets the work-dir seed replace a stale control-plane set after a
	// binary-only upgrade, and a pre-marker archive has none, so it is not asserted.
	items = append(items, artifact{kind: kindFile, disp: dispInstallDirCovered, path: filepath.Join(cfg.InstallDir, "bin", executor.KubeMarkerName), assertExists: false})
	items = append(items, []artifact{
		// Forward-declared: the cp-payload bin tree + relocated k3sm-netd land
		// under InstallDir once the packaging follow-up moves them off DataRoot. They
		// do not exist on disk today (cp/kine land under DataRoot at runtime), so
		// existence is not asserted; the InstallDir sweep already covers them.
		{kind: kindDir, disp: dispInstallDirCovered, path: filepath.Join(cfg.InstallDir, "bin"), assertExists: false},
		{kind: kindFile, disp: dispInstallDirCovered, path: filepath.Join(cfg.InstallDir, "bin", "k3sm-netd"), assertExists: false},

		// The two LaunchDaemons — netd before server (install order: netd is
		// bootstrapped first, the server depends on it). Each removed on uninstall:
		// Bootout(label) then RemoveAll(plistPath). Removing the plist is the fix for
		// a leak — previously the label was booted out but the plist leaked, leaving a
		// phantom KeepAlive respawn-throttle root job pointing at a deleted binary.
	}...)
	// The data-volume mount daemon goes IMMEDIATELY BEFORE netd, present only
	// when this Mac has a data volume to manage. Its position is its contract:
	// install lays plists down and restarts jobs in manifest order, so the
	// mount is attempted before the two daemons that refuse an unmounted data
	// root, and the reverse uninstall walk boots it out last of the three.
	// assertExists is false because a Mac that never asked for a volume has no
	// such plist, and one that just asked for its first has none yet either.
	if cfg.dataVolumeDeclared {
		items = append(items, artifact{kind: kindDaemon, disp: dispRemove, label: DatavolLabel, path: cfg.plistPath(DatavolLabel), oneshot: true, assertExists: false})
	}
	// The staged join token, for an agent node only, and REMOVED on uninstall
	// unlike everything else under the preserved data root. It is a credential
	// with no further use once the node has joined (the stored node credential
	// is what every later start presents), so leaving it behind would leave a
	// cluster-joining secret on a machine somebody just uninstalled k3sm from.
	// It sits before the daemon entries so the reverse uninstall walk removes it
	// AFTER the agent has been booted out, never from under a running daemon.
	// assertExists is false: an install that staged no token wrote no file.
	if cfg.Role == RoleAgent {
		items = append(items, artifact{kind: kindFile, disp: dispRemove, path: cfg.agentTokenPath(), assertExists: false})
	}
	// The control plane's staged admin token, the same entry for the other role
	// and in the same position, for the same reason: it is a system:masters
	// bearer token with no use once this Mac is no longer a k3sm server, so it
	// is REMOVED rather than preserved with the rest of the data root, and it is
	// removed after the daemon that reads it has been booted out.
	// assertExists is false because a data root an older build installed has no
	// such file until the next install stages one.
	if cfg.Role == RoleServer {
		items = append(items, artifact{kind: kindFile, disp: dispRemove, path: cfg.serverTokenPath(), assertExists: false})
		// A joining HA server's staged server-class join token, removed for the
		// same reason and with more cause: it decrypts every cluster CA. It
		// lives as long as the joined server needs it (it is read at every
		// start) and no longer. assertExists is false: only a --server-join
		// install stages one.
		items = append(items, artifact{kind: kindFile, disp: dispRemove, path: cfg.serverJoinTokenPath(), assertExists: false})
		// The secrets encryption pair, PRESERVED with the datastore it unlocks:
		// deleting the key would leave every Secret in the preserved state.db
		// unreadable. assertExists is false: encryption is opt-in.
		items = append(items,
			artifact{kind: kindFile, disp: dispPreserve, path: executor.EncryptionConfigPath(cfg.serverWorkDir()), assertExists: false},
			artifact{kind: kindFile, disp: dispPreserve, path: executor.EncryptionFingerprintPath(cfg.serverWorkDir()), assertExists: false})
	}
	// This node's wireguard identity: the role's work-dir copy, the root-only
	// key dir, and the copy inside it that netd's MeshKeyResolver reads. All
	// three are PRESERVED, which is the disposition of everything else under the
	// data root that is state rather than a credential in transit:
	//
	//   - the work-dir key IS the node's mesh identity. Removing it would rotate
	//     the public key every peer has in its AllowedIPs on the next install,
	//     which is the failure loadOrCreateMeshKey exists to prevent, and it is
	//     already covered by DataRoot's own preserve entry ("kine state.db + mesh
	//     keys").
	//   - the helper copy and its directory, MeshKeyDir, are root-owned state
	//     directly under the data root and are preserved in their own right: a
	//     reinstall picks the identity up where it left off (provisionMeshKey
	//     restores the work-dir copy from it rather than minting). Removing the
	//     whole tree for good is a separate, explicit operation, not uninstall.
	//
	// Neither path's existence is asserted: a data root an older build installed
	// has no key until the install that provisions one, and a node that has never
	// run has no work-dir copy either.
	items = append(items,
		artifact{kind: kindFile, disp: dispPreserve, path: cfg.meshKeyWorkPath(), assertExists: false},
		artifact{kind: kindDir, disp: dispPreserve, path: MeshKeyDir, assertExists: false},
		artifact{kind: kindFile, disp: dispPreserve, path: cfg.meshKeyHelperPath(), assertExists: false},
	)
	// The one leaf inside that preserved key dir that is REMOVED: the node pod
	// CIDR netd adopted from this role's join and persisted so a restart the node
	// daemon did not drive keeps the same /24. It is state OF A ROLE, not of the
	// machine. A role change goes through uninstall (refuseCrossRole refuses
	// anything else), so if it survived, the returning role's netd would restore
	// the other role's /24 at start and admit pod aliases against a boundary the
	// cluster handed to a node that no longer exists. Removing it costs nothing:
	// the next join hands netd its pod CIDR again. The directory, node.key and the
	// helper key above stay exactly as they are.
	//
	// It sits after the key-dir entries and before the daemons, so the reverse
	// uninstall walk removes it only once netd has been booted out and can no
	// longer rewrite it. Install never writes it (netd does), so nothing lays it
	// down; assertExists is false because a node that never adopted has none.
	items = append(items, artifact{kind: kindFile, disp: dispRemove, path: netdsvc.NodeIdentityPath(MeshKeyDir), assertExists: false})
	// The node daemon AFTER netd, and it is the ROLE's daemon: io.k3sm.server on
	// a control plane, io.k3sm.agent on a joining worker. Exactly one of them is
	// ever in a manifest — a Mac that carried both would register two nodes out
	// of one data root — and the position is the same either way, because both
	// depend on the helper netd bootstraps first.
	items = append(items, []artifact{
		{kind: kindDaemon, disp: dispRemove, label: NetdLabel, path: cfg.plistPath(NetdLabel), assertExists: true},
		{kind: kindDaemon, disp: dispRemove, label: daemonLabel(cfg.Role), path: cfg.plistPath(daemonLabel(cfg.Role)), assertExists: true},

		// The admin kubeconfig in the human's home — preserved (it may hold other
		// clusters; k3sm never owns the whole file).
		{kind: kindKubeconfig, disp: dispPreserve, user: cfg.TargetUser},

		// Preserved privileged state: DataRoot (kine state.db + mesh keys) and the
		// daemon LogDir. Both survive an uninstall→reinstall.
		{kind: kindDir, disp: dispPreserve, path: cfg.DataRoot, assertExists: false},
		{kind: kindDir, disp: dispPreserve, path: LogDir, assertExists: false},
	}...)
	// The data-volume record, beside the data root it declares and preserved for
	// the same reason: an uninstall keeps the volume mounted and its data
	// intact, so deleting the declaration would leave the next `k3sm install`
	// unable to tell a k3sm volume from an operator's. It lives outside
	// InstallDir precisely so the uninstall sweep cannot reach it; the entry is
	// here to say that is deliberate. `k3sm datavol delete --yes` is the one
	// thing that removes it.
	if cfg.dataVolumeDeclared {
		items = append(items, artifact{kind: kindFile, disp: dispPreserve, path: dataroot.DefaultRecordPath, assertExists: false})
	}
	// The role's arguments record, UNCONDITIONALLY and preserved: every install
	// writes one (an empty set is the truthful record of a node with no operator
	// flags), and an uninstall must keep it or the next install is back to
	// re-rendering the stock template over an operator's configuration. It lives
	// outside InstallDir so the sweep cannot reach it; the entry is here to say
	// that is deliberate, and to put it in the list uninstall prints. A server
	// install names the server record and an agent install the agent one, so
	// neither role can ever be handed the other's flags.
	items = append(items, artifact{kind: kindFile, disp: dispPreserve, path: cfg.argsRecordPath(), assertExists: false})
	items = append(items, []artifact{
		// The container-log tree is REMOVED on uninstall, unlike the daemon LogDir
		// above and unlike DataRoot. It holds no state a reinstall wants and no
		// record anyone is keeping: every file in it belongs to a pod that no
		// longer exists once k3sm is gone, and leaving a root-equivalent tree of
		// former workloads' output behind on a machine somebody just uninstalled
		// k3sm from is not a kindness.
		{kind: kindDir, disp: dispRemove, path: PodLogsDir, assertExists: false},
		{kind: kindDir, disp: dispRemove, path: ContainerLogsDir, assertExists: false},
	}...)
	return items
}

// carriesServerDaemon reports whether the manifest tears down the control-plane
// daemon.
func carriesServerDaemon(m []artifact) bool {
	for _, a := range m {
		if a.kind == kindDaemon && a.label == ServerLabel {
			return true
		}
	}
	return false
}

// carriesAgentDaemon reports whether the manifest tears down the worker daemon,
// which is the one durable fact that says this Mac is a worker.
func carriesAgentDaemon(m []artifact) bool {
	for _, a := range m {
		if a.kind == kindDaemon && a.label == AgentLabel {
			return true
		}
	}
	return false
}

// keptArtifacts describes, in manifest order, what an uninstall deliberately
// leaves on disk. It is derived from the manifest's dispPreserve entries rather
// than hand-listed, so an artifact that becomes preserved (or stops being)
// cannot quietly fall out of the sentence an operator reads.
func keptArtifacts(cfg Config, m []artifact) []string {
	var kept []string
	for _, a := range m {
		switch {
		case a.disp != dispPreserve:
			continue
		case a.kind == kindServiceUser:
			kept = append(kept, "the "+a.user+" service user")
		case a.kind == kindKubeconfig:
			kept = append(kept, "your admin kubeconfig")
		case a.path == cfg.DataRoot:
			// Named with its record, because that file is the one preserved
			// thing whose existence is not obvious: it is why the next install
			// still knows this node's --mesh-ip.
			kept = append(kept, "the data root "+a.path+" (your cluster state)")
		case a.path == LogDir:
			kept = append(kept, "the daemon log dir "+a.path)
		case a.path == cfg.ServerArgsRecord:
			kept = append(kept, "the server arguments you configured, in "+a.path)
		case a.path == cfg.AgentArgsRecord:
			kept = append(kept, "the agent arguments you configured, in "+a.path)
		case a.path == dataroot.DefaultRecordPath:
			kept = append(kept, "the data-volume record "+a.path)
		default:
			kept = append(kept, a.path)
		}
	}
	return kept
}
