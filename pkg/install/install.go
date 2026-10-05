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

// Package install lays down (and tears down) k3sm's two boot-surviving root
// LaunchDaemons — io.k3sm.netd (the root privileged-network helper) and
// io.k3sm.server (the control plane, running as the unprivileged _k3sm user) —
// behind a small System seam so the privileged orchestration is unit-testable
// with a fake. The real darwin System (sysadminctl/dscl, ditto, launchctl,
// chown) lives in install_darwin.go; the seam, the install/uninstall ordering,
// the launchd plist rendering, and the fake live here.
//
// The Homebrew formula / goreleaser config / brew post_install kickstart hook /
// notarization + designated-requirement entitlements that drive these commands
// are the packaging follow-up (DESIGN §5c) — out of scope here.
package install

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"k3sm.io/darwin-net/pkg/podnet"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/datavol"
	"k3sm.io/k3sm/pkg/defaults"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/provider/podlogs"
	runtimed "k3sm.io/runtimed/pkg/runtime"
	"k3sm.io/runtimed/pkg/sandbox"
)

// Reverse-DNS launchd labels for the two daemons (io.k3sm.* per the project
// conventions). netd is root; server runs as the _k3sm service user.
const (
	// NetdLabel is the root privileged-network helper LaunchDaemon.
	NetdLabel = "io.k3sm.netd"
	// ServerLabel is the control-plane LaunchDaemon (UserName=_k3sm).
	ServerLabel = "io.k3sm.server"
	// AgentLabel is the joining-worker LaunchDaemon (UserName=_k3sm): `k3sm
	// agent`, the node half of the distribution on a Mac that has no control
	// plane of its own. It is the SIBLING of ServerLabel, never its companion —
	// a node carries one or the other, which is what RoleServer/RoleAgent
	// decide and what Install refuses to blur.
	AgentLabel = "io.k3sm.agent"
	// DatavolLabel is the data-volume mount LaunchDaemon. It is root, it is a
	// ONESHOT (`k3sm datavol mount` mounts and exits), and it exists because
	// launchd offers no ordering: netd and the server would otherwise race disk
	// arbitration for the volume their data root lives on. See DatavolPlist.
	DatavolLabel = "io.k3sm.datavol"
)

// Leaf values shared with the runtime packages; their home is pkg/defaults.
const (
	// DefaultServiceUser is defaults.ServiceUser.
	DefaultServiceUser = defaults.ServiceUser
	// DefaultServiceCIDR is defaults.ServiceCIDR.
	DefaultServiceCIDR = defaults.ServiceCIDR
	// PathShimName is defaults.PathShimName.
	PathShimName = defaults.PathShimName
	// DNSShimName is defaults.DNSShimName.
	DNSShimName = defaults.DNSShimName
)

// Default install locations.
const (
	// DefaultInstallDir is the root-owned (root:wheel 0755) directory the binary
	// and supporting files are copied into.
	DefaultInstallDir = "/Library/k3sm"
	// DatavolStagingDir is the mount point Install stages a data-root migration
	// on: the new volume is mounted HERE, filled, and verified before anything
	// at the real data root is touched. It lives under the install dir because
	// that tree is already root-owned, already swept by uninstall, and is never
	// the volume being migrated onto.
	DatavolStagingDir = DefaultInstallDir + "/" + datavolStagingName
	// DefaultLinkDir is the directory the installer lays the `k3sm` launcher
	// SYMLINK into, pointing back at installedBinary(). It exists because
	// nothing about copying the binary into DefaultInstallDir puts `k3sm` on a
	// shell's PATH, and every post-install instruction k3sm prints assumes it is
	// there.
	//
	// /usr/local/bin is the choice because macOS ships it as the FIRST line of
	// /etc/paths, which path_helper(8) expands into PATH for every login shell —
	// so a link there is found by a new terminal with no profile edit, and it
	// takes precedence over a same-named binary further down the path. It is a
	// symlink and never a copy: the LaunchDaemons exec installedBinary()
	// directly, so a second copy would be a second thing to keep in step, and a
	// copy of a signed Mach-O out of its install tree is a signature/notarization
	// hazard a symlink simply does not have.
	DefaultLinkDir = "/usr/local/bin"
	// DefaultLaunchDaemonDir is where the two .plist files are written.
	DefaultLaunchDaemonDir = "/Library/LaunchDaemons"
	// DefaultDataRoot is the data root (the _k3sm home): the control-plane
	// work-dir, runtimed pods/storage/image cache and the root-only mesh keys
	// live under it. The root itself is root:wheel 0755, as k3s's data dir is;
	// the trees the service user writes are its own. See OwnershipOf for the
	// one table that says which level is whose.
	DefaultDataRoot = "/var/lib/k3sm"
	// DefaultRunDir is the runtime run directory under the default data root: the
	// directory half of every k3sm rendezvous socket (netd.sock, runtimed.sock,
	// the per-pod vm agent sockets) and of the mesh key dir. It is composed from
	// runtimed's OWN subdir name rather than re-typed, so the directory the
	// installer prepares and the one provider.RuntimedSocketPath binds inside can
	// never drift; RunDir is the same derivation for a non-default data root.
	DefaultRunDir = DefaultDataRoot + "/" + sandbox.RunSubdir
	// DefaultNetdSocket is the root netd unix socket the daemons rendezvous on.
	DefaultNetdSocket = DefaultRunDir + "/netd.sock"
	// DefaultAPIServerPort is the apiserver secure port (avoids Docker's :6443).
	DefaultAPIServerPort = 6444
	// MeshKeyDir is the directory the netd MeshKeyResolver reads the node's
	// wireguard private key from, and where netd persists the node identity
	// (netdsvc.NodeIdentityPath). It sits DIRECTLY under the root-owned data
	// root, root:wheel 0700 (OwnershipOf(StateKeys)), so no unprivileged
	// principal owns any component of its path and nothing but root can
	// unlink or rename it.
	MeshKeyDir = DefaultDataRoot + "/" + meshKeySubdir
	// LegacyMeshKeyDir is where builds before the root-owned data root kept the
	// same files: inside the service-user-owned run dir, where the service user
	// could rename or unlink the whole directory. `k3sm install` moves anything
	// it finds there into MeshKeyDir once (see migrateLegacyMeshKeys) and netd
	// warns when it still finds a key there; nothing else reads it.
	//
	// The move is FORWARD-ONLY. A binary older than it looks for the keys here,
	// finds nothing, and mints a new identity; the remedy before a downgrade is
	// to copy the files from MeshKeyDir back here by hand.
	LegacyMeshKeyDir = DefaultRunDir + "/" + meshKeySubdir
	// MeshKeyRefServer and MeshKeyRefAgent are the BARE file names each node role
	// stores its wireguard private key under — both in that role's work dir (the
	// copy the unprivileged daemon loads) and in MeshKeyDir (the root-only copy
	// the netd MeshKeyResolver resolves in helper mode).
	//
	// They live here, exported, because three parties must agree on them and only
	// one of the three can see the other two: `k3sm install` provisions both
	// copies, `k3sm server`/`k3sm agent` load the work-dir copy and pass the ref
	// over the netd socket, and netd resolves that ref inside MeshKeyDir. A
	// second spelling in cmd would be a daemon naming a key nothing provisioned —
	// which is the state this pair replaced, and which fails at mesh bring-up
	// rather than at install.
	//
	// The two are DISTINCT so a control plane and a joined worker on one Mac (the
	// single-host acceptance posture) never overwrite each other's identity in
	// the one key dir. Each is a bare file name: the resolver rejects anything
	// with a separator in it.
	MeshKeyRefServer = "server.key"
	MeshKeyRefAgent  = "node.key"
	// MeshKeyDirMode and MeshKeyFileMode are the ownership POLICY for the
	// root-only key dir and the key inside it: root:wheel, 0700 on the directory
	// and 0600 on the file, and never the service user's.
	//
	// That is the whole point of the helper copy. The unprivileged daemon already
	// holds the same bytes in its own work dir, so a helper copy readable by
	// _k3sm would buy nothing; what it buys root-owned is that netd — which runs
	// as root and is the only party that has to open it — reads a key no other
	// account on the Mac can. See provisionMeshKey for the residual this does NOT
	// cover.
	MeshKeyDirMode  fs.FileMode = 0o700
	MeshKeyFileMode fs.FileMode = 0o600
	// VMRunDir is the per-pod guest-agent socket directory runtimed binds under,
	// as the SERVICE USER. It is pre-created by the installer for the same reason
	// the run dir itself is: only root can hand the service user a directory
	// under /var/lib, and an install over a tree an earlier build left root-owned
	// must repair the ownership rather than leave it unusable.
	//
	// The path mirrors runtimed's guestAgentSocket derivation
	// (<runtimed root>/run/vm/<podID>/agent.sock). Without it every vm pod dies
	// at boot with "agent socket dir: mkdir /var/lib/k3sm/run/vm: permission
	// denied" (FAILURE_REASON_SANDBOX_SETUP) on an otherwise healthy, entitled
	// Mac — i.e. the whole vm RuntimeClass is unusable on a stock install.
	VMRunDir = DefaultRunDir + "/vm"
	// LogDir is where the daemons' stdout/stderr are written.
	LogDir = "/var/log/k3sm"
	// LogDirMode, LogDirGID and LogFileMode are the ownership POLICY for that
	// directory and for the daemon logs inside it: service-user-owned,
	// group ADMIN (gid 80), directory 0750, files 0640.
	//
	// The group is `admin` and deliberately NOT the `staff` of ServiceTreeGID.
	// staff is the primary group of every ordinary macOS account, so a
	// staff-readable log tree is a world-readable one under another name, and
	// tightening the mode over it would buy nothing. `admin` is the
	// sudo-capable tier docs/privilege-model.md already treats as k3sm's
	// administrative boundary (the one-time-admin install, the netd control
	// socket's root-owned 0660 group), which is the right audience for a log
	// that carries daemon argv, cluster endpoints and failure detail.
	//
	// 0750/0640 is the tightest pair launchd still works with. launchd opens a
	// UserName=_k3sm job's StandardOut/ErrorPath AS _k3sm, so the service user
	// must be able to traverse the directory and append to its own file; the
	// root jobs (netd, datavol) bypass the mode entirely. Per launchd.plist(5)
	// a path that ALREADY exists is simply opened, and only a missing one is
	// created from the job's identity and umask — which is why EnsureLogDir
	// pre-creates every one of those files rather than leaving their mode to the umask
	// in force when a daemon first spawned.
	LogDirMode  fs.FileMode = 0o750
	LogDirGID   int         = 80
	LogFileMode fs.FileMode = 0o640
	// PodLogsDir is the root of the CRI container-log tree the node writes pod
	// output into (<dir>/<ns>_<pod>_<uid>/<container>/<n>.log). It is the
	// kubelet's own default path, taken from the package that defines the layout
	// so the installer and the node can never name two different directories.
	PodLogsDir = podlogs.DefaultPodLogsDir
	// ContainerLogsDir is the flat per-container symlink directory log shippers
	// glob, again the kubelet's own path.
	ContainerLogsDir = podlogs.ContainerLogsDir
)

// ContainerLogDirMode and ContainerLogDirGID are the ownership POLICY for the
// container-log tree: service-user-owned, group WHEEL (gid 0), mode 0700.
//
// Deliberately tighter than the `admin 0750` of LogDirMode above, and the
// difference is the whole point. That directory holds the daemons' own stdout,
// which an administrator of the Mac is entitled to read while diagnosing the
// cluster. This one holds every pod's output — application logs, stack traces,
// whatever a workload prints — and upstream's /var/log/pods is root-owned, i.e.
// readable only by root. _k3sm's primary group is `staff`, which is the default
// group of every ordinary macOS account, so copying upstream's numeric 0755
// across would silently turn "root only" into "any local user can read every
// pod's output". 0700 with group wheel is the closest honest equivalent of
// upstream's posture on this platform: the node reads it, `kubectl logs` serves
// it, and a human reads it with sudo.
const (
	ContainerLogDirMode fs.FileMode = 0o700
	ContainerLogDirGID  int         = 0
)

// The join-token copy's ownership POLICY, and why the installer makes a copy at
// all.
//
// The agent daemon runs as the unprivileged service user. The file an operator
// writes the join token into is theirs: it is created by a root shell, it lives
// wherever they chose (/var/root is the obvious place), and root-owned 0600
// under a 0750 home is a file the service user cannot open, nor even traverse
// to. Rendering that path into the daemon's argv would have produced a worker
// that could never read the token it was pointed at, and nothing in the install
// would have said so.
//
// So Install, which IS root, reads the operator's file once and writes the
// token where the daemon can reach it: inside the agent's own work dir, owned
// by the service user, 0600 in a 0700 directory. The operator's file is never
// referenced again and stays theirs to delete.
const (
	// AgentTokenDirMode is the mode of the agent work dir the copy lives in:
	// service-user-owned, nobody else, because the node credential the agent
	// stores after its join lives in the same directory.
	AgentTokenDirMode fs.FileMode = 0o700
	// AgentTokenFileMode is the mode of the copy itself: the credential is
	// readable by exactly the uid that must present it.
	AgentTokenFileMode fs.FileMode = 0o600
	// ServerTokenDirMode and ServerTokenFileMode are the same two values for the
	// control plane's staged static admin token, stated separately rather than
	// reused under the agent's names because they are a decision about a
	// DIFFERENT file: the admin token is a system:masters bearer token, so the
	// posture it needs is if anything stricter than the join token's, never
	// looser. They are equal by policy, not by accident, and either may move
	// without dragging the other with it.
	ServerTokenDirMode  fs.FileMode = 0o700
	ServerTokenFileMode fs.FileMode = 0o600
	// agentWorkSubdir is the agent's state root under the data root, the same
	// directory `k3sm agent --work-dir` defaults to, so the token the installer
	// stages and the state the agent keeps are one tree rather than two.
	agentWorkSubdir = "agent"
	// agentTokenName is the leaf name of the staged token.
	agentTokenName = "join-token"
	// serverTokenName is the leaf name of the control plane's staged static
	// admin token, inside the server work dir for the same reason the agent's
	// sits in the agent work dir: the credential a daemon presents lives in
	// that daemon's own state tree.
	serverTokenName = "token"
	// agentNodeKubeconfigName is the leaf name of the node kubeconfig the agent
	// writes on a successful join — see AgentCredentialPath.
	agentNodeKubeconfigName = "node.kubeconfig"
	// agentNodePasswordName is the leaf name of the node-password `k3sm agent`
	// mints once and reuses on every restart, so the control plane's
	// first-write-wins anti-impersonation binding keeps matching
	// (cmd/k3sm's loadOrCreateNodePassword).
	agentNodePasswordName = "node-password"
	// agentMeshKeyName is the leaf name of the worker's persisted wireguard
	// private key (cmd/k3sm's meshKeyRef). Like the node-password it is minted
	// once and MUST survive: a re-minted key rotates the node's mesh identity
	// and blackholes it until every peer re-reconciles.
	//
	// Both names are stated here rather than imported because pkg/install cannot
	// import cmd/k3sm. They are the on-disk contract between the agent that
	// writes them and the installer that has to hand them over; adoptLegacyAgentFiles
	// documents what goes wrong when the two spellings drift.
	agentMeshKeyName = "node.key"
)

// datavolStagingName is the leaf name of the migration staging mount point. It
// is stated once and joined onto whichever install dir a Config names, so
// DatavolStagingDir and Config.datavolStaging can never spell it differently.
const datavolStagingName = "datavol-staging"

// ServerLogPath returns the control-plane daemon's combined stdout/stderr log path.
// The server plist points at it and diagnostics (`k3sm certificate rotate`'s failure
// message) name it, so the two can never drift apart.
func ServerLogPath() string { return filepath.Join(LogDir, "server.log") }

// AgentLogPath returns the joining worker's combined stdout/stderr log path.
// The agent plist points at it and EnsureLogDir pre-creates it, so the file
// launchd opens and the one the installer prepares cannot drift apart.
func AgentLogPath() string { return filepath.Join(LogDir, "agent.log") }

// NetdLogPath returns the root network helper's combined stdout/stderr log path.
// The netd plist points at it, so — like ServerLogPath — the plist and any
// diagnostic that names the file cannot drift apart.
func NetdLogPath() string { return filepath.Join(LogDir, "netd.log") }

// DatavolLogPath returns the data-volume mount daemon's combined stdout/stderr
// log path. The datavol plist points at it and `k3sm status` names the file on
// the datavol row, so — like NetdLogPath — the plist and the diagnostic that
// names it cannot drift apart.
func DatavolLogPath() string { return filepath.Join(LogDir, "datavol.log") }

// refuseShadowedDataRoot returns dataroot.Refusal when dir is declared in
// /etc/fstab as a mount point but nothing is mounted there. Installing into that
// posture would chown the bare mountpoint on the boot disk to the service user,
// which is worse than the crash it prevents: the control plane would then build
// a fresh, empty datastore that shadows the real volume's. An inspection error
// is not a refusal — the caller's own mkdir/chown reports the real failure.
func refuseShadowedDataRoot(fsys dataroot.FS, dir string) error {
	st, err := dataroot.Read(fsys, dir)
	if err != nil {
		return nil
	}
	if st.Shadowed() {
		return dataroot.Refusal(dir)
	}
	return nil
}

// RunDir returns the runtime run directory for a data root: <dataRoot>/run, with
// an empty dataRoot meaning runtimed's default work dir. It is the DIRECTORY the
// node's runtimed control-socket listener binds inside — the same derivation
// provider.RuntimedSocketPath performs on the socket itself, composed from
// runtimed's exported subdir name rather than a second literal so the directory
// the installer prepares is by construction the one the listener needs.
//
// That single-sourcing is load-bearing, not tidiness. The run dir was created by
// whichever daemon reached it first, which is root netd — leaving it root:wheel,
// so the _k3sm server's bind of <run>/runtimed.sock failed EACCES, the node's
// bounded retry gave up, and the control socket was silently disabled on an
// otherwise healthy install. Install now prepares it explicitly, before either
// daemon bootstraps.
func RunDir(dataRoot string) string {
	if dataRoot == "" {
		dataRoot = sandbox.DefaultWorkDir
	}
	return filepath.Join(dataRoot, sandbox.RunSubdir)
}

// Role is which k3sm node this install lays down: the control plane, or a
// worker that joins one.
//
// The type, its two values and the on-disk decision live in pkg/dataroot — the
// leaf package that already owns the facts a Mac carries on disk — so a
// reporting caller can reach the same verdict without importing the installer.
// They are re-exported here because this package is where roles are ACTED on,
// and every existing caller says install.RoleServer.
type Role = dataroot.Role

const (
	// RoleServer lays down the control plane (io.k3sm.server). The default.
	RoleServer = dataroot.RoleServer
	// RoleAgent lays down a joining worker (io.k3sm.agent) instead.
	RoleAgent = dataroot.RoleAgent
)

// RoleFromPlists decides which role a Mac carries from the two node-daemon
// plists on disk. See dataroot.RoleFromPlists for the decision and why the disk
// — never a running pid — is what answers it.
func RoleFromPlists(serverPresent, agentPresent bool) (Role, bool) {
	return dataroot.RoleFromPlists(serverPresent, agentPresent)
}

// daemonLabel is the LaunchDaemon label a role's node daemon carries. It is a
// function rather than a method because Role is an alias for a type this
// package does not define, and the LABELS are this package's own.
func daemonLabel(r Role) string {
	if r == RoleAgent {
		return AgentLabel
	}
	return ServerLabel
}

// EntryKind is what an OwnedEntry IS, stated explicitly rather than left to a
// caller to re-derive from the type bits.
//
// It is an explicit enum, and not a pair of booleans, because the decision that
// reads it is a security decision: an ownership verdict reached about a name is
// applied to whatever that name resolves to, so "this is a symlink" has to be a
// value the code must handle rather than the absence of two other values.
type EntryKind int

const (
	// EntryOther is a socket, a device, a fifo — anything with no other name
	// here. It is the ZERO value on purpose: a kind nobody set is the one this
	// package refuses to act on, never "an ordinary file".
	EntryOther EntryKind = iota
	// EntryRegular is a regular file.
	EntryRegular
	// EntryDir is a directory.
	EntryDir
	// EntrySymlink is a symbolic link — the entry itself, never its target, since
	// the seam lstats.
	EntrySymlink
)

// String names the kind as an error message needs it ("a symlink", "a
// directory"), so a refusal says what it found rather than what it did not.
func (k EntryKind) String() string {
	switch k {
	case EntryRegular:
		return "a regular file"
	case EntryDir:
		return "a directory"
	case EntrySymlink:
		return "a symlink"
	}
	return "neither a file nor a directory"
}

// OwnedEntry is one filesystem entry as an ownership decision sees it: where it
// is, who owns it, what it permits, and what kind of entry it is. It is what the
// System seam's Owner and ListOwned answer with.
//
// Mode carries the permission bits ONLY (fs.FileMode.Perm); the kind is in Kind,
// so no caller has to re-derive it from the type bits and get the derivation
// subtly different from the next caller's.
type OwnedEntry struct {
	// Path is the full path of the entry, so an error or a chown built from an
	// entry never has to re-join a directory and a name.
	Path string
	// UID and GID are the numeric owner and group.
	UID, GID int
	// Mode is the permission bits.
	Mode fs.FileMode
	// Kind is what the entry is.
	Kind EntryKind
}

// DirHandle is a directory held open by descriptor (System.OpenDirNoFollow).
// Every method acts on the entry name DIRECTLY inside the held directory,
// relative to its descriptor, and never follows a symlink.
type DirHandle interface {
	// ReadEntry returns the bytes of the regular file name. A symlink or any
	// other non-regular entry is refused with ErrNotRegularFile; a missing one
	// has ReadFile's fs.ErrNotExist contract.
	ReadEntry(name string) ([]byte, error)
	// RemoveEntry unlinks the file name. Absent is success.
	RemoveEntry(name string) error
	// ListEntries returns the names of the entries in the held directory,
	// sorted. Names only: nothing is opened or followed.
	ListEntries() ([]string, error)
	// Close releases the descriptor.
	Close() error
}

// System is the privileged-operation seam install/uninstall drive. The real
// darwin implementation performs the root syscalls/tools; tests inject a fake so
// the orchestration runs without privilege.
type System interface {
	// EnsureServiceUser idempotently creates name as a no-login system user
	// (home = the configured data root, owned by it) and returns its uid.
	EnsureServiceUser(name, dataRoot string) (uid uint32, err error)
	// CopyToRootOwned copies src to exactly dst (creating dst's parent dir
	// root:wheel 0755), leaving dst root:wheel 0755 with signature/xattrs
	// preserved. dst is the full installed path — never derived from src's
	// basename: the LaunchDaemon plists exec the fixed installedBinary() path, so
	// a build artifact named e.g. `k3sm-m2` must still land at InstallDir/k3sm (a
	// basename-derived dst bricks both daemons with launchd's unrecoverable
	// "Missing executable" — an observed live-hardware failure this contract fixes).
	CopyToRootOwned(src, dst string) error
	// CloneToOwned clones src to exactly dst (APFS clonefile, falling back to
	// a plain copy across volumes), creating dst's parent root:wheel 0755 and
	// leaving dst owned uid:gid at mode. Unlike CopyToRootOwned the source's
	// signature is not the point: the shadow copies are re-signed right after
	// (AdHocSign). A missing src reports an error wrapping fs.ErrNotExist.
	CloneToOwned(src, dst string, uid, gid int, mode fs.FileMode) error
	// AdHocSign replaces path's code signature with an ad-hoc one, carrying no
	// hardened runtime and no library validation (runtimed's image.AdHocSign),
	// so the copy is neither a platform binary nor restricted and dyld keeps
	// DYLD_INSERT_LIBRARIES in it.
	AdHocSign(path string) error
	// CDHash reads path's code directory hash (codesign -dvvv).
	CDHash(path string) (string, error)
	// VerifyShadowCopy checks a made shadow copy (shadow.CheckCopyFile and
	// shadow.CheckCopySignature: a regular file, not SF_RESTRICTED, no
	// setuid/setgid or group/world write, an ad-hoc signature without the
	// hardened runtime or restrict flag and with no entitlements) and returns
	// its size in bytes. A failing copy is an error naming the property.
	VerifyShadowCopy(path string) (int64, error)
	// EnsureSymlink idempotently makes link a symlink pointing at target — the
	// `k3sm` launcher in LinkDir. It is the ONE thing install writes outside the
	// root-owned trees it owns, so it is fail-closed on both halves of that
	// exposure: it REFUSES a link directory that is not a real, root-owned,
	// non-group/other-writable directory, and it REFUSES to replace anything at
	// link that is not already a symlink (a regular file or directory there
	// belongs to someone else). Replacing a stale or dangling symlink is
	// atomic — a temp link renamed over it — so no window exists in which the
	// launcher is missing. An already-correct link is a no-op success.
	EnsureSymlink(target, link string) error
	// LinkDirTrust reports whether the directory that will hold the `k3sm`
	// launcher is one k3sm is willing to link into — root-owned, a real
	// directory, and not group- or other-writable — for the launcher path link.
	// When link's parent does not exist yet, the directory judged is ITS parent,
	// the one whose permissions decide who could create the missing one.
	//
	// It is READ-ONLY: it Lstats and nothing else, creating no directory and no
	// link, so a reinstall over a healthy Mac only reads. It exists as its own
	// seam because the refusal has to be available in Install's
	// refuse-before-write phase: the same judgement made at EnsureSymlink time
	// arrives AFTER the binaries, the plists, the service user and the data root
	// are already on disk, and a refusal there leaves a half-installed machine.
	// EnsureSymlink still makes the check at the moment it writes — the same
	// function, deliberately twice: this one keeps the tree clean, that one
	// guards the write itself.
	LinkDirTrust(link string) error
	// ResolveJoinHost returns every address the join host resolves to, in the
	// order the resolver returned them. An IP literal resolves to itself.
	//
	// The addresses are PLURAL on purpose: a control-plane Mac's name commonly
	// carries both a LAN address and a public or stale one, and the join reaches
	// the cluster iff at least ONE of them answers. A seam that resolved to a
	// single address would make the preflight's verdict depend on which record
	// the resolver happened to return first, which is the opposite of what it is
	// for. It is READ-ONLY, like the two probes beside it.
	ResolveJoinHost(host string, timeout time.Duration) ([]string, error)
	// DialJoinServer opens and immediately closes a TCP connection to addr (a
	// host:port, the bootstrap listener), returning the dial error when it does
	// not answer inside timeout. It proves reachability and nothing else — the
	// cluster's identity is FetchJoinCA's question.
	DialJoinServer(addr string, timeout time.Duration) error
	// FetchJoinCA returns the cluster CA PEM the bootstrap listener at addr
	// serves on bootstrap.CACertPath — the unauthenticated, deliberately public
	// endpoint a node with no credential reads to learn which cluster it is
	// talking to.
	//
	// The fetch does NOT verify the server's certificate chain against the
	// token's pin the way bootstrap.PinnedClient does, and that is the point:
	// a pinned client reports a wrong-cluster endpoint as a TLS handshake
	// failure, indistinguishable from a broken listener. Fetching the CA
	// unverified and comparing its hash HERE is what lets the installer say
	// "that address is a different cluster" instead of "handshake failed", and
	// it trusts nothing: the bytes are hashed and compared, never used as a
	// trust anchor, and the install is refused unless they match the pin the
	// operator's own token carries.
	FetchJoinCA(addr string, timeout time.Duration) ([]byte, error)
	// RemoveSymlink removes link ONLY when it is a symlink that still points at
	// target, and reports whether it did. Anything else — absent, a regular file,
	// a symlink someone re-pointed — is (false, nil): not ours, never touched.
	// That is what makes uninstall safe on a path outside k3sm's own trees; an
	// error means the check itself could not be made.
	RemoveSymlink(link, target string) (removed bool, err error)
	// VerifyVirtualizationEntitlement reports whether the Mach-O at path is signed
	// and its signature grants VirtualizationEntitlement. It is READ-ONLY — it is in
	// this seam not because it is privileged but because it is the one environment
	// fact install must observe about a file it is about to copy, and tests must be
	// able to state that fact without signing anything.
	//
	// The contract is deliberately three-valued, and FAIL-CLOSED on everything the
	// probe cannot affirm:
	//
	//	nil                                  signed, and the entitlement is present
	//	errors.Is(err, fs.ErrNotExist)       nothing at path — the caller falls through
	//	                                     to the copy, which owns that message
	//	any other error                      REFUSE: unsigned, signed-but-unentitled,
	//	                                     or the probe itself could not run
	//
	// The fs.ErrNotExist arm mirrors ReadFile's above: absence is a state a caller
	// interprets, never a failure this seam decides.
	VerifyVirtualizationEntitlement(path string) error
	// EnsureLogDir creates (or repairs) the daemons' log directory owned by the
	// service uid (group admin, LogDirMode) so launchd can open the
	// UserName=_k3sm server job's StandardOut/ErrorPath as _k3sm. launchd
	// auto-creates a missing log dir with root-only perms when the root netd job
	// spawns first — the _k3sm server job then fails "Service could not
	// initialize" and never spawns (an observed live-hardware failure this
	// fixes). It also pre-creates the daemon logs inside it at
	// LogFileMode, because a file launchd creates for itself takes the spawning
	// job's umask and has been landing world-readable. Idempotent: perms/owner
	// are re-applied to the directory AND to those files on every install,
	// repairing a previously mis-created or over-permissive tree.
	EnsureLogDir(dir string, uid uint32) error
	// WriteDataRootMarker writes dataroot.MarkerName into dir, root:wheel 0644,
	// naming dir itself (dataroot.WriteMarker). Install writes one into the data
	// root and one into the log dir on every install, and `k3sm uninstall
	// --purge` refuses to delete a tree that does not carry one. Idempotent.
	WriteDataRootMarker(dir string) error
	// EnsureContainerLogDir creates (or repairs) one directory of the container-log
	// tree — /var/log/pods and /var/log/containers — owned by the service uid,
	// group wheel, mode 0700 (ContainerLogDirMode / ContainerLogDirGID).
	//
	// Only root can hand a directory under /var/log to the service user, and only
	// the installer runs as root, which is why this is an install step and not
	// something the node does for itself at start-up. The node REFUSES to start
	// when the directory is missing or unwritable rather than creating it, because
	// a node-created directory would be owned by _k3sm with whatever umask was in
	// force, and the one thing this tree's mode has to be is deliberate.
	//
	// Owner and mode are re-applied on every install, so a tree an earlier build
	// (or a hand-run mkdir) left group-readable is repaired rather than left as it
	// was found.
	EnsureContainerLogDir(dir string, uid uint32) error
	// EnsureRunDir creates (or repairs) the runtime run directory owned by the
	// service uid (group staff, 0700) — the directory the _k3sm node binds its
	// runtimed control socket in (RunDir / provider.RuntimedSocketPath), and the
	// parent of the vm guest-agent socket dir.
	//
	// It must run BEFORE either daemon bootstraps. Whichever daemon starts first
	// creates a missing run dir, and that is root netd — which left it root:wheel,
	// so the unprivileged server could not create runtimed.sock there and its
	// control socket was disabled after a bounded retry. Only root can hand the
	// directory to the service user, and only the installer runs as root.
	//
	// Owner and mode are re-applied on every install, repairing a tree an earlier
	// build left root-owned instead of silently keeping the socket unbindable.
	//
	// What the ownership does NOT fence off, stated plainly: root netd still
	// creates netd.sock inside a directory the service user owns (root bypasses
	// the mode), so _k3sm — the control plane, which already drives netd over
	// that socket — can rename or replace it. That is a smaller trust surface
	// than it looks (netd takes its orders from _k3sm regardless). The mesh
	// keys are deliberately NOT in this directory: they live in MeshKeyDir,
	// directly under the root-owned data root.
	EnsureRunDir(dir string, uid uint32) error
	// EnsureVMRunDir creates (or repairs) the vm guest-agent socket directory
	// owned by the service uid (group staff, 0700). runtimed binds a per-pod
	// socket under it as _k3sm, but its parent is root-owned so the
	// unprivileged mkdir cannot succeed; only the root installer can carve it
	// out. Idempotent, and owner/mode are re-applied on every install so a
	// directory left root-owned by an earlier build is repaired rather than
	// silently keeping every vm pod unbootable. See VMRunDir.
	EnsureVMRunDir(dir string, uid uint32) error
	// EnsureMeshKeyDir creates (or repairs) the root-only mesh key directory at
	// mode, owned by root:wheel — MeshKeyDir, which netd's MeshKeyResolver reads
	// this node's wireguard private key out of in helper mode.
	//
	// It is the one level under the data root besides the root itself that is
	// NOT handed to the service user (OwnershipOf(StateKeys)), which is why it
	// has its own method rather than riding EnsureOwnedDir with a service uid:
	// the two answers must not be able to drift into one. Its parent is the
	// root-owned data root, so no unprivileged principal can rename or unlink
	// it, and re-applying owner and mode on every install repairs a directory
	// an earlier build — or the daemon's own best-effort runtime write — left
	// at looser terms.
	//
	// The mode is a PARAMETER for WriteServiceUserFile's reason: the policy a
	// caller applied is then visible at the seam, and a unit test can assert it
	// without a real filesystem or privilege.
	EnsureMeshKeyDir(dir string, mode fs.FileMode) error
	// EnsureOwnedDir creates (or repairs) one level of the state tree at exactly
	// uid:gid and mode, re-applying all three on an existing directory and
	// refusing a symlink at dir rather than chowning its target. It creates the
	// one level only: its parent is always a level ensured before it.
	//
	// It is the seam every row of the ownership table is applied through (see
	// OwnershipOf and ensureStateTree): the data root with root:wheel, each
	// service-user tree with the service uid. The owner, group and mode are
	// PARAMETERS so the row a caller applied is visible at the seam and a test
	// can assert that the root was never handed to the service user.
	EnsureOwnedDir(dir string, uid, gid int, mode fs.FileMode) error
	// RemoveEntry removes the entry name DIRECTLY inside dir — a file, or an
	// EMPTY directory — and nothing else. Absent (dir or entry) is success, so a
	// re-run is idempotent.
	//
	// It is descriptor-relative (dir opened O_NOFOLLOW|O_DIRECTORY, the entry
	// unlinked against that descriptor) because its one caller removes the
	// legacy mesh keys from inside the run dir, which the service user owns:
	// a by-path remove there could be redirected by a directory swapped for a
	// symlink between the check and the unlink, and root would then delete a
	// file of the service user's choosing.
	RemoveEntry(dir, name string) error
	// OpenDirNoFollow opens dir and HOLDS it: a directory whose final component
	// is a symlink is refused (an error that is not fs.ErrNotExist), and every
	// read and removal through the returned handle is descriptor-relative, so a
	// rename of the path afterwards cannot redirect them. A missing dir has
	// ReadFile's fs.ErrNotExist contract.
	//
	// Its one caller is the one-time key move, which reads the legacy keys out
	// of a directory inside the service user's run dir: a by-path read there is
	// a check-then-use race against the one account that can rename the path.
	OpenDirNoFollow(dir string) (DirHandle, error)
	// EnsureRootDir creates dir root-owned at mode (idempotent, re-applying the
	// mode on an existing directory). It is the seam the data-volume migration
	// carves its staging mount point with: unlike the Ensure*Dir methods above
	// it hands the directory to NOBODY — a staging mount point is root's for the
	// minutes the copy takes, and the volume's own ownership is applied at the
	// real mount point afterwards.
	EnsureRootDir(dir string, mode fs.FileMode) error
	// CopyTree copies the whole tree at src into dst preserving ownership,
	// modes, extended attributes and ACLs (ditto). It is the data-root
	// migration's copy: APFS cloning cannot cross a volume boundary, so this is
	// always a full byte copy, and every attribute it preserves is one the
	// migration's verification then compares.
	CopyTree(src, dst string) error
	// Rename moves old to new within one filesystem. The migration uses it for
	// the one irreversible-looking step that is in fact the safe one: the old
	// data root is RENAMED aside to <dir>.pre-volume, never deleted in place.
	Rename(old, new string) error
	// RemoveTree deletes path and everything under it. It is deliberately
	// separate from RemoveAll, which uninstall drives through its own
	// unsafe-path guard: this one is reached only by the data-volume paths (the
	// emptied staging mount point, and the .pre-volume copy under
	// --remove-old-data-root) and by the install root's staging tree (which
	// carries its own root-owned-real-directory check, stagingTrustVerdict), so
	// a future change to any caller's guarding cannot silently widen another's.
	RemoveTree(path string) error
	// LockInstall takes the exclusive, install-wide lock at path and returns the
	// release. A lock another install already holds is refused IMMEDIATELY with
	// an error matching ErrInstallInProgress — never waited on: an operator who
	// started a second `sudo k3sm install` wants to be told, not queued behind a
	// run they cannot see.
	//
	// It exists because nothing else in this package serialises two installs,
	// and two of them interleaving their copies into ONE staging tree is the
	// hazard the staging exists to remove, one level up: the swap would then
	// atomically publish a mixture of two builds, which is worse than the
	// half-written tree it replaced, because it looks complete.
	//
	// The lock is advisory (flock) and is held for the whole install, through
	// the reap. Its file lives BESIDE the install root, never inside it: a lock
	// on a file in the tree being swapped would travel with that tree.
	LockInstall(path string) (unlock func() error, err error)
	// SwapInstallRoot publishes the staged install tree by exchanging it with
	// whatever is at live, in ONE filesystem operation, and reports whether
	// there was a previous tree.
	//
	//	previous == true   live held a tree; it is now at staging, the staged
	//	                   tree is live, and calling this again with the same
	//	                   arguments puts both back
	//	previous == false  live was ABSENT — a first install — and the staged
	//	                   tree was renamed into place; there is nothing to reap
	//	                   and nothing to revert to
	//
	// Every other failure is returned with the live tree UNCHANGED, and the
	// caller must not attempt a reverse swap on one: a swap that did not happen
	// has nothing to undo, and a second attempt on a failing path is how a
	// half-published tree would actually get created. EXDEV is reported as
	// ErrInstallRootCrossDevice.
	//
	// What it guarantees, precisely: no observer ever sees a partially published
	// install root, because the exchange is one operation. Durability across a
	// power loss is an INFERENCE from APFS's transactional metadata design and
	// not a documented property of the swap — rename(2) states atomicity for the
	// plain form only — so nothing here or in its callers claims it as one.
	SwapInstallRoot(staging, live string) (previous bool, err error)
	// InstallSpace reports the bytes currently free on the filesystem holding
	// dir, and the total bytes the named sources occupy — a source that is
	// absent contributing zero, because the copy that needs it owns that
	// message, and a source that is a directory contributing its whole tree.
	//
	// Two stat families and no judgement: the verdict is freeSpaceVerdict's, so
	// the policy is testable without a filesystem and the seam cannot grow a
	// second opinion about what "enough room" means.
	InstallSpace(dir string, sources []string) (free, need uint64, err error)
	// WriteDataVolumeRecord writes the data-volume record at path, atomically
	// and root-owned 0644.
	//
	// It takes the RECORD, not bytes, because pkg/dataroot owns the record's
	// encoding, its version stamp and its temp-and-rename — a seam that took
	// bytes would need a second encoder here, and two encoders of one
	// declaration is the drift this whole feature exists to end. The seam
	// exists at all so a unit test can observe the write and so nothing writes
	// the record before its volume is proven mounted.
	WriteDataVolumeRecord(path string, rec dataroot.Record) error
	// WriteServerArgsRecord writes the server-arguments record at path,
	// atomically and root-owned 0600 — the operator's own `k3sm server` flags,
	// kept in root-owned /Library/Preferences so they survive the uninstall that
	// removes the plist they were read from, and so the unprivileged service user
	// cannot rewrite what the next root-run install puts on the daemon's argv.
	//
	// It takes the RECORD for the same reason WriteDataVolumeRecord does:
	// pkg/dataroot owns the encoding, the version stamp and the
	// temp-and-rename. The seam exists so a unit test can observe the write —
	// and so the write happens at ONE point in the install, after the carried
	// arguments have been decided.
	WriteServerArgsRecord(path string, rec dataroot.ServerArgsRecord) error
	// WriteAgentArgsRecord writes the agent-arguments record at path, atomically
	// and root-owned 0600 — the same contract WriteServerArgsRecord has, for the
	// sibling record a RoleAgent install carries its operator-supplied `k3sm
	// agent` flags in. The two records are separate files and never cross roles.
	WriteAgentArgsRecord(path string, rec dataroot.AgentArgsRecord) error
	// WriteServiceUserFile writes contents at path owned by the service uid at
	// mode, creating path's parent directory owned by the same uid at dirMode.
	// It is how the root installer hands a file to the unprivileged user a
	// daemon runs as — today the staged join token, whose whole problem is that
	// the operator's own copy is root-only (see AgentTokenFileMode).
	//
	// The mode and the directory mode are PARAMETERS rather than constants read
	// inside the implementation, so the policy a caller applied is visible at
	// the seam and a test can assert it without touching a real filesystem.
	WriteServiceUserFile(path string, contents []byte, uid uint32, mode, dirMode fs.FileMode) error
	// WriteRootOnlyFile writes contents at path root:wheel at mode, atomically,
	// without creating or re-owning path's parent (the caller ensures that
	// directory through its own seam, so one write cannot silently loosen a
	// directory another step decided).
	//
	// It is WriteServiceUserFile's opposite number and exists for exactly one
	// file today: the root-only copy of this node's wireguard private key in
	// MeshKeyDir. The service-user seam cannot be reused for it, because handing
	// that copy to _k3sm would erase the only difference between the two copies —
	// see MeshKeyDirMode.
	//
	// The mode is a PARAMETER, as on every other write seam here, so the policy
	// is visible at the call site and assertable without privilege.
	WriteRootOnlyFile(path string, contents []byte, mode fs.FileMode) error
	// Owner reports who owns the entry at path, what it permits, and what kind
	// of entry it is — an lstat, so a symlink is described rather than followed.
	// A missing entry has ReadFile's contract (an error satisfying
	// errors.Is(err, fs.ErrNotExist)): absence is a posture the caller reads,
	// never a failure this seam decides.
	//
	// FileMode above answers only "what does this file permit"; ownership is a
	// separate question and the legacy-file adoption cannot be asked in terms of
	// the mode alone, because root:wheel 0600 and _k3sm:staff 0600 are the same
	// mode and opposite outcomes for the daemon that has to read the file.
	Owner(path string) (OwnedEntry, error)
	// ListOwned lists the entries DIRECTLY inside dir, each described exactly as
	// Owner describes it, and never descends into a subdirectory. A missing dir
	// has Owner's missing-entry contract.
	//
	// The shallow contract is the point, not a simplification: its one caller
	// judges the agent work dir, which holds a fixed handful of credential
	// files, and a seam that walked would invite the same judgement to be
	// applied to trees (the pod-log tree) where it does not belong.
	ListOwned(dir string) ([]OwnedEntry, error)
	// AdoptTree hands every root-owned entry of a container-log tree to uid:gid,
	// walking DESCRIPTOR-RELATIVE from root, to the depth maxDepth allows and
	// under the top-level rule policy states. It reports what it adopted and
	// every entry it stepped over; a missing root has Owner's missing-entry
	// contract (an error satisfying errors.Is(err, fs.ErrNotExist)).
	//
	// It is a seam method rather than a loop in this package over ListOwned and
	// Chown because of WHO is running while an install runs. Native pods are
	// ordinary Darwin processes owned by the service user and they survive the
	// daemon stop by design, so /var/log/pods has a live, unprivileged writer
	// throughout. A walk that classified an entry by lstat and then acted on the
	// PATH — re-listing it, chowning it — gives that writer the window between
	// the two calls to replace the entry with a symlink and aim the rest of a
	// root-run walk at a tree of its choosing. Nothing in this package can close
	// that window, because a path string is re-resolved by the kernel on every
	// syscall that takes one.
	//
	// So the contract is stated in terms the kernel can keep: the root is opened
	// O_NOFOLLOW|O_DIRECTORY, every child is classified with fstatat(...,
	// AT_SYMLINK_NOFOLLOW) against the parent's DESCRIPTOR, adopted with
	// fchownat(..., AT_SYMLINK_NOFOLLOW) against that same descriptor, and
	// descended into only by openat(..., O_NOFOLLOW|O_DIRECTORY) — so the object
	// acted on is the object that was classified, and a symlink anywhere in the
	// tree is stepped over rather than followed. It NEVER deletes: the pod-log GC
	// is that tree's only deleter.
	//
	// The mode is left exactly as found, for Chown's reason, and a parent is
	// handed over before its children so nothing is left inside a directory the
	// service user cannot yet traverse.
	AdoptTree(root string, uid, gid, maxDepth int, policy AdoptPolicy) (TreeAdoption, error)
	// Chown sets the owner of path to uid:gid and changes NOTHING else. The mode
	// is deliberately left exactly as it was found — the files this is used on
	// are already 0600 and re-deciding their mode here would be a second,
	// unreviewed policy sitting next to the one WriteServiceUserFile applies.
	// It does not follow a symlink, for the reason Owner does not.
	Chown(path string, uid, gid int) error
	// WriteLaunchDaemon writes a launchd plist root:wheel at plistPath, at mode.
	//
	// The mode is a PARAMETER rather than a constant inside the implementation
	// because it is not one policy: the server plist is 0600 (see plistMode) and
	// every other plist is PlistMode. Passing it makes the decision visible at
	// the one call site that takes it, and lets a test assert the mode a given
	// daemon was laid down at without a real filesystem.
	WriteLaunchDaemon(plistPath string, contents []byte, mode fs.FileMode) error
	// ReadRegularFile reads a root-readable file, refusing to follow a symlink and
	// refusing anything that is not a REGULAR file (an error matching
	// ErrNotRegularFile); a missing file keeps ReadFile's fs.ErrNotExist contract.
	//
	// It exists because of one file whose directory the installer does not own.
	// The mesh key's work-dir copy lives in a service-user-owned work dir,
	// and install reads it AS ROOT and copies its bytes into a root-only
	// directory. With an ordinary read, the service uid could replace that file
	// with a symlink to anything on the Mac and have root copy the target out for
	// it — a confused-deputy read that hands the attacker's own uid nothing, but
	// hands root's reach to whatever it points at. The refusal, not the mode, is
	// what closes that: the file is opened O_NOFOLLOW and its type checked on the
	// open descriptor, so there is no window between the check and the read.
	ReadRegularFile(path string) ([]byte, error)
	// ReadRegularFileWithMode is ReadRegularFile plus the permission bits, both
	// read off the SAME open descriptor as the content — unlike a separate
	// FileMode-then-ReadFile (or FileMode-then-ReadRegularFile) pair, there is
	// no window in which the mode judged and the bytes read could belong to two
	// different files. It exists for operatorJoinToken, the one reader in this
	// package that has to judge a credential's mode before trusting its
	// content, the same way ReadRegularFile already judges the mesh key's TYPE
	// before trusting it.
	ReadRegularFileWithMode(path string) ([]byte, fs.FileMode, error)
	// ReadFile reads a root-readable file: the installed server plist, whose
	// operator-supplied arguments a reinstall must carry over; the
	// server-arguments record that carries those same arguments when no plist
	// survives; and the cluster CA the admin kubeconfig pins. A missing file
	// returns an error satisfying errors.Is(err, fs.ErrNotExist), which callers
	// treat as a POSTURE rather than a failure — an absent plist sends the
	// carry-over to the record, an absent record means there is nothing to carry,
	// and a FIRST install has none of the three.
	ReadFile(path string) ([]byte, error)
	// MaxFilesPerProc returns the kernel's per-process open-file ceiling
	// (sysctl kern.maxfilesperproc). It is READ-ONLY and advisory: the kernel
	// allocates a process at most this many descriptors whatever its plist's
	// NumberOfFiles, and install reads it only to tell the operator when the
	// ceiling sits below the requested limit (see warnKernelFDCap).
	// An error is never a reason to refuse an install.
	MaxFilesPerProc() (uint64, error)
	// LaunchctlBootstrap loads the labelled daemon into the system domain.
	LaunchctlBootstrap(label string) error
	// LaunchctlBootout unloads the labelled daemon (idempotent: a not-loaded
	// label is a no-op success).
	LaunchctlBootout(label string) error
	// LaunchctlEnable clears the labelled daemon's disabled bit in the system
	// domain (launchctl enable system/<label>). It is idempotent: enabling a
	// label that is already enabled, or that launchd has never seen, succeeds.
	// A disabled label refuses bootstrap with the same EIO launchd returns
	// while a label drains, so install enables before it bootstraps rather
	// than trying to tell the two apart from the output text.
	LaunchctlEnable(label string) error
	// LaunchctlKickstart (re)starts the labelled daemon (launchctl kickstart -k).
	// It returns as soon as the restart is requested — not when the old instance
	// is gone — so a caller that must observe the new instance pairs it with
	// LaunchctlServicePID.
	LaunchctlKickstart(label string) error
	// LaunchctlServicePID returns the pid launchd currently reports for the
	// labelled job, or 0 when the job is loaded but not running (the respawn
	// window, or a job that has exited and not yet been relaunched). A label that
	// is not loaded at all is an error. It is read-only.
	LaunchctlServicePID(label string) (int, error)
	// PathExists reports whether path exists, WITHOUT reading it. Install's
	// post-restart verification uses it on the netd unix socket, which no
	// ReadFile can answer for: opening a socket with the file API fails on
	// darwin regardless of whether the helper is listening, so "readable" and
	// "present" are different questions and only the second one is meaningful
	// here. A false verdict is not an error; an error means the check itself
	// could not be made (a permission or IO failure on the parent tree).
	PathExists(path string) (bool, error)
	// ProbeNetd reports whether the netd helper at path is SERVING: it connects,
	// sends one framed request, and requires the daemon to act on it inside a
	// bounded timeout. It is the question PathExists cannot answer — a listening
	// socket is created on the filesystem before its server accepts, so the node
	// daemon can find the file there and still be refused when it dials (the
	// 2026-09-17 install, where the agent started 24ms after netd and died on
	// "k3sm-netd helper unreachable").
	//
	// A CONNECT IS NOT AN ANSWER EITHER, which is why this is a round trip rather
	// than a dial. connect(2) on a unix socket completes as soon as the listen
	// backlog has room, with no involvement from the process that bound it: a netd
	// that is listening but wedged — stuck in its own start-up, deadlocked, paused —
	// accepts every connection the kernel queues and answers none of them. Only a
	// reply proves the accept loop and the handler behind it are running.
	//
	// The bar is "the daemon ANSWERED", not "the daemon said yes": a rejection is a
	// perfectly good answer, and the installer is not netd's client. An empty reply
	// (the peer closed the connection after its own checks) counts for the same
	// reason.
	//
	// A refusal, a wedged peer, or a path that is not a socket is an ERROR, never a
	// verdict this seam interprets: the caller decides whether to keep waiting.
	ProbeNetd(path string) error
	// WriteUserKubeconfig writes the admin kubeconfig into targetUser's
	// ~/.kube/config, owned by targetUser (not root).
	WriteUserKubeconfig(targetUser string, contents []byte) error
	// RemoveAll removes a path tree (the install dir on uninstall).
	RemoveAll(path string) error
	// ReapOrphans SIGKILLs any lingering process whose executable path is under
	// binPrefix (the control-plane children the server spawns at <DataRoot>/
	// server/bin) — the uninstall backstop for children that outlived the daemon
	// (a Stop() that didn't finish before launchd's SIGKILL, or a server crash;
	// each child is in its own process group so launchd's job-kill misses it).
	// A no-op when nothing matches.
	ReapOrphans(binPrefix string) error
	// FlushLo0Aliases removes every lo0 inet alias that falls inside one of the
	// given prefixes — the uninstall backstop for the k3sm-owned durable kernel
	// state NO daemon flushes on the way out: pod /32s a mid-run failure leaked,
	// the Service VIP aliases (the API + DNS VIPs), and the node's own
	// mesh-egress .1 (which the pod-range stale sweep deliberately never touches).
	// It inspects the live interface (ifconfig) rather than walking ranges, so it
	// removes exactly what exists. A no-op when nothing matches.
	FlushLo0Aliases(prefixes []netip.Prefix) error
	// FlushMeshPFAnchor is the uninstall backstop for the pf anchor (darwin-net's
	// mesh.PFAnchor, "io.k3sm.mesh") that an older release loaded the mesh MSS
	// clamp into. Nothing loads it now (k3sm loads no pf rule), but a rule an
	// older release left behind outlives netd, scoped to a utun that no longer
	// exists. Best-effort like FlushLo0Aliases: an anchor that was never loaded
	// is a no-op (pfctl succeeds flushing zero rules), and a pfctl failure is
	// reported but never stops the rest of uninstall.
	FlushMeshPFAnchor() error
	// ReadPodReapRecords returns the pod process groups the runtime recorded in
	// its reap store under dataRoot (runtime.ReadPodReapRecords). An absent store
	// holds none.
	ReadPodReapRecords(dataRoot string) ([]runtimed.PodReapRecord, error)
	// ProcessGroupLeaderStart reports the kernel start time (unix nanoseconds)
	// of process group pgid's leader, the member whose pid is pgid. alive is
	// false when no such member exists: the group is empty, or only a
	// grandchild of the leader keeps it alive.
	ProcessGroupLeaderStart(pgid int) (startUnixNano int64, alive bool)
	// ProcessGroupMemberStart reports the kernel start time (unix nanoseconds)
	// of process pid, read as a member of process group pgid. alive is false
	// when pid is not a live member of that group: it exited, or it now
	// belongs to another group.
	ProcessGroupMemberStart(pgid, pid int) (startUnixNano int64, alive bool)
	// SignalProcessGroup sends sig to every member of process group pgid. A
	// group that no longer exists is a no-op success.
	SignalProcessGroup(pgid int, sig syscall.Signal) error
	// WaitProcessGroupsGone waits up to timeout for every group in pgids to
	// have no members, and returns the groups that still have one.
	WaitProcessGroupsGone(ctx context.Context, pgids []int, timeout time.Duration) []int

	// The methods below serve `k3sm uninstall --purge` only.

	// ResolvePath returns path with every symlink resolved (EvalSymlinks).
	ResolvePath(path string) (string, error)
	// StatNoFollow lstats path. A missing path has ReadFile's fs.ErrNotExist
	// contract.
	StatNoFollow(path string) (PathStat, error)
	// ReadDataRootMarker reports what dir's dataroot.MarkerName file is, read
	// off one O_NOFOLLOW descriptor (dataroot.ReadMarker). Missing has
	// ReadFile's fs.ErrNotExist contract.
	ReadDataRootMarker(dir string) (dataroot.MarkerFacts, error)
	// PurgeTree deletes the tree at root, which must still be the directory
	// (dev, ino) the purge guard approved. It walks descriptor-relative and
	// never follows a symlink (a symlink is unlinked, its target untouched),
	// never enters a directory on another device (that is reported as an
	// error, and the walk goes on), clears file flags and retries once on
	// EPERM, collects every failure rather than stopping at the first, and
	// unlinks root's marker and then root itself only when everything else is
	// gone. It never uses os.RemoveAll.
	//
	// A root that is no longer the (dev, ino) handed in is refused with an
	// error wrapping ErrPurgeTreeChanged and nothing removed.
	PurgeTree(root string, dev, ino uint64) error
	// DirIsEmpty reports whether dir (not followed if it is a symlink) holds no
	// entries at all.
	DirIsEmpty(dir string) (bool, error)
	// LoadedLabels lists the launchd jobs loaded in the system domain whose
	// label starts with prefix. The subprocess is bounded by ctx.
	LoadedLabels(ctx context.Context, prefix string) ([]string, error)
	// ProcessesOfUID lists the pids whose real or effective uid is uid,
	// leaving out zombies (exited, awaiting their parent's wait): they hold
	// nothing open and no signal reaches them.
	ProcessesOfUID(uid uint32) ([]int, error)
	// KillProcess sends SIGKILL to pid. A process that is already gone is
	// success.
	KillProcess(pid int) error
	// BootoutUserDomain boots out uid's per-user launchd domain (launchctl
	// bootout user/<uid>), stopping every agent launchd runs there and keeps
	// respawning. A domain that is already gone is success. The subprocess is
	// bounded by ctx.
	BootoutUserDomain(ctx context.Context, uid uint32) error
	// ServiceUser reads the named user's directory-service record. A user that
	// does not exist is Exists=false with a nil error. Subprocesses are bounded
	// by ctx.
	ServiceUser(ctx context.Context, name string) (ServiceUserRecord, error)
	// DeleteServiceUser deletes the named user's record (dscl . -delete
	// /Users/<name>). It deletes no group. The subprocess is bounded by ctx
	// alone; a kill at ctx's deadline returns an error wrapping ctx.Err(). A
	// deletion macOS refused (eDSPermissionError: deleting a user record needs
	// an approval at the screen, which an unattended process cannot get)
	// returns an error wrapping errServiceUserDeleteDenied.
	DeleteServiceUser(ctx context.Context, name string) error
	// DisableServiceUser leaves the named account, which the purge could not
	// delete, with no login shell, hidden, and a RealName that says to delete
	// it by hand (serviceUserDisabledRealName). It changes attributes only,
	// none of which needs the approval a deletion does.
	DisableServiceUser(ctx context.Context, name string) error
	// RemoveAdminKubeconfigContext removes the k3sm context (and the cluster
	// and user it alone references) from targetUser's ~/.kube/config, keeping
	// every other entry, the file's owner and its mode. An absent file or
	// context is a no-op success, reported as removed=false.
	RemoveAdminKubeconfigContext(targetUser string) (removed bool, err error)
}

// Config parametrizes Install/Uninstall. Empty fields take the Default* values.
type Config struct {
	// Role is which node this Mac becomes: the control plane (RoleServer, the
	// zero value) or a worker joining an existing cluster (RoleAgent). It
	// selects which node daemon the manifest carries and which arguments record
	// is written; everything else install lays down is identical, because a
	// worker runs the same binary, the same shims and the same netd helper.
	Role Role
	// JoinServer is the host this node joins, an UNDERLAY address, because the
	// join dials <host>:9345 before this node has any mesh to route over. On
	// RoleAgent it is the control-plane host and is required. On RoleServer it
	// is an existing server's LAN address and is used only with ServerJoin.
	JoinServer string
	// NodeIP is role-dependent. On RoleAgent it is an OPTIONAL assertion of the
	// joining worker's own mesh InternalIP: the control plane assigns that
	// address and issues the node's certificates for it, so a worker needs none;
	// when set it is rendered onto the daemon's argv and the join refuses a value
	// that differs from the assignment. On RoleServer it is the LAN address the
	// embedded etcd member's peer listener binds, required with ClusterInit or
	// ServerJoin and used only with them.
	NodeIP string
	// ClusterInit asks this server to form a new embedded etcd HA control
	// plane (`k3sm server --cluster-init`). RoleServer only; needs NodeIP.
	ClusterInit bool
	// ServerJoin asks this server to join an existing embedded etcd HA control
	// plane through JoinServer (`k3sm server --server-join`). RoleServer only;
	// needs JoinServer, NodeIP and TokenFile holding a server-class token.
	ServerJoin bool
	// TokenFile is the OPERATOR's join-token file, read once by Install (which
	// is root) and copied to stagedJoinTokenPath() for the daemon: the agent's
	// K10 join token, or with ServerJoin the server-class token. It is not what
	// the daemon reads and is never named on its argv: the operator's file is
	// root-only by construction, and the service user the daemon runs as could
	// not open it.
	//
	// It is optional on an agent. A node that has already joined starts from its
	// stored credential and needs no token at all, so a reinstall with no
	// --token-file stages nothing and leaves whatever is already there. A
	// ServerJoin install requires it.
	TokenFile       string
	ServiceUser     string // _k3sm
	InstallDir      string // /Library/k3sm
	LinkDir         string // /usr/local/bin
	LaunchDaemonDir string // /Library/LaunchDaemons
	DataRoot        string // /var/lib/k3sm
	NetdSocket      string // /var/lib/k3sm/run/netd.sock
	ServiceCIDR     string // 10.43.0.0/16
	APIServerPort   int    // 6444
	// BinarySource is the k3sm binary to install (typically the running
	// executable). Required.
	BinarySource string
	// ExecShimSource is the k3sm-execshim helper binary to install NEXT TO the
	// k3sm binary. The server plist hardcodes --runtime runtimed, whose Seatbelt
	// backend resolves the shim beside the running executable
	// (sandbox.FindExecShim) — without it the server dies at boot in a KeepAlive
	// crash-loop. Defaults to the k3sm-execshim sibling of BinarySource.
	ExecShimSource string
	// PayloadSource is a directory holding the control-plane payload
	// (executor.PayloadBinaries: kube-apiserver/scheduler/controller-manager/
	// kubectl + kine + etcd) staged by `k3sm payload <dir>`. Install copies it to
	// InstallDir/bin, from which the daemon boot seeds its workdir — the launchd
	// _k3sm daemon has neither gh nor a Go toolchain to acquire them itself.
	// Defaults to the cp-payload sibling dir of BinarySource.
	PayloadSource string
	// PathShimSource is the path-rebase DYLD shim dylib (PathShimName) to install
	// beside the binary, from which runtimed resolves it (next to the executable)
	// and injects it into a mounting pod for absolute-mount-path rebasing. Defaults
	// to the PathShimName sibling of BinarySource.
	PathShimSource string
	// DNSShimSource is the getaddrinfo DNS shim dylib (DNSShimName) to install beside
	// the binary, from which the provider resolves it and injects it into each pod so
	// in-pod cluster DNS reaches the per-node resolver. Defaults to the DNSShimName
	// sibling of BinarySource.
	DNSShimSource string
	// VMHostSource is the k3sm-vmhost VM-host helper binary to install beside the
	// binary, from which sandbox.FindVMHost resolves it for vm-RuntimeClass pods.
	// The helper carries its own ad-hoc signature and the
	// com.apple.security.virtualization entitlement — install copies it verbatim
	// (see CopyToRootOwned) and never re-signs it: a release helper is
	// Developer-ID signed, and re-signing would destroy that.
	//
	// Because the copy can only propagate whatever the build produced, install
	// FAILS CLOSED on a helper that does not already carry the entitlement
	// (VerifyVirtualizationEntitlement, run in Install's preflight block before
	// anything is written — see there for why it moved off "immediately before
	// the copy"). Without that gate a dev helper built with a plain `go build`
	// installs unentitled and the consequence surfaces nowhere near the cause:
	// runtimed withholds VMBackendAvailable, the server deletes the node's
	// k3sm.io/virtualization label, and every vm-RuntimeClass pod stays Pending
	// behind the RuntimeClass's own node selector — reported only as "didn't
	// match node affinity/selector".
	//
	// Defaults to the VMHostName sibling of BinarySource.
	VMHostSource string
	// TargetUser is the human (SUDO_USER) the admin kubeconfig is written for and
	// owned by. Required for the kubeconfig step; empty skips it with an error.
	TargetUser string
	// AdminToken is the static bearer token shared between the server LaunchDaemon
	// and the admin kubeconfig. Generated when empty.
	//
	// The daemon is given it as a FILE: Install stages the value at
	// serverTokenPath() and the plist carries --token-file, so the token itself
	// is on no argv. The admin kubeconfig still carries the value, by design —
	// it is a 0600 file in the human's own home and the credential is what
	// `kubectl` presents.
	AdminToken string
	// ExtraServerArgs are operator-supplied `k3sm server` arguments appended to
	// the fixed set ServerPlist renders (--mesh-ip, --registry-port, …).
	//
	// Install populates it from TWO sources, in precedence order: the arguments
	// of the server plist ALREADY ON DISK, and — when there is no plist, which is
	// every install that follows an uninstall — the server-arguments record at
	// ServerArgsRecord. So a reinstall preserves what an operator configured
	// instead of re-rendering the bare template over it, and so does an
	// uninstall-then-install; only a genuine first install, which has neither
	// source, leaves it empty. AdminKubeconfig reads --mesh-ip out of it to
	// address the apiserver where it actually binds.
	ExtraServerArgs []string
	// MeshIP is this node's wireguard mesh address, from `k3sm install --mesh-ip`
	// — the CLI's own request, distinct from ExtraServerArgs (which is what a
	// PRIOR install left behind). When set, it REPLACES whatever --mesh-ip the
	// carried ExtraServerArgs holds rather than sitting beside it as a second,
	// shadowed flag: an operator repointing which mesh address this node's
	// server binds wins over history. Empty leaves a carried --mesh-ip (if any)
	// untouched. See resolvedExtraServerArgs, the one place the two are merged;
	// meshIP(), ServerPlist and writeServerArgsRecord all read the merge through
	// it, so the address that decides bind/kubeconfig posture, the address
	// actually rendered into the daemon's argv, and the address persisted to
	// ServerArgsRecord can never disagree. The CLI parses and refuses the
	// unspecified, loopback and multicast forms before Install ever sees it.
	MeshIP string
	// ExtraAgentArgs are operator-supplied `k3sm agent` arguments appended to the
	// fixed set AgentPlist renders (--mesh-port, --dns-vip, …). Install
	// populates it exactly as it populates ExtraServerArgs: from the agent plist
	// already on disk, and — when there is none, which is every install that
	// follows an uninstall — from the agent-arguments record.
	ExtraAgentArgs []string
	// AgentArgsRecord is where those arguments are recorded so they survive the
	// uninstall that removes the plist they were read from. Empty takes
	// dataroot.DefaultAgentArgsRecordPath. It is a SEPARATE file from
	// ServerArgsRecord and is read only by a RoleAgent install, so the two
	// records can never cross roles.
	AgentArgsRecord string
	// ServerArgsRecord is where the operator's own server arguments are recorded
	// so they survive the uninstall that removes the plist they were read from.
	// Empty takes dataroot.DefaultServerArgsRecordPath — root-owned
	// /Library/Preferences, deliberately NOT under the data root, whose trees
	// the service user owns; see that constant for the privilege reason. A test
	// points it at a scratch file.
	ServerArgsRecord string
	// ClusterCA is the cluster CA certificate PEM the admin kubeconfig pins as
	// certificate-authority-data on a MESH install — the posture in which the
	// apiserver presents a cluster-CA-signed leaf (--tls-cert-file). Install reads
	// it off disk at step 2e; empty degrades that kubeconfig to
	// insecure-skip-tls-verify, which a first install does before the control plane
	// has minted anything. The single-node loopback endpoint has its own anchor —
	// see LoopbackCA.
	ClusterCA []byte
	// LoopbackCA is the trust anchor the admin kubeconfig pins for the SINGLE-NODE
	// loopback endpoint: the certificate kube-apiserver self-signs into its own
	// --cert-dir (executor.APIServerCertDir), leaf followed by the self-signed CA
	// that issued it. That file is the ONLY anchor for what the loopback listener
	// presents, and pinning it is what stops an unprivileged local process that
	// grabs the apiserver port during an outage from collecting the admin bearer
	// token. Install reads it off disk at step 2e, and leaves it empty — keeping
	// the skip-verify fallback — when the file is absent or its leaf does not name
	// the loopback address.
	LoopbackCA []byte
	// DataVolume asks install to create, adopt or migrate onto a dedicated APFS
	// volume for the data root. Nil is the default posture: the data root is a
	// plain directory (or a volume an operator declared in /etc/fstab by hand),
	// and install touches no disk.
	DataVolume *datavol.Options
	// DataVolumeDeps are the diskutil / keychain / indexing seams the
	// data-volume work runs through. An incomplete value is filled with
	// datavol.NewDarwin() by withDefaults, so production callers say nothing and
	// tests inject datavoltest.Fake.Deps().
	DataVolumeDeps datavol.Deps
	// RemoveOldDataRoot deletes the .pre-volume copy a migration leaves beside
	// the data root, once the copy has been verified. It is REQUIRED for an
	// encrypted volume (an encrypted volume beside a plaintext duplicate of the
	// same secrets is not encryption) and optional otherwise.
	RemoveOldDataRoot bool
	// SecretsEncryption is `k3sm install --secrets-encryption`: enable secrets
	// encryption at rest on a NEW single-server control plane. The install mints
	// a key and writes the credential pair under <DataRoot>/server/cred before
	// the first start; it refuses on a worker, beside a carried --cluster-init or
	// --server-join, and over an existing datastore. False never touches
	// the credential directory. See preflightSecretsEncryption.
	SecretsEncryption bool
	// KeyEntropy is where a minted secrets-encryption key is read from. Nil is
	// crypto/rand.Reader; a test injects a placeholder reader so no real key
	// material is ever produced.
	KeyEntropy io.Reader
	// Deregister removes this node from the cluster it joined, and is called by
	// Uninstall on a WORKER teardown only. Nil — the zero value — skips it, and
	// is what every server-role uninstall and every caller that has no stored
	// node credential to authenticate with passes.
	//
	// It is a closure rather than a set of fields because everything the call
	// needs is a cmd-layer concern this package must not acquire: the stored
	// node credential, the node-identity HTTP client built from it, and the
	// bootstrap URL of the control plane. What install owns is WHEN the call
	// happens (before the daemons are booted out, while the credential and the
	// mesh are still intact) and that it can never block the teardown.
	//
	// It is BEST EFFORT by contract. A control plane that is off, asleep, or on
	// another network is the ordinary case for a Mac being retired, so a failure
	// is logged once with the manual remedy and the local teardown continues.
	// The error the closure returns is what names the node, so it is logged
	// verbatim beside the remedy.
	//
	// The stored node credential under <DataRoot>/agent is PRESERVED either way
	// — the documented reinstall invariant, which deregistering does not change.
	// The consequence is worth stating: a same-Mac reinstall after a successful
	// deregistration resumes with a credential the cluster no longer has a
	// MeshPeer for. `k3sm agent` already handles exactly that case, because it
	// is the same one a node hits when its peer is deleted by hand — with a
	// token it falls back to a full token join, and without one it stops with a
	// terminal error naming the remedy (mint a token on the server and start the
	// agent with it).
	Deregister func(ctx context.Context) error
	// DeregisterServer removes this server's own etcd member from the embedded-etcd
	// cluster it belongs to, and is called by Uninstall on a SERVER teardown whose
	// installed plist carries --cluster-init or --server-join, and on no other. Nil
	// skips it.
	//
	// It runs at the same point as Deregister — after any purge preflight, before
	// a single daemon is booted out — because the call needs the local etcd member
	// still running: a member removes itself through its own loopback client, which
	// needs only the cluster's quorum, the same condition any membership change
	// needs. The uninstalling host holds no server-class token, so it does not ask
	// a peer.
	//
	// BEST EFFORT, like Deregister: a failure (no quorum, the member already gone)
	// is one warning with the remedy for the servers that stay, and the teardown
	// continues. A purge the preflight refuses makes no call.
	DeregisterServer func(ctx context.Context) error
	// Purge makes Uninstall also remove everything it otherwise keeps: the data
	// root (and the data volume under it), the daemon log dir, the arguments
	// records, the k3sm context in TargetUser's kubeconfig and the service user.
	// See purge for the order and the guards.
	Purge bool
	// PurgeConfirmed is the operator's --yes. A Purge without it is refused
	// before any system call.
	PurgeConfirmed bool
	// TargetHome is the invoking human's home directory. A purge refuses to
	// delete any tree that equals, contains or lies inside it. Empty skips that
	// one rule; the /Users and /Volumes rules still hold.
	TargetHome string
	// DataRootFS is the read-only filesystem the data-root posture is read
	// through (the record, /etc/fstab, the mount state). It defaults to the real
	// filesystem; a test injects a fake so the sequencing can be exercised
	// against a mount posture no unprivileged process could create.
	DataRootFS dataroot.FS
	Logger     *slog.Logger
	// Out receives a command's result lines: what a purge removed, and what it
	// could not and how to finish by hand. The CLI hands it stdout; Logger
	// (stderr) carries the progress and diagnostics. Nil discards.
	Out io.Writer
	// dataVolumeDeclared reports that this Mac has a data volume to manage --
	// either a record already declares one, or --data-volume asked for one. It
	// is what puts the io.k3sm.datavol daemon and the record into the artifact
	// manifest, and Install and Uninstall each set it from the record before
	// they build that manifest.
	dataVolumeDeclared bool
}

func (c Config) withDefaults() Config {
	if c.ServiceUser == "" {
		c.ServiceUser = DefaultServiceUser
	}
	if c.InstallDir == "" {
		c.InstallDir = DefaultInstallDir
	}
	if c.LinkDir == "" {
		c.LinkDir = DefaultLinkDir
	}
	if c.LaunchDaemonDir == "" {
		c.LaunchDaemonDir = DefaultLaunchDaemonDir
	}
	if c.DataRoot == "" {
		c.DataRoot = DefaultDataRoot
	}
	if c.NetdSocket == "" {
		c.NetdSocket = DefaultNetdSocket
	}
	if c.ServiceCIDR == "" {
		c.ServiceCIDR = DefaultServiceCIDR
	}
	if c.APIServerPort == 0 {
		c.APIServerPort = DefaultAPIServerPort
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	if c.Out == nil {
		c.Out = io.Discard
	}
	if c.DataRootFS == nil {
		c.DataRootFS = dataroot.OSFS{}
	}
	if c.ServerArgsRecord == "" {
		c.ServerArgsRecord = dataroot.DefaultServerArgsRecordPath
	}
	if c.AgentArgsRecord == "" {
		c.AgentArgsRecord = dataroot.DefaultAgentArgsRecordPath
	}
	if c.Role == "" {
		c.Role = RoleServer
	}
	// All three seams or none: datavol refuses a partially filled Deps rather
	// than calling through a nil interface, so a caller that supplied two of
	// them would fail at the first operation instead of here.
	if c.DataVolumeDeps.Volumes == nil || c.DataVolumeDeps.Keychain == nil || c.DataVolumeDeps.Indexing == nil {
		c.DataVolumeDeps = datavol.NewDarwin()
	}
	if c.ExecShimSource == "" && c.BinarySource != "" {
		c.ExecShimSource = filepath.Join(filepath.Dir(c.BinarySource), ExecShimName)
	}
	if c.PayloadSource == "" && c.BinarySource != "" {
		c.PayloadSource = filepath.Join(filepath.Dir(c.BinarySource), PayloadDirName)
	}
	if c.PathShimSource == "" && c.BinarySource != "" {
		c.PathShimSource = filepath.Join(filepath.Dir(c.BinarySource), PathShimName)
	}
	if c.DNSShimSource == "" && c.BinarySource != "" {
		c.DNSShimSource = filepath.Join(filepath.Dir(c.BinarySource), DNSShimName)
	}
	if c.VMHostSource == "" && c.BinarySource != "" {
		c.VMHostSource = filepath.Join(filepath.Dir(c.BinarySource), VMHostName)
	}
	return c
}

// runDir is the runtime run directory for this Config's data root — the one the
// installer prepares for the service user (see RunDir).
func (c Config) runDir() string { return RunDir(c.DataRoot) }

// serverWorkDir is the control-plane state root the _k3sm server resolves under
// its home (executor.ResolveWorkDir's unprivileged branch: <home>/server, and the
// _k3sm home IS DataRoot). The installer needs it to read the PKI the running
// control plane wrote there; it is a Config accessor so the leaf name is not
// re-typed at each use.
func (c Config) serverWorkDir() string { return filepath.Join(c.DataRoot, "server") }

// agentWorkDir is the joining worker's state root under the data root — the
// directory `k3sm agent --work-dir` defaults to, holding the node credential,
// the node-password, the mesh key and the agent's crash-loop record.
//
// It is serverWorkDir's sibling and exists for the same reason: the installer
// reads what the daemon wrote there (the credential a join produces, and the
// record a start failure leaves), and a second spelling of the path would be a
// verifier watching a directory nothing writes. The empty-data-root default
// mirrors AgentCredentialPath's, so the two can never disagree about which
// tree they are looking at.
func (c Config) agentWorkDir() string {
	root := c.DataRoot
	if root == "" {
		root = DefaultDataRoot
	}
	return filepath.Join(root, agentWorkSubdir)
}

// datavolStaging is the migration staging mount point for this Config's install
// dir (see DatavolStagingDir). It is an accessor rather than a second literal so
// a Config pointing at another install dir stages inside it.
func (c Config) datavolStaging() string { return filepath.Join(c.InstallDir, datavolStagingName) }

// resolvedExtraServerArgs returns ExtraServerArgs with MeshIP merged in: when
// MeshIP is set it REPLACES any --mesh-ip already in ExtraServerArgs (an
// explicit `k3sm install --mesh-ip` on THIS install wins over whatever a carried
// plist or ServerArgsRecord held); when it is empty, ExtraServerArgs comes back
// unchanged. This is the ONE place the two are merged — meshIP(), ServerPlist
// and writeServerArgsRecord all call it rather than reading ExtraServerArgs
// directly, so the bind/kubeconfig decision, the rendered daemon argv, and the
// persisted record can never disagree about which address won.
//
// An HA request (ClusterInit or ServerJoin) is merged the same way, after the
// mesh address: it REPLACES every carried role flag, --server and --node-ip
// (setEtcdArgs). With neither set the carried arguments come back as they were,
// so a single-node install renders exactly what it rendered before HA flags
// existed.
func (c Config) resolvedExtraServerArgs() []string {
	args := c.ExtraServerArgs
	if c.MeshIP != "" {
		args = setMeshIPArg(args, c.MeshIP)
	}
	if c.etcdRequested() {
		args = setEtcdArgs(args, c)
	}
	return args
}

// RecordedServerArgs returns the operator `k3sm server` arguments an install
// with cfg renders after the managed set AND writes to the server-arguments
// record: the carried arguments with this install's --mesh-ip and HA request
// merged in. It is exported so the CLI can assert, without root, that what
// its flags ask for is what a later reinstall carries forward.
func RecordedServerArgs(cfg Config) []string { return cfg.resolvedExtraServerArgs() }

// meshIP returns the effective --mesh-ip value (resolvedExtraServerArgs), or ""
// when the server runs single-node. It is the discriminator between the two
// apiserver postures the admin kubeconfig must address: a mesh server binds its
// wireguard IP ONLY and serves a cluster-CA-signed leaf, so a loopback URL
// reaches nothing and the cluster CA is the right anchor; single-node binds
// loopback and self-signs, for which no CA on disk is the anchor.
func (c Config) meshIP() string { return flagValue(c.resolvedExtraServerArgs(), "mesh-ip") }

// AgentCredentialPath is the first file `k3sm agent` writes when a token join
// succeeds: the node kubeconfig in the agent work dir under dataRoot. An empty
// dataRoot means the default.
//
// It is what makes an agent install VERIFIABLE. The daemon's pid says only that
// launchd spawned it; an agent whose token was wrong sits in its own terminal
// backoff with a perfectly healthy pid, and an install that reported success
// there would have handed the operator a worker that never joins. This file
// appearing is the first externally visible fact that the join actually
// happened.
//
// The name is stated here because pkg/install cannot import cmd/k3sm, and the
// two are bound by a test on the cmd side that asserts this path equals the
// credential store's own kubeconfig path. If that test goes red, the verifier
// is watching a file nothing writes.
func AgentCredentialPath(dataRoot string) string {
	if dataRoot == "" {
		dataRoot = DefaultDataRoot
	}
	return filepath.Join(dataRoot, agentWorkSubdir, agentNodeKubeconfigName)
}

// agentTokenPath is where Install stages the join token for the agent daemon to
// read: <DataRoot>/agent/join-token, service-user-owned 0600 (see
// AgentTokenFileMode). It is derived from the data root rather than configured,
// because it is not an operator's choice: it is the one path the renderer puts
// on the daemon's argv and the one path the installer writes, and a second
// spelling of either would be a daemon pointed at a file nobody wrote.
func (c Config) agentTokenPath() string {
	return filepath.Join(c.agentWorkDir(), agentTokenName)
}

// serverTokenPath is where Install stages the static admin token for the
// control-plane daemon to read: <DataRoot>/server/token, service-user-owned
// 0600 (see ServerTokenFileMode).
//
// It is agentTokenPath's sibling and exists for the same reason the agent's
// does, one privilege level up. The token is a system:masters bearer token, and
// rendering it as a VALUE on the server LaunchDaemon's argv published it three
// ways at once: the plist was root-owned 0644, `ps` shows a running job's argv
// to every account, and launchd echoes it back from its own job description. The
// daemon is now told where its token is and never what it is.
//
// Like the agent's, the path is derived rather than configured: it is the one
// path the renderer puts on the argv and the one path the installer writes, and
// a second spelling of either would be a daemon pointed at a file nobody wrote.
func (c Config) serverTokenPath() string {
	return filepath.Join(c.serverWorkDir(), serverTokenName)
}

// stageTokenFile writes token at dst, owned by the service uid at mode inside a
// directory at dirMode, so the unprivileged daemon that must present it can read
// it and nothing else on the Mac can. what names the credential for the error
// message ("join token", "admin token").
//
// It is ONE function for both roles because the two stagings are one decision
// made twice: a daemon's argv publishes whatever is on it, so the credential
// goes to a file and the path goes on the argv, and the file is worth preferring
// only because of the owner and the mode applied here. Two copies of that write
// would be two chances for one role to stage a credential at a mode the other
// would have refused.
//
// The modes stay PARAMETERS, as they are on the WriteServiceUserFile seam below
// it and for the same reason: each role's policy is then visible at its own call
// site rather than decided inside a shared helper neither role reads.
//
// The token is written with a trailing newline (both readers trim), and it is
// never logged or echoed: callers log the PATH.
func stageTokenFile(sys System, uid uint32, token, dst, what string, mode, dirMode fs.FileMode) error {
	if err := sys.WriteServiceUserFile(dst, []byte(token+"\n"), uid, mode, dirMode); err != nil {
		return fmt.Errorf("install: stage the %s at %s: %w", what, dst, err)
	}
	return nil
}

// ensureStateTree applies the ownership table (OwnershipOf) to the data root and
// every service-user tree under it, in the table's order.
//
// The root goes FIRST, and that order is the safety argument for everything
// after it. Each level is repaired by path, and a by-path chown is only as safe
// as the directory the path is resolved in: once the root is root:wheel 0755,
// no unprivileged principal can rename or replace any entry directly inside it,
// so the service-user trees chowned next are the directories that were there
// when they were checked (and EnsureOwnedDir refuses one that is a symlink).
// Healing a root an older build left service-user-owned is this same first
// step; nothing else in the installer ever hands the root to the service user.
//
// The trees are created as root because the service user can no longer create
// a top-level directory of its own under a root-owned root.
//
// Three rows are applied by a later step instead, each through its own seam and
// with the same row's values:
//
//   - the key directory is MeshKeyDir, a fixed path the netd plist names
//     whatever this Config's data root is, and provisionMeshKey ensures it
//     (EnsureMeshKeyDir) before it writes a key;
//   - the two work dirs are handed over by the steps that write into them
//     (WriteServiceUserFile creates its parent at ServerTokenDirMode or
//     AgentTokenDirMode), and the agent's is ALSO where adoptLegacyAgentFiles
//     migrates root-owned credentials files-first, directory-last, so the
//     service user never owns that directory while a root-owned file in it is
//     still pending. Chowning it here, before that step, would break the order.
func ensureStateTree(sys System, cfg Config, uid uint32) error {
	appliedLater := map[StateLevel]bool{
		StateKeys:                        true,
		StateLevel(sandbox.ServerSubdir): true,
		StateLevel(agentWorkSubdir):      true,
	}
	for _, level := range StateLevels() {
		if appliedLater[level] {
			continue
		}
		own, _ := OwnershipOf(level)
		dir := level.Path(cfg.DataRoot)
		if err := sys.EnsureOwnedDir(dir, own.UID(int(uid)), own.GID, own.Mode); err != nil {
			return fmt.Errorf("install: ensure %s (%d:%d %#o): %w", dir, own.UID(int(uid)), own.GID, own.Mode, err)
		}
	}
	cfg.Logger.Info("ensured the data root and the service user's trees under it", "root", cfg.DataRoot, "trees", len(ServiceLevels()))
	return nil
}

// ErrNotRegularFile is what ReadRegularFile reports for a path that exists but
// is a symlink, a directory, a device or a fifo. It is a sentinel because the
// callers must tell it apart from "absent": absence is a posture (nothing has
// been provisioned yet), while a non-regular file where a key belongs is
// somebody having put it there, and the two lead to opposite actions.
var ErrNotRegularFile = errors.New("not a regular file")

// argsRecordPath is the arguments record THIS role reads and writes: the
// server record on a control plane, the agent record on a worker. It is an
// accessor rather than a branch at each use so no code path can pick up the
// other role's file by forgetting the role it is in.
func (c Config) argsRecordPath() string {
	if c.Role == RoleAgent {
		return c.AgentArgsRecord
	}
	return c.ServerArgsRecord
}

// installedBinary is the path the k3sm binary is copied to.
func (c Config) installedBinary() string {
	return filepath.Join(c.InstallDir, "k3sm")
}

// installedLink is the path of the `k3sm` launcher symlink, in LinkDir, pointing
// at installedBinary(). Its BASENAME is taken from the installed binary rather
// than re-typed, so the command a shell resolves and the file the LaunchDaemons
// exec can never be given different names; no bare /usr/local/bin/k3sm literal
// exists outside the tests that pin this derivation.
func (c Config) installedLink() string {
	return filepath.Join(c.LinkDir, filepath.Base(c.installedBinary()))
}

// installedExecShim is the path the k3sm-execshim helper is copied to — beside
// the binary, the first place sandbox.FindExecShim probes.
func (c Config) installedExecShim() string {
	return filepath.Join(c.InstallDir, "k3sm-execshim")
}

// installedPathShim is the path the path-rebase DYLD shim is copied to — beside
// the binary, where runtimedConfig resolves it next to the executable.
func (c Config) installedPathShim() string {
	return filepath.Join(c.InstallDir, PathShimName)
}

// installedDNSShim is the path the getaddrinfo DNS shim is copied to — beside the
// binary, where runtimedConfig resolves it next to the executable.
func (c Config) installedDNSShim() string {
	return filepath.Join(c.InstallDir, DNSShimName)
}

// installedVMHost is the path the k3sm-vmhost VM-host helper is copied to —
// beside the binary, the first place sandbox.FindVMHost probes.
func (c Config) installedVMHost() string {
	return filepath.Join(c.InstallDir, VMHostName)
}

// plistPath is the LaunchDaemon plist path for a label.
func (c Config) plistPath(label string) string {
	return filepath.Join(c.LaunchDaemonDir, label+".plist")
}

// Install lays down both daemons in dependency order. It is the single root step
// (run via sudo): ensure _k3sm, copy the binary root-owned, write the two
// plists, bootstrap netd (the helper) BEFORE server (which needs it), then write
// the admin kubeconfig to the human's home. The caller has already verified root.
func Install(ctx context.Context, sys System, cfg Config) (err error) {
	cfg = cfg.withDefaults()
	// Taken before anything is written, and carried to the post-restart
	// verification: it is what separates a failure THIS install caused from one
	// the machine was already living with (see verifyServerNotParked).
	startedAt := time.Now()
	if cfg.BinarySource == "" {
		return fmt.Errorf("install: BinarySource (the k3sm binary to install) is required")
	}
	if cfg.TargetUser == "" {
		return fmt.Errorf("install: TargetUser (the kubeconfig owner, e.g. $SUDO_USER) is required")
	}
	// BEFORE anything is written, and before a single byte is copied: a Mac
	// carries one role. Installing the other one over it would leave two node
	// daemons bootstrapped out of one data root, one run dir and one netd
	// socket — two Kubernetes nodes claiming the same machine — and the
	// half-overwritten state would outlive whichever install failed second.
	// Refusing here costs an operator one command and nothing else.
	if err := refuseCrossRole(sys, cfg); err != nil {
		return err
	}
	// The HA request's own shape, from the Config alone: the same validator
	// the CLI ran at parse time.
	if err := ValidateHARequest(cfg); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	// Still before anything is written: the directory that will hold the `k3sm`
	// launcher must already be trusted. The link is laid down at step 2b, long
	// after the service user, the log trees, the run dir, the staged credentials
	// and the binary itself — so making this judgement there (EnsureSymlink does,
	// and keeps doing) turns a legitimate refusal into a half-installed Mac the
	// operator then has to unpick. Read-only, so a reinstall over a healthy
	// install passes it exactly as the first install did.
	if err := sys.LinkDirTrust(cfg.installedLink()); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	// ...and the last thing asked before the first write, on a worker: can the
	// control plane this node is being pointed at actually be reached, and is it
	// the cluster the operator's token names? Both answers are available now and
	// neither is available later without a half-installed Mac to unpick — see
	// preflightJoinEndpoint for the install that made this necessary. A server
	// install joins nothing and returns immediately.
	// It returns the operator's join token — the exact bytes it validated and
	// compared against the endpoint's cluster — so staging writes those and the
	// file is read once, with no privileged write between the check and the copy.
	joinToken, err := preflightJoinEndpoint(sys, cfg)
	if err != nil {
		return err
	}
	// Also before anything is written: does the staged k3sm-vmhost helper carry
	// the entitlement runtimed's sandbox backend requires? CopyToRootOwned (the
	// step that lays this helper down, at 2b⁗ below) preserves whatever
	// signature the build produced VERBATIM and never re-signs it, so this is
	// the only point in the whole install that can decline an unentitled
	// helper — and it is read-only, so making that judgement here rather than
	// immediately before that copy costs nothing and avoids exactly the failure
	// this preflight block exists to prevent: a real 2026-09-17 upgrade refused
	// on this very check AFTER the new binary and every other sibling helper
	// had already been copied into the install root, leaving them beside the
	// OLD helper while the daemons still ran the old build — an availability
	// hazard, not just untidiness, since launchd's KeepAlive execs whatever is
	// on disk and a crash in that window promotes an untested mix.
	//
	// A MISSING helper is not this gate's business — the probe reports
	// fs.ErrNotExist and the copy at 2b⁗ keeps its existing message.
	if err := sys.VerifyVirtualizationEntitlement(cfg.VMHostSource); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("install: staged %s does not carry the %s entitlement: %w (install copies the helper verbatim and never re-signs it, so an unentitled helper installs unentitled and every vm-RuntimeClass pod then stays Pending on an opaque node-affinity message; sign a dev build with `codesign --force --sign - --entitlements runtimed/cmd/k3sm-vmhost/vmhost.entitlements %s` — release artifacts already carry it)", cfg.VMHostSource, VirtualizationEntitlement, err, cfg.VMHostSource)
	}
	// The last input-only refusal, and the one that is a courtesy rather than a
	// correctness gate: is there room on this volume for a second copy of the
	// install root? Staging means the new tree and the old one coexist until the
	// reap, so an install now needs the space twice over. The copies themselves
	// remain the authority on whether they fit — this exists so a Mac with no
	// room says so in one sentence, before anything is written, instead of
	// failing part-way through the payload with an ENOSPC from ditto.
	if err := preflightInstallSpace(sys, cfg); err != nil {
		return err
	}
	// NOTHING BELOW THIS LINE IS WRITTEN BY TWO INSTALLS AT ONCE. The lock is
	// taken here — after every input-only refusal, so a refusal never has to
	// take it, and before the first write, so everything that follows is
	// serialised — and it is held until this function returns, which is past the
	// reap. See System.LockInstall for why two concurrent installs are the one
	// hazard the staging below cannot contain by itself.
	unlock, err := sys.LockInstall(cfg.installLockPath())
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}
	defer func() {
		if err := unlock(); err != nil {
			cfg.Logger.Warn("could not release the install lock", "path", cfg.installLockPath(), "err", err)
		}
	}()

	if cfg.AdminToken == "" {
		tok, err := generateToken()
		if err != nil {
			return err
		}
		cfg.AdminToken = tok
	}

	// 0. The data volume, BEFORE everything else -- see ensureDataVolume for why
	//    this block cannot sit anywhere later. It also decides
	//    cfg.dataVolumeDeclared, which the manifest below reads.
	st, err := dataroot.Read(cfg.DataRootFS, cfg.DataRoot)
	if err != nil {
		return fmt.Errorf("install: inspect the data root %s: %w", cfg.DataRoot, err)
	}
	cfg.dataVolumeDeclared = st.Volume != nil || cfg.DataVolume != nil

	// The manifest is the single source of truth for the artifacts laid down (and,
	// on uninstall, torn down): daemon plist paths + install order come from it, so
	// there is no second hardcoded list to diverge from the teardown. It is built
	// AFTER the declaration above, because the datavol daemon and the record are
	// in it only when there is a data volume to manage.
	m := artifactManifest(cfg)

	if cfg.DataVolume != nil {
		if err := ensureDataVolume(ctx, sys, cfg, m, st); err != nil {
			return err
		}
	}

	// 0b. Still before anything else is written: on a control-plane install,
	//     does the carried `k3sm server` argument set (the installed plist, or
	//     the survives-uninstall record when there is none) name a retired
	//     external-datastore flag? Rendering the plist anyway would hand launchd
	//     a daemon that exits on an unknown flag at every respawn, so this
	//     refuses before the copies below rather than after them, and names the
	//     embedded-etcd replacement. It returns the SAME
	//     carried arguments step 2d assigns to cfg.ExtraServerArgs, so the
	//     installed plist/record is read exactly once per install. Runs after
	//     the data volume above: the carry-over's "nothing was carried" warning
	//     inspects the data root for prior cluster state, which only ensureDataVolume
	//     has made available at cfg.DataRoot by this point. An agent install (or
	//     one with no operator server arguments) gets back a nil slice and no
	//     error.
	serverArgs, err := preflightServerArgs(sys, cfg)
	if err != nil {
		return err
	}
	// 0b′. Secrets encryption, decided from reads alone and before the first
	//      write that follows: it needs the carried arguments above (a carried
	//      --cluster-init or --server-join refuses it) and the data root as the
	//      data volume left it (a datastore already there refuses it). The
	//      pair itself is written at 1f′, once the service uid is known.
	encryptionAction, err := preflightSecretsEncryption(sys, cfg, serverArgs)
	if err != nil {
		return err
	}

	// 0c. An UPGRADE stops the daemons the previous install left running before
	//     anything under the data root changes owner: EnsureServiceUser below
	//     already applies the root row of the ownership table. See
	//     stopRunningDaemons; on a first install nothing is loaded and nothing
	//     is booted out.
	stopped, err := stopRunningDaemons(ctx, sys, m, cfg.Logger)
	// Until step 4 takes over restarting them, a failure leaves the stopped
	// daemons stopped, and the error says so rather than leaving the operator
	// to discover it.
	restartOwned := false
	defer func() {
		if err != nil && len(stopped) > 0 && !restartOwned {
			err = fmt.Errorf("%w (the daemons stopped before the state tree was re-owned are still stopped: %s; re-run `sudo k3sm install`)", err, strings.Join(stopped, ", "))
		}
	}()
	if err != nil {
		return fmt.Errorf("install: stop the running daemons before re-owning the state tree: %w", err)
	}

	// 1. The service user must exist before the server LaunchDaemon (UserName=_k3sm)
	//    can resolve it and before the trees it owns under the data root exist.
	uid, err := sys.EnsureServiceUser(cfg.ServiceUser, cfg.DataRoot)
	if err != nil {
		return fmt.Errorf("install: ensure service user %s: %w", cfg.ServiceUser, err)
	}
	cfg.Logger.Info("ensured service user", "user", cfg.ServiceUser, "uid", uid)

	// 1a. The state tree, per the ownership table and BEFORE anything is written
	//     under it: the data root root:wheel 0755, then every tree the
	//     unprivileged daemons write, handed to the service user one by one. The
	//     root going first is what makes the rest safe and what heals a root an
	//     older build left service-user-owned. See ensureStateTree.
	if err := ensureStateTree(sys, cfg, uid); err != nil {
		return err
	}

	// 1b. The log dir must be writable by the service user before either daemon
	//     bootstraps: launchd opens a UserName job's StandardOut/ErrorPath as
	//     that user, and if the root netd job's spawn auto-creates the dir first
	//     (root-only perms), the _k3sm server job fails "Service could not
	//     initialize" and never spawns. Created/repaired idempotently.
	if err := sys.EnsureLogDir(LogDir, uid); err != nil {
		return fmt.Errorf("install: ensure log dir %s: %w", LogDir, err)
	}

	// 1b‴. The purge markers, in the two trees `k3sm uninstall --purge` deletes
	//     whole. Both directories exist by now (the data root from step 1a, the
	//     log dir from the step above), and the marker is rewritten on every
	//     install, so a Mac installed before markers existed gains them on its
	//     next install. Each names the directory it sits in.
	for _, dir := range []string{cfg.DataRoot, LogDir} {
		if err := sys.WriteDataRootMarker(dir); err != nil {
			return fmt.Errorf("install: write the k3sm marker in %s: %w", dir, err)
		}
	}

	// 1b'. The container-log tree, for the same reason and at the same moment: the
	//     node refuses to start without it, and only root can create it owned by
	//     the service user with a mode that does not expose every pod's output to
	//     every local account.
	for _, dir := range []string{PodLogsDir, ContainerLogsDir} {
		if err := sys.EnsureContainerLogDir(dir, uid); err != nil {
			return fmt.Errorf("install: ensure container log dir %s: %w", dir, err)
		}
	}

	// 1b″. ...and the PER-POD directories inside that tree, on a node whose
	//     daemon once ran as root. The step above repairs the root and only the
	//     root; the directories a root-era node created under it stay root-owned
	//     0700, and the service-user node then fails every CreatePod with
	//     "failed to create container log directory ...: permission denied".
	//     Unconditional, exactly like the step it repairs: a single-node server
	//     runs pods and writes this same tree, so a role gate here would leave
	//     one of the two roles with the failure. See adoptPodLogTree for why
	//     this one walks, never refuses, and never deletes. It returns nothing:
	//     a tree whose sole deleter is an asynchronous GC is not something to
	//     fail an install over.
	adoptPodLogTree(sys, cfg, uid)

	// 1c. The run dir, BEFORE either daemon bootstraps — because whichever daemon
	//     starts first creates it, and that is root netd, which left it root:wheel
	//     0755. The _k3sm server then could not bind <run>/runtimed.sock there
	//     (EACCES), its bounded retry gave up, and the runtimed control socket was
	//     silently disabled on an install that otherwise looked healthy. Root netd
	//     still creates netd.sock inside a service-user-owned directory — root
	//     bypasses the mode — so ordering this first costs the helper nothing.
	runDir := cfg.runDir()
	if err := sys.EnsureRunDir(runDir, uid); err != nil {
		return fmt.Errorf("install: ensure run dir %s: %w", runDir, err)
	}

	// 1d. The vm guest-agent socket dir inside it: runtimed binds
	//     <VMRunDir>/<podID>/agent.sock as _k3sm, and an install over a tree an
	//     earlier build left root-owned must repair the ownership or every
	//     vm-RuntimeClass pod fails to boot.
	if err := sys.EnsureVMRunDir(VMRunDir, uid); err != nil {
		return fmt.Errorf("install: ensure vm run dir %s: %w", VMRunDir, err)
	}

	// 1e. The join token, staged where the daemon can actually read it. It needs
	//     the service uid, so it cannot happen before EnsureServiceUser, and it
	//     happens before the plist that names it is written. A reinstall with no
	//     --token-file stages nothing and leaves any previous copy alone: a
	//     joined node presents its stored credential and needs no token.
	//     A joining server stages its server-class token the same way, into
	//     its own work dir.
	if (cfg.Role == RoleAgent && cfg.TokenFile != "") || cfg.serverJoining() {
		if err := stageJoinToken(sys, cfg, uid, joinToken); err != nil {
			return err
		}
	}

	// 1e′. Hand any agent state an OLDER install left root-owned over to the
	//     service user — after the step above, which is what may have just
	//     created the work dir, and well before step 4 restarts the daemon that
	//     has to write in it. See adoptLegacyAgentFiles for why a node installed
	//     before the daemon moved to _k3sm otherwise crash-loops on its own
	//     node-password, and for why this is a migration to the fresh-install
	//     posture rather than a widening of it.
	if cfg.Role == RoleAgent {
		if err := adoptLegacyAgentFiles(sys, cfg, uid); err != nil {
			return err
		}
	}

	// 1f. The control plane's static admin token, staged the same way and for a
	//     stronger version of the same reason: it authenticates as
	//     system:masters, and it used to be rendered as a VALUE on the server
	//     LaunchDaemon's argv, where the 0644 plist, `ps` and launchd's own job
	//     description each handed it to every account on the Mac. Unlike the
	//     agent's it is staged on EVERY install, because it is not an operator's
	//     optional input: it is minted (or carried) by this install and has to be
	//     the same value the admin kubeconfig written below carries, or every
	//     admin request is Unauthorized.
	if cfg.Role == RoleServer {
		if err := stageTokenFile(sys, uid, cfg.AdminToken, cfg.serverTokenPath(), "admin token", ServerTokenFileMode, ServerTokenDirMode); err != nil {
			return err
		}
		cfg.Logger.Info("staged the control plane's admin token for the server daemon (the daemon is told where its token is, never what it is)", "path", cfg.serverTokenPath())
	}

	// 1f′. The secrets encryption pair, when 0b′ decided to write one: after
	//      the service uid exists and before any daemon is started, so the
	//      first start of a new cluster already encrypts.
	if err := stageSecretsEncryption(sys, cfg, uid, encryptionAction); err != nil {
		return err
	}

	// 1g. This node's wireguard identity, in both copies, for BOTH roles — see
	//     provisionMeshKey. It sits with the token stagings because it is the
	//     same kind of step (root hands the unprivileged daemon a credential it
	//     could not place for itself), and after the state tree at 1a because the
	//     root-only key dir is carved directly under the root-owned data root.
	if err := provisionMeshKey(sys, cfg, uid); err != nil {
		return err
	}

	// 2. THE STAGED INSTALL ROOT BEGINS HERE. Every artifact below lands in
	//    <InstallDir>.staging, not in the live tree, and the whole set is
	//    published in one step at 2f. See stage.go for the hazard that buys: the
	//    copies used to go straight into /Library/k3sm one after another, so any
	//    fault part-way through left the new binary beside old helpers while
	//    launchd's KeepAlive re-execs whatever is at the fixed paths those plists
	//    name.
	if err := prepareStagingDir(sys, cfg); err != nil {
		return err
	}

	// 2a. Copy the binary to the exact path the plists will exec
	//    (installedBinary()), regardless of the source artifact's name — staged
	//    at its counterpart under the staging tree, so the name it is published
	//    under is still the fixed one. It lands under InstallDir, so the
	//    InstallDir sweep covers it on uninstall.
	if err := sys.CopyToRootOwned(cfg.BinarySource, cfg.stagedBinary()); err != nil {
		return fmt.Errorf("install: copy binary to %s: %w", cfg.stagedBinary(), err)
	}
	// 2b′. Copy the k3sm-execshim Seatbelt helper beside it. Fail fast when the
	//     source shim is absent: the server plist hardcodes --runtime runtimed,
	//     whose backend resolves the shim next to the executable — without it the
	//     server dies at boot in an invisible KeepAlive crash-loop (the live
	//     live-hardware failure mode), so a missing shim is an install-time error.
	if err := sys.CopyToRootOwned(cfg.ExecShimSource, cfg.stagedExecShim()); err != nil {
		return fmt.Errorf("install: copy k3sm-execshim to %s: %w (build k3sm.io/runtimed/cmd/k3sm-execshim, codesign it, and place it next to the k3sm binary — the runtimed Seatbelt backend cannot boot without it)", cfg.stagedExecShim(), err)
	}
	// 2b″. Copy the path-rebase DYLD shim beside the binary. runtimed resolves it
	//      next to the executable and injects it into a mounting pod so an absolute
	//      volume mount resolves under the pod data volume (build it with
	//      runtimed/hack/build-pathshim.sh and ad-hoc sign it).
	if err := sys.CopyToRootOwned(cfg.PathShimSource, cfg.stagedPathShim()); err != nil {
		return fmt.Errorf("install: copy path-rebase shim to %s: %w (build it with runtimed/hack/build-pathshim.sh, codesign it, and place it next to the k3sm binary)", cfg.stagedPathShim(), err)
	}
	// 2b‴. Copy the getaddrinfo DNS shim beside the binary. The provider resolves it
	//      next to the executable and injects it into each pod so in-pod cluster DNS
	//      reaches the per-node resolver (build it with darwin-net/hack/build-shim.sh).
	if err := sys.CopyToRootOwned(cfg.DNSShimSource, cfg.stagedDNSShim()); err != nil {
		return fmt.Errorf("install: copy getaddrinfo DNS shim to %s: %w (build it with darwin-net/hack/build-shim.sh, codesign it, and place it next to the k3sm binary)", cfg.stagedDNSShim(), err)
	}
	// 2b⁗. Copy the k3sm-vmhost VM-host helper beside the binary. runtimed's
	//      sandbox.FindVMHost resolves it next to the executable for
	//      vm-RuntimeClass pods. The helper is ad-hoc signed with the
	//      com.apple.security.virtualization entitlement, and CopyToRootOwned
	//      (ditto) carries that signature through verbatim — install never
	//      re-signs it, matching every other sibling binary here.
	//
	//      The entitlement itself was already verified, in the preflight block
	//      before ANY of the copies in this function ran — see the comment
	//      there for why waiting until immediately before this one copy was
	//      itself the defect: it let every other artifact land first. This copy
	//      can therefore only fail on an I/O error, not on the entitlement.
	if err := sys.CopyToRootOwned(cfg.VMHostSource, cfg.stagedVMHost()); err != nil {
		return fmt.Errorf("install: copy k3sm-vmhost to %s: %w (build k3sm.io/runtimed/cmd/k3sm-vmhost, ad-hoc sign it with the com.apple.security.virtualization entitlement, and place it next to the k3sm binary — vm-RuntimeClass pods cannot boot without it)", cfg.stagedVMHost(), err)
	}
	// 2c. Stage the control-plane payload into InstallDir/bin. Fail fast when a
	//     payload binary is absent: the daemon boot otherwise falls back to
	//     `gh`/`go` acquisition, which cannot exist under launchd as _k3sm (the
	//     second live-hardware failure mode). Produce the payload with
	//     `k3sm payload <dir>` in a shell that has gh + go.
	for _, name := range executor.PayloadBinaries() {
		src := filepath.Join(cfg.PayloadSource, name)
		dst := cfg.stagedPayloadFile(name)
		if err := sys.CopyToRootOwned(src, dst); err != nil {
			return fmt.Errorf("install: stage control-plane payload %s: %w (run `k3sm payload %s` first — the launchd daemon cannot acquire binaries itself)", name, err, cfg.PayloadSource)
		}
	}
	//     The kine version marker is staged best-effort beside the payload, and the error
	//     is ignored: an archive produced before markers existed simply does not have
	//     one, and its absence must not fail an install. It also cannot fail silently
	//     in the dangerous direction — an unmarked payload is one the daemon's work-dir
	//     seed refuses to trust (it rebuilds, or reports), rather than one it stamps
	//     with a pin nothing vouched for.
	_ = sys.CopyToRootOwned(filepath.Join(cfg.PayloadSource, executor.KineMarkerName),
		cfg.stagedPayloadFile(executor.KineMarkerName))
	//     The etcd version marker is staged the same way, for the same reasons.
	_ = sys.CopyToRootOwned(filepath.Join(cfg.PayloadSource, executor.EtcdMarkerName),
		cfg.stagedPayloadFile(executor.EtcdMarkerName))
	//     The control-plane version marker is staged the same way and for the same
	//     reasons: without it the seed cannot tell this release's kube binaries from
	//     the ones an earlier release left in the work dir, and an absent marker only
	//     means the seed leaves the present set alone.
	_ = sys.CopyToRootOwned(filepath.Join(cfg.PayloadSource, executor.KubeMarkerName),
		cfg.stagedPayloadFile(executor.KubeMarkerName))

	// 2c′. The shadow binary set: ad-hoc re-signed copies of the host shells,
	//      tar and the common coreutils under <InstallDir>/shadow, with the manifest of what they were made
	//      from. Made HERE, by the privileged installer and nowhere else (a
	//      daemon-writable copy would be a code-injection path into every pod),
	//      and staged like every other artifact, so the set is published with
	//      the binary that uses it. See makeShadowSet.
	if err := makeShadowSet(sys, cfg); err != nil {
		return err
	}

	// 2d. Carry over the operator-supplied server arguments — from the plist
	//     ALREADY ON DISK, or, when there is none, from the record the previous
	//     install left in the data root. ServerPlist renders a fixed template, so
	//     without this a reinstall silently dropped every argument a human had
	//     added (--mesh-ip, --registry-port) and the cluster came back single-node
	//     on loopback until someone repaired the plist by hand. A genuine first
	//     install finds neither source and preserves nothing; --token is
	//     deliberately NOT preserved (it is install-managed and re-minted here, in
	//     lockstep with the kubeconfig).
	//     An agent install does the same for `k3sm agent`, through its own plist
	//     and its own record; the two roles never read each other's.
	if cfg.Role == RoleAgent {
		extra, err := installedAgentArgs(sys, cfg)
		if err != nil {
			return err
		}
		cfg.ExtraAgentArgs = extra
		if len(extra) > 0 {
			cfg.Logger.Info("preserved operator-supplied agent arguments across reinstall", "args", redactedServerArgsText(extra))
		}
	} else {
		// Already read, in the preflight block above (preflightServerArgs) — the
		// same call, reused rather than repeated, so the installed plist/record
		// is read exactly once per install and this does not re-emit its own
		// "preserved" log line.
		cfg.ExtraServerArgs = serverArgs
		if len(serverArgs) > 0 {
			cfg.Logger.Info("preserved operator-supplied server arguments across reinstall", "args", redactedServerArgsText(serverArgs))
		}
	}
	// 2d″. An explicit --mesh-ip on THIS install replaces whatever --mesh-ip was
	//      just carried over — see Config.MeshIP and resolvedExtraServerArgs,
	//      which every downstream reader (the record write below, ServerPlist,
	//      the cluster-CA read at 2e, AdminKubeconfig) goes through, so this is
	//      log-only: nothing here needs to mutate cfg.ExtraServerArgs itself.
	if old := flagValue(cfg.ExtraServerArgs, "mesh-ip"); cfg.MeshIP != "" && old != "" && old != cfg.MeshIP {
		cfg.Logger.Info("--mesh-ip replaces the mesh address carried over from the previous install", "old", old, "new", cfg.MeshIP)
	}
	// 2d′. Record them, on EVERY install and whatever the source was — including
	//      an empty set, which is the truthful record of a node that has none.
	//      The plist this install is about to write will not survive the next
	//      `k3sm uninstall`; the record lives in the preserved data root and
	//      does.
	if err := writeArgsRecord(sys, cfg); err != nil {
		return err
	}

	// 2e. Read the trust anchor for the endpoint the admin kubeconfig is about to
	//     name. WHICH certificate that endpoint presents is decided by the posture
	//     this install renders, so the anchor is read per posture (install runs as
	//     root; both files are the _k3sm control plane's, and both are PUBLIC 0644
	//     certificates, so this is not a credential read):
	//
	//       - MESH: cmd/k3sm issues a CLUSTER-CA-SIGNED leaf into the PKI dir and
	//         hands it to the apiserver as --tls-cert-file, so the cluster CA is
	//         the anchor.
	//       - SINGLE-NODE: nothing supplies a serving keypair, so kube-apiserver
	//         self-signs into its own --cert-dir instead — see readLoopbackAnchor.
	//
	//     Either anchor is absent on a first install, where the control plane has
	//     not booted yet; the kubeconfig then falls back to the skip-verify posture
	//     and the next reinstall picks the anchor up.
	if mesh := cfg.meshIP(); mesh != "" {
		caPath := certs.ClusterCACertPath(cfg.serverWorkDir())
		ca, err := sys.ReadFile(caPath)
		switch {
		case err == nil:
			cfg.ClusterCA = ca
		case errors.Is(err, fs.ErrNotExist):
			cfg.Logger.Warn("cluster CA not on disk yet; admin kubeconfig keeps insecure-skip-tls-verify until the next install", "path", caPath)
		default:
			return fmt.Errorf("install: read cluster CA %s: %w", caPath, err)
		}
	} else if err := readLoopbackAnchor(sys, &cfg); err != nil {
		return err
	}

	// 2f. PUBLISH. One filesystem operation exchanges the staged tree with the
	//     live install root, so no observer ever sees a partial one. Everything
	//     above this line wrote either into the staging tree or outside the
	//     install root entirely, which is why a failure up to here leaves the
	//     previous install byte-for-byte as it was and has nothing to undo.
	//
	//     From here to the reap at 4c, the previous tree is intact at the
	//     staging path and every failure routes through revertInstallRoot.
	previous, err := publishStagedRoot(sys, cfg)
	if err != nil {
		return err
	}

	// 3. The launcher link and the plists, in that order, and BOTH after the
	//    publish: each names a fixed absolute path inside the install root, and
	//    that path holds this install's binary only now. The link used to go
	//    down immediately after the binary copy, which under staging would have
	//    pointed `k3sm` at a path a first install had not created yet.
	//
	//    Neither needs rewriting BECAUSE the paths are fixed: the swap moves
	//    inodes, not names, so the plists' ProgramArguments and the launcher's
	//    target mean the new tree the moment it is live.
	restartOwned = true // step 4 restarts, and on failure reports, every daemon
	if err := publishedWiring(ctx, sys, cfg, m, startedAt); err != nil {
		return revertInstallRoot(ctx, sys, cfg, m, previous, err)
	}

	// 4c. REAP, and not one step earlier. The previous install root is still
	//     sitting at the staging path, and it has been the rollback target for
	//     every failure since the publish; only now that the daemons have
	//     restarted on the new tree AND been verified healthy is it safe to let
	//     go of it. Nothing after this line can be rolled back, which is why the
	//     kubeconfig write below is deliberately on this side of it: an install
	//     whose daemons are up and verified is a successful install, and undoing
	//     it because a file in a home directory could not be written would be the
	//     wrong trade.
	if previous {
		reapPreviousRoot(sys, cfg)
	}

	// 5. Write the admin kubeconfig to the human's home (owned by them, not root)
	//    — on a CONTROL PLANE only. A worker has no apiserver of its own and no
	//    admin credential to carry: writing one there would point kubectl at a
	//    loopback address nothing serves, with a token no cluster honours, over
	//    whatever the operator's ~/.kube/config already said about the real
	//    cluster. An operator administers a k3sm cluster from the server's
	//    kubeconfig (or a copy of it), never from the worker's.
	if cfg.Role != RoleAgent {
		if err := sys.WriteUserKubeconfig(cfg.TargetUser, AdminKubeconfig(cfg)); err != nil {
			return fmt.Errorf("install: write admin kubeconfig for %s: %w", cfg.TargetUser, err)
		}
	}
	cfg.Logger.Info("k3sm installed", "install-dir", cfg.InstallDir, "link", cfg.installedLink(), "kubeconfig-owner", cfg.TargetUser)
	return nil
}

// publishedWiring is everything an install does once the new tree is live: the
// launcher link, the plists, the restart, and the verification that the
// daemons came back. It is one function rather than four statements in Install
// so that the caller has exactly one error path to route through
// revertInstallRoot — the window in which a rollback is both possible and
// correct is precisely this function's extent.
func publishedWiring(ctx context.Context, sys System, cfg Config, m []artifact, startedAt time.Time) error {
	// 3a. Put `k3sm` on PATH, from the manifest's kindSymlink entries. Copying
	//     the binary into /Library/k3sm never made `k3sm` a command a shell
	//     could find, yet every post-install instruction (and install.sh's
	//     closing hint) assumes it is one; the link is the whole of that fix and
	//     is therefore a hard install failure when it cannot be laid down, not a
	//     best-effort nicety.
	for _, a := range m {
		if a.kind != kindSymlink {
			continue
		}
		if err := sys.EnsureSymlink(a.target, a.path); err != nil {
			return fmt.Errorf("install: link %s -> %s: %w", a.path, a.target, err)
		}
	}
	// 3b. Render + write both plists, in manifest (install) order. Before each
	//     write, the file limit the new plist requests is checked against the
	//     kernel ceiling, and compared with the limit the plist being replaced
	//     requested; the reload notice that comparison produces is held until
	//     the restart below has actually rebound the limit.
	var limitNotices []fileLimitChange
	for _, a := range m {
		if a.kind != kindDaemon {
			continue
		}
		content, err := plistContent(a.label, cfg)
		if err != nil {
			return fmt.Errorf("install: %w", err)
		}
		if n, ok := checkFileLimit(sys, cfg.Logger, a.label, a.path, content); ok {
			limitNotices = append(limitNotices, n)
		}
		if err := sys.WriteLaunchDaemon(a.path, content, plistMode(a.label)); err != nil {
			return fmt.Errorf("install: write %s plist: %w", a.label, err)
		}
	}

	// 4. (Re)start in manifest order: netd first (root helper), then the server
	//    (depends on it) — the manifest lists netd before server. Each label is
	//    booted out first (idempotent — a not-loaded label is a no-op), then
	//    bootstrapped: `launchctl bootstrap` on an already-loaded label does not
	//    re-exec an updated on-disk binary — the stale daemon keeps running the old
	//    code, so a reinstall/upgrade (or a live rebuild between acceptance runs)
	//    would silently serve the superseded binary.
	//
	//    The two commands are NOT a pair: bootout returns before launchd has
	//    removed the label, so an immediate bootstrap races the teardown and loses.
	//    restart.go sequences them — see its file comment for the failure this cost
	//    in the field, the transient errnos, and the rollback on a mid-loop failure.
	if err := restartDaemons(ctx, sys, cfg, m); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	for _, n := range limitNotices {
		cfg.Logger.Info("the daemon's open-file limit changed; this install booted it out and bootstrapped it again, which is what binds a new SoftResourceLimits/HardResourceLimits NumberOfFiles (launchctl kickstart -k alone would NOT: it respawns the job with the limit captured at its last bootstrap)",
			"label", n.label, "old", n.old, "new", n.new)
	}

	// 4b. Verify the claim step 4 makes, rather than assuming it. An install that
	//     reports success having left a daemon down is worse than one that fails:
	//     the operator walks away, and the breakage surfaces later as something
	//     else entirely (a cluster whose DNS stopped answering).
	if err := verifyDaemons(ctx, sys, cfg, m, startedAt); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	return nil
}

// Uninstall tears down every artifact install laid down, driven by the same
// manifest install consumes — so nothing install creates can be left behind
// (the leak was the two plists, which the old hardcoded uninstall never
// removed). It walks the manifest in reverse install order: the server daemon
// before netd, so the control plane stops driving the helper before the helper
// goes away. Each daemon is torn down as Bootout(label) then
// RemoveAll(plistPath) so the label and its plist never diverge. InstallDir-
// covered artifacts are swept by the single RemoveAll(InstallDir); dispPreserve
// artifacts (DataRoot's kine state.db + mesh keys, the human kubeconfig, the
// _k3sm user, LogDir) are left in place. It is idempotent: a bootout of a
// not-loaded label and a RemoveAll of an absent path are both no-op successes,
// so re-running after a partial install (or twice) is safe.
//
// What netd's SIGTERM does, precisely: `k3sm netd` cancels its context, and
// netd.Server.Serve closes its listener and returns. That is all — it flushes
// NOTHING. A full teardown does exist (mesh.WGDevice.Down deletes the routes,
// flushes the pf anchor, drops the mesh-egress alias and closes the utun), but
// the only caller is the RemoveMesh RPC; no signal path reaches it. This comment
// used to assert the opposite — "netd's SIGTERM handler then flushes lo0/pf/utun"
// — and believing it is how the residue below went unaccounted for.
//
// So a booted-out netd leaves durable kernel state, and uninstall removes two
// classes of it:
//
//   - lo0 inet aliases — SWEPT, by the FlushLo0Aliases backstop below, precisely
//     because no daemon does it.
//   - the pf anchor an older release loaded the mesh MSS clamp into: SWEPT, by
//     the FlushMeshPFAnchor backstop below. Nothing loads it now (k3sm loads no
//     pf rule), but a rule an older release left behind would survive netd,
//     scoped to a utun that is gone, and macOS recycles utun numbers. A
//     daemon-shutdown-path fix was considered and rejected: the flush is a
//     backstop for old state, not a live resource.
//   - the wireguard utun and its routes — NOT explicitly removed. The interface
//     is created in-process (tun.CreateTUN) and goes away with netd, and the
//     kernel drops routes whose interface has vanished; nothing here proves the
//     routing table is clean, only that no rule keeps it dirty.
//
// Flushing the utun/routes class on the way out (if it ever proves necessary)
// is a darwin-net change (a shutdown hook that reaches Down), not an installer
// one, and would be filed separately. Uninstall makes no claim to do it.
//
// With cfg.Purge set it is `k3sm uninstall --purge`: the same teardown, then
// every artifact this one keeps (see purge).
func Uninstall(ctx context.Context, sys System, cfg Config) error {
	cfg = cfg.withDefaults()
	if cfg.Purge {
		return purge(ctx, sys, cfg)
	}
	_, err := uninstall(ctx, sys, cfg, nil)
	return err
}

// uninstall is Uninstall's teardown, and returns the manifest it walked so a
// purge consumes that same manifest rather than one rebuilt after the state it
// was derived from has changed. preflight, when non-nil, runs after the
// manifest is built and BEFORE anything is torn down, and is handed the
// data-root posture and the error reading it; an error from it is
// returned as it stands, with nothing changed. cfg already carries its defaults.
func uninstall(ctx context.Context, sys System, cfg Config, preflight func(m []artifact, st dataroot.State, stErr error) error) ([]artifact, error) {
	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	// safeRemove guards every root RemoveAll: it refuses a non-absolute path or one
	// fewer than two segments deep, so an operator fat-finger (e.g. a Config with
	// InstallDir="/" or "/Library") can never hand "/" or a filesystem root to a
	// root-privileged RemoveAll. The normal targets (/Library/k3sm, the two
	// /Library/LaunchDaemons/io.k3sm.*.plist files) pass unchanged.
	safeRemove := func(path string) error {
		cleaned := filepath.Clean(path)
		if !filepath.IsAbs(cleaned) || strings.Count(cleaned, "/") < 2 {
			return fmt.Errorf("refusing root RemoveAll of unsafe path %q", path)
		}
		return sys.RemoveAll(cleaned)
	}
	// The record decides whether this Mac has a datavol daemon to tear down. It
	// is read BEFORE the manifest is built, for the same reason Install reads
	// it first: the manifest carries the datavol plist only when there is one,
	// and a teardown that did not know about it would leave a root LaunchDaemon
	// pointing at a deleted binary -- the exact leak the shared manifest exists
	// to prevent. The record itself, the fstab line and the volume all STAY.
	st, sterr := dataroot.Read(cfg.DataRootFS, cfg.DataRoot)
	if sterr != nil {
		cfg.Logger.Warn("could not inspect the data root; the data-volume daemon is not torn down", "path", cfg.DataRoot, "err", sterr)
	}
	cfg.dataVolumeDeclared = st.Volume != nil

	// Whatever is actually on this Mac, not merely what this Config describes:
	// uninstall tears down the role it was asked about AND the other role's
	// daemon when that one's plist is on disk. A node changes role by
	// uninstalling and installing again, and an uninstall that swept only the
	// default role would leave the other one's KeepAlive plist behind pointing
	// at a deleted binary — the exact leak the shared manifest exists to prevent.
	m := uninstallManifest(sys, cfg)
	if preflight != nil {
		if err := preflight(m, st, sterr); err != nil {
			return m, err
		}
	}
	// Leave the cluster BEFORE anything local is torn down. Everything the call
	// depends on is alive right now and stops being alive a few lines below: the
	// agent daemon still holds the mesh up, the stored credential is still on
	// disk, and the control plane still has a MeshPeer to delete. It is
	// best-effort and never note()d — a Mac being retired is often being retired
	// because the cluster is gone, and an uninstall that refused to finish over
	// that would leave the operator with a half-installed machine.
	deregisterServer(ctx, sys, cfg, m)
	deregisterNode(ctx, cfg, m)
	for i := len(m) - 1; i >= 0; i-- {
		a := m[i]
		switch a.disp {
		case dispPreserve:
			// Deliberately kept — DataRoot, the human kubeconfig, the _k3sm user, LogDir.
			continue
		case dispInstallDirCovered:
			// Removed by the single RemoveAll(InstallDir) sweep below; skip to avoid
			// a redundant double-remove.
			continue
		case dispRemove:
			if a.kind == kindDaemon {
				// Uninstall never touches the label's enabled/disabled bit
				// (no launchctl enable or disable): it removes only what
				// install created, and a disable is the operator's own act.
				//
				// Bootout then remove the plist — binding them so a booted-out label
				// can never leave a leaked KeepAlive plist. But if
				// bootout returns a real error (not the idempotent not-loaded case,
				// which returns nil), the root job may still be loaded — do not delete
				// its plist definition (that would orphan a live root job until reboot,
				// a variant of the same leak). Record the error and leave the plist.
				if err := sys.LaunchctlBootout(a.label); err != nil {
					note(err)
					continue
				}
				note(safeRemove(a.path))
			} else if a.kind == kindSymlink {
				// The launcher link lives OUTSIDE the trees k3sm owns, so it is
				// removed by identity, not by path: only a symlink still pointing
				// at this install's binary is ours. A regular file, a directory, or
				// a link someone re-pointed is left exactly where it is — an
				// uninstall that deleted it would be deleting another tool's
				// launcher. safeRemove is deliberately NOT the mechanism here: it
				// removes a path, and the question is what the path IS.
				removed, err := sys.RemoveSymlink(a.path, a.target)
				if err != nil {
					note(err)
					continue
				}
				if !removed {
					if exists, perr := sys.PathExists(a.path); perr == nil && exists {
						cfg.Logger.Info("link kept: not ours", "path", a.path, "expected-target", a.target)
					}
				}
			} else {
				note(safeRemove(a.path))
			}
		}
	}
	// Stop every pod process group the runtime recorded. The node daemon's own
	// shutdown leaves native pods running on purpose (a restart re-attaches to
	// them), so after its bootout above they are the one thing still running
	// k3sm workloads, and a reinstall would re-attach to them. It runs here,
	// after every daemon is booted out (none is left to start a replacement),
	// and reads the records from the data root, which uninstall preserves.
	note(teardownPodGroups(ctx, sys, cfg))
	// Backstop: reap any control-plane children that outlived the booted-out
	// server daemon (a Stop() cut short by launchd's SIGKILL, or a crash). They
	// run out of <DataRoot>/server/bin and would otherwise hold the apiserver/
	// kine ports + the SQLite DB, breaking the next install.
	note(sys.ReapOrphans(filepath.Join(cfg.serverWorkDir(), "bin")))
	// Backstop: flush the pf anchor an older release loaded the mesh MSS clamp
	// into. Nothing loads it now, so this only clears what an older release left
	// behind, which would outlive netd scoped to a utun that is gone.
	note(sys.FlushMeshPFAnchor())
	// Backstop: flush the k3sm-owned lo0 aliases. They are durable kernel state
	// no daemon removes on the way out — netd tracks per-connection alias caps
	// (not cleanup), the server's pod teardown misses anything a failed run
	// leaked, the Service VIP aliases (API + DNS VIPs) live for the daemon's
	// lifetime, and the node's own mesh-egress .1 is outside the pod
	// stale-sweep range. Scope: the pinned cluster pod aggregate + the Service
	// CIDR — exactly the address space k3sm ever aliases (never the host's own
	// addresses). Uninstall runs as root, so this is direct ifconfig, no helper.
	flush := []netip.Prefix{podnet.ClusterPodCIDR}
	if svc, err := netip.ParsePrefix(cfg.ServiceCIDR); err == nil {
		flush = append(flush, svc)
	}
	note(sys.FlushLo0Aliases(flush))
	if firstErr != nil {
		return m, fmt.Errorf("uninstall: %w", firstErr)
	}
	cfg.Logger.Info("k3sm uninstalled", "install-dir", cfg.InstallDir)
	if cfg.Purge {
		// Nothing is kept: the purge removes it next and says what it removed.
		return m, nil
	}
	// What was KEPT, named. An uninstall that lists only what it removed leaves
	// the operator guessing whether their datastore, their kubeconfig and the
	// server flags they configured are still there — and guessing wrong in the
	// safe direction means restoring a backup nobody needed to take.
	cfg.Logger.Info("kept, so a reinstall picks up where you left off: "+strings.Join(keptArtifacts(cfg, m), ", "),
		"remove-the-carried-arguments", "sudo rm "+cfg.argsRecordPath())
	if st.Volume != nil {
		// The volume is data, not an artifact: it holds the datastore, the image
		// blobs and every PersistentVolume, so uninstall leaves it mounted and
		// declared. Saying so -- with both of the commands that act on it next --
		// is the difference between an operator who knows their data is intact and
		// one who goes looking for it with diskutil.
		cfg.Logger.Info(fmt.Sprintf("data volume %s (%s) is kept and mounted at %s", st.Volume.Name, st.Volume.UUID, st.Volume.Mountpoint),
			"reinstall", "sudo k3sm install --data-volume",
			"remove-for-good", "sudo k3sm datavol delete --yes")
	}
	return m, nil
}

// deregisterTimeout is the outer bound on the whole deregistration attempt.
//
// The call itself is already bounded on the wire (bootstrap.DeregisterTimeout),
// so this is the backstop for everything that is not the wire: a DNS lookup that
// hangs, a TLS handshake against a Mac that answers the SYN and nothing else, a
// closure that retries. Fifteen seconds is a pause an operator will wait through
// at a terminal, and a teardown that cannot be delayed longer than that by a
// cluster it is leaving.
const deregisterTimeout = 15 * time.Second

// deregisterRemedy is the command that finishes the job by hand when the
// deregistration could not be delivered. The node name is a placeholder because
// this package does not know it; the error logged beside this line does, because
// the closure that produced it named the node.
const deregisterRemedy = "on the control plane: kubectl delete meshpeer/<node> node/<node>"

// deregisterNode asks the cluster to forget this node, on a WORKER teardown and
// on no other.
//
// The role question is answered from the MANIFEST rather than from cfg.Role, and
// that is what makes `sudo k3sm uninstall` work with no flags: the CLI passes a
// Config that says nothing about which role is installed, and uninstallManifest
// has already read the disk to find out. A Mac carrying the agent daemon is a
// worker, whatever the Config claims.
//
// Every failure is one Warn line carrying the error and the manual remedy, and
// then the teardown continues. The nil closure — a server, or a worker with no
// usable credential — is silent here: the CLI has already said why it passed
// nothing, and repeating it from a package that does not know the reason would
// only guess.
func deregisterNode(ctx context.Context, cfg Config, m []artifact) {
	if cfg.Deregister == nil || !carriesAgentDaemon(m) {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, deregisterTimeout)
	defer cancel()
	if err := cfg.Deregister(ctx); err != nil {
		cfg.Logger.Warn("could not remove this node from the cluster; it will still be listed there, and its peers will keep a wireguard entry for it until it is deleted",
			"err", err, "remedy", deregisterRemedy)
		return
	}
	cfg.Logger.Info("removed this node from the cluster: its MeshPeer and Node are gone, so the remaining nodes drop their wireguard entry for it")
}

// serverDeregisterRemedy is what the servers that stay do when this server's etcd
// member could not be removed: with the member still registered, a two-server
// cluster has lost its quorum the moment this daemon stops.
const serverDeregisterRemedy = "on the surviving server run: sudo launchctl bootout system/" + ServerLabel +
	" && sudo k3sm server --cluster-reset --work-dir <its work dir> --node-ip <its node IP>, then start it again; or, while the cluster still has quorum, remove the member from a surviving server"

// deregisterServer removes this server's etcd member before the teardown stops it,
// on a server whose installed plist selects the embedded-etcd posture and on no
// other. The posture is read from the plist on disk (as the role is read from the
// manifest), so `sudo k3sm uninstall` needs no flags. A plist that cannot be read or
// parsed says nothing about the posture, so nothing is attempted.
func deregisterServer(ctx context.Context, sys System, cfg Config, m []artifact) {
	if cfg.DeregisterServer == nil || !carriesServerDaemon(m) {
		return
	}
	raw, err := sys.ReadFile(cfg.plistPath(ServerLabel))
	if err != nil {
		return
	}
	args, err := parseProgramArguments(raw)
	if err != nil || !carriesEtcdPosture(args) {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, deregisterTimeout)
	defer cancel()
	if err := cfg.DeregisterServer(ctx); err != nil {
		cfg.Logger.Warn("could not remove this server's etcd member from the cluster; the servers that stay still count it toward quorum",
			"err", err, "remedy", serverDeregisterRemedy)
		return
	}
	cfg.Logger.Info("removed this server's etcd member from the cluster; the remaining servers no longer count it toward quorum")
}

// adminLoopbackHost is the apiserver address the admin kubeconfig uses on a
// single-node install: the loopback the control plane binds when no mesh IP is
// configured. A mesh install overrides it with the mesh IP — see AdminKubeconfig.
const adminLoopbackHost = "127.0.0.1"

// apiServerSelfSignedCertPath is the serving certificate the SINGLE-NODE apiserver
// self-signs into its own --cert-dir. The basename is kube-apiserver's own fixed
// choice; the directory is executor.APIServerCertDir, which is also the
// controller-manager's --root-ca-file source on that posture. The file holds the
// leaf followed by the self-signed CA that issued it, which is what makes it usable
// as a trust anchor. cmd/k3sm names the same file for its post-rotation health probe
// (apiServerTrustAnchor).
//
// NOT certs.APIServerServingCertPath: that is the mesh path's cluster-CA-signed leaf
// under the PKI dir, re-issued on every boot, and the apiserver only presents it when
// a serving keypair was supplied.
func apiServerSelfSignedCertPath(workDir string) string {
	return filepath.Join(executor.APIServerCertDir(workDir), "apiserver.crt")
}

// readLoopbackAnchor reads the trust anchor for the single-node loopback apiserver
// endpoint into cfg.LoopbackCA, so the admin kubeconfig VERIFIES the listener it
// talks to instead of trusting whatever answers on the port.
//
// That matters because the apiserver's port is bindable by any unprivileged local
// user (the control plane itself runs as the unprivileged service user), so a
// kubeconfig carrying insecure-skip-tls-verify hands the admin bearer token to
// whoever holds the port during an outage, and accepts that impostor's readiness.
//
// Two conditions keep the old skip-verify posture, because both describe a pin that
// would break kubectl rather than secure it, and an install that cannot talk to its
// own cluster is worse than an unverified one:
//
//   - the file is absent — a first install, before the control plane has ever
//     booted and self-signed. The next `k3sm install` picks it up.
//   - its leaf does not name the loopback address, so a verifying client would
//     reject the connection on the SAN check before trust ever came into it.
func readLoopbackAnchor(sys System, cfg *Config) error {
	path := apiServerSelfSignedCertPath(cfg.serverWorkDir())
	anchor, err := sys.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		cfg.Logger.Warn("the apiserver has not self-signed its serving certificate yet; admin kubeconfig keeps insecure-skip-tls-verify until the next install", "path", path)
		return nil
	case err != nil:
		return fmt.Errorf("install: read apiserver serving certificate %s: %w", path, err)
	}
	if !certPEMHasIPSAN(anchor, adminLoopbackHost) {
		cfg.Logger.Warn("the apiserver's serving certificate does not name the loopback address; admin kubeconfig keeps insecure-skip-tls-verify rather than pin an anchor kubectl could not connect through", "path", path, "missing-ip-san", adminLoopbackHost)
		return nil
	}
	cfg.LoopbackCA = anchor
	return nil
}

// certPEMHasIPSAN reports whether the LEAF in pemBytes carries ip among its IP SANs.
//
// The leaf is the FIRST certificate block: that is the order kube-apiserver writes
// its self-signed pair in (leaf, then the CA that issued it), and it is the
// certificate a TLS client is presented and checks its address against. Only that
// one certificate can answer the question asked — "does what this listener presents
// name the address the kubeconfig is about to name". A trailing CA block carrying
// the address would be an anchor, never the presented identity, and letting it
// answer yes would pin a file through which kubectl still fails the SAN check.
//
// Anything unparseable answers NO: a certificate this cannot read is one the caller
// must not pin, and the caller's fallback is the safe-but-unverified posture.
func certPEMHasIPSAN(pemBytes []byte, ip string) bool {
	want := net.ParseIP(ip)
	if want == nil {
		return false
	}
	for rest := pemBytes; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return false
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		crt, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return false
		}
		return slices.ContainsFunc(crt.IPAddresses, want.Equal)
	}
	return false
}

// AdminKubeconfig renders the admin kubeconfig (the apiserver's EFFECTIVE
// address + the shared static token) written to the human's home so `kubectl`
// works once the server is up.
//
// Two postures, selected by whether the preserved server arguments carry a
// --mesh-ip (Config.meshIP):
//
//   - MESH: the apiserver binds its wireguard IP ONLY and serves a
//     cluster-CA-signed leaf. The URL is that IP — a loopback URL addresses
//     nothing, which is how a multi-node install shipped an admin kubeconfig that
//     could not connect at all — and the cluster CA (Config.ClusterCA, read off
//     disk by Install) is pinned as certificate-authority-data so the connection
//     is actually verified. An absent CA falls back to skip-verify, because a
//     first install writes this file before the control plane has minted one.
//   - SINGLE-NODE: loopback, and the certificate the apiserver SELF-SIGNS into its
//     own --cert-dir (Config.LoopbackCA, read off disk by Install) pinned as
//     certificate-authority-data. No cluster CA anchors that listener, but the
//     self-signed file holds the leaf and its issuing CA, so it anchors itself. The
//     loopback port is bindable by any unprivileged local user, so an unverified
//     kubeconfig there would surrender the admin bearer token to whatever holds the
//     port while the control plane is down. An absent or non-loopback-SAN anchor
//     falls back to skip-verify, for the same first-install reason as the mesh case.
func AdminKubeconfig(cfg Config) []byte {
	cfg = cfg.withDefaults()
	host := adminLoopbackHost
	clusterTLS := "    insecure-skip-tls-verify: true"
	anchor := cfg.LoopbackCA
	if mesh := cfg.meshIP(); mesh != "" {
		host = mesh
		anchor = cfg.ClusterCA
	}
	if len(anchor) > 0 {
		clusterTLS = "    certificate-authority-data: " + base64.StdEncoding.EncodeToString(anchor)
	}
	server := "https://" + net.JoinHostPort(host, strconv.Itoa(cfg.APIServerPort))
	return []byte(fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: k3sm
  cluster:
    server: %q
%s
contexts:
- name: k3sm
  context:
    cluster: k3sm
    user: admin
current-context: k3sm
users:
- name: admin
  user:
    token: %s
`, server, clusterTLS, cfg.AdminToken))
}

// generateToken returns a random hex bearer token for the admin kubeconfig +
// server LaunchDaemon.
func generateToken() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate admin token: %w", err)
	}
	return "k3sm-" + hex.EncodeToString(buf), nil
}
