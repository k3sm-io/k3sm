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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"k3sm.io/darwin-net/pkg/podnet"
	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/datavol"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/nodecred"
	"k3sm.io/k3sm/pkg/provider/podlogs"
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

// Default install locations.
const (
	// DefaultServiceUser is the unprivileged, no-login system user the control
	// plane, node, runtimed, and Service proxy all run as.
	DefaultServiceUser = "_k3sm"
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
	// PathShimName is the basename of the path-rebase DYLD shim (runtimed's
	// shim/pathrebase_shim.c) installed beside the binary. runtimed resolves it
	// next to the executable and injects it into a mounting pod so an absolute
	// volume mount resolves under the pod data volume (no chroot).
	PathShimName = "libk3sm_pathrebase_shim.dylib"
	// DNSShimName is the basename of the getaddrinfo DNS shim (darwin-net's
	// shim/getaddrinfo_shim.c) installed beside the binary. The provider resolves it
	// next to the executable and injects it into each pod (DYLD_INSERT_LIBRARIES) so
	// an in-pod cluster-name lookup goes to the per-node resolver on the DNS VIP;
	// without it a pod uses the system resolver and cluster names are NXDOMAIN.
	DNSShimName = "libk3sm_getaddrinfo_shim.dylib"
	// DefaultLaunchDaemonDir is where the two .plist files are written.
	DefaultLaunchDaemonDir = "/Library/LaunchDaemons"
	// DefaultDataRoot is the _k3sm-owned data root (the _k3sm home): the
	// control-plane work-dir, runtimed pods/storage/image cache live under it.
	DefaultDataRoot = "/var/lib/k3sm"
	// DataRootMode and DataRootGID are the ownership POLICY for the data root:
	// service-user-owned, group staff (the service user's primary group), 0750.
	// They are named because two daemons apply them — `k3sm install` when it
	// creates the root, and the netd helper when it finds one that has drifted —
	// and a second literal would let those two answers diverge.
	DataRootMode fs.FileMode = 0o750
	DataRootGID  int         = 20
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
	// DefaultServiceCIDR is the cluster Service CIDR the netd daemon pins so the
	// proxy's ClusterIP VIP aliases are admitted.
	DefaultServiceCIDR = "10.43.0.0/16"
	// MeshKeyDir is the directory the netd MeshKeyResolver reads the node's
	// wireguard private key from. It lives inside the run dir, whose owner is the
	// service user — see EnsureRunDir for what that ownership does and does not
	// fence off.
	MeshKeyDir = DefaultRunDir + "/keys"
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
	// The group is `admin` and deliberately NOT the `staff` of DataRootGID.
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
	// DatastoreEndpointFileMode is the mode of the staged HA datastore DSN, the
	// other credential the control-plane daemon is handed as a file. Stated
	// separately from ServerTokenFileMode for the reason that one is stated
	// separately from the agent's: it is a decision about a different file, whose
	// contents are the OPERATOR's Postgres password rather than a token k3sm
	// minted, and the two may move independently. The directory is the server
	// work dir, so its mode is ServerTokenDirMode's — one directory, one answer.
	DatastoreEndpointFileMode fs.FileMode = 0o600
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
	// datastoreEndpointName is the leaf name of the staged HA datastore DSN,
	// beside the admin token in the server work dir for the same reason: what a
	// daemon must read lives in that daemon's own state tree.
	datastoreEndpointName = "datastore-endpoint"
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
	// parent of the vm guest-agent socket dir and the mesh key dir.
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
	// creates netd.sock and reads MeshKeyDir inside a directory the service user
	// owns (root bypasses the mode), so _k3sm — the control plane, which already
	// drives netd over that socket — can rename or replace either. That is a
	// smaller trust surface than it looks (netd takes its orders from _k3sm
	// regardless), and it is the price of the service user owning the one
	// directory it must write in; per-uid isolation is the vm RuntimeClass's job,
	// not this directory's.
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
	// It is the ONE directory under the run dir that is NOT handed to the service
	// user, which is why it has its own method rather than riding EnsureRunDir's:
	// the two answers must not be able to drift into one. Its parent is
	// service-user-owned (EnsureRunDir), so a root-owned child inside it is
	// exactly what the mode has to say, and re-applying owner and mode on every
	// install repairs a directory an earlier build — or the daemon's own
	// best-effort runtime write — left at looser terms.
	//
	// The mode is a PARAMETER for WriteServiceUserFile's reason: the policy a
	// caller applied is then visible at the seam, and a unit test can assert it
	// without a real filesystem or privilege.
	EnsureMeshKeyDir(dir string, mode fs.FileMode) error
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
	// --remove-old-data-root), so a future change to either caller's guarding
	// cannot silently widen the other's.
	RemoveTree(path string) error
	// LookupServiceUID resolves the named service account's uid, reporting
	// false when the account does not exist yet. It is three-valued in
	// practice: install may run BEFORE EnsureServiceUser has created _k3sm, and
	// a data volume mounted at that moment is left to root rather than chowned
	// to a uid nobody has been assigned.
	LookupServiceUID(name string) (int, bool)
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
	// FileMode reports the permission bits of the file at path, with ReadFile's
	// missing-file contract (an error satisfying errors.Is(err, fs.ErrNotExist)).
	// The installer needs it for exactly one judgement: whether the operator's
	// join token file is readable by anyone but its owner.
	FileMode(path string) (fs.FileMode, error)
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
	// The mesh key's work-dir copy lives under the service-user-owned data root,
	// and install reads it AS ROOT and copies its bytes into a root-only
	// directory. With an ordinary read, the service uid could replace that file
	// with a symlink to anything on the Mac and have root copy the target out for
	// it — a confused-deputy read that hands the attacker's own uid nothing, but
	// hands root's reach to whatever it points at. The refusal, not the mode, is
	// what closes that: the file is opened O_NOFOLLOW and its type checked on the
	// open descriptor, so there is no window between the check and the read.
	ReadRegularFile(path string) ([]byte, error)
	// ReadFile reads a root-readable file: the installed server plist, whose
	// operator-supplied arguments a reinstall must carry over; the
	// server-arguments record that carries those same arguments when no plist
	// survives; and the cluster CA the admin kubeconfig pins. A missing file
	// returns an error satisfying errors.Is(err, fs.ErrNotExist), which callers
	// treat as a POSTURE rather than a failure — an absent plist sends the
	// carry-over to the record, an absent record means there is nothing to carry,
	// and a FIRST install has none of the three.
	ReadFile(path string) ([]byte, error)
	// LaunchctlBootstrap loads the labelled daemon into the system domain.
	LaunchctlBootstrap(label string) error
	// LaunchctlBootout unloads the labelled daemon (idempotent: a not-loaded
	// label is a no-op success).
	LaunchctlBootout(label string) error
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
	// FlushMeshPFAnchor is the uninstall backstop for the mesh's MSS-clamp pf
	// anchor (darwin-net's mesh.PFAnchor, "io.k3sm.mesh"), which outlives netd:
	// the anchor is loaded against a utun interface number, and only the
	// RemoveMesh RPC — not a daemon shutdown — ever reaches mesh.WGDevice.Down,
	// which flushes it. Left in place, the rule survives the booted-out daemon
	// scoped to a utun that no longer exists, and macOS recycles utun numbers —
	// so the next tunnel that is assigned that same number silently inherits a
	// stale MSS clamp. Best-effort like FlushLo0Aliases: an anchor that was
	// never loaded is a no-op (pfctl succeeds flushing zero rules), and a
	// pfctl failure is reported but never stops the rest of uninstall.
	FlushMeshPFAnchor() error
}

// Config parametrizes Install/Uninstall. Empty fields take the Default* values.
type Config struct {
	// Role is which node this Mac becomes: the control plane (RoleServer, the
	// zero value) or a worker joining an existing cluster (RoleAgent). It
	// selects which node daemon the manifest carries and which arguments record
	// is written; everything else install lays down is identical, because a
	// worker runs the same binary, the same shims and the same netd helper.
	Role Role
	// JoinServer is the control-plane host a RoleAgent node joins — an UNDERLAY
	// address, because the join dials <host>:9345 before this node has any mesh
	// to route over. Required for RoleAgent, ignored otherwise.
	JoinServer string
	// NodeIP is an OPTIONAL assertion of the joining worker's own mesh
	// InternalIP. The control plane assigns that address and issues the node's
	// certificates for it, so a worker needs none; when set it is rendered onto
	// the daemon's argv and the join refuses a value that differs from the
	// assignment. Ignored outside RoleAgent.
	NodeIP string
	// TokenFile is the OPERATOR's join-token file, read once by Install (which
	// is root) and copied to agentTokenPath() for the daemon. It is not what the
	// daemon reads and is never named on its argv: the operator's file is
	// root-only by construction, and the service user the agent runs as could
	// not open it.
	//
	// It is optional. A node that has already joined starts from its stored
	// credential and needs no token at all, so a reinstall with no --token-file
	// stages nothing and leaves whatever is already there.
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
	// kubectl + kine) staged by `k3sm payload <dir>`. Install copies it to
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
	// (VerifyVirtualizationEntitlement, run immediately before the copy). Without
	// that gate a dev helper built with a plain `go build` installs unentitled and
	// the consequence surfaces nowhere near the cause: runtimed withholds
	// VMBackendAvailable, the server deletes the node's k3sm.io/virtualization
	// label, and every vm-RuntimeClass pod stays Pending behind the RuntimeClass's
	// own node selector — reported only as "didn't match node affinity/selector".
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
	// /Library/Preferences, deliberately NOT the _k3sm-owned data root; see that
	// constant for the privilege reason. A test points it at a scratch file.
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
	// DataRootFS is the read-only filesystem the data-root posture is read
	// through (the record, /etc/fstab, the mount state). It defaults to the real
	// filesystem; a test injects a fake so the sequencing can be exercised
	// against a mount posture no unprivileged process could create.
	DataRootFS dataroot.FS
	Logger     *slog.Logger
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
func (c Config) resolvedExtraServerArgs() []string {
	if c.MeshIP == "" {
		return c.ExtraServerArgs
	}
	return setMeshIPArg(c.ExtraServerArgs, c.MeshIP)
}

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

// legacyAgentArtifacts is the FIXED table of leaf names the agent work dir is
// known to hold: the five artifacts of a stored node credential, plus the three
// this package and cmd/k3sm name themselves.
//
// The credential names come from nodecred.Store rather than being retyped, so
// the directory the installer repairs and the directory the daemon reads can
// never disagree about what lives in it. The dir value is irrelevant — only the
// leaf names are taken.
func legacyAgentArtifacts() map[string]bool {
	store := nodecred.Store{Dir: "."}
	known := make(map[string]bool, len(store.Paths())+3)
	for _, p := range store.Paths() {
		known[filepath.Base(p)] = true
	}
	for _, name := range []string{agentNodePasswordName, agentMeshKeyName, agentTokenName} {
		known[name] = true
	}
	return known
}

// serviceCanRead reports whether the service user can open e.
//
// Three ways, and the middle one is the trap this predicate exists to avoid.
// The owner can always read its own 0600 file. An other-read bit lets everyone
// read it, the service user included. A GROUP-read bit only helps when the group
// is one the service user is IN — and the only group this installer can assert
// that about is DataRootGID (staff), the service user's primary group. A
// root:wheel 0640 file carries a group-read bit and is still unreadable to
// _k3sm, so a predicate that took any group-read bit as "readable" would wave
// exactly the file an operator most needs to be told about straight through.
func serviceCanRead(e OwnedEntry, svcUID, svcGID int) bool {
	switch {
	case e.UID == svcUID:
		return true
	case e.Mode&0o004 != 0:
		return true
	case e.Mode&0o040 != 0 && e.GID == svcGID:
		return true
	}
	return false
}

// adoptLegacyAgentFiles hands the agent work dir and the known artifacts inside
// it to the service user, on a reinstall over a worker that was installed before
// the node daemon moved from root to _k3sm.
//
// This is a MIGRATION to the posture a fresh install already produces — service
// uid, group staff, the mode untouched, which is exactly what
// WriteServiceUserFile writes the staged join token at — and NOT a widening of
// anything. Nothing becomes readable to an account that could not read it
// before: every file involved is 0600 both before and after, and the mode is
// carried across verbatim rather than re-decided. What changes is only WHICH
// single uid the 0600 names, from root to the unprivileged user the daemon now
// runs as.
//
// Without it, such a node crash-loops: `k3sm agent` starts as _k3sm, finds a
// root-owned 0600 node-password it cannot rewrite, and dies on "persist
// node-password: permission denied" — with the same fate waiting behind it for
// the mesh key and the node credential. Only root can hand those files over and
// only the installer runs as root, which is why this is an install step and not
// something the node does for itself at start-up (the reasoning EnsureRunDir and
// EnsureContainerLogDir already record for their own directories).
//
// Three limits, all deliberate:
//
//   - Only the entries in legacyAgentArtifacts are adopted. A file k3sm does not
//     recognise is never chowned, because giving an unknown file to the service
//     user IS the widening this function is careful not to be.
//   - An unrecognised regular file the service user cannot read REFUSES the
//     install, before a single chown happens. It would otherwise be a silent
//     landmine: the daemon may need it, nothing here can know, and an install
//     that reported success over it would hand back the crash-loop it was run to
//     fix. The operator is told the file and both remedies.
//   - An entry under one of the KNOWN names that is not a regular file refuses
//     the install too. An adoption is decided about a name and applied to what
//     the name resolves to, so a symlink standing in for node.key is not a file
//     to hand over.
//   - Nothing is walked. Subdirectories are not descended into and not judged:
//     this is the five-artifact credential directory, not a tree.
//
// The chowns are ordered files-first, directory-last, so the service user never
// owns the directory while a root-owned artifact inside it is still pending.
func adoptLegacyAgentFiles(sys System, cfg Config, uid uint32) error {
	dir := cfg.agentWorkDir()
	svcUID, svcGID := int(uid), DataRootGID
	self, err := sys.Owner(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// No work dir yet: a first install, or one whose token staging is still
		// to create it. Nothing to migrate.
		return nil
	case err != nil:
		return fmt.Errorf("install: inspect the agent work dir %s: %w", dir, err)
	case self.Kind != EntryDir:
		return fmt.Errorf("install: the agent work dir %s is not a directory: the agent daemon keeps this node's credential there, so move whatever is at that path aside before reinstalling", dir)
	}
	entries, err := sys.ListOwned(dir)
	if err != nil {
		return fmt.Errorf("install: list the agent work dir %s: %w", dir, err)
	}

	// Two passes, and the split is the contract: everything is CLASSIFIED before
	// anything is changed, so a refusal leaves the directory exactly as it was
	// found rather than half-migrated.
	known := legacyAgentArtifacts()
	var adopt []OwnedEntry
	var unreadable, notRegular, ignored []string
	for _, e := range entries {
		switch {
		case known[filepath.Base(e.Path)]:
			switch {
			case e.Kind != EntryRegular:
				notRegular = append(notRegular, fmt.Sprintf("%s (%s)", e.Path, e.Kind))
			case e.UID == 0 && svcUID != 0:
				adopt = append(adopt, e)
			}
		case e.Kind != EntryRegular:
			// A subdirectory, a symlink, a socket under a name k3sm does not
			// claim: not this step's business, and never chowned.
		case !serviceCanRead(e, svcUID, svcGID):
			unreadable = append(unreadable, e.Path)
		default:
			ignored = append(ignored, e.Path)
		}
	}
	// The known-name-wrong-kind refusal comes first because it is the sharper
	// one. An adoption is a decision made about a NAME and applied to whatever
	// that name resolves to; a symlink at node.key, plantable by anything that
	// can write in this directory, would aim a root-run chown at a file
	// somewhere else on the Mac. Lchown means the link itself would move rather
	// than its target, so this is a refusal out of caution rather than a repair
	// of a live escalation — but "the artifact k3sm was about to hand over is
	// not the artifact" is never something to continue past.
	if len(notRegular) > 0 {
		return fmt.Errorf("install: the agent work dir %s holds an entry under one of this node's own state file names that is not a regular file; remove it and let the agent write its state afresh: %s — k3sm hands ownership of a state file to %s, never of something standing in for one",
			dir, strings.Join(notRegular, ", "), cfg.ServiceUser)
	}
	if len(unreadable) > 0 {
		return fmt.Errorf("install: the agent work dir %s holds file(s) the %s service user the node daemon runs as cannot read, and k3sm does not recognise them: %s — `sudo chown %s <file>` if the file belongs to this node's agent, or remove it if it is not k3sm's; k3sm will not hand a file it cannot account for to the service user on its own",
			dir, cfg.ServiceUser, strings.Join(unreadable, ", "), cfg.ServiceUser)
	}
	for _, path := range ignored {
		// The PATH only, never a byte of the file: an unrecognised file in a
		// credential directory is exactly the thing not to echo into a log. It is
		// still worth one line each, because "k3sm saw this and chose to leave it"
		// is the record an operator needs when they later wonder why it was not
		// repaired.
		cfg.Logger.Info("left an unrecognised file in the agent work dir alone: the service user can already read it, and k3sm does not adopt files it cannot account for", "path", path)
	}
	// The files FIRST and the directory LAST. In between, the directory is still
	// root's while its contents move — never the reverse. Handing the directory
	// over first would give the service user a 0700 directory it owns (and so
	// may rename or unlink within) for the duration of the remaining chowns,
	// while root-owned artifacts inside were still pending; ending with the
	// directory means that window does not exist.
	if self.UID == 0 && svcUID != 0 {
		adopt = append(adopt, self)
	}
	for _, e := range adopt {
		if err := sys.Chown(e.Path, svcUID, svcGID); err != nil {
			return fmt.Errorf("install: hand the agent state %s over to %s (uid %d): %w", e.Path, cfg.ServiceUser, svcUID, err)
		}
	}
	if len(adopt) > 0 {
		paths := make([]string, len(adopt))
		for i, e := range adopt {
			paths[i] = e.Path
		}
		cfg.Logger.Info("adopted agent state left root-owned by an install that predates the service user (the mode is unchanged; only the uid the 0600 names moves)",
			"user", cfg.ServiceUser, "uid", svcUID, "paths", strings.Join(paths, ","))
	}
	return nil
}

// podLogWalkMaxDepth bounds the pod-log adoption walk below the tree's root.
// The layout podlogs defines is exactly
// <root>/<ns>_<pod>_<uid>/<container>/<n>.log — three levels — so this bound is
// never reached by a tree k3sm itself wrote, and it is what keeps a walk run as
// root from descending forever into whatever a hand-run mkdir, a half-finished
// restore, or a rotation tool left behind. It bounds DEPTH rather than entries
// because the walk never follows a symlink: the only way down is for the
// directories to really be there.
const podLogWalkMaxDepth = 8

// AdoptPolicy says which entries at the TOP level of a tree AdoptTree may hand
// over. It exists because k3sm's two container-log directories have opposite
// rules about the one entry kind that matters, and neither rule is safe to apply
// to the other directory.
type AdoptPolicy int

const (
	// AdoptPodDirs is /var/log/pods: at the top level ONLY a directory whose
	// name has the <ns>_<pod>_<uid> shape podlogs writes is adopted, and then
	// everything inside it recursively (directories and regular files). A
	// symlink is never adopted and never descended into, at any level.
	//
	// It is the ZERO value so that a policy nobody set is the conservative one.
	AdoptPodDirs AdoptPolicy = iota
	// AdoptLogLinks is /var/log/containers: a FLAT directory of symlinks, which
	// is the one place a symlink is the artifact rather than an intruder — a log
	// shipper globs them and the node has to be able to replace them. They are
	// adopted with an lchown, so the link moves and its target is never touched,
	// and nothing is descended into.
	AdoptLogLinks
)

// SkippedEntry is one entry an adoption walk stepped over, and why — the record
// the installer turns into a line for the operator. It carries the PATH only:
// a log directory's name is namespace/pod/container, which the operator already
// knows, and nothing here ever reads a byte of a pod's output.
type SkippedEntry struct {
	Path   string
	Reason string
}

// TreeAdoption is what one AdoptTree walk did: how many entries it handed over,
// and every entry it did not.
//
// The skipped entries are RETURNED rather than logged inside the seam, because
// the seam performs syscalls and this package decides what an operator is told.
// The count is separate from len(Skipped) for nobody's benefit but the caller's
// summary line.
type TreeAdoption struct {
	Adopted int
	Skipped []SkippedEntry
}

// podLogDirName mirrors the pod-log directory name
// podlogs.BuildPodLogsDirectory writes: <namespace>_<pod>_<uid>, where the
// namespace and the pod name are DNS-1123 names (so neither can contain the `_`
// delimiter) and the uid is a Kubernetes UID.
//
// podlogs exports a parser (ParsePodUIDFromLogsDirectory) but not a validator —
// it answers "the last field" for any string at all, including one with no
// delimiter — so the shape is re-stated here as the smallest thing that can say
// NO. It is deliberately a shape check and not a lookup against live pods: the
// tree is full of directories whose pods are long gone, and adopting only the
// pods currently scheduled here would leave exactly the debris an operator
// cannot clean up.
var podLogDirName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?_[a-z0-9]([-a-z0-9.]*[a-z0-9])?_[A-Za-z0-9-]+$`)

// isPodLogDirName reports whether name is one of this node's own pod log
// directories. Getting it wrong in either direction is survivable and neither
// direction is silent: a genuine directory rejected here is reported to the
// operator and left root-owned, and debris accepted here is chowned inside a
// tree the service user already owns the root of. What it buys is that a
// root-run walk descends only into the shape k3sm itself writes.
func isPodLogDirName(name string) bool { return podLogDirName.MatchString(name) }

// adoptPodLogTree hands the per-pod log directories an OLDER install left
// root-owned over to the service user, on a reinstall over a node whose daemon
// once ran as root.
//
// It is adoptLegacyAgentFiles' sibling for the one tree that step deliberately
// does not touch, and it closes the failure that survived it: the log-dir step
// above chowns the ROOT of the tree, and only the root, so a node whose
// root-era daemon had already created <root>/<ns>_<pod>_<uid> directories
// (0700, root-owned) came back up as _k3sm and failed every CreatePod with
//
//	failed to create container log directory
//	/var/log/pods/<ns>_<pod>_<uid>/<container>: permission denied
//
// — a per-pod directory it can traverse to and not write in. Only root can hand
// those directories over and only the installer runs as root, which is the same
// reason EnsureContainerLogDir is an install step rather than something the node
// does for itself.
//
// This is a MIGRATION to the posture a fresh install already produces — service
// uid, group wheel (ContainerLogDirGID), the mode carried across verbatim — and
// widens nothing: a 0700 directory is readable by exactly one account before and
// after, and what moves is which uid that is.
//
// Four properties, all deliberate, and all different from the agent work dir's:
//
//   - The walk is performed by the System seam, DESCRIPTOR-relative (see
//     AdoptTree). Pods are running as the service user throughout an install,
//     so a path re-resolved after it was classified is a path something else
//     can have replaced in between.
//   - It NEVER refuses the install. The tree is GC-pending debris by nature —
//     pkg/provider/podlogs GC is its sole deleter and runs asynchronously — so
//     an unreadable directory or an entry k3sm cannot account for is reported
//     and stepped over, not turned into a failed install of an otherwise healthy
//     node.
//   - It DELETES nothing, for the same reason: the GC owns removal, and an
//     installer that also removed would be a second deleter racing it.
//   - It is unconditional across roles, exactly like the EnsureContainerLogDir
//     step it repairs: a single-node server runs pods and writes this same tree.
func adoptPodLogTree(sys System, cfg Config, uid uint32) {
	svcUID := int(uid)
	if svcUID == 0 {
		// Nothing to migrate TO: the service user is root, so the tree already
		// names the account the node runs as.
		return
	}
	trees := []struct {
		root   string
		policy AdoptPolicy
		depth  int
	}{
		{PodLogsDir, AdoptPodDirs, podLogWalkMaxDepth},
		// A flat directory: one level, and the bound says so rather than
		// relying on the policy never to descend.
		{ContainerLogsDir, AdoptLogLinks, 1},
	}
	var adopted, skipped int
	for _, t := range trees {
		rep, err := sys.AdoptTree(t.root, svcUID, ContainerLogDirGID, t.depth, t.policy)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			// A node that has never run a pod has no tree. A posture, not a
			// problem, and not worth a line.
			continue
		case err != nil:
			cfg.Logger.Info("left a container-log directory alone", "path", t.root, "reason", err.Error())
			skipped++
			continue
		}
		for _, s := range rep.Skipped {
			cfg.Logger.Info("left an entry in the container-log tree alone", "path", s.Path, "reason", s.Reason)
		}
		adopted += rep.Adopted
		skipped += len(rep.Skipped)
	}
	if adopted > 0 || skipped > 0 {
		// One line, with counts rather than paths: a node with a long pod
		// history has thousands of entries, and the per-entry lines above are
		// already there for the ones that were NOT adopted.
		cfg.Logger.Info("adopted container-log entries left root-owned by an install that predates the service user (modes unchanged; only the uid the entries name moves)",
			"user", cfg.ServiceUser, "uid", svcUID, "gid", ContainerLogDirGID, "adopted", adopted, "skipped", skipped)
	}
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

// datastoreEndpointPath is where Install stages the HA datastore DSN for the
// control-plane daemon to read: <DataRoot>/server/datastore-endpoint,
// service-user-owned 0600 (see DatastoreEndpointFileMode).
//
// It is serverTokenPath's sibling and exists for the same reason, against a
// credential that is not k3sm's to mint. A Postgres DSN carries a password, and
// rendering it as a VALUE on the server LaunchDaemon's argv published it twice
// over even after B249 narrowed the plist to 0600: `ps` shows a running job's
// arguments to every account on the Mac for the daemon's whole life, and
// launchd echoes them back from its own job description. Neither is affected by
// the plist's mode.
//
// The path is derived rather than configured, exactly as the token's is: it is
// the one path the installer writes and the one path it renders onto the argv.
func (c Config) datastoreEndpointPath() string {
	return filepath.Join(c.serverWorkDir(), datastoreEndpointName)
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

// ErrNotRegularFile is what ReadRegularFile reports for a path that exists but
// is a symlink, a directory, a device or a fifo. It is a sentinel because the
// callers must tell it apart from "absent": absence is a posture (nothing has
// been provisioned yet), while a non-regular file where a key belongs is
// somebody having put it there, and the two lead to opposite actions.
var ErrNotRegularFile = errors.New("not a regular file")

// readMeshKey reads one copy of this node's wireguard identity and returns
// (nil, nil) when that copy does not exist — the only absence this step treats
// as a posture rather than a failure.
//
// Everything else is refused, and refused LOUDLY, because both copies sit in
// directories root does not own outright: the work-dir copy is the service
// user's, and the root-only copy's PARENT is (the run dir). So a file there is
// not automatically this node's identity — it is whatever the last writer put
// there. Two things are therefore checked before any byte is copied anywhere:
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
// What this does NOT buy, stated plainly: MeshKeyDir's PARENT is the run dir,
// which is service-user-owned by necessity (EnsureRunDir), so _k3sm can rename,
// replace or unlink the key dir and anything beneath it. Root ownership here
// protects the key's CONFIDENTIALITY — no other account on the Mac can read the
// bytes — and not its integrity against the one account that already drives
// netd over its socket. Every read below is O_NOFOLLOW and type-checked for
// that reason, and every write is a temp-and-rename, so neither operation can be
// redirected by something planted at the path. Per-uid isolation of that account
// is the vm RuntimeClass's job, not this directory's.
func provisionMeshKey(sys System, cfg Config, uid uint32) error {
	if err := sys.EnsureMeshKeyDir(MeshKeyDir, MeshKeyDirMode); err != nil {
		return fmt.Errorf("install: ensure the root-only mesh key dir %s: %w", MeshKeyDir, err)
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

// linkDirMaxMode is the permission bits a link directory may NOT carry: group or
// other write. A directory anyone in the `admin` group (or any local user) can
// write is a directory in which the launcher can be swapped for something else,
// and the launcher is what a human types.
const linkDirMaxMode = 0o022

// linkDirFacts is what a launcher directory IS, already read off the disk — the
// four properties linkDirVerdict decides on. It exists so that the decision can
// be a pure function of resolved inputs: the Lstat and the euid read stay in the
// darwin System, and every arm of the refusal (including the root-ownership arm,
// which an unprivileged test could not otherwise reach, since it cannot chown a
// temp dir to root) is stated in a table instead of in a live filesystem.
type linkDirFacts struct {
	// UID is the owning uid of the directory.
	UID uint32
	// Mode is the mode Lstat reported; only the permission bits are consulted.
	Mode fs.FileMode
	// IsDir reports whether the path is a directory.
	IsDir bool
	// IsSymlink reports whether the path ITSELF is a symlink — an Lstat question,
	// never a Stat one: a symlink to a trusted directory is not a trusted
	// directory, because whoever can re-point the link chooses the destination.
	IsSymlink bool
	// Absent reports that the judged path is not there at all. It is stated the
	// negative way round so the zero value describes a path that EXISTS, which is
	// every ordinary case; an absent path is routed through the same verdict
	// table as every other refusal rather than escaping as a bare Lstat error,
	// because "no such file or directory" tells an operator nothing about which
	// directory k3sm wanted or what to do about it.
	Absent bool
}

// linkDirVerdict reports whether dir may hold — or, when it is an ancestor,
// may come to hold — the `k3sm` launcher symlink for launcherDir: a REAL
// directory (not a symlink to one), not group- or other-writable, and — when
// euid is 0, the only posture in which the answer is meaningful — owned by root.
//
// dir and launcherDir are the same path in the ordinary case. They differ when
// the launcher directory does not exist yet and linkDirTrustTarget has ESCALATED
// the judgement to its parent — the directory whose permissions decide who could
// create the missing one. That distinction is carried into the message rather
// than left to the reader, because it changes the remedy: telling an operator to
// `remove /usr/local` because /usr/local/bin is missing would be advice to
// delete a base system directory, when what they actually need is to create the
// launcher directory under it.
//
// THE HAZARD, named here because the check has always asserted it without ever
// saying it: the launcher directory sits on ROOT's PATH, and /usr/local/bin
// precedes /usr/bin in the default /etc/paths. A launcher directory some local
// user can write is therefore a directory in which that user can leave a file
// called `k3sm` — and the next `sudo k3sm …`, install script or root-run helper
// that types the bare command executes it as root. That is a local privilege
// escalation k3sm would have created by linking there, which is why this refuses
// rather than warns. It is not hypothetical: on a Mac carrying an Intel-prefix
// Homebrew, /usr/local/bin is owned by the admin user who installed Homebrew
// (and /opt/homebrew/bin is, on an Apple Silicon one), so this is the ordinary
// state of a developer's machine rather than a misconfiguration.
//
// This is also the one deliberate exception to the privilege model's "the binary
// and plist live in /Library/k3sm, never a Homebrew, /usr/local or /Applications
// prefix an `admin`-group member could overwrite" rule (docs/privilege-model.md
// §Root-owned everything). The exception is narrow and is trusted ONLY because
// this check holds: nothing executable is placed in the link directory, only a
// symlink back into the root-owned tree, and the link is refused outright unless
// the directory holding it has the same trust properties /Library does.
//
// The refusal names the path, the property that is wrong, the literal command
// that fixes it, and why k3sm cares. An operator told only the rule has to guess
// the remedy, and guessing at chown under /usr/local is how a Homebrew tree gets
// broken; the uid-0 half is conditional on euid because an unprivileged caller
// (the unit table, a dry run) cannot chown anything anyway.
func linkDirVerdict(dir, launcherDir string, f linkDirFacts, euid int) error {
	if launcherDir == "" {
		launcherDir = dir
	}
	escalated := dir != launcherDir
	why := fmt.Sprintf("root's PATH searches %s, so anything named k3sm left there is what the next `sudo k3sm …` would run as root", launcherDir)
	// Three remedies, and which one applies is decided by what is wrong rather
	// than by how it was phrased: repair the judged directory's ownership/mode;
	// create the launcher directory under an ancestor that can never hold a link
	// itself; or clear the way when the LAUNCHER path is the thing that is not a
	// directory. Only the third ever says "remove", and it never names an
	// ancestor.
	chown := fmt.Sprintf("sudo chown root:wheel %s && sudo chmod 755 %s", dir, dir)
	create := fmt.Sprintf("create %s as a root-owned directory first: sudo mkdir -p %s && sudo chown root:wheel %s && sudo chmod 755 %s", launcherDir, launcherDir, launcherDir, launcherDir)
	remove := fmt.Sprintf("remove %s, or choose another directory already on your shell's PATH", dir)

	reason, remedy := "", ""
	switch {
	case f.Absent:
		reason, remedy = "does not exist", create
	case f.IsSymlink:
		reason, remedy = "is a symlink, not a real directory, and whoever can re-point it decides where the launcher lands", remove
		if escalated {
			remedy = create
		}
	case !f.IsDir:
		reason, remedy = "is not a directory", remove
		if escalated {
			remedy = create
		}
	case f.Mode.Perm()&linkDirMaxMode != 0:
		which := "group-writable"
		switch f.Mode.Perm() & linkDirMaxMode {
		case 0o002:
			which = "world-writable"
		case 0o022:
			which = "group- and world-writable"
		}
		reason, remedy = fmt.Sprintf("is %s (mode %04o, want 755)", which, f.Mode.Perm()), chown
	case euid == 0 && f.UID != 0:
		reason, remedy = fmt.Sprintf("is owned by uid %d, not root", f.UID), chown
	default:
		return nil
	}
	if escalated {
		return fmt.Errorf("refusing to create the k3sm launcher directory %s: its parent %s %s, so %s cannot be created under it — %s — fix it: %s", launcherDir, dir, reason, launcherDir, why, remedy)
	}
	return fmt.Errorf("refusing to link the k3sm launcher into %s: it %s — %s — fix it: %s", dir, reason, why, remedy)
}

// linkDirTrustTarget reports WHICH directory's trust decides whether the launcher
// may be linked at link, given whether link's parent already exists.
//
// When the parent does not exist the answer is its own parent: that is the
// directory whose permissions decide who could have created the missing one —
// and therefore who could own it — before k3sm gets there. parentAbsent is also
// the caller's signal that it must create the parent itself once the verdict is
// clean.
func linkDirTrustTarget(link string, parentExists bool) (dir string, parentAbsent bool) {
	parent := filepath.Dir(link)
	if parentExists {
		return parent, false
	}
	return filepath.Dir(parent), true
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

// The two LaunchDaemon plist modes, and why the control plane's is not the
// other one.
//
// PlistMode is launchd's conventional 0644: root writes it, launchd reads it as
// root, and anyone may look at it. That is right for a plist whose argv is a set
// of paths and ports.
//
// ServerPlistMode is 0600, because the server plist's argv is the one that
// carries credentials. Not the admin token any more — that moved to a staged
// file — but the OPERATOR's preserved arguments, which legitimately include
// `--datastore-endpoint postgres://user:password@host/db`. pkg/dataroot already
// keeps the server-arguments record root-only 0600 for exactly that reason
// (serverArgsRecordMode), and the plist holds the same string, so leaving it
// 0644 kept a world-readable second copy of what the record is careful about.
// Nothing but root needs to read it: launchd is root, and `k3sm install` and
// `k3sm status` read it as root when they can.
//
// One consequence is deliberate and visible: `k3sm status` run as an ordinary
// user can no longer read the server plist, so its server-arguments row reports
// "unreadable as this user" instead of listing the flags. That row already had
// that state for exactly this case and it never moves the verdict; `sudo k3sm
// status` still shows them.
const (
	PlistMode       fs.FileMode = 0o644
	ServerPlistMode fs.FileMode = 0o600
)

// plistMode is the mode the labelled daemon's plist is written at. It is a
// function of the LABEL rather than a field on the artifact so a new daemon
// cannot be added with no decision taken about its mode: it lands on the 0644
// default, and only a label named here is treated as carrying secrets.
func plistMode(label string) fs.FileMode {
	if label == ServerLabel {
		return ServerPlistMode
	}
	return PlistMode
}

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
		// The staged HA datastore DSN, beside it and with the OPPOSITE
		// disposition: PRESERVED, like everything else under the data root.
		//
		// The token is a credential this install minted and can mint again, so
		// leaving it behind would leave a cluster-admin secret on a machine
		// somebody just uninstalled k3sm from. The DSN is the OPERATOR's: k3sm
		// cannot re-derive it, the flag naming it is carried across a reinstall
		// out of the preserved arguments record, and an uninstall that deleted
		// the file would turn the next install into the refusal
		// requireDatastoreEndpointFile exists to raise. It is no more exposed
		// there than the rest of the preserved data root, which holds the
		// cluster's signing keys.
		//
		// assertExists is false: a single-node server stages no DSN at all.
		items = append(items, artifact{kind: kindFile, disp: dispPreserve, path: cfg.datastoreEndpointPath(), assertExists: false})
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
	//   - the helper copy and its directory sit under the run dir, so they follow
	//     the run dir's disposition — preserved with DataRoot. Removing just this
	//     copy would buy nothing while the work-dir copy of the SAME bytes stays,
	//     and a reinstall re-provisions it from there regardless.
	//
	// Neither path's existence is asserted: a data root an older build installed
	// has no key until the install that provisions one, and a node that has never
	// run has no work-dir copy either.
	items = append(items,
		artifact{kind: kindFile, disp: dispPreserve, path: cfg.meshKeyWorkPath(), assertExists: false},
		artifact{kind: kindDir, disp: dispPreserve, path: MeshKeyDir, assertExists: false},
		artifact{kind: kindFile, disp: dispPreserve, path: cfg.meshKeyHelperPath(), assertExists: false},
	)
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

// plistContent renders the launchd plist for a daemon label, so Install can drive
// the writes from the manifest's daemon entries rather than a second hardcoded
// list. An unknown label is a programmer error (a daemon in the manifest with no
// renderer) surfaced as an error, never a panic.
func plistContent(label string, cfg Config) ([]byte, error) {
	switch label {
	case NetdLabel:
		return NetdPlist(cfg), nil
	case ServerLabel:
		return ServerPlist(cfg), nil
	case AgentLabel:
		return AgentPlist(cfg), nil
	case DatavolLabel:
		return DatavolPlist(cfg), nil
	default:
		return nil, fmt.Errorf("no plist renderer for daemon %s", label)
	}
}

// Install lays down both daemons in dependency order. It is the single root step
// (run via sudo): ensure _k3sm, copy the binary root-owned, write the two
// plists, bootstrap netd (the helper) BEFORE server (which needs it), then write
// the admin kubeconfig to the human's home. The caller has already verified root.
func Install(ctx context.Context, sys System, cfg Config) error {
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

	// 1. The service user must exist before the server LaunchDaemon (UserName=_k3sm)
	//    can resolve it and before its _k3sm-owned data root is usable.
	uid, err := sys.EnsureServiceUser(cfg.ServiceUser, cfg.DataRoot)
	if err != nil {
		return fmt.Errorf("install: ensure service user %s: %w", cfg.ServiceUser, err)
	}
	cfg.Logger.Info("ensured service user", "user", cfg.ServiceUser, "uid", uid)

	// 1b. The log dir must be writable by the service user before either daemon
	//     bootstraps: launchd opens a UserName job's StandardOut/ErrorPath as
	//     that user, and if the root netd job's spawn auto-creates the dir first
	//     (root-only perms), the _k3sm server job fails "Service could not
	//     initialize" and never spawns. Created/repaired idempotently.
	if err := sys.EnsureLogDir(LogDir, uid); err != nil {
		return fmt.Errorf("install: ensure log dir %s: %w", LogDir, err)
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
	if cfg.Role == RoleAgent && cfg.TokenFile != "" {
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

	// 1g. This node's wireguard identity, in both copies, for BOTH roles — see
	//     provisionMeshKey. It sits with the token stagings because it is the
	//     same kind of step (root hands the unprivileged daemon a credential it
	//     could not place for itself), and after EnsureRunDir at 1c because the
	//     root-only key dir is carved inside the run dir.
	if err := provisionMeshKey(sys, cfg, uid); err != nil {
		return err
	}

	// 2. Copy the binary to the exact path the plists exec (installedBinary()),
	//    regardless of the source artifact's name. It lands under InstallDir, so
	//    the InstallDir sweep covers it on uninstall.
	if err := sys.CopyToRootOwned(cfg.BinarySource, cfg.installedBinary()); err != nil {
		return fmt.Errorf("install: copy binary to %s: %w", cfg.installedBinary(), err)
	}
	// 2b. Put `k3sm` on PATH, from the manifest's kindSymlink entries — right
	//     after the binary they point at, and before anything else, so the
	//     launcher exists the moment its target does. Copying the binary into
	//     /Library/k3sm never made `k3sm` a command a shell could find, yet every
	//     post-install instruction (and install.sh's closing hint) assumes it is
	//     one; the link is the whole of that fix and is therefore a hard install
	//     failure when it cannot be laid down, not a best-effort nicety.
	for _, a := range m {
		if a.kind != kindSymlink {
			continue
		}
		if err := sys.EnsureSymlink(a.target, a.path); err != nil {
			return fmt.Errorf("install: link %s -> %s: %w", a.path, a.target, err)
		}
	}
	// 2b′. Copy the k3sm-execshim Seatbelt helper beside it. Fail fast when the
	//     source shim is absent: the server plist hardcodes --runtime runtimed,
	//     whose backend resolves the shim next to the executable — without it the
	//     server dies at boot in an invisible KeepAlive crash-loop (the live
	//     live-hardware failure mode), so a missing shim is an install-time error.
	if err := sys.CopyToRootOwned(cfg.ExecShimSource, cfg.installedExecShim()); err != nil {
		return fmt.Errorf("install: copy k3sm-execshim to %s: %w (build k3sm.io/runtimed/cmd/k3sm-execshim, codesign it, and place it next to the k3sm binary — the runtimed Seatbelt backend cannot boot without it)", cfg.installedExecShim(), err)
	}
	// 2b″. Copy the path-rebase DYLD shim beside the binary. runtimed resolves it
	//      next to the executable and injects it into a mounting pod so an absolute
	//      volume mount resolves under the pod data volume (build it with
	//      runtimed/hack/build-pathshim.sh and ad-hoc sign it).
	if err := sys.CopyToRootOwned(cfg.PathShimSource, cfg.installedPathShim()); err != nil {
		return fmt.Errorf("install: copy path-rebase shim to %s: %w (build it with runtimed/hack/build-pathshim.sh, codesign it, and place it next to the k3sm binary)", cfg.installedPathShim(), err)
	}
	// 2b‴. Copy the getaddrinfo DNS shim beside the binary. The provider resolves it
	//      next to the executable and injects it into each pod so in-pod cluster DNS
	//      reaches the per-node resolver (build it with darwin-net/hack/build-shim.sh).
	if err := sys.CopyToRootOwned(cfg.DNSShimSource, cfg.installedDNSShim()); err != nil {
		return fmt.Errorf("install: copy getaddrinfo DNS shim to %s: %w (build it with darwin-net/hack/build-shim.sh, codesign it, and place it next to the k3sm binary)", cfg.installedDNSShim(), err)
	}
	// 2b⁗. Copy the k3sm-vmhost VM-host helper beside the binary. runtimed's
	//      sandbox.FindVMHost resolves it next to the executable for
	//      vm-RuntimeClass pods. The helper is ad-hoc signed with the
	//      com.apple.security.virtualization entitlement, and CopyToRootOwned
	//      (ditto) carries that signature through verbatim — install never
	//      re-signs it, matching every other sibling binary here.
	//
	//      Which is exactly why the entitlement is verified FIRST. Copying verbatim
	//      means install can only propagate what the build produced, and a helper
	//      built with a plain `go build` carries no entitlement at all. Installed
	//      that way it fails silently and remotely: runtimed withholds
	//      VMBackendAvailable, the server deletes the node's k3sm.io/virtualization
	//      label, and every vm-RuntimeClass pod sits Pending reporting only the
	//      RuntimeClass selector it no longer matches. Refusing here turns that into
	//      one legible sentence at the one moment the fix is trivial.
	//
	//      A MISSING helper is not this gate's business — the probe reports
	//      fs.ErrNotExist and the copy below keeps its existing message.
	if err := sys.VerifyVirtualizationEntitlement(cfg.VMHostSource); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("install: staged %s does not carry the %s entitlement: %w (install copies the helper verbatim and never re-signs it, so an unentitled helper installs unentitled and every vm-RuntimeClass pod then stays Pending on an opaque node-affinity message; sign a dev build with `codesign --force --sign - --entitlements runtimed/cmd/k3sm-vmhost/vmhost.entitlements %s` — release artifacts already carry it)", cfg.VMHostSource, VirtualizationEntitlement, err, cfg.VMHostSource)
	}
	if err := sys.CopyToRootOwned(cfg.VMHostSource, cfg.installedVMHost()); err != nil {
		return fmt.Errorf("install: copy k3sm-vmhost to %s: %w (build k3sm.io/runtimed/cmd/k3sm-vmhost, ad-hoc sign it with the com.apple.security.virtualization entitlement, and place it next to the k3sm binary — vm-RuntimeClass pods cannot boot without it)", cfg.installedVMHost(), err)
	}
	// 2c. Stage the control-plane payload into InstallDir/bin. Fail fast when a
	//     payload binary is absent: the daemon boot otherwise falls back to
	//     `gh`/`go` acquisition, which cannot exist under launchd as _k3sm (the
	//     second live-hardware failure mode). Produce the payload with
	//     `k3sm payload <dir>` in a shell that has gh + go.
	for _, name := range executor.PayloadBinaries() {
		src := filepath.Join(cfg.PayloadSource, name)
		dst := filepath.Join(cfg.InstallDir, "bin", name)
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
		filepath.Join(cfg.InstallDir, "bin", executor.KineMarkerName))

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
		extra, err := installedServerArgs(sys, cfg)
		if err != nil {
			return err
		}
		cfg.ExtraServerArgs = extra
		if len(extra) > 0 {
			cfg.Logger.Info("preserved operator-supplied server arguments across reinstall", "args", redactedServerArgsText(extra))
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
	// 2d‴. Move a password-bearing datastore DSN off the daemon's command line,
	//      into a service-user-owned 0600 file the argv then merely names. It sits
	//      HERE and nowhere else: after the carry-over has decided the arguments,
	//      and before both the record below and the plist at step 3 are written
	//      from them, so the two on-disk copies of the argv agree and neither
	//      holds the password. It also refuses an install whose carried
	//      --datastore-endpoint-file names a file that is gone — see
	//      stageDatastoreEndpoint.
	if cfg.Role == RoleServer {
		if err := stageDatastoreEndpoint(sys, &cfg, uid); err != nil {
			return err
		}
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

	// 3. Render + write both plists, in manifest (install) order.
	for _, a := range m {
		if a.kind != kindDaemon {
			continue
		}
		content, err := plistContent(a.label, cfg)
		if err != nil {
			return fmt.Errorf("install: %w", err)
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

	// 4b. Verify the claim step 4 makes, rather than assuming it. An install that
	//     reports success having left a daemon down is worse than one that fails:
	//     the operator walks away, and the breakage surfaces later as something
	//     else entirely (a cluster whose DNS stopped answering).
	if err := verifyDaemons(ctx, sys, cfg, m, startedAt); err != nil {
		return fmt.Errorf("install: %w", err)
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
//   - the mesh MSS-clamp pf anchor — SWEPT, by the FlushMeshPFAnchor backstop
//     below (B274). Left alone it survives netd, scoped to a utun that is gone,
//     and macOS recycles utun numbers — the next tunnel assigned that number
//     silently inherits the stale clamp. A daemon-shutdown-path fix was
//     considered and rejected: a restart already self-heals, because Up
//     reloads the anchor for the current interface on every daemon start, so
//     the uninstall backstop is the only place the residue is user-visible.
//   - the wireguard utun and its routes — NOT explicitly removed. The interface
//     is created in-process (tun.CreateTUN) and goes away with netd, and the
//     kernel drops routes whose interface has vanished; nothing here proves the
//     routing table is clean, only that no rule keeps it dirty.
//
// Flushing the utun/routes class on the way out (if it ever proves necessary)
// is a darwin-net change (a shutdown hook that reaches Down), not an installer
// one, and would be filed separately. Uninstall makes no claim to do it.
func Uninstall(ctx context.Context, sys System, cfg Config) error {
	cfg = cfg.withDefaults()
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
	// Leave the cluster BEFORE anything local is torn down. Everything the call
	// depends on is alive right now and stops being alive a few lines below: the
	// agent daemon still holds the mesh up, the stored credential is still on
	// disk, and the control plane still has a MeshPeer to delete. It is
	// best-effort and never note()d — a Mac being retired is often being retired
	// because the cluster is gone, and an uninstall that refused to finish over
	// that would leave the operator with a half-installed machine.
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
	// Backstop: reap any control-plane children that outlived the booted-out
	// server daemon (a Stop() cut short by launchd's SIGKILL, or a crash). They
	// run out of <DataRoot>/server/bin and would otherwise hold the apiserver/
	// kine ports + the SQLite DB, breaking the next install.
	note(sys.ReapOrphans(filepath.Join(cfg.serverWorkDir(), "bin")))
	// Backstop: flush the mesh MSS-clamp pf anchor (B274). It outlives netd —
	// only the RemoveMesh RPC reaches mesh.WGDevice.Down, and no signal path
	// ever calls it — so a booted-out daemon leaves the anchor loaded against a
	// utun number macOS will eventually recycle onto an unrelated tunnel.
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
		return fmt.Errorf("uninstall: %w", firstErr)
	}
	cfg.Logger.Info("k3sm uninstalled", "install-dir", cfg.InstallDir)
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
	return nil
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

// NetdPlist renders the io.k3sm.netd LaunchDaemon plist. It runs as ROOT (no
// UserName) — it is the only irreducibly-root component — execing `k3sm netd`
// with the Service CIDR (so proxy VIP binds are authorizable), the socket, the
// mesh key dir, and a read kubeconfig (the PortAuthorizer's Service informer).
//
// The kubeconfig is the ONE argument that follows the node's role, because the
// two roles hold different credentials in different places. A RoleServer node
// runs the control plane, so netd reads the admin kubeconfig in the server work
// dir. A RoleAgent node has no server work dir at all: the credential a worker
// owns is the node kubeconfig `k3sm agent` writes when its join succeeds
// (AgentCredentialPath), and that is what its netd is handed. Handing a worker
// the server path is not a cosmetic mismatch — buildServiceSet's informer is the
// authorizer's only source of truth, so a kubeconfig that cannot load leaves
// every <1024 bind denied for the daemon's whole life, and on a Mac that was
// once a server the file still exists and is a STALE credential.
//
// It deliberately passes NO --node-pod-cidr on either role. The node's pod /24
// is not knowable at install time — it is decided by the join — so netd starts
// on the flag's own pre-adoption default and adopts the real prefix from the
// agent's ConfigureMesh RPC. Writing the install-time value into the launchd job
// would pin a guess that the next netd restart comes back on, dropping every pod
// alias and route the adopted prefix had established. It passes no --node-ip for
// the separate reason TestNetdPlistXML records (the node-address authorizer
// branch is dormant by configuration).
func NetdPlist(cfg Config) []byte {
	cfg = cfg.withDefaults()
	kubeconfig := filepath.Join(cfg.serverWorkDir(), "k3sm.kubeconfig")
	if cfg.Role == RoleAgent {
		kubeconfig = AgentCredentialPath(cfg.DataRoot)
	}
	return renderPlist(launchdPlist{
		Label: NetdLabel,
		ProgramArguments: []string{
			cfg.installedBinary(), "netd",
			"--socket", cfg.NetdSocket,
			"--service-cidr", cfg.ServiceCIDR,
			"--mesh-key-dir", MeshKeyDir,
			"--kubeconfig", kubeconfig,
		},
		RunAtLoad:  true,
		KeepAlive:  true,
		StdoutPath: NetdLogPath(),
		StderrPath: NetdLogPath(),
		// No UserName: netd is root.
	})
}

// serverFileLimit is the soft+hard RLIMIT_NOFILE (launchd NumberOfFiles) the
// server AND agent LaunchDaemons request — both host a node, and a worker runs
// the same Service proxy the control plane does. The process hosts the proxy /
// UDP relay, whose flow budget darwin-net sizes as max(8192, rl.Cur/2)
// (defaultUDPFlowBudget) — so the fd table it reads must be raised above launchd's
// 256 default, which floors the budget at 8192 with NO headroom for the
// co-resident apiserver/kine.
//
// 131072 is chosen because it is ≤ kern.maxfilesperproc (245760 on Apple Silicon)
// so it binds. The k3s Linux value (1048576) exceeds the macOS per-process ceiling
// and would be clamped by the kernel, voiding the budget's half-for-UDP /
// half-for-control-plane split. 131072 yields a UDP flow budget of 65536
// (rl.Cur/2), ~8× the 8192 floor, leaving the control plane the other half.
//
// Reload contract: launchd applies *ResourceLimits at process spawn from the job
// definition captured at bootstrap — so this raised limit binds on a fresh
// install or an uninstall→install (bootout→bootstrap), not on
// `launchctl kickstart -k`, which respawns the existing in-memory job with the
// old limit. Existing installs need a reinstall for the new limit to bind.
const serverFileLimit = 131072

// ServerPlist renders the io.k3sm.server LaunchDaemon plist. It runs as the
// unprivileged _k3sm user (UserName) execing `k3sm server` (the control plane +
// VK node), which reaches the root helper over the netd socket. KeepAlive +
// RunAtLoad make it boot-surviving and headless.
//
// The argument list is the fixed managed set followed by Config.ExtraServerArgs
// — the operator's own arguments, which Install resolves from the installed
// plist when there is one and otherwise from the server-arguments record in
// /Library/Preferences, so neither a reinstall nor an uninstall-then-install
// re-renders the bare template over them (a first install has neither source and
// renders the template alone). They are appended AFTER the managed set (and in
// their original relative order) so a preserved argument can never displace one
// this renderer owns.
func ServerPlist(cfg Config) []byte {
	cfg = cfg.withDefaults()
	args := []string{
		cfg.installedBinary(), "server",
		"--runtime", "runtimed",
		// The STAGED copy's PATH, never the token value — the agent plist's
		// contract, applied to the credential that matters most. The token this
		// names is the static admin bearer token: it authenticates as
		// system:masters, so a copy of it on a world-readable argv is a copy of
		// cluster-admin. Install writes the file (serverTokenPath, 0600, owned by
		// the service user) before this plist is laid down, and the server reads
		// it once at start through the same reader the agent uses.
		"--token-file", cfg.serverTokenPath(),
	}
	args = append(args, cfg.resolvedExtraServerArgs()...)
	return renderPlist(launchdPlist{
		Label:            ServerLabel,
		UserName:         cfg.ServiceUser,
		ProgramArguments: args,
		RunAtLoad:        true,
		KeepAlive:        true,
		WorkingDirectory: cfg.DataRoot,
		StdoutPath:       ServerLogPath(),
		StderrPath:       ServerLogPath(),
		EnvironmentVars:  map[string]string{"HOME": cfg.DataRoot},
		// Derived from the stages the server actually runs on its way out — see
		// serverExitTimeOut. Never a hand-picked number: every stage's bound lives
		// in its own package, and a literal here would be wrong the first time one
		// of them moved.
		ExitTimeOut: serverExitTimeOut,
		// Raise RLIMIT_NOFILE so darwin-net's UDP flow budget sizes against a real
		// fd table, not launchd's 256 default (the agent plist does the same; netd
		// is not a relay host). Binds at bootstrap, not on kickstart -k — see the
		// serverFileLimit reload contract above.
		SoftFileLimit: serverFileLimit,
	})
}

// The teardown budget, and why ExitTimeOut is derived rather than chosen.
//
// launchd SIGTERMs the job at `bootout`/`kickstart -k` and SIGKILLs it
// ExitTimeOut seconds later (its default is 20). Everything a k3sm daemon does on
// its way out happens inside that ONE number, and each stage's bound is owned by a
// different package — so a hand-picked literal here is wrong the first time any of
// them moves, and the failure is silent and bad: a SIGKILL mid-stop orphans
// exactly the children the stop exists to reap (kine and the apiserver on the
// server path, a vm host helper on either).
//
// The stages, each with the symbol that owns its bound:
//
//	runtimed close     37s  vmShutdownBound (35s) + defaultCloseGrace (2s), both
//	                        runtimed pkg/runtime/close.go — the embedded runtime's
//	                        concurrent vm-helper stop, deferred by startNode.
//	control-plane stop 40s  executor.StopBound (30s) — four components drained
//	                        serially at drainGrace each, plus the post-SIGKILL reap
//	                        — plus the 5s outer margin runServer's WAIT for it adds
//	                        (cmd/k3sm's controlPlaneStopWaitMargin), plus the 5s the
//	                        stop waits for the node's own loops to drain first
//	                        (cmd/k3sm's nodeDrainGrace), so the apiserver does not go
//	                        away under a run loop still publishing status. SERVER
//	                        ONLY: a worker runs no control plane.
//	                        It runs CONCURRENTLY with the runtimed close above (the
//	                        node starts the server's stop from its own teardown —
//	                        cmd/k3sm/exitoverlap.go), so the two together cost the
//	                        LARGER of them, never their sum.
//	control socket      5s  runtimedSocketShutdownGrace, cmd/k3sm/runtimedsocket.go.
//	mesh teardown       5s  meshTeardownTimeout, cmd/k3sm/agent.go — both roles.
//	headroom           10s  launchd's own signal/reap latency and the log flush.
//
// Every bound is a LITERAL here so the table above can be read in one place, and
// each literal is bound back to its owner by a test rather than by trust:
// TestExitTimeOutCoversTheDaemonTeardown compares the control-plane stage with
// executor.StopBound (the one owner this package can import), and
// hack/acceptance/B253.sh's CI tier reads runtimed's two constants out of its
// module and compares them with the close stage. The three stages whose owners live
// in package main (runtimedSocketShutdownGrace, controlPlaneStopWaitMargin and
// nodeDrainGrace) have no importable owner and no gate — 15s of a 60s budget
// between them, and the headroom absorbs a drift in any of them.
//
// The sums are rounded UP to the next multiple of ten, because an ExitTimeOut is
// read by operators in a plist and 60 is legible where 57 invites the question of
// what the 7 was for. Rounding up can only add headroom.
//
// Both roles land on the same 60s today, and that is a RESULT, not a coincidence
// to lean on: the server's extra stage is overlapped with the runtimed close, so
// only the 3s by which it now exceeds that close reaches the total, and the
// rounding absorbs them.
const (
	teardownRuntimedClose = 37
	teardownControlSocket = 5
	teardownControlPlane  = 30
	teardownMesh          = 5
	teardownHeadroom      = 10

	// teardownStopWaitMargin is the slack runServer's WAIT for the control-plane
	// stop adds on top of that stop's own budget — cmd/k3sm's
	// controlPlaneStopWaitMargin, which lives in package main and so, like
	// runtimedSocketShutdownGrace, cannot be imported and asserted here.
	teardownStopWaitMargin = 5
	// teardownNodeDrain is how long the control-plane stop waits, before it starts
	// at all, for the node's Virtual Kubelet and status loops to return —
	// cmd/k3sm's nodeDrainGrace, another package-main bound. It is part of the
	// concurrent stage rather than a stage of its own: it is spent inside the same
	// window the runtimed close occupies.
	teardownNodeDrain = 5

	// serverConcurrentTeardown is the cost of the server's two LONGEST stages,
	// which overlap rather than queue: the node starts the control-plane stop at
	// the very beginning of its own teardown and closes its embedded runtime while
	// that stop drains (cmd/k3sm/exitoverlap.go). They contend for nothing — vm
	// host helpers on one side, control-plane children on the other — so the budget
	// is the larger of the two, and the day either one grows past the other this
	// arithmetic follows it without being re-chosen. The control-plane side counts
	// its own drain wait, because the clock on it starts when the node's teardown
	// does, not when the stop finally begins.
	serverConcurrentTeardown = max(teardownRuntimedClose, teardownNodeDrain+teardownControlPlane+teardownStopWaitMargin)

	serverTeardownBudget = serverConcurrentTeardown + teardownControlSocket + teardownMesh + teardownHeadroom
	agentTeardownBudget  = teardownRuntimedClose + teardownControlSocket + teardownMesh + teardownHeadroom

	// serverExitTimeOut is the io.k3sm.server plist's ExitTimeOut: every stage
	// above, rounded up to the next multiple of ten.
	serverExitTimeOut = ((serverTeardownBudget + 9) / 10) * 10
	// agentExitTimeOut is the io.k3sm.agent plist's, on the same derivation minus
	// the control-plane stop a worker never runs.
	agentExitTimeOut = ((agentTeardownBudget + 9) / 10) * 10
)

// agentThrottleInterval is launchd's minimum seconds between spawns of the
// agent job. The agent's terminal start failures — no credential and no token,
// an expired credential, a cluster that has forgotten this node's MeshPeer —
// recur identically on the next start, and KeepAlive respawns an exited job
// immediately, so without a throttle a node that cannot join burns a core and
// floods agent.log while looking, from the outside, like an agent that is
// running. 10 is launchd's own default, stated explicitly because it is a
// decision here rather than an inherited one: the agent already backs off
// in-process (agentTerminalBackoff) and this is the supervisor-side floor
// under it.
const agentThrottleInterval = 10

// AgentPlist renders the io.k3sm.agent LaunchDaemon plist — the joining
// worker's daemon, the sibling of ServerPlist on a Mac that has no control
// plane of its own. It runs as the same unprivileged _k3sm user, with the same
// data root as its working directory and HOME, and reaches the root helper over
// the same netd socket.
//
// The join credential is rendered as a --token-file PATH and NEVER as a token
// value. A LaunchDaemon plist is root-owned 0644, so a token on this argv would
// be readable by every account on the Mac and visible in `ps` for the life of
// the process; the file the path names is the operator's, is read once at
// start, and is theirs to delete once the node has joined. A node that has
// already joined needs neither: it starts from its stored credential.
//
// ExitTimeOut is derived the same way the server's is (see serverExitTimeOut),
// from the stages an AGENT runs: it stops its embedded runtime's vm guests, tears
// down the runtimed control socket, drains the Service proxy's listeners and runs
// the same deferred mesh teardown the server does — everything except the
// control-plane stop, which a worker has no control plane to run. A SIGKILL
// part-way through leaves vm helpers, or a utun and its routes, behind on a node
// that looks stopped.
func AgentPlist(cfg Config) []byte {
	cfg = cfg.withDefaults()
	args := []string{
		cfg.installedBinary(), "agent",
		"--server", cfg.JoinServer,
		// The STAGED copy, unconditionally — never Config.TokenFile, which is a
		// root-only file this user cannot open, and never a token value. The
		// path is rendered even on an install that staged nothing: the agent
		// treats a missing token file as "no token" and starts from its stored
		// credential, so this is the one durable place a token is ever read
		// from, and the argv does not churn between installs.
		"--token-file", cfg.agentTokenPath(),
	}
	// --node-ip ONLY when the operator asserted one. Rendering an empty value
	// would put `--node-ip ""` on the daemon's argv, which is not "no assertion"
	// but an unparseable one, and the join is the wrong place to discover it.
	if cfg.NodeIP != "" {
		args = append(args, "--node-ip", cfg.NodeIP)
	}
	args = append(args, cfg.ExtraAgentArgs...)
	return renderPlist(launchdPlist{
		Label:            AgentLabel,
		UserName:         cfg.ServiceUser,
		ProgramArguments: args,
		RunAtLoad:        true,
		KeepAlive:        true,
		ThrottleInterval: agentThrottleInterval,
		WorkingDirectory: cfg.DataRoot,
		StdoutPath:       AgentLogPath(),
		StderrPath:       AgentLogPath(),
		EnvironmentVars:  map[string]string{"HOME": cfg.DataRoot},
		ExitTimeOut:      agentExitTimeOut,
		// The same RLIMIT_NOFILE raise the control plane gets, for the same
		// reason and with the same reload contract: a worker hosts the Service
		// proxy and the UDP relay, whose flow budget darwin-net sizes as
		// max(8192, rl.Cur/2), so under launchd's 256-fd default the budget
		// floors with no headroom for the node's own watches and pod streams.
		SoftFileLimit: serverFileLimit,
	})
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

// launchdPlist is the subset of a launchd job we render. A non-empty UserName
// makes the daemon run as that user (the server); an empty UserName runs as root
// (netd).
type launchdPlist struct {
	Label            string
	UserName         string
	ProgramArguments []string
	RunAtLoad        bool
	KeepAlive        bool
	// KeepAliveOnFailure renders KeepAlive as the dict {SuccessfulExit: false}
	// instead of a bare boolean: launchd then relaunches the job ONLY when it
	// exits non-zero. It is what a oneshot needs — `k3sm datavol mount` mounts
	// and exits 0, and a bare KeepAlive would respawn it forever. It is
	// mutually exclusive with KeepAlive, and renderPlist emits one or the other.
	KeepAliveOnFailure bool
	// ThrottleInterval, when > 0, is launchd's minimum seconds between spawns.
	// For the datavol oneshot it bounds how fast a failing mount is retried,
	// against the in-process retry MountRecorded already performs. 0 omits the
	// key (launchd's own 10s default applies).
	ThrottleInterval int
	WorkingDirectory string
	StdoutPath       string
	StderrPath       string
	EnvironmentVars  map[string]string
	// SoftFileLimit, when > 0, emits SoftResourceLimits + HardResourceLimits with
	// NumberOfFiles (RLIMIT_NOFILE) at this value. 0 (netd) omits both.
	SoftFileLimit int
	// ExitTimeOut, when > 0, is the launchd ExitTimeOut (seconds) — how long
	// bootout waits after SIGTERM before SIGKILL. The server needs longer than
	// launchd's 20s default: its Stop() tears the control-plane children down
	// SERIALLY (apiserver→scheduler→KCM→kine, up to 4×drainGrace), and a SIGKILL
	// mid-teardown orphans the not-yet-reaped children (own process groups). 0
	// omits the key (launchd default).
	ExitTimeOut int
}

// renderPlist serializes p to a launchd XML property list. String values are
// XML-escaped; booleans render as <true/>/<false/>; the ProgramArguments array
// and the optional EnvironmentVariables dict follow the launchd schema.
func renderPlist(p launchdPlist) []byte {
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0">` + "\n<dict>\n")

	writeKeyString(&b, "Label", p.Label)
	if p.UserName != "" {
		writeKeyString(&b, "UserName", p.UserName)
	}

	b.WriteString("  <key>ProgramArguments</key>\n  <array>\n")
	for _, a := range p.ProgramArguments {
		b.WriteString("    <string>")
		xmlEscape(&b, a)
		b.WriteString("</string>\n")
	}
	b.WriteString("  </array>\n")

	writeKeyBool(&b, "RunAtLoad", p.RunAtLoad)
	// KeepAlive is EITHER the boolean the two long-running daemons carry or the
	// {SuccessfulExit: false} dict the oneshot carries, never both: launchd
	// reads one KeepAlive key, and emitting two would leave which one binds to
	// the parser's order rather than to this decision.
	if p.KeepAliveOnFailure {
		b.WriteString("  <key>KeepAlive</key>\n  <dict>\n    <key>SuccessfulExit</key>\n    <false/>\n  </dict>\n")
	} else {
		writeKeyBool(&b, "KeepAlive", p.KeepAlive)
	}
	if p.ThrottleInterval > 0 {
		writeKeyInt(&b, "ThrottleInterval", p.ThrottleInterval)
	}
	if p.ExitTimeOut > 0 {
		writeKeyInt(&b, "ExitTimeOut", p.ExitTimeOut)
	}
	if p.SoftFileLimit > 0 {
		// Emit both Soft and Hard NumberOfFiles: a soft limit may never exceed the
		// hard one, and an MDM-managed Mac may set a finite launchd hard limit that
		// would clamp a soft-only raise — launchd (PID 1) can raise the hard limit
		// up to the kernel ceiling, so we set both to the requested value.
		for _, key := range []string{"SoftResourceLimits", "HardResourceLimits"} {
			b.WriteString("  <key>" + key + "</key>\n  <dict>\n    ")
			writeKeyInt(&b, "NumberOfFiles", p.SoftFileLimit)
			b.WriteString("  </dict>\n")
		}
	}
	if p.WorkingDirectory != "" {
		writeKeyString(&b, "WorkingDirectory", p.WorkingDirectory)
	}
	if p.StdoutPath != "" {
		writeKeyString(&b, "StandardOutPath", p.StdoutPath)
	}
	if p.StderrPath != "" {
		writeKeyString(&b, "StandardErrorPath", p.StderrPath)
	}
	if len(p.EnvironmentVars) > 0 {
		b.WriteString("  <key>EnvironmentVariables</key>\n  <dict>\n")
		for _, k := range sortedKeys(p.EnvironmentVars) {
			b.WriteString("    ")
			writeKeyString(&b, k, p.EnvironmentVars[k])
		}
		b.WriteString("  </dict>\n")
	}

	b.WriteString("</dict>\n</plist>\n")
	return b.Bytes()
}

func writeKeyString(b *bytes.Buffer, key, val string) {
	b.WriteString("  <key>")
	xmlEscape(b, key)
	b.WriteString("</key>\n  <string>")
	xmlEscape(b, val)
	b.WriteString("</string>\n")
}

func writeKeyBool(b *bytes.Buffer, key string, val bool) {
	b.WriteString("  <key>")
	xmlEscape(b, key)
	if val {
		b.WriteString("</key>\n  <true/>\n")
	} else {
		b.WriteString("</key>\n  <false/>\n")
	}
}

func writeKeyInt(b *bytes.Buffer, key string, val int) {
	b.WriteString("  <key>")
	xmlEscape(b, key)
	b.WriteString("</key>\n  <integer>")
	b.WriteString(strconv.Itoa(val))
	b.WriteString("</integer>\n")
}

func xmlEscape(b *bytes.Buffer, s string) {
	_ = xml.EscapeText(b, []byte(s))
}

// sortedKeys returns the map keys in deterministic order (stable plist output).
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
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
