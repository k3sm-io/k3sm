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
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"

	"k3sm.io/darwin-net/pkg/podnet"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/runtimed/pkg/sandbox"
)

// Reverse-DNS launchd labels for the two daemons (io.k3sm.* per the project
// conventions). netd is root; server runs as the _k3sm service user.
const (
	// NetdLabel is the root privileged-network helper LaunchDaemon.
	NetdLabel = "io.k3sm.netd"
	// ServerLabel is the control-plane LaunchDaemon (UserName=_k3sm).
	ServerLabel = "io.k3sm.server"
)

// Default install locations.
const (
	// DefaultServiceUser is the unprivileged, no-login system user the control
	// plane, node, runtimed, and Service proxy all run as.
	DefaultServiceUser = "_k3sm"
	// DefaultInstallDir is the root-owned (root:wheel 0755) directory the binary
	// and supporting files are copied into.
	DefaultInstallDir = "/Library/k3sm"
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
)

// ServerLogPath returns the control-plane daemon's combined stdout/stderr log path.
// The server plist points at it and diagnostics (`k3sm certificate rotate`'s failure
// message) name it, so the two can never drift apart.
func ServerLogPath() string { return filepath.Join(LogDir, "server.log") }

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

// System is the privileged-operation seam install/uninstall drive. The real
// darwin implementation performs the root syscalls/tools; tests inject a fake so
// the orchestration runs without privilege.
type System interface {
	// EnsureServiceUser idempotently creates name as a no-login system user
	// (home = DefaultDataRoot, owned by it) and returns its uid.
	EnsureServiceUser(name string) (uid uint32, err error)
	// CopyToRootOwned copies src to exactly dst (creating dst's parent dir
	// root:wheel 0755), leaving dst root:wheel 0755 with signature/xattrs
	// preserved. dst is the full installed path — never derived from src's
	// basename: the LaunchDaemon plists exec the fixed installedBinary() path, so
	// a build artifact named e.g. `k3sm-m2` must still land at InstallDir/k3sm (a
	// basename-derived dst bricks both daemons with launchd's unrecoverable
	// "Missing executable" — the live M2-gate failure this contract fixes).
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
	// service uid (group staff, 0755) so launchd can open the UserName=_k3sm
	// server job's StandardOut/ErrorPath as _k3sm. launchd auto-creates a missing
	// log dir with root-only perms when the root netd job spawns first — the
	// _k3sm server job then fails "Service could not initialize" and never
	// spawns (the live M2-gate failure this fixes). Idempotent: perms/owner are
	// re-applied on every install, repairing a previously mis-created dir.
	EnsureLogDir(dir string, uid uint32) error
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
	// WriteLaunchDaemon writes a launchd plist (root:wheel 0644) at plistPath.
	WriteLaunchDaemon(plistPath string, contents []byte) error
	// ReadFile reads a root-readable file: the installed server plist, whose
	// operator-supplied arguments a reinstall must carry over, and the cluster CA
	// the admin kubeconfig pins. A missing file returns an error satisfying
	// errors.Is(err, fs.ErrNotExist), which callers treat as "nothing to carry
	// over" rather than a failure — a FIRST install has neither file.
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
}

// Config parametrizes Install/Uninstall. Empty fields take the Default* values.
type Config struct {
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
	// (--token) and the admin kubeconfig. Generated when empty.
	AdminToken string
	// ExtraServerArgs are operator-supplied `k3sm server` arguments appended to
	// the fixed set ServerPlist renders (--mesh-ip, --registry-port, …). Install
	// populates it from the ARGUMENTS OF THE PLIST ALREADY ON DISK, so a reinstall
	// preserves what an operator configured instead of re-rendering the bare
	// template over it; a first install leaves it empty. AdminKubeconfig reads
	// --mesh-ip out of it to address the apiserver where it actually binds.
	ExtraServerArgs []string
	// ClusterCA is the cluster CA certificate PEM the admin kubeconfig pins as
	// certificate-authority-data. Install reads it off disk on a mesh install (the
	// only posture in which the apiserver serves a cluster-CA-signed leaf); empty
	// keeps the single-node insecure-skip-tls-verify posture, which is the only
	// correct one against a self-signed serving cert.
	ClusterCA []byte
	Logger    *slog.Logger
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

// meshIP returns the --mesh-ip value carried in ExtraServerArgs, or "" when the
// server runs single-node. It is the discriminator between the two apiserver
// postures the admin kubeconfig must address: a mesh server binds its wireguard
// IP ONLY and serves a cluster-CA-signed leaf, so a loopback URL reaches nothing
// and the cluster CA is the right anchor; single-node binds loopback and
// self-signs, for which no CA on disk is the anchor.
func (c Config) meshIP() string { return flagValue(c.ExtraServerArgs, "mesh-ip") }

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
// path is the same divergence bug B62 fixes). A daemon binds its Label and
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
		// Bootout(label) then RemoveAll(plistPath). Removing the plist is the B62
		// fix — previously the label was booted out but the plist leaked, leaving a
		// phantom KeepAlive respawn-throttle root job pointing at a deleted binary.
		{kind: kindDaemon, disp: dispRemove, label: NetdLabel, path: cfg.plistPath(NetdLabel), assertExists: true},
		{kind: kindDaemon, disp: dispRemove, label: ServerLabel, path: cfg.plistPath(ServerLabel), assertExists: true},

		// The admin kubeconfig in the human's home — preserved (it may hold other
		// clusters; k3sm never owns the whole file).
		{kind: kindKubeconfig, disp: dispPreserve, user: cfg.TargetUser},

		// Preserved privileged state: DataRoot (kine state.db + mesh keys) and the
		// daemon LogDir. Both survive an uninstall→reinstall.
		{kind: kindDir, disp: dispPreserve, path: cfg.DataRoot, assertExists: false},
		{kind: kindDir, disp: dispPreserve, path: LogDir, assertExists: false},
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
	if cfg.BinarySource == "" {
		return fmt.Errorf("install: BinarySource (the k3sm binary to install) is required")
	}
	if cfg.TargetUser == "" {
		return fmt.Errorf("install: TargetUser (the kubeconfig owner, e.g. $SUDO_USER) is required")
	}
	if cfg.AdminToken == "" {
		tok, err := generateToken()
		if err != nil {
			return err
		}
		cfg.AdminToken = tok
	}

	// The manifest is the single source of truth for the artifacts laid down (and,
	// on uninstall, torn down): daemon plist paths + install order come from it, so
	// there is no second hardcoded list to diverge from the teardown.
	m := artifactManifest(cfg)

	// 1. The service user must exist before the server LaunchDaemon (UserName=_k3sm)
	//    can resolve it and before its _k3sm-owned data root is usable.
	uid, err := sys.EnsureServiceUser(cfg.ServiceUser)
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
	//     M2-gate failure mode), so a missing shim is an install-time error.
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
	//     second live M2-gate failure mode). Produce the payload with
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

	// 2d. Carry over the operator-supplied server arguments from the plist ALREADY
	//     ON DISK. ServerPlist renders a fixed template, so before this a reinstall
	//     silently dropped every argument a human had added (--mesh-ip,
	//     --registry-port) and the cluster came back single-node on loopback until
	//     someone repaired the plist by hand. A first install finds no plist and
	//     preserves nothing; --token is deliberately NOT preserved (it is
	//     install-managed and re-minted here, in lockstep with the kubeconfig).
	extra, err := installedServerArgs(sys, cfg)
	if err != nil {
		return err
	}
	cfg.ExtraServerArgs = extra
	if len(extra) > 0 {
		cfg.Logger.Info("preserved operator-supplied server arguments across reinstall", "args", strings.Join(extra, " "))
	}

	// 2e. On a mesh install the apiserver serves a CLUSTER-CA-SIGNED leaf, so the
	//     admin kubeconfig can and must verify it. Read that CA (install runs as
	//     root; the file is the _k3sm control plane's). Absent on a first install,
	//     where the control plane has not booted yet — the kubeconfig then falls
	//     back to the skip-verify posture and the next reinstall picks the CA up.
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
		if err := sys.WriteLaunchDaemon(a.path, content); err != nil {
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
	if err := restartDaemons(ctx, sys, m, cfg.Logger); err != nil {
		return fmt.Errorf("install: %w", err)
	}

	// 4b. Verify the claim step 4 makes, rather than assuming it. An install that
	//     reports success having left a daemon down is worse than one that fails:
	//     the operator walks away, and the breakage surfaces later as something
	//     else entirely (a cluster whose DNS stopped answering).
	if err := verifyDaemons(ctx, sys, cfg); err != nil {
		return fmt.Errorf("install: %w", err)
	}

	// 5. Write the admin kubeconfig to the human's home (owned by them, not root).
	if err := sys.WriteUserKubeconfig(cfg.TargetUser, AdminKubeconfig(cfg)); err != nil {
		return fmt.Errorf("install: write admin kubeconfig for %s: %w", cfg.TargetUser, err)
	}
	cfg.Logger.Info("k3sm installed", "install-dir", cfg.InstallDir, "link", cfg.installedLink(), "kubeconfig-owner", cfg.TargetUser)
	return nil
}

// Uninstall tears down every artifact install laid down, driven by the same
// manifest install consumes — so nothing install creates can be left behind
// (the B62 leak was the two plists, which the old hardcoded uninstall never
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
// So a booted-out netd leaves durable kernel state, and uninstall removes exactly
// one class of it:
//
//   - lo0 inet aliases — SWEPT, by the FlushLo0Aliases backstop below, precisely
//     because no daemon does it.
//   - the mesh MSS-clamp pf anchor — NOT removed. It survives netd, scoped to a
//     utun that is gone, until something flushes the anchor or the host reboots.
//   - the wireguard utun and its routes — NOT explicitly removed. The interface
//     is created in-process (tun.CreateTUN) and goes away with netd, and the
//     kernel drops routes whose interface has vanished; nothing here proves the
//     routing table is clean, only that no rule keeps it dirty.
//
// Flushing those on the way out is a darwin-net change (a shutdown hook that
// reaches Down), not an installer one, and is filed separately. Uninstall makes
// no claim to do it.
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
	m := artifactManifest(cfg)
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
				// can never leave a leaked KeepAlive plist (the B62 leak). But if
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
	return nil
}

// NetdPlist renders the io.k3sm.netd LaunchDaemon plist. It runs as ROOT (no
// UserName) — it is the only irreducibly-root component — execing `k3sm netd`
// with the Service CIDR (so proxy VIP binds are authorizable), the socket, the
// mesh key dir, and a read kubeconfig (the PortAuthorizer's Service informer).
func NetdPlist(cfg Config) []byte {
	cfg = cfg.withDefaults()
	return renderPlist(launchdPlist{
		Label: NetdLabel,
		ProgramArguments: []string{
			cfg.installedBinary(), "netd",
			"--socket", cfg.NetdSocket,
			"--service-cidr", cfg.ServiceCIDR,
			"--mesh-key-dir", MeshKeyDir,
			"--kubeconfig", filepath.Join(cfg.serverWorkDir(), "k3sm.kubeconfig"),
		},
		RunAtLoad:  true,
		KeepAlive:  true,
		StdoutPath: filepath.Join(LogDir, "netd.log"),
		StderrPath: filepath.Join(LogDir, "netd.log"),
		// No UserName: netd is root.
	})
}

// serverFileLimit is the soft+hard RLIMIT_NOFILE (launchd NumberOfFiles) the
// server LaunchDaemon requests. The server process hosts the Service proxy / UDP
// relay, whose flow budget darwin-net sizes as max(8192, rl.Cur/2) (B48's
// defaultUDPFlowBudget) — so the fd table it reads must be raised above launchd's
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
// — the operator's own arguments, which Install reads off the installed plist so
// a reinstall does not re-render the bare template over them. They are appended
// AFTER the managed set (and in their original relative order) so a preserved
// argument can never displace one this renderer owns.
func ServerPlist(cfg Config) []byte {
	cfg = cfg.withDefaults()
	args := []string{
		cfg.installedBinary(), "server",
		"--runtime", "runtimed",
		"--token", cfg.AdminToken,
	}
	args = append(args, cfg.ExtraServerArgs...)
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
		// Give Stop() room to reap the serial control-plane teardown before launchd
		// SIGKILLs the job (default 20s ≈ the worst-case 4×drainGrace, which orphans
		// the not-yet-reaped children). 45s clears it with margin.
		ExitTimeOut: 45,
		// Server-only: raise RLIMIT_NOFILE so darwin-net's UDP flow budget sizes
		// against a real fd table, not launchd's 256 default. Binds at bootstrap,
		// not on kickstart -k — see the serverFileLimit reload contract above.
		SoftFileLimit: serverFileLimit,
	})
}

// adminLoopbackHost is the apiserver address the admin kubeconfig uses on a
// single-node install: the loopback the control plane binds when no mesh IP is
// configured. A mesh install overrides it with the mesh IP — see AdminKubeconfig.
const adminLoopbackHost = "127.0.0.1"

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
//   - SINGLE-NODE: loopback, and insecure-skip-tls-verify — the apiserver
//     self-signs its serving cert there, so no CA on disk anchors it and pinning
//     one would break kubectl rather than secure it. This mirrors the executor's
//     own posture split (writeComponentKubeconfig's verifyClusterCA).
func AdminKubeconfig(cfg Config) []byte {
	cfg = cfg.withDefaults()
	host := adminLoopbackHost
	clusterTLS := "    insecure-skip-tls-verify: true"
	if mesh := cfg.meshIP(); mesh != "" {
		host = mesh
		if len(cfg.ClusterCA) > 0 {
			clusterTLS = "    certificate-authority-data: " + base64.StdEncoding.EncodeToString(cfg.ClusterCA)
		}
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
	writeKeyBool(&b, "KeepAlive", p.KeepAlive)
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
