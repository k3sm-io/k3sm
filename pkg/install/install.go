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
// notarization + designated-requirement entitlements that DRIVE these commands
// are the packaging follow-up (DESIGN §5c) — out of scope here.
package install

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
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
	// DefaultLaunchDaemonDir is where the two .plist files are written.
	DefaultLaunchDaemonDir = "/Library/LaunchDaemons"
	// DefaultDataRoot is the _k3sm-owned data root (the _k3sm home): the
	// control-plane work-dir, runtimed pods/storage/image cache live under it.
	DefaultDataRoot = "/var/lib/k3sm"
	// DefaultNetdSocket is the root netd unix socket the daemons rendezvous on.
	DefaultNetdSocket = "/var/lib/k3sm/run/netd.sock"
	// DefaultAPIServerPort is the apiserver secure port (avoids Docker's :6443).
	DefaultAPIServerPort = 6444
	// DefaultServiceCIDR is the cluster Service CIDR the netd daemon pins so the
	// proxy's ClusterIP VIP aliases are admitted.
	DefaultServiceCIDR = "10.43.0.0/16"
	// MeshKeyDir is the root-only directory the netd MeshKeyResolver reads.
	MeshKeyDir = "/var/lib/k3sm/run/keys"
	// LogDir is where the daemons' stdout/stderr are written.
	LogDir = "/var/log/k3sm"
)

// System is the privileged-operation seam install/uninstall drive. The real
// darwin implementation performs the root syscalls/tools; tests inject a fake so
// the orchestration runs without privilege.
type System interface {
	// EnsureServiceUser idempotently creates name as a no-login system user
	// (home = DefaultDataRoot, owned by it) and returns its uid.
	EnsureServiceUser(name string) (uid uint32, err error)
	// CopyToRootOwned copies src to EXACTLY dst (creating dst's parent dir
	// root:wheel 0755), leaving dst root:wheel 0755 with signature/xattrs
	// preserved. dst is the full installed path — NEVER derived from src's
	// basename: the LaunchDaemon plists exec the fixed installedBinary() path, so
	// a build artifact named e.g. `k3sm-m2` must still land at InstallDir/k3sm (a
	// basename-derived dst bricks both daemons with launchd's unrecoverable
	// "Missing executable" — the live M2-gate failure this contract fixes).
	CopyToRootOwned(src, dst string) error
	// WriteLaunchDaemon writes a launchd plist (root:wheel 0644) at plistPath.
	WriteLaunchDaemon(plistPath string, contents []byte) error
	// LaunchctlBootstrap loads the labelled daemon into the system domain.
	LaunchctlBootstrap(label string) error
	// LaunchctlBootout unloads the labelled daemon (idempotent: a not-loaded
	// label is a no-op success).
	LaunchctlBootout(label string) error
	// LaunchctlKickstart (re)starts the labelled daemon (launchctl kickstart -k).
	LaunchctlKickstart(label string) error
	// WriteUserKubeconfig writes the admin kubeconfig into targetUser's
	// ~/.kube/config, owned by targetUser (NOT root).
	WriteUserKubeconfig(targetUser string, contents []byte) error
	// RemoveAll removes a path tree (the install dir on uninstall).
	RemoveAll(path string) error
}

// Config parametrizes Install/Uninstall. Empty fields take the Default* values.
type Config struct {
	ServiceUser     string // _k3sm
	InstallDir      string // /Library/k3sm
	LaunchDaemonDir string // /Library/LaunchDaemons
	DataRoot        string // /var/lib/k3sm
	NetdSocket      string // /var/lib/k3sm/run/netd.sock
	ServiceCIDR     string // 10.43.0.0/16
	APIServerPort   int    // 6444
	// BinarySource is the k3sm binary to install (typically the running
	// executable). Required.
	BinarySource string
	// TargetUser is the human (SUDO_USER) the admin kubeconfig is written for and
	// owned by. Required for the kubeconfig step; empty skips it with an error.
	TargetUser string
	// AdminToken is the static bearer token shared between the server LaunchDaemon
	// (--token) and the admin kubeconfig. Generated when empty.
	AdminToken string
	Logger     *slog.Logger
}

func (c Config) withDefaults() Config {
	if c.ServiceUser == "" {
		c.ServiceUser = DefaultServiceUser
	}
	if c.InstallDir == "" {
		c.InstallDir = DefaultInstallDir
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
	return c
}

// installedBinary is the path the k3sm binary is copied to.
func (c Config) installedBinary() string {
	return filepath.Join(c.InstallDir, "k3sm")
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
)

// disposition is what uninstall does with an artifact install laid down.
type disposition int

const (
	// dispRemove is torn down on uninstall (the two plists; the InstallDir tree).
	dispRemove disposition = iota
	// dispInstallDirCovered lives under InstallDir and is removed by the single
	// RemoveAll(InstallDir) sweep — never individually (that would double-remove).
	dispInstallDirCovered
	// dispPreserve is installed but DELIBERATELY kept on uninstall: DataRoot (kine
	// state.db + mesh keys — nuking it loses data on reinstall), the human
	// kubeconfig (may hold other clusters), the _k3sm user, LogDir.
	dispPreserve
)

// artifact is one thing install lays down. Every path is derived from a Config
// accessor/const — NEVER a re-hardcoded /Library/... literal (a third copy of a
// path is the same divergence bug B62 fixes). A daemon binds its Label and
// plistPath into one entry so a booted-out label can never leave a leaked
// KeepAlive plist (the original leak).
type artifact struct {
	kind  artifactKind
	disp  disposition
	path  string // file/dir/plist path; empty for kindServiceUser/kindKubeconfig
	label string // launchd label for kindDaemon; empty otherwise
	user  string // user name for kindServiceUser/kindKubeconfig; empty otherwise
	// assertExists records whether the path is expected on disk TODAY. It is
	// false for the forward-declared cp-payload items (the /Library/k3sm/bin tree
	// + relocated k3sm-netd): the packaging follow-up owns moving cp/kine off
	// DataRoot into InstallDir, so those paths do not exist yet. The manifest
	// proves the DISPOSITION (InstallDir-covered), not on-disk presence — that
	// follow-up lights them up with no manifest change.
	assertExists bool
}

// artifactManifest is the SINGLE source of truth for what install lays down and
// how uninstall tears it down. It is a pure func(Config) — hermetic and testable
// — deriving every path from the existing Config accessors/consts. Both Install
// (lay-down order + plist paths) and Uninstall (reverse-order teardown) consume
// it, closing the divergence between the two hardcoded lists that leaked the
// plists. Order is install order; uninstall walks it in reverse.
func artifactManifest(cfg Config) []artifact {
	cfg = cfg.withDefaults()
	return []artifact{
		// The _k3sm service user — created before the server daemon can resolve it.
		// PRESERVED: its home IS DataRoot; removing it orphans the data root.
		{kind: kindServiceUser, disp: dispPreserve, user: cfg.ServiceUser},

		// The InstallDir tree — the single RemoveAll(InstallDir) sweep on uninstall.
		{kind: kindDir, disp: dispRemove, path: cfg.InstallDir, assertExists: true},
		// The k3sm binary copied into InstallDir — covered by the sweep, not
		// removed individually.
		{kind: kindFile, disp: dispInstallDirCovered, path: cfg.installedBinary(), assertExists: true},
		// FORWARD-DECLARED: the cp-payload bin tree + relocated k3sm-netd land
		// under InstallDir once the packaging follow-up moves them off DataRoot. They
		// do NOT exist on disk today (cp/kine land under DataRoot at runtime), so
		// existence is NOT asserted; the InstallDir sweep already covers them.
		{kind: kindDir, disp: dispInstallDirCovered, path: filepath.Join(cfg.InstallDir, "bin"), assertExists: false},
		{kind: kindFile, disp: dispInstallDirCovered, path: filepath.Join(cfg.InstallDir, "bin", "k3sm-netd"), assertExists: false},

		// The two LaunchDaemons — netd BEFORE server (install order: netd is
		// bootstrapped first, the server depends on it). Each REMOVED on uninstall:
		// Bootout(label) THEN RemoveAll(plistPath). Removing the plist is the B62
		// fix — previously the label was booted out but the plist LEAKED, leaving a
		// phantom KeepAlive respawn-throttle root job pointing at a deleted binary.
		{kind: kindDaemon, disp: dispRemove, label: NetdLabel, path: cfg.plistPath(NetdLabel), assertExists: true},
		{kind: kindDaemon, disp: dispRemove, label: ServerLabel, path: cfg.plistPath(ServerLabel), assertExists: true},

		// The admin kubeconfig in the human's home — PRESERVED (it may hold other
		// clusters; k3sm never owns the whole file).
		{kind: kindKubeconfig, disp: dispPreserve, user: cfg.TargetUser},

		// PRESERVED privileged state: DataRoot (kine state.db + mesh keys) and the
		// daemon LogDir. Both survive an uninstall→reinstall.
		{kind: kindDir, disp: dispPreserve, path: cfg.DataRoot, assertExists: false},
		{kind: kindDir, disp: dispPreserve, path: LogDir, assertExists: false},
	}
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

	// 2. Copy the binary to the EXACT path the plists exec (installedBinary()),
	//    regardless of the source artifact's name. It lands under InstallDir, so
	//    the InstallDir sweep covers it on uninstall.
	if err := sys.CopyToRootOwned(cfg.BinarySource, cfg.installedBinary()); err != nil {
		return fmt.Errorf("install: copy binary to %s: %w", cfg.installedBinary(), err)
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

	// 4. Bootstrap in manifest order: netd FIRST (root helper), then the server
	//    (depends on it) — the manifest lists netd before server.
	for _, a := range m {
		if a.kind != kindDaemon {
			continue
		}
		if err := sys.LaunchctlBootstrap(a.label); err != nil {
			return fmt.Errorf("install: bootstrap %s: %w", a.label, err)
		}
	}

	// 5. Write the admin kubeconfig to the HUMAN's home (owned by them, not root).
	if err := sys.WriteUserKubeconfig(cfg.TargetUser, AdminKubeconfig(cfg)); err != nil {
		return fmt.Errorf("install: write admin kubeconfig for %s: %w", cfg.TargetUser, err)
	}
	cfg.Logger.Info("k3sm installed", "install-dir", cfg.InstallDir, "kubeconfig-owner", cfg.TargetUser)
	return nil
}

// Uninstall tears down every artifact install laid down, driven by the SAME
// manifest install consumes — so nothing install creates can be left behind
// (the B62 leak was the two plists, which the old hardcoded uninstall never
// removed). It walks the manifest in REVERSE install order: the server daemon
// before netd (server first stops driving the helper; netd's SIGTERM handler
// then flushes lo0/pf/utun), each daemon torn down as Bootout(label) THEN
// RemoveAll(plistPath) so the label and its plist never diverge. InstallDir-
// covered artifacts are swept by the single RemoveAll(InstallDir); dispPreserve
// artifacts (DataRoot's kine state.db + mesh keys, the human kubeconfig, the
// _k3sm user, LogDir) are DELIBERATELY left in place. It is idempotent: a
// bootout of a not-loaded label and a RemoveAll of an absent path are both
// no-op successes, so re-running after a partial install (or twice) is safe.
func Uninstall(ctx context.Context, sys System, cfg Config) error {
	cfg = cfg.withDefaults()
	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	// safeRemove guards every ROOT RemoveAll: it refuses a non-absolute path or one
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
				// Bootout THEN remove the plist — binding them so a booted-out label
				// can never leave a leaked KeepAlive plist (the B62 leak). But if
				// bootout returns a REAL error (not the idempotent not-loaded case,
				// which returns nil), the root job may still be LOADED — do NOT delete
				// its plist definition (that would orphan a live root job until reboot,
				// a variant of the same leak). Record the error and leave the plist.
				if err := sys.LaunchctlBootout(a.label); err != nil {
					note(err)
					continue
				}
				note(safeRemove(a.path))
			} else {
				note(safeRemove(a.path))
			}
		}
	}
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
			"--kubeconfig", filepath.Join(cfg.DataRoot, "server", "k3sm.kubeconfig"),
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
// 131072 is deliberate: it is ≤ kern.maxfilesperproc (245760 on Apple Silicon) so
// it BINDS. The k3s Linux value (1048576) EXCEEDS the macOS per-process ceiling
// and would be clamped by the kernel, voiding the budget's half-for-UDP /
// half-for-control-plane split. 131072 yields a UDP flow budget of 65536
// (rl.Cur/2), ~8× the 8192 floor, leaving the control plane the other half.
//
// RELOAD CONTRACT: launchd applies *ResourceLimits at process SPAWN from the job
// definition captured at bootstrap — so this raised limit binds on a FRESH
// install or an uninstall→install (bootout→bootstrap), NOT on
// `launchctl kickstart -k`, which respawns the existing in-memory job with the
// OLD limit. Existing installs need a reinstall for the new limit to bind.
const serverFileLimit = 131072

// ServerPlist renders the io.k3sm.server LaunchDaemon plist. It runs as the
// unprivileged _k3sm user (UserName) execing `k3sm server` (the control plane +
// VK node), which reaches the root helper over the netd socket. KeepAlive +
// RunAtLoad make it boot-surviving and headless.
func ServerPlist(cfg Config) []byte {
	cfg = cfg.withDefaults()
	return renderPlist(launchdPlist{
		Label:    ServerLabel,
		UserName: cfg.ServiceUser,
		ProgramArguments: []string{
			cfg.installedBinary(), "server",
			"--runtime", "runtimed",
			"--token", cfg.AdminToken,
		},
		RunAtLoad:        true,
		KeepAlive:        true,
		WorkingDirectory: cfg.DataRoot,
		StdoutPath:       filepath.Join(LogDir, "server.log"),
		StderrPath:       filepath.Join(LogDir, "server.log"),
		EnvironmentVars:  map[string]string{"HOME": cfg.DataRoot},
		// Server-only: raise RLIMIT_NOFILE so darwin-net's UDP flow budget sizes
		// against a real fd table, not launchd's 256 default. Binds at bootstrap,
		// not on kickstart -k — see the serverFileLimit reload contract above.
		SoftFileLimit: serverFileLimit,
	})
}

// AdminKubeconfig renders the admin kubeconfig (loopback apiserver + the shared
// static token + insecure-skip-tls for the single-node self-signed serving cert)
// written to the human's home so `kubectl` works once the server is up.
func AdminKubeconfig(cfg Config) []byte {
	cfg = cfg.withDefaults()
	return []byte(fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: k3sm
  cluster:
    server: "https://127.0.0.1:%d"
    insecure-skip-tls-verify: true
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
`, cfg.APIServerPort, cfg.AdminToken))
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
	if p.SoftFileLimit > 0 {
		// Emit BOTH Soft and Hard NumberOfFiles: a soft limit may never exceed the
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
