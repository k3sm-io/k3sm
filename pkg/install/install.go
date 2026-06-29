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
// are the M4 packaging follow-up (DESIGN §5c) — out of scope here.
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
	// CopyToRootOwned copies src into dstDir as root:wheel 0755 and returns the
	// installed path (dstDir/base(src)).
	CopyToRootOwned(src, dstDir string) (dst string, err error)
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

	// 1. The service user must exist before the server LaunchDaemon (UserName=_k3sm)
	//    can resolve it and before its _k3sm-owned data root is usable.
	uid, err := sys.EnsureServiceUser(cfg.ServiceUser)
	if err != nil {
		return fmt.Errorf("install: ensure service user %s: %w", cfg.ServiceUser, err)
	}
	cfg.Logger.Info("ensured service user", "user", cfg.ServiceUser, "uid", uid)

	// 2. Copy the binary into the root-owned install dir (both daemons exec it).
	if _, err := sys.CopyToRootOwned(cfg.BinarySource, cfg.InstallDir); err != nil {
		return fmt.Errorf("install: copy binary to %s: %w", cfg.InstallDir, err)
	}

	// 3. Render + write both plists.
	if err := sys.WriteLaunchDaemon(cfg.plistPath(NetdLabel), NetdPlist(cfg)); err != nil {
		return fmt.Errorf("install: write %s plist: %w", NetdLabel, err)
	}
	if err := sys.WriteLaunchDaemon(cfg.plistPath(ServerLabel), ServerPlist(cfg)); err != nil {
		return fmt.Errorf("install: write %s plist: %w", ServerLabel, err)
	}

	// 4. Bootstrap netd FIRST (root helper), then the server (depends on it).
	if err := sys.LaunchctlBootstrap(NetdLabel); err != nil {
		return fmt.Errorf("install: bootstrap %s: %w", NetdLabel, err)
	}
	if err := sys.LaunchctlBootstrap(ServerLabel); err != nil {
		return fmt.Errorf("install: bootstrap %s: %w", ServerLabel, err)
	}

	// 5. Write the admin kubeconfig to the HUMAN's home (owned by them, not root).
	if err := sys.WriteUserKubeconfig(cfg.TargetUser, AdminKubeconfig(cfg)); err != nil {
		return fmt.Errorf("install: write admin kubeconfig for %s: %w", cfg.TargetUser, err)
	}
	cfg.Logger.Info("k3sm installed", "install-dir", cfg.InstallDir, "kubeconfig-owner", cfg.TargetUser)
	return nil
}

// Uninstall tears both daemons down and removes the install dir. It is
// idempotent: a bootout of a not-loaded label is a no-op, so re-running after a
// partial install (or twice) is safe. The server is booted out FIRST (so it
// stops issuing privileged requests), then netd (which flushes lo0/pf/utun on
// SIGTERM). Privileged STATE (the data root) is intentionally left in place; the
// operator removes it explicitly.
func Uninstall(ctx context.Context, sys System, cfg Config) error {
	cfg = cfg.withDefaults()
	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	// Server first (stops driving the helper), then netd (its SIGTERM handler
	// tears down lo0 aliases / pf anchor / utun).
	note(sys.LaunchctlBootout(ServerLabel))
	note(sys.LaunchctlBootout(NetdLabel))
	note(sys.RemoveAll(cfg.InstallDir))
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
