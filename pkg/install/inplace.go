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
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/nodecred"
)

// The in-place update: `k3sm install --from-staging <dir>` with no role flag
// (--agent, --server-join) and no --token-file reinstalls whatever this Mac
// already is, from the staged build. It is the shape the k3sm-netd root helper
// runs for a managed update, which knows nothing about the node it serves:
// the role is read from the installed daemon plist, an agent keeps the
// --server its plist names and the node credential its work dir holds, and
// every operator argument is carried over from the installed plist (or the
// recorded arguments) the way any reinstall carries it. The result is the
// same reinstall an operator performs with explicit flags, with one
// difference: a control plane keeps its admin token (carriedAdminToken).

// Result is what an install reports beyond success.
type Result struct {
	// AdminTokenRotated is set when an in-place update of a control plane
	// could not carry the installed admin token (missing, malformed, or a file
	// carriedAdminToken does not trust) and minted a new one, so every copy of
	// the admin kubeconfig outside this Mac stops authenticating. A fresh
	// install, which always mints, never sets it.
	AdminTokenRotated bool
}

// ErrNothingToUpdate refuses an in-place update on a Mac with no k3sm
// installed.
var ErrNothingToUpdate = errors.New("install: nothing to update in place: this Mac carries neither the k3sm server nor the agent daemon")

// FileOwner names the user that owns the file at path.
type FileOwner func(path string) (user string, err error)

// ResolveInPlace turns cfg, an in-place update (see above), into the
// reinstall of the installed role. A control plane is reinstalled as one; its
// admin kubeconfig is rewritten for cfg.TargetUser, or when that is empty for
// the owner of the kubeconfig the last install recorded writing. A worker is
// reinstalled with its plist's --server and must hold a valid node credential,
// because it rejoins with no token. A control plane also keeps the admin token
// it already serves (carriedAdminToken). Both daemons installed, an unreadable
// plist or record, and nothing installed at all refuse.
//
// One case is not an update: nothing is installed and cfg.TargetUser is set.
// That is k3sm.app's first install (`--from-staging <dir> --user <name>`), and
// cfg comes back unchanged, a control-plane install as before.
func ResolveInPlace(sys System, cfg Config, owner FileOwner) (Config, error) {
	d := cfg.withDefaults()
	srvPath, srv, err := roleInstalled(sys, d, RoleServer)
	if err != nil {
		return cfg, fmt.Errorf("install: read the installed server plist %s: %w", srvPath, err)
	}
	agPath, ag, err := roleInstalled(sys, d, RoleAgent)
	if err != nil {
		return cfg, fmt.Errorf("install: read the installed agent plist %s: %w", agPath, err)
	}
	switch {
	case srv && ag:
		return cfg, fmt.Errorf("install: both %s and %s are on disk, so the role to update in place is ambiguous: run `k3sm uninstall` and install the role this Mac should have", srvPath, agPath)
	case ag:
		return resolveAgentInPlace(sys, cfg, d)
	case srv:
		return resolveServerInPlace(sys, cfg, d, owner)
	case cfg.TargetUser != "":
		cfg.Role = RoleServer
		return cfg, nil
	}
	return cfg, ErrNothingToUpdate
}

func resolveAgentInPlace(sys System, cfg, d Config) (Config, error) {
	host, err := AgentJoinServer(sys, d)
	if err != nil {
		return cfg, fmt.Errorf("install: update the agent in place: %w", err)
	}
	state, _, err := nodecred.Status(sysFS{sys: sys}, d.agentWorkDir(), time.Now())
	if err != nil && state != nodecred.Corrupt {
		return cfg, fmt.Errorf("install: update the agent in place: read its node credential in %s: %w", d.agentWorkDir(), err)
	}
	switch state {
	case nodecred.Valid, nodecred.AddressMismatch:
	default:
		return cfg, fmt.Errorf("install: update the agent in place: its node credential in %s is %s, and an in-place update rejoins with no token; reinstall with `--agent --server %s --token-file <file>`", d.agentWorkDir(), state, host)
	}
	cfg.Role = RoleAgent
	cfg.JoinServer = host
	cfg.Logger = d.Logger
	cfg.Logger.Info("updating the installed agent in place", "server", host)
	return cfg, nil
}

func resolveServerInPlace(sys System, cfg, d Config, owner FileOwner) (Config, error) {
	cfg.Role = RoleServer
	cfg.Logger = d.Logger
	cfg.keepAdminToken = true
	if cfg.TargetUser != "" {
		cfg.Logger.Info("updating the installed server in place", "kubeconfig-owner", cfg.TargetUser)
		return cfg, nil
	}
	rec, err := dataroot.ReadServerArgsRecord(systemFiles{sys}, d.ServerArgsRecord)
	if err != nil {
		return cfg, fmt.Errorf("install: update the server in place: %w", err)
	}
	if rec == nil || rec.AdminKubeconfig == "" {
		return cfg, fmt.Errorf("install: update the server in place: %s does not record which admin kubeconfig the last install wrote, so its owner is unknown; run the install again with --user", d.ServerArgsRecord)
	}
	if owner == nil {
		return cfg, fmt.Errorf("install: update the server in place: no way to read the owner of %s", rec.AdminKubeconfig)
	}
	u, err := owner(rec.AdminKubeconfig)
	if err != nil || u == "" || u == "root" {
		return cfg, fmt.Errorf("install: update the server in place: the owner of the recorded admin kubeconfig %s is unusable (%q, %v); run the install again with --user", rec.AdminKubeconfig, u, err)
	}
	cfg.TargetUser = u
	cfg.Logger.Info("updating the installed server in place", "kubeconfig-owner", u, "kubeconfig", rec.AdminKubeconfig)
	return cfg, nil
}

// adminTokenPattern is the shape generateToken mints. A staged value of any
// other shape is not carried: the server renders the token into its
// token-auth CSV, so a stray comma or newline would change what it grants.
var adminTokenPattern = regexp.MustCompile(`^k3sm-[0-9a-f]{48}$`)

// maxAdminTokenFile bounds the read of the staged admin token: a minted one
// is 53 bytes plus a newline.
const maxAdminTokenFile = 256

// carriedAdminToken returns the admin token the installed control plane
// serves (the file staged at serverTokenPath) and true, or false so the
// install mints one.
//
// An in-place update is not a fresh install, so it keeps the credential, as
// k3s keeps its token across an upgrade: a fresh token would leave every copy
// of the admin kubeconfig outside this Mac (a worker's, a tool's)
// Unauthorized after a managed roll that reports Done, with no path for them
// to learn the new one. The cluster CA survives the reinstall as well, so the
// kubeconfig the install rewrites is the one those copies already hold.
//
// The install reads this file as root from a directory the service user can
// write, so the file is trusted only when the descriptor read says it is a
// regular file (never a symlink) owned by root or the service uid with no
// group or other write bit. A missing, untrusted or malformed file falls back
// to minting, so a repair still fixes a corrupt one, and the caller reports
// the rotation (Result.AdminTokenRotated). The value is never logged.
func carriedAdminToken(sys System, cfg Config, serviceUID uint32) (string, bool) {
	path := cfg.serverTokenPath()
	const rotated = "this update mints a new admin token, and every copy of the admin kubeconfig on another Mac must be refreshed"
	raw, e, err := sys.ReadOwnedRegularFile(path, maxAdminTokenFile)
	if err != nil {
		cfg.Logger.Warn("the installed admin token is unreadable or not a regular file; "+rotated, "path", path, "err", err)
		return "", false
	}
	if e.UID != 0 && e.UID != int(serviceUID) {
		cfg.Logger.Warn("the installed admin token is owned by neither root nor the service user; "+rotated, "path", path, "uid", e.UID)
		return "", false
	}
	if e.Mode.Perm()&0o022 != 0 {
		cfg.Logger.Warn("the installed admin token is group- or world-writable; "+rotated, "path", path, "mode", e.Mode.Perm())
		return "", false
	}
	tok := strings.TrimSpace(string(raw))
	if !adminTokenPattern.MatchString(tok) {
		cfg.Logger.Warn("the installed admin token is not a k3sm admin token; "+rotated, "path", path)
		return "", false
	}
	cfg.Logger.Info("keeping the installed admin token across the in-place update", "path", path)
	return tok, true
}

// keepAdminTokenInPlace sets cfg.AdminToken for an in-place update of a
// control plane: the carried token, or a minted one when it cannot be carried,
// reported as minted so Install sets Result.AdminTokenRotated once the new
// token is staged. Any other install is left as it is.
func keepAdminTokenInPlace(sys System, cfg *Config, serviceUID uint32) (minted bool, err error) {
	if !cfg.keepAdminToken || cfg.AdminToken != "" {
		return false, nil
	}
	if tok, ok := carriedAdminToken(sys, *cfg, serviceUID); ok {
		cfg.AdminToken = tok
		return false, nil
	}
	tok, err := generateToken()
	if err != nil {
		return false, err
	}
	cfg.AdminToken = tok
	return true, nil
}
