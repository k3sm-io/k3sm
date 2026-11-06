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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/nodecred"
	"k3sm.io/k3sm/pkg/version"
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

// AdminTokenRotatedMarkerName is the file a control-plane install leaves in
// the server work dir when it minted a new admin token over an installed one
// (Result.AdminTokenRotated). It holds two lines, the install's time (RFC
// 3339) and the release version the install put on the node (what `k3sm
// version` reports after it), and never the token or anything derived from
// it. The update controller decides by the version, which no clock can skew.
//
// It exists because the stderr line the install prints for the rotation is
// read by nobody under a managed roll: that install runs inside the root
// helper, whose output goes to a root-owned log. The server daemon reads the
// marker once its node is Ready, publishes its version and time on its Node
// for the update controller, and removes it (see AdminTokenRotatedMarkerPath).
const AdminTokenRotatedMarkerName = "admin-token-rotated-at"

// AdminTokenRotatedMarkerPath is the rotation marker inside a control plane's
// work dir (<data root>/server for an installed server). It is a function of
// the work dir alone so the installer, which derives the dir from the data
// root, and the daemon, which is told it, name one file.
func AdminTokenRotatedMarkerPath(serverWorkDir string) string {
	return filepath.Join(serverWorkDir, AdminTokenRotatedMarkerName)
}

// adminTokenRollback keeps the operator's kubeconfig working across a rollback.
// The admin token file is not in the tree a rollback swaps back, and the daemons
// the rollback restarts read it, so without this a rollback leaves the control
// plane serving a token this install minted and the kubeconfig step never wrote:
// the operator's kubeconfig is Unauthorized until the next install.
//
// Putting the old token back comes first, because it also keeps every copy of
// the kubeconfig on another Mac working. A rollback that could not do that writes
// the new kubeconfig instead. The token is never logged.
type adminTokenRollback struct {
	// prior is the token the file held before this install staged its own,
	// empty when it held none this install would have carried.
	prior string
	uid   uint32
	// settled says the kubeconfig the operator holds still matches the file.
	settled bool
}

// captureAdminToken reads the installed admin token by carriedAdminToken's trust
// rules, right before the install stages over it. The rules' warnings speak of an
// update minting a token, which this read does not decide, so they stay unsaid. A
// worker has neither a token nor an admin kubeconfig, so it has nothing to keep.
func captureAdminToken(sys System, cfg Config, uid uint32) adminTokenRollback {
	if cfg.Role != RoleServer {
		return adminTokenRollback{settled: true}
	}
	quiet := cfg
	quiet.Logger = slog.New(slog.DiscardHandler)
	prior, ok := carriedAdminToken(sys, quiet, uid)
	if !ok {
		prior = ""
	}
	return adminTokenRollback{prior: prior, uid: uid, settled: prior == cfg.AdminToken}
}

// putBack stages the token captureAdminToken read. It runs after the reverse swap
// and before the daemons restart, so they come back reading it. A failure is
// survived: the rollback then writes the kubeconfig (keepKubeconfigWorking).
func (r *adminTokenRollback) putBack(sys System, cfg Config) {
	if r.settled || r.prior == "" {
		return
	}
	if err := stageTokenFile(sys, r.uid, r.prior, cfg.serverTokenPath(), "admin token", ServerTokenFileMode, ServerTokenDirMode); err != nil {
		cfg.Logger.Warn("could not put the previous admin token back after the rollback", "path", cfg.serverTokenPath(), "err", err)
		return
	}
	r.settled = true
	cfg.Logger.Info("put the previous admin token back: the admin kubeconfig already carries it", "path", cfg.serverTokenPath())
}

// keepKubeconfigWorking runs once a rollback returned err. When the old token did
// not go back (none to restore, a failed write, a failed reverse swap), the
// control plane serves this install's token, so the kubeconfig is written with it.
// A first install has rolled nothing back and its failure asks for another
// install, so it writes nothing. The result is err, plus what became of the
// kubeconfig when that write failed.
func (r *adminTokenRollback) keepKubeconfigWorking(ctx context.Context, sys System, cfg Config, previous bool, err error) error {
	if r.settled || !previous {
		return err
	}
	if kerr := writeAdminKubeconfig(ctx, sys, &cfg); kerr != nil {
		return fmt.Errorf("%w; the admin token changed and the admin kubeconfig could not be rewritten, so it gets Unauthorized until `sudo k3sm install` succeeds: %v", err, kerr)
	}
	cfg.Logger.Warn("the previous admin token could not be put back, so the admin kubeconfig was rewritten with the new one: copy it again to every other Mac or tool that uses it", "kubeconfig-owner", cfg.TargetUser)
	return err
}

// recordAdminTokenRotation leaves the rotation marker for the server daemon
// when this install minted over an installed token. An install that kept the
// token leaves an existing marker in place: the rotation it reports has not
// been published yet if the marker is still there, and only the node removes
// it, once its Node carries the mark (the update controller counts a mark naming
// the release the node was moved to, and falls back to the node's handover time
// only for a mark naming another version). The marker is the service user's (the
// daemon consumes it), 0600 like the token beside it, and written
// temp-and-rename by the seam.
func recordAdminTokenRotation(sys System, cfg Config, uid uint32, rotated bool) error {
	if !rotated {
		return nil
	}
	path := AdminTokenRotatedMarkerPath(cfg.serverWorkDir())
	at := sys.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	release := version.Get().Version
	if err := sys.WriteServiceUserFile(path, []byte(at+"\n"+release+"\n"), uid, ServerTokenFileMode, ServerTokenDirMode); err != nil {
		return fmt.Errorf("install: record the admin token rotation at %s: %w", path, err)
	}
	cfg.Logger.Info("recorded the admin token rotation for the server to report on its Node", "path", path, "at", at, "release", release)
	return nil
}
