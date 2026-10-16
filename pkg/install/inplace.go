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
// same reinstall an operator performs with explicit flags.

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
// because it rejoins with no token. Both daemons installed, an unreadable
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
