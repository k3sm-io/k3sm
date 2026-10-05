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
	"io/fs"
	"net"
	"path/filepath"
	"strconv"
	"strings"

	"k3sm.io/k3sm/pkg/executor"
)

// The embedded-etcd HA request of `k3sm install`.
//
// `k3sm server` forms an HA control plane with --cluster-init and joins one with
// --server-join --server <host>, each with a non-loopback --node-ip the etcd peer
// listener binds. Before the installer could say so itself, those flags reached
// a daemon only through a carried argument set, which a first install does not
// have: an operator could form a cluster only by hand-writing the server-arguments
// record. Config.ClusterInit and Config.ServerJoin are the installer's own
// request. They are merged into the operator's arguments in exactly one place
// (resolvedExtraServerArgs), so the rendered argv and the written record carry the
// same flags and a later plain reinstall carries them forward the way --mesh-ip
// already is.

const (
	// serverJoinServerFlag and nodeIPFlag are the two valued `k3sm server` flags
	// an HA request renders beside its role flag.
	serverJoinServerFlag = "server"
	nodeIPFlag           = "node-ip"
	// serverJoinTokenName is the leaf name of the staged server-class join token
	// in the server work dir. It is a different file from the static admin token
	// (serverTokenName) because it is a different credential: the admin token is
	// re-minted by every install, the join token is the operator's and is staged
	// only when they pass one.
	serverJoinTokenName = "join-token"
)

// ErrEtcdRoleSwitch refuses an install that asks a server for the other
// embedded-etcd role than the one its carried arguments and its member data
// already have.
var ErrEtcdRoleSwitch = errors.New("install: this server already holds an embedded etcd member in the other role")

// etcdRoleFlags are the flags an HA request replaces in the carried arguments:
// both role flags (a request for one drops the other) and the two values that
// describe the member.
var etcdRoleFlags = map[string]bool{
	clusterInitFlag:      true,
	serverJoinFlag:       true,
	serverJoinServerFlag: true,
	nodeIPFlag:           true,
}

// etcdRequested reports whether THIS install asked for an HA role.
func (c Config) etcdRequested() bool {
	return c.Role == RoleServer && (c.ClusterInit || c.ServerJoin)
}

// serverJoining reports whether THIS install asked the server to join an
// existing HA control plane, the one request that carries a credential.
func (c Config) serverJoining() bool { return c.Role == RoleServer && c.ServerJoin }

// setEtcdArgs returns args with every carried HA flag removed (either spelling,
// inline or separate value) and this install's request appended:
// --cluster-init, or --server-join --server <host>, then --node-ip <ip>.
// The two role flags are booleans, which Go's flag package never gives a
// separate value, so only --server and --node-ip consume the argument after
// them.
func setEtcdArgs(args []string, c Config) []string {
	out := make([]string, 0, len(args)+5)
	for i := 0; i < len(args); i++ {
		name, _, inline := splitFlag(args[i])
		if !etcdRoleFlags[name] {
			out = append(out, args[i])
			continue
		}
		if !inline && (name == serverJoinServerFlag || name == nodeIPFlag) {
			i++ // drop the separate value too
		}
	}
	if c.ServerJoin {
		out = append(out, "--"+serverJoinFlag, "--"+serverJoinServerFlag, c.JoinServer)
	} else {
		out = append(out, "--"+clusterInitFlag)
	}
	return append(out, "--"+nodeIPFlag, c.NodeIP)
}

// boolFlagSet reports whether args set the named boolean flag, in any spelling
// (single or double dash, bare or with an inline value Go's flag package reads
// as true: =true, =1, =t, =T, =TRUE, =True). An inline false, or a value the
// flag package would reject, does not count.
func boolFlagSet(args []string, name string) bool {
	for _, a := range args {
		n, value, inline := splitFlag(a)
		if n != name {
			continue
		}
		if !inline {
			return true
		}
		if b, err := strconv.ParseBool(value); err == nil && b {
			return true
		}
	}
	return false
}

// serverJoinTokenPath is where Install stages the server-class join token for a
// joining server: <DataRoot>/server/join-token, service-user-owned 0600. Derived,
// never configured, for the reason serverTokenPath is.
func (c Config) serverJoinTokenPath() string {
	return filepath.Join(c.serverWorkDir(), serverJoinTokenName)
}

// serverDaemonTokenPath is the file the server plist's --token-file names. A
// joining server reads its server-class join token from it at EVERY start: the
// CA-bundle import runs on each start of a --server-join daemon and the promotion
// of a learner can happen on any of them, so the daemon needs the credential
// for as long as --server is on its argv. Every other server reads its static
// admin token. The answer comes from the RESOLVED arguments, so a plain
// reinstall of a joined server keeps pointing at the join token it staged.
func (c Config) serverDaemonTokenPath() string {
	if boolFlagSet(c.resolvedExtraServerArgs(), serverJoinFlag) {
		return c.serverJoinTokenPath()
	}
	return c.serverTokenPath()
}

// stagedJoinTokenPath is where this install stages the operator's join token:
// the server work dir for a joining server, the agent work dir otherwise.
func (c Config) stagedJoinTokenPath() string {
	if c.serverJoining() {
		return c.serverJoinTokenPath()
	}
	return c.agentTokenPath()
}

// ValidateHARequest is THE contract of an embedded-etcd HA request, over the
// Config the request becomes. It is pure and exported because there must be
// exactly one copy of it: `k3sm install` calls it at parse time, before any
// privilege is taken, and Install calls it again before anything is written,
// so a caller that builds a Config by hand cannot render a daemon `k3sm server`
// would refuse at every launchd respawn, and the two cannot drift.
//
// On RoleServer a join value (JoinServer, TokenFile) means "the operator passed
// --server / --token-file", and NodeIP means "--node-ip": each is refused when
// the request it belongs to is absent, so a flag that would be silently
// ignored is stopped instead.
func ValidateHARequest(cfg Config) error {
	if cfg.Role != RoleServer {
		switch {
		case cfg.ClusterInit:
			return fmt.Errorf("--%s cannot be combined with --agent: it configures the control plane, and a worker runs none of it", clusterInitFlag)
		case cfg.ServerJoin:
			return fmt.Errorf("--%s cannot be combined with --agent: it configures the control plane, and a worker runs none of it", serverJoinFlag)
		}
		return nil
	}
	if cfg.ClusterInit && cfg.ServerJoin {
		return fmt.Errorf("--cluster-init and --server-join are mutually exclusive: --cluster-init forms a new etcd cluster on this server, --server-join adds it to an existing one")
	}
	if !cfg.ServerJoin {
		for _, f := range []struct{ name, value string }{
			{serverJoinServerFlag, cfg.JoinServer},
			{"token-file", cfg.TokenFile},
		} {
			if f.value == "" {
				continue
			}
			if cfg.ClusterInit {
				return fmt.Errorf("--%s cannot be combined with --cluster-init: --cluster-init forms a new cluster and joins nothing; --%s belongs to --server-join (another server) or --agent (a worker)", f.name, f.name)
			}
			return fmt.Errorf("--%s needs --agent or --server-join: it configures a node joining an existing cluster, and without either this Mac is being installed as a control plane of its own", f.name)
		}
	}
	if !cfg.ClusterInit && !cfg.ServerJoin {
		if cfg.NodeIP != "" {
			return fmt.Errorf("--node-ip needs --agent, --cluster-init or --server-join: on a control-plane install it is the embedded etcd peer address, and a single-node control plane has none")
		}
		return nil
	}
	if cfg.ServerJoin {
		if strings.TrimSpace(cfg.JoinServer) == "" {
			return fmt.Errorf("--server-join needs --server (an existing server's LAN address)")
		}
		if cfg.TokenFile == "" {
			return fmt.Errorf("--server-join needs --token-file (a file holding the server token `k3sm token create --server` printed on an existing server)")
		}
	}
	return ValidateEtcdNodeIP(cfg.NodeIP)
}

// ValidateEtcdNodeIP refuses a --node-ip an embedded etcd member cannot
// advertise: one that does not parse, loopback, or unspecified. It is the
// predicate `k3sm server` applies to the same flag, so the installer refuses
// at the terminal what the daemon would refuse at every start.
func ValidateEtcdNodeIP(raw string) error {
	ip := net.ParseIP(raw)
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return fmt.Errorf("--cluster-init and --server-join need --node-ip set to this Mac's LAN address (got %q): the etcd peer listener binds it and every other server dials it, so it cannot be loopback or unspecified", raw)
	}
	return nil
}

// refuseEtcdRoleSwitch refuses an HA request for the OTHER role than the
// carried arguments name while this server's etcd member data is on disk.
//
// A member's data dir records which cluster it belongs to. Re-rendering a server
// that formed a cluster with --server-join (or a joined member with
// --cluster-init) over that data would start a member whose flags and whose data
// describe two different clusters. With the data dir gone, as after the member
// was removed and its data deliberately wiped, there is nothing to contradict
// and the request replaces the carried role.
func refuseEtcdRoleSwitch(cfg Config, carried []string) error {
	if !cfg.etcdRequested() {
		return nil
	}
	carriedInit := boolFlagSet(carried, clusterInitFlag)
	carriedJoin := boolFlagSet(carried, serverJoinFlag)
	var had, asked string
	switch {
	case cfg.ServerJoin && carriedInit:
		had, asked = clusterInitFlag, serverJoinFlag
	case cfg.ClusterInit && carriedJoin:
		had, asked = serverJoinFlag, clusterInitFlag
	default:
		return nil
	}
	// An EMPTY data dir holds no member either (a wipe that removed the
	// contents and kept the directory), so it counts as absent.
	dir := executor.EtcdDataDir(cfg.serverWorkDir())
	switch entries, err := cfg.DataRootFS.ReadDir(dir); {
	case errors.Is(err, fs.ErrNotExist) || (err == nil && len(entries) == 0):
		cfg.Logger.Info("--"+asked+" replaces the carried --"+had+": this server holds no etcd member data", "etcd-data", dir)
		return nil
	case err != nil:
		return fmt.Errorf("install: check for this server's etcd member data at %s: %w", dir, err)
	}
	return fmt.Errorf("%w: it was installed with --%s and its member data is in %s, so --%s would start that member under flags that describe a different cluster. Nothing has been written. To change its role: stop it (`sudo launchctl bootout system/%s`), make sure its member is no longer part of the cluster, remove %s (this discards this server's copy of the cluster data), then run this install again",
		ErrEtcdRoleSwitch, had, dir, asked, ServerLabel, dir)
}

// retireStaleServerJoinToken removes the staged server join token when the
// carried arguments named --server-join and the arguments this install renders
// do not: the role change refuseEtcdRoleSwitch allows once the member data is
// gone. Every other install leaves the file alone, so a joined server's plain
// reinstall keeps the token its daemon reads at every start.
func retireStaleServerJoinToken(sys System, cfg Config, carried []string) error {
	if cfg.Role != RoleServer || !boolFlagSet(carried, serverJoinFlag) {
		return nil
	}
	probe := cfg
	probe.ExtraServerArgs = carried
	if boolFlagSet(probe.resolvedExtraServerArgs(), serverJoinFlag) {
		return nil
	}
	path := cfg.serverJoinTokenPath()
	if err := sys.RemoveAll(path); err != nil {
		return fmt.Errorf("install: remove the server join token %s this server no longer joins with: %w", path, err)
	}
	cfg.Logger.Info("removed the staged server join token: this server no longer joins an existing control plane", "path", path)
	return nil
}
