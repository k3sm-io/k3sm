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
	"bytes"
	"encoding/xml"
	"fmt"
	"io/fs"
	"path/filepath"
	"strconv"
)

// The two LaunchDaemon plist modes, and why the control plane's is not the
// other one.
//
// PlistMode is launchd's conventional 0644: root writes it, launchd reads it as
// root, and anyone may look at it. That is right for a plist whose argv is a set
// of paths and ports.
//
// ServerPlistMode is 0600, because the server plist's argv is the one that
// carries credentials. Not the admin token any more — that moved to a staged
// file — but the OPERATOR's preserved arguments, which k3sm cannot vouch for and
// which may carry a credential. pkg/dataroot already keeps the server-arguments
// record root-only 0600 for exactly that reason (serverArgsRecordMode), and the
// plist holds the same strings, so leaving it 0644 kept a world-readable second
// copy of what the record is careful about.
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

// daemonEnv is the environment a service-user node daemon runs under: HOME is
// the data root (the _k3sm home), and the Go module and build caches are pinned
// inside the role's own work dir rather than left to derive from HOME.
//
// The pin is what keeps the boot-time kine build working under a root-owned
// data root. Derived from HOME, the caches land at <home>/go/pkg/mod and
// <home>/Library/Caches/go-build, and the service user cannot create a new
// top-level directory in a root:wheel 0755 root. The work dir is already the
// service user's (0700, see OwnershipOf), so nothing new has to be handed over.
// The executor's module-cache lookup (`go env GOMODCACHE`) and the kine build's
// inherited environment honour both variables as they are.
func daemonEnv(dataRoot, workDir string) map[string]string {
	return map[string]string{
		"HOME":       dataRoot,
		"GOMODCACHE": filepath.Join(workDir, "go", "mod"),
		"GOCACHE":    filepath.Join(workDir, "go", "build"),
	}
}

// serverFileLimit is the soft+hard RLIMIT_NOFILE (launchd NumberOfFiles) the
// server AND agent LaunchDaemons request — both host a node, and a worker runs
// the same Service proxy the control plane does. The process hosts the proxy /
// UDP relay, whose flow budget darwin-net sizes as max(8192, rl.Cur/2)
// (defaultUDPFlowBudget) — so the fd table it reads must be raised above launchd's
// 256 default, which floors the budget at 8192 with NO headroom for the
// co-resident apiserver/kine.
//
// 131072 is ≤ kern.maxfilesperproc on a large Mac, so every descriptor it grants
// can actually be allocated there. That ceiling scales with installed RAM
// (measured on macOS 26: 245760 at 64 GB, 10240 at 8 GB); launchd still grants
// the requested soft limit on a small Mac, but the kernel refuses opens past the
// ceiling with EMFILE. The k3s Linux value (1048576) exceeds the macOS ceiling
// on every Mac. 131072 yields a UDP flow budget of 65536 (rl.Cur/2), ~8× the
// 8192 floor, leaving the control plane the other half; darwin-net derives the
// budget from the kernel ceiling too, so a small Mac falls back toward the floor.
//
// Reload contract: launchd applies *ResourceLimits at process spawn from the job
// definition captured at bootstrap — so this raised limit binds on a fresh
// install or an uninstall→install (bootout→bootstrap), not on
// `launchctl kickstart -k`, which respawns the existing in-memory job with the
// old limit. Existing installs need a reinstall for the new limit to bind.
// Install says both halves out loud (checkFileLimit): a WARN when the kernel
// ceiling sits below this value, and a post-restart notice when the plist it
// replaced requested a different one.
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
		// it once at start through the same reader the agent uses. A joining HA
		// server is pointed at its staged server-class join token instead (see
		// serverDaemonTokenPath).
		"--token-file", cfg.serverDaemonTokenPath(),
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
		EnvironmentVars:  daemonEnv(cfg.DataRoot, cfg.serverWorkDir()),
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
		EnvironmentVars:  daemonEnv(cfg.DataRoot, cfg.agentWorkDir()),
		ExitTimeOut:      agentExitTimeOut,
		// The same RLIMIT_NOFILE raise the control plane gets, for the same
		// reason and with the same reload contract: a worker hosts the Service
		// proxy and the UDP relay, whose flow budget darwin-net sizes as
		// max(8192, rl.Cur/2), so under launchd's 256-fd default the budget
		// floors with no headroom for the node's own watches and pod streams.
		SoftFileLimit: serverFileLimit,
	})
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
