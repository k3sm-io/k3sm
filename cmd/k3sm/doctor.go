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

package main

import (
	"errors"
	"flag"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/status"
	"k3sm.io/runtimed/pkg/sandbox"
)

// supportedMacOSFloor is the minimum supported macOS major version (macOS 26).
// k3sm targets darwin/arm64 on macOS 26+; below the floor the runtime SPI it
// depends on is not guaranteed present.
const supportedMacOSFloor = 26

// doctorStatus is the verdict of a single preflight check. Only statusFail makes
// `k3sm doctor` exit non-zero; statusWarn and statusSkip are surfaced distinctly
// but do not fail the command. statusSkip means "could not/should not probe" and
// must never read as healthy (statusPass) — see checkDatastore.
type doctorStatus int

const (
	statusPass doctorStatus = iota
	statusWarn
	statusFail
	statusSkip
)

// String renders the status as a fixed-width tag for the doctor ladder.
func (s doctorStatus) String() string {
	switch s {
	case statusPass:
		return "PASS"
	case statusWarn:
		return "WARN"
	case statusFail:
		return "FAIL"
	case statusSkip:
		return "SKIP"
	default:
		return "????"
	}
}

// checkResult is the outcome of one check: a stable name, a status verdict, and a
// human-readable detail explaining the verdict.
type checkResult struct {
	name   string
	status doctorStatus
	detail string
}

// doctorEnv is the set of fakeable seams the pure check functions read. The real
// probes (sysctl/csrutil/launchctl/sqlite) are wired only inside runDoctor at the
// main boundary via realDoctorEnv; the check functions never call os/exec or open
// files directly, so unit tests inject a fake doctorEnv per case (-race / t.Parallel
// safe — it is a value with function fields, no shared mutable global).
type doctorEnv struct {
	goarch           string                                                                // runtime.GOARCH
	macOSVersion     func() (string, error)                                                // sysctl kern.osproductversion
	sipEnabled       func() (bool, error)                                                  // csrutil status
	helperState      func() (installed, running bool)                                      // launchctl print system/io.k3sm.netd
	brewPresent      func() bool                                                           // exec.LookPath("brew")
	datastorePosture func() (present bool, userVersion int, journalMode string, err error) // read-only sqlite header
	developerDir     func() (string, error)                                                // xcode-select -p
	// nodeRole is which node this Mac is installed as, from the two
	// node-daemon plists (install.RoleFromPlists), and whether it is installed
	// at all. agentState is the agent LaunchDaemon's launchd state, and
	// agentCredential is what the node credential store holds and when this
	// node's client certificate runs out.
	nodeRole        func() (install.Role, bool)
	agentState      func() (installed, running bool)
	agentCredential func() (status.CredentialState, time.Time)
}

// doctorCheck is a registry entry: a stable name and its pure check function. The
// gate (cmd/k3sm::TestDoctorChecksTable) iterates doctorChecks() with fake envs.
type doctorCheck struct {
	name string
	fn   func(doctorEnv) checkResult
}

// doctorChecks is the declarative registry of preflight checks, run in order. Each
// fn returns a checkResult whose name matches the entry name (asserted by the gate).
func doctorChecks() []doctorCheck {
	return []doctorCheck{
		{"arch", checkArch},
		{"macos", checkMacOS},
		{"sip", checkSIP},
		{"netd-helper", checkHelper},
		{"brew", checkBrew},
		{"datastore", checkDatastore},
		{"toolchain", checkXcodeToolchain},
		{"agent-daemon", checkAgentDaemon},
	}
}

// checkArch verifies the binary runs on Apple Silicon (arm64). k3sm is
// Apple-Silicon-only, so a non-arm64 arch is a hard FAIL.
func checkArch(env doctorEnv) checkResult {
	if env.goarch == "arm64" {
		return checkResult{"arch", statusPass, "arm64 (Apple Silicon)"}
	}
	return checkResult{"arch", statusFail, fmt.Sprintf("%s — k3sm is Apple-Silicon-only (arm64)", env.goarch)}
}

// checkMacOS verifies macOS is at or above the supported floor. Below the floor is
// a FAIL; a probe/parse error is a WARN (could not determine, not proven bad).
func checkMacOS(env doctorEnv) checkResult {
	ver, err := env.macOSVersion()
	if err != nil {
		return checkResult{"macos", statusWarn, fmt.Sprintf("could not determine macOS version: %v", err)}
	}
	major, perr := majorVersion(ver)
	if perr != nil {
		return checkResult{"macos", statusWarn, fmt.Sprintf("unparseable macOS version %q: %v", ver, perr)}
	}
	if major >= supportedMacOSFloor {
		return checkResult{"macos", statusPass, fmt.Sprintf("macOS %s (>= %d)", ver, supportedMacOSFloor)}
	}
	return checkResult{"macos", statusFail, fmt.Sprintf("macOS %s is below the supported floor (macOS %d)", ver, supportedMacOSFloor)}
}

// checkSIP reports System Integrity Protection posture. k3sm needs no SIP-off
// (see docs/privilege-model.md), so enabled is PASS; disabled is an unexpected,
// weaker posture (WARN, not fatal); a probe error is WARN.
func checkSIP(env doctorEnv) checkResult {
	on, err := env.sipEnabled()
	if err != nil {
		return checkResult{"sip", statusWarn, fmt.Sprintf("could not determine SIP status: %v", err)}
	}
	if on {
		return checkResult{"sip", statusPass, "System Integrity Protection enabled (k3sm needs no SIP-off)"}
	}
	return checkResult{"sip", statusWarn, "SIP disabled — unexpected; k3sm does not require it and this is a weaker posture"}
}

// checkHelper reports the k3sm-netd root helper's launchd state. Installed and
// running is PASS; installed-but-stopped or not-installed are WARN — the
// DEFAULT runtimed runtime refuses to start unprivileged without it (the
// runtime preflight), but root, `--runtime hostprocess` (rootless dev), and
// `--network none` (control-plane-only) all work, so it is not a hard fail.
func checkHelper(env doctorEnv) checkResult {
	installed, running := env.helperState()
	switch {
	case installed && running:
		return checkResult{"netd-helper", statusPass, install.NetdLabel + " installed and running"}
	case installed:
		return checkResult{"netd-helper", statusWarn, install.NetdLabel + " installed but not running — the default runtimed runtime and the datapath need it (sudo launchctl kickstart -k system/" + install.NetdLabel + ")"}
	default:
		return checkResult{"netd-helper", statusWarn, install.NetdLabel + " not detected — either not installed, or not readable without privilege (a system-domain launchctl print may need root); the default runtimed runtime (unprivileged) and the datapath need it — an unprivileged node without it refuses to start (run `sudo k3sm install`, or pass --runtime hostprocess for rootless dev). Re-run doctor with sudo to confirm it is truly absent"}
	}
}

// checkBrew reports Homebrew presence. Homebrew is an install vector, not a
// runtime dependency, so absence is a WARN.
func checkBrew(env doctorEnv) checkResult {
	if env.brewPresent() {
		return checkResult{"brew", statusPass, "Homebrew present"}
	}
	return checkResult{"brew", statusWarn, "Homebrew not found — an install vector, not required at runtime"}
}

// checkDatastore reports the kine SQLite datastore posture. It is a pure REPORTER:
// an absent state.db is a fresh node → SKIP (distinct from PASS — never a silent
// pass); a present, readable db → PASS reporting the bundled kine pin, user_version,
// and journal_mode. A non-WAL journal is a WARN; a read error is a WARN. Migration
// and remediation logic stays in executor, not here.
//
// The absent arm says WHY it is absent, and that depends on the role: a worker
// runs no control plane and therefore no kine at all, so telling its operator
// "the control plane has not initialized the datastore" would describe a wait
// that is never going to end.
func checkDatastore(env doctorEnv) checkResult {
	present, uv, jm, err := env.datastorePosture()
	if err != nil {
		return checkResult{"datastore", statusWarn, fmt.Sprintf("could not read datastore posture: %v", err)}
	}
	if !present {
		if role, installed := env.nodeRole(); installed && role == install.RoleAgent {
			return checkResult{"datastore", statusSkip, "no state.db, and none is expected: this Mac is installed as a k3sm worker, which runs no control plane and no kine datastore"}
		}
		return checkResult{"datastore", statusSkip, "no state.db yet (fresh node — the control plane has not initialized the kine SQLite datastore)"}
	}
	detail := fmt.Sprintf("kine %s, user_version=%d, journal_mode=%s", executor.DefaultKineVersion, uv, jm)
	if jm != "wal" {
		return checkResult{"datastore", statusWarn, detail + " (expected journal_mode=wal)"}
	}
	return checkResult{"datastore", statusPass, detail}
}

// checkXcodeToolchain reports what the k3sm.io/xcode-toolchain annotation grants
// on THIS node. It is a reporter, never a failure: a Mac with no Xcode is a
// perfectly good k3sm node for every workload that is not a build, so the two
// no-grant classes are WARN.
//
// The verdict comes from sandbox.ValidateXcodeToolchainDir — the profile
// generator's own predicate, the same one the provider asks before it stamps
// SandboxProfile.xcode_toolchain_dir. A checker that re-derived the rule here
// would be vouching for a decision it does not make, and would report a grant on
// a directory the generator then refuses; that refusal is fail-closed and costs
// the pod its start, which is exactly the outcome this row exists to predict.
//
// The node fact itself (`xcode-select -p`, unconfined) is read the same way the
// daemon reads it, deliberately: this row answers "what will the daemon grant",
// so it must start from the daemon's input, not from a confined re-probe that
// would answer a different question.
//
// Three classes, and the middle one is the reason the row exists: a Command Line
// Tools selection is a directory `xcode-select -p` reports successfully, so
// nothing upstream of the generator looks wrong, yet it is not a DEVELOPER_DIR
// the Xcode stanza can be rendered from.
func checkXcodeToolchain(env doctorEnv) checkResult {
	const (
		name   = "toolchain"
		once   = "The directory is resolved once, when the node daemon starts, so a later `xcode-select --switch` is invisible until it restarts."
		remedy = "For the Xcode toolchain run `sudo xcode-select -s /Applications/Xcode.app/Contents/Developer`."
	)
	dir, err := env.developerDir()
	if err != nil {
		return checkResult{name, statusWarn, fmt.Sprintf(
			"no developer toolchain on this node (%v), so %s grants nothing here. %s %s",
			err, runtimev1.AnnotationXcodeToolchain, remedy, once)}
	}
	granted, verr := sandbox.ValidateXcodeToolchainDir(dir, sandbox.Posture{})
	if verr != nil {
		return checkResult{name, statusWarn, fmt.Sprintf(
			"%s is not a directory the toolchain grant accepts, so %s grants nothing here — and needs to grant nothing if it is a Command Line Tools root, which a pod already reads. %s %s",
			dir, runtimev1.AnnotationXcodeToolchain, remedy, once)}
	}
	return checkResult{name, statusPass, fmt.Sprintf(
		"%s — %s grants a pod read access to this toolchain. %s",
		granted, runtimev1.AnnotationXcodeToolchain, once)}
}

// checkAgentDaemon reports the joining worker's daemon and the credential that
// makes this Mac a cluster member. On anything that is not a worker it is a
// SKIP: a control plane has no agent daemon and never will, and a WARN there
// would teach an operator to ignore the row on the Macs where it matters.
//
// On a worker it answers the question a pid cannot. launchd keeps the `k3sm
// agent` process alive whether or not the join ever succeeded, so a running
// daemon with no stored credential is a Mac that is NOT in the cluster — the
// one failure this check exists for. Its remedy spans two Macs, because the
// token is minted on the control plane and only then can this one be reinstalled
// with it.
func checkAgentDaemon(env doctorEnv) checkResult {
	const name = "agent-daemon"
	role, installed := env.nodeRole()
	if !installed || role != install.RoleAgent {
		return checkResult{name, statusSkip, fmt.Sprintf(
			"this Mac is not installed as a k3sm worker (%s is not on disk), so there is no %s daemon to check",
			install.AgentLabel+".plist", install.AgentLabel)}
	}
	daemonInstalled, running := env.agentState()
	if !daemonInstalled || !running {
		return checkResult{name, statusFail, fmt.Sprintf(
			"%s is not running, so this worker is not serving pods — run `sudo launchctl kickstart -k system/%s` and read %s",
			install.AgentLabel, install.AgentLabel, install.AgentLogPath())}
	}
	state, notAfter := env.agentCredential()
	switch state {
	case status.CredentialAbsent:
		return checkResult{name, statusWarn, fmt.Sprintf(
			"%s is running but this Mac holds no node credential yet, so it has not joined a cluster: read %s, then mint a token on the control-plane Mac (`k3sm token create`), stage it here and re-run `sudo k3sm install --role agent --server <control-plane> --token-file <file>` (the join token is read from %s)",
			install.AgentLabel, install.AgentLogPath(), agentStagedTokenPath())}
	case status.CredentialExpired:
		return checkResult{name, statusWarn, fmt.Sprintf(
			"the node credential expired on %s, so this worker can no longer authenticate: mint a token on the control-plane Mac (`k3sm token create`) and re-run `sudo k3sm install --role agent --server <control-plane> --token-file <file>` here to rejoin",
			notAfter.UTC().Format("2006-01-02"))}
	case status.CredentialCorrupt:
		return checkResult{name, statusWarn, fmt.Sprintf(
			"the stored node credential in %s does not parse; read %s, remove the offending file to force a fresh token join, and rejoin with a token minted on the control-plane Mac",
			agentCredentialDir(), install.AgentLogPath())}
	case status.CredentialValid:
		return checkResult{name, statusPass, fmt.Sprintf(
			"%s is running and this node's credential is valid until %s",
			install.AgentLabel, notAfter.UTC().Format("2006-01-02"))}
	default:
		return checkResult{name, statusSkip, fmt.Sprintf(
			"%s is running; the node credential in %s is not readable as this user (re-run with sudo)",
			install.AgentLabel, agentCredentialDir())}
	}
}

// agentCredentialDir is the directory the node credential store lives in, named
// once so the checks and the status report quote the same path.
func agentCredentialDir() string {
	return filepath.Dir(install.AgentCredentialPath(install.DefaultDataRoot))
}

// agentStagedTokenPath is the join token `k3sm install --token-file` stages for
// the agent daemon to read: the agent work dir's join-token, beside the node
// credential the join writes.
//
// The leaf name is spelled here because the installer's own accessor for it is
// unexported, and a doctor line that named no file would send an operator
// looking for a credential they staged and cannot find. The directory comes
// from install, so only the leaf could ever drift, and the check that catches
// it is TestAgentCredentialPathsMatchTheStore.
func agentStagedTokenPath() string {
	return filepath.Join(agentCredentialDir(), "join-token")
}

// majorVersion parses the leading integer of a dotted version string ("26.1" → 26).
func majorVersion(v string) (int, error) {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, '.'); i >= 0 {
		v = v[:i]
	}
	return strconv.Atoi(v)
}

// runDoctor runs the preflight environment + datastore-posture checks and prints a
// ladder. It exits non-zero (returns an error) iff any check is statusFail; WARN
// and SKIP are surfaced but do not fail the command.
func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	// Posture-aware default (the _k3sm control plane writes <home>/server, not the
	// root-only const); a resolve failure falls back to the const, overridable.
	defaultWorkDir, err := executor.ResolveWorkDir()
	if err != nil {
		defaultWorkDir = executor.DefaultWorkDir
	}
	workDir := fs.String("work-dir", defaultWorkDir, "control-plane state root (the kine state.db lives here)")
	_ = fs.Parse(args)

	env := realDoctorEnv(*workDir)
	var failed bool
	for _, c := range doctorChecks() {
		r := c.fn(env)
		fmt.Printf("[%s] %-12s %s\n", r.status, r.name, r.detail)
		if r.status == statusFail {
			failed = true
		}
	}
	if failed {
		return errors.New("one or more preflight checks failed")
	}
	return nil
}

// realDoctorEnv wires the real probes for a given work dir. This is the only place
// os/exec and the filesystem are touched; the check functions stay pure behind the
// doctorEnv seam.
func realDoctorEnv(workDir string) doctorEnv {
	return doctorEnv{
		goarch:       runtime.GOARCH,
		macOSVersion: probeMacOSVersion,
		sipEnabled:   probeSIPEnabled,
		helperState:  probeHelperState,
		brewPresent:  func() bool { _, err := exec.LookPath("brew"); return err == nil },
		datastorePosture: func() (bool, int, string, error) {
			return probeDatastorePosture(executor.StateDBPath(workDir))
		},
		developerDir: probeDeveloperDir,
		nodeRole:     installedRole,
		agentState:   func() (bool, bool) { return probeDaemonState(install.AgentLabel) },
		agentCredential: func() (status.CredentialState, time.Time) {
			return status.NodeCredentialState(osStatusFS{}, agentCredentialDir(), time.Now())
		},
	}
}

// probeMacOSVersion reads kern.osproductversion via sysctl (e.g. "26.1").
func probeMacOSVersion() (string, error) {
	out, err := exec.Command("sysctl", "-n", "kern.osproductversion").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// probeSIPEnabled parses `csrutil status` for the enabled marker.
func probeSIPEnabled() (bool, error) {
	out, err := exec.Command("csrutil", "status").Output()
	if err != nil {
		return false, err
	}
	return strings.Contains(strings.ToLower(string(out)), "status: enabled"), nil
}

// probeHelperState reports whether the io.k3sm.netd LaunchDaemon is bootstrapped
// (installed) and running.
func probeHelperState() (installed, running bool) {
	return probeDaemonState(install.NetdLabel)
}

// probeDaemonState reports whether a LaunchDaemon is bootstrapped (installed)
// and running, via `launchctl print system/<label>`. A non-zero exit means the
// job is not bootstrapped (not installed).
//
// The output is never carried into a result: `launchctl print` echoes the job's
// whole argv, and a node daemon's argv is where a join token would be.
func probeDaemonState(label string) (installed, running bool) {
	out, err := exec.Command("launchctl", "print", "system/"+label).CombinedOutput()
	if err != nil {
		return false, false
	}
	return true, strings.Contains(string(out), "state = running")
}

// probeDeveloperDir reads this node's active developer directory from
// `xcode-select -p`, trimmed — the same command, and the same trim, the provider
// runs at daemon construction (pkg/provider.lookupDeveloperDir). The two are
// separate calls because a CLI preflight cannot reach into the provider's
// package-level seam; what must not be duplicated is the VERDICT, and that comes
// from sandbox.ValidateXcodeToolchainDir in both places.
//
// An empty result is an error, not a directory: `xcode-select -p` printing
// nothing is a node with no selection, and returning "" as a success would make
// the check report a grant on the empty string.
func probeDeveloperDir() (string, error) {
	out, err := exec.Command("/usr/bin/xcode-select", "-p").Output()
	if err != nil {
		return "", fmt.Errorf("xcode-select -p: %w", err)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		return "", fmt.Errorf("xcode-select -p: empty developer directory")
	}
	return dir, nil
}

// probeDatastorePosture reads the kine SQLite datastore posture. The read-only
// SQLite-header parse behind it lives in pkg/status, which reports the same
// posture in `k3sm status`; two parsers would eventually disagree about what
// "wal" means.
func probeDatastorePosture(path string) (present bool, userVersion int, journalMode string, err error) {
	return status.DatastorePosture(path)
}
