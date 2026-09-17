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
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
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
	"k3sm.io/k3sm/pkg/version"
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

// checkResult is the outcome of one check: a stable name, a status verdict, a
// human-readable detail explaining the verdict, and the remedy that repairs it.
//
// detail says WHAT IS TRUE; remedy says WHAT TO RUN, one step per line, and is
// empty only when there is nothing to do — a PASS, or a SKIP the operator
// cannot act on. Every FAIL and every WARN carries one, because the rows are
// rolled up by status.Aggregate, which builds the screen's `Next:` block out of
// exactly these lines: a non-pass row with no remedy is a complaint with no
// answer, and it silently shortens the block an operator reads.
type checkResult struct {
	name   string
	status doctorStatus
	detail string
	remedy string
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
	// The --report bundle's seams. They are here, beside the check seams, for
	// the same reason: the bundle is assembled by a pure function that reads
	// them, so the gate proves what a bundle CONTAINS without writing a byte to
	// the real filesystem.
	//
	// daemonInfo returns pkg/status's PARSED launchd scalars and never the text
	// they came from (see daemonSnapshot). writeReport is the one write path,
	// and reportDir decides where — never the working directory by default.
	statusReport func(context.Context) status.Report
	logTail      func(path string) ([]string, error)
	daemonInfo   func(label string) status.DaemonInfo
	reportDir    func(requested string) (string, error)
	writeReport  func(dir, name string, contents []byte) error
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
		return checkResult{name: "arch", status: statusPass, detail: "arm64 (Apple Silicon)"}
	}
	return checkResult{
		name:   "arch",
		status: statusFail,
		detail: fmt.Sprintf("%s — k3sm is Apple-Silicon-only (arm64)", env.goarch),
		remedy: "run k3sm on an Apple Silicon Mac — there is no Intel build of it",
	}
}

// checkMacOS verifies macOS is at or above the supported floor. Below the floor is
// a FAIL; a probe/parse error is a WARN (could not determine, not proven bad).
func checkMacOS(env doctorEnv) checkResult {
	const readByHand = "read the version by hand: sysctl -n kern.osproductversion"
	ver, err := env.macOSVersion()
	if err != nil {
		return checkResult{
			name:   "macos",
			status: statusWarn,
			detail: fmt.Sprintf("could not determine macOS version: %v", err),
			remedy: readByHand,
		}
	}
	major, perr := majorVersion(ver)
	if perr != nil {
		return checkResult{
			name:   "macos",
			status: statusWarn,
			detail: fmt.Sprintf("unparseable macOS version %q: %v", ver, perr),
			remedy: readByHand,
		}
	}
	if major >= supportedMacOSFloor {
		return checkResult{name: "macos", status: statusPass, detail: fmt.Sprintf("macOS %s (>= %d)", ver, supportedMacOSFloor)}
	}
	return checkResult{
		name:   "macos",
		status: statusFail,
		detail: fmt.Sprintf("macOS %s is below the supported floor (macOS %d)", ver, supportedMacOSFloor),
		remedy: fmt.Sprintf("upgrade this Mac to macOS %d or later", supportedMacOSFloor),
	}
}

// checkSIP reports System Integrity Protection posture. k3sm needs no SIP-off
// (see docs/privilege-model.md), so enabled is PASS; disabled is an unexpected,
// weaker posture (WARN, not fatal); a probe error is WARN.
func checkSIP(env doctorEnv) checkResult {
	on, err := env.sipEnabled()
	if err != nil {
		return checkResult{
			name:   "sip",
			status: statusWarn,
			detail: fmt.Sprintf("could not determine SIP status: %v", err),
			remedy: "read the posture by hand: csrutil status",
		}
	}
	if on {
		return checkResult{name: "sip", status: statusPass, detail: "System Integrity Protection enabled (k3sm needs no SIP-off)"}
	}
	return checkResult{
		name:   "sip",
		status: statusWarn,
		detail: "SIP disabled — unexpected; k3sm does not require it and this is a weaker posture",
		remedy: "re-enable it from Recovery (Startup Security Utility, or csrutil enable) — nothing in k3sm needs it off",
	}
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
		return checkResult{name: "netd-helper", status: statusPass, detail: install.NetdLabel + " installed and running"}
	case installed:
		return checkResult{
			name:   "netd-helper",
			status: statusWarn,
			detail: install.NetdLabel + " installed but not running — the default runtimed runtime and the datapath need it",
			remedy: "sudo launchctl kickstart -k system/" + install.NetdLabel,
		}
	default:
		return checkResult{
			name:   "netd-helper",
			status: statusWarn,
			detail: install.NetdLabel + " not detected — either not installed, or not readable without privilege (a system-domain launchctl print may need root); the default runtimed runtime (unprivileged) and the datapath need it, and an unprivileged node without it refuses to start",
			remedy: "sudo k3sm doctor   # confirm it is truly absent rather than unreadable\nsudo k3sm install   # or pass --runtime hostprocess for rootless dev",
		}
	}
}

// checkBrew reports Homebrew presence. Homebrew is an install vector, not a
// runtime dependency, so absence is a WARN.
func checkBrew(env doctorEnv) checkResult {
	if env.brewPresent() {
		return checkResult{name: "brew", status: statusPass, detail: "Homebrew present"}
	}
	return checkResult{
		name:   "brew",
		status: statusWarn,
		detail: "Homebrew not found — an install vector, not required at runtime",
		remedy: "install Homebrew from https://brew.sh only if you want the brew install path; nothing k3sm runs needs it",
	}
}

// checkDatastore reports the kine SQLite datastore posture. It is a pure REPORTER:
// an absent state.db is a fresh node → SKIP (distinct from PASS — never a silent
// pass); a present, readable db → PASS reporting the bundled kine pin, user_version,
// and journal_mode. A non-WAL journal is a WARN; a read error is a WARN. Migration
// and remediation logic stays in executor, not here.
//
// The ROLE is read first and decides everything, because on a worker there is no
// datastore of this node's to have a posture at all: an agent runs no control
// plane and therefore no kine. A Mac installed as an agent after a server-era
// install still carries the old <DataRoot>/server directory, and reading the
// dead database inside it answered with THAT file's posture — a PASS when it was
// readable, and in the ordinary unprivileged run "could not read datastore
// posture … sudo k3sm doctor", a repair for a datastore this Mac does not own.
// So the worker arm returns before any posture read, and it says the one
// sentence `k3sm status`'s datastore row says (status.WorkerDatastoreDetail):
// one sentence for both the absent and the present case, in both commands, is
// one that cannot drift into four.
func checkDatastore(env doctorEnv) checkResult {
	if role, installed := env.nodeRole(); installed && role == install.RoleAgent {
		return checkResult{name: "datastore", status: statusSkip, detail: status.WorkerDatastoreDetail}
	}
	present, uv, jm, err := env.datastorePosture()
	if err != nil {
		return checkResult{
			name:   "datastore",
			status: statusWarn,
			detail: fmt.Sprintf("could not read datastore posture: %v", err),
			remedy: "sudo k3sm doctor   # the datastore is root-owned; an ordinary account cannot read it",
		}
	}
	if !present {
		return checkResult{name: "datastore", status: statusSkip, detail: "no state.db yet (fresh node — the control plane has not initialized the kine SQLite datastore)"}
	}
	detail := fmt.Sprintf("kine %s, user_version=%d, journal_mode=%s", executor.DefaultKineVersion, uv, jm)
	if jm != "wal" {
		return checkResult{
			name:   "datastore",
			status: statusWarn,
			detail: detail + " (expected journal_mode=wal)",
			remedy: "sudo launchctl kickstart -k system/" + install.ServerLabel + "   # let the control plane re-open the datastore",
		}
	}
	return checkResult{name: "datastore", status: statusPass, detail: detail}
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
		remedy = "sudo xcode-select -s /Applications/Xcode.app/Contents/Developer   # then restart the node daemon"
	)
	dir, err := env.developerDir()
	if err != nil {
		return checkResult{
			name:   name,
			status: statusWarn,
			detail: fmt.Sprintf("no developer toolchain on this node (%v), so %s grants nothing here. %s",
				err, runtimev1.AnnotationXcodeToolchain, once),
			remedy: remedy,
		}
	}
	granted, verr := sandbox.ValidateXcodeToolchainDir(dir, sandbox.Posture{})
	if verr != nil {
		return checkResult{
			name:   name,
			status: statusWarn,
			detail: fmt.Sprintf("%s is not a directory the toolchain grant accepts, so %s grants nothing here — and needs to grant nothing if it is a Command Line Tools root, which a pod already reads. %s",
				dir, runtimev1.AnnotationXcodeToolchain, once),
			remedy: remedy,
		}
	}
	return checkResult{name: name, status: statusPass, detail: fmt.Sprintf(
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
	// rejoin is the two-Mac repair, one step per line: the token is minted on
	// the CONTROL PLANE and only then can this Mac be reinstalled with it.
	rejoin := fmt.Sprintf(
		"k3sm token create   # on the control-plane Mac\nsudo k3sm install --role agent --server <control-plane> --token-file <file>   # here (staged at %s)\nsudo k3sm status logs agent   # read %s",
		agentStagedTokenPath(), install.AgentLogPath())
	role, installed := env.nodeRole()
	if !installed || role != install.RoleAgent {
		return checkResult{name: name, status: statusSkip, detail: fmt.Sprintf(
			"this Mac is not installed as a k3sm worker (%s is not on disk), so there is no %s daemon to check",
			install.AgentLabel+".plist", install.AgentLabel)}
	}
	daemonInstalled, running := env.agentState()
	if !daemonInstalled || !running {
		return checkResult{
			name:   name,
			status: statusFail,
			detail: fmt.Sprintf("%s is not running, so this worker is not serving pods", install.AgentLabel),
			remedy: fmt.Sprintf("sudo launchctl kickstart -k system/%s\nsudo k3sm status logs agent   # read %s",
				install.AgentLabel, install.AgentLogPath()),
		}
	}
	state, notAfter := env.agentCredential()
	switch state {
	case status.CredentialAbsent:
		return checkResult{
			name:   name,
			status: statusWarn,
			detail: fmt.Sprintf("%s is running but this Mac holds no node credential yet, so it has not joined a cluster", install.AgentLabel),
			remedy: rejoin,
		}
	case status.CredentialExpired:
		return checkResult{
			name:   name,
			status: statusWarn,
			detail: fmt.Sprintf("the node credential expired on %s, so this worker can no longer authenticate",
				notAfter.UTC().Format("2006-01-02")),
			remedy: rejoin,
		}
	case status.CredentialCorrupt:
		return checkResult{
			name:   name,
			status: statusWarn,
			detail: fmt.Sprintf("the stored node credential in %s does not parse", agentCredentialDir()),
			remedy: fmt.Sprintf("remove the unparseable credential under %s to force a fresh token join\n%s", agentCredentialDir(), rejoin),
		}
	case status.CredentialValid:
		return checkResult{name: name, status: statusPass, detail: fmt.Sprintf(
			"%s is running and this node's credential is valid until %s",
			install.AgentLabel, notAfter.UTC().Format("2006-01-02"))}
	default:
		return checkResult{
			name:   name,
			status: statusSkip,
			detail: fmt.Sprintf("%s is running; the node credential in %s is not readable as this user",
				install.AgentLabel, agentCredentialDir()),
			remedy: "sudo k3sm doctor",
		}
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

// doctorUsage is the canonical home of the `k3sm doctor` exit-code table. It is
// printed by `k3sm doctor --help`, and nothing else restates the numbers.
const doctorUsage = `k3sm doctor — preflight checks for this Mac

Usage: k3sm doctor [flags]

It reports what k3sm needs from the machine — the CPU, the macOS floor, SIP, the
` + "`" + install.NetdLabel + "`" + ` helper, Homebrew, the kine datastore, the Xcode toolchain
grant, and (on a worker) the agent daemon and its node credential. Every row
that is not a pass carries the command that repairs it, collected under ` + "`Next:`" + `.

Flags:
  -work-dir <dir>     control-plane state root (the kine state.db lives here)
  --json              print the report as JSON — the same shape as ` + "`k3sm status -o json`" + `
  --no-color          never emit colour or glyphs
  --report [dir]      write a redacted bug-report bundle (this report, the
                      runtime status report, the launchd state of each daemon,
                      and the bounded tails of the server and agent logs) to
                      dir, or to a fresh directory under the system temp dir.
                      Credentials are removed, but the bundle still names this
                      Mac's host name and its peers — read it before attaching
                      it to a public issue

Exit codes:
  0  every check passes (or is deliberately skipped)
  1  at least one check FAILED — the code ` + "`k3sm doctor`" + ` has always returned for this
  2  usage — a bad flag
  4  WARN only: nothing is broken, something is off. This is ` + "`k3sm status`" + `'s
     "degraded" code, because it is the same verdict about the same machine
`

// Doctor's own exit code for a failed check.
//
// It is 1, and deliberately NOT status.VerdictDegraded's 4: `k3sm doctor` has
// returned 1 for a failed check since it shipped, the release instructions tell
// an operator to run it and read that, and a preflight FAIL is not the same
// event as a degraded cluster. Every OTHER doctor code comes from
// status.Verdict.ExitCode, so a WARN-only run reports 4 exactly as `k3sm
// status` does. The cost of the carve-out is that 1 means "a check failed" here
// and "an internal error" in `k3sm status`; the two tables are printed in full
// by their own --help, which is where an operator reads them.
const exitDoctorCheckFailed = 1

// doctorSeverity maps a preflight verdict onto the row severity and STATE word
// `k3sm status` renders. The words are the ones the status screens already use,
// so one glyph column means one thing across both commands.
func doctorSeverity(s doctorStatus) (status.Severity, status.RowState) {
	switch s {
	case statusPass:
		return status.SeverityOK, status.StateOK
	case statusWarn:
		return status.SeverityWarn, doctorStateWarn
	case statusFail:
		return status.SeverityFail, status.StateFailed
	default:
		return status.SeveritySkip, status.StateSkip
	}
}

// doctorStateWarn is the STATE word a warning check renders. The shipped status
// vocabulary has no plain "warn" — its rows name what is wrong with the
// subsystem (crash-loop, wrong-owner, not-mounted) — but a preflight check's
// warning is exactly and only "this is off", so the word is the severity's.
const doctorStateWarn status.RowState = "warn"

// doctorRow converts one check result into a report row.
func doctorRow(r checkResult) status.Row {
	severity, state := doctorSeverity(r.status)
	return status.Row{Name: r.name, State: state, Severity: severity, Detail: r.detail, Remedy: r.remedy}
}

// doctorReport runs every check and folds the results into the same report
// shape `k3sm status` produces: a verdict, a summary, the rows, and the ordered
// remedies. It is PURE — every probe is behind the doctorEnv seam — so the gate
// drives it with fakes.
//
// installed is passed to Aggregate as TRUE unconditionally, which is the one
// place doctor deliberately differs from status. Aggregate answers
// "not-installed" first and outright, because a status report about a Mac with
// no k3sm on it has nothing to say; a PREFLIGHT report about that Mac is the
// whole point of the command — it answers "will k3sm work here" before there is
// an install. The install-shaped rows (netd-helper, agent-daemon) carry that
// fact themselves.
func doctorReport(env doctorEnv, ver version.Info, now time.Time) status.Report {
	checks := doctorChecks()
	rows := make([]status.Row, 0, len(checks))
	var passed, skipped int
	for _, c := range checks {
		r := c.fn(env)
		switch r.status {
		case statusPass:
			passed++
		case statusSkip:
			skipped++
		}
		rows = append(rows, doctorRow(r))
	}
	role, _ := env.nodeRole()
	verdict, summary, next := status.Aggregate(rows, true, role)
	if verdict == status.VerdictRunning {
		// Aggregate's healthy summary and its one next step are claims about a
		// SERVING control plane, which a preflight has not established and is
		// not about. A clean doctor run says what it actually checked.
		summary = fmt.Sprintf("%d preflight checks pass, %d skipped", passed, skipped)
		next = nil
	}
	host, err := env.macOSVersion()
	if err != nil {
		host = ""
	}
	return status.Report{
		Verdict:   verdict,
		Role:      role,
		Summary:   summary,
		Rows:      rows,
		Next:      next,
		Version:   ver,
		Host:      host,
		Timestamp: now,
	}
}

// doctorExitCode is the process exit status for a doctor report: 1 when any
// check failed, and the verdict's own code otherwise. See exitDoctorCheckFailed
// for why the failure code is not the verdict's.
func doctorExitCode(rep status.Report) int {
	for _, row := range rep.Rows {
		if row.Severity == status.SeverityFail {
			return exitDoctorCheckFailed
		}
	}
	return rep.Verdict.ExitCode()
}

// doctorOptions is the parsed doctor command line.
type doctorOptions struct {
	workDir string
	json    bool
	noColor bool
	// report asks for the bug-report bundle, and reportDir is the directory
	// the operator named for it (empty means a fresh temp directory).
	report    bool
	reportDir string
}

// parseDoctorArgs parses the doctor command line.
func parseDoctorArgs(args []string, errOut io.Writer) (doctorOptions, error) {
	// Posture-aware default (the _k3sm control plane writes <home>/server, not the
	// root-only const); a resolve failure falls back to the const, overridable.
	defaultWorkDir, err := executor.ResolveWorkDir()
	if err != nil {
		defaultWorkDir = executor.DefaultWorkDir
	}
	o := doctorOptions{workDir: defaultWorkDir}
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.Usage = func() { fmt.Fprint(errOut, doctorUsage) }
	fs.StringVar(&o.workDir, "work-dir", o.workDir, "control-plane state root (the kine state.db lives here)")
	fs.BoolVar(&o.json, "json", false, "print the report as JSON")
	fs.BoolVar(&o.noColor, "no-color", false, "never emit colour or glyphs")
	fs.BoolVar(&o.report, "report", false, "write a redacted bug-report bundle")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	// The one positional is the bundle's directory, and it is accepted ONLY
	// with --report: a stray argument anywhere else is a typo, and silently
	// ignoring it would leave an operator believing they asked for something.
	if fs.NArg() > 0 {
		if !o.report {
			return o, fmt.Errorf("unexpected argument %q", fs.Arg(0))
		}
		o.reportDir = fs.Arg(0)
	}
	if fs.NArg() > 1 {
		return o, fmt.Errorf("unexpected argument %q — --report takes at most one directory", fs.Arg(1))
	}
	return o, nil
}

// emitDoctorReport writes one report in the requested format and returns its
// exit code. The JSON is status.Report's own encoding, produced by the same
// encoder `k3sm status -o json` uses, so a consumer parses one shape.
func emitDoctorReport(rep status.Report, o doctorOptions, out, errOut io.Writer, color bool) int {
	if o.json {
		encoded, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			fmt.Fprintln(errOut, "k3sm doctor: encode report:", err)
			return exitInternalError
		}
		if _, err := fmt.Fprintln(out, string(encoded)); err != nil {
			fmt.Fprintln(errOut, "k3sm doctor: write report:", err)
			return exitInternalError
		}
		return doctorExitCode(rep)
	}
	if _, err := io.WriteString(out, status.RenderRows(rep, status.Style{Color: color, Glyphs: color})); err != nil {
		fmt.Fprintln(errOut, "k3sm doctor: write report:", err)
		return exitInternalError
	}
	return doctorExitCode(rep)
}

// runDoctor is the `k3sm doctor` entry point. It runs the preflight checks,
// renders them on the status screen's columns, and returns the process exit
// code — its own, rather than an error, because the exit code IS the verdict
// here (see doctorUsage's table).
func runDoctor(args []string) int {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		fmt.Print(doctorUsage)
		return 0
	}
	o, err := parseDoctorArgs(args, os.Stderr)
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stderr, "k3sm doctor:", err)
		}
		return exitUsage
	}
	env := realDoctorEnv(o.workDir)
	rep := doctorReport(env, version.Get(), time.Now())
	if o.report {
		return emitDoctorBundle(context.Background(), env, rep, o, os.Stdout, os.Stderr)
	}
	return emitDoctorReport(rep, o, os.Stdout, os.Stderr, status.ColorEnabled(os.Stdout, o.noColor, os.Getenv))
}

// emitDoctorBundle writes the bug-report bundle and prints what it wrote, with
// the directory LAST — it is the one line the operator has to act on.
//
// The exit code is still the report's: --report changes what is written, not
// what the checks found, so a script that runs doctor with it branches on the
// same numbers.
func emitDoctorBundle(ctx context.Context, env doctorEnv, rep status.Report, o doctorOptions, out, errOut io.Writer) int {
	dir, written, err := writeDoctorBundle(ctx, env, rep, o.reportDir)
	for _, name := range written {
		fmt.Fprintln(out, "  "+name)
	}
	if err != nil {
		fmt.Fprintln(errOut, "k3sm doctor:", err)
		return exitInternalError
	}
	fmt.Fprintf(out, "\nbug-report bundle: %s\n", dir)
	fmt.Fprintln(out, "credentials are redacted, but it still names this Mac's host name and its peers — read it before attaching it to a public issue")
	return doctorExitCode(rep)
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
		statusReport: func(ctx context.Context) status.Report { return newStatusCollector().Collect(ctx) },
		logTail:      func(path string) ([]string, error) { return readTail(path, reportLogLines) },
		daemonInfo:   probeDaemonInfo,
		reportDir:    makeReportDir,
		writeReport:  writeReportFile,
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
