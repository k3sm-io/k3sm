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
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
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
// DEFAULT runtimed runtime refuses to start unprivileged without it (the M10.1
// preflight), but root, `--runtime hostprocess` (rootless dev), and
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
func checkDatastore(env doctorEnv) checkResult {
	present, uv, jm, err := env.datastorePosture()
	if err != nil {
		return checkResult{"datastore", statusWarn, fmt.Sprintf("could not read datastore posture: %v", err)}
	}
	if !present {
		return checkResult{"datastore", statusSkip, "no state.db yet (fresh node — the control plane has not initialized the kine SQLite datastore)"}
	}
	detail := fmt.Sprintf("kine %s, user_version=%d, journal_mode=%s", executor.DefaultKineVersion, uv, jm)
	if jm != "wal" {
		return checkResult{"datastore", statusWarn, detail + " (expected journal_mode=wal)"}
	}
	return checkResult{"datastore", statusPass, detail}
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
// (installed) and running, via `launchctl print system/<label>`. A non-zero exit
// means the job is not bootstrapped (not installed).
func probeHelperState() (installed, running bool) {
	out, err := exec.Command("launchctl", "print", "system/"+install.NetdLabel).CombinedOutput()
	if err != nil {
		return false, false
	}
	return true, strings.Contains(string(out), "state = running")
}

// probeDatastorePosture reads the kine SQLite datastore posture WITHOUT creating,
// writing, or checkpointing the db. It os.Stat's the path first (absent → present
// false → the check SKIPs), then opens the file READ-ONLY and parses the 100-byte
// SQLite database header directly:
//
//	offset 0..15  magic string "SQLite format 3\000"
//	offset 18     file-format write version (1 = rollback journal, 2 = WAL)
//	offset 60..63 user_version (big-endian uint32)
//
// This is strictly read-only: a naive sql.Open()+Ping() would CREATE an empty
// state.db on a fresh node — a forbidden side effect — and would need a cgo sqlite
// driver dependency. The header parse avoids both.
func probeDatastorePosture(path string) (present bool, userVersion int, journalMode string, err error) {
	if _, statErr := os.Stat(path); statErr != nil {
		if os.IsNotExist(statErr) {
			return false, 0, "", nil
		}
		return false, 0, "", statErr
	}
	f, err := os.Open(path) // read-only; never creates
	if err != nil {
		return false, 0, "", err
	}
	defer func() { _ = f.Close() }()

	var hdr [100]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return false, 0, "", fmt.Errorf("read sqlite header: %w", err)
	}
	if string(hdr[0:16]) != "SQLite format 3\x00" {
		return false, 0, "", errors.New("not a sqlite database (bad header magic)")
	}
	userVersion = int(binary.BigEndian.Uint32(hdr[60:64]))
	switch hdr[18] {
	case 2:
		journalMode = "wal"
	case 1:
		journalMode = "rollback"
	default:
		journalMode = fmt.Sprintf("unknown(%d)", hdr[18])
	}
	return true, userVersion, journalMode, nil
}
