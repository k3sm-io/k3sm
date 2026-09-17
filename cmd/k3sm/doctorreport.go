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
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/status"
)

// The bundle's log bounds: the last reportLogLines lines of a daemon log, and
// never more than reportLogBytes of them. Both bounds apply and the smaller
// wins, because the two failure modes are different — a log of long lines is
// bounded by the bytes, a log of short ones by the lines — and a bug-report
// attachment that is neither is one nobody reads.
const (
	reportLogLines = 200
	reportLogBytes = 256 << 10
)

// The bundle's components. Each is a file name, and the set is the whole
// bundle: there is no directory walk and no "everything under this path", so a
// file can only be in a bundle because it is named here.
const (
	reportDoctorFile  = "doctor.json"
	reportStatusFile  = "status.json"
	reportLaunchdFile = "launchd.json"
	reportServerLog   = "server.log"
	reportAgentLog    = "agent.log"
)

// reportDirPrefix names the temp directory a bundle lands in when the operator
// named none.
const reportDirPrefix = "k3sm-doctor-report-"

// daemonSnapshot is the launchd view a bundle carries: the four scalars
// `k3sm status`'s daemon rows already show, and NOTHING ELSE.
//
// This type is the boundary, and it is a boundary rather than a redaction
// because `launchctl print` echoes the job's whole argv and environment, and a
// k3sm server's argv carries the cluster join token. Redacting that text would
// mean betting a credential on a regexp matching every shape a secret can take
// in output this package does not control. Parsing four known keys out of it
// and writing only those cannot leak a fifth. Nothing here ever receives the
// raw text (see probeDaemonInfo, which consumes it and returns this).
type daemonSnapshot struct {
	Label    string `json:"label"`
	State    string `json:"state"`
	PID      int    `json:"pid"`
	Runs     int    `json:"runs"`
	LastExit *int   `json:"last_exit"`
}

// reportedLabels are the LaunchDaemons a bundle reports on, in install order.
var reportedLabels = []string{install.DatavolLabel, install.NetdLabel, install.ServerLabel, install.AgentLabel}

// writeDoctorBundle writes the bug-report bundle and returns the directory it
// landed in and the files it wrote, in order.
//
// Every component goes out through ONE write path, and that path applies
// status.Redact to the bytes. Putting the redaction at the write rather than at
// each producer is deliberate: a component added later is redacted by
// construction, and cannot be the one that forgot.
//
// What that buys is bounded, and the bound is worth stating: status.Redact
// recognises the credential-bearing argv flags (--token, --agent-token,
// --server-token, --server-ca-hash), the two literal shapes k3sm mints
// (`k3sm-<opaque>` and `K10<sha256>::…`), and the userinfo password of a URL —
// and NOT a bare node-password hex, which has no distinguishing shape to match.
// No code path logs one today, which is what makes the bundle safe rather than
// the redaction being complete: a new log line must never print a bare secret,
// because nothing downstream of it would recognise one.
func writeDoctorBundle(ctx context.Context, env doctorEnv, rep status.Report, requestedDir string) (string, []string, error) {
	dir, err := env.reportDir(requestedDir)
	if err != nil {
		return "", nil, fmt.Errorf("create report directory: %w", err)
	}
	var written []string
	write := func(name string, data []byte) error {
		if err := env.writeReport(dir, name, []byte(status.Redact(string(data)))); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
		written = append(written, name)
		return nil
	}

	doctorJSON, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return dir, written, fmt.Errorf("encode the doctor report: %w", err)
	}
	if err := write(reportDoctorFile, doctorJSON); err != nil {
		return dir, written, err
	}

	statusJSON, err := json.MarshalIndent(env.statusReport(ctx), "", "  ")
	if err != nil {
		return dir, written, fmt.Errorf("encode the status report: %w", err)
	}
	if err := write(reportStatusFile, statusJSON); err != nil {
		return dir, written, err
	}

	snapshots := make([]daemonSnapshot, 0, len(reportedLabels))
	for _, label := range reportedLabels {
		info := env.daemonInfo(label)
		snapshots = append(snapshots, daemonSnapshot{
			Label: label, State: info.State, PID: info.PID, Runs: info.Runs, LastExit: info.LastExit,
		})
	}
	launchdJSON, err := json.MarshalIndent(snapshots, "", "  ")
	if err != nil {
		return dir, written, fmt.Errorf("encode the launchd view: %w", err)
	}
	if err := write(reportLaunchdFile, launchdJSON); err != nil {
		return dir, written, err
	}

	for _, log := range []struct{ name, path string }{
		{reportServerLog, install.ServerLogPath()},
		{reportAgentLog, install.AgentLogPath()},
	} {
		if err := write(log.name, boundedLogTail(env, log.path)); err != nil {
			return dir, written, err
		}
	}
	return dir, written, nil
}

// boundedLogTail reads a log's tail through the seam and bounds it. A log this
// Mac does not have, or may not read, is reported as a line inside the bundle
// rather than as an error: "there is no agent.log here" is a fact about the
// node, and a bundle that fails to assemble over it is a bug report that never
// gets sent.
func boundedLogTail(env doctorEnv, path string) []byte {
	lines, err := env.logTail(path)
	if err != nil {
		return []byte(fmt.Sprintf("(%s unavailable: %v)\n", path, err))
	}
	return boundTail(lines, reportLogLines, reportLogBytes)
}

// boundTail keeps the LAST maxLines lines, then drops whole lines from the
// front until what is left fits maxBytes. It is pure, and it trims from the
// front because the end of a log is the part that explains the failure.
func boundTail(lines []string, maxLines, maxBytes int) []byte {
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	for len(lines) > 0 {
		joined := strings.Join(lines, "\n") + "\n"
		if len(joined) <= maxBytes {
			return []byte(joined)
		}
		lines = lines[1:]
	}
	return nil
}

// reportDirRemedy is the one sentence every directory refusal ends with. It is
// a single const because an operator who is refused four different ways should
// be told the same way out each time.
const reportDirRemedy = "choose a directory you own that others cannot write, or omit the argument to use a fresh temp directory"

// dirFacts is what the guard needs to know about an operator-named directory,
// read with Lstat so a SYMLINK is a fact about the named path rather than
// silently the fact about its target.
type dirFacts struct {
	exists  bool
	symlink bool
	dir     bool
	uid     int
	// perm is the permission bits only; the guard reads the group and other
	// write bits out of it.
	perm fs.FileMode
}

// lstatDirFacts reads a path's facts without following a final symlink. A path
// that does not exist is not an error: it is the ordinary case, and the caller
// creates it.
func lstatDirFacts(path string) (dirFacts, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return dirFacts{}, nil
	}
	if err != nil {
		return dirFacts{}, err
	}
	f := dirFacts{
		exists:  true,
		symlink: info.Mode()&fs.ModeSymlink != 0,
		dir:     info.IsDir(),
		perm:    info.Mode().Perm(),
		uid:     -1,
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		f.uid = int(st.Uid)
	}
	return f, nil
}

// checkReportDir decides whether a bundle may be written into a path the
// operator named. It is PURE — the facts come from lstatDirFacts and the
// identity from the caller — so every refusal is a table row.
//
// It matters because `k3sm doctor` is commonly run under sudo, and a bundle
// carries log tails and a whole status report. Writing that as root into a
// path somebody else controls is the classic handover: a symlink at the named
// path redirects the whole bundle, a directory owned by another account can
// have its contents read or replaced, and a group- or other-writable directory
// lets a third party swap a component between the write and the read. Each
// refusal names the property that failed, because "permission denied" would
// send an operator to chmod exactly the wrong way.
func checkReportDir(path string, f dirFacts, euid int) error {
	if !f.exists {
		return nil
	}
	switch {
	case f.symlink:
		return fmt.Errorf("%s is a symlink, and a bundle is never written through one: %s", path, reportDirRemedy)
	case !f.dir:
		return fmt.Errorf("%s is not a directory: %s", path, reportDirRemedy)
	case f.uid != euid:
		return fmt.Errorf("%s is owned by uid %d, not by this account (uid %d): %s", path, f.uid, euid, reportDirRemedy)
	case f.perm&0o022 != 0:
		return fmt.Errorf("%s is group- or other-writable (mode %04o), so another account could replace a bundle file: %s", path, f.perm, reportDirRemedy)
	}
	return nil
}

// makeReportDir is the real directory factory: the operator's directory when
// they named one, else a fresh temp directory.
//
// The default is the system temp dir and never the working directory, because
// the caller is usually standing in a checkout when they run this, and a
// bundle that lands there is one `git add -A` away from being committed — a
// bundle carries log tails and a whole status report, which is exactly the
// material that must not end up in a repository by accident.
//
// A named directory is checked BEFORE anything is written (checkReportDir) and
// a missing one is created 0700.
func makeReportDir(requested string) (string, error) {
	if requested == "" {
		return os.MkdirTemp("", reportDirPrefix)
	}
	dir, err := filepath.Abs(requested)
	if err != nil {
		return "", err
	}
	facts, err := lstatDirFacts(dir)
	if err != nil {
		return "", err
	}
	if err := checkReportDir(dir, facts, os.Geteuid()); err != nil {
		return "", err
	}
	if !facts.exists {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
	}
	return dir, nil
}

// writeReportFile writes one bundle component, owner-readable only: the bundle
// quotes daemon logs, and the directory it sits in may not be as private as
// this process would like.
//
// O_EXCL|O_NOFOLLOW is the other half of checkReportDir's guard, and it closes
// what a check cannot: the directory may be fine when it is checked and carry
// a planted symlink named server.log a moment later. O_NOFOLLOW refuses to
// follow one at the leaf, and O_EXCL refuses to write over anything at all —
// so a bundle NEVER overwrites a file, and a name that is already taken is a
// refusal that says which one.
func writeReportFile(dir, name string, data []byte) error {
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s already exists and a bundle never overwrites: %s", path, reportDirRemedy)
		}
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// probeDaemonInfo reads a LaunchDaemon's four bookkeeping scalars through
// pkg/status's parser — the same parser `k3sm status` reads them with.
//
// The raw `launchctl print` output is consumed here and returned to nobody:
// this function is the only place in the bundle path that ever holds it. See
// daemonSnapshot for why that is structural rather than a redaction.
func probeDaemonInfo(label string) status.DaemonInfo {
	out, err := exec.Command("launchctl", "print", "system/"+label).CombinedOutput()
	return status.ParseLaunchctlPrint(out, err)
}
