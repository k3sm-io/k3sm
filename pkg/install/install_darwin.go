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
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// darwinSystem is the production System: it performs the privileged operations
// via the macOS tools (dscl for the service user, ditto for the root-owned copy,
// launchctl for the daemons) and os.Chown for ownership. It is exercised by the
// M2 acceptance gate (the one-time root install), NOT by unit tests — the
// standards forbid real privilege in unit tests, so install_test.go uses the
// fake instead.
type darwinSystem struct{}

// NewDarwinSystem returns the production darwin System.
func NewDarwinSystem() System { return darwinSystem{} }

// systemUIDFloor/Ceil bound the search for a free hidden service-user uid (the
// macOS daemon range below the 500 login-user floor).
const (
	systemUIDFloor = 250
	systemUIDCeil  = 400
)

// EnsureServiceUser idempotently creates name as a hidden, no-login system user
// whose home is DefaultDataRoot, and ensures that data root exists owned by it
// (so the _k3sm control plane can write its work-dir there). It returns the uid.
func (darwinSystem) EnsureServiceUser(name string) (uint32, error) {
	if u, err := user.Lookup(name); err == nil {
		uid, _ := strconv.Atoi(u.Uid)
		if err := ensureOwnedDir(DefaultDataRoot, uid); err != nil {
			return 0, err
		}
		return uint32(uid), nil
	}

	uid, err := freeSystemUID()
	if err != nil {
		return 0, err
	}
	record := "/Users/" + name
	steps := [][]string{
		{"dscl", ".", "-create", record},
		{"dscl", ".", "-create", record, "UserShell", "/usr/bin/false"},
		{"dscl", ".", "-create", record, "RealName", "k3sm service user"},
		{"dscl", ".", "-create", record, "UniqueID", strconv.Itoa(uid)},
		{"dscl", ".", "-create", record, "PrimaryGroupID", "20"}, // staff
		{"dscl", ".", "-create", record, "NFSHomeDirectory", DefaultDataRoot},
		{"dscl", ".", "-create", record, "IsHidden", "1"},
	}
	for _, s := range steps {
		if out, err := exec.Command(s[0], s[1:]...).CombinedOutput(); err != nil {
			return 0, fmt.Errorf("create service user (%s): %w: %s", strings.Join(s, " "), err, out)
		}
	}
	if err := ensureOwnedDir(DefaultDataRoot, uid); err != nil {
		return 0, err
	}
	return uint32(uid), nil
}

// freeSystemUID returns the first uid in [floor,ceil] not already assigned.
func freeSystemUID() (int, error) {
	for uid := systemUIDFloor; uid <= systemUIDCeil; uid++ {
		if _, err := user.LookupId(strconv.Itoa(uid)); err != nil {
			return uid, nil
		}
	}
	return 0, fmt.Errorf("no free system uid in [%d,%d]", systemUIDFloor, systemUIDCeil)
}

// ensureOwnedDir creates dir 0750 (idempotent) and chowns it to uid:staff so the
// service user owns its data root.
func ensureOwnedDir(dir string, uid int) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create data root %s: %w", dir, err)
	}
	if err := os.Chown(dir, uid, 20); err != nil {
		return fmt.Errorf("chown data root %s to %d: %w", dir, uid, err)
	}
	return nil
}

// EnsureLogDir creates (or repairs) the log dir owned by the service uid, group
// staff, mode 0755 — so launchd, opening the UserName=_k3sm server job's
// StandardOut/ErrorPath AS _k3sm, can create/append server.log (the root netd
// job is unaffected by perms). Owner+mode are re-applied even when the dir
// already exists, repairing one auto-created root-only by a prior netd spawn.
func (darwinSystem) EnsureLogDir(dir string, uid uint32) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create log dir %s: %w", dir, err)
	}
	if err := os.Chown(dir, int(uid), 20); err != nil { // group staff (_k3sm's primary)
		return fmt.Errorf("chown log dir %s to %d:staff: %w", dir, uid, err)
	}
	if err := os.Chmod(dir, 0o755); err != nil { // repair a mis-created mode (MkdirAll skips existing)
		return fmt.Errorf("chmod log dir %s 0755: %w", dir, err)
	}
	return nil
}

// EnsureRunDir creates (or repairs) the runtime run dir owned by the service
// uid, group staff, mode 0700 — the directory the _k3sm node binds its runtimed
// control socket in. See the System interface for why the installer, not a
// daemon, must be the one to create it.
func (darwinSystem) EnsureRunDir(dir string, uid uint32) error {
	return ensureServiceOwnedDir(dir, uid, "run dir")
}

// EnsureVMRunDir creates (or repairs) the vm guest-agent socket dir owned by the
// service uid, group staff, mode 0700.
//
// Its PARENT — the run dir — is ensured first, through the same helper and with
// the same owner and mode. A bare MkdirAll of the leaf would create a missing
// parent root-owned, which _k3sm could not then traverse; and re-applying the
// parent's ownership here (rather than assuming Install already did) keeps this
// function correct on its own terms instead of correct only in one call order.
func (darwinSystem) EnsureVMRunDir(dir string, uid uint32) error {
	parent := filepath.Dir(dir)
	if err := ensureServiceOwnedDir(parent, uid, "vm run dir parent"); err != nil {
		return err
	}
	return ensureServiceOwnedDir(dir, uid, "vm run dir")
}

// ensureServiceOwnedDir creates dir and re-applies owner uid:staff and mode 0700
// on EVERY call. MkdirAll skips an existing directory, so an install over a tree
// an earlier build (or a root daemon that got there first) left root-owned is
// repaired rather than silently left unwritable by the service user. what names
// the directory in any error, so a failure says which one.
func ensureServiceOwnedDir(dir string, uid uint32, what string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s %s: %w", what, dir, err)
	}
	if err := os.Chown(dir, int(uid), 20); err != nil { // group staff (_k3sm's primary)
		return fmt.Errorf("chown %s %s to %d:staff: %w", what, dir, uid, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("chmod %s %s 0700: %w", what, dir, err)
	}
	return nil
}

// CopyToRootOwned copies src to exactly dst (parent dir created root:wheel 0755)
// using ditto (preserves the signature/extended attributes the notarized binary
// needs). dst is the caller's contract — never derived from src's basename, so a
// build artifact named `k3sm-m2` still lands at the installedBinary() path the
// LaunchDaemon plists exec. A final X_OK access check fails the install fast if
// the copy somehow left dst non-executable (the alternative is launchd's
// unrecoverable "Missing executable" job invalidation at bootstrap).
func (darwinSystem) CopyToRootOwned(src, dst string) error {
	dstDir := filepath.Dir(dst)
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return fmt.Errorf("create install dir %s: %w", dstDir, err)
	}
	if err := os.Chown(dstDir, 0, 0); err != nil {
		return fmt.Errorf("chown install dir %s root:wheel: %w", dstDir, err)
	}
	if out, err := exec.Command("ditto", src, dst).CombinedOutput(); err != nil {
		return fmt.Errorf("ditto %s -> %s: %w: %s", src, dst, err, out)
	}
	if err := os.Chown(dst, 0, 0); err != nil {
		return fmt.Errorf("chown %s root:wheel: %w", dst, err)
	}
	if err := os.Chmod(dst, 0o755); err != nil {
		return fmt.Errorf("chmod %s 0755: %w", dst, err)
	}
	if err := unix.Access(dst, unix.X_OK); err != nil {
		return fmt.Errorf("installed binary %s is not executable (launchd would invalidate the daemons): %w", dst, err)
	}
	return nil
}

// VerifyVirtualizationEntitlement reads the code-signing entitlements off the
// Mach-O at path and requires VirtualizationEntitlement to be among them. See the
// System interface for the three-valued contract; this implementation is where the
// "any other error means refuse" arm gets its concrete causes.
//
// The oracle is `codesign -d --entitlements -`, the SAME invocation
// hack/release/stage.sh makes after it signs the helper. That identity is the
// reason for the choice: the release stager and the installer then judge an
// artifact by one mechanism instead of two that can disagree, and the property the
// stager asserts on the way out is the property the installer asserts on the way
// in.
//
// Reading the entitlement blob is not a signature VALIDITY check, and deliberately
// so. A stricter probe exists — runtimed's cgo SecStaticCodeCheckValidity read
// behind sandbox.VMBackend.Available — and it is the daemon's job, run at every
// boot against the INSTALLED helper. Duplicating it here would mean either a
// second cgo Security.framework shim in this repo or a Go re-implementation of
// signature validation, to catch a case (a helper mangled after signing) that the
// daemon already catches. What install adds is the case the daemon cannot report
// legibly: an entitlement that was never granted in the first place.
//
// An unsigned binary needs no separate arm: codesign exits non-zero on it ("code
// object is not signed at all"), which is already a refusal.
func (darwinSystem) VerifyVirtualizationEntitlement(path string) error {
	if _, err := os.Stat(path); err != nil {
		// Wraps fs.ErrNotExist for a missing file, which the caller reads as
		// "nothing staged" rather than "unentitled".
		return err
	}
	cmd := exec.Command("codesign", "-d", "--entitlements", "-", path)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	// Entitlements go to stdout; codesign's "Executable=<path>" banner goes to
	// stderr. Only stdout is matched, so a path that happens to contain the
	// entitlement string cannot satisfy the check.
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("codesign -d --entitlements - %s: %w: %s", path, err, strings.TrimSpace(stderr.String()))
	}
	if !bytes.Contains(out, []byte(VirtualizationEntitlement)) {
		return fmt.Errorf("signature grants no %s", VirtualizationEntitlement)
	}
	return nil
}

// WriteLaunchDaemon writes the plist root:wheel 0644.
func (darwinSystem) WriteLaunchDaemon(plistPath string, contents []byte) error {
	if err := os.MkdirAll(filepath.Dir(plistPath), 0o755); err != nil {
		return fmt.Errorf("create launchd dir: %w", err)
	}
	if err := os.WriteFile(plistPath, contents, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", plistPath, err)
	}
	if err := os.Chown(plistPath, 0, 0); err != nil {
		return fmt.Errorf("chown %s root:wheel: %w", plistPath, err)
	}
	return nil
}

// ReadFile reads a root-readable file, propagating os.ReadFile's error verbatim
// so a caller can distinguish "not there yet" (fs.ErrNotExist — a first install
// has neither the installed plist nor the cluster CA) from a real read failure.
func (darwinSystem) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// LaunchctlBootstrap loads the daemon into the system domain. A failure launchd
// attributes to the domain still settling is wrapped with ErrLaunchctlTransient so
// the caller can retry exactly that class — see transientLaunchctlOutput. This is
// the ONLY place launchctl's output text is inspected; the orchestration above
// compares sentinels.
func (darwinSystem) LaunchctlBootstrap(label string) error {
	plist := filepath.Join(DefaultLaunchDaemonDir, label+".plist")
	out, err := exec.Command("launchctl", "bootstrap", "system", plist).CombinedOutput()
	if err == nil {
		return nil
	}
	if transientLaunchctlOutput(string(out)) {
		return fmt.Errorf("launchctl bootstrap %s: %w: %w: %s", label, ErrLaunchctlTransient, err, out)
	}
	return fmt.Errorf("launchctl bootstrap %s: %w: %s", label, err, out)
}

// transientErrno matches launchctl's "<verb> failed: <errno>: <text>" line for the
// two errnos launchd returns while a booted-out label is still leaving the system
// domain: 37 (EINPROGRESS — the removal is in flight) and 5 (EIO — observed for
// 1.77s while the label drained on a live install). The errno is anchored to the
// failure line so an unrelated ": 5:" elsewhere in the output cannot match.
var transientErrno = regexp.MustCompile(`(?im)^\s*\w+ failed:\s*(5|37):`)

// transientLaunchctlOutput reports whether launchctl's output describes the domain
// settling rather than a verdict on the job. It matches both the numeric form and
// the two strerror texts, because launchctl has printed each shape depending on
// the subcommand and the macOS release, and a missed classification here silently
// reverts the caller to the un-retried behaviour this exists to fix.
//
// Misclassifying a PERMANENT failure as transient costs only a bounded retry that
// fails identically and is then reported; the asymmetry is deliberate.
func transientLaunchctlOutput(out string) bool {
	lower := strings.ToLower(out)
	return strings.Contains(lower, "operation already in progress") ||
		strings.Contains(lower, "input/output error") ||
		transientErrno.MatchString(out)
}

// PathExists reports whether path exists, without opening it. Install verifies the
// netd unix socket this way because no file read can answer for a socket: opening
// one with the file API fails whether or not netd is listening. A not-exist stat is
// (false, nil); any other stat failure is returned, because "I could not tell" must
// never be reported as "absent". Lstat, not Stat, so a dangling symlink at the
// socket path is reported as present — it exists, and it is not this check's job to
// decide it is the wrong kind of thing.
func (darwinSystem) PathExists(path string) (bool, error) {
	if _, err := os.Lstat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// LaunchctlBootout unloads the daemon. A not-loaded label (exit 113/3) is treated
// as success so uninstall is idempotent.
func (darwinSystem) LaunchctlBootout(label string) error {
	out, err := exec.Command("launchctl", "bootout", "system/"+label).CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "Could not find") || strings.Contains(string(out), "No such process") {
			return nil
		}
		return fmt.Errorf("launchctl bootout %s: %w: %s", label, err, out)
	}
	return nil
}

// LaunchctlKickstart force-restarts the daemon. An unloaded/absent label is an
// ERROR here (unlike Bootout's idempotent no-op): a caller asking for a restart must
// never be told a daemon that is not there was restarted. launchctl's output is
// trimmed because this error is surfaced verbatim in a CLI message.
//
// It returns once launchd has ACCEPTED the restart request. The old instance is
// still draining at that point (the control plane tears its components down
// serially, within the plist's ExitTimeOut), so anything that must observe the NEW
// instance polls LaunchctlServicePID for a changed pid.
func (darwinSystem) LaunchctlKickstart(label string) error {
	if out, err := exec.Command("launchctl", "kickstart", "-k", "system/"+label).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl kickstart %s: %w: %s", label, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// LaunchctlServicePID reads the pid launchd reports for the job out of
// `launchctl print system/<label>`'s "pid = N" field. A loaded-but-not-running job
// has no such field and yields 0 (not an error — it is the normal respawn window);
// a label that is not loaded fails, because "no job" must never be reported as "no
// pid yet". Read-only: it starts, stops and changes nothing.
//
// Unlike the other launchctl wrappers this one does NOT put the command's output in
// its error. `launchctl print` dumps the whole job on success — including the
// daemon's argv, which carries the apiserver's static admin token — and this error
// string is surfaced verbatim in a CLI message. Only the exit status is reported;
// the operator is pointed at the command instead.
func (darwinSystem) LaunchctlServicePID(label string) (int, error) {
	out, err := exec.Command("launchctl", "print", "system/"+label).Output()
	if err != nil {
		return 0, fmt.Errorf("launchctl print system/%s (is the daemon loaded?): %w", label, err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "pid = ")
		if !ok {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(rest))
		if err != nil {
			return 0, fmt.Errorf("launchctl print system/%s: unparsable pid field %q: %w", label, rest, err)
		}
		return pid, nil
	}
	return 0, nil
}

// WriteUserKubeconfig MERGES the k3sm admin context (contents) into targetUser's
// ~/.kube/config, owned by targetUser (NOT root) so the human can kubectl without
// sudo. Any pre-existing clusters/contexts are preserved — install must never
// clobber a developer's other kubeconfigs (uninstall likewise leaves the file).
// The write is atomic (temp + rename) so a crash mid-write can't corrupt the file.
func (darwinSystem) WriteUserKubeconfig(targetUser string, contents []byte) error {
	u, err := user.Lookup(targetUser)
	if err != nil {
		return fmt.Errorf("lookup target user %s: %w", targetUser, err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	kubeDir := filepath.Join(u.HomeDir, ".kube")
	if err := os.MkdirAll(kubeDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", kubeDir, err)
	}
	_ = os.Chown(kubeDir, uid, gid)
	path := filepath.Join(kubeDir, "config")

	existing, rerr := os.ReadFile(path)
	if rerr != nil && !os.IsNotExist(rerr) {
		return fmt.Errorf("read existing kubeconfig %s: %w", path, rerr)
	}
	merged, err := mergeAdminKubeconfig(existing, contents, adminContextName)
	if err != nil {
		return fmt.Errorf("merge admin kubeconfig into %s: %w", path, err)
	}

	tmp, err := os.CreateTemp(kubeDir, ".k3sm-kubeconfig-*")
	if err != nil {
		return fmt.Errorf("create temp kubeconfig: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp kubeconfig: %w", err)
	}
	if _, err := tmp.Write(merged); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp kubeconfig: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp kubeconfig: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename kubeconfig into place: %w", err)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("chown %s to %s: %w", path, targetUser, err)
	}
	return nil
}

// ReapOrphans SIGKILLs any process whose command line references binPrefix — the
// control-plane children (kine/kube-apiserver/…) left behind when the server
// daemon died before Stop() reaped them. `pkill -9 -f` matches the absolute
// <DataRoot>/server/bin/ path, which is specific to this install's spawned
// children and never a bystander. Exit code 1 (no match) is the common no-op and
// is NOT an error; only a real failure (>1) is.
func (darwinSystem) ReapOrphans(binPrefix string) error {
	cmd := exec.Command("pkill", "-9", "-f", binPrefix)
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
			return nil // no matching process — nothing to reap
		}
		return fmt.Errorf("pkill orphaned control-plane children (%s): %w", binPrefix, err)
	}
	return nil
}

// RemoveAll removes a path tree.
func (darwinSystem) RemoveAll(path string) error {
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}

// FlushLo0Aliases lists lo0's live inet aliases (`ifconfig lo0`) and removes
// every one inside the given prefixes with `ifconfig lo0 -alias <ip>` — the
// root-privileged uninstall backstop for k3sm's durable alias state (pod /32s,
// Service VIPs, the node mesh-egress .1). Removal failures are collected and
// the flush continues, so one stuck alias never strands the rest; removing an
// address that vanished between list and remove is tolerated.
func (darwinSystem) FlushLo0Aliases(prefixes []netip.Prefix) error {
	out, err := exec.Command("ifconfig", "lo0").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig lo0: %w\n%s", err, out)
	}
	var errs []error
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		// A v4 alias line reads "inet A.B.C.D netmask 0xffffffff".
		if len(fields) < 2 || fields[0] != "inet" {
			continue
		}
		ip, err := netip.ParseAddr(fields[1])
		if err != nil {
			continue
		}
		owned := false
		for _, p := range prefixes {
			if p.Contains(ip) {
				owned = true
				break
			}
		}
		if !owned {
			continue
		}
		if rmOut, err := exec.Command("ifconfig", "lo0", "-alias", ip.String()).CombinedOutput(); err != nil {
			errs = append(errs, fmt.Errorf("ifconfig lo0 -alias %s: %w\n%s", ip, err, rmOut))
		}
	}
	return errors.Join(errs...)
}
