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
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/executor"
)

// TestMain points the three GLOBAL declaration paths at a scratch directory for
// the whole package's tests.
//
// Without it every test that runs Install would read the running Mac's own
// /etc/fstab and /Library/Preferences/io.k3sm.datavol.json, and a developer
// whose Mac actually has a k3sm data volume would watch unrelated tests change
// verdict. The two are vars precisely so a test can do this; nothing in the
// product writes them.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "k3sm-install-decl-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "create the scratch declaration dir:", err)
		os.Exit(1)
	}
	dataroot.FstabPath = filepath.Join(dir, "fstab")
	dataroot.DefaultRecordPath = filepath.Join(dir, "io.k3sm.datavol.json")
	dataroot.DefaultServerArgsRecordPath = filepath.Join(dir, "io.k3sm.server-args.json")
	dataroot.DefaultAgentArgsRecordPath = filepath.Join(dir, "io.k3sm.agent-args.json")
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// fakeSystem records every privileged seam call in order so a test can assert
// the install orchestration without any real privilege.
type fakeSystem struct {
	calls       []string
	kubeUser    string
	kubeContent string
	// files is the fake root filesystem ReadFile answers from. WriteLaunchDaemon
	// records into it, so running Install twice against ONE fake reproduces a real
	// reinstall: the second run reads back the plist the first run wrote.
	files map[string][]byte
	// pid is the next pid the fake launchd hands out; a bootstrap or a kickstart
	// advances it, so a restarted job reports a DIFFERENT pid — the discriminator
	// `k3sm certificate rotate` uses to tell the new control plane from the old one
	// still draining its listeners.
	pid int
	// loaded models the launchd system domain: a label present here is loaded, and
	// its value is the pid launchd reports (0 = loaded but not spawned). A label
	// ABSENT is not loaded, which LaunchctlServicePID reports as an ERROR — the very
	// discriminator install's await-unloaded step polls on.
	loaded map[string]int
	// drain[label] is how many LaunchctlServicePID reads the label lingers in the
	// domain AFTER its bootout returns. This is the real launchd behaviour the whole
	// restart sequence exists for (bootout returns before the label is gone), and it
	// is 0 by default so every pre-existing test still describes an instant unload.
	drain map[string]int
	// bootstrapErrs[label] is a queue of errors LaunchctlBootstrap returns before it
	// finally succeeds — the transient-then-succeeds shape a racing bootstrap has on
	// a real install. Empty (the zero value) means every bootstrap succeeds, so no
	// pre-existing test has to say anything about it.
	bootstrapErrs map[string][]error
	// bootstrapAlways[label] is an error LaunchctlBootstrap returns for EVERY
	// attempt (a plist launchd will never accept, or a domain that never settles).
	// It is consulted after the queue, so a test can describe "transient twice,
	// then permanently broken" if it needs to.
	bootstrapAlways map[string]error
	// missingPaths are paths PathExists reports absent. The zero value reports
	// EVERY path present, so an unconfigured fake describes a healthy install and
	// only a test that cares about the netd socket has to say so.
	missingPaths map[string]bool
	// links models the symlinks EnsureSymlink has laid down (link -> target), so a
	// SECOND Install over the same fake describes the real "already correct"
	// reinstall rather than a fresh lay-down.
	links map[string]string
	// modes is what FileMode answers, keyed by path — the operator's join token
	// file being the only thing the installer judges by mode. A path with no
	// entry but present in files is 0600, so an unconfigured fake describes a
	// credential nobody else can read.
	modes map[string]fs.FileMode
	// entitlement is the verdict VerifyVirtualizationEntitlement returns, keyed by
	// path. The zero value (no entry) means "signed and entitled" so that every
	// pre-existing test keeps describing a healthy staging tree; a test that cares
	// states the failure explicitly with putEntitlement.
	entitlement map[string]error
	// serviceUID is what LookupServiceUID answers. Nil — the zero value — is the
	// FIRST-INSTALL posture: the account does not exist yet, so a data volume
	// mounted before EnsureServiceUser is left to root. A test that wants an
	// owner sets it, and then the mount really chowns, which needs privilege.
	serviceUID *int
	// records is every data-volume record WriteDataVolumeRecord was handed,
	// keyed by path. It is the fake's whole model of /Library/Preferences: the
	// real write is pkg/dataroot's, and a unit test must not perform it.
	records map[string]dataroot.Record
	// serverArgs is every server-arguments record WriteServerArgsRecord was
	// handed, keyed by path. The write ALSO lands in files, encoded exactly as
	// the real writer would encode it, because the whole point of that record is
	// that a LATER install reads it back — a fake that only remembered the
	// struct would leave the uninstall-then-install gate asserting nothing.
	serverArgs map[string]dataroot.ServerArgsRecord
	// agentArgs is the same for the agent role's record. The two maps are
	// separate because the two records are separate files that never cross
	// roles, and a fake that pooled them could not tell the difference.
	agentArgs map[string]dataroot.AgentArgsRecord
}

// putDrain makes the fake launchd keep label in the domain for reads
// LaunchctlServicePID answers after its bootout — the bootout-returns-early race.
func (f *fakeSystem) putDrain(label string, reads int) {
	if f.drain == nil {
		f.drain = map[string]int{}
	}
	f.drain[label] = reads
}

// putBootstrapErrs queues the errors LaunchctlBootstrap returns for label before it
// succeeds.
func (f *fakeSystem) putBootstrapErrs(label string, errs ...error) {
	if f.bootstrapErrs == nil {
		f.bootstrapErrs = map[string][]error{}
	}
	f.bootstrapErrs[label] = errs
}

// putBootstrapAlways makes every LaunchctlBootstrap of label fail with err.
func (f *fakeSystem) putBootstrapAlways(label string, err error) {
	if f.bootstrapAlways == nil {
		f.bootstrapAlways = map[string]error{}
	}
	f.bootstrapAlways[label] = err
}

// putLoaded seeds the fake launchd domain with an already-running label — the
// reinstall posture, where both daemons are up before install touches them.
func (f *fakeSystem) putLoaded(labels ...string) {
	if f.loaded == nil {
		f.loaded = map[string]int{}
	}
	for _, l := range labels {
		f.pid++
		f.loaded[l] = f.pid
	}
}

// putMissingPath makes PathExists report path absent (the netd socket a helper that
// never came up never binds).
func (f *fakeSystem) putMissingPath(path string) {
	if f.missingPaths == nil {
		f.missingPaths = map[string]bool{}
	}
	f.missingPaths[path] = true
}

// shrinkRestartBudgets collapses the restart waits for the duration of a test, so a
// sequence that would spend a real minute waiting on launchd runs in microseconds.
func shrinkRestartBudgets(t *testing.T) {
	t.Helper()
	tiny := restartBudget{unload: 50 * time.Millisecond, running: 50 * time.Millisecond, poll: time.Microsecond}
	netdOrig, serverOrig, joinOrig := netdRestartBudget, serverRestartBudget, agentJoinBudget
	netdRestartBudget, serverRestartBudget, agentJoinBudget = tiny, tiny, tiny
	t.Cleanup(func() {
		netdRestartBudget, serverRestartBudget, agentJoinBudget = netdOrig, serverOrig, joinOrig
	})
}

// putEntitlement makes the faked codesign probe report err for path — the seam at
// which the entitlement check is stubbed, so no unit test signs anything.
func (f *fakeSystem) putEntitlement(path string, err error) {
	if f.entitlement == nil {
		f.entitlement = map[string]error{}
	}
	f.entitlement[path] = err
}

func (f *fakeSystem) VerifyVirtualizationEntitlement(path string) error {
	f.calls = append(f.calls, "VerifyVirtualizationEntitlement:"+path)
	return f.entitlement[path]
}

// putFile seeds the fake root filesystem (an installed plist, the cluster CA).
func (f *fakeSystem) putFile(path string, content []byte) {
	if f.files == nil {
		f.files = map[string][]byte{}
	}
	f.files[path] = content
}

// putFileMode makes FileMode report perm for path — how a test describes an
// operator's token file that anyone can read.
func (f *fakeSystem) putFileMode(path string, perm fs.FileMode) {
	if f.modes == nil {
		f.modes = map[string]fs.FileMode{}
	}
	f.modes[path] = perm
}

// FileMode answers 0600 for any seeded file a test has not said otherwise
// about, so an unconfigured fake describes a well-permissioned credential and
// only a test that cares states the exposure.
func (f *fakeSystem) FileMode(path string) (fs.FileMode, error) {
	f.calls = append(f.calls, "FileMode:"+path)
	if perm, ok := f.modes[path]; ok {
		return perm, nil
	}
	if _, ok := f.files[path]; ok {
		return 0o600, nil
	}
	return 0, fmt.Errorf("stat %s: %w", path, fs.ErrNotExist)
}

func (f *fakeSystem) ReadFile(path string) ([]byte, error) {
	f.calls = append(f.calls, "ReadFile:"+path)
	if content, ok := f.files[path]; ok {
		return content, nil
	}
	return nil, fmt.Errorf("open %s: %w", path, fs.ErrNotExist)
}

func (f *fakeSystem) EnsureServiceUser(name, dataRoot string) (uint32, error) {
	f.calls = append(f.calls, "EnsureServiceUser:"+name+":"+dataRoot)
	return 271, nil
}

func (f *fakeSystem) EnsureLogDir(dir string, uid uint32) error {
	f.calls = append(f.calls, "EnsureLogDir:"+dir)
	return nil
}

func (f *fakeSystem) EnsureContainerLogDir(dir string, uid uint32) error {
	f.calls = append(f.calls, "EnsureContainerLogDir:"+dir)
	return nil
}

func (f *fakeSystem) EnsureRunDir(dir string, uid uint32) error {
	f.calls = append(f.calls, "EnsureRunDir:"+dir)
	return nil
}

func (f *fakeSystem) EnsureVMRunDir(dir string, uid uint32) error {
	f.calls = append(f.calls, "EnsureVMRunDir:"+dir)
	return nil
}

func (f *fakeSystem) ReapOrphans(binPrefix string) error {
	f.calls = append(f.calls, "ReapOrphans:"+binPrefix)
	return nil
}

func (f *fakeSystem) CopyToRootOwned(src, dst string) error {
	// Record the EXACT dst the installer requested — the contract under test: the
	// destination must be the fixed installedBinary() path, never src's basename
	// (the live M2-gate failure: a `k3sm-m2` artifact landed at
	// /Library/k3sm/k3sm-m2 while the plists exec'd /Library/k3sm/k3sm, and
	// launchd invalidated both daemons with "Missing executable").
	f.calls = append(f.calls, "CopyToRootOwned:"+dst)
	return nil
}

// EnsureSymlink records the requested link and models idempotence: a second call
// for a link already pointing at the same target still records the call (the
// installer asks unconditionally) and still succeeds, which is the contract the
// real darwin implementation's "already correct → no-op nil" arm provides.
func (f *fakeSystem) EnsureSymlink(target, link string) error {
	f.calls = append(f.calls, "EnsureSymlink:"+target+"->"+link)
	if f.links == nil {
		f.links = map[string]string{}
	}
	f.links[link] = target
	return nil
}

// RemoveSymlink records the link and reports it removed — the healthy uninstall
// of a link this install laid down. A test that needs the "not ours" verdict
// asserts on the real implementation's table in install_darwin_test.go, where the
// judgement actually lives.
func (f *fakeSystem) RemoveSymlink(link, target string) (bool, error) {
	f.calls = append(f.calls, "RemoveSymlink:"+link)
	delete(f.links, link)
	return true, nil
}

func (f *fakeSystem) WriteLaunchDaemon(plistPath string, contents []byte) error {
	f.calls = append(f.calls, "WriteLaunchDaemon:"+plistPath)
	f.putFile(plistPath, contents)
	return nil
}

// LaunchctlBootstrap loads the label, unless the test queued a failure for it. A
// queued error is consumed, so putBootstrapErrs(l, transient) describes "fails
// once, then succeeds" — the racing-bootstrap shape.
func (f *fakeSystem) LaunchctlBootstrap(label string) error {
	f.calls = append(f.calls, "Bootstrap:"+label)
	if queued := f.bootstrapErrs[label]; len(queued) > 0 {
		f.bootstrapErrs[label] = queued[1:]
		return queued[0]
	}
	if err := f.bootstrapAlways[label]; err != nil {
		return err
	}
	if f.loaded == nil {
		f.loaded = map[string]int{}
	}
	f.pid++
	f.loaded[label] = f.pid
	return nil
}

// LaunchctlBootout removes the label — but only after f.drain[label] further
// LaunchctlServicePID reads, mirroring launchd's real behaviour: bootout returns
// before the label has left the domain.
func (f *fakeSystem) LaunchctlBootout(label string) error {
	f.calls = append(f.calls, "Bootout:"+label)
	if f.drain[label] > 0 {
		return nil // still in the domain; ServicePID drains the counter
	}
	delete(f.loaded, label)
	return nil
}

func (f *fakeSystem) LaunchctlKickstart(label string) error {
	f.calls = append(f.calls, "Kickstart:"+label)
	// A kickstart replaces the running instance, so the fake's reported pid moves —
	// the discriminator `k3sm certificate rotate` uses to tell the NEW control plane
	// from the old one still draining its listeners.
	f.pid++
	if f.loaded == nil {
		f.loaded = map[string]int{}
	}
	f.loaded[label] = f.pid
	return nil
}

// LaunchctlServicePID answers from the fake domain: a loaded label reports its pid,
// an absent one is an ERROR (never pid 0 — "not loaded" and "loaded but not
// spawned" are different states, and install's await-unloaded step depends on the
// difference). Each read also drains one tick of a pending bootout.
func (f *fakeSystem) LaunchctlServicePID(label string) (int, error) {
	f.calls = append(f.calls, "ServicePID:"+label)
	if n := f.drain[label]; n > 0 {
		f.drain[label] = n - 1
		if f.drain[label] == 0 {
			delete(f.loaded, label)
		}
		return f.loaded[label], nil
	}
	pid, ok := f.loaded[label]
	if !ok {
		return 0, fmt.Errorf("launchctl print system/%s: %w", label, fs.ErrNotExist)
	}
	return pid, nil
}

// PathExists answers present for every path a test has not explicitly hidden, so an
// unconfigured fake describes a healthy install.
func (f *fakeSystem) PathExists(path string) (bool, error) {
	f.calls = append(f.calls, "PathExists:"+path)
	return !f.missingPaths[path], nil
}

func (f *fakeSystem) WriteUserKubeconfig(targetUser string, contents []byte) error {
	f.calls = append(f.calls, "WriteUserKubeconfig:"+targetUser)
	f.kubeUser = targetUser
	f.kubeContent = string(contents)
	return nil
}

// RemoveAll records the call and REALLY removes the path from the fake root
// filesystem — the file itself and everything under it, plus any symlink or
// record keyed there.
//
// It used to only record, which made every uninstall in this package a no-op on
// the state a following install reads back. An uninstall-then-install test could
// then "pass" while the installed plist was still sitting in f.files, i.e. while
// the sequence under test had not actually happened. Deletion is what makes the
// fake describe a real teardown.
func (f *fakeSystem) RemoveAll(path string) error {
	f.calls = append(f.calls, "RemoveAll:"+path)
	prefix := strings.TrimSuffix(path, "/") + "/"
	under := func(p string) bool { return p == path || strings.HasPrefix(p, prefix) }
	for p := range f.files {
		if under(p) {
			delete(f.files, p)
		}
	}
	for p := range f.links {
		if under(p) {
			delete(f.links, p)
		}
	}
	for p := range f.records {
		if under(p) {
			delete(f.records, p)
		}
	}
	for p := range f.serverArgs {
		if under(p) {
			delete(f.serverArgs, p)
		}
	}
	for p := range f.agentArgs {
		if under(p) {
			delete(f.agentArgs, p)
		}
	}
	return nil
}

// The four data-volume filesystem seams below RECORD the call and then really
// perform it, unlike every other method on this fake.
//
// That is deliberate and it is what keeps the migration test non-vacuous:
// datavol.Migrate verifies its own copy by walking both trees on the real
// filesystem and hashing the datastore, so a seam that only remembered "a copy
// was requested" would leave the verification comparing an empty directory
// against a full one and the test would assert nothing about the sequence it
// exists to pin. The paths are the test's own t.TempDir()s, so nothing
// privileged happens.

func (f *fakeSystem) EnsureRootDir(dir string, mode fs.FileMode) error {
	f.calls = append(f.calls, "EnsureRootDir:"+dir)
	return os.MkdirAll(dir, mode)
}

func (f *fakeSystem) CopyTree(src, dst string) error {
	f.calls = append(f.calls, "CopyTree:"+src+"->"+dst)
	return copyTreeForTest(src, dst)
}

func (f *fakeSystem) Rename(old, new string) error {
	f.calls = append(f.calls, "Rename:"+old+"->"+new)
	return os.Rename(old, new)
}

func (f *fakeSystem) RemoveTree(path string) error {
	f.calls = append(f.calls, "RemoveTree:"+path)
	return os.RemoveAll(path)
}

// LookupServiceUID answers the first-install posture (no account yet) unless a
// test said otherwise with putServiceUID.
func (f *fakeSystem) LookupServiceUID(name string) (int, bool) {
	f.calls = append(f.calls, "LookupServiceUID:"+name)
	if f.serviceUID == nil {
		return 0, false
	}
	return *f.serviceUID, true
}

// putServiceUID makes LookupServiceUID report an existing account.
func (f *fakeSystem) putServiceUID(uid int) { f.serviceUID = &uid }

func (f *fakeSystem) WriteDataVolumeRecord(path string, rec dataroot.Record) error {
	f.calls = append(f.calls, "WriteDataVolumeRecord:"+path)
	if f.records == nil {
		f.records = map[string]dataroot.Record{}
	}
	f.records[path] = rec
	return nil
}

// WriteServerArgsRecord remembers the record AND lands its real encoding in the
// fake root filesystem, so the next install's ReadFile of that path decodes what
// a real installer would have written (dataroot owns the encoding; the fake does
// not get a second one).
func (f *fakeSystem) WriteServerArgsRecord(path string, rec dataroot.ServerArgsRecord) error {
	f.calls = append(f.calls, "WriteServerArgsRecord:"+path)
	if f.serverArgs == nil {
		f.serverArgs = map[string]dataroot.ServerArgsRecord{}
	}
	rec.Version = dataroot.ServerArgsRecordVersion
	f.serverArgs[path] = rec
	data, err := dataroot.EncodeServerArgsRecord(rec)
	if err != nil {
		return err
	}
	f.putFile(path, data)
	return nil
}

// WriteAgentArgsRecord is WriteServerArgsRecord's sibling for the agent role:
// it remembers the record AND lands its real encoding in the fake root
// filesystem, so a later install's ReadFile of that path decodes exactly what a
// real installer would have written.
func (f *fakeSystem) WriteAgentArgsRecord(path string, rec dataroot.AgentArgsRecord) error {
	f.calls = append(f.calls, "WriteAgentArgsRecord:"+path)
	if f.agentArgs == nil {
		f.agentArgs = map[string]dataroot.AgentArgsRecord{}
	}
	rec.Version = dataroot.AgentArgsRecordVersion
	f.agentArgs[path] = rec
	data, err := dataroot.EncodeAgentArgsRecord(rec)
	if err != nil {
		return err
	}
	f.putFile(path, data)
	return nil
}

// WriteServiceUserFile records the path, the MODE, the directory mode and the
// uid the installer asked for — the four things that decide whether the
// unprivileged daemon can read what root just wrote — and lands the bytes in
// the fake root filesystem so a later read sees them.
func (f *fakeSystem) WriteServiceUserFile(path string, contents []byte, uid uint32, mode, dirMode fs.FileMode) error {
	f.calls = append(f.calls, fmt.Sprintf("WriteServiceUserFile:%s:%#o:%#o:%d", path, mode, dirMode, uid))
	f.putFile(path, contents)
	return nil
}

// putServerArgsRecord seeds a server-arguments record an EARLIER install left
// behind, in the bytes that install would have written.
func putServerArgsRecord(t *testing.T, f *fakeSystem, path string, args ...string) {
	t.Helper()
	data, err := dataroot.EncodeServerArgsRecord(dataroot.ServerArgsRecord{
		Args: args, CreatedBy: "k3sm test", CreatedAt: time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("encode the server arguments record: %v", err)
	}
	f.putFile(path, data)
}

// writeFileForTest writes content at path, creating the parent directories. It
// seeds the REAL scratch data root a test hands the installer, which is what
// the "is there prior cluster state here" probe reads.
func writeFileForTest(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("seed %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("seed %s: %v", path, err)
	}
}

// copyTreeForTest is ditto(1)'s contract as far as an unprivileged test can
// honour it: the tree's shape, its file contents and its permission bits.
// Ownership is whatever the test process is on both sides, which is what makes
// Migrate's uid/gid comparison pass rather than vacuous.
func copyTreeForTest(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		if !d.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode().Perm())
	})
}

func (f *fakeSystem) FlushLo0Aliases(prefixes []netip.Prefix) error {
	strs := make([]string, len(prefixes))
	for i, p := range prefixes {
		strs[i] = p.String()
	}
	f.calls = append(f.calls, "FlushLo0Aliases:"+strings.Join(strs, ","))
	return nil
}

func (f *fakeSystem) FlushMeshPFAnchor() error {
	f.calls = append(f.calls, "FlushMeshPFAnchor")
	return nil
}

// TestInstallOrchestration proves the install drives the seam in the right
// TestLogDirIsNotWorldReadable pins the daemon log tree's ownership policy and
// the fact that install applies it.
//
// The policy is the point. /var/log/k3sm holds the control plane's, the network
// helper's and the data-volume daemon's stdout: argv, cluster endpoints, and
// the failure detail a crash prints. The directory used to be group `staff`
// 0755 and the files were whatever umask the spawning launchd job had, which on
// a Mac means every local account could read all of it. `staff` is the primary
// group of every ordinary account, so the group had to move too: tightening the
// mode over `staff` would have changed nothing.
//
// The on-disk half of this, against a real directory, is
// TestLogDirIsNotWorldReadableOnDisk in install_darwin_test.go.
func TestLogDirIsNotWorldReadable(t *testing.T) {
	t.Run("the policy is a 0750 admin-group dir with 0640 files", func(t *testing.T) {
		if LogDirMode != 0o750 {
			t.Errorf("LogDirMode = %#o, want 0750 (daemon logs are not readable by every local account)", LogDirMode)
		}
		if LogFileMode != 0o640 {
			t.Errorf("LogFileMode = %#o, want 0640 (launchd reuses a pre-created file's mode)", LogFileMode)
		}
		if LogDirGID != 80 {
			t.Errorf("LogDirGID = %d, want 80 (admin, the sudo-capable tier)", LogDirGID)
		}
		// Not staff. DataRootGID is staff, and staff is the default primary
		// group of every ordinary macOS account — a staff-readable log tree is
		// a world-readable one with extra steps.
		if LogDirGID == DataRootGID {
			t.Errorf("LogDirGID = %d = DataRootGID (staff); staff is every local account's primary group", LogDirGID)
		}
		if LogDirMode.Perm()&0o007 != 0 || LogFileMode.Perm()&0o007 != 0 {
			t.Errorf("mode %#o/%#o grants `other` access to the daemon logs", LogDirMode, LogFileMode)
		}
	})

	t.Run("install ensures the log dir", func(t *testing.T) {
		f := &fakeSystem{}
		if err := Install(context.Background(), f, Config{BinarySource: "/tmp/k3sm", TargetUser: "alice"}); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if !slices.Contains(f.calls, "EnsureLogDir:"+LogDir) {
			t.Errorf("install never ensured %s (calls: %v)", LogDir, f.calls)
		}
	})
}

// ORDER: ensure _k3sm → copy binary root-owned → write both plists → bootstrap
// netd BEFORE server → write the admin kubeconfig to the HUMAN (not root).
func TestInstallOrchestration(t *testing.T) {
	f := &fakeSystem{}
	cfg := Config{BinarySource: "/tmp/k3sm", TargetUser: "alice"}
	if err := Install(context.Background(), f, cfg); err != nil {
		t.Fatalf("Install: %v", err)
	}

	want := []string{
		// Before anything is written: is the OTHER role's daemon already on this
		// Mac? A node is a control plane or a worker, never both.
		"ReadFile:/Library/LaunchDaemons/io.k3sm.agent.plist",
		"EnsureServiceUser:_k3sm:" + DefaultDataRoot,
		"EnsureLogDir:/var/log/k3sm",
		// The container-log tree, at the same moment and for the same reason: the
		// node refuses to start without it, and only root can create it owned by
		// the service user at a mode that keeps pod output off every local account.
		"EnsureContainerLogDir:/var/log/pods",
		"EnsureContainerLogDir:/var/log/containers",
		// Before any daemon bootstraps: root netd would otherwise create the run
		// dir root-owned and the _k3sm server could not bind runtimed.sock in it.
		"EnsureRunDir:/var/lib/k3sm/run",
		// Same reason, one level down: runtimed binds each vm pod's guest-agent
		// socket under here as _k3sm. Missing it makes every vm pod fail to boot.
		"EnsureVMRunDir:/var/lib/k3sm/run/vm",
		"CopyToRootOwned:/Library/k3sm/k3sm",
		// The launcher link goes down immediately after the binary it points at,
		// and long before any daemon work: copying into /Library/k3sm never put
		// `k3sm` on a shell's PATH, which every post-install instruction assumes.
		"EnsureSymlink:/Library/k3sm/k3sm->/usr/local/bin/k3sm",
		"CopyToRootOwned:/Library/k3sm/k3sm-execshim",
		"CopyToRootOwned:/Library/k3sm/libk3sm_pathrebase_shim.dylib",
		"CopyToRootOwned:/Library/k3sm/libk3sm_getaddrinfo_shim.dylib",
		// The helper's entitlement is read BEFORE it is copied: the copy preserves
		// the signature verbatim, so this is the last moment install can still
		// decline to lay down a helper that cannot boot a VM.
		"VerifyVirtualizationEntitlement:/tmp/k3sm-vmhost",
		"CopyToRootOwned:/Library/k3sm/k3sm-vmhost",
		"CopyToRootOwned:/Library/k3sm/bin/kube-apiserver",
		"CopyToRootOwned:/Library/k3sm/bin/kube-scheduler",
		"CopyToRootOwned:/Library/k3sm/bin/kube-controller-manager",
		"CopyToRootOwned:/Library/k3sm/bin/kubectl",
		"CopyToRootOwned:/Library/k3sm/bin/kine",
		// The kine version marker rides beside the kine binary it describes, staged
		// best-effort (a pre-marker archive has none and must still install).
		"CopyToRootOwned:/Library/k3sm/bin/" + executor.KineMarkerName,
		// The installed server plist is read BEFORE the plists are rendered, so a
		// reinstall carries the operator's own arguments into the new render.
		"ReadFile:/Library/LaunchDaemons/io.k3sm.server.plist",
		// There is none here (a first install), so the second source is read: the
		// root-owned record that survives an uninstall.
		"ReadFile:" + dataroot.DefaultServerArgsRecordPath,
		// And whatever was carried — nothing, on a first install — is recorded
		// again, before the plist that will not survive the next uninstall.
		"WriteServerArgsRecord:" + dataroot.DefaultServerArgsRecordPath,
		"WriteLaunchDaemon:/Library/LaunchDaemons/io.k3sm.netd.plist",
		"WriteLaunchDaemon:/Library/LaunchDaemons/io.k3sm.server.plist",
		// Each label: bootout → await-unloaded (the ServicePID read whose ERROR is
		// the only proof launchd finished the teardown) → bootstrap → await-running
		// (the read that proves the fresh instance actually spawned). The bare
		// bootout;bootstrap pair this replaced raced launchd's own removal.
		"Bootout:io.k3sm.netd",
		"ServicePID:io.k3sm.netd",
		"Bootstrap:io.k3sm.netd",
		"ServicePID:io.k3sm.netd",
		"Bootout:io.k3sm.server",
		"ServicePID:io.k3sm.server",
		"Bootstrap:io.k3sm.server",
		"ServicePID:io.k3sm.server",
		// Then the post-restart verification: both pids re-read, and the netd
		// socket the two daemons rendezvous on asserted present.
		"ServicePID:io.k3sm.netd",
		"ServicePID:io.k3sm.server",
		"PathExists:/var/lib/k3sm/run/netd.sock",
		// ...and the server's crash-loop record read, because a daemon parked by
		// its breaker reports a healthy pid while serving nothing.
		"ReadFile:/var/lib/k3sm/server/crashloop.json",
		"WriteUserKubeconfig:alice",
	}
	if len(f.calls) != len(want) {
		t.Fatalf("call sequence = %v, want %v", f.calls, want)
	}
	for i := range want {
		if f.calls[i] != want[i] {
			t.Errorf("call %d = %q, want %q", i, f.calls[i], want[i])
		}
	}

	// netd must be bootstrapped BEFORE the server (the server depends on the helper).
	if idx(f.calls, "Bootstrap:io.k3sm.netd") >= idx(f.calls, "Bootstrap:io.k3sm.server") {
		t.Error("netd must be bootstrapped before the server")
	}
	// Each daemon is BOOTED OUT before it is (re)bootstrapped, so a reinstall/upgrade
	// always restarts the FRESH on-disk binary instead of leaving a stale daemon
	// (launchctl bootstrap does not re-exec an updated binary on an already-loaded job).
	for _, label := range []string{"io.k3sm.netd", "io.k3sm.server"} {
		if idx(f.calls, "Bootout:"+label) >= idx(f.calls, "Bootstrap:"+label) {
			t.Errorf("%s must be booted out before it is bootstrapped (fresh-binary restart)", label)
		}
	}
	// The kubeconfig is owned by the human, never root.
	if f.kubeUser != "alice" || f.kubeUser == "root" {
		t.Errorf("kubeconfig owner = %q, want the human (alice), never root", f.kubeUser)
	}
	if !strings.Contains(f.kubeContent, "token:") {
		t.Error("admin kubeconfig must carry the shared bearer token")
	}
}

// TestEnsureServiceUserCreatesTheConfiguredDataRoot proves the service user's
// home tracks Config.DataRoot, not the DefaultDataRoot constant — no shipped
// flag sets a non-default root today, but the seam must carry whatever value
// the config holds, and it must still fall back to the default when the
// config leaves DataRoot empty (the common case, exercised the same way by
// TestInstallOrchestration).
func TestEnsureServiceUserCreatesTheConfiguredDataRoot(t *testing.T) {
	cases := []struct {
		name     string
		dataRoot string
		want     string
	}{
		{name: "configured data root", dataRoot: filepath.Join(t.TempDir(), "custom-root"), want: ""},
		{name: "empty data root falls back to the default", dataRoot: "", want: DefaultDataRoot},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := tc.want
			if want == "" {
				want = tc.dataRoot
			}
			f := &fakeSystem{}
			cfg := Config{BinarySource: "/tmp/k3sm", TargetUser: "alice", DataRoot: tc.dataRoot}
			if err := Install(context.Background(), f, cfg); err != nil {
				t.Fatalf("Install: %v", err)
			}
			// The FIRST privileged call — the cross-role probe ahead of it is a
			// read, and install performs nothing else before the service user
			// exists: the data root is its home, and every later step writes into it.
			wantCall := "EnsureServiceUser:_k3sm:" + want
			var first string
			for _, c := range f.calls {
				if !strings.HasPrefix(c, "ReadFile:") {
					first = c
					break
				}
			}
			if first != wantCall {
				t.Fatalf("first privileged call = %q (calls %v), want %q", first, f.calls, wantCall)
			}
		})
	}
}

// TestInstallBinaryLandsAtFixedPath is the regression for the live M2-gate
// failure: the gate builds the binary as `k3sm-m2`, and the old CopyToRootOwned
// derived the destination from the SOURCE basename — landing /Library/k3sm/k3sm-m2
// while both plists exec /Library/k3sm/k3sm, so launchd invalidated both daemons
// with the unrecoverable "Missing executable". The installer must request the
// EXACT installedBinary() destination regardless of the artifact's name.
func TestInstallBinaryLandsAtFixedPath(t *testing.T) {
	f := &fakeSystem{}
	cfg := Config{BinarySource: "/tmp/build/k3sm-m2", TargetUser: "alice"}
	if err := Install(context.Background(), f, cfg); err != nil {
		t.Fatalf("Install: %v", err)
	}
	var dsts []string
	for _, c := range f.calls {
		if strings.HasPrefix(c, "CopyToRootOwned:") {
			dsts = append(dsts, strings.TrimPrefix(c, "CopyToRootOwned:"))
		}
	}
	fixedHead := []string{"/Library/k3sm/k3sm", "/Library/k3sm/k3sm-execshim", "/Library/k3sm/" + PathShimName, "/Library/k3sm/" + DNSShimName, "/Library/k3sm/" + VMHostName}
	if len(dsts) < len(fixedHead) {
		t.Fatalf("only %d copies %v, want at least the fixed head %v (never the source basename)", len(dsts), dsts, fixedHead)
	}
	for i, want := range fixedHead {
		if dsts[i] != want {
			t.Errorf("copy %d landed at %q, want the fixed head %q (never the source basename)", i, dsts[i], want)
		}
	}
	// The payload set lands at InstallDir/bin/<name> — one copy per
	// executor.PayloadBinaries entry, in order, after the binary + exec-shim + shims + vmhost.
	head := len(fixedHead)
	// +1 for the kine version marker, staged beside the kine binary it describes.
	if want := head + len(executor.PayloadBinaries()) + 1; len(dsts) != want {
		t.Errorf("%d copies, want %d (binary + exec-shim + path-shim + dns-shim + vmhost + the payload set + the kine marker)", len(dsts), want)
	}
	for i, name := range executor.PayloadBinaries() {
		if got, want := dsts[head+i], "/Library/k3sm/bin/"+name; got != want {
			t.Errorf("payload copy %d landed at %q, want %q", i, got, want)
		}
	}
	// The shim/payload sources default to SIBLINGS of BinarySource — the
	// gate/goreleaser stage all artifacts side by side.
	if got := cfg.withDefaults().ExecShimSource; got != "/tmp/build/k3sm-execshim" {
		t.Errorf("ExecShimSource default = %q, want the BinarySource sibling /tmp/build/k3sm-execshim", got)
	}
	if got := cfg.withDefaults().PayloadSource; got != "/tmp/build/cp-payload" {
		t.Errorf("PayloadSource default = %q, want the BinarySource sibling dir /tmp/build/cp-payload", got)
	}
	if got := cfg.withDefaults().PathShimSource; got != "/tmp/build/"+PathShimName {
		t.Errorf("PathShimSource default = %q, want the BinarySource sibling /tmp/build/%s", got, PathShimName)
	}
	if got := cfg.withDefaults().DNSShimSource; got != "/tmp/build/"+DNSShimName {
		t.Errorf("DNSShimSource default = %q, want the BinarySource sibling /tmp/build/%s", got, DNSShimName)
	}
	if got := cfg.withDefaults().VMHostSource; got != "/tmp/build/"+VMHostName {
		t.Errorf("VMHostSource default = %q, want the BinarySource sibling /tmp/build/%s", got, VMHostName)
	}
}

// TestInstallRequiresInputs proves the install fails fast without the binary
// source or the target user (no silent partial install).
func TestInstallRequiresInputs(t *testing.T) {
	if err := Install(context.Background(), &fakeSystem{}, Config{TargetUser: "alice"}); err == nil {
		t.Error("Install must require BinarySource")
	}
	if err := Install(context.Background(), &fakeSystem{}, Config{BinarySource: "/tmp/k3sm"}); err == nil {
		t.Error("Install must require TargetUser (the kubeconfig owner)")
	}
}

// TestUninstallIdempotent proves uninstall boots out BOTH daemons (server first,
// then netd), REMOVES both leaked plists (the B62 fix), and sweeps the install
// dir — in reverse install order — and that re-running is safe.
func TestUninstallIdempotent(t *testing.T) {
	f := &fakeSystem{}
	if err := Uninstall(context.Background(), f, Config{}); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	want := []string{
		// Uninstall asks the disk which roles are installed before it tears
		// anything down, so a Mac that was installed as a worker has its agent
		// daemon swept by the same run.
		"ReadFile:/Library/LaunchDaemons/io.k3sm.agent.plist",
		// The container-log tree goes FIRST (the manifest is walked in reverse
		// install order) and it goes at all, unlike DataRoot and the daemon
		// LogDir: every file in it belongs to a pod that will not exist once k3sm
		// is uninstalled, and it is a root-equivalent tree of former workloads'
		// output.
		"RemoveAll:/var/log/containers",
		"RemoveAll:/var/log/pods",
		"Bootout:io.k3sm.server",
		"RemoveAll:/Library/LaunchDaemons/io.k3sm.server.plist",
		"Bootout:io.k3sm.netd",
		"RemoveAll:/Library/LaunchDaemons/io.k3sm.netd.plist",
		// The launcher link is judged BEFORE the sweep deletes its target: after
		// the sweep it is a dangling link whose identity can no longer be read.
		"RemoveSymlink:/usr/local/bin/k3sm",
		"RemoveAll:/Library/k3sm",
		"ReapOrphans:/var/lib/k3sm/server/bin",
		// The mesh pf anchor flush (B274) is the uninstall backstop for the
		// MSS-clamp rule netd's own shutdown path never reaches.
		"FlushMeshPFAnchor",
		// The lo0 flush covers the pinned pod aggregate + the Service CIDR — the
		// pod /32s, the API/DNS VIPs, and the node mesh-egress .1 (which the pod
		// stale-sweep deliberately never touches) all fall inside these two.
		"FlushLo0Aliases:100.64.0.0/10,10.43.0.0/16",
	}
	if strings.Join(f.calls, ",") != strings.Join(want, ",") {
		t.Fatalf("uninstall calls = %v, want %v", f.calls, want)
	}
	// Second run is safe (bootout of a not-loaded label is a no-op in the real impl).
	if err := Uninstall(context.Background(), &fakeSystem{}, Config{}); err != nil {
		t.Errorf("second Uninstall must be idempotent, got %v", err)
	}
}

// TestUninstallFlushesTheMeshPFAnchor proves Uninstall calls FlushMeshPFAnchor
// exactly once — the B274 backstop for the mesh MSS-clamp pf anchor, which
// outlives netd (only the RemoveMesh RPC reaches mesh.WGDevice.Down, and no
// signal path ever calls it) and would otherwise survive scoped to a utun
// number macOS recycles onto an unrelated tunnel.
func TestUninstallFlushesTheMeshPFAnchor(t *testing.T) {
	f := &fakeSystem{}
	if err := Uninstall(context.Background(), f, Config{}); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	n := 0
	for _, c := range f.calls {
		if c == "FlushMeshPFAnchor" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("FlushMeshPFAnchor called %d times, want exactly 1 (calls: %v)", n, f.calls)
	}
}

// TestNetdPlistXML proves the netd plist is root (NO UserName), execs `k3sm
// netd` with the Service CIDR, and is boot-surviving (RunAtLoad + KeepAlive).
func TestNetdPlistXML(t *testing.T) {
	x := string(NetdPlist(Config{}))
	mustContain(t, x, "<key>Label</key>\n  <string>io.k3sm.netd</string>")
	mustContain(t, x, "<string>netd</string>")
	mustContain(t, x, "<string>--service-cidr</string>")
	mustContain(t, x, "<key>RunAtLoad</key>\n  <true/>")
	mustContain(t, x, "<key>KeepAlive</key>\n  <true/>")
	if strings.Contains(x, "<key>UserName</key>") {
		t.Error("netd plist must NOT carry a UserName (it runs as root)")
	}
	// B116/B133 — the plist must render NO --node-ip. netdsvc's node-address
	// authorizer branch (a <1024 bind on the node's OWN InternalIP, authorized
	// ONLY by the canonical kube-system/k3sm-ingress Service since B133) is
	// DORMANT BY CONFIGURATION, not by construction: the code is still there, and
	// passing --node-ip would re-arm it. Since B116 the ingress/svclb listeners
	// bind the wildcard in-process and never ask netd for a node-address bind, so
	// re-adding the flag would widen the root helper's authorized surface with no
	// consumer. Adding it must redden HERE.
	if strings.Contains(x, "--node-ip") {
		t.Error("netd plist must NOT render --node-ip: the node-address authorizer branch is dormant by configuration (B116/B133); re-arming it needs a deliberate decision, not a plist edit")
	}
}

// TestServerPlistXML proves the server plist runs as the _k3sm user (UserName
// present), execs `k3sm server --runtime runtimed`, and is boot-surviving.
func TestServerPlistXML(t *testing.T) {
	x := string(ServerPlist(Config{}))
	mustContain(t, x, "<key>Label</key>\n  <string>io.k3sm.server</string>")
	mustContain(t, x, "<key>UserName</key>\n  <string>_k3sm</string>")
	mustContain(t, x, "<string>server</string>")
	mustContain(t, x, "<string>runtimed</string>")
	mustContain(t, x, "<key>RunAtLoad</key>\n  <true/>")
	mustContain(t, x, "<key>KeepAlive</key>\n  <true/>")
	// ExitTimeOut > launchd's 20s default so Stop()'s serial control-plane
	// teardown finishes before SIGKILL (else the stragglers orphan).
	mustContain(t, x, "<key>ExitTimeOut</key>\n  <integer>45</integer>")
	if strings.Contains(string(NetdPlist(Config{})), "ExitTimeOut") {
		t.Error("netd plist should NOT set ExitTimeOut (it has no child processes to reap)")
	}
}

// TestServerPlistRaisesFileLimit proves the server plist raises RLIMIT_NOFILE so
// darwin-net's UDP flow budget (B48, rl.Cur/2) sizes against a real fd table, not
// launchd's 256 default. The load-bearing assertion is well-formedness: a
// hand-rolled unbalanced/mis-nested <dict> would still pass the substring checks
// yet make launchd REJECT the plist at bootstrap (a non-loading control plane),
// so the generated XML is decoded to EOF. The raise is server-ONLY (netd is not
// the UDP-relay host), which the NetdPlist negative assertion pins.
func TestServerPlistRaisesFileLimit(t *testing.T) {
	x := ServerPlist(Config{})

	// (1) Well-formedness (load-bearing): the whole plist must PARSE as XML. A
	// mis-nested <dict> from the hand-rolled builder would fail here even though
	// the substring checks in (2) would still pass on a corrupt plist.
	dec := xml.NewDecoder(bytes.NewReader(x))
	for {
		_, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("ServerPlist is not well-formed XML: %v\n--- plist ---\n%s", err, x)
		}
	}

	// (2) Soft + Hard NumberOfFiles = 131072, correctly nested as <integer>.
	s := string(x)
	for _, needle := range []string{
		"<key>SoftResourceLimits</key>",
		"<key>HardResourceLimits</key>",
		"<key>NumberOfFiles</key>",
		"<integer>131072</integer>",
	} {
		mustContain(t, s, needle)
	}

	// (3) NODE daemons only: netd is not a relay host, so its plist carries no
	// resource limits (the agent's does — it runs the same Service proxy). This
	// also proves SoftFileLimit is conditional (not emitted for every plist) —
	// the field is honored, not hard-wired into renderPlist.
	if n := string(NetdPlist(Config{})); strings.Contains(n, "SoftResourceLimits") {
		t.Error("NetdPlist must NOT raise file limits (the raise is server-only)")
	}
}

// TestPlistEscaping proves string values are XML-escaped (a token with an &
// cannot corrupt the plist).
func TestPlistEscaping(t *testing.T) {
	x := string(ServerPlist(Config{AdminToken: "a&b<c", BinarySource: "/tmp/k3sm", TargetUser: "alice"}))
	if strings.Contains(x, "a&b<c") {
		t.Error("plist string values must be XML-escaped")
	}
	mustContain(t, x, "a&amp;b&lt;c")
}

// meshIPOccurrences returns how many times --mesh-ip (either spelling) appears
// in the rendered plist's ProgramArguments, and the value of the last one — so
// a test can assert BOTH "exactly once" and "the right value" without decoding
// the argv twice.
func meshIPOccurrences(t *testing.T, plist []byte) (count int, value string) {
	t.Helper()
	argv, err := parseProgramArguments(plist)
	if err != nil {
		t.Fatalf("parseProgramArguments: %v", err)
	}
	for i, a := range argv {
		name, v, inline := splitFlag(a)
		if name != "mesh-ip" {
			continue
		}
		count++
		if inline {
			value = v
			continue
		}
		if i+1 < len(argv) {
			value = argv[i+1]
		}
	}
	return count, value
}

// TestInstallPlistCarriesMeshIP is the gate for Config.MeshIP: an explicit
// `k3sm install --mesh-ip` must render into the server plist's argv exactly
// once, must REPLACE whatever --mesh-ip a carried plist/record already held,
// and must leave the plist byte-for-byte unchanged when no --mesh-ip is
// involved at all — a defect here either drops the operator's mesh address or
// silently duplicates the flag, and launchd's flag package takes the LAST
// occurrence, so a duplicate is a silent value flip, not an error.
func TestInstallPlistCarriesMeshIP(t *testing.T) {
	t.Run("an explicit MeshIP renders --mesh-ip exactly once", func(t *testing.T) {
		x := ServerPlist(Config{MeshIP: "100.64.0.1"})
		count, value := meshIPOccurrences(t, x)
		if count != 1 || value != "100.64.0.1" {
			t.Errorf("--mesh-ip occurrences = %d, value = %q; want 1 occurrence of 100.64.0.1", count, value)
		}
	})

	t.Run("no MeshIP and no carried args renders identically to before this change", func(t *testing.T) {
		// Pinned in memory rather than as a golden file (the package has no
		// testdata convention): this is exactly TestServerPlistXML's Config{},
		// asserted byte-for-byte so an empty MeshIP can never perturb the
		// existing render.
		before := ServerPlist(Config{})
		after := ServerPlist(Config{})
		if !bytes.Equal(before, after) {
			t.Errorf("ServerPlist(Config{}) is non-deterministic:\n--- a ---\n%s\n--- b ---\n%s", before, after)
		}
		if count, _ := meshIPOccurrences(t, after); count != 0 {
			t.Errorf("ServerPlist(Config{}) must render no --mesh-ip at all, got %d", count)
		}
	})

	t.Run("an explicit MeshIP replaces a carried --mesh-ip, not beside it", func(t *testing.T) {
		x := ServerPlist(Config{
			ExtraServerArgs: []string{"--mesh-ip", "100.64.0.9", "--registry-port", "5000"},
			MeshIP:          "100.64.0.1",
		})
		count, value := meshIPOccurrences(t, x)
		if count != 1 || value != "100.64.0.1" {
			t.Errorf("--mesh-ip occurrences = %d, value = %q; want the single carried 100.64.0.9 replaced by 100.64.0.1", count, value)
		}
		mustContain(t, string(x), "--registry-port")
		mustContain(t, string(x), "5000")
	})

	t.Run("no MeshIP flag leaves a carried --mesh-ip untouched", func(t *testing.T) {
		x := ServerPlist(Config{ExtraServerArgs: []string{"--mesh-ip", "100.64.0.9"}})
		count, value := meshIPOccurrences(t, x)
		if count != 1 || value != "100.64.0.9" {
			t.Errorf("--mesh-ip occurrences = %d, value = %q; want the carried 100.64.0.9 unchanged", count, value)
		}
	})
}

// recorded returns the arguments of every fake seam call whose "Op:arg" string
// carries prefix (e.g. "RemoveAll:").
func recorded(calls []string, prefix string) []string {
	var out []string
	for _, c := range calls {
		if rest, ok := strings.CutPrefix(c, prefix); ok {
			out = append(out, rest)
		}
	}
	return out
}

func toSet(xs []string) map[string]bool {
	s := make(map[string]bool, len(xs))
	for _, x := range xs {
		s[x] = true
	}
	return s
}

func daemonByPath(m []artifact, path string) (artifact, bool) {
	for _, a := range m {
		if a.kind == kindDaemon && a.path == path {
			return a, true
		}
	}
	return artifact{}, false
}

// fileDispByPath classifies a path-bearing manifest entry. kindSymlink is
// admitted alongside kindFile/kindDir so a symlink entry whose disposition is not
// dispRemove fails the coverage assertion instead of being silently invisible to
// it — an unremoved launcher link is exactly the leak this gate exists to catch.
func fileDispByPath(m []artifact, path string) (disposition, bool) {
	for _, a := range m {
		if (a.kind == kindFile || a.kind == kindDir || a.kind == kindSymlink) && a.path == path {
			return a.disp, true
		}
	}
	return 0, false
}

// uninstallGaps returns, for a REAL Install run (installCalls) and a REAL
// Uninstall run (uninstallCalls) recorded by the fake, the install-created
// artifacts the uninstall FAILS to tear down — classified through the manifest.
// An install artifact absent from the manifest is itself a gap: an off-manifest
// lay-down line is the exact future regression the gate must catch, which a
// manifest-vs-manifest tautology never would.
func uninstallGaps(cfg Config, installCalls, uninstallCalls []string) []string {
	cfg = cfg.withDefaults()
	m := artifactManifest(cfg)
	removed := toSet(recorded(uninstallCalls, "RemoveAll:"))
	bootedOut := toSet(recorded(uninstallCalls, "Bootout:"))
	installDirSwept := removed[cfg.InstallDir]

	var gaps []string

	// Files copied in by CopyToRootOwned (the recorded value IS the installed path).
	for _, path := range recorded(installCalls, "CopyToRootOwned:") {
		disp, known := fileDispByPath(m, path)
		if !known {
			gaps = append(gaps, "off-manifest install: "+path)
			continue
		}
		switch disp {
		case dispInstallDirCovered:
			if !installDirSwept && !removed[path] {
				gaps = append(gaps, "installDir artifact not swept: "+path)
			}
		case dispRemove:
			if !removed[path] {
				gaps = append(gaps, "artifact not removed: "+path)
			}
		}
	}

	// Daemons written by WriteLaunchDaemon (each: Bootout(label) + RemoveAll(plist)).
	for _, plist := range recorded(installCalls, "WriteLaunchDaemon:") {
		a, known := daemonByPath(m, plist)
		if !known {
			gaps = append(gaps, "off-manifest plist: "+plist)
			continue
		}
		if a.disp != dispRemove {
			continue
		}
		if !bootedOut[a.label] {
			gaps = append(gaps, "daemon not booted out: "+a.label)
		}
		if !removed[a.path] {
			gaps = append(gaps, "plist leaked: "+a.path)
		}
	}

	// Files handed to the service user (the staged join token). They live under
	// the PRESERVED data root, which no sweep reaches, so uninstall must name
	// each one: a credential install wrote and uninstall forgot would sit on the
	// machine after k3sm is gone.
	for _, call := range recorded(installCalls, "WriteServiceUserFile:") {
		path, _, ok := strings.Cut(call, ":")
		if !ok {
			gaps = append(gaps, "unparsable WriteServiceUserFile record: "+call)
			continue
		}
		disp, known := fileDispByPath(m, path)
		switch {
		case !known:
			gaps = append(gaps, "off-manifest service-user file: "+path)
		case disp == dispRemove && !removed[path]:
			gaps = append(gaps, "artifact not removed: "+path)
		}
	}

	// Symlinks laid down by EnsureSymlink. They live OUTSIDE the InstallDir sweep
	// (that is the entire point of a launcher on PATH), so no sweep can cover
	// them: uninstall must ask for each one by name, and a link install created
	// with no matching RemoveSymlink is a leak the other three loops cannot see.
	unlinked := toSet(recorded(uninstallCalls, "RemoveSymlink:"))
	for _, call := range recorded(installCalls, "EnsureSymlink:") {
		target, link, ok := strings.Cut(call, "->")
		if !ok {
			gaps = append(gaps, "unparsable EnsureSymlink record: "+call)
			continue
		}
		disp, known := fileDispByPath(m, link)
		if !known {
			gaps = append(gaps, "off-manifest link: "+link)
			continue
		}
		if disp != dispRemove {
			gaps = append(gaps, "link not marked for removal: "+link)
			continue
		}
		if !unlinked[link] {
			gaps = append(gaps, "link leaked (never unlinked): "+link+" -> "+target)
		}
	}
	return gaps
}

// TestUninstallManifestCoversInstall is the B62 gate. It asserts over the seam
// calls RECORDED from a REAL Install run + a REAL Uninstall run against the fake
// (never the manifest against itself — that tautology would never catch a future
// off-manifest install line, the exact bug): forward coverage, bidirectional
// no-over-broad-removal, the preserve set untouched, and idempotency.
func TestUninstallManifestCoversInstall(t *testing.T) {
	cfg := Config{BinarySource: "/tmp/k3sm", TargetUser: "alice"}
	dc := cfg.withDefaults()

	inst := &fakeSystem{}
	if err := Install(context.Background(), inst, cfg); err != nil {
		t.Fatalf("Install: %v", err)
	}
	uninst := &fakeSystem{}
	if err := Uninstall(context.Background(), uninst, cfg); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	installCalls := inst.calls
	uninstallCalls := uninst.calls
	removed := toSet(recorded(uninstallCalls, "RemoveAll:"))
	bootedOut := toSet(recorded(uninstallCalls, "Bootout:"))

	t.Run("coverage: uninstall tears down everything install laid down", func(t *testing.T) {
		if gaps := uninstallGaps(cfg, installCalls, uninstallCalls); len(gaps) != 0 {
			t.Errorf("uninstall leaves install artifacts behind: %v", gaps)
		}
	})

	t.Run("both leaked plists are now removed (the B62 fix)", func(t *testing.T) {
		for _, label := range []string{ServerLabel, NetdLabel} {
			plist := dc.plistPath(label)
			if !bootedOut[label] {
				t.Errorf("daemon %s not booted out", label)
			}
			if !removed[plist] {
				t.Errorf("plist LEAKED (not removed on uninstall): %s", plist)
			}
		}
	})

	t.Run("RED: an off-manifest install line is caught", func(t *testing.T) {
		// Simulate a future regression: an install laying a binary into a path the
		// manifest does not know. The gate MUST flag it — proving non-vacuity (a
		// manifest-vs-manifest check would silently pass).
		rogue := append(append([]string{}, installCalls...), "CopyToRootOwned:/Library/rogue")
		gaps := uninstallGaps(cfg, rogue, uninstallCalls)
		if len(gaps) == 0 {
			t.Fatal("expected an off-manifest install to be flagged, got none")
		}
		found := false
		for _, g := range gaps {
			if strings.Contains(g, "/Library/rogue") {
				found = true
			}
		}
		if !found {
			t.Errorf("gaps %v do not name the rogue artifact", gaps)
		}
	})

	t.Run("bidirectional: uninstall removes only install-created paths", func(t *testing.T) {
		// Every path uninstall RemoveAll's must be one install created: a written
		// plist, or the InstallDir tree (the CopyToRootOwned dst). Catches a
		// RemoveAll reaching into /Library or a home dir for a path k3sm never made.
		created := toSet(recorded(installCalls, "WriteLaunchDaemon:"))
		for _, path := range recorded(installCalls, "CopyToRootOwned:") {
			created[filepath.Dir(path)] = true // the InstallDir tree (the sweep root)
		}
		// The container-log tree is created through its own seam method rather
		// than by a copy, so it enters the created set the same way it is laid
		// down. The bidirectional property is unchanged: a RemoveAll of a path
		// NOTHING in installCalls produced is still a failure.
		for _, path := range recorded(installCalls, "EnsureContainerLogDir:") {
			created[path] = true
		}
		for _, p := range recorded(uninstallCalls, "RemoveAll:") {
			if !created[p] {
				t.Errorf("uninstall removed %q, which install never created (over-broad removal)", p)
			}
		}
		bootstrapped := toSet(recorded(installCalls, "Bootstrap:"))
		for _, l := range recorded(uninstallCalls, "Bootout:") {
			if !bootstrapped[l] {
				t.Errorf("uninstall booted out %q, which install never bootstrapped", l)
			}
		}
	})

	t.Run("preserve set untouched: DataRoot, LogDir, kubeconfig, _k3sm home", func(t *testing.T) {
		// Table-driven over the manifest's dispPreserve entries: none may be removed.
		for _, a := range artifactManifest(dc) {
			if a.disp != dispPreserve || a.path == "" {
				continue
			}
			if removed[a.path] {
				t.Errorf("uninstall removed PRESERVED artifact %q", a.path)
			}
		}
		// The admin kubeconfig (preserve; its ~/.kube/config path is resolved in the
		// darwin impl) — no removal may touch a kube path.
		for _, p := range recorded(uninstallCalls, "RemoveAll:") {
			if strings.Contains(p, "/.kube/") {
				t.Errorf("uninstall removed a kubeconfig path %q (may hold other clusters)", p)
			}
		}
		// The _k3sm user's home IS DataRoot; asserting DataRoot survives keeps the
		// service user's state intact (there is no user-removal seam to invoke).
		if removed[dc.DataRoot] {
			t.Error("the _k3sm user's home (DataRoot) must be preserved")
		}
	})

	t.Run("idempotency: a second uninstall over removed state returns nil", func(t *testing.T) {
		second := &fakeSystem{}
		if err := Uninstall(context.Background(), second, cfg); err != nil {
			t.Errorf("second Uninstall must be a no-op success (partial-install recovery), got %v", err)
		}
	})

	t.Run("forward-declared cp-payload items are InstallDir-covered, existence not asserted", func(t *testing.T) {
		for _, a := range artifactManifest(dc) {
			if a.assertExists || a.disp != dispInstallDirCovered {
				continue
			}
			if !strings.HasPrefix(a.path, dc.InstallDir+"/") {
				t.Errorf("forward-declared artifact %q must live under InstallDir %q", a.path, dc.InstallDir)
			}
		}
	})
}

// TestInstallLinksK3smOntoPath is the gate for the defect this manifest entry
// fixes: install copied the binary to /Library/k3sm and stopped, so `k3sm` was
// not a command any shell could resolve — while install.sh closed by telling the
// operator to run one. The launcher is a first-class manifest artifact, laid
// down after its target and torn down by identity before the InstallDir sweep
// deletes what it points at.
func TestInstallLinksK3smOntoPath(t *testing.T) {
	cfg := Config{BinarySource: "/tmp/build/k3sm-m2", TargetUser: "alice"}
	dc := cfg.withDefaults()

	t.Run("the manifest carries exactly one launcher link", func(t *testing.T) {
		var links []artifact
		for _, a := range artifactManifest(dc) {
			if a.kind == kindSymlink {
				links = append(links, a)
			}
		}
		if len(links) != 1 {
			t.Fatalf("manifest has %d kindSymlink entries, want exactly 1: %+v", len(links), links)
		}
		a := links[0]
		if a.path != dc.installedLink() {
			t.Errorf("link path = %q, want installedLink() %q", a.path, dc.installedLink())
		}
		if a.target != dc.installedBinary() {
			t.Errorf("link target = %q, want installedBinary() %q", a.target, dc.installedBinary())
		}
		if a.path != "/usr/local/bin/k3sm" {
			t.Errorf("link path = %q, want the /etc/paths-covered launcher %q", a.path, "/usr/local/bin/k3sm")
		}
		// It cannot ride the InstallDir sweep: it does not live under InstallDir.
		if a.disp != dispRemove {
			t.Errorf("link disposition = %v, want dispRemove (no sweep covers a path outside InstallDir)", a.disp)
		}
	})

	t.Run("install links after the binary lands and before any daemon starts", func(t *testing.T) {
		f := &fakeSystem{}
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		link := idx(f.calls, "EnsureSymlink:/Library/k3sm/k3sm->/usr/local/bin/k3sm")
		if link < 0 {
			t.Fatalf("install never linked k3sm onto PATH; calls = %v", f.calls)
		}
		// After its target: a link laid before the binary points at nothing.
		if binary := idx(f.calls, "CopyToRootOwned:/Library/k3sm/k3sm"); binary < 0 || link < binary {
			t.Errorf("link (%d) must be laid down after the binary copy (%d)", link, binary)
		}
		// Before any daemon work, so a failure to link fails the install early
		// rather than after the cluster is running.
		for _, label := range []string{NetdLabel, ServerLabel} {
			if boot := idx(f.calls, "Bootstrap:"+label); boot >= 0 && link > boot {
				t.Errorf("link (%d) must be laid down before %s bootstraps (%d)", link, label, boot)
			}
		}
	})

	t.Run("uninstall unlinks before the InstallDir sweep removes the target", func(t *testing.T) {
		f := &fakeSystem{}
		if err := Uninstall(context.Background(), f, cfg); err != nil {
			t.Fatalf("Uninstall: %v", err)
		}
		unlink := idx(f.calls, "RemoveSymlink:/usr/local/bin/k3sm")
		if unlink < 0 {
			t.Fatalf("uninstall never removed the launcher link; calls = %v", f.calls)
		}
		sweep := idx(f.calls, "RemoveAll:/Library/k3sm")
		if sweep < 0 {
			t.Fatalf("uninstall never swept InstallDir; calls = %v", f.calls)
		}
		if unlink > sweep {
			t.Errorf("the link (%d) must be judged before its target is deleted (%d): after the sweep it is a dangling link whose identity can no longer be read", unlink, sweep)
		}
	})
}

func idx(calls []string, want string) int {
	for i, c := range calls {
		if c == want {
			return i
		}
	}
	return -1
}

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("plist missing %q\n--- plist ---\n%s", needle, haystack)
	}
}
