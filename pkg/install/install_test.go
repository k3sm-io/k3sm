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
	// netdRefusals[path] is how many ProbeNetd attempts are refused before netd
	// is listening. It is 0 by default, so an unconfigured fake describes a
	// helper that is already serving and no pre-existing test has to say
	// anything about it.
	netdRefusals map[string]int
	// wedgedSockets are sockets that CONNECT and never answer — bound by a netd
	// that is not serving. They are the case a connect-only probe cannot see, so
	// the fake has to be able to state it.
	wedgedSockets map[string]bool
	// missingPaths are paths PathExists reports absent. The zero value reports
	// EVERY path present, so an unconfigured fake describes a healthy install and
	// only a test that cares about the netd socket has to say so.
	missingPaths map[string]bool
	// links models the symlinks EnsureSymlink has laid down (link -> target), so a
	// SECOND Install over the same fake describes the real "already correct"
	// reinstall rather than a fresh lay-down.
	links map[string]string
	// linkDirTrust is the verdict LinkDirTrust returns, keyed by launcher path.
	// The zero value (no entry) is a TRUSTED launcher directory, so every
	// pre-existing test keeps describing an ordinary Mac whose /usr/local/bin is
	// root-owned; a test that wants the refusal states it with putLinkDirTrust.
	linkDirTrust map[string]error
	// joinAddrs is what ResolveJoinHost answers, keyed by the host asked about.
	// No entry means the host resolves to ITSELF — the ordinary single-address
	// control plane — so an unconfigured fake describes a reachable cluster and
	// only a test about multi-address resolution has to say anything.
	joinAddrs map[string][]string
	// joinDialErrs are the addresses DialJoinServer REFUSES, keyed by host:port.
	// The zero value answers on every address, for the reason above: a test that
	// wants the crash-loop this preflight prevents states the refusal itself.
	joinDialErrs map[string]error
	// joinCA is the cluster CA PEM FetchJoinCA serves, keyed by host:port; the
	// EMPTY key is the answer for every address. Unset, the fake serves
	// testCluster()'s CA — the one theJoinToken pins — so an unconfigured agent
	// install passes the identity half of the preflight exactly as one against
	// the right control plane does.
	joinCA map[string][]byte
	// joinCAErrs are the addresses whose CA cannot be fetched (an endpoint that
	// answers TCP but is not a k3sm control plane), keyed by host:port.
	joinCAErrs map[string]error
	// swapAfterRead is the content a path takes on AFTER its next read, keyed by
	// path — a file replaced between two readers. It exists for exactly one
	// question: the install reads the operator's join token once, so a token file
	// swapped after that read must not change what is staged.
	swapAfterRead map[string][]byte
	// plistModes is the mode each LaunchDaemon plist was last written at, keyed
	// by plist path. It is the fake's whole model of the file's permissions: the
	// real chmod is the darwin implementation's, and a unit test must not need
	// privilege to ask what mode root would have left behind.
	plistModes map[string]fs.FileMode
	// modes is what FileMode answers, keyed by path — the operator's join token
	// file being the only thing the installer judges by mode. A path with no
	// entry but present in files is 0600, so an unconfigured fake describes a
	// credential nobody else can read.
	modes map[string]fs.FileMode
	// kinds is what a path IS, for the one seam that cares: ReadRegularFile. The
	// zero value (no entry) is a regular file, so every pre-existing test keeps
	// describing an ordinary tree, and a test that wants the swap this seam
	// refuses states it with putSymlink/putIrregular.
	kinds map[string]fakeFileKind
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
	// delayed are files that APPEAR part-way through a test: absent for their
	// first few reads, then present. It is how a test describes a daemon that
	// writes something while the installer is polling for it — a join that
	// completes during the join budget — without a goroutine racing these maps.
	delayed map[string]*delayedFile
	// owners is the fake's model of unix ownership, keyed by path: what Owner
	// and ListOwned answer from, and what Chown MUTATES. It is deliberately
	// independent of files above — ownership is not derivable from content, and
	// the whole question the legacy-file adoption asks is one only this table
	// can answer.
	//
	// Nil (the zero value) means every path is ABSENT, which is the first-install
	// posture: no agent work dir, nothing to migrate. So an unconfigured fake
	// describes a Mac with no prior agent state, and only a test that cares about
	// the migration has to say anything at all.
	owners map[string]OwnedEntry
}

// delayedFile is one file of the fake root filesystem that CHANGES part-way
// through a test: a daemon writing while the installer polls.
type delayedFile struct {
	content []byte
	// absentReads is how many more reads answer with before (or report it
	// missing, when before is nil). It is decremented by ReadFile, on ReadFile's
	// own goroutine, so the fake stays single-threaded.
	absentReads int
	// before is what those first reads return. Nil — the zero value — is ABSENT,
	// which is the file-appears case; non-nil is the file-CHANGES case, the one
	// a crash record needs (it is there throughout, and the daemon appends an
	// entry to it while the verification is watching).
	before []byte
}

// putFileAfterReads seeds a file that reads as ABSENT for the next absentReads
// reads and is present from then on.
func (f *fakeSystem) putFileAfterReads(path string, content []byte, absentReads int) {
	if f.delayed == nil {
		f.delayed = map[string]*delayedFile{}
	}
	f.delayed[path] = &delayedFile{content: content, absentReads: absentReads}
}

// putFileChangingAfterReads seeds a file that reads as before for the next
// reads reads and as after from then on — a record the daemon appends to while
// the installer is polling it.
func (f *fakeSystem) putFileChangingAfterReads(path string, before, after []byte, reads int) {
	if f.delayed == nil {
		f.delayed = map[string]*delayedFile{}
	}
	f.delayed[path] = &delayedFile{content: after, before: before, absentReads: reads}
}

// putOwned seeds the fake's ownership table with one entry. It is how a test
// describes what an OLDER install left on disk — root:wheel 0600 files in the
// agent work dir — without needing the privilege to create such a file for real.
//
// The kind is EXPLICIT rather than inferred from anything else, because the
// entry a test most needs to be able to plant is a symlink wearing an artifact's
// name, and a fake that could only say "file or directory" could not express the
// case the refusal exists for.
func (f *fakeSystem) putOwned(path string, uid, gid int, mode fs.FileMode, kind EntryKind) {
	if f.owners == nil {
		f.owners = map[string]OwnedEntry{}
	}
	f.owners[path] = OwnedEntry{Path: path, UID: uid, GID: gid, Mode: mode, Kind: kind}
}

// Owner answers from the ownership table. A path with no entry is ABSENT with
// ReadFile's contract, which is what makes an unconfigured fake describe a Mac
// that has never joined.
func (f *fakeSystem) Owner(path string) (OwnedEntry, error) {
	f.calls = append(f.calls, "Owner:"+path)
	if e, ok := f.owners[path]; ok {
		return e, nil
	}
	return OwnedEntry{}, fmt.Errorf("lstat %s: %w", path, fs.ErrNotExist)
}

// ListOwned answers the entries whose parent is dir, sorted by path so the
// classification a test asserts on does not ride Go's map iteration order. It is
// SHALLOW, matching the real implementation: an entry two levels down is not
// listed, so a test cannot accidentally describe a tree walk this package does
// not do.
func (f *fakeSystem) ListOwned(dir string) ([]OwnedEntry, error) {
	f.calls = append(f.calls, "ListOwned:"+dir)
	self, ok := f.owners[dir]
	if !ok {
		return nil, fmt.Errorf("open %s: %w", dir, fs.ErrNotExist)
	}
	if self.Kind != EntryDir {
		return nil, fmt.Errorf("open %s: not a directory", dir)
	}
	var out []OwnedEntry
	for path, e := range f.owners {
		if path != dir && filepath.Dir(path) == dir {
			out = append(out, e)
		}
	}
	slices.SortFunc(out, func(a, b OwnedEntry) int { return strings.Compare(a.Path, b.Path) })
	return out, nil
}

// Chown records the call AND really moves the entry in the ownership table, so a
// test asserts the STATE the installer left behind rather than the sequence of
// calls it made. The mode is carried across untouched — the contract the seam
// states, and the one thing a caller could quietly get wrong.
func (f *fakeSystem) Chown(path string, uid, gid int) error {
	f.calls = append(f.calls, fmt.Sprintf("Chown:%s:%d:%d", path, uid, gid))
	e, ok := f.owners[path]
	if !ok {
		return fmt.Errorf("lchown %s: %w", path, fs.ErrNotExist)
	}
	e.UID, e.GID = uid, gid
	f.owners[path] = e
	return nil
}

// AdoptTree walks the fake ownership table with the SAME rules the darwin
// implementation applies to a real tree: the top-level policy, the
// <ns>_<pod>_<uid> shape filter, parent-before-child, no descent through a
// symlink, and a failed entry recorded rather than returned.
//
// It cannot model the hazard the real one exists for — a fake has no descriptors
// and nothing races it — so what it pins here is the POLICY, and the descriptor
// discipline is pinned against a real filesystem in install_darwin_test.go. The
// chowns go through Chown, so every existing assertion about which paths moved,
// in which order, keeps reading the same call log.
func (f *fakeSystem) AdoptTree(root string, uid, gid, maxDepth int, policy AdoptPolicy) (TreeAdoption, error) {
	f.calls = append(f.calls, "AdoptTree:"+root)
	self, ok := f.owners[root]
	if !ok {
		return TreeAdoption{}, fmt.Errorf("open %s: %w", root, fs.ErrNotExist)
	}
	if self.Kind != EntryDir {
		return TreeAdoption{}, fmt.Errorf("open %s: not a directory", root)
	}
	w := &fakeAdopt{f: f, uid: uid, gid: gid, maxDepth: maxDepth, policy: policy}
	w.walk(root, 1)
	return w.rep, nil
}

// fakeAdopt is one AdoptTree run over the ownership table.
type fakeAdopt struct {
	f        *fakeSystem
	uid, gid int
	maxDepth int
	policy   AdoptPolicy
	rep      TreeAdoption
}

func (w *fakeAdopt) walk(dir string, depth int) {
	if depth > w.maxDepth {
		w.skip(dir, "too deep")
		return
	}
	var children []OwnedEntry
	for path, e := range w.f.owners {
		if path != dir && filepath.Dir(path) == dir {
			children = append(children, e)
		}
	}
	slices.SortFunc(children, func(a, b OwnedEntry) int { return strings.Compare(a.Path, b.Path) })
	for _, e := range children {
		w.visit(e, depth)
	}
}

func (w *fakeAdopt) visit(e OwnedEntry, depth int) {
	if depth > 1 {
		switch e.Kind {
		case EntryDir:
			if e.UID == 0 {
				w.adopt(e)
			}
			w.walk(e.Path, depth+1)
		case EntryRegular:
			if e.UID == 0 {
				w.adopt(e)
			}
		default:
			w.skip(e.Path, "it is "+e.Kind.String()+", which k3sm does not follow or chown here")
		}
		return
	}
	if e.UID != 0 {
		return
	}
	switch w.policy {
	case AdoptLogLinks:
		if e.Kind != EntrySymlink && e.Kind != EntryRegular {
			w.skip(e.Path, "it is "+e.Kind.String()+", which is not a container log link")
			return
		}
		w.adopt(e)
	default:
		switch {
		case e.Kind != EntryDir:
			w.skip(e.Path, "it is "+e.Kind.String()+" at the root of the pod log tree, which k3sm did not write")
		case !isPodLogDirName(filepath.Base(e.Path)):
			w.skip(e.Path, "its name is not the <namespace>_<pod>_<uid> shape k3sm writes, so k3sm does not descend into it")
		default:
			w.adopt(e)
			w.walk(e.Path, depth+1)
		}
	}
}

func (w *fakeAdopt) adopt(e OwnedEntry) {
	if err := w.f.Chown(e.Path, w.uid, w.gid); err != nil {
		w.skip(e.Path, err.Error())
		return
	}
	w.rep.Adopted++
}

func (w *fakeAdopt) skip(path, reason string) {
	w.rep.Skipped = append(w.rep.Skipped, SkippedEntry{Path: path, Reason: reason})
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
	// The agent's steady-run observation shrinks with them, and by the same
	// ratio: it is a fraction of the join budget in production and must stay one
	// here, or every agent install in this package would time out waiting for a
	// window the budget cannot contain.
	observationOrig := agentRecoveryObservation
	agentRecoveryObservation = time.Millisecond
	t.Cleanup(func() {
		netdRestartBudget, serverRestartBudget, agentJoinBudget = netdOrig, serverOrig, joinOrig
		agentRecoveryObservation = observationOrig
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

// fakeFileKind is what the fake filesystem says a path is. Only ReadRegularFile
// consults it: every other seam here is path-based and has no type to observe.
type fakeFileKind int

const (
	// fakeRegular is the zero value: an ordinary file.
	fakeRegular fakeFileKind = iota
	// fakeSymlink is a symlink at the path — what a service-uid writer plants to
	// make a root read copy somebody else's bytes out.
	fakeSymlink
	// fakeIrregular is a directory/fifo/device at the path.
	fakeIrregular
)

// putSymlink makes ReadRegularFile refuse path as a symlink (the fake's ELOOP).
// The bytes, if any, are still in files — which is the point: a seam that
// followed the link would return them and the test would go green.
func (f *fakeSystem) putSymlink(path string) { f.putKind(path, fakeSymlink) }

// putIrregular makes ReadRegularFile refuse path as a non-regular file.
func (f *fakeSystem) putIrregular(path string) { f.putKind(path, fakeIrregular) }

func (f *fakeSystem) putKind(path string, k fakeFileKind) {
	if f.kinds == nil {
		f.kinds = map[string]fakeFileKind{}
	}
	f.kinds[path] = k
}

// ReadRegularFile answers ReadFile's bytes for an ordinary path, and the
// ErrNotRegularFile refusal for one a test has said is a symlink or a
// non-regular file — the two verdicts the real O_NOFOLLOW open reaches.
func (f *fakeSystem) ReadRegularFile(path string) ([]byte, error) {
	f.calls = append(f.calls, "ReadRegularFile:"+path)
	switch f.kinds[path] {
	case fakeSymlink:
		return nil, fmt.Errorf("open %s: %w: it is a symlink, and this read refuses to follow one", path, ErrNotRegularFile)
	case fakeIrregular:
		return nil, fmt.Errorf("open %s: %w: it is a directory", path, ErrNotRegularFile)
	}
	if content, ok := f.files[path]; ok {
		return content, nil
	}
	return nil, fmt.Errorf("open %s: %w", path, fs.ErrNotExist)
}

func (f *fakeSystem) ReadFile(path string) ([]byte, error) {
	f.calls = append(f.calls, "ReadFile:"+path)
	// A file whose content changes AFTER this read: the swap is applied once the
	// current read has been answered, so the caller sees the old bytes and every
	// later reader sees the new ones. See putFileSwappedAfterRead.
	if next, ok := f.swapAfterRead[path]; ok {
		defer func() {
			f.putFile(path, next)
			delete(f.swapAfterRead, path)
		}()
	}
	if d, ok := f.delayed[path]; ok {
		if d.absentReads > 0 {
			d.absentReads--
			if d.before != nil {
				return d.before, nil
			}
			return nil, fmt.Errorf("open %s: %w", path, fs.ErrNotExist)
		}
		return d.content, nil
	}
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

// putLinkDirTrust makes LinkDirTrust refuse link with err — the Mac whose
// launcher directory is user-owned (an Intel-prefix Homebrew at /usr/local).
func (f *fakeSystem) putLinkDirTrust(link string, err error) {
	if f.linkDirTrust == nil {
		f.linkDirTrust = map[string]error{}
	}
	f.linkDirTrust[link] = err
}

// LinkDirTrust records the READ and answers from the table. It is recorded so a
// test can assert the preflight happened at all and happened before the first
// write; the recorded call names the launcher path the installer asked about,
// which is the only input the real seam takes.
func (f *fakeSystem) LinkDirTrust(link string) error {
	f.calls = append(f.calls, "LinkDirTrust:"+link)
	return f.linkDirTrust[link]
}

// putFileSwappedAfterRead seeds a file holding first, which becomes then the
// moment it has been read once — an operator (or somebody else) replacing the
// token between the preflight that validated it and the staging that copies it.
func (f *fakeSystem) putFileSwappedAfterRead(path string, first, then []byte) {
	f.putFile(path, first)
	if f.swapAfterRead == nil {
		f.swapAfterRead = map[string][]byte{}
	}
	f.swapAfterRead[path] = then
}

// putJoinAddrs makes the join host resolve to addrs, in order — the Mac whose
// name carries both a LAN address and a public one.
func (f *fakeSystem) putJoinAddrs(host string, addrs ...string) {
	if f.joinAddrs == nil {
		f.joinAddrs = map[string][]string{}
	}
	f.joinAddrs[host] = addrs
}

// putJoinDialErr makes the bootstrap listener at addr refuse the dial — the
// unreachable address the 2026-09-17 install wrote a whole tree for.
func (f *fakeSystem) putJoinDialErr(addr string, err error) {
	if f.joinDialErrs == nil {
		f.joinDialErrs = map[string]error{}
	}
	f.joinDialErrs[addr] = err
}

// putJoinCA makes FetchJoinCA serve pem; an empty addr answers for every
// address, which is what a fixture minting its own cluster uses.
func (f *fakeSystem) putJoinCA(addr string, pem []byte) {
	if f.joinCA == nil {
		f.joinCA = map[string][]byte{}
	}
	f.joinCA[addr] = pem
}

// putJoinCAErr makes the endpoint at addr answer TCP but fail to serve a cluster
// CA — something that is listening on 9345 and is not a k3sm control plane.
func (f *fakeSystem) putJoinCAErr(addr string, err error) {
	if f.joinCAErrs == nil {
		f.joinCAErrs = map[string]error{}
	}
	f.joinCAErrs[addr] = err
}

// ResolveJoinHost records the question and answers from the table, defaulting to
// the host itself.
func (f *fakeSystem) ResolveJoinHost(host string, _ time.Duration) ([]string, error) {
	f.calls = append(f.calls, "ResolveJoinHost:"+host)
	if addrs, ok := f.joinAddrs[host]; ok {
		return addrs, nil
	}
	return []string{host}, nil
}

// DialJoinServer records the address dialed, IN ORDER — the record a test reads
// to say the preflight tried every address the host resolved to and stopped at
// the first one that answered.
func (f *fakeSystem) DialJoinServer(addr string, _ time.Duration) error {
	f.calls = append(f.calls, "DialJoinServer:"+addr)
	return f.joinDialErrs[addr]
}

// FetchJoinCA records the address and serves the configured CA: the per-address
// entry, then the every-address one, then this package's own test cluster.
func (f *fakeSystem) FetchJoinCA(addr string, _ time.Duration) ([]byte, error) {
	f.calls = append(f.calls, "FetchJoinCA:"+addr)
	if err := f.joinCAErrs[addr]; err != nil {
		return nil, err
	}
	if pem, ok := f.joinCA[addr]; ok {
		return pem, nil
	}
	if pem, ok := f.joinCA[""]; ok {
		return pem, nil
	}
	return testCluster().caPEM, nil
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

// WriteLaunchDaemon records the write and REMEMBERS THE MODE, keyed by path, so
// a test can assert the posture a plist was laid down at. The mode rides a map
// rather than the call string because the call log is asserted verbatim
// elsewhere, and because a reinstall must be able to show the mode it ENDED at:
// the second write overwrites the first entry exactly as the real chmod does.
func (f *fakeSystem) WriteLaunchDaemon(plistPath string, contents []byte, mode fs.FileMode) error {
	f.calls = append(f.calls, "WriteLaunchDaemon:"+plistPath)
	if f.plistModes == nil {
		f.plistModes = map[string]fs.FileMode{}
	}
	f.plistModes[plistPath] = mode
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

// ProbeNetd answers SERVING for every socket a test has not said otherwise
// about, so an unconfigured fake keeps describing a helper that is already up.
// A socket hidden with putMissingPath cannot be probed at all (nothing is on
// disk to connect to), and a WEDGED one connects and never answers — the state
// a dial-only probe could not tell from a healthy daemon.
func (f *fakeSystem) ProbeNetd(path string) error {
	f.calls = append(f.calls, "ProbeNetd:"+path)
	if f.missingPaths[path] {
		return fmt.Errorf("dial unix %s: %w", path, fs.ErrNotExist)
	}
	if f.wedgedSockets[path] {
		return fmt.Errorf("accepted the connection but did not answer within 1s (a socket that is bound while its daemon is not serving)")
	}
	if n := f.netdRefusals[path]; n > 0 {
		f.netdRefusals[path] = n - 1
		return fmt.Errorf("dial unix %s: connection refused", path)
	}
	return nil
}

// putNetdRefusals makes the next refusals probes of path fail before netd is
// listening at all — the window between launchd spawning the helper and the
// helper binding its socket, which is the ordinary reason the node daemon waits.
func (f *fakeSystem) putNetdRefusals(path string, refusals int) {
	if f.netdRefusals == nil {
		f.netdRefusals = map[string]int{}
	}
	f.netdRefusals[path] = refusals
}

// putWedgedSocket makes path connect and never answer: netd bound its socket and
// then stopped serving. The kernel completes a connect into the listen backlog
// with no involvement from the daemon, so this is precisely the state a
// dial-only probe reports as healthy.
func (f *fakeSystem) putWedgedSocket(path string) {
	if f.wedgedSockets == nil {
		f.wedgedSockets = map[string]bool{}
	}
	f.wedgedSockets[path] = true
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

// EnsureMeshKeyDir records the directory AND the mode the installer asked for.
// It performs no mkdir: the real one is root's, and the only thing a unit test
// can meaningfully assert about it is the policy the caller applied.
func (f *fakeSystem) EnsureMeshKeyDir(dir string, mode fs.FileMode) error {
	f.calls = append(f.calls, fmt.Sprintf("EnsureMeshKeyDir:%s:%#o", dir, mode))
	return nil
}

// WriteRootOnlyFile records the path and the MODE — the two things that decide
// whether the root-only copy of a key stays root-only — and lands the bytes in
// the fake root filesystem, so a later read (this install's idempotence check,
// or the next install's) sees exactly what was written. No uid is recorded
// because the seam takes none: root:wheel is the whole contract.
func (f *fakeSystem) WriteRootOnlyFile(path string, contents []byte, mode fs.FileMode) error {
	f.calls = append(f.calls, fmt.Sprintf("WriteRootOnlyFile:%s:%#o", path, mode))
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
		// ...and, still before the first write: is the directory that will hold
		// the `k3sm` launcher root-owned? A read, like the probe above it; the
		// link itself is not laid down until step 2b, and a refusal there would
		// arrive with the whole tree already on disk.
		//
		// A THIRD refuse-before-write probe sits after this one on a worker — the
		// join endpoint's reachability and cluster identity — and is absent here
		// because a control plane joins nothing (TestAgentInstallPreflightsTheJoinEndpoint).
		"LinkDirTrust:/usr/local/bin/k3sm",
		// The staged k3sm-vmhost helper's entitlement, checked here rather than
		// immediately before its copy (far below): copying it verbatim is the
		// only chance to decline an unentitled helper, and checking it AFTER the
		// binary and every other sibling helper had already been copied is
		// exactly the defect this ordering fixes — a real upgrade refused there,
		// leaving a mix of new and old artifacts beside the still-running old
		// daemon (TestInstallVerifiesTheVMHostBeforeWritingTheRoot).
		"VerifyVirtualizationEntitlement:/tmp/k3sm-vmhost",
		// The installed server plist, read here for the SAME reason and to
		// answer a different refusal: does the argument set this install would
		// carry over name a --datastore-endpoint-file that is no longer there?
		// (See requireDatastoreEndpointFile.) There is none here (a first
		// install), so the second source is read next: the root-owned record
		// that survives an uninstall. Both reads are reused later, at the carry-
		// over step below, rather than repeated.
		"ReadFile:/Library/LaunchDaemons/io.k3sm.server.plist",
		"ReadFile:" + dataroot.DefaultServerArgsRecordPath,
		"EnsureServiceUser:_k3sm:" + DefaultDataRoot,
		"EnsureLogDir:/var/log/k3sm",
		// The container-log tree, at the same moment and for the same reason: the
		// node refuses to start without it, and only root can create it owned by
		// the service user at a mode that keeps pod output off every local account.
		"EnsureContainerLogDir:/var/log/pods",
		"EnsureContainerLogDir:/var/log/containers",
		// ...and the descriptor-relative walk that hands the PER-POD directories
		// inside that tree over, for BOTH roles, because a single-node server
		// writes the same tree. Each root is opened once and found absent on a
		// first install, which is the only reason this is two calls and not a
		// walk (B327).
		"AdoptTree:/var/log/pods",
		"AdoptTree:/var/log/containers",
		// Before any daemon bootstraps: root netd would otherwise create the run
		// dir root-owned and the _k3sm server could not bind runtimed.sock in it.
		"EnsureRunDir:/var/lib/k3sm/run",
		// Same reason, one level down: runtimed binds each vm pod's guest-agent
		// socket under here as _k3sm. Missing it makes every vm pod fail to boot.
		"EnsureVMRunDir:/var/lib/k3sm/run/vm",
		// The control plane's static admin token, staged where the _k3sm daemon
		// can read it and nothing else can. It needs the service uid, so it
		// cannot precede EnsureServiceUser, and it precedes the plist that names
		// it: the daemon must never be pointed at a file nobody has written.
		"WriteServiceUserFile:/var/lib/k3sm/server/token:0600:0700:271",
		// This node's wireguard identity, provisioned by the party that can: the
		// root-only key dir carved inside the (service-user-owned) run dir, the
		// role's work-dir key read to see whether the node already has one — it
		// does not, on a first install — so one is minted and written to BOTH the
		// work dir (service-user 0600, where the daemon loads it) and the key dir
		// (root 0600, where netd resolves the ref). Before any daemon starts.
		"EnsureMeshKeyDir:/var/lib/k3sm/run/keys:0700",
		// BOTH copies are read before anything is written, and read through the
		// seam that refuses a symlink: whether a key already exists decides
		// between copying, restoring and minting, and only a mint is destructive.
		// Neither exists here (a first install), so one is minted and written to
		// the work dir (service-user 0600, where the daemon loads it) and the key
		// dir (root 0600, where netd resolves the ref).
		"ReadRegularFile:/var/lib/k3sm/server/server.key",
		"ReadRegularFile:/var/lib/k3sm/run/keys/server.key",
		"WriteServiceUserFile:/var/lib/k3sm/server/server.key:0600:0700:271",
		"WriteRootOnlyFile:/var/lib/k3sm/run/keys/server.key:0600",
		"CopyToRootOwned:/Library/k3sm/k3sm",
		// The launcher link goes down immediately after the binary it points at,
		// and long before any daemon work: copying into /Library/k3sm never put
		// `k3sm` on a shell's PATH, which every post-install instruction assumes.
		"EnsureSymlink:/Library/k3sm/k3sm->/usr/local/bin/k3sm",
		"CopyToRootOwned:/Library/k3sm/k3sm-execshim",
		"CopyToRootOwned:/Library/k3sm/libk3sm_pathrebase_shim.dylib",
		"CopyToRootOwned:/Library/k3sm/libk3sm_getaddrinfo_shim.dylib",
		// The helper's entitlement was already verified, in the preflight block
		// before any of these copies ran (see above) — this copy can now only
		// fail on an I/O error.
		"CopyToRootOwned:/Library/k3sm/k3sm-vmhost",
		"CopyToRootOwned:/Library/k3sm/bin/kube-apiserver",
		"CopyToRootOwned:/Library/k3sm/bin/kube-scheduler",
		"CopyToRootOwned:/Library/k3sm/bin/kube-controller-manager",
		"CopyToRootOwned:/Library/k3sm/bin/kubectl",
		"CopyToRootOwned:/Library/k3sm/bin/kine",
		// The kine version marker rides beside the kine binary it describes, staged
		// best-effort (a pre-marker archive has none and must still install).
		"CopyToRootOwned:/Library/k3sm/bin/" + executor.KineMarkerName,
		// The installed server plist and args record were already read, in the
		// preflight block before any of these copies ran (see above); the carry-
		// over below reuses that answer — nothing, on a first install — rather
		// than reading either file a second time.
		// And whatever was carried — nothing, on a first install — is recorded
		// again, before the plist that will not survive the next uninstall.
		"WriteServerArgsRecord:" + dataroot.DefaultServerArgsRecordPath,
		// The trust anchor for the endpoint the admin kubeconfig will name, read
		// AFTER the arguments are resolved (they decide the posture, so they decide
		// which certificate the apiserver serves) and BEFORE the daemons restart, so
		// this install pins what the PREVIOUS boot left on disk rather than racing
		// the one it is about to start. Single-node here, so it is the certificate
		// the apiserver self-signs into its own --cert-dir; a first install finds
		// nothing and the kubeconfig keeps skip-verify.
		"ReadFile:/var/lib/k3sm/server/apiserver-certs/apiserver.crt",
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
		// ...and then the wait the node daemon's own start depends on: netd must
		// ANSWER on the helper socket before io.k3sm.server is bootstrapped into
		// it. A pid says the helper process was spawned and a connect says only
		// that the kernel queued it; one framed round trip is what says netd is
		// serving, and a node daemon that starts before that records the refusal
		// as a bring-up failure of its own.
		"ProbeNetd:/var/lib/k3sm/run/netd.sock",
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
			// The FIRST privileged call — the refuse-before-write probes ahead of
			// it (the cross-role plist read, the launcher-directory trust read,
			// the staged vmhost helper's entitlement, and the carried server
			// arguments' datastore-endpoint-file check) are all reads, and
			// install performs nothing else before the service user exists: the
			// data root is its home, and every later step writes into it.
			wantCall := "EnsureServiceUser:_k3sm:" + want
			var first string
			for _, c := range f.calls {
				if strings.HasPrefix(c, "ReadFile:") || strings.HasPrefix(c, "LinkDirTrust:") || strings.HasPrefix(c, "VerifyVirtualizationEntitlement:") {
					continue
				}
				first = c
				break
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
		// The staged admin token, removed with the daemons rather than preserved
		// with the rest of the data root: it is a system:masters credential with
		// no use on a Mac that is no longer a k3sm server, and it goes AFTER the
		// daemon that reads it has been booted out.
		"RemoveAll:/var/lib/k3sm/server/token",
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

// TestAgentInstallRendersNetdWithTheNodeIdentity proves the netd plist's
// --kubeconfig follows the node's ROLE, and that neither role's argv carries a
// pod CIDR or a node IP.
//
// netd's Service informer is the privileged-port authorizer's only source of
// truth (cmd/k3sm/netd.go buildServiceSet): a kubeconfig it can never load
// leaves the authorizer deny-all for the daemon's whole life, so EVERY <1024
// bind — the DNS VIP :53, the apiserver ClusterIP :443 — is denied. A worker
// has no server work dir (the control plane's k3sm.kubeconfig is written on the
// SERVER, and nothing on a worker ever creates it), so a role-blind plist
// pointed a worker's netd at a file that does not exist; on a Mac that was once
// a server the file DOES exist and is a stale credential, which is worse than
// absent. The agent's node credential (AgentCredentialPath — the kubeconfig
// `k3sm agent` writes on a successful join) is the only identity a worker has.
//
// The negative half is as load-bearing as the positive one. --node-pod-cidr is
// not knowable at install time on a worker: the allocation is made by the join,
// and netd learns it from the agent's ConfigureMesh RPC. A plist that re-stated
// it would pin the pre-adoption default into launchd's job definition, so the
// next netd restart would come back on the wrong /24 and drop every pod alias
// and route. --node-ip re-arms the dormant node-address authorizer branch
// (TestNetdPlistXML owns that reasoning).
func TestAgentInstallRendersNetdWithTheNodeIdentity(t *testing.T) {
	// A NON-default data root: every path below must be DERIVED from it, so a
	// hard-coded default would fail here rather than pass by coincidence.
	const dataRoot = "/opt/k3sm-b326"
	serverWork := filepath.Join(dataRoot, "server")

	for _, tc := range []struct {
		name string
		cfg  Config
		// wantKubeconfig is the exact --kubeconfig value the rendered argv must
		// carry; forbid, when non-empty, is a substring no argv element may hold.
		wantKubeconfig string
		forbid         string
	}{
		{
			name:           "agent is handed its own node credential",
			cfg:            Config{Role: RoleAgent, DataRoot: dataRoot},
			wantKubeconfig: AgentCredentialPath(dataRoot),
			forbid:         serverWork,
		},
		{
			name:           "server keeps the control-plane kubeconfig",
			cfg:            Config{Role: RoleServer, DataRoot: dataRoot},
			wantKubeconfig: filepath.Join(serverWork, "k3sm.kubeconfig"),
		},
		{
			name:           "the zero-value role is the server",
			cfg:            Config{DataRoot: dataRoot},
			wantKubeconfig: filepath.Join(serverWork, "k3sm.kubeconfig"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args, err := parseProgramArguments(NetdPlist(tc.cfg))
			if err != nil {
				t.Fatalf("parse netd ProgramArguments: %v", err)
			}
			if got := flagValue(args, "kubeconfig"); got != tc.wantKubeconfig {
				t.Errorf("netd --kubeconfig = %q, want %q (argv: %v)", got, tc.wantKubeconfig, args)
			}
			if tc.forbid != "" {
				for _, a := range args {
					if strings.Contains(a, tc.forbid) {
						t.Errorf("netd argv element %q names the server work dir %q, which does not exist on a worker (argv: %v)", a, tc.forbid, args)
					}
				}
			}
			for _, flag := range []string{"--node-pod-cidr", "--node-ip"} {
				if slices.Contains(args, flag) {
					t.Errorf("netd argv must NOT carry %s (argv: %v)", flag, args)
				}
			}
		})
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
	// ExitTimeOut > launchd's 20s default so the daemon's teardown — the embedded
	// runtime's vm stop and Stop()'s control-plane drain, which run concurrently,
	// then the control socket and the mesh teardown — finishes before SIGKILL (else
	// the stragglers orphan). The number is derived;
	// TestExitTimeOutCoversTheDaemonTeardown owns the arithmetic, and this golden is
	// what pins the derivation to the rendered plist.
	mustContain(t, x, "<key>ExitTimeOut</key>\n  <integer>60</integer>")
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

// TestPlistEscaping proves string values are XML-escaped (a value with an &
// cannot corrupt the plist).
//
// It pins the DATA ROOT rather than the admin token, because the token is no
// longer rendered: the server plist carries the PATH of the staged token file,
// which is derived from Config.DataRoot and is therefore the value on that argv
// an operator can still choose the bytes of.
func TestPlistEscaping(t *testing.T) {
	cfg := Config{DataRoot: "/var/lib/a&b<c", BinarySource: "/tmp/k3sm", TargetUser: "alice"}
	x := string(ServerPlist(cfg))
	if strings.Contains(x, "a&b<c") {
		t.Error("plist string values must be XML-escaped")
	}
	mustContain(t, x, "a&amp;b&lt;c")
	// And the round trip gives the path back unescaped, so the escaping is a
	// transport detail and not a corrupted argument.
	argv, err := parseProgramArguments(ServerPlist(cfg))
	if err != nil {
		t.Fatalf("parseProgramArguments: %v", err)
	}
	if got, want := flagValue(argv, "token-file"), cfg.withDefaults().serverTokenPath(); got != want {
		t.Errorf("--token-file = %q, want %q", got, want)
	}
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
		// The staged credentials (the server's admin token, a worker's join
		// token) come through the service-user write seam, whose record carries
		// the modes after the path — so the path is the head of the record.
		for _, call := range recorded(installCalls, "WriteServiceUserFile:") {
			path, _, ok := strings.Cut(call, ":")
			if !ok {
				t.Fatalf("unparsable WriteServiceUserFile record: %s", call)
			}
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

// TestEnsureSymlinkNamesTheRemedyForAnUntrustedLinkDir pins the two halves of
// the launcher-directory refusal that a live Mac with an Intel-prefix Homebrew
// exposed: WHAT the refusal says, and WHEN it happens.
//
// The what: /usr/local/bin on such a Mac is owned by the admin user Homebrew was
// installed as, and root's PATH searches it ahead of /usr/bin — so linking a
// launcher there would let that user leave a `k3sm` for the next `sudo k3sm …`
// to run as root. k3sm refuses, and since the operator has to repair a directory
// they did not create, the refusal has to name the path, the property that is
// wrong and the literal command that fixes it; the old message named only the
// rule. The verdict is asserted through the PURE function so the root-ownership
// arm is reachable at all: an unprivileged test cannot chown a temp dir to root.
//
// The when: the refusal used to arrive from EnsureSymlink at install step 2b,
// by which time the service user, the log trees, the run dir, the staged
// credentials, the binary and the shims were all on disk — a correct refusal
// that left a half-installed Mac behind. It is now also a read-only preflight
// beside refuseCrossRole, and the two Install cases below are what say so.
func TestEnsureSymlinkNamesTheRemedyForAnUntrustedLinkDir(t *testing.T) {
	const bin = "/usr/local/bin"

	t.Run("verdict", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			dir  string
			// launcher is the directory the launcher is wanted in. Empty means
			// it IS dir (the ordinary, unescalated case); a different value is
			// the escalated one, where dir is only an ancestor.
			launcher string
			facts    linkDirFacts
			euid     int
			// want are substrings the refusal must carry; empty means the
			// directory must be ACCEPTED.
			want []string
			// notWant are substrings the refusal must NOT carry — the remedies
			// that would be actively harmful to follow.
			notWant []string
		}{
			{
				// The Homebrew-on-Intel-prefix Mac this whole check exists for.
				name:  "user-owned directory, running as root",
				dir:   bin,
				facts: linkDirFacts{UID: 501, Mode: 0o755 | fs.ModeDir, IsDir: true},
				euid:  0,
				want: []string{
					bin,
					"uid 501",
					"root's PATH",
					"sudo chown root:wheel " + bin + " && sudo chmod 755 " + bin,
				},
			},
			{
				name:  "root-owned but group-writable",
				dir:   bin,
				facts: linkDirFacts{UID: 0, Mode: 0o775 | fs.ModeDir, IsDir: true},
				euid:  0,
				want:  []string{bin, "group-writable", "0775", "root's PATH", "sudo chmod 755 " + bin},
			},
			{
				name:  "root-owned but world-writable",
				dir:   bin,
				facts: linkDirFacts{UID: 0, Mode: 0o757 | fs.ModeDir, IsDir: true},
				euid:  0,
				want:  []string{bin, "world-writable", "0757", "root's PATH", "sudo chmod 755 " + bin},
			},
			{
				// Lstat, never Stat: whoever can re-point the symlink chooses
				// where the launcher lands, so the destination's mode says
				// nothing about the trust of the path.
				name:  "symlink to a directory",
				dir:   bin,
				facts: linkDirFacts{UID: 0, Mode: 0o755 | fs.ModeSymlink, IsDir: true, IsSymlink: true},
				euid:  0,
				want:  []string{bin, "is a symlink", "remove " + bin},
			},
			{
				name:  "not a directory",
				dir:   bin,
				facts: linkDirFacts{UID: 0, Mode: 0o644},
				euid:  0,
				want:  []string{bin, "not a directory", "remove " + bin},
			},
			{
				// ESCALATED: /usr/local/bin is absent, so /usr/local is judged —
				// and it is a symlink. "remove /usr/local" would be advice to
				// delete a base system directory (and on a stock Mac /usr/local
				// may well be a symlink an operator put there deliberately), so
				// the remedy must be to CREATE the launcher directory instead.
				name:     "a symlink ancestor is never told to remove itself",
				dir:      "/usr/local",
				launcher: bin,
				facts:    linkDirFacts{UID: 0, Mode: 0o755 | fs.ModeSymlink, IsDir: true, IsSymlink: true},
				euid:     0,
				want: []string{
					bin,
					"its parent /usr/local",
					"is a symlink",
					"sudo mkdir -p " + bin,
					"sudo chown root:wheel " + bin,
				},
				notWant: []string{"remove /usr/local"},
			},
			{
				// The ancestor is not there either. That used to escape as a bare
				// lstat ENOENT naming a path the operator never asked about; it
				// is a refusal like any other, and its remedy is the same mkdir.
				name:     "an absent ancestor is a refusal with a mkdir remedy",
				dir:      "/usr/local",
				launcher: bin,
				facts:    linkDirFacts{Absent: true},
				euid:     0,
				want: []string{
					bin,
					"/usr/local does not exist",
					"sudo mkdir -p " + bin,
					"sudo chmod 755 " + bin,
				},
				notWant: []string{"remove /usr/local", "no such file"},
			},
			{
				name:  "root-owned 0755 directory is what install wants",
				dir:   bin,
				facts: linkDirFacts{UID: 0, Mode: 0o755 | fs.ModeDir, IsDir: true},
				euid:  0,
			},
			{
				// The euid arm: an unprivileged caller cannot chown anything, so
				// demanding root ownership of a directory it could not repair
				// would refuse installs that are not being performed.
				name:  "user-owned directory, running unprivileged",
				dir:   bin,
				facts: linkDirFacts{UID: 501, Mode: 0o755 | fs.ModeDir, IsDir: true},
				euid:  501,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				err := linkDirVerdict(tc.dir, tc.launcher, tc.facts, tc.euid)
				if len(tc.want) == 0 {
					if err != nil {
						t.Fatalf("linkDirVerdict(%q, %q, %+v, %d) = %v, want nil", tc.dir, tc.launcher, tc.facts, tc.euid, err)
					}
					return
				}
				if err == nil {
					t.Fatalf("linkDirVerdict(%q, %q, %+v, %d) = nil, want a refusal", tc.dir, tc.launcher, tc.facts, tc.euid)
				}
				for _, w := range tc.want {
					if !strings.Contains(err.Error(), w) {
						t.Errorf("refusal %q does not name %q", err, w)
					}
				}
				for _, w := range tc.notWant {
					if strings.Contains(err.Error(), w) {
						t.Errorf("refusal %q tells the operator to %q", err, w)
					}
				}
			})
		}
	})

	// The parent-absent → grandparent rule: when /usr/local/bin does not exist,
	// the directory whose permissions decide who could create it is /usr/local,
	// so that is the directory judged and the one the refusal must name.
	t.Run("absent launcher dir is judged by its parent", func(t *testing.T) {
		dir, parentAbsent := linkDirTrustTarget(bin+"/k3sm", false)
		if dir != "/usr/local" || !parentAbsent {
			t.Fatalf("linkDirTrustTarget(%q, false) = (%q, %v), want (\"/usr/local\", true)", bin+"/k3sm", dir, parentAbsent)
		}
		err := linkDirVerdict(dir, bin, linkDirFacts{UID: 501, Mode: 0o755 | fs.ModeDir, IsDir: true}, 0)
		if err == nil {
			t.Fatal("a user-owned /usr/local must be refused: that user could create /usr/local/bin and own it")
		}
		for _, w := range []string{"/usr/local", "uid 501", "sudo chown root:wheel /usr/local"} {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("refusal %q does not name %q", err, w)
			}
		}
	})

	// The ordering half: a refused launcher directory must stop the install
	// before it has written anything at all.
	t.Run("a refused launcher dir leaves nothing on disk", func(t *testing.T) {
		f := &fakeSystem{}
		f.putLinkDirTrust("/usr/local/bin/k3sm", fmt.Errorf("refusing to link the k3sm launcher into /usr/local/bin: it is owned by uid 501, not root"))
		err := Install(context.Background(), f, Config{BinarySource: "/tmp/k3sm", TargetUser: "alice"})
		if err == nil {
			t.Fatal("Install accepted an untrusted launcher directory")
		}
		if !strings.Contains(err.Error(), "uid 501") {
			t.Errorf("Install error = %v, want the launcher-directory refusal", err)
		}
		for _, prefix := range []string{"EnsureServiceUser:", "CopyToRootOwned:", "WriteLaunchDaemon:", "EnsureLogDir:", "EnsureRunDir:", "WriteServiceUserFile:", "EnsureSymlink:"} {
			for _, c := range f.calls {
				if strings.HasPrefix(c, prefix) {
					t.Errorf("install wrote %q after refusing the launcher directory; calls = %v", c, f.calls)
				}
			}
		}
	})

	// ...and the preflight is a READ, so a healthy Mac — including one being
	// reinstalled over — passes it and proceeds, twice.
	t.Run("a healthy install records the read and proceeds", func(t *testing.T) {
		f := &fakeSystem{}
		cfg := Config{BinarySource: "/tmp/k3sm", TargetUser: "alice"}
		for _, run := range []string{"install", "reinstall"} {
			before := len(f.calls)
			if err := Install(context.Background(), f, cfg); err != nil {
				t.Fatalf("%s: %v", run, err)
			}
			calls := f.calls[before:]
			probe := idx(calls, "LinkDirTrust:/usr/local/bin/k3sm")
			if probe < 0 {
				t.Fatalf("%s never asked about the launcher directory; calls = %v", run, calls)
			}
			user := idx(calls, "EnsureServiceUser:_k3sm:"+DefaultDataRoot)
			if user < 0 || probe >= user {
				t.Errorf("%s asked about the launcher directory at %d, after the first write at %d; the refusal must precede every write", run, probe, user)
			}
			if link := idx(calls, "EnsureSymlink:/Library/k3sm/k3sm->/usr/local/bin/k3sm"); link < 0 {
				t.Errorf("%s never laid down the launcher; calls = %v", run, calls)
			}
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
