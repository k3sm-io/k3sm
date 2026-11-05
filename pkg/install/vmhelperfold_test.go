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
	"fmt"
	"log/slog"
	"strings"
	"syscall"
	"testing"
)

// TestTeardownKeepsAHelperWhosePathSpellsTheVersionInOtherCase pins the
// teardown's answer for a helper whose executable path spells a version in a
// case other than the versions directory's own (the default APFS volume is
// case-insensitive, so both spellings reach one directory). The helper runs
// from versions/0.3.0-RC1/ while the directory is 0.3.0-rc1, and no link
// points at it, so only the running pod keeps it in use: it is stopped, and
// nothing is reported as unretained.
func TestTeardownKeepsAHelperWhosePathSpellsTheVersionInOtherCase(t *testing.T) {
	const pid = 841
	exe := DefaultInstallDir + "/versions/0.3.0-RC1/" + VMHostName
	var logs bytes.Buffer
	f := &fakeSystem{}
	f.podLeaders = map[int]int64{pid: 1}
	f.life.vmhosts = []VMHostRecord{{Schema: 1, PodID: "fold-pod", Pgid: pid, StartUnixNano: 1}}
	f.life.procs = map[int]fakeProc{pid: {exe: exe, uid: fakeServiceUID}}
	f.purge.links = map[string]string{
		DefaultInstallDir + "/current":  "versions/0.3.0",
		DefaultInstallDir + "/previous": "versions/0.2.9",
	}
	f.owners = versionDirs("0.3.0-rc1", "0.2.9", "0.3.0")
	cfg := Config{Logger: slog.New(slog.NewTextHandler(&logs, nil))}.withDefaults()

	err := stopVMHelpers(context.Background(), f, cfg)
	if idx(f.calls, fmt.Sprintf("Signal:%d:TERM", pid)) < 0 {
		t.Errorf("the helper on the other-case spelling was not stopped: %q", f.calls)
	}
	if err != nil {
		t.Errorf("stopVMHelpers = %v, want the helper stopped without a report", err)
	}
	if strings.Contains(logs.String(), "no longer retains") {
		t.Errorf("the helper was logged as unretained:\n%s", logs.String())
	}
}

// TestTeardownCountsOnlyDirectoriesAsRetainedVersions pins the decision for
// the versions directory's listing: an entry named like a version counts as
// that version's directory only when it is a directory. A stray file or
// symlink of that name retains nothing, so a helper whose path names it is
// reported as unretained and never signalled. The other rows are the neighbours
// of that decision: no entry at all, a listed name that is not a valid version
// yet folds to the helper's, and a directory of the right spelling.
func TestTeardownCountsOnlyDirectoriesAsRetainedVersions(t *testing.T) {
	const pid = 851
	dir := DefaultInstallDir + "/versions"
	for _, tc := range []struct {
		name     string
		ver      string // the version the helper's path spells
		entry    string // the entry the listing holds, "" for none
		kind     EntryKind
		retained bool
	}{
		{name: "a directory", ver: "0.2.8", entry: "0.2.8", kind: EntryDir, retained: true},
		{name: "a regular file", ver: "0.2.8", entry: "0.2.8", kind: EntryRegular},
		{name: "a symlink", ver: "0.2.8", entry: "0.2.8", kind: EntrySymlink},
		{name: "no entry of that name", ver: "0.2.8"},
		// U+212A KELVIN SIGN folds to k, but is no part of a valid version.
		{name: "an invalid name that folds to a valid one", ver: "0.2.8-ks1", entry: "0.2.8-Ks1", kind: EntryDir},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exe := dir + "/" + tc.ver + "/" + VMHostName
			f := &fakeSystem{}
			f.podLeaders = map[int]int64{pid: 1}
			f.life.vmhosts = []VMHostRecord{{Schema: 1, PodID: "kind-pod", Pgid: pid, StartUnixNano: 1}}
			f.life.procs = map[int]fakeProc{pid: {exe: exe, uid: fakeServiceUID}}
			f.purge.links = map[string]string{
				DefaultInstallDir + "/current":  "versions/0.3.0",
				DefaultInstallDir + "/previous": "versions/0.2.9",
			}
			f.owners = versionDirs("0.2.9", "0.3.0")
			if tc.entry != "" {
				f.owners[dir+"/"+tc.entry] = OwnedEntry{Path: dir + "/" + tc.entry, Kind: tc.kind}
			}
			cfg := Config{Logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))}.withDefaults()

			err := stopVMHelpers(context.Background(), f, cfg)
			signalled := idx(f.calls, fmt.Sprintf("Signal:%d:TERM", pid)) >= 0
			if signalled != tc.retained {
				t.Errorf("helper signalled = %v, want %v: %q", signalled, tc.retained, f.calls)
			}
			if tc.retained {
				if err != nil {
					t.Errorf("stopVMHelpers = %v, want a retained helper stopped without a report", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "no longer retains") {
				t.Errorf("stopVMHelpers = %v, want the helper reported as no longer retained", err)
			}
		})
	}
}

// TestTeardownReportsEveryHelperWhenTheVersionsListingFails pins a failed
// listing across two helpers on two version paths: each leaves its version
// unknown, so neither is signalled and both are reported as unresolvable,
// never as unretained.
func TestTeardownReportsEveryHelperWhenTheVersionsListingFails(t *testing.T) {
	const a, b = 861, 862
	exeA := DefaultInstallDir + "/versions/0.2.7/" + VMHostName
	exeB := DefaultInstallDir + "/versions/0.2.8/" + VMHostName
	f := &fakeSystem{}
	f.podLeaders = map[int]int64{a: 1, b: 2}
	f.life.vmhosts = []VMHostRecord{
		{Schema: 1, PodID: "a-pod", Pgid: a, StartUnixNano: 1},
		{Schema: 1, PodID: "b-pod", Pgid: b, StartUnixNano: 2},
	}
	f.life.procs = map[int]fakeProc{a: {exe: exeA, uid: fakeServiceUID}, b: {exe: exeB, uid: fakeServiceUID}}
	f.purge.links = map[string]string{
		DefaultInstallDir + "/current":  "versions/0.3.0",
		DefaultInstallDir + "/previous": "versions/0.2.9",
	}
	f.owners = versionDirs("0.2.7", "0.2.8", "0.2.9", "0.3.0")
	f.purge.listErrs = map[string]error{DefaultInstallDir + "/versions": syscall.EACCES}
	cfg := Config{Logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))}.withDefaults()

	err := stopVMHelpers(context.Background(), f, cfg)
	for _, pid := range []int{a, b} {
		for _, sig := range []string{"TERM", "KILL"} {
			if idx(f.calls, fmt.Sprintf("Signal:%d:%s", pid, sig)) >= 0 {
				t.Errorf("helper %d of unknown retention was signalled %s: %q", pid, sig, f.calls)
			}
		}
	}
	if err == nil {
		t.Fatal("stopVMHelpers = nil, want both helpers reported")
	}
	msg := err.Error()
	for _, want := range []string{fmt.Sprintf("pid %d", a), fmt.Sprintf("pid %d", b), exeA, exeB, "cannot be resolved", "permission denied"} {
		if !strings.Contains(msg, want) {
			t.Errorf("stopVMHelpers = %q, want it to name %q", msg, want)
		}
	}
	if strings.Contains(msg, "no longer retains") {
		t.Errorf("stopVMHelpers = %q, reports an unknown retention as unretained", msg)
	}
}
