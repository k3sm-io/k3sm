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

// TestVerifyVMHelperFollowsVersionedLayout pins the vm helper's peer identity
// check across the install layouts: the helper is this install's k3sm-vmhost
// whether its recorded executable is the flat path of today's layout, the same
// name through current, the name inside the version directory current or
// previous points at (where the runtime's symlink-resolved lookup lands, and
// where a helper started before a flip keeps running), the name inside a
// version directory the helper's own running pod keeps in use (the layout's
// retention rule), or the flat path with its symlinks resolved. A path outside
// versions/, a version directory that is gone, a version path with no current
// link at all, a deeper or partial version path, or any other basename is
// refused with an error and never signalled.
func TestVerifyVMHelperFollowsVersionedLayout(t *testing.T) {
	const pgid = 801
	flat := DefaultInstallDir + "/" + VMHostName
	current := DefaultInstallDir + "/current"
	previous := DefaultInstallDir + "/previous"
	// The versioned tree: current is 0.3.0, previous (the rollback, and the
	// version a pod started before the last flip runs from) is 0.2.9.
	retained := map[string]string{current: "versions/0.3.0", previous: "versions/0.2.9"}
	for _, tc := range []struct {
		name     string
		exe      string
		uid      uint32
		resolved map[string]string
		gone     map[string]bool
		links    map[string]string
		want     bool
	}{
		{name: "flat layout path", exe: flat, uid: fakeServiceUID, want: true},
		{name: "flat path uncleaned", exe: DefaultInstallDir + "//" + VMHostName, uid: fakeServiceUID, want: true},
		{name: "through current", exe: DefaultInstallDir + "/current/" + VMHostName, uid: fakeServiceUID, want: true},
		{name: "flat layout path, no current link", exe: flat, uid: fakeServiceUID, links: map[string]string{}, want: true},
		{name: "under versions, the active version", exe: DefaultInstallDir + "/versions/0.3.0/" + VMHostName, uid: fakeServiceUID, links: retained, want: true},
		{name: "under versions, the retained previous version", exe: DefaultInstallDir + "/versions/0.2.9/" + VMHostName, uid: fakeServiceUID, links: retained, want: true},
		{
			name:  "under versions, a migrated unknown version that is current",
			exe:   DefaultInstallDir + "/versions/unknown-0123456789ab/" + VMHostName,
			uid:   fakeServiceUID,
			links: map[string]string{current: "versions/unknown-0123456789ab"},
			want:  true,
		},
		{
			name:  "under versions, a version no link retains that the running helper keeps in use",
			exe:   DefaultInstallDir + "/versions/0.2.8/" + VMHostName,
			uid:   fakeServiceUID,
			links: retained,
			want:  true,
		},
		{
			name:  "under versions, a version no link retains whose directory is gone",
			exe:   DefaultInstallDir + "/versions/0.2.8/" + VMHostName,
			uid:   fakeServiceUID,
			links: retained,
			gone:  map[string]bool{DefaultInstallDir + "/versions/0.2.8": true},
		},
		{name: "under versions, no current link (the flat layout)", exe: DefaultInstallDir + "/versions/0.3.0/" + VMHostName, uid: fakeServiceUID},
		{
			name:  "under versions, current points somewhere not a version directory",
			exe:   DefaultInstallDir + "/versions/0.3.0/" + VMHostName,
			uid:   fakeServiceUID,
			links: map[string]string{current: "/Library/k3sm/versions/0.3.0"},
		},
		{
			name:     "the flat path resolved elsewhere",
			exe:      "/private/k3sm-root/" + VMHostName,
			uid:      fakeServiceUID,
			resolved: map[string]string{flat: "/private/k3sm-root/" + VMHostName},
			want:     true,
		},
		{name: "outside versions", exe: "/tmp/" + VMHostName, uid: fakeServiceUID},
		{name: "a sibling of versions", exe: DefaultInstallDir + "/updater-work/" + VMHostName, uid: fakeServiceUID},
		{name: "a staged partial version", exe: DefaultInstallDir + "/versions/0.3.0.partial/" + VMHostName, uid: fakeServiceUID},
		{name: "deeper than a version directory", exe: DefaultInstallDir + "/versions/0.3.0/bin/" + VMHostName, uid: fakeServiceUID},
		{name: "a dot-dot escape", exe: DefaultInstallDir + "/versions/../../tmp/" + VMHostName, uid: fakeServiceUID},
		{name: "wrong name under versions", exe: DefaultInstallDir + "/versions/0.3.0/k3sm", uid: fakeServiceUID},
		{name: "wrong name through current", exe: DefaultInstallDir + "/current/k3sm-execshim", uid: fakeServiceUID},
		{name: "wrong name flat", exe: DefaultInstallDir + "/k3sm", uid: fakeServiceUID},
		{name: "relative path", exe: "versions/0.3.0/" + VMHostName, uid: fakeServiceUID},
		{
			name:     "resolved to a different basename",
			exe:      "/private/k3sm-root/other",
			uid:      fakeServiceUID,
			resolved: map[string]string{flat: "/private/k3sm-root/other"},
		},
		{name: "right path, wrong uid", exe: DefaultInstallDir + "/versions/0.3.0/" + VMHostName, uid: 0, links: retained},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			f := &fakeSystem{}
			f.podLeaders = map[int]int64{pgid: 7}
			f.life.procs = map[int]fakeProc{pgid: {exe: tc.exe, uid: tc.uid}}
			f.purge.resolved = tc.resolved
			f.purge.gone = tc.gone
			f.purge.links = tc.links
			f.owners = versionDirs("0.2.8", "0.2.9", "0.3.0")
			cfg := Config{Logger: slog.New(slog.NewTextHandler(&logs, nil))}.withDefaults()
			ok, err := verifyVMHelper(f, cfg, VMHostRecord{PodID: "p", Pgid: pgid, StartUnixNano: 7}, fakeServiceUID)
			if ok != tc.want {
				t.Fatalf("verifyVMHelper(%q, uid %d) = %v (%v), want %v", tc.exe, tc.uid, ok, err, tc.want)
			}
			if tc.want && err != nil {
				t.Errorf("an accepted helper reported %v", err)
			}
			if !tc.want && (err == nil || !strings.Contains(err.Error(), "not signalled")) {
				t.Errorf("a refused helper reported %v, want the forged record named", err)
			}
		})
	}
}

// TestTeardownReportsAnUnretainedVMHelper pins the teardown's answer to a
// helper running from a version directory that is neither current nor
// previous, by the layout's retention rule (current, previous, staged, in use
// by a running pod):
//
//   - a helper whose version directory is still there is that version's
//     running pod, so the tree keeps the version in use and the helper is
//     stopped like any other, never reported as a leftover;
//   - a helper whose version directory is gone runs from a version the tree no
//     longer retains: it is never signalled, because nothing but its path
//     vouches for it, and the teardown names it as the leftover it is, by pid,
//     executable path and version, with the command that stops it, in the
//     error and in the Warn record, instead of reporting it as a forged record;
//   - a process on such a path that does not run as the service user is still
//     a forged record, reported as one.
//
// A helper of the active version beside each is always stopped.
func TestTeardownReportsAnUnretainedVMHelper(t *testing.T) {
	const (
		stale = 811 // runs from 0.2.8, which no link points at
		live  = 812 // runs from 0.3.0, the active version
	)
	staleExe := DefaultInstallDir + "/versions/0.2.8/" + VMHostName
	gone := map[string]bool{DefaultInstallDir + "/versions/0.2.8": true}
	for _, tc := range []struct {
		name string
		uid  uint32
		gone map[string]bool
		// stopped: the 0.2.8 helper is SIGTERMed and nothing is reported.
		stopped bool
		// leftover: it is reported as an unretained leftover; otherwise, when
		// not stopped, as a forged record.
		leftover bool
	}{
		{name: "a helper on a version its running pod keeps in use", uid: fakeServiceUID, stopped: true},
		{name: "a helper on a version whose directory is gone", uid: fakeServiceUID, gone: gone, leftover: true},
		{name: "a non-service uid on an unretained path", uid: 0, gone: gone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			f := &fakeSystem{}
			f.podLeaders = map[int]int64{stale: 1, live: 2}
			f.life.vmhosts = []VMHostRecord{
				{Schema: 1, PodID: "stale-pod", Pgid: stale, StartUnixNano: 1},
				{Schema: 1, PodID: "live-pod", Pgid: live, StartUnixNano: 2},
			}
			f.life.procs = map[int]fakeProc{
				stale: {exe: staleExe, uid: tc.uid},
				live:  {exe: DefaultInstallDir + "/versions/0.3.0/" + VMHostName, uid: fakeServiceUID},
			}
			f.purge.links = map[string]string{
				DefaultInstallDir + "/current":  "versions/0.3.0",
				DefaultInstallDir + "/previous": "versions/0.2.9",
			}
			f.purge.gone = tc.gone
			f.owners = versionDirs("0.2.8", "0.2.9", "0.3.0")
			cfg := Config{Logger: slog.New(slog.NewTextHandler(&logs, nil))}.withDefaults()

			err := stopVMHelpers(context.Background(), f, cfg)
			if idx(f.calls, fmt.Sprintf("Signal:%d:TERM", live)) < 0 {
				t.Errorf("the active version's helper beside it was not stopped: %q", f.calls)
			}
			signalled := idx(f.calls, fmt.Sprintf("Signal:%d:TERM", stale)) >= 0
			if signalled != tc.stopped {
				t.Errorf("the 0.2.8 helper signalled = %v, want %v: %q", signalled, tc.stopped, f.calls)
			}
			const warnMsg = "a vm helper runs from a version this install no longer retains"
			if tc.stopped {
				if err != nil {
					t.Errorf("stopVMHelpers = %v, want a helper of an in-use version stopped without a report", err)
				}
				if strings.Contains(logs.String(), warnMsg) {
					t.Errorf("a helper of an in-use version was logged as unretained:\n%s", logs.String())
				}
				return
			}
			if err == nil {
				t.Fatal("stopVMHelpers = nil, want the 0.2.8 helper reported")
			}
			msg := err.Error()
			forged := "not " + cfg.installedVMHost()
			if !tc.leftover {
				if !strings.Contains(msg, forged) || strings.Contains(msg, "no longer retains") {
					t.Errorf("stopVMHelpers = %q, want the forged-record error and no leftover report", msg)
				}
				if strings.Contains(logs.String(), warnMsg) {
					t.Errorf("a forged record was logged as an unretained helper:\n%s", logs.String())
				}
				return
			}
			for _, want := range []string{
				fmt.Sprintf("pid %d", stale),
				staleExe,
				"version 0.2.8",
				"no longer retains",
				fmt.Sprintf("kill -TERM -%d", stale),
			} {
				if !strings.Contains(msg, want) {
					t.Errorf("stopVMHelpers = %q, want it to name %q", msg, want)
				}
			}
			if strings.Contains(msg, forged) {
				t.Errorf("stopVMHelpers = %q, reports the unretained helper as a forged record", msg)
			}
			var warn string
			for _, line := range strings.Split(logs.String(), "\n") {
				if strings.Contains(line, warnMsg) {
					warn = line
				}
			}
			for _, field := range []string{
				"level=WARN",
				"pod=stale-pod",
				fmt.Sprintf("pid=%d", stale),
				"exe=" + staleExe,
				"version=0.2.8",
			} {
				if !strings.Contains(warn, field) {
					t.Errorf("the unretained helper's Warn record %q lacks %q", warn, field)
				}
			}
		})
	}
}

// TestTeardownTreatsResolveErrorsAsUnknownNotUnretained pins the teardown's
// answer when the version directory a helper runs from cannot be resolved for
// a reason other than its being gone (EACCES here; EIO alike): whether the
// tree retains that version is unknown, so the helper is never signalled, and
// it is reported by pid, path and version as a path that cannot be resolved,
// never as a helper this install no longer retains and never as a forged
// record. A helper of the active version beside it is still stopped.
func TestTeardownTreatsResolveErrorsAsUnknownNotUnretained(t *testing.T) {
	const (
		stale = 821 // runs from 0.2.8, whose directory cannot be read
		live  = 822 // runs from 0.3.0, the active version
	)
	staleExe := DefaultInstallDir + "/versions/0.2.8/" + VMHostName
	for _, tc := range []struct {
		name string
		dir  string // the path ResolvePath refuses with EACCES
	}{
		{name: "the helper's version directory", dir: DefaultInstallDir + "/versions/0.2.8"},
		{name: "the versions directory itself", dir: DefaultInstallDir + "/versions"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			f := &fakeSystem{}
			f.podLeaders = map[int]int64{stale: 1, live: 2}
			f.life.vmhosts = []VMHostRecord{
				{Schema: 1, PodID: "stale-pod", Pgid: stale, StartUnixNano: 1},
				{Schema: 1, PodID: "live-pod", Pgid: live, StartUnixNano: 2},
			}
			f.life.procs = map[int]fakeProc{
				stale: {exe: staleExe, uid: fakeServiceUID},
				live:  {exe: DefaultInstallDir + "/versions/0.3.0/" + VMHostName, uid: fakeServiceUID},
			}
			f.purge.links = map[string]string{
				DefaultInstallDir + "/current":  "versions/0.3.0",
				DefaultInstallDir + "/previous": "versions/0.2.9",
			}
			f.purge.resolveErrs = map[string]error{tc.dir: syscall.EACCES}
			cfg := Config{Logger: slog.New(slog.NewTextHandler(&logs, nil))}.withDefaults()

			err := stopVMHelpers(context.Background(), f, cfg)
			if idx(f.calls, fmt.Sprintf("Signal:%d:TERM", live)) < 0 {
				t.Errorf("the active version's helper beside it was not stopped: %q", f.calls)
			}
			for _, sig := range []string{"TERM", "KILL"} {
				if idx(f.calls, fmt.Sprintf("Signal:%d:%s", stale, sig)) >= 0 {
					t.Errorf("a helper whose retention is unknown was signalled %s: %q", sig, f.calls)
				}
			}
			if err == nil {
				t.Fatal("stopVMHelpers = nil, want the 0.2.8 helper reported as unresolvable")
			}
			msg := err.Error()
			for _, want := range []string{
				fmt.Sprintf("pid %d", stale),
				staleExe,
				"version 0.2.8",
				"cannot be resolved",
				"permission denied",
			} {
				if !strings.Contains(msg, want) {
					t.Errorf("stopVMHelpers = %q, want it to name %q", msg, want)
				}
			}
			for _, wrong := range []string{"no longer retains", "not " + cfg.installedVMHost()} {
				if strings.Contains(msg, wrong) {
					t.Errorf("stopVMHelpers = %q, reports an unknown retention as %q", msg, wrong)
				}
			}
			if strings.Contains(logs.String(), "no longer retains") {
				t.Errorf("an unknown retention was logged as unretained:\n%s", logs.String())
			}
		})
	}
}

// versionDirs is the fake's ownership model of a versions directory holding
// the named version directories, which the teardown lists to spell an in-use
// version the way the directory does.
func versionDirs(vers ...string) map[string]OwnedEntry {
	dir := DefaultInstallDir + "/versions"
	out := map[string]OwnedEntry{dir: {Path: dir, Kind: EntryDir}}
	for _, v := range vers {
		out[dir+"/"+v] = OwnedEntry{Path: dir + "/" + v, Kind: EntryDir}
	}
	return out
}
