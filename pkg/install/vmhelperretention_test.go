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
	"regexp"
	"strings"
	"syscall"
	"testing"
)

// TestTeardownUnknownRetentionCoversEveryNonENOENTError pins the retention
// rule's one line between gone and unknown (retainedVersion): only
// fs.ErrNotExist names no version, and every other failure leaves the version
// unknown. It runs EACCES, EIO and ENOTDIR through both seams the rule reads,
// the resolve of the helper's version directory and the versions directory's
// listing, and expects the helper of an unlinked version reported as unknown,
// with the remedy, and never signalled, never as unretained and never as a
// forged record. ENOTDIR is the case a widened gone test would most plausibly
// swallow. A last case keeps the version retained by previous while the
// versions directory is unreadable: the links answer on their own, so both
// helpers are stopped and nothing is reported.
func TestTeardownUnknownRetentionCoversEveryNonENOENTError(t *testing.T) {
	const (
		stale = 841 // runs from 0.2.8
		live  = 842 // runs from 0.3.0, the active version
	)
	staleExe := DefaultInstallDir + "/versions/0.2.8/" + VMHostName
	versions := DefaultInstallDir + "/versions"
	type seam int
	const (
		resolveSeam seam = iota
		listSeam
	)
	errnos := []struct {
		name  string
		errno syscall.Errno
		text  string
	}{
		{name: "EACCES", errno: syscall.EACCES, text: "permission denied"},
		{name: "EIO", errno: syscall.EIO, text: "input/output error"},
		{name: "ENOTDIR", errno: syscall.ENOTDIR, text: "not a directory"},
	}
	type tcase struct {
		name     string
		seam     seam
		errno    syscall.Errno
		text     string
		previous string // the version previous points at
		retained bool   // previous retains 0.2.8, so it is stopped
	}
	var cases []tcase
	for _, s := range []struct {
		name string
		seam seam
	}{{"pod-path resolve", resolveSeam}, {"versions listing", listSeam}} {
		for _, e := range errnos {
			cases = append(cases, tcase{name: s.name + "/" + e.name, seam: s.seam, errno: e.errno, text: e.text, previous: "0.2.9"})
		}
		cases = append(cases, tcase{name: s.name + "/previous retains it", seam: s.seam, errno: syscall.EACCES, previous: "0.2.8", retained: true})
	}
	for _, tc := range cases {
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
				live:  {exe: versions + "/0.3.0/" + VMHostName, uid: fakeServiceUID},
			}
			f.purge.links = map[string]string{
				DefaultInstallDir + "/current":  "versions/0.3.0",
				DefaultInstallDir + "/previous": "versions/" + tc.previous,
			}
			f.owners = versionDirs("0.2.8", "0.2.9", "0.3.0")
			switch tc.seam {
			case resolveSeam:
				f.purge.resolveErrs = map[string]error{versions + "/0.2.8": tc.errno}
			case listSeam:
				f.purge.listErrs = map[string]error{versions: tc.errno}
			}
			cfg := Config{Logger: slog.New(slog.NewTextHandler(&logs, nil))}.withDefaults()

			err := stopVMHelpers(context.Background(), f, cfg)
			if idx(f.calls, fmt.Sprintf("Signal:%d:TERM", live)) < 0 {
				t.Errorf("the active version's helper beside it was not stopped: %q", f.calls)
			}
			if tc.retained {
				if idx(f.calls, fmt.Sprintf("Signal:%d:TERM", stale)) < 0 {
					t.Errorf("the helper of the version previous retains was not stopped: %q", f.calls)
				}
				if err != nil {
					t.Errorf("stopVMHelpers = %v, want both helpers stopped without a report", err)
				}
				return
			}
			for _, call := range f.calls {
				if strings.HasPrefix(call, fmt.Sprintf("Signal:%d:", stale)) {
					t.Errorf("a helper whose retention is unknown was signalled (%s): %q", call, f.calls)
				}
			}
			if err == nil {
				t.Fatal("stopVMHelpers = nil, want the 0.2.8 helper reported as unknown")
			}
			msg := err.Error()
			for _, want := range []string{
				fmt.Sprintf("pid %d", stale),
				fmt.Sprintf("%q", staleExe),
				`version "0.2.8"`,
				"cannot be resolved",
				"unknown",
				tc.text,
				fmt.Sprintf("check that %q and each of its parents are owned by root and not writable by group or others", versions+"/0.2.8"),
				"an I/O error means the disk needs checking",
				fmt.Sprintf("if ps -o pid,command -g %d shows only %q processes, stop it with: sudo kill -TERM -%d", stale, staleExe, stale),
			} {
				if !strings.Contains(msg, want) {
					t.Errorf("stopVMHelpers = %q, want it to name %q", msg, want)
				}
			}
			for _, wrong := range []string{"fix the permissions", "no longer retains", "not " + cfg.installedVMHost()} {
				if strings.Contains(msg, wrong) {
					t.Errorf("stopVMHelpers = %q, reports an unknown retention as %q", msg, wrong)
				}
			}
			if regexp.MustCompile(fmt.Sprintf(`\b%d\b`, live)).MatchString(msg) {
				t.Errorf("stopVMHelpers = %q, names the live group %d", msg, live)
			}
			if strings.Contains(logs.String(), "no longer retains") {
				t.Errorf("an unknown retention was logged as unretained:\n%s", logs.String())
			}
		})
	}
}
