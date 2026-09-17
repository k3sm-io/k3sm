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
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/executor"
)

// TestRequiredSiblingsMatchesConfigDefaults is the anti-drift test: it asserts
// that every path Config.withDefaults derives for a given binary directory is
// also reported by RequiredSiblings. The release tooling asserts an archive's
// member set against RequiredSiblings, so if withDefaults grew a fifth artifact
// class that RequiredSiblings did not know about, the archive could omit it and
// every gate would stay green while `k3sm install` fail-fasted on a user's Mac.
func TestRequiredSiblingsMatchesConfigDefaults(t *testing.T) {
	const dir = "/tmp/build"
	cfg := Config{BinarySource: filepath.Join(dir, "k3sm"), TargetUser: "someone"}.withDefaults()

	got := make(map[string]bool)
	for _, p := range RequiredSiblings(dir) {
		got[p] = true
	}

	// Every source path withDefaults derives must be covered. PayloadSource is a
	// directory, so it is covered by its members rather than by itself.
	for _, want := range []string{cfg.ExecShimSource, cfg.PathShimSource, cfg.DNSShimSource, cfg.VMHostSource} {
		if !got[want] {
			t.Errorf("RequiredSiblings(%q) omits %q, which withDefaults requires", dir, want)
		}
	}
	for _, b := range executor.PayloadBinaries() {
		want := filepath.Join(cfg.PayloadSource, b)
		if !got[want] {
			t.Errorf("RequiredSiblings(%q) omits payload binary %q", dir, want)
		}
	}
	if n := len(RequiredSiblings(dir)); n != 4+len(executor.PayloadBinaries()) {
		t.Errorf("RequiredSiblings returned %d entries, want 4 shims + %d payload binaries", n, len(executor.PayloadBinaries()))
	}
}

// TestRequiredSiblingsRelative pins the empty-dir form the `k3sm install
// --print-required-artifacts` flag emits: relative paths a caller joins onto an
// extracted archive root. A leading separator here would make the release gate
// compare absolute paths against archive members and never match.
func TestRequiredSiblingsRelative(t *testing.T) {
	for _, p := range RequiredSiblings("") {
		if strings.HasPrefix(p, "/") {
			t.Errorf("RequiredSiblings(\"\") returned absolute path %q, want relative", p)
		}
	}
	want := []string{
		ExecShimName,
		PathShimName,
		DNSShimName,
		VMHostName,
		filepath.Join(PayloadDirName, "kube-apiserver"),
	}
	got := strings.Join(RequiredSiblings(""), "\n")
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("RequiredSiblings(\"\") = %q, missing %q", got, w)
		}
	}
}

// TestExecShimNameMatchesRuntimed guards the re-export: pkg/install must not
// drift from the constant runtimed's sandbox package resolves at exec time.
func TestExecShimNameMatchesRuntimed(t *testing.T) {
	if ExecShimName != "k3sm-execshim" {
		t.Errorf("ExecShimName = %q, want k3sm-execshim (runtimed's sandbox.ExecShimName)", ExecShimName)
	}
}

// TestVMHostNameMatchesRuntimed guards the re-export: pkg/install must not
// drift from the constant runtimed's sandbox package resolves at exec time
// (sandbox.FindVMHost).
func TestVMHostNameMatchesRuntimed(t *testing.T) {
	if VMHostName != "k3sm-vmhost" {
		t.Errorf("VMHostName = %q, want k3sm-vmhost (runtimed's sandbox.VMHostName)", VMHostName)
	}
}

// TestManifestDataVolumeEntries pins the two CONDITIONAL manifest entries the
// data volume adds, and the one property the manifest exists to hold: whatever
// install lays down, uninstall tears down.
//
// Conditional entries are the interesting case precisely because they are easy
// to get half right. An entry that appears when it should not makes uninstall
// boot out a label that was never installed; one that is missing when it should
// be there leaks a root LaunchDaemon pointing at a deleted binary, which is the
// original leak this manifest was written to end.
func TestManifestDataVolumeEntries(t *testing.T) {
	plain := Config{BinarySource: "/tmp/k3sm", TargetUser: "alice"}.withDefaults()
	declared := withDeclaredVolume(plain)

	t.Run("absent on a Mac with no data volume", func(t *testing.T) {
		for _, a := range artifactManifest(plain) {
			if a.label == DatavolLabel {
				t.Errorf("the datavol daemon is in the manifest of a Mac with no data volume: %+v", a)
			}
			if a.path == dataroot.DefaultRecordPath {
				t.Errorf("the record is in the manifest of a Mac with no data volume: %+v", a)
			}
		}
	})

	t.Run("the daemon sits immediately before netd", func(t *testing.T) {
		m := artifactManifest(declared)
		var daemons []string
		for _, a := range m {
			if a.kind == kindDaemon {
				daemons = append(daemons, a.label)
			}
		}
		want := []string{DatavolLabel, NetdLabel, ServerLabel}
		if strings.Join(daemons, ",") != strings.Join(want, ",") {
			t.Fatalf("daemon order = %v, want %v (install writes plists and restarts jobs in this order, so the mount is attempted before the two daemons that refuse an unmounted data root)", daemons, want)
		}
	})

	t.Run("the daemon is a removable oneshot and the record is preserved", func(t *testing.T) {
		var daemon, record artifact
		for _, a := range artifactManifest(declared) {
			switch {
			case a.label == DatavolLabel:
				daemon = a
			case a.path == dataroot.DefaultRecordPath:
				record = a
			}
		}
		if daemon.label == "" || record.path == "" {
			t.Fatalf("manifest is missing the datavol entries: daemon=%+v record=%+v", daemon, record)
		}
		if !daemon.oneshot {
			t.Error("the datavol daemon is not marked oneshot; the restart would wait for a pid it never has")
		}
		if daemon.disp != dispRemove {
			t.Errorf("datavol disposition = %v, want dispRemove", daemon.disp)
		}
		if daemon.assertExists {
			t.Error("the datavol plist's existence must not be asserted: a Mac asking for its first volume has none yet")
		}
		if record.disp != dispPreserve {
			t.Errorf("record disposition = %v, want dispPreserve (uninstall keeps the volume, so it must keep the declaration)", record.disp)
		}
	})

	t.Run("uninstall still covers everything install lays down", func(t *testing.T) {
		r := newDatavolRig(t)
		r.seedRecord(t, "6DEAE471-0000-0000-0000-00000000BBBB")
		if err := os.MkdirAll(r.cfg.DataRoot, 0o750); err != nil {
			t.Fatalf("create the mount point: %v", err)
		}
		if err := Install(context.Background(), r.sys, r.cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		un := &fakeSystem{}
		if err := Uninstall(context.Background(), un, r.cfg); err != nil {
			t.Fatalf("Uninstall: %v", err)
		}
		if gaps := uninstallGaps(withDeclaredVolume(r.cfg), r.sys.calls, un.calls); len(gaps) != 0 {
			t.Errorf("uninstall leaves install artifacts behind: %v", gaps)
		}
	})
}

// TestManifestServerArgsRecordEntry pins the server-arguments record's place in
// the manifest: present on EVERY Mac (every install writes one), preserved (an
// uninstall that removed it would put the next install back to re-rendering the
// stock template), and outside every tree the uninstall sweep removes.
func TestManifestServerArgsRecordEntry(t *testing.T) {
	cfg := Config{BinarySource: "/tmp/k3sm", TargetUser: "alice"}.withDefaults()

	var entry artifact
	for _, a := range artifactManifest(cfg) {
		if a.path == cfg.ServerArgsRecord {
			entry = a
		}
	}
	if entry.path == "" {
		t.Fatalf("the manifest has no entry for the server-arguments record %q", cfg.ServerArgsRecord)
	}
	if entry.kind != kindFile {
		t.Errorf("kind = %v, want kindFile", entry.kind)
	}
	if entry.disp != dispPreserve {
		t.Errorf("disposition = %v, want dispPreserve (uninstall keeps the operator's flags)", entry.disp)
	}
	if entry.assertExists {
		t.Error("existence must not be asserted: a Mac installed by an older k3sm has no record")
	}
	if strings.HasPrefix(cfg.ServerArgsRecord, cfg.InstallDir+"/") || strings.HasPrefix(cfg.ServerArgsRecord, cfg.DataRoot+"/") {
		t.Errorf("the record at %q must live outside both the swept install dir and the service-user-owned data root", cfg.ServerArgsRecord)
	}
}
