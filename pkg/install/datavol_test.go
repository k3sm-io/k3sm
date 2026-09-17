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
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/datavol"
	"k3sm.io/k3sm/pkg/datavol/datavoltest"
)

// datavolRig is one test's whole world: a scratch install dir and data root, a
// fake disk, and a fake privileged system whose call log the datavol seams write
// into as well.
//
// The single interleaved log is the point of the rig. The property under test is
// an ORDER that spans two packages — the diskutil work must happen before
// pkg/install's own first step — and two separate call slices could never state
// it. datavoltest.Fake.Log exists for exactly this.
type datavolRig struct {
	cfg  Config
	sys  *fakeSystem
	disk *datavoltest.Fake
	root string
}

// newDatavolRig builds the rig. The data root is NOT created: a subtest that
// wants an existing one says so with seedDataRoot.
func newDatavolRig(t *testing.T) *datavolRig {
	t.Helper()
	shrinkRestartBudgets(t)
	root := t.TempDir()

	// Per-test declaration paths. TestMain already points both away from the
	// running Mac; these narrow them to this test, because EnsureFstabLine
	// really writes the file it is given.
	fstabPath, recordPath := dataroot.FstabPath, dataroot.DefaultRecordPath
	dataroot.FstabPath = filepath.Join(root, "fstab")
	dataroot.DefaultRecordPath = filepath.Join(root, "io.k3sm.datavol.json")
	t.Cleanup(func() { dataroot.FstabPath, dataroot.DefaultRecordPath = fstabPath, recordPath })

	sys := &fakeSystem{}
	disk := datavoltest.New()
	// A pinned UUID for whatever this test creates, so an assertion can name the
	// mount of the DATA ROOT specifically -- a migration also mounts the same
	// volume on the staging point, and "a mount happened" would not tell the two
	// apart.
	disk.NextUUID = createdVolumeUUID
	disk.Log = func(line string) { sys.calls = append(sys.calls, "datavol."+line) }

	return &datavolRig{
		sys:  sys,
		disk: disk,
		root: root,
		cfg: Config{
			BinarySource:   filepath.Join(root, "build", "k3sm"),
			TargetUser:     "alice",
			InstallDir:     filepath.Join(root, "Library", "k3sm"),
			DataRoot:       filepath.Join(root, "var", "lib", "k3sm"),
			DataRootFS:     disk.FS(),
			DataVolumeDeps: disk.Deps(),
		},
	}
}

// createdVolumeUUID is the UUID the fake disk assigns to a volume created
// during a test.
const createdVolumeUUID = "11111111-2222-3333-4444-555555555555"

// wantVolume asks install for a freshly created 32 GiB volume named k3sm.
func (r *datavolRig) wantVolume(encrypt bool) {
	r.cfg.DataVolume = &datavol.Options{
		Name:       "k3sm",
		Mountpoint: r.cfg.DataRoot,
		QuotaBytes: datavol.MinQuotaBytes,
		Encrypt:    encrypt,
		CreatedBy:  "k3sm test",
	}
}

// seedDataRoot creates a plain, non-empty data root: a kine datastore, the
// server-arguments record, and one other file — what a migration has to carry
// across and verify.
func (r *datavolRig) seedDataRoot(t *testing.T) {
	t.Helper()
	argsRecord, err := dataroot.EncodeServerArgsRecord(dataroot.ServerArgsRecord{
		Args: []string{"--mesh-ip", "100.64.0.1"}, CreatedBy: "k3sm test",
	})
	if err != nil {
		t.Fatalf("encode the server arguments record: %v", err)
	}
	files := map[string]string{
		"server/db/state.db": "SQLite format 3\x00 pretend datastore",
		"agent/etc/hosts":    "127.0.0.1 localhost\n",
		// The record rides in the data root precisely so a migration onto a
		// volume carries it; seeding it here puts it inside the tree Migrate
		// copies and then verifies file-for-file.
		"server-args.json": string(argsRecord),
	}
	for rel, content := range files {
		path := filepath.Join(r.cfg.DataRoot, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("seed the data root: %v", err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("seed the data root: %v", err)
		}
	}
}

// seedRecord declares an existing data volume, the posture of a Mac that has
// already run `k3sm install --data-volume` once.
func (r *datavolRig) seedRecord(t *testing.T, uuid string) dataroot.Record {
	t.Helper()
	rec := dataroot.Record{
		Version:    dataroot.RecordVersion,
		UUID:       uuid,
		Name:       "k3sm",
		Mountpoint: r.cfg.DataRoot,
		QuotaBytes: datavol.MinQuotaBytes,
		CreatedBy:  "k3sm test",
		CreatedAt:  "2026-09-13T00:00:00Z",
	}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("encode the record: %v", err)
	}
	r.disk.Files[dataroot.DefaultRecordPath] = string(data)
	r.disk.Add(datavoltest.Volume{
		UUID: uuid, Name: "k3sm", Container: "disk3", Device: "disk3s7",
		Quota: datavol.MinQuotaBytes, InUse: 1 << 20, CaseSensitive: true,
	})
	return rec
}

// callIndex is the position of the first call with the given prefix, or -1.
func callIndex(calls []string, prefix string) int {
	for i, c := range calls {
		if strings.HasPrefix(c, prefix) {
			return i
		}
	}
	return -1
}

// assertOrder asserts that the given call prefixes appear in the log in this
// order, each present. It names the whole log on failure, because a sequencing
// failure is only legible next to what did happen.
func assertOrder(t *testing.T, calls []string, prefixes ...string) {
	t.Helper()
	prev, prevName := -1, ""
	for _, p := range prefixes {
		at := callIndex(calls, p)
		if at < 0 {
			t.Fatalf("call %q never happened; calls =\n%s", p, strings.Join(calls, "\n"))
		}
		if at < prev {
			t.Fatalf("call %q (%d) happened before %q (%d); calls =\n%s", p, at, prevName, prev, strings.Join(calls, "\n"))
		}
		prev, prevName = at, p
	}
}

// TestInstallWithDataVolumeSequencing is the gate for the data-volume block's
// ORDER, which is the whole of its correctness: the block runs before the
// refuse-shadow guard EnsureServiceUser carries, the record is written only
// after a verified mount, a migration stops the daemons before it copies, and a
// refusal that costs downtime happens before any daemon goes down.
func TestInstallWithDataVolumeSequencing(t *testing.T) {
	t.Run("the data-volume block runs before EnsureServiceUser", func(t *testing.T) {
		r := newDatavolRig(t)
		r.wantVolume(false)
		if err := Install(context.Background(), r.sys, r.cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		// EnsureServiceUser carries the unconditional refuse-shadow check, which
		// fires on a declared-but-unmounted root. If the block ran after it, the
		// one command that repairs that state could never repair it.
		assertOrder(t, r.sys.calls, "datavol.", "EnsureServiceUser:")
	})

	t.Run("create: ensure, mount, record, then the plists", func(t *testing.T) {
		r := newDatavolRig(t)
		r.wantVolume(false)
		if err := Install(context.Background(), r.sys, r.cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		assertOrder(t, r.sys.calls,
			"datavol.addvolume ",
			"datavol.mount "+createdVolumeUUID+" "+r.cfg.DataRoot,
			"WriteDataVolumeRecord:"+dataroot.DefaultRecordPath,
			"WriteLaunchDaemon:"+r.cfg.withDefaults().plistPath(DatavolLabel),
		)
		// Nothing was in the way, so nothing was copied and no daemon was stopped
		// for a migration.
		if at := callIndex(r.sys.calls, "CopyTree:"); at >= 0 {
			t.Errorf("an empty data root was migrated; calls =\n%s", strings.Join(r.sys.calls, "\n"))
		}
		if at := callIndex(r.sys.calls, "Bootout:"+ServerLabel); at >= 0 && at < callIndex(r.sys.calls, "WriteLaunchDaemon:") {
			t.Errorf("the daemons were stopped for a migration that was not needed; calls =\n%s", strings.Join(r.sys.calls, "\n"))
		}
		rec, ok := r.sys.records[dataroot.DefaultRecordPath]
		if !ok {
			t.Fatal("no record was written")
		}
		if rec.Mountpoint != r.cfg.DataRoot || rec.QuotaBytes != datavol.MinQuotaBytes {
			t.Errorf("record = %+v, want mountpoint %q and the requested quota", rec, r.cfg.DataRoot)
		}
		// The second declaration: an /etc/fstab line, so a k3sm too old to read
		// the record still perceives the volume and refuses a shadowed root.
		fstab, err := os.ReadFile(dataroot.FstabPath)
		if err != nil {
			t.Fatalf("read the fstab: %v", err)
		}
		if !strings.Contains(string(fstab), rec.UUID) || !strings.Contains(string(fstab), datavol.MountOptions) {
			t.Errorf("fstab = %q, want a UUID=%s line carrying %q", fstab, rec.UUID, datavol.MountOptions)
		}
	})

	t.Run("migration: daemons down, copy, rename, then mount and record", func(t *testing.T) {
		r := newDatavolRig(t)
		r.wantVolume(false)
		r.seedDataRoot(t)
		r.sys.putLoaded(NetdLabel, ServerLabel)
		if err := Install(context.Background(), r.sys, r.cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		assertOrder(t, r.sys.calls,
			"datavol.addvolume ",
			// The server first, then the helper it drives: copying a datastore
			// that is still being written is copying a moving target.
			"Bootout:"+ServerLabel,
			"Bootout:"+NetdLabel,
			"CopyTree:",
			"Rename:",
			// The data root, not the staging point: the same volume is mounted
			// twice in a migration and only the second one is the install's claim.
			"datavol.mount "+createdVolumeUUID+" "+r.cfg.DataRoot,
			"WriteDataVolumeRecord:",
			"WriteLaunchDaemon:",
		)
		// The old data root was renamed aside, never deleted: it is the operator's
		// only rollback until they say otherwise.
		preVolume := r.cfg.DataRoot + datavol.PreVolumeSuffix
		if _, err := os.Stat(filepath.Join(preVolume, "server", "db", "state.db")); err != nil {
			t.Errorf("the pre-migration copy is not at %s: %v", preVolume, err)
		}
		// The server-arguments record went across with everything else. What
		// this asserts, precisely: it was in the tree Migrate copied and then
		// VERIFIED file-for-file (a missing file fails that verification, and
		// the install above would have failed), and it is in the rollback copy.
		// What this harness cannot assert is the record sitting on the mounted
		// volume afterwards: the fake diskutil does not materialise a volume on
		// disk, and the staging copy is removed once the migration succeeds, so
		// the only copies a test can stat are the pre-volume one and what the
		// verification already compared.
		if _, err := os.Stat(filepath.Join(preVolume, "server-args.json")); err != nil {
			t.Errorf("the migration lost the server-arguments record: %v", err)
		}
		// And the staging mount point is gone, so nothing looks half-finished.
		if _, err := os.Stat(r.cfg.withDefaults().datavolStaging()); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the staging mount point survived the migration: %v", err)
		}
	})

	t.Run("no flag and no record: no datavol artifact and no disk work", func(t *testing.T) {
		r := newDatavolRig(t)
		if err := Install(context.Background(), r.sys, r.cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if at := callIndex(r.sys.calls, "datavol."); at >= 0 {
			t.Errorf("install touched the disk without --data-volume; calls =\n%s", strings.Join(r.sys.calls, "\n"))
		}
		for _, a := range artifactManifest(r.cfg) {
			if a.label == DatavolLabel {
				t.Errorf("the manifest carries the datavol daemon on a Mac that has no data volume: %+v", a)
			}
			if a.path == dataroot.DefaultRecordPath {
				t.Errorf("the manifest carries the record on a Mac that has none: %+v", a)
			}
		}
		if at := callIndex(r.sys.calls, "WriteLaunchDaemon:"+r.cfg.withDefaults().plistPath(DatavolLabel)); at >= 0 {
			t.Error("the datavol plist was written on a Mac with no data volume")
		}
	})

	t.Run("a record without the flag still manages the daemon, and never the record", func(t *testing.T) {
		r := newDatavolRig(t)
		rec := r.seedRecord(t, "6DEAE471-0000-0000-0000-00000000AAAA")
		if err := os.MkdirAll(r.cfg.DataRoot, 0o750); err != nil {
			t.Fatalf("create the mount point: %v", err)
		}

		var daemon, record bool
		for _, a := range artifactManifest(withDeclaredVolume(r.cfg)) {
			if a.label == DatavolLabel {
				daemon = true
				if !a.oneshot || a.disp != dispRemove {
					t.Errorf("the datavol artifact is %+v, want a removable oneshot", a)
				}
			}
			if a.path == dataroot.DefaultRecordPath {
				record = true
				if a.disp != dispPreserve {
					t.Errorf("the record artifact is %+v, want dispPreserve", a)
				}
			}
		}
		if !daemon || !record {
			t.Fatalf("manifest carries datavol daemon=%t record=%t, want both", daemon, record)
		}

		if err := Install(context.Background(), r.sys, r.cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if at := callIndex(r.sys.calls, "WriteLaunchDaemon:"+r.cfg.withDefaults().plistPath(DatavolLabel)); at < 0 {
			t.Errorf("the datavol plist was not written for a recorded volume; calls =\n%s", strings.Join(r.sys.calls, "\n"))
		}
		// Install must not have touched the disk: no flag was given, so there is
		// nothing to create, adopt or migrate.
		if at := callIndex(r.sys.calls, "datavol.addvolume"); at >= 0 {
			t.Error("a recorded volume was re-created")
		}

		un := &fakeSystem{}
		uncfg := r.cfg
		if err := Uninstall(context.Background(), un, uncfg); err != nil {
			t.Fatalf("Uninstall: %v", err)
		}
		if at := callIndex(un.calls, "Bootout:"+DatavolLabel); at < 0 {
			t.Errorf("uninstall left the datavol daemon loaded; calls =\n%s", strings.Join(un.calls, "\n"))
		}
		if at := callIndex(un.calls, "RemoveAll:"+r.cfg.withDefaults().plistPath(DatavolLabel)); at < 0 {
			t.Errorf("uninstall leaked the datavol plist; calls =\n%s", strings.Join(un.calls, "\n"))
		}
		// The volume is data, not an artifact. Its declaration survives, or the
		// next install cannot tell a k3sm volume from an operator's.
		for _, c := range un.calls {
			if strings.HasPrefix(c, "RemoveAll:") && strings.Contains(c, dataroot.DefaultRecordPath) {
				t.Errorf("uninstall removed the data-volume record: %s", c)
			}
		}
		if _, ok := r.disk.Files[dataroot.DefaultRecordPath]; !ok {
			t.Errorf("the record for volume %s is gone after uninstall", rec.UUID)
		}
	})

	t.Run("an encrypted migration without --remove-old-data-root fails before any bootout", func(t *testing.T) {
		r := newDatavolRig(t)
		r.wantVolume(true)
		r.seedDataRoot(t)
		r.sys.putLoaded(NetdLabel, ServerLabel)

		err := Install(context.Background(), r.sys, r.cfg)
		if !errors.Is(err, datavol.ErrEncryptedNeedsRemoveOld) {
			t.Fatalf("Install = %v, want ErrEncryptedNeedsRemoveOld", err)
		}
		// The refusal costs no downtime: an operator who has to make a decision
		// makes it with their cluster still running.
		if at := callIndex(r.sys.calls, "Bootout:"); at >= 0 {
			t.Errorf("a daemon was stopped before the refusal; calls =\n%s", strings.Join(r.sys.calls, "\n"))
		}
		if at := callIndex(r.sys.calls, "CopyTree:"); at >= 0 {
			t.Error("the data root was copied despite the refusal")
		}
	})
}

// withDeclaredVolume returns cfg as Install and Uninstall see it once they have
// read a record: the manifest's two conditional entries are keyed on that flag,
// and it is unexported, so a manifest assertion has to set it the same way.
func withDeclaredVolume(cfg Config) Config {
	cfg = cfg.withDefaults()
	cfg.dataVolumeDeclared = true
	return cfg
}

// TestDatavolPlist pins the boot contract the io.k3sm.datavol job carries: it
// runs `k3sm datavol mount` as root at load, launchd relaunches it ONLY on a
// non-zero exit, and the relaunch is throttled.
func TestDatavolPlist(t *testing.T) {
	cfg := Config{BinarySource: "/tmp/k3sm", TargetUser: "alice"}
	plist := string(DatavolPlist(cfg))

	for _, want := range []string{
		"<key>Label</key>\n  <string>io.k3sm.datavol</string>",
		"<string>/Library/k3sm/k3sm</string>",
		"<string>datavol</string>",
		"<string>mount</string>",
		"<key>RunAtLoad</key>\n  <true/>",
		// The oneshot's whole design: a successful mount ENDS the job, a failed
		// one is relaunched. A bare KeepAlive would respawn it forever.
		"<key>KeepAlive</key>\n  <dict>\n    <key>SuccessfulExit</key>\n    <false/>\n  </dict>",
		"<key>ThrottleInterval</key>\n  <integer>10</integer>",
		"<string>" + DatavolLogPath() + "</string>",
	} {
		mustContain(t, plist, want)
	}
	// Root: mounting a volume is not the service user's to do.
	if strings.Contains(plist, "<key>UserName</key>") {
		t.Errorf("the datavol plist names a UserName; it must run as root:\n%s", plist)
	}
	// And the bare boolean form must be absent, or which KeepAlive binds would
	// be up to launchd's parser rather than to this decision.
	if strings.Contains(plist, "<key>KeepAlive</key>\n  <true/>") {
		t.Errorf("the datavol plist carries a bare KeepAlive as well as the dict:\n%s", plist)
	}
}

// TestRenderPlistKeepAliveOnFailure pins the renderer's own contract for the two
// KeepAlive shapes, independently of any one daemon.
func TestRenderPlistKeepAliveOnFailure(t *testing.T) {
	tests := []struct {
		name        string
		in          launchdPlist
		want        string
		wantAbsent  string
		wantThrottl string
	}{
		{
			name:       "a long-running daemon keeps the boolean",
			in:         launchdPlist{Label: "io.k3sm.example", KeepAlive: true},
			want:       "<key>KeepAlive</key>\n  <true/>",
			wantAbsent: "<key>SuccessfulExit</key>",
		},
		{
			name:       "a oneshot renders the dict instead",
			in:         launchdPlist{Label: "io.k3sm.example", KeepAliveOnFailure: true},
			want:       "<key>KeepAlive</key>\n  <dict>\n    <key>SuccessfulExit</key>\n    <false/>\n  </dict>",
			wantAbsent: "<key>KeepAlive</key>\n  <true/>",
		},
		{
			name:        "ThrottleInterval renders only when set",
			in:          launchdPlist{Label: "io.k3sm.example", KeepAliveOnFailure: true, ThrottleInterval: 42},
			want:        "<key>ThrottleInterval</key>\n  <integer>42</integer>",
			wantAbsent:  "<key>KeepAlive</key>\n  <true/>",
			wantThrottl: "42",
		},
		{
			name:       "no throttle key at zero",
			in:         launchdPlist{Label: "io.k3sm.example", KeepAlive: true},
			want:       "<key>Label</key>",
			wantAbsent: "<key>ThrottleInterval</key>",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := string(renderPlist(tc.in))
			mustContain(t, got, tc.want)
			if strings.Contains(got, tc.wantAbsent) {
				t.Errorf("plist contains %q, which it must not:\n%s", tc.wantAbsent, got)
			}
			if err := plistWellFormed(got); err != nil {
				t.Errorf("rendered plist is not well-formed XML: %v\n%s", err, got)
			}
		})
	}
}

// plistWellFormed reports whether the rendered plist parses as XML. The
// KeepAlive dict is the first nested element renderPlist emits by hand, and a
// substring assertion would pass just as happily on a mis-nested one.
func plistWellFormed(s string) error {
	dec := xml.NewDecoder(strings.NewReader(s))
	for {
		_, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("parse: %w", err)
		}
	}
}
