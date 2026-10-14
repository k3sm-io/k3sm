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
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInstallRecordsLANAccess pins what an install records for the LAN
// switch: a new install records off; an install over an earlier one (a node
// plist or work dir already there) with nothing recorded keeps LAN access on;
// a recorded value survives a reinstall untouched; --lan always wins; an
// unusable record is refused unless --lan replaces it; and the record is
// root-owned, world-readable and survives as a file, not as daemon argv.
func TestInstallRecordsLANAccess(t *testing.T) {
	t.Parallel()
	off, on := LANOff, LANOn
	fresh := func(f *fakeSystem, cfg Config) {
		for _, p := range []string{cfg.plistPath(ServerLabel), cfg.plistPath(AgentLabel), cfg.serverWorkDir(), cfg.agentWorkDir()} {
			f.putMissingPath(p)
		}
	}
	cases := []struct {
		name     string
		setup    func(*fakeSystem, Config)
		lan      *LAN
		existing string
		want     LAN
		wantErr  error
		written  bool
	}{
		{name: "a new install records off", setup: fresh, want: LANOff, written: true},
		{name: "an upgrade with nothing recorded keeps on", want: LANOn, written: true},
		{name: "a recorded value is kept", existing: `{"version":1,"lan":"off","serial":"x"}`, want: LANOff},
		{name: "a recorded on is kept on a fresh-looking Mac", setup: fresh, existing: `{"version":1,"lan":"on","serial":"x"}`, want: LANOn},
		{name: "--lan on wins over a recorded off", lan: &on, existing: `{"version":1,"lan":"off","serial":"x"}`, want: LANOn, written: true},
		{name: "--lan off wins on an upgrade", lan: &off, want: LANOff, written: true},
		{name: "an unusable record is refused", existing: `{"version":1,"lan":"maybe"}`, wantErr: ErrNetworkRecord},
		{name: "--lan replaces an unusable record", lan: &off, existing: `{"version":9}`, want: LANOff, written: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeSystem{}
			record := filepath.Join(t.TempDir(), "io.k3sm.network.json")
			cfg := Config{BinarySource: "/tmp/k3sm", TargetUser: "alice", NetworkRecord: record, LAN: tc.lan}
			if tc.setup != nil {
				tc.setup(f, cfg.withDefaults())
			}
			if tc.existing != "" {
				f.putFile(record, []byte(tc.existing))
				putRootRecordOwner(f, record)
			}
			err := Install(context.Background(), f, cfg)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Install = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Install: %v", err)
			}
			putRootRecordOwner(f, record)
			rec, present, err := ReadNetworkRecord(SystemNetworkRecordReader(f), record)
			if err != nil || !present {
				t.Fatalf("read back the record: present=%v err=%v", present, err)
			}
			if rec.LAN != tc.want {
				t.Fatalf("recorded LAN = %s, want %s", rec.LAN, tc.want)
			}
			wrote := false
			for _, c := range f.calls {
				if c == "WriteRootOnlyFile:"+record+":0644" {
					wrote = true
				}
				if strings.HasPrefix(c, "WriteRootOnlyFile:"+record+":") && c != "WriteRootOnlyFile:"+record+":0644" {
					t.Errorf("the record was written with the wrong mode: %s", c)
				}
			}
			if wrote != tc.written {
				t.Errorf("record written = %v, want %v", wrote, tc.written)
			}
		})
	}

	t.Run("an absent record reads as on", func(t *testing.T) {
		t.Parallel()
		absent := func(string) (NetworkRecordFile, error) { return NetworkRecordFile{}, fs.ErrNotExist }
		rec, present, err := ReadNetworkRecord(absent, "/nonexistent")
		if err != nil || present || rec.LAN != LANOn {
			t.Fatalf("absent record = %+v present=%v err=%v, want on, absent, no error", rec, present, err)
		}
	})
}

// putRootRecordOwner describes path to the fake's lstat as a root-owned 0644
// regular file, the shape WriteNetworkRecord leaves.
func putRootRecordOwner(f *fakeSystem, path string) {
	if f.owners == nil {
		f.owners = map[string]OwnedEntry{}
	}
	f.owners[path] = OwnedEntry{Path: path, UID: 0, GID: 0, Mode: 0o644, Kind: EntryRegular}
}

// TestNetworkRecordTrust pins what a record must be before anyone acts on
// it: a regular file, owned by root, writable by no one else, at most
// MaxNetworkRecordBytes, exactly one JSON value. Anything else is unusable
// (ErrNetworkRecord), which the node daemon serves as off.
func TestNetworkRecordTrust(t *testing.T) {
	t.Parallel()
	good := []byte(`{"version":1,"lan":"on","serial":"s"}`)
	file := func(mut func(*NetworkRecordFile)) NetworkRecordReader {
		return func(string) (NetworkRecordFile, error) {
			f := NetworkRecordFile{Data: good, UID: 0, Mode: 0o644, Kind: EntryRegular}
			mut(&f)
			return f, nil
		}
	}
	if rec, present, err := ReadNetworkRecord(file(func(*NetworkRecordFile) {}), "r"); err != nil || !present || rec.LAN != LANOn {
		t.Fatalf("a good record = %+v, %v, %v", rec, present, err)
	}
	for name, mut := range map[string]func(*NetworkRecordFile){
		"a symlink":       func(f *NetworkRecordFile) { f.Kind = EntrySymlink; f.Data = nil },
		"owned by a user": func(f *NetworkRecordFile) { f.UID = 501 },
		"group-writable":  func(f *NetworkRecordFile) { f.Mode = 0o664 },
		"world-writable":  func(f *NetworkRecordFile) { f.Mode = 0o646 },
		"trailing data":   func(f *NetworkRecordFile) { f.Data = append(append([]byte{}, good...), []byte(` {"lan":"off"}`)...) },
		"oversized": func(f *NetworkRecordFile) {
			f.Data = append(append([]byte{}, good...), make([]byte, MaxNetworkRecordBytes)...)
		},
		"not JSON":            func(f *NetworkRecordFile) { f.Data = []byte("lan=on") },
		"an unknown lan word": func(f *NetworkRecordFile) { f.Data = []byte(`{"version":1,"lan":"both"}`) },
	} {
		if _, present, err := ReadNetworkRecord(file(mut), "r"); !errors.Is(err, ErrNetworkRecord) || !present {
			t.Errorf("%s: present=%v err=%v, want present and ErrNetworkRecord", name, present, err)
		}
	}

	t.Run("the production reader refuses a symlink and bounds the read", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		target := filepath.Join(dir, "target")
		if err := os.WriteFile(target, good, 0o644); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		f, err := ReadNetworkRecordFile(link)
		if err != nil || f.Kind != EntrySymlink || f.Data != nil {
			t.Fatalf("symlink read = %+v, %v; want kind symlink, no data", f, err)
		}
		big := filepath.Join(dir, "big")
		if err := os.WriteFile(big, make([]byte, 3*MaxNetworkRecordBytes), 0o644); err != nil {
			t.Fatal(err)
		}
		f, err = ReadNetworkRecordFile(big)
		if err != nil || len(f.Data) != MaxNetworkRecordBytes+1 {
			t.Fatalf("big read = %d bytes, %v; want %d", len(f.Data), err, MaxNetworkRecordBytes+1)
		}
	})
}
