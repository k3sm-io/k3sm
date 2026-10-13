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
			rec, present, err := ReadNetworkRecord(f.ReadFile, record)
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
		rec, present, err := ReadNetworkRecord(func(string) ([]byte, error) { return nil, fs.ErrNotExist }, "/nonexistent")
		if err != nil || present || rec.LAN != LANOn {
			t.Fatalf("absent record = %+v present=%v err=%v, want on, absent, no error", rec, present, err)
		}
	})
}
