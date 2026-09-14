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

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/datavol"
	"k3sm.io/k3sm/pkg/install"
)

// TestInstallFlagsDataVolume pins the data-volume flag CONTRACT, which is the
// part of this feature a unit test can reach: the install itself needs root and
// a disk, but every refusal an operator is most likely to meet is decided here,
// before anything is touched.
func TestInstallFlagsDataVolume(t *testing.T) {
	const testVersion = "v0.1.5"

	t.Run("no flag asks for no volume", func(t *testing.T) {
		opts, err := parseInstallFlags([]string{"--user", "alice"})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		got, err := opts.dataVolumeOptions(testVersion)
		if err != nil {
			t.Fatalf("dataVolumeOptions: %v", err)
		}
		if got != nil {
			t.Errorf("dataVolumeOptions = %+v, want nil: an install that was not asked for a volume must not touch the disk", got)
		}
	})

	t.Run("the defaults are the documented ones", func(t *testing.T) {
		opts, err := parseInstallFlags([]string{"--data-volume"})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		got, err := opts.dataVolumeOptions(testVersion)
		if err != nil {
			t.Fatalf("dataVolumeOptions: %v", err)
		}
		if got == nil {
			t.Fatal("dataVolumeOptions = nil, want a volume request")
		}
		if got.Name != "k3sm" {
			t.Errorf("Name = %q, want k3sm", got.Name)
		}
		if got.QuotaBytes != 100<<30 {
			t.Errorf("QuotaBytes = %d, want 100 GiB", got.QuotaBytes)
		}
		if got.Mountpoint != install.DefaultDataRoot {
			t.Errorf("Mountpoint = %q, want the data root %q", got.Mountpoint, install.DefaultDataRoot)
		}
		if got.Encrypt {
			t.Error("Encrypt is set without --data-volume-encrypt")
		}
		if got.CreatedBy != "k3sm "+testVersion {
			t.Errorf("CreatedBy = %q, want the k3sm version that wrote the record", got.CreatedBy)
		}
		// The gate-only waiver must never be reachable from a flag: it exists so
		// a lab run can prove the create path on a two-gigabyte scratch volume,
		// and an operator reaching it would get a volume permanently inside the
		// band that triggers reclamation.
		if got.AllowSmallQuota {
			t.Error("AllowSmallQuota is set from the CLI; it is the acceptance gate's alone")
		}
	})

	t.Run("the requested options are carried through", func(t *testing.T) {
		opts, err := parseInstallFlags([]string{"--data-volume", "--data-volume-name", "k3sm-lab", "--data-volume-size", "256g", "--data-volume-encrypt", "--remove-old-data-root"})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		got, err := opts.dataVolumeOptions(testVersion)
		if err != nil {
			t.Fatalf("dataVolumeOptions: %v", err)
		}
		if got.Name != "k3sm-lab" || got.QuotaBytes != 256<<30 || !got.Encrypt {
			t.Errorf("options = %+v, want name k3sm-lab, 256 GiB, encrypted", got)
		}
		if !opts.removeOldDataRoot {
			t.Error("--remove-old-data-root was not parsed")
		}
	})

	t.Run("a quota below the floor is refused, and the floor is named", func(t *testing.T) {
		opts, err := parseInstallFlags([]string{"--data-volume", "--data-volume-size", "8g"})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		_, err = opts.dataVolumeOptions(testVersion)
		if err == nil {
			t.Fatal("dataVolumeOptions accepted a quota below the floor")
		}
		if !strings.Contains(err.Error(), datavol.FormatSize(datavol.MinQuotaBytes)) {
			t.Errorf("error %q does not name the %s floor, so it does not say what to pass instead", err, datavol.FormatSize(datavol.MinQuotaBytes))
		}
	})

	t.Run("--data-volume-encrypt alone is refused", func(t *testing.T) {
		opts, err := parseInstallFlags([]string{"--data-volume-encrypt"})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if _, err := opts.dataVolumeOptions(testVersion); err == nil {
			t.Fatal("dataVolumeOptions accepted --data-volume-encrypt with no volume to encrypt")
		}
	})

	t.Run("an unparsable size is refused", func(t *testing.T) {
		opts, err := parseInstallFlags([]string{"--data-volume", "--data-volume-size", "lots"})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if _, err := opts.dataVolumeOptions(testVersion); err == nil {
			t.Fatal("dataVolumeOptions accepted a size that is not a size")
		}
	})
}

// TestDatavolStatusJSONShape pins the machine interface of `k3sm datavol status
// -o json`: the shape a script parses, and the fact that an unprivileged run
// answers at all.
func TestDatavolStatusJSONShape(t *testing.T) {
	dir := t.TempDir()
	mountpoint := filepath.Join(dir, "var", "lib", "k3sm")
	if err := os.MkdirAll(mountpoint, 0o750); err != nil {
		t.Fatalf("create the mount point: %v", err)
	}
	recordPath := filepath.Join(dir, "io.k3sm.datavol.json")
	rec := dataroot.Record{
		Version:    dataroot.RecordVersion,
		UUID:       "6DEAE471-6CDE-4A4E-88A1-6A7B4DEF2DDD",
		Name:       "k3sm",
		Mountpoint: mountpoint,
		QuotaBytes: 100 << 30,
		CreatedBy:  "k3sm test",
		CreatedAt:  "2026-09-13T00:00:00Z",
	}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("encode the record: %v", err)
	}
	if err := os.WriteFile(recordPath, data, 0o644); err != nil {
		t.Fatalf("write the record: %v", err)
	}
	// A leftover pre-migration copy beside the data root, with something in it.
	preVolume := mountpoint + datavol.PreVolumeSuffix
	if err := os.MkdirAll(filepath.Join(preVolume, "server", "db"), 0o750); err != nil {
		t.Fatalf("create the pre-volume copy: %v", err)
	}
	const dbBytes = 4096
	if err := os.WriteFile(filepath.Join(preVolume, "server", "db", "state.db"), bytes.Repeat([]byte("x"), dbBytes), 0o644); err != nil {
		t.Fatalf("write the pre-volume datastore: %v", err)
	}

	var out bytes.Buffer
	if err := runDatavolStatus([]string{"--record", recordPath, "--mountpoint", mountpoint, "-o", "json"}, &out); err != nil {
		t.Fatalf("datavol status: %v", err)
	}

	var got datavolStatusReport
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("the JSON does not parse: %v\n%s", err, out.String())
	}
	if got.Record == nil || got.Record.UUID != rec.UUID || got.Record.QuotaBytes != rec.QuotaBytes {
		t.Errorf("record = %+v, want the one on disk", got.Record)
	}
	// The temp directory is not a mount point, which is exactly the posture the
	// report must not dress up as a mounted volume.
	if got.Mounted {
		t.Errorf("mounted = true for %s, which is a plain directory", mountpoint)
	}
	if got.Statfs != nil {
		t.Errorf("statfs = %+v, want it omitted while nothing is mounted", got.Statfs)
	}
	if !got.PreVolume.Present {
		t.Errorf("preVolume.present = false, but %s is there", preVolume)
	}
	if got.PreVolume.Bytes != dbBytes {
		t.Errorf("preVolume.bytes = %d, want %d", got.PreVolume.Bytes, dbBytes)
	}

	t.Run("the text screen names the same facts", func(t *testing.T) {
		var text bytes.Buffer
		if err := runDatavolStatus([]string{"--record", recordPath, "--mountpoint", mountpoint}, &text); err != nil {
			t.Fatalf("datavol status: %v", err)
		}
		for _, want := range []string{"volume", rec.Name, rec.UUID, "quota", datavol.FormatSize(rec.QuotaBytes), "pre-volume"} {
			if !strings.Contains(text.String(), want) {
				t.Errorf("the text screen does not name %q:\n%s", want, text.String())
			}
		}
	})

	t.Run("a Mac with no record says so instead of failing", func(t *testing.T) {
		var text bytes.Buffer
		if err := runDatavolStatus([]string{"--record", filepath.Join(dir, "absent.json"), "--mountpoint", mountpoint}, &text); err != nil {
			t.Fatalf("datavol status: %v", err)
		}
		if !strings.Contains(text.String(), "no data volume") {
			t.Errorf("status on a Mac with no record printed %q", text.String())
		}
	})

	t.Run("an unknown output format is refused", func(t *testing.T) {
		var text bytes.Buffer
		if err := runDatavolStatus([]string{"--record", recordPath, "-o", "yaml"}, &text); err == nil {
			t.Fatal("datavol status accepted an output format it cannot render")
		}
	})
}
