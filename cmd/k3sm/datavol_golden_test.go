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
	"testing"

	"k3sm.io/k3sm/pkg/dataroot"
)

// TestDatavolStatusJSONGoldens pins the shape of `k3sm datavol status -o json`,
// which the macOS app's Storage tab decodes. Each case renders the report
// through the encoder runDatavolStatus uses and compares the bytes with
// testdata/datavol_status_json_<name>.json; the app vendors the same files.
// UPDATE_GOLDEN=1 rewrites them.
func TestDatavolStatusJSONGoldens(t *testing.T) {
	t.Parallel()

	rec := func(quota uint64, encrypted, adopted bool) *dataroot.Record {
		return &dataroot.Record{
			Version:    dataroot.RecordVersion,
			UUID:       "6DEAE471-6CDE-4A4E-88A1-6A7B4DEF2DDD",
			Name:       "k3sm",
			Mountpoint: "/var/lib/k3sm",
			QuotaBytes: quota,
			Encrypted:  encrypted,
			CreatedBy:  "k3sm 0.1.7",
			CreatedAt:  "2026-09-13T00:00:00Z",
			Adopted:    adopted,
		}
	}
	used := uint64(37580963840)

	for _, tc := range []struct {
		name   string
		report datavolStatusReport
	}{
		{"mounted", datavolStatusReport{
			Record:  rec(107374182400, false, false),
			Mounted: true,
			Statfs: &datavolStatfs{
				TotalBytes: 107374182400,
				AvailBytes: 69793218560,
				UsedBytes:  &used,
				UsedSource: "apfs",
			},
			PreVolume: datavolPreVolume{Present: true, Bytes: 4096},
		}},
		{"not-mounted", datavolStatusReport{Record: rec(0, true, true)}},
		{"no-record", datavolStatusReport{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetIndent("", "  ")
			if err := enc.Encode(tc.report); err != nil {
				t.Fatalf("encode: %v", err)
			}
			path := filepath.Join("testdata", "datavol_status_json_"+tc.name+".json")
			if os.Getenv("UPDATE_GOLDEN") == "1" {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden (UPDATE_GOLDEN=1 writes it): %v", err)
			}
			if !bytes.Equal(buf.Bytes(), want) {
				t.Errorf("%s drifted; rerun with UPDATE_GOLDEN=1 if intended\n got: %s\nwant: %s", path, buf.Bytes(), want)
			}
		})
	}
}
