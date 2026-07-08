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

package dev

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFidelityBannerGolden pins the banner text against testdata goldens so its
// SAFE/NEEDS-datapath/UNFAITHFUL warnings cannot silently regress (a security-
// documentation invariant — the fidelity axis is surfaced at the entry point).
func TestFidelityBannerGolden(t *testing.T) {
	cases := []struct {
		name     string
		datapath string
		runtime  string
		golden   string
	}{
		{"rootless", DatapathNone, runtimeRuntimed, "banner_rootless.txt"},
		{"datapath", DatapathDirect, runtimeRuntimed, "banner_datapath.txt"},
		{"rootless-hostprocess", DatapathNone, runtimeHostProcess, "banner_rootless_hostprocess.txt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want, err := os.ReadFile(filepath.Join("testdata", tc.golden))
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}
			got := FidelityBanner(tc.datapath, tc.runtime)
			if got != string(want) {
				t.Errorf("banner mismatch for %s:\n--- got ---\n%s\n--- want ---\n%s", tc.name, got, want)
			}
		})
	}
}

// TestFidelityBannerContent asserts the load-bearing warnings are present
// regardless of the golden bytes — a belt-and-braces guard so a golden re-gen
// can't drop a critical line unnoticed.
func TestFidelityBannerContent(t *testing.T) {
	rootless := FidelityBanner(DatapathNone, runtimeRuntimed)
	for _, must := range []string{
		"datapath INERT (rootless)",
		"Service traffic needs --datapath",
		"NOT kind",
		"SAFE",
		"UNFAITHFUL",
		"Seatbelt-confined",
		"docs/UPSTREAM-ALIGNMENT.md",
		"docs/conformance-profile.md",
	} {
		if !strings.Contains(rootless, must) {
			t.Errorf("rootless banner missing %q", must)
		}
	}
	direct := FidelityBanner(DatapathDirect, runtimeRuntimed)
	if !strings.Contains(direct, "datapath is LIVE") {
		t.Errorf("datapath banner missing the LIVE posture line")
	}
	if strings.Contains(direct, "datapath INERT") {
		t.Errorf("datapath banner must not claim INERT")
	}
	// The hostprocess fallback must report pods run UNCONFINED honestly.
	hp := FidelityBanner(DatapathNone, runtimeHostProcess)
	if !strings.Contains(hp, "UNCONFINED") {
		t.Errorf("hostprocess banner missing the UNCONFINED isolation warning")
	}
	if strings.Contains(hp, "Seatbelt-confined via the k3sm-execshim") {
		t.Errorf("hostprocess banner must not claim Seatbelt confinement")
	}
}

func TestLoadImageLineStamped(t *testing.T) {
	line := LoadImageLine("/opt/k3sm/mybin")
	if !strings.HasPrefix(line, "image: /opt/k3sm/mybin") {
		t.Errorf("LoadImageLine = %q, want it to lead with the image: <abs> convention", line)
	}
	if !strings.Contains(line, LoadStamp) {
		t.Errorf("LoadImageLine = %q, want the NON-PORTABLE stamp", line)
	}
	if !strings.Contains(LoadStamp, "NON-PORTABLE") {
		t.Errorf("LoadStamp = %q, want it to warn NON-PORTABLE", LoadStamp)
	}
}
