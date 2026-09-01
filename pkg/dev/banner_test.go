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

	"k3sm.io/k3sm/pkg/install"
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

// TestDatapathBannerNamesTheRootPodPosture is the B210 gate: the `--datapath`
// banner must state that pods on that tier run as ROOT.
//
// The M8 gate run confirmed uid=0 inside a --datapath pod. The chain is
// provider.PodExecutionUID's: the provider sets no PodBox uid/gid, so runtimed
// resolves Credential{Drop: false}, so the pod keeps the daemon identity — and
// --datapath needs root. That is strictly worse than the documented shipped
// posture (the installed LaunchDaemon runs as install.DefaultServiceUser) and
// nothing in the banner or the docs said so, which made it invisible rather than
// accepted. This asserts the disclosure, NOT a behavior change: whether the dev
// tier should default a runAsUser is a separate decision, deliberately not taken.
//
// Golden-backed on BOTH sides, which is what makes it non-vacuous. The golden
// comparison reds if the line is removed from FidelityBanner; the content
// assertions below run against the GOLDEN BYTES, so re-generating the golden to
// match a stripped banner reds too. One of the two locks always fires.
func TestDatapathBannerNamesTheRootPodPosture(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join("testdata", "banner_datapath.txt"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if got := FidelityBanner(DatapathDirect, runtimeRuntimed); got != string(golden) {
		t.Errorf("--datapath banner does not match its golden:\n--- got ---\n%s\n--- want ---\n%s", got, golden)
	}
	for _, must := range []string{
		"pod identity:",
		"ROOT (uid 0)",
		"securityContext.runAsUser",
		install.DefaultServiceUser,
		"dev-only",
	} {
		if !strings.Contains(string(golden), must) {
			t.Errorf("--datapath banner golden missing %q — the root-pod posture is undisclosed on the tier where it is true", must)
		}
	}
	// The disclosure must not overclaim in the other direction: pods on this tier
	// ARE still Seatbelt-confined, and saying otherwise would be its own lie.
	if !strings.Contains(string(golden), "Seatbelt") {
		t.Errorf("--datapath banner golden dropped the Seatbelt confinement statement")
	}
	// The rootless tier must NOT claim root — it runs as the invoking user.
	rootless := FidelityBanner(DatapathNone, runtimeRuntimed)
	if strings.Contains(rootless, "ROOT (uid 0)") {
		t.Errorf("rootless banner claims pods run as root:\n%s", rootless)
	}
	if !strings.Contains(rootless, "pod identity:") {
		t.Errorf("rootless banner omits the pod-identity axis entirely:\n%s", rootless)
	}
}
