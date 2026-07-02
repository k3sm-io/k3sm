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

package version

import (
	"runtime/debug"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/executor"
)

// buildInfo builds an injected ReadBuildInfo reader with a given main-module
// version, VCS settings, and deps, so the fallback path is exercised
// deterministically (never touching the ambient test binary's build info).
func buildInfo(mainVer, revision, vcsTime string, deps ...*debug.Module) func() (*debug.BuildInfo, bool) {
	return func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{
			Main: debug.Module{Path: "k3sm.io/k3sm", Version: mainVer},
			Settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: revision},
				{Key: "vcs.time", Value: vcsTime},
			},
			Deps: deps,
		}, true
	}
}

func dep(path, version string) *debug.Module {
	return &debug.Module{Path: path, Version: version}
}

// TestVersionFromBuildInfo is the B57 gate: it proves the stamped ldflags render
// verbatim (and win over build info), the unstamped path recovers version/commit
// /date + sibling SHAs from ReadBuildInfo, and the no-build-info path degrades
// without panic — while Info.String genuinely renders the aligned Kubernetes and
// kine versions (not a tautology on the input vars). Driven through the pure get
// core so subtests inject state instead of mutating package globals (race-clean).
func TestVersionFromBuildInfo(t *testing.T) {
	t.Parallel()

	const (
		kube = "v1.36.2"
		kine = "v1.14.2"
	)

	tests := []struct {
		name                    string
		version, commit, date   string
		reader                  func() (*debug.BuildInfo, bool)
		wantVersion, wantCommit string
		wantDate                string
		wantContains            []string
		wantNotContains         []string
	}{
		{
			name:    "stamped ldflags render verbatim and win over build info",
			version: "v1.4.0", commit: "abcdef1234567890", date: "2026-07-02T00:00:00Z",
			reader: buildInfo("(devel)", "IGNORED_REVISION", "IGNORED_TIME",
				dep("k3sm.io/apis", "v0.5.0-apis"),
				dep("k3sm.io/darwin-net", "v0.5.0-dnet"),
				dep("k3sm.io/runtimed", "v0.5.0-rtd")),
			wantVersion: "v1.4.0",
			wantCommit:  "abcdef1234567890",
			wantDate:    "2026-07-02T00:00:00Z",
			wantContains: []string{
				"k3sm v1.4.0", "abcdef1234567890", "2026-07-02T00:00:00Z",
				kube, kine,
				"k3sm.io/apis", "v0.5.0-apis", "v0.5.0-dnet", "v0.5.0-rtd",
			},
			wantNotContains: []string{"IGNORED_REVISION", "IGNORED_TIME"},
		},
		{
			name:    "unstamped falls back to ReadBuildInfo for version/commit/date + sibling SHAs",
			version: "dev", commit: "", date: "",
			reader: buildInfo("v9.9.9-recovered", "cafebabedeadbeef", "2026-01-02T03:04:05Z",
				dep("k3sm.io/apis", "v0.0.0-20260101000000-aaaaaaaaaaaa"),
				dep("k3sm.io/runtimed", "v0.0.0-20260101000000-bbbbbbbbbbbb")),
			wantVersion: "v9.9.9-recovered",
			wantCommit:  "cafebabedeadbeef",
			wantDate:    "2026-01-02T03:04:05Z",
			wantContains: []string{
				"k3sm v9.9.9-recovered", "cafebabedeadbeef", "2026-01-02T03:04:05Z",
				kube, kine,
				"k3sm.io/apis", "v0.0.0-20260101000000-aaaaaaaaaaaa",
				"k3sm.io/runtimed", "v0.0.0-20260101000000-bbbbbbbbbbbb",
				// A module absent from the deps renders honestly, not fabricated.
				"k3sm.io/darwin-net", "unknown",
			},
		},
		{
			name:    "unstamped dirty tree marks the recovered SHA as (dirty)",
			version: "dev", commit: "", date: "",
			reader: func() (*debug.BuildInfo, bool) {
				return &debug.BuildInfo{
					Main: debug.Module{Path: "k3sm.io/k3sm", Version: "(devel)"},
					Settings: []debug.BuildSetting{
						{Key: "vcs.revision", Value: "0badc0de0badc0de"},
						{Key: "vcs.time", Value: "2026-07-02T09:00:00Z"},
						{Key: "vcs.modified", Value: "true"},
					},
				}, true
			},
			wantVersion:  "dev",
			wantCommit:   "0badc0de0badc0de",
			wantDate:     "2026-07-02T09:00:00Z",
			wantContains: []string{"0badc0de0badc0de (dirty)", kube, kine},
		},
		{
			name:    "stamped commit is never tainted by this build's dirty tree",
			version: "v2.0.0", commit: "feedface00000000", date: "2026-07-02T10:00:00Z",
			reader: func() (*debug.BuildInfo, bool) {
				return &debug.BuildInfo{
					Main:     debug.Module{Path: "k3sm.io/k3sm", Version: "(devel)"},
					Settings: []debug.BuildSetting{{Key: "vcs.modified", Value: "true"}},
				}, true
			},
			wantVersion:     "v2.0.0",
			wantCommit:      "feedface00000000",
			wantDate:        "2026-07-02T10:00:00Z",
			wantContains:    []string{"feedface00000000", kube, kine},
			wantNotContains: []string{"(dirty)"},
		},
		{
			name:    "locally-replaced module renders replacement version, not the zero pin",
			version: "dev", commit: "", date: "",
			reader: func() (*debug.BuildInfo, bool) {
				return &debug.BuildInfo{
					Main: debug.Module{Path: "k3sm.io/k3sm", Version: "(devel)"},
					Deps: []*debug.Module{{
						Path:    "k3sm.io/apis",
						Version: "v0.0.0-00010101000000-000000000000",
						Replace: &debug.Module{Path: "../apis", Version: "(devel)"},
					}},
				}, true
			},
			wantVersion: "dev",
			wantContains: []string{
				"k3sm dev", kube, kine,
				"k3sm.io/apis", "(devel)",
			},
			wantNotContains: []string{"v0.0.0-00010101000000-000000000000"},
		},
		{
			name:    "no build info degrades to stamped-or-default without panic",
			version: "dev", commit: "", date: "",
			reader:      func() (*debug.BuildInfo, bool) { return nil, false },
			wantVersion: "dev", wantCommit: "", wantDate: "",
			wantContains: []string{"k3sm dev", kube, kine},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := get(tt.version, tt.commit, tt.date, kube, kine, tt.reader)

			if got.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", got.Version, tt.wantVersion)
			}
			if got.Commit != tt.wantCommit {
				t.Errorf("Commit = %q, want %q", got.Commit, tt.wantCommit)
			}
			if got.Date != tt.wantDate {
				t.Errorf("Date = %q, want %q", got.Date, tt.wantDate)
			}
			if got.KubeVersion != kube {
				t.Errorf("KubeVersion = %q, want %q", got.KubeVersion, kube)
			}
			if got.KineVersion != kine {
				t.Errorf("KineVersion = %q, want %q", got.KineVersion, kine)
			}

			rendered := got.String()
			for _, want := range tt.wantContains {
				if !strings.Contains(rendered, want) {
					t.Errorf("String() does not contain %q\n--- rendered ---\n%s", want, rendered)
				}
			}
			for _, no := range tt.wantNotContains {
				if strings.Contains(rendered, no) {
					t.Errorf("String() unexpectedly contains %q\n--- rendered ---\n%s", no, rendered)
				}
			}
		})
	}
}

// TestGetUsesExecutorAlignedVersions pins the single-source-of-truth wiring:
// Get()'s rendered aligned versions must equal pkg/executor's pinned defaults,
// so a bump to the control-plane pins can never silently desync the version
// output.
func TestGetUsesExecutorAlignedVersions(t *testing.T) {
	t.Parallel()
	got := Get()
	if got.KubeVersion != executor.DefaultKubeVersion {
		t.Errorf("KubeVersion = %q, want executor.DefaultKubeVersion %q", got.KubeVersion, executor.DefaultKubeVersion)
	}
	if got.KineVersion != executor.DefaultKineVersion {
		t.Errorf("KineVersion = %q, want executor.DefaultKineVersion %q", got.KineVersion, executor.DefaultKineVersion)
	}
	if !strings.Contains(got.String(), executor.DefaultKubeVersion) {
		t.Errorf("String() does not render the aligned Kubernetes version %q:\n%s", executor.DefaultKubeVersion, got.String())
	}
}
