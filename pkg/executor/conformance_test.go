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

package executor

import (
	"os"
	"testing"

	"sigs.k8s.io/yaml"
)

// auditRuleDoc / auditPolicyDocParsed mirror the audit.k8s.io/v1 Policy shape the
// test asserts against. Parsed as plain YAML (json tags for sigs.k8s.io/yaml) so
// the test pins the FILE CONTENT, not a Go type round-trip.
type auditRuleDoc struct {
	Level     string   `json:"level"`
	Users     []string `json:"users"`
	Verbs     []string `json:"verbs"`
	Resources []struct {
		Group     string   `json:"group"`
		Resources []string `json:"resources"`
	} `json:"resources"`
	Namespaces      []string `json:"namespaces"`
	NonResourceURLs []string `json:"nonResourceURLs"`
}

type auditPolicyParsed struct {
	APIVersion string         `json:"apiVersion"`
	Kind       string         `json:"kind"`
	Rules      []auditRuleDoc `json:"rules"`
}

// psaConfigParsed / admissionConfigParsed mirror the AdmissionConfiguration +
// embedded PodSecurityConfiguration shape.
type psaConfigParsed struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Defaults   map[string]string `json:"defaults"`
	Exemptions struct {
		Usernames      []string `json:"usernames"`
		RuntimeClasses []string `json:"runtimeClasses"`
		Namespaces     []string `json:"namespaces"`
	} `json:"exemptions"`
}

type admissionConfigParsed struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Plugins    []struct {
		Name          string          `json:"name"`
		Configuration psaConfigParsed `json:"configuration"`
	} `json:"plugins"`
}

// requireMetadataOnly walks EVERY rule and fails on any level that is not
// Metadata or None — the SECURITY-BINDING structural invariant (Res.4): no
// Request/RequestResponse rule anywhere means no Secret cleartext at rest,
// regardless of rule ordering mistakes in a future edit.
func requireMetadataOnly(t *testing.T, rules []auditRuleDoc) {
	t.Helper()
	for i, r := range rules {
		switch r.Level {
		case "Metadata", "None":
		default:
			t.Errorf("audit rule %d: level %q — the policy must be STRUCTURALLY Metadata/None-only (never Request/RequestResponse)", i, r.Level)
		}
	}
}

// TestProvisionConformanceConfigPinned pins the M10.0 provision write (Res.3/4):
// writeConformanceConfig produces the three artifacts (0700 audit dir + the two
// 0600 config files), the GV literals are exactly the vendored-k8s pins, the
// audit policy is structurally Metadata/None-only with secrets/configmaps as the
// ordered FIRST rule and a Metadata catch-all LAST, and the PSA config embeds
// the PodSecurityConfiguration.
func TestProvisionConformanceConfigPinned(t *testing.T) {
	wd := t.TempDir()
	if err := writeConformanceConfig(wd, false); err != nil {
		t.Fatalf("writeConformanceConfig: %v", err)
	}

	t.Run("audit dir 0700", func(t *testing.T) {
		fi, err := os.Stat(auditDir(wd))
		if err != nil {
			t.Fatalf("audit dir: %v", err)
		}
		if !fi.IsDir() || fi.Mode().Perm() != 0o700 {
			t.Errorf("audit dir mode = %v, want dir 0700", fi.Mode())
		}
	})

	t.Run("audit policy", func(t *testing.T) {
		b, err := os.ReadFile(auditPolicyPath(wd))
		if err != nil {
			t.Fatalf("read audit policy: %v", err)
		}
		if fi, _ := os.Stat(auditPolicyPath(wd)); fi.Mode().Perm() != 0o600 {
			t.Errorf("audit policy mode = %v, want 0600", fi.Mode())
		}
		var p auditPolicyParsed
		if err := yaml.Unmarshal(b, &p); err != nil {
			t.Fatalf("parse audit policy: %v", err)
		}
		if p.APIVersion != "audit.k8s.io/v1" || p.Kind != "Policy" {
			t.Errorf("audit policy GV = %s/%s, want audit.k8s.io/v1 Policy (pinned, Res.3)", p.APIVersion, p.Kind)
		}
		if len(p.Rules) < 2 {
			t.Fatalf("audit policy has %d rules, want >= 2 (secrets/configmaps first + catch-all last)", len(p.Rules))
		}
		requireMetadataOnly(t, p.Rules)

		// The ordered FIRST rule pins secrets + configmaps (core group) at Metadata/None.
		first := p.Rules[0]
		if len(first.Resources) != 1 || first.Resources[0].Group != "" {
			t.Fatalf("first rule must scope the core group, got %+v", first.Resources)
		}
		got := map[string]bool{}
		for _, r := range first.Resources[0].Resources {
			got[r] = true
		}
		if !got["secrets"] || !got["configmaps"] {
			t.Errorf("first rule resources = %v, must pin secrets AND configmaps", first.Resources[0].Resources)
		}

		// The LAST rule is the explicit Metadata catch-all: level Metadata, no scoping.
		last := p.Rules[len(p.Rules)-1]
		if last.Level != "Metadata" {
			t.Errorf("last rule level = %q, want the Metadata catch-all", last.Level)
		}
		if len(last.Resources) != 0 || len(last.Users) != 0 || len(last.Verbs) != 0 || len(last.Namespaces) != 0 || len(last.NonResourceURLs) != 0 {
			t.Errorf("last rule must be an UNSCOPED catch-all, got %+v", last)
		}
	})

	t.Run("admission config", func(t *testing.T) {
		b, err := os.ReadFile(admissionConfigPath(wd))
		if err != nil {
			t.Fatalf("read admission config: %v", err)
		}
		if fi, _ := os.Stat(admissionConfigPath(wd)); fi.Mode().Perm() != 0o600 {
			t.Errorf("admission config mode = %v, want 0600", fi.Mode())
		}
		var ac admissionConfigParsed
		if err := yaml.Unmarshal(b, &ac); err != nil {
			t.Fatalf("parse admission config: %v", err)
		}
		if ac.APIVersion != "apiserver.config.k8s.io/v1" || ac.Kind != "AdmissionConfiguration" {
			t.Errorf("admission config GV = %s/%s, want apiserver.config.k8s.io/v1 AdmissionConfiguration (pinned)", ac.APIVersion, ac.Kind)
		}
		if len(ac.Plugins) != 1 || ac.Plugins[0].Name != "PodSecurity" {
			t.Fatalf("plugins = %+v, want exactly the PodSecurity plugin", ac.Plugins)
		}
		psa := ac.Plugins[0].Configuration
		if psa.APIVersion != "pod-security.admission.config.k8s.io/v1" || psa.Kind != "PodSecurityConfiguration" {
			t.Errorf("PSA GV = %s/%s, want pod-security.admission.config.k8s.io/v1 PodSecurityConfiguration (pinned)", psa.APIVersion, psa.Kind)
		}
	})
}

// TestPSADefaultLevel pins the PSA level tuple via the PURE renderer for BOTH
// flag values (Res.2): warn-by-default (enforce stays privileged) and
// enforce-under-flag (baseline, everything else unchanged). Versions are PINNED
// v1.36 — never "latest" — and exemptions stay EMPTY (the B71 enforce cutover
// decides exemptions with pre-flight evidence, never pre-baked).
func TestPSADefaultLevel(t *testing.T) {
	for _, tc := range []struct {
		name            string
		enforceBaseline bool
		wantEnforce     string
	}{
		{"shipped default is baseline-warn (enforce privileged)", false, "privileged"},
		{"--psa-enforce-baseline flips enforce to baseline", true, "baseline"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var ac admissionConfigParsed
			if err := yaml.Unmarshal([]byte(admissionConfigYAML(tc.enforceBaseline)), &ac); err != nil {
				t.Fatalf("parse rendered admission config: %v", err)
			}
			if len(ac.Plugins) != 1 {
				t.Fatalf("plugins = %+v, want exactly one", ac.Plugins)
			}
			psa := ac.Plugins[0].Configuration
			want := map[string]string{
				"enforce":         tc.wantEnforce,
				"enforce-version": "v1.36",
				"warn":            "baseline",
				"warn-version":    "v1.36",
				"audit":           "restricted",
				"audit-version":   "v1.36",
			}
			for k, v := range want {
				if got := psa.Defaults[k]; got != v {
					t.Errorf("defaults[%s] = %q, want %q", k, got, v)
				}
			}
			for k, v := range psa.Defaults {
				if v == "latest" {
					t.Errorf("defaults[%s] = latest — versions must be PINNED, never latest", k)
				}
			}
			if len(psa.Exemptions.Usernames) != 0 || len(psa.Exemptions.RuntimeClasses) != 0 || len(psa.Exemptions.Namespaces) != 0 {
				t.Errorf("exemptions must be EMPTY (B71 decides them with pre-flight evidence), got %+v", psa.Exemptions)
			}
		})
	}
}

// TestConformanceConfigOverwriteOnBoot pins the overwrite-on-boot contract: the
// config files track the BINARY (mirroring writeTokenFile, not the Stat-guarded
// writeServiceAccountKeys) — a stale pre-existing file is refreshed, including
// a PSA posture change between boots (the argv-reversible B71 cutover).
func TestConformanceConfigOverwriteOnBoot(t *testing.T) {
	wd := t.TempDir()
	if err := writeConformanceConfig(wd, true); err != nil {
		t.Fatalf("first writeConformanceConfig: %v", err)
	}
	// Pre-seed both files with stale garbage (simulating a previous binary's output).
	for _, p := range []string{auditPolicyPath(wd), admissionConfigPath(wd)} {
		if err := os.WriteFile(p, []byte("level: RequestResponse # STALE\n"), 0o600); err != nil {
			t.Fatalf("seed stale %s: %v", p, err)
		}
	}

	if err := writeConformanceConfig(wd, false); err != nil {
		t.Fatalf("re-run writeConformanceConfig: %v", err)
	}
	if got, _ := os.ReadFile(auditPolicyPath(wd)); string(got) != auditPolicyDoc {
		t.Errorf("audit policy not refreshed on boot:\n%s", got)
	}
	if got, _ := os.ReadFile(admissionConfigPath(wd)); string(got) != admissionConfigYAML(false) {
		t.Errorf("admission config not refreshed on boot (must track the flag, incl. reverting the cutover):\n%s", got)
	}
}
