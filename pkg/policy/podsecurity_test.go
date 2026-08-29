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

package policy

import (
	"regexp"
	"testing"

	"sigs.k8s.io/yaml"
)

// psaDefaultsDoc / psaExemptionsDoc / psaConfigDoc / admissionConfigDoc mirror the
// apiserver.config.k8s.io/v1 AdmissionConfiguration + embedded
// pod-security.admission.config.k8s.io/v1 PodSecurityConfiguration shape. The
// gate PARSES the rendered document into these (yaml.UnmarshalStrict — an
// unknown or misspelled key is a failure, not a silently-ignored line); it never
// string-matches the template, because a substring match cannot tell
// `enforce: baseline` from `warn: baseline`.
type psaDefaultsDoc struct {
	Enforce        string `json:"enforce"`
	EnforceVersion string `json:"enforce-version"`
	Warn           string `json:"warn"`
	WarnVersion    string `json:"warn-version"`
	Audit          string `json:"audit"`
	AuditVersion   string `json:"audit-version"`
}

type psaExemptionsDoc struct {
	Usernames      []string `json:"usernames"`
	RuntimeClasses []string `json:"runtimeClasses"`
	Namespaces     []string `json:"namespaces"`
}

type psaConfigDoc struct {
	APIVersion string           `json:"apiVersion"`
	Kind       string           `json:"kind"`
	Defaults   psaDefaultsDoc   `json:"defaults"`
	Exemptions psaExemptionsDoc `json:"exemptions"`
}

type admissionConfigDoc struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Plugins    []struct {
		Name          string       `json:"name"`
		Configuration psaConfigDoc `json:"configuration"`
	} `json:"plugins"`
}

// psaVersionRe pins the shape of every *-version value: an explicit vX.Y minor.
// "latest" (the upstream default) is the failure this asserts against — it would
// retarget all three levels on a control-plane upgrade.
var psaVersionRe = regexp.MustCompile(`^v1\.\d+$`)

// parsePSAConfig renders through the REAL production renderer and returns the
// parsed PodSecurityConfiguration, failing on any structural surprise.
func parsePSAConfig(t *testing.T, enforce PodSecurityLevel) psaConfigDoc {
	t.Helper()
	var ac admissionConfigDoc
	if err := yaml.UnmarshalStrict([]byte(PodSecurityAdmissionConfigYAML(enforce)), &ac); err != nil {
		t.Fatalf("parse rendered admission config: %v", err)
	}
	if ac.APIVersion != "apiserver.config.k8s.io/v1" || ac.Kind != "AdmissionConfiguration" {
		t.Fatalf("admission config GV = %s/%s, want the pinned apiserver.config.k8s.io/v1 AdmissionConfiguration", ac.APIVersion, ac.Kind)
	}
	if len(ac.Plugins) != 1 || ac.Plugins[0].Name != "PodSecurity" {
		t.Fatalf("plugins = %+v, want exactly the PodSecurity plugin", ac.Plugins)
	}
	psa := ac.Plugins[0].Configuration
	if psa.APIVersion != "pod-security.admission.config.k8s.io/v1" || psa.Kind != "PodSecurityConfiguration" {
		t.Fatalf("PSA GV = %s/%s, want the pinned pod-security.admission.config.k8s.io/v1 PodSecurityConfiguration", psa.APIVersion, psa.Kind)
	}
	return psa
}

// TestPSADefaultLevel is the B71 gate: it pins the cluster-default Pod Security
// Admission level tuple k3sm ships, by rendering through the production renderer
// and PARSING the result.
//
// The SAFETY PROPERTY is the first subtest: the shipped default must be
// warn-only — enforce=privileged, i.e. admission rejects nothing (Res.2). PSA is
// conformance-surface + defense-in-depth here, NOT the privilege boundary (the
// foreign-uid VAP + Seatbelt stay that), so a silent warn→enforce drift would be
// a rejection surface nobody signed off; flipping DefaultPodSecurityEnforceLevel
// to baseline turns this test red on purpose. The baseline-ENFORCE cutover is a
// separate operator decision taken with pre-flight scan evidence.
func TestPSADefaultLevel(t *testing.T) {
	t.Run("shipped default is warn-only (enforce=privileged)", func(t *testing.T) {
		psa := parsePSAConfig(t, DefaultPodSecurityEnforceLevel)
		if got := PodSecurityLevel(psa.Defaults.Enforce); got != PodSecurityLevelPrivileged {
			t.Errorf("defaults.enforce = %q, want %q — the SHIPPED posture rejects NOTHING (Res.2 warn-first)", got, PodSecurityLevelPrivileged)
		}
	})

	for _, tc := range []struct {
		name        string
		enforce     PodSecurityLevel
		wantEnforce PodSecurityLevel
	}{
		{"warn-first default renders enforce=privileged", DefaultPodSecurityEnforceLevel, PodSecurityLevelPrivileged},
		{"the B71 cutover renders enforce=baseline, levels otherwise unchanged", PodSecurityLevelBaseline, PodSecurityLevelBaseline},
	} {
		t.Run(tc.name, func(t *testing.T) {
			psa := parsePSAConfig(t, tc.enforce)
			d := psa.Defaults

			if PodSecurityLevel(d.Enforce) != tc.wantEnforce {
				t.Errorf("defaults.enforce = %q, want %q", d.Enforce, tc.wantEnforce)
			}
			// warn=baseline is the interactive half of "baseline-warn +
			// restricted-warn"; audit=restricted is the recorded half (one level
			// per axis, so the stricter one rides the observation-only axis).
			if PodSecurityLevel(d.Warn) != PodSecurityLevelBaseline {
				t.Errorf("defaults.warn = %q, want %q — the baseline warning is the whole point of the warn-first slice", d.Warn, PodSecurityLevelBaseline)
			}
			if PodSecurityLevel(d.Audit) != PodSecurityLevelRestricted {
				t.Errorf("defaults.audit = %q, want %q — restricted violations must stay audit-observable", d.Audit, PodSecurityLevelRestricted)
			}

			// Every level is pinned to an explicit minor, never "latest".
			for _, v := range []struct{ field, val string }{
				{"enforce-version", d.EnforceVersion},
				{"warn-version", d.WarnVersion},
				{"audit-version", d.AuditVersion},
			} {
				if v.val != PodSecurityPinnedVersion {
					t.Errorf("defaults.%s = %q, want the pinned %q", v.field, v.val, PodSecurityPinnedVersion)
				}
				if !psaVersionRe.MatchString(v.val) {
					t.Errorf("defaults.%s = %q — must be an explicit vX.Y minor, never latest (a kube bump would silently retarget the level)", v.field, v.val)
				}
			}

			// Exemptions stay EMPTY: warn-mode needs none, and the enforce
			// cutover picks them from pre-flight evidence, never pre-baked.
			if e := psa.Exemptions; len(e.Usernames) != 0 || len(e.RuntimeClasses) != 0 || len(e.Namespaces) != 0 {
				t.Errorf("exemptions must be EMPTY, got %+v", e)
			}
		})
	}
}
