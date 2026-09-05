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
	"fmt"
	"os"
	"path/filepath"

	"k3sm.io/k3sm/pkg/policy"
)

// The apiserver conformance config: the
// audit policy and the admission-control config (PSA PodSecurityConfiguration)
// the apiserver argv references. Both files TRACK THE BINARY — they are
// overwritten on every boot (mirroring writeTokenFile, NOT the Stat-guarded
// writeServiceAccountKeys), so a binary upgrade can never leave a stale policy
// on disk that argv silently keeps loading.

// auditDir is the audit-log directory (<workDir>/audit, sibling of db/ — same
// volume-off-the-datastore posture as the component logs; rotation bounds the
// worst case, see apiServerArgs). Created 0700: the log carries request
// metadata (usernames, object names) and must not be world-readable.
func auditDir(workDir string) string { return filepath.Join(workDir, "audit") }

// auditPolicyPath is the audit policy file --audit-policy-file loads.
func auditPolicyPath(workDir string) string { return filepath.Join(workDir, "audit-policy.yaml") }

// admissionConfigPath is the AdmissionConfiguration file
// --admission-control-config-file loads (carries the PSA cluster defaults).
func admissionConfigPath(workDir string) string {
	return filepath.Join(workDir, "admission-control.yaml")
}

// auditPolicyDoc is the shipped audit policy (Res.4). It is SECURITY-BINDING
// that the policy stays STRUCTURALLY Metadata/None-only: NO rule at level
// Request or RequestResponse may appear ANYWHERE in this file, so a Secret's
// cleartext payload can never land in the audit log at rest. Rules are ordered
// first-match: secrets/configmaps are pinned at Metadata FIRST (so no later
// edit can accidentally widen them), and an explicit Metadata catch-all is
// LAST. The apiVersion is pinned to the vendored k8s v1.36.2's audit.k8s.io/v1
// (Res.3). TestProvisionConformanceConfigPinned walks the parsed rules and
// enforces all of this.
const auditPolicyDoc = `apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: Metadata
  resources:
  - group: ""
    resources: ["secrets", "configmaps"]
- level: Metadata
`

// admissionConfigYAML renders the --admission-control-config-file content by
// delegating to pkg/policy, the SINGLE authority for the PSA level tuple
// (Res.2). The executor owns the FILE — path, 0600 mode, the provision-time
// write, and the argv that references it; policy owns WHAT the levels are, so
// the baseline-enforce cutover is one value there and not a second opinion here.
//
//   - enforceBaseline=false (the SHIPPED default): enforce stays privileged
//     (zero rejection); warn=baseline + audit=restricted make every violation
//     observable — the warn-first posture.
//   - enforceBaseline=true (the baseline-enforce cutover, via `k3sm server
//     --psa-enforce-baseline`): enforce flips to baseline; warn/audit unchanged.
func admissionConfigYAML(enforceBaseline bool) string {
	enforce := policy.DefaultPodSecurityEnforceLevel
	if enforceBaseline {
		enforce = policy.PodSecurityLevelBaseline
	}
	return policy.PodSecurityAdmissionConfigYAML(enforce)
}

// writeConformanceConfig lays down the apiserver conformance config artifacts in
// provision() (before startAPIServer — Res.3: argv referencing a missing file
// would wedge bring-up opaquely for the healthz timeout): the 0700 audit dir
// and the two 0600 config files, both overwritten on every boot (they track
// the binary).
func writeConformanceConfig(workDir string, psaEnforceBaseline bool) error {
	if err := os.MkdirAll(auditDir(workDir), 0o700); err != nil {
		return fmt.Errorf("mkdir audit dir: %w", err)
	}
	if err := os.WriteFile(auditPolicyPath(workDir), []byte(auditPolicyDoc), 0o600); err != nil {
		return fmt.Errorf("write audit policy: %w", err)
	}
	if err := os.WriteFile(admissionConfigPath(workDir), []byte(admissionConfigYAML(psaEnforceBaseline)), 0o600); err != nil {
		return fmt.Errorf("write admission-control config: %w", err)
	}
	return nil
}
