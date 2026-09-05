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

import "fmt"

// PodSecurityLevel is a Pod Security Standards level as the PodSecurity
// admission plugin names it in a PodSecurityConfiguration.
type PodSecurityLevel string

// The three Pod Security Standards levels. On native Darwin, privileged/caps/
// seccomp are moot; the meaningful baseline axis is hostPath + hostNetwork/
// hostPID/hostPort, and restricted additionally constrains runAsUser — which is
// why restricted is an OBSERVATION level here and never an enforcement one (it
// would collide head-on with the foreign-uid VAP, which is the actual guard).
const (
	PodSecurityLevelPrivileged PodSecurityLevel = "privileged"
	PodSecurityLevelBaseline   PodSecurityLevel = "baseline"
	PodSecurityLevelRestricted PodSecurityLevel = "restricted"
)

// PodSecurityPinnedVersion is the policy version every defaults entry pins
// (enforce-version/warn-version/audit-version). PINNED to the vendored k8s minor
// — NEVER "latest": "latest" would silently retarget every level on a
// control-plane upgrade, turning a kube bump into an unreviewed policy change.
const PodSecurityPinnedVersion = "v1.36"

// The shipped cluster-default PSA level tuple (the warn-first posture). These three constants ARE the posture; nothing else in the tree
// decides a level:
//
//   - DefaultPodSecurityEnforceLevel is privileged, i.e. admission rejects
//     NOTHING. The baseline-ENFORCE cutover is exactly this one value
//     becoming PodSecurityLevelBaseline (operators can already take it per-boot
//     with `k3sm server --psa-enforce-baseline`, which is argv-reversible: the
//     config file is re-rendered on every boot, so dropping the flag reverts the
//     posture).
//   - PodSecurityWarnLevel is baseline: a baseline-violating pod is ADMITTED and
//     the author gets a kubectl warning naming the violation.
//   - PodSecurityAuditLevel is restricted: restricted-level violations are
//     recorded as audit annotations in the audit log. Res.2 asks for
//     "baseline-warn + restricted-warn", and a PodSecurityConfiguration carries
//     exactly ONE level per axis — so the stricter level rides the axis that is
//     observation-only by construction, which is what "audit-observable, zero
//     rejection" means.
//
// PSA here is conformance-surface + defense-in-depth, NOT the privilege boundary
// — the foreign-uid VAP (see foreignuser.go) and the runtimed Seatbelt profile
// stay that.
const (
	DefaultPodSecurityEnforceLevel = PodSecurityLevelPrivileged
	PodSecurityWarnLevel           = PodSecurityLevelBaseline
	PodSecurityAuditLevel          = PodSecurityLevelRestricted
)

// PodSecurityAdmissionConfigYAML renders the apiserver's
// --admission-control-config-file content: an apiserver.config.k8s.io/v1
// AdmissionConfiguration embedding the pod-security.admission.config.k8s.io/v1
// PodSecurityConfiguration cluster defaults. Both apiVersions are pinned to the
// vendored k8s v1.36.2.
//
// It is a PURE function and the SINGLE authority for the level tuple: enforce is
// the caller's argument (DefaultPodSecurityEnforceLevel ships it), warn and audit
// are the constants above. Callers own the file (path, mode, when it is written)
// and the argv; they never re-decide a level.
//
// exemptions is deliberately EMPTY (usernames/runtimeClasses/namespaces all []):
// warn-mode needs none — nothing is rejected — and the enforce cutover picks
// exemptions from pre-flight scan evidence, never from a pre-baked guess that
// would silently carry a hole into enforcement.
func PodSecurityAdmissionConfigYAML(enforce PodSecurityLevel) string {
	return fmt.Sprintf(`apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: PodSecurity
  configuration:
    apiVersion: pod-security.admission.config.k8s.io/v1
    kind: PodSecurityConfiguration
    defaults:
      enforce: %s
      enforce-version: %s
      warn: %s
      warn-version: %s
      audit: %s
      audit-version: %s
    exemptions:
      usernames: []
      runtimeClasses: []
      namespaces: []
`, enforce, PodSecurityPinnedVersion,
		PodSecurityWarnLevel, PodSecurityPinnedVersion,
		PodSecurityAuditLevel, PodSecurityPinnedVersion)
}
