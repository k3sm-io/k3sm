//go:build e2e

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

package e2e

import "testing"

// M10 conformance criterion stubs (docs/m10-plan.md §"Gate machinery", Res.9).
//
// These are authored as t.Skip'd TODO tests so the criterion set is VISIBLE and
// each criterion has a named home to grow into, WITHOUT yet being required. Per
// Res.9 a new conformance criterion is promoted into the required M2_CRITERIA/
// M4_CRITERIA sets (in hack/acceptance/m<n>.sh, enforced by the non-vacuous guard
// hack/lib/conformance.sh) ONLY in the PR that lands it green — never before, so a
// green gate is never regressed. Until then a skipped-but-not-required criterion is
// allowed: conformance.sh only fails on a missing/failed/SKIPPED *required* criterion,
// and none of these are in a required list. The eventual composite hack/acceptance/
// m10.sh execs the M10 slice once these land green.
//
// Criterion names carry the M10 tag (Res.9 — native sidecars / node Events are M10.x,
// NOT TestM2_*/TestM4_*).

// TestM10_AuditLogLevel is the M10.0 audit-logging criterion (Res.4): apply an object
// touching secrets/configmaps and assert the shipped audit policy records it at
// level: Metadata (or None) — NEVER Request/RequestResponse (no Secret cleartext at
// rest), with the audit file at a 0600, Seatbelt-denied, off-datastore-volume path.
func TestM10_AuditLogLevel(t *testing.T) {
	t.Skip("TODO(M10.0): assert the shipped audit policy records secrets/configmaps at level Metadata/None (never Request/RequestResponse) — B70")
}

// TestM10_PSADefaultWarn is the M10.0 Pod Security Admission criterion (Res.2): with
// the shipped --admission-control-config-file + PodSecurityConfiguration default, a
// baseline-violating pod is WARNED (audit-observable, zero rejection) pre-enforce;
// post-preflight the baseline-enforce cutover turns it into a 403. Carries a negative
// control — k3sm system pods + a baseline reference workload stay ADMITTED (Res.6).
func TestM10_PSADefaultWarn(t *testing.T) {
	t.Skip("TODO(M10.0): assert the PSA cluster-default (baseline-warn → enforce cutover) with a negative control — B71")
}

// TestM10_NativeSidecar is the M10.2 native-sidecar criterion (Res.8): an initContainer
// with restartPolicy:Always (the k8s 1.33 stable sidecar) STAYS RUNNING alongside the
// regular containers and tears down in reverse order — over the new apis PodBox/
// Container proto restart_policy field (never a k3sm.io/* annotation).
func TestM10_NativeSidecar(t *testing.T) {
	t.Skip("TODO(M10.2): assert an initContainer restartPolicy:Always sidecar stays Running + reverse-order teardown over the apis proto field — B73")
}

// TestM10_ProviderEvents is the M10.2 node-lifecycle-Events criterion: the provider's
// EventRecorder emits Pulled/Created/Started/Killing/BackOff so `kubectl describe pod`
// shows the container lifecycle (today the provider has no EventRecorder).
func TestM10_ProviderEvents(t *testing.T) {
	t.Skip("TODO(M10.2): assert the provider emits Pulled/Created/Started/Killing/BackOff lifecycle Events — B75")
}

// TestM10_PerPodIP is the M10.1 per-pod-IP criterion (Res.1): two pods on the same
// node each report a DISTINCT status.podIP (a real podnet /32, not podIP≈nodeIP), and
// a headless Service returns ALL backend pod IPs — proving the podnet adapter over
// supervisor.NodeNetwork on the converged runtimed path.
func TestM10_PerPodIP(t *testing.T) {
	t.Skip("TODO(M10.1): assert two same-node pods get distinct podnet /32s + a headless Service returns all pod IPs — B81 (blocked on M10.1 podnet wiring)")
}

// TestM10_ImagePullSecret is the M10.2 imagePullSecrets pull-auth criterion (Res.9):
// a pod carrying imagePullSecrets pulls a private image from an auth-gated (rejects-
// anonymous) IN-PROCESS loopback registry via a standard .dockerconfigjson Secret,
// WITH a mandatory negative control (the same image WITHOUT the secret + a cold cache
// → ImagePullBackOff, proving the secret was the enabler not an anonymous/cached pull)
// and the M2.6 confidentiality invariant (the resolved cred never lands in the pod
// fs/env, container logs, or Events). The pull path already exists (resolver.go +
// runtimed/pkg/image/pull.go); this criterion is LAB-PENDING on the e2e harness gaining
// an in-process authed-registry + native-exec OCI-image fixture (a separate prerequisite),
// so it ships as a structured placeholder rather than a fake body that falls back to
// Image:"native" (which would prove nothing).
func TestM10_ImagePullSecret(t *testing.T) {
	t.Skip("TODO(M10.2): assert a pod with imagePullSecrets pulls a private image from an auth-gated in-process registry (ggcr + httptest basic-auth, rejects anonymous) via a programmatically-built .dockerconfigjson Secret (fake testuser/testpass, no real cred); NEGATIVE CONTROL (mandatory) — the same image WITHOUT the secret + imagePullPolicy:Always (cache-cold) → container status waiting.reason ImagePullBackOff/ErrImagePull, proving the secret enabled the pull; CONFIDENTIALITY — after a successful pull assert the resolved credential is absent from the pod fs/env, container logs, and Events (the M2.6 cred-never-written-to-disk invariant) — B80 (blocked on an in-process authed-registry + native-exec OCI-image e2e harness fixture)")
}
