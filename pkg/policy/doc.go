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

// Package policy provisions k3sm's cluster policy objects idempotently at server
// start: the admission guardrails — ValidatingAdmissionPolicies (GA since 1.30,
// so no webhook server is needed; the apiserver evaluates the CEL in-process)
// plus one MutatingAdmissionPolicy — and the plain (non-admission) default
// policy objects, today the memory-only LimitRange.
//
// Two are Deny guards:
//   - os=darwin (the INTENT guard): every Pod must target k3sm's darwin nodes via
//     nodeSelector kubernetes.io/os=darwin, so a stray Linux pod is rejected at
//     admission rather than landing on (or pending against) the only node. It
//     pairs with the PLACEMENT guard on the node — the k3sm.io/provider:NoSchedule
//     taint (see cmd/k3sm/node.go). Taint = where pods may land; admission =
//     what the user must have declared.
//   - foreign-user: a Pod may not request a uid/gid (runAsUser/runAsGroup/fsGroup/
//     supplementalGroups, across pod + every container shape) other than the
//     _k3sm identity, since the runtime has no per-pod uid/gid isolation — rejected
//     at admission, never silently coerced.
//
// Two are Warn advisories that surface honest k3sm datapath divergences to
// kubectl WITHOUT rejecting the Service (failurePolicy Ignore so they can only
// ever warn):
//   - externalTrafficPolicy: Local is not honored (the userspace splice does not
//     preserve client source IP — only Cluster).
//   - UDP Service ports have no datapath yet (the proxy opens no UDP listener).
//
// One is a MUTATING policy — a MutatingAdmissionPolicy (beta,
// admissionregistration.k8s.io/v1beta1), which unlike the Deny/Warn VAPs above CHANGES
// the stored object:
//   - daemonset-provider-toleration: a DaemonSet-owned pod is created by the DS
//     controller (in the kube-controller-manager), so the CREATE-Warn advisory never
//     reaches its author and the pod sits Unschedulable against the
//     k3sm.io/provider:NoSchedule taint. The policy appends the provider toleration
//     (JSONPatch on the atomic /spec/tolerations list — not an ApplyConfiguration that
//     would clobber the DefaultTolerationSeconds-injected NoExecute tolerations) so DS
//     pods schedule. It injects ONLY the toleration, NEVER the
//     kubernetes.io/os=darwin nodeSelector — a DaemonSet declares its own placement
//     intent and overriding it would defeat the DS's selector/affinity (Res.7).
//
// One is a plain policy OBJECT, not an admission policy:
//   - the memory-only default LimitRange in the `default` namespace
//     (EnsureDefaultLimitRange): default/defaultRequest MEMORY per container —
//     memory is enforced by the runtime (rusage sampler → OOMKill) — and
//     deliberately NO cpu key anywhere (CPU is best-effort; a CPU default would
//     over-claim a guarantee k3sm cannot keep).
//
// PROVISIONING CONTRACT (every Ensure* here, one implementation — ensure.go):
// CREATE-OR-UPDATE. The object is created when absent and RECONCILED onto the
// current shape when its stored spec has drifted; an already-current object is not
// written at all. This replaced create-if-absent, which had frozen every
// policy's CEL — and the foreign-user policy's allowed uid — at whatever shape the
// cluster was first provisioned with, making any later fix inert on an existing
// datastore. The k3sm.io/managed label is stamped at create and is otherwise
// untouched: this package selects on nothing and deletes nothing.
//
// POSTURE INDEPENDENCE: every policy here is provisioned in EVERY --network
// posture. The foreign-user ceiling used to be gated on the netd-helper backend
// which let a `--network none`/`direct` cluster run with the guard absent.
//
// CONFORMANCE requirement: a k3sm DaemonSet MUST declare
// nodeSelector: kubernetes.io/os=darwin in its OWN pod template. The os=darwin Deny VAP
// (the intent guard) still requires that selector on every pod; the mutating policy
// injects only the
// toleration and deliberately does not supply the selector (injecting it would override
// the DS's placement, Res.7).
package policy
