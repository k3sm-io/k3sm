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

// Package policy provisions k3sm's admission guardrails as
// ValidatingAdmissionPolicies (GA since 1.30, so no webhook server is needed — the
// apiserver evaluates the CEL in-process), idempotently at server start.
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
// Two are Warn advisories (M3.1) that surface honest k3sm datapath divergences to
// kubectl WITHOUT rejecting the Service (failurePolicy Ignore so they can only
// ever warn):
//   - externalTrafficPolicy: Local is not honored (the userspace splice does not
//     preserve client source IP — only Cluster).
//   - UDP Service ports have no datapath yet (the proxy opens no UDP listener).
//
// One is a MUTATING policy (B76) — a MutatingAdmissionPolicy (beta,
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
// CONFORMANCE requirement: a k3sm DaemonSet MUST declare
// nodeSelector: kubernetes.io/os=darwin in its OWN pod template. The os=darwin Deny VAP
// (the intent guard) still requires that selector on every pod; B76 injects only the
// toleration and deliberately does not supply the selector (injecting it would override
// the DS's placement, Res.7).
package policy
