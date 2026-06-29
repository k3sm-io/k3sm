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
package policy
