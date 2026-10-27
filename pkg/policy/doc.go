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
// plus two MutatingAdmissionPolicies — and the plain (non-admission) default
// policy objects, today the memory-only LimitRange.
//
// Four are Deny guards:
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
//   - reserved LoadBalancer port: a type: LoadBalancer Service may not declare a
//     port in ports.Reserved: the NodePort range and the kubelet API port, which
//     k3sm's own node listeners hold, and the macOS host-service ports (22, 53,
//     88, 445, 548, 631), which a tenant listener would keep their service from
//     binding. The rejection is the legible half of a guard svclb also enforces
//     at the datapath.
//   - denied local port: a Service may not publish a port every confined pod's
//     sandbox denies connect() to (the node's loopback datastore client port and, in
//     the etcd posture, the member's loopback metrics port; see cmd/k3sm's
//     opts.deniedLocalPorts()). Unlike the one above this has NO type
//     scope: the sandbox denies by port number whatever address the pod dials, so
//     a ClusterIP and a headless Service are as unreachable as a LoadBalancer.
//
// Five are Warn advisories that surface an honest k3sm divergence to kubectl
// WITHOUT rejecting the object (failurePolicy Ignore so they can only ever warn).
// Two are on Services, for datapath divergences:
//   - externalTrafficPolicy: Local is not honored (the userspace splice does not
//     preserve client source IP — only Cluster).
//   - a UDP port the proxy does not serve: a UDP nodePort, a UDP LoadBalancer
//     port, or a UDP ClusterIP port below 1024. A UDP ClusterIP port of 1024 or
//     above is relayed and draws no warning.
//
// Three are on Pod create:
//   - provider toleration: a pod with no toleration for the provider taint, which
//     the scheduler would leave Unschedulable.
//   - internet-egress annotation: a hand-set opt-in annotation meant to be stamped
//     by a controller acting on the pod's behalf.
//   - Xcode toolchain annotation: the same, for the annotation that grants read
//     access to the node's Xcode developer directory.
//
// Two are MUTATING policies — MutatingAdmissionPolicies
// (admissionregistration.k8s.io/v1), which unlike the Deny/Warn VAPs above CHANGE
// the stored object. Both inject the provider toleration and NEVER the
// kubernetes.io/os=darwin nodeSelector — a DaemonSet declares its own placement
// intent and overriding it would defeat the DS's selector/affinity — and
// both use a JSONPatch on the atomic tolerations list (not an ApplyConfiguration,
// which would clobber the DefaultTolerationSeconds-injected NoExecute tolerations):
//   - daemonset-template-provider-toleration: on DaemonSet CREATE and UPDATE, adds
//     the toleration to spec.template.spec. The DaemonSet controller decides which
//     nodes should run a daemon pod from the TEMPLATE, so without it every node's
//     k3sm.io/provider:NoSchedule taint keeps desiredNumberScheduled at 0. A
//     template that already tolerates the taint is not matched, so an UPDATE of it
//     is not mutated. A DaemonSet stored before this policy existed gets the
//     toleration on its first UPDATE, which bumps its generation and controller
//     revision and rolls its pods once.
//   - daemonset-provider-toleration: on Pod CREATE, adds the toleration to a
//     DaemonSet-owned pod. It now covers only DaemonSets stored before the template
//     policy existed and pods created directly with a DaemonSet ownerReference.
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
// untouched: this package selects on nothing, and the ONE delete it performs is
// confined to the two objects EnsureRejectServiceDeniedLocalPort owns, on the
// empty denied-port set — a guard for a port number nothing denies any more must
// not outlive the deny it was provisioned for.
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
// the DS's placement).
package policy
