// Package policy provisions k3sm's admission guardrails. In M1 that is the
// os=darwin ValidatingAdmissionPolicy: the INTENT guard that requires every Pod
// to target k3sm's darwin nodes via nodeSelector kubernetes.io/os=darwin, so a
// stray Linux pod is rejected at admission rather than landing on (or pending
// against) the only node.
//
// It pairs with the PLACEMENT guard provisioned on the node itself — the
// k3sm.io/provider:NoSchedule taint (see cmd/k3sm/node.go) — which keeps pods
// that lack the matching toleration off the node. Taint = where pods may land;
// admission policy = what the user must have declared.
//
// The policy is provisioned idempotently at server start via the
// admissionregistration/v1 API (ValidatingAdmissionPolicy is GA since 1.30, so
// no webhook server is needed — the apiserver evaluates the CEL in-process).
package policy
