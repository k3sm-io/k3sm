package rbac

import (
	"context"
	"fmt"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	netv1 "k3sm.io/apis/net/v1"
)

// nodeDatapathRole / inPodReaderRole are the cluster-scoped / namespaced names of
// the objects this package provisions. Both carry the "k3sm:" prefix so they never
// collide with — nor are mistaken for — the apiserver's auto-reconciled default
// system:* roles and bindings, which this package must not author (see doc.go).
const (
	nodeDatapathRole = "k3sm:node-datapath"
	inPodReaderRole  = "k3sm:in-pod-reader"
)

// systemNodesGroup is the group every joined worker's system:node:<name> client
// cert carries (O=system:nodes). The node-datapath ClusterRoleBinding binds the
// datapath grant to THIS group; the group, and the stock system:node ClusterRole,
// are owned by the apiserver — k3sm references the group, never authors a system:*
// object.
const systemNodesGroup = "system:nodes"

// ConformanceNamespace / ConformanceServiceAccount name the ServiceAccount the
// in-pod-kubectl reference path runs as (docs/stockkitty-readiness.md →
// TestM2_InPodKubectl, the snapshotManager workload). Provision binds it to the
// minimal in-pod reader Role so that path keeps working once the authorizer is
// Node,RBAC (default-deny). They are EXPORTED so the M2 e2e / in-pod test binds the
// SAME names — one source of truth, not two hard-coded copies that can drift.
const (
	ConformanceNamespace      = "default"
	ConformanceServiceAccount = "snapshot-manager"
)

// Provision retry bounds. A provisioning failure must fail closed (Provision returns
// an error the caller turns into a halt / blocked readiness), but a transient
// apiserver-still-warming error should not — so provision retries a bounded number
// of times before giving up.
const (
	provisionAttempts = 6
	provisionBackoff  = 2 * time.Second
)

// managedLabels marks every object this package provisions, matching pkg/policy's
// convention so k3sm-managed RBAC is greppable and distinct from operator- or
// apiserver-authored objects. It returns a fresh map per call (no shared mutation).
func managedLabels() map[string]string { return map[string]string{"k3sm.io/managed": "true"} }

// Provision idempotently lays down the RBAC graph that must exist before the
// apiserver enforces --authorization-mode=Node,RBAC, then returns. It is
// FAIL-CLOSED: it returns a non-nil error (which the caller turns into a halt /
// blocked readiness) rather than log-and-continue, because a half-applied graph
// under an enforcing authorizer silently locks joined workers out of the datapath.
// Run it under the retained system:masters admin client (which bypasses RBAC) so it
// succeeds even with the authorizer already on — this is why a single Node,RBAC boot
// needs no two-phase restart. It provisions ONLY k3sm-named objects (see doc.go for
// what it deliberately does not touch) and is safe to call on every server start
// (AlreadyExists is success).
func Provision(ctx context.Context, cs kubernetes.Interface) error {
	return provision(ctx, cs, provisionAttempts, provisionBackoff)
}

// provision is the bounded-retry core of Provision, parameterized so tests run fast.
// It re-attempts ensureGraph up to attempts times, sleeping backoff between tries and
// honoring ctx cancellation, and returns the last error if every attempt fails.
func provision(ctx context.Context, cs kubernetes.Interface, attempts int, backoff time.Duration) error {
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("provision rbac graph: %w", ctx.Err())
			case <-time.After(backoff):
			}
		}
		if lastErr = ensureGraph(ctx, cs); lastErr == nil {
			return nil
		}
	}
	return fmt.Errorf("provision rbac graph after %d attempts: %w", attempts, lastErr)
}

// ensureGraph provisions every k3sm RBAC object once. A single Create error (other
// than AlreadyExists) aborts and propagates immediately — so provision retries the
// WHOLE graph and never silently continues past a partial apply.
func ensureGraph(ctx context.Context, cs kubernetes.Interface) error {
	if err := ensureNodeDatapathRBAC(ctx, cs); err != nil {
		return err
	}
	return ensureInPodReaderRBAC(ctx, cs, ConformanceNamespace, ConformanceServiceAccount)
}

// ensureNodeDatapathRBAC provisions the node-datapath ClusterRole + its
// ClusterRoleBinding to the system:nodes group — THE grant that keeps a joined
// worker's datapath alive after the Node,RBAC flip. Its Service proxy, DNS resolver,
// and mesh watcher authenticate as system:node:<name> and must get/list/watch
// services (core), endpointslices (discovery.k8s.io), and meshpeers (net.k3sm.io),
// none of which the Node authorizer or the stock system:node ClusterRole grant.
// meshpeers is READ-only here; the WRITE path stays server-mediated behind
// bootstrap.AuthorizeMeshPeerWrite, since NodeRestriction never covers a CRD.
// Create-tolerate-AlreadyExists so a server restart is a no-op (never a mutation of
// the existing object).
func ensureNodeDatapathRBAC(ctx context.Context, cs kubernetes.Interface) error {
	api := cs.RbacV1()

	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: nodeDatapathRole, Labels: managedLabels()},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"services"}, Verbs: []string{"get", "list", "watch"}},
			{APIGroups: []string{"discovery.k8s.io"}, Resources: []string{"endpointslices"}, Verbs: []string{"get", "list", "watch"}},
			{APIGroups: []string{netv1.GroupName}, Resources: []string{"meshpeers"}, Verbs: []string{"get", "list", "watch"}},
		},
	}
	if _, err := api.ClusterRoles().Create(ctx, role, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create node-datapath cluster role: %w", err)
	}

	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: nodeDatapathRole, Labels: managedLabels()},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     nodeDatapathRole,
		},
		Subjects: []rbacv1.Subject{{
			APIGroup: rbacv1.GroupName,
			Kind:     "Group",
			Name:     systemNodesGroup,
		}},
	}
	if _, err := api.ClusterRoleBindings().Create(ctx, binding, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create node-datapath cluster role binding: %w", err)
	}
	return nil
}

// ensureInPodReaderRBAC provisions the minimal namespaced Role + RoleBinding that
// lets the in-pod-kubectl reference ServiceAccount (sa in namespace ns) read pods,
// configmaps, and services after the Node,RBAC flip — so the M2 in-pod-kubectl
// conformance path stays green under default-deny. It is deliberately MINIMAL
// (read-only, three core resources, one namespace): the M4 acceptance asserts this
// SA is authorized for those verbs yet DENIED everything else (e.g. secrets). The
// binding may name an SA that does not exist yet — RBAC resolves subjects by name at
// request time — so it is safe to provision before the workload is created.
// Create-tolerate-AlreadyExists so a restart is a no-op.
func ensureInPodReaderRBAC(ctx context.Context, cs kubernetes.Interface, ns, sa string) error {
	api := cs.RbacV1()

	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: inPodReaderRole, Labels: managedLabels()},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"pods", "configmaps", "services"}, Verbs: []string{"get", "list", "watch"}},
		},
	}
	if _, err := api.Roles(ns).Create(ctx, role, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create in-pod reader role in %s: %w", ns, err)
	}

	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: inPodReaderRole, Labels: managedLabels()},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     inPodReaderRole,
		},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      sa,
			Namespace: ns,
		}},
	}
	if _, err := api.RoleBindings(ns).Create(ctx, binding, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create in-pod reader role binding in %s: %w", ns, err)
	}
	return nil
}
