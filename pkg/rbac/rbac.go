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

package rbac

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	netv1 "k3sm.io/apis/net/v1"

	"k3sm.io/k3sm/pkg/registrysvc"
)

// nodeDatapathRole / inPodReaderRole are the cluster-scoped / namespaced names of
// the objects this package provisions. Both carry the "k3sm:" prefix so they never
// collide with — nor are mistaken for — the apiserver's auto-reconciled default
// system:* roles and bindings, which this package must not author (see doc.go).
const (
	nodeDatapathRole = "k3sm:node-datapath"
	inPodReaderRole  = "k3sm:in-pod-reader"
)

// registryAdvertReaderRole is the namespaced Role (and its RoleBinding) that lets
// a node identity read the per-node registry advertisements. It is named without
// the "k3sm:" prefix because it is the object an operator inspects when a
// cross-node image pull does not fall back, and a bare name is what
// `kubectl get role -n k3sm-registry` reads back; the collision the prefix
// guards against does not arise for a namespaced object in a k3sm-owned
// namespace.
const registryAdvertReaderRole = "k3sm-registry-advert-reader"

// systemNodesGroup is the group every joined worker's system:node:<name> client
// cert carries (O=system:nodes). The node-datapath ClusterRoleBinding binds the
// datapath grant to THIS group; the group, and the stock system:node ClusterRole,
// are owned by the apiserver — k3sm references the group, never authors a system:*
// object.
const systemNodesGroup = "system:nodes"

// ConformanceNamespace / ConformanceServiceAccount name the ServiceAccount the
// in-pod-kubectl reference path runs as (TestM2_InPodKubectl, the snapshotManager
// workload). Provision binds it to the
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
	if err := ensureInPodReaderRBAC(ctx, cs, ConformanceNamespace, ConformanceServiceAccount); err != nil {
		return err
	}
	return ensureRegistryAdvertReaderRBAC(ctx, cs)
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

// ensureRegistryAdvertReaderRBAC provisions the k3sm-registry namespace and the
// namespaced Role + RoleBinding that let a joined worker's image puller read the
// per-node registry advertisements (registrysvc.AdvertisementNamespace) — the
// grant without which a node never learns which peers hold an image it was asked
// to pull, and a cross-node pull of a `localhost:<port>/…` reference fails on a
// node that was simply never fed.
//
// OPERATOR-APPROVED 2026-09-02 as the narrowest widening available. Approval was
// asked for because this is the first grant that gives the system:nodes group a
// read it did not have, and the shape of it is forced: the reader is a shared
// informer, so it needs list and watch, and RBAC's resourceNames narrows GET but
// has NO effect on list or watch — a rule cannot say "watch only the objects
// named k3sm-node-registry-*". THE NAMESPACE IS THEREFORE THE SCOPE. Putting the
// advertisements in their own namespace (rather than beside the KEP-1755
// document in kube-public, where they used to live) is what makes the grant read
// exactly these objects and nothing any other component parks in a shared
// namespace. The verbs are read-only for the same reason: a node publishes its
// OWN advertisement through the server, never through this identity.
//
// The namespace is created HERE, next to the Role that is meaningless without
// it: a Role create into an absent namespace fails, so the two are one
// provisioning step rather than an ordering an unrelated caller has to know
// about. Create-tolerate-AlreadyExists throughout, so a restart is a no-op.
func ensureRegistryAdvertReaderRBAC(ctx context.Context, cs kubernetes.Interface) error {
	ns := registrysvc.AdvertisementNamespace

	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: managedLabels()},
	}
	if _, err := cs.CoreV1().Namespaces().Create(ctx, namespace, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create the %s namespace: %w", ns, err)
	}

	api := cs.RbacV1()

	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: registryAdvertReaderRole, Labels: managedLabels()},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get", "list", "watch"}},
		},
	}
	if _, err := api.Roles(ns).Create(ctx, role, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create the registry advertisement reader role in %s: %w", ns, err)
	}

	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: registryAdvertReaderRole, Labels: managedLabels()},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     registryAdvertReaderRole,
		},
		// The same system:nodes GROUP the node-datapath ClusterRoleBinding names —
		// every joined worker's client cert carries O=system:nodes, and the reader
		// is the node's own puller, not a workload ServiceAccount. Referenced,
		// never authored (see doc.go).
		Subjects: []rbacv1.Subject{{
			APIGroup: rbacv1.GroupName,
			Kind:     "Group",
			Name:     systemNodesGroup,
		}},
	}
	if _, err := api.RoleBindings(ns).Create(ctx, binding, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create the registry advertisement reader role binding in %s: %w", ns, err)
	}
	return nil
}
