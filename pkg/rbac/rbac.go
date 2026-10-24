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
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	netv1 "k3sm.io/apis/net/v1"

	"k3sm.io/k3sm/pkg/certs"
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
// Node,RBAC (default-deny). They are EXPORTED so the e2e / in-pod test binds the
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
	if err := ensureRegistryAdvertReaderRBAC(ctx, cs); err != nil {
		return err
	}
	if err := ensureNetserveRBAC(ctx, cs); err != nil {
		return err
	}
	return ensureRegistryPushRBAC(ctx, cs)
}

// NetserveRole names the ClusterRole and the ClusterRoleBinding that grant the
// netserve identity (certs.NetserveGroup) its reads.
const NetserveRole = "k3sm:netserve"

// netserveRules is the netserve ClusterRole's whole grant: get, list and watch,
// cluster-wide, on exactly the five resources a node's datapath reads. services
// and endpointslices feed the Service proxy and the cluster DNS zone; namespaces,
// networkpolicies and pods feed the NetworkPolicy watcher. pods is cluster-wide
// on purpose: a policy's peer selector names pods on every node, and a watcher
// that saw only its own node's pods could not resolve a cross-node peer (the
// Node authorizer's scope is exactly that blind spot).
//
// It is read-only. There is no create (the kube-dns Service is the server's to
// provision, under its own identity), and no secrets, configmaps or nodes: none
// is read by the datapath, and each would be a confidentiality or a node-identity
// grant the netserve identity has no consumer for. TestWorkerNodeGrantsAreProvisionedAndMinimal
// pins the set.
func netserveRules() []rbacv1.PolicyRule {
	read := func(group string, resources ...string) rbacv1.PolicyRule {
		return rbacv1.PolicyRule{APIGroups: []string{group}, Resources: resources, Verbs: []string{"get", "list", "watch"}}
	}
	return []rbacv1.PolicyRule{
		read("", "services", "namespaces", "pods"),
		read("discovery.k8s.io", "endpointslices"),
		read("networking.k8s.io", "networkpolicies"),
	}
}

// ensureNetserveRBAC provisions the k3sm:netserve ClusterRole (netserveRules)
// and its ClusterRoleBinding to the k3sm:netservers group: the grant every
// node's datapath runs under, the k3s system:k3s-controller shape.
//
// Unlike the grants above it is CREATE-OR-UPDATE (ensureClusterRole,
// ensureClusterRoleBinding): the set is pinned and narrow, so a drifted copy (an
// operator edit, an older build's shape) is repaired to it on the next server
// start rather than trusted because the name exists.
func ensureNetserveRBAC(ctx context.Context, cs kubernetes.Interface) error {
	if err := ensureClusterRole(ctx, cs, "netserve", NetserveRole, netserveRules()); err != nil {
		return err
	}
	return ensureClusterRoleBinding(ctx, cs, "netserve", NetserveRole, certs.NetserveGroup)
}

// RegistryGateRole names the ClusterRole and the ClusterRoleBinding that grant
// the ingest registry's push gate (certs.RegistryGateGroup) the three calls it
// makes to authorize an in-pod push.
const RegistryGateRole = "k3sm:registry-gate"

// RegistryPusherRole names the ClusterRole a namespace binds, with an ordinary
// RoleBinding, to the ServiceAccounts it lets push to a node's ingest registry.
// k3sm's one binding to it is RegistryBuilderBinding, to the builder
// ServiceAccount alone; every other pusher is the namespace's decision, made in
// RBAC.
const RegistryPusherRole = "k3sm:registry-pusher"

// registryGateRules is the push gate's whole grant: create a TokenReview (is
// this token valid for the registry audience), create a SubjectAccessReview
// (may this identity push this repository), and get a namespace by name (does
// it carry the push label). There is no list or watch: the gate reads one
// namespace at a time, cached for seconds, so a cluster-wide namespace read is
// authority it has no consumer for.
func registryGateRules() []rbacv1.PolicyRule {
	return []rbacv1.PolicyRule{
		{APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"tokenreviews"}, Verbs: []string{"create"}},
		{APIGroups: []string{"authorization.k8s.io"}, Resources: []string{"subjectaccessreviews"}, Verbs: []string{"create"}},
		{APIGroups: []string{""}, Resources: []string{"namespaces"}, Verbs: []string{"get"}},
	}
}

// registryPusherRules is the verb the push gate's SubjectAccessReview asks
// about: push on registry.k3sm.io repositories. It is a virtual resource (no
// such API is served), which is exactly how RBAC carries an authorization that
// a component other than the apiserver enforces.
func registryPusherRules() []rbacv1.PolicyRule {
	return []rbacv1.PolicyRule{{
		APIGroups: []string{registrysvc.PushAPIGroup},
		Resources: []string{registrysvc.PushResource},
		Verbs:     []string{registrysvc.PushVerb},
	}}
}

// ensureRegistryPushRBAC provisions the push gate's ClusterRole and its binding
// to the k3sm:registry-gates group, and the UNBOUND k3sm:registry-pusher
// ClusterRole a namespace binds itself. Both roles are create-or-update, like
// the netserve role.
func ensureRegistryPushRBAC(ctx context.Context, cs kubernetes.Interface) error {
	if err := ensureClusterRole(ctx, cs, "registry gate", RegistryGateRole, registryGateRules()); err != nil {
		return err
	}
	if err := ensureClusterRoleBinding(ctx, cs, "registry gate", RegistryGateRole, certs.RegistryGateGroup); err != nil {
		return err
	}
	if err := ensureClusterRole(ctx, cs, "registry pusher", RegistryPusherRole, registryPusherRules()); err != nil {
		return err
	}
	return ensureRegistryBuilderRBAC(ctx, cs)
}

// RegistryBuilderBinding names the ClusterRoleBinding that grants the builder
// ServiceAccount (registrysvc.BuilderNamespace/registrysvc.BuilderServiceAccount)
// the k3sm:registry-pusher role cluster-wide.
const RegistryBuilderBinding = "k3sm:registry-builder"

// RegistryBuilderTokenRole names the Role, in registrysvc.BuilderNamespace,
// that lets its holder mint a token for the builder ServiceAccount, and
// nothing else. It is a namespaced Role, not a ClusterRole, so no binding
// anywhere can make it reach a ServiceAccount named builder in another
// namespace. k3sm ships it with NO binding: an admin binds it, with a
// RoleBinding in registrysvc.BuilderNamespace, to a user who should push
// without administering the cluster.
const RegistryBuilderTokenRole = "k3sm:registry-builder-token"

// registryBuilderTokenRules is the token role's whole grant: create on the
// serviceaccounts/token subresource of the one ServiceAccount named builder.
// Bound by a RoleBinding in the builder's namespace it reaches exactly
// k3sm-registry/builder; it carries no get, list or watch, so a holder cannot
// read the ServiceAccount, its Secrets or anything else.
func registryBuilderTokenRules() []rbacv1.PolicyRule {
	return []rbacv1.PolicyRule{{
		APIGroups:     []string{""},
		Resources:     []string{"serviceaccounts/token"},
		ResourceNames: []string{registrysvc.BuilderServiceAccount},
		Verbs:         []string{"create"},
	}}
}

// ensureRegistryBuilderRBAC provisions the builder identity a user pushes as
// from any Mac: the ServiceAccount, its cluster-wide ClusterRoleBinding to
// k3sm:registry-pusher (the push gate asks a cluster-wide SubjectAccessReview
// for it), and the UNBOUND k3sm:registry-builder-token Role in its namespace. It runs on
// every server start, so a new cluster has the identity from its first start.
//
// Who may push as builder is decided by who may create its token: an admin
// kubeconfig can, and a user an admin bound the token role to can. The builder
// ServiceAccount itself is never mounted into a Pod by k3sm.
func ensureRegistryBuilderRBAC(ctx context.Context, cs kubernetes.Interface) error {
	ns := registrysvc.BuilderNamespace
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: registrysvc.BuilderServiceAccount, Labels: managedLabels()},
	}
	if _, err := cs.CoreV1().ServiceAccounts(ns).Create(ctx, sa, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create the registry builder service account in %s: %w", ns, err)
	}
	builder := rbacv1.Subject{Kind: "ServiceAccount", Name: registrysvc.BuilderServiceAccount, Namespace: ns}
	if err := ensureClusterRoleBindingTo(ctx, cs, "registry builder", RegistryBuilderBinding, RegistryPusherRole, builder); err != nil {
		return err
	}
	return ensureRole(ctx, cs, "registry builder token", ns, RegistryBuilderTokenRole, registryBuilderTokenRules())
}

// ensureRole creates the named managed Role in ns with exactly rules, or
// repairs it when its rules or its managed label drifted. what names the role
// in errors.
func ensureRole(ctx context.Context, cs kubernetes.Interface, what, ns, name string, rules []rbacv1.PolicyRule) error {
	api := cs.RbacV1().Roles(ns)
	want := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: managedLabels()},
		Rules:      rules,
	}
	have, err := api.Get(ctx, name, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		if _, err := api.Create(ctx, want, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("create the %s role in %s: %w", what, ns, err)
		}
	case err != nil:
		return fmt.Errorf("get the %s role in %s: %w", what, ns, err)
	case !equality.Semantic.DeepEqual(have.Rules, want.Rules) || !hasManagedLabel(have.Labels):
		upd := have.DeepCopy()
		upd.Rules = want.Rules
		upd.Labels = withManagedLabel(upd.Labels)
		if _, err := api.Update(ctx, upd, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("repair the %s role in %s: %w", what, ns, err)
		}
	}
	return nil
}

// ensureClusterRole creates the named managed ClusterRole with exactly rules, or
// repairs it when its rules, its managed label or an aggregation rule drifted.
// The Get is authoritative by name, never a LIST (see doc.go). what names the
// role in errors.
func ensureClusterRole(ctx context.Context, cs kubernetes.Interface, what, name string, rules []rbacv1.PolicyRule) error {
	api := cs.RbacV1()
	want := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: managedLabels()},
		Rules:      rules,
	}
	have, err := api.ClusterRoles().Get(ctx, name, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		if _, err := api.ClusterRoles().Create(ctx, want, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("create the %s cluster role: %w", what, err)
		}
	case err != nil:
		return fmt.Errorf("get the %s cluster role: %w", what, err)
	case !equality.Semantic.DeepEqual(have.Rules, want.Rules) || !hasManagedLabel(have.Labels) || have.AggregationRule != nil:
		upd := have.DeepCopy()
		upd.Rules = want.Rules
		upd.AggregationRule = nil
		upd.Labels = withManagedLabel(upd.Labels)
		if _, err := api.ClusterRoles().Update(ctx, upd, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("repair the %s cluster role: %w", what, err)
		}
	}
	return nil
}

// ensureClusterRoleBinding creates the managed ClusterRoleBinding name, binding
// the ClusterRole of the same name to exactly one group, or repairs it. A
// binding whose roleRef drifted is deleted and re-created, because roleRef is
// immutable.
func ensureClusterRoleBinding(ctx context.Context, cs kubernetes.Interface, what, name, group string) error {
	return ensureClusterRoleBindingTo(ctx, cs, what, name, name, rbacv1.Subject{APIGroup: rbacv1.GroupName, Kind: "Group", Name: group})
}

// ensureClusterRoleBindingTo creates the managed ClusterRoleBinding name,
// binding the ClusterRole role to exactly subject, or repairs it, on the same
// terms as ensureClusterRoleBinding.
func ensureClusterRoleBindingTo(ctx context.Context, cs kubernetes.Interface, what, name, role string, subject rbacv1.Subject) error {
	api := cs.RbacV1()
	wantBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: managedLabels()},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role},
		Subjects:   []rbacv1.Subject{subject},
	}
	haveBinding, err := api.ClusterRoleBindings().Get(ctx, name, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		if _, err := api.ClusterRoleBindings().Create(ctx, wantBinding, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("create the %s cluster role binding: %w", what, err)
		}
	case err != nil:
		return fmt.Errorf("get the %s cluster role binding: %w", what, err)
	case haveBinding.RoleRef != wantBinding.RoleRef:
		if err := api.ClusterRoleBindings().Delete(ctx, name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete the %s cluster role binding to re-create its roleRef: %w", what, err)
		}
		if _, err := api.ClusterRoleBindings().Create(ctx, wantBinding, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("re-create the %s cluster role binding: %w", what, err)
		}
	case !equality.Semantic.DeepEqual(haveBinding.Subjects, wantBinding.Subjects) || !hasManagedLabel(haveBinding.Labels):
		upd := haveBinding.DeepCopy()
		upd.Subjects = wantBinding.Subjects
		upd.Labels = withManagedLabel(upd.Labels)
		if _, err := api.ClusterRoleBindings().Update(ctx, upd, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("repair the %s cluster role binding: %w", what, err)
		}
	}
	return nil
}

// hasManagedLabel reports whether labels carry k3sm.io/managed=true.
func hasManagedLabel(labels map[string]string) bool {
	return labels["k3sm.io/managed"] == "true"
}

// withManagedLabel returns a copy of labels with k3sm.io/managed=true set,
// keeping any other label an operator added.
func withManagedLabel(labels map[string]string) map[string]string {
	out := make(map[string]string, len(labels)+1)
	for k, v := range labels {
		out[k] = v
	}
	for k, v := range managedLabels() {
		out[k] = v
	}
	return out
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
// configmaps, and services after the Node,RBAC flip — so the in-pod-kubectl
// conformance path stays green under default-deny. It is deliberately MINIMAL
// (read-only, three core resources, one namespace): the acceptance gate asserts this
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
// It is the narrowest widening available, and it was reviewed as such because
// this is the first grant that gives the system:nodes group a
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

// ManifestApplierNamespace and ManifestApplierName name the ServiceAccount the
// auto-deploy manifest reconciler (pkg/addons.ManifestDir) authenticates as, and
// the ClusterRole + ClusterRoleBinding that bound it. They are exported so the
// reconciler requests its token for the SAME account this package grants.
const (
	ManifestApplierNamespace = "kube-system"
	ManifestApplierName      = "k3sm-manifests"
)

// manifestApplierVerbs is exactly what a server-side apply needs: an apply is a
// PATCH that may create. No read verb (the reconciler never reads back, and a
// read grant on a kind like Secret would be a confidentiality grant), no update,
// and no delete: the reconciler is apply-only.
var manifestApplierVerbs = []string{"create", "patch"}

// manifestApplierRules is the ClusterRole's whole grant. It is deliberately a
// fixed list of workload and configuration kinds:
//
//   - rbac.authorization.k8s.io and admissionregistration.k8s.io are ABSENT, and
//     the reconciler refuses those groups before it ever calls the apiserver, so a
//     manifest can neither grant authority nor change what admission enforces.
//     Because the identity holds no RBAC write, the apiserver's escalation
//     prevention bounds anything a manifest could still express.
//   - secrets and serviceaccounts are ABSENT, and the reconciler refuses both kinds:
//     creating a kubernetes.io/service-account-token Secret for an existing
//     ServiceAccount mints that account's token, which escalation prevention does
//     not cover.
//   - namespaces, nodes, CustomResourceDefinitions and the net.k3sm.io MeshPeer are
//     ABSENT. A MeshPeer write stays server-mediated (see doc.go), and a manifest
//     that needs a namespace or a CRD gets it from the component that owns it.
//   - events are create/patch only, for the Warning Event the reconciler records on
//     a Pod-template object that lacks the Darwin scheduling fields.
func manifestApplierRules() []rbacv1.PolicyRule {
	rule := func(group string, resources ...string) rbacv1.PolicyRule {
		return rbacv1.PolicyRule{APIGroups: []string{group}, Resources: resources, Verbs: append([]string(nil), manifestApplierVerbs...)}
	}
	return []rbacv1.PolicyRule{
		rule("", "configmaps", "services", "persistentvolumeclaims", "pods"),
		rule("apps", "deployments", "daemonsets", "statefulsets"),
		rule("batch", "jobs", "cronjobs"),
		rule("networking.k8s.io", "ingresses", "networkpolicies"),
		rule("storage.k8s.io", "storageclasses"),
		rule("autoscaling", "horizontalpodautoscalers"),
		rule("policy", "poddisruptionbudgets"),
		rule(mlxv1alpha1.GroupName, "mlxmodels"),
		{APIGroups: []string{""}, Resources: []string{"events"}, Verbs: []string{"create", "patch"}},
	}
}

// ProvisionManifestApplier idempotently lays down the bounded identity the
// auto-deploy manifest reconciler applies with: the k3sm-manifests
// ServiceAccount in kube-system, the k3sm-manifests ClusterRole
// (manifestApplierRules), and the ClusterRoleBinding joining them. It is never
// system:masters and never a system:* object.
//
// Unlike Provision it is NOT on the fail-closed bring-up path: the manifest
// directory is an optional operator surface, so a failure here disables that
// surface (the caller logs it) and nothing else. It shares Provision's discipline
// otherwise: Create-tolerate-AlreadyExists, a bounded retry for an apiserver that
// is still warming, and no LIST to decide anything.
func ProvisionManifestApplier(ctx context.Context, cs kubernetes.Interface) error {
	return provisionManifestApplier(ctx, cs, provisionAttempts, provisionBackoff)
}

// provisionManifestApplier is the bounded-retry core of ProvisionManifestApplier,
// parameterized so tests run fast.
func provisionManifestApplier(ctx context.Context, cs kubernetes.Interface, attempts int, backoff time.Duration) error {
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("provision manifest applier: %w", ctx.Err())
			case <-time.After(backoff):
			}
		}
		if lastErr = ensureManifestApplier(ctx, cs); lastErr == nil {
			return nil
		}
	}
	return fmt.Errorf("provision manifest applier after %d attempts: %w", attempts, lastErr)
}

// ensureManifestApplier creates the ServiceAccount, the ClusterRole and the
// ClusterRoleBinding once each, tolerating AlreadyExists.
func ensureManifestApplier(ctx context.Context, cs kubernetes.Interface) error {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Namespace: ManifestApplierNamespace, Name: ManifestApplierName, Labels: managedLabels()},
	}
	if _, err := cs.CoreV1().ServiceAccounts(ManifestApplierNamespace).Create(ctx, sa, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create the %s/%s service account: %w", ManifestApplierNamespace, ManifestApplierName, err)
	}

	api := cs.RbacV1()
	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: ManifestApplierName, Labels: managedLabels()},
		Rules:      manifestApplierRules(),
	}
	if _, err := api.ClusterRoles().Create(ctx, role, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create the manifest applier cluster role: %w", err)
	}

	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: ManifestApplierName, Labels: managedLabels()},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     ManifestApplierName,
		},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      ManifestApplierName,
			Namespace: ManifestApplierNamespace,
		}},
	}
	if _, err := api.ClusterRoleBindings().Create(ctx, binding, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create the manifest applier cluster role binding: %w", err)
	}
	// The HelmChart grant rides beside the bounded role, in its OWN ClusterRole
	// and binding (manifestHelmRules), never merged into manifestApplierRules.
	// It is the one grant that gives this identity an indirect path to
	// cluster-admin: a HelmChart dropped in the manifest directory makes the helm
	// controller run a Job bound to cluster-admin. That is the k3s shape (a
	// manifest in server/manifests already runs as the server), and the set of
	// principals reaching cluster-admin stays {root on the node, the admin
	// kubeconfig}, because only root can write the manifest directory.
	return ensureManifestHelmGrant(ctx, cs)
}
