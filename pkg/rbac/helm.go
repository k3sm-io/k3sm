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

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	helmv1 "k3sm.io/apis/helm/v1"

	"k3sm.io/k3sm/pkg/helmchart"
)

// helmJobClusterRole is the ClusterRole a HelmChart's Job identity is bound to.
// It is the apiserver's own default cluster-admin, REFERENCED as a roleRef and
// never authored here (see doc.go): helm installs arbitrary objects, so nothing
// narrower is correct, which is k3s's reasoning for its helm-<chart> binding too.
const helmJobClusterRole = "cluster-admin"

// ManifestHelmRoleName names the ClusterRole (and its ClusterRoleBinding) that
// lets the manifest-directory identity write HelmChart and HelmChartConfig
// objects. It is a separate object from the k3sm-manifests ClusterRole on
// purpose; see manifestHelmRules.
const ManifestHelmRoleName = "k3sm-manifest-helm"

// HelmJobBindingName is the ClusterRoleBinding granting chart's Job identity in
// namespace ns cluster-admin: helm-<ns>-<chart>, unique across namespaces.
func HelmJobBindingName(ns, chart string) string { return "helm-" + ns + "-" + chart }

// ProvisionHelmJobIdentity lays down the identity a HelmChart's Jobs run as: the
// ServiceAccount helm-<chart> in ns and the ClusterRoleBinding
// helm-<ns>-<chart> binding it to cluster-admin, both labelled k3sm.io/managed.
// Create-tolerate-AlreadyExists, one attempt: the helm controller calls it on
// every reconcile and requeues on an error, so a retry loop here would only
// stall its single worker.
//
// The identity lives as long as the HelmChart (DeleteHelmJobIdentity runs when
// its uninstall finishes). Every pod in ns can run as any ServiceAccount in ns,
// and k3sm has no per-pod uid isolation, so a namespace holding a HelmChart
// should hold no untrusted pods; docs/user/helm.md says so.
func ProvisionHelmJobIdentity(ctx context.Context, cs kubernetes.Interface, ns, chart string) error {
	saName := helmchart.ServiceAccountName(chart)
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: saName, Labels: helmIdentityLabels(chart)},
	}
	if _, err := cs.CoreV1().ServiceAccounts(ns).Create(ctx, sa, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create the helm job service account %s/%s: %w", ns, saName, err)
	}
	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: HelmJobBindingName(ns, chart), Labels: helmIdentityLabels(chart)},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     helmJobClusterRole,
		},
		Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: saName, Namespace: ns}},
	}
	if _, err := cs.RbacV1().ClusterRoleBindings().Create(ctx, binding, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create the helm job cluster role binding %s: %w", binding.Name, err)
	}
	return nil
}

// DeleteHelmJobIdentity removes what ProvisionHelmJobIdentity created, each by
// name (never by a LIST or a label selector; see doc.go). NotFound is success, so
// a rerun after a partial delete converges. The binding goes first: it is the
// grant, and the ServiceAccount is harmless without it.
func DeleteHelmJobIdentity(ctx context.Context, cs kubernetes.Interface, ns, chart string) error {
	name := HelmJobBindingName(ns, chart)
	if err := cs.RbacV1().ClusterRoleBindings().Delete(ctx, name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete the helm job cluster role binding %s: %w", name, err)
	}
	saName := helmchart.ServiceAccountName(chart)
	if err := cs.CoreV1().ServiceAccounts(ns).Delete(ctx, saName, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete the helm job service account %s/%s: %w", ns, saName, err)
	}
	return nil
}

// helmIdentityLabels marks a Job identity as k3sm-managed and names its chart.
func helmIdentityLabels(chart string) map[string]string {
	l := managedLabels()
	l[helmchart.LabelChart] = chart
	return l
}

// manifestHelmRules is the whole grant of the k3sm-manifest-helm ClusterRole:
// write (and read back) HelmChart and HelmChartConfig objects, the k3s shape of
// dropping a HelmChart into server/manifests.
//
// It is a SEPARATE ClusterRole, never merged into manifestApplierRules, because
// it is the one grant that gives the manifest identity an indirect path to
// cluster-admin: a HelmChart it writes makes the helm controller run a Job as a
// ServiceAccount bound to cluster-admin, installing whatever the chart holds.
// Keeping it in its own object keeps that path visible and removable on its
// own, and keeps manifestApplierRules the bounded list its test pins.
func manifestHelmRules() []rbacv1.PolicyRule {
	return []rbacv1.PolicyRule{{
		APIGroups: []string{helmv1.GroupName},
		Resources: []string{"helmcharts", "helmchartconfigs"},
		Verbs:     []string{"create", "patch", "get"},
	}}
}

// ensureManifestHelmGrant creates the k3sm-manifest-helm ClusterRole and binds
// it to the manifest-directory ServiceAccount, tolerating AlreadyExists.
func ensureManifestHelmGrant(ctx context.Context, cs kubernetes.Interface) error {
	api := cs.RbacV1()
	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: ManifestHelmRoleName, Labels: managedLabels()},
		Rules:      manifestHelmRules(),
	}
	if _, err := api.ClusterRoles().Create(ctx, role, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create the manifest helm cluster role: %w", err)
	}
	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: ManifestHelmRoleName, Labels: managedLabels()},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     ManifestHelmRoleName,
		},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      ManifestApplierName,
			Namespace: ManifestApplierNamespace,
		}},
	}
	if _, err := api.ClusterRoleBindings().Create(ctx, binding, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create the manifest helm cluster role binding: %w", err)
	}
	return nil
}
