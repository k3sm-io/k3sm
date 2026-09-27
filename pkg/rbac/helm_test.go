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
	"reflect"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	helmv1 "k3sm.io/apis/helm/v1"
	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
)

// TestProvisionHelmJobIdentity pins the k3s-shaped Job identity: helm-<chart> in
// the chart's namespace, bound by helm-<ns>-<chart> to the default cluster-admin
// ClusterRole (referenced, not authored), idempotent, and removed by name.
func TestProvisionHelmJobIdentity(t *testing.T) {
	ctx := context.Background()
	cs := fake.NewClientset()
	for i := 0; i < 2; i++ {
		if err := ProvisionHelmJobIdentity(ctx, cs, "apps", "podinfo"); err != nil {
			t.Fatalf("ProvisionHelmJobIdentity #%d: %v", i+1, err)
		}
	}
	sa, err := cs.CoreV1().ServiceAccounts("apps").Get(ctx, "helm-podinfo", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("service account apps/helm-podinfo: %v", err)
	}
	if sa.Labels["k3sm.io/managed"] != "true" {
		t.Errorf("service account labels = %v, want k3sm.io/managed", sa.Labels)
	}
	crb, err := cs.RbacV1().ClusterRoleBindings().Get(ctx, "helm-apps-podinfo", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("cluster role binding helm-apps-podinfo: %v", err)
	}
	if crb.RoleRef != (rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "cluster-admin"}) {
		t.Errorf("roleRef = %+v, want ClusterRole cluster-admin", crb.RoleRef)
	}
	if want := []rbacv1.Subject{{Kind: "ServiceAccount", Name: "helm-podinfo", Namespace: "apps"}}; !reflect.DeepEqual(crb.Subjects, want) {
		t.Errorf("subjects = %+v, want %+v", crb.Subjects, want)
	}
	if crb.Labels["k3sm.io/managed"] != "true" {
		t.Errorf("binding labels = %v, want k3sm.io/managed", crb.Labels)
	}
	if _, err := cs.RbacV1().ClusterRoles().Get(ctx, "cluster-admin", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("the identity authored the cluster-admin ClusterRole (get err = %v); it must only reference it", err)
	}

	for i := 0; i < 2; i++ {
		if err := DeleteHelmJobIdentity(ctx, cs, "apps", "podinfo"); err != nil {
			t.Fatalf("DeleteHelmJobIdentity #%d: %v", i+1, err)
		}
	}
	if _, err := cs.RbacV1().ClusterRoleBindings().Get(ctx, "helm-apps-podinfo", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("binding survives the delete: %v", err)
	}
	if _, err := cs.CoreV1().ServiceAccounts("apps").Get(ctx, "helm-podinfo", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("service account survives the delete: %v", err)
	}
}

// TestRBACManifestHelmGrantIsSeparate pins that the manifest identity's
// HelmChart grant lives in its own ClusterRole, bound to the same
// ServiceAccount, and that manifestApplierRules did not grow to carry it.
func TestRBACManifestHelmGrantIsSeparate(t *testing.T) {
	ctx := context.Background()
	cs := fake.NewClientset()
	if err := ProvisionManifestApplier(ctx, cs); err != nil {
		t.Fatal(err)
	}
	role, err := cs.RbacV1().ClusterRoles().Get(ctx, ManifestHelmRoleName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("cluster role %s: %v", ManifestHelmRoleName, err)
	}
	want := []rbacv1.PolicyRule{{
		APIGroups: []string{helmv1.GroupName},
		Resources: []string{"helmcharts", "helmchartconfigs"},
		Verbs:     []string{"create", "patch", "get"},
	}}
	if !reflect.DeepEqual(role.Rules, want) {
		t.Errorf("%s rules = %+v, want %+v", ManifestHelmRoleName, role.Rules, want)
	}
	crb, err := cs.RbacV1().ClusterRoleBindings().Get(ctx, ManifestHelmRoleName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("cluster role binding %s: %v", ManifestHelmRoleName, err)
	}
	if crb.RoleRef.Name != ManifestHelmRoleName || len(crb.Subjects) != 1 ||
		crb.Subjects[0].Name != ManifestApplierName || crb.Subjects[0].Namespace != ManifestApplierNamespace {
		t.Errorf("binding = %+v / %+v, want %s bound to %s/%s", crb.RoleRef, crb.Subjects, ManifestHelmRoleName, ManifestApplierNamespace, ManifestApplierName)
	}

	bounded, err := cs.RbacV1().ClusterRoles().Get(ctx, ManifestApplierName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range bounded.Rules {
		for _, g := range r.APIGroups {
			if g == helmv1.GroupName {
				t.Errorf("the bounded %s ClusterRole carries the helm group: %+v", ManifestApplierName, r)
			}
		}
	}
	// manifestApplierRules as it stood before the helm grant existed. A change
	// here is a change to the bounded identity and must be made on purpose.
	cm := []string{"create", "patch"}
	unchanged := []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"configmaps", "services", "persistentvolumeclaims", "pods"}, Verbs: cm},
		{APIGroups: []string{"apps"}, Resources: []string{"deployments", "daemonsets", "statefulsets"}, Verbs: cm},
		{APIGroups: []string{"batch"}, Resources: []string{"jobs", "cronjobs"}, Verbs: cm},
		{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses", "networkpolicies"}, Verbs: cm},
		{APIGroups: []string{"storage.k8s.io"}, Resources: []string{"storageclasses"}, Verbs: cm},
		{APIGroups: []string{"autoscaling"}, Resources: []string{"horizontalpodautoscalers"}, Verbs: cm},
		{APIGroups: []string{"policy"}, Resources: []string{"poddisruptionbudgets"}, Verbs: cm},
		{APIGroups: []string{mlxv1alpha1.GroupName}, Resources: []string{"mlxmodels"}, Verbs: cm},
		{APIGroups: []string{""}, Resources: []string{"events"}, Verbs: cm},
	}
	if !reflect.DeepEqual(manifestApplierRules(), unchanged) {
		t.Errorf("manifestApplierRules changed:\n got %+v\nwant %+v", manifestApplierRules(), unchanged)
	}
}
