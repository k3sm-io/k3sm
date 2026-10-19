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
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	updatesv1alpha1 "k3sm.io/apis/updates/v1alpha1"
)

// TestNoProvisionedRuleGrantsUpdates pins the invariant the release pin's
// required annotation rests on (k3sm/pkg/updatectl/pin.go, the
// ReleasePinRequiredAnnotation comment): no rule k3sm provisions names the
// updates.k3sm.io group or a wildcard group, so only a cluster-admin identity
// can write an Update, and removing the annotation needs an identity that can
// already change spec.version. A change that grants Updates to anyone fails
// here, and that claim must be revisited before this test is changed.
//
// It walks every ClusterRole and Role the package's provisioners create: the
// provisioned graph (Provision, the graph TestRBACGrantSetGolden pins), the
// manifest applier's roles, and a helm Job identity, which binds the default
// cluster-admin role by reference and authors no rule.
func TestNoProvisionedRuleGrantsUpdates(t *testing.T) {
	ctx := context.Background()
	cs := fake.NewClientset()
	if err := Provision(ctx, cs); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if err := ProvisionManifestApplier(ctx, cs); err != nil {
		t.Fatalf("ProvisionManifestApplier: %v", err)
	}
	if err := ProvisionHelmJobIdentity(ctx, cs, "apps", "podinfo"); err != nil {
		t.Fatalf("ProvisionHelmJobIdentity: %v", err)
	}
	crs, err := cs.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rs, err := cs.RbacV1().Roles(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	type role struct {
		kind, ns, name string
		rules          []rbacv1.PolicyRule
	}
	var roles []role
	for _, r := range crs.Items {
		roles = append(roles, role{"ClusterRole", "", r.Name, r.Rules})
	}
	for _, r := range rs.Items {
		roles = append(roles, role{"Role", r.Namespace, r.Name, r.Rules})
	}
	rules := 0
	for _, o := range roles {
		for _, r := range o.rules {
			rules++
			for _, g := range r.APIGroups {
				if g == updatesv1alpha1.GroupName || g == rbacv1.APIGroupAll {
					t.Errorf("%s %s/%s grants apiGroup %q (%v on %v): the release pin's required-annotation claim no longer holds",
						o.kind, o.ns, o.name, g, r.Verbs, r.Resources)
				}
			}
		}
	}
	if rules == 0 {
		t.Fatal("no rule was walked; the test would pass on an empty graph")
	}
}
