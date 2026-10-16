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
	"sort"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// The netserve identity, spelled as literals on purpose: this test pins the
// names an operator's `kubectl get clusterrolebinding` and the issued
// certificates carry, so it must not follow a renamed constant.
const (
	wantNetserveRole  = "k3sm:netserve"
	wantNetserveGroup = "k3sm:netservers"
)

// wantNetserveGrants is the whole netserve grant, as group/resource pairs, each
// with exactly get, list and watch.
var wantNetserveGrants = []string{
	"/namespaces",
	"/pods",
	"/services",
	"discovery.k8s.io/endpointslices",
	"networking.k8s.io/networkpolicies",
}

// flattenGrants renders rules as "group/resource" -> sorted verbs, failing on a
// wildcard anywhere (a wildcard is never an exact grant).
func flattenGrants(t *testing.T, rules []rbacv1.PolicyRule) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, r := range rules {
		if len(r.NonResourceURLs) != 0 || len(r.ResourceNames) != 0 {
			t.Errorf("rule %+v carries nonResourceURLs or resourceNames; the netserve grant has neither", r)
		}
		verbs := append([]string(nil), r.Verbs...)
		sort.Strings(verbs)
		for _, g := range r.APIGroups {
			for _, res := range r.Resources {
				if g == "*" || res == "*" || strings.Contains(strings.Join(verbs, ","), "*") {
					t.Errorf("rule %+v uses a wildcard", r)
				}
				out[g+"/"+res] = strings.Join(verbs, ",")
			}
		}
	}
	return out
}

// assertNetserveGraph checks the provisioned k3sm:netserve ClusterRole and
// ClusterRoleBinding are exactly the pinned shape.
func assertNetserveGraph(t *testing.T, cs *fake.Clientset) {
	t.Helper()
	ctx := context.Background()
	role, err := cs.RbacV1().ClusterRoles().Get(ctx, wantNetserveRole, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get the %s ClusterRole: %v", wantNetserveRole, err)
	}
	if role.Labels["k3sm.io/managed"] != "true" {
		t.Errorf("ClusterRole %s labels = %v, want k3sm.io/managed=true", role.Name, role.Labels)
	}
	if role.AggregationRule != nil {
		t.Errorf("ClusterRole %s carries an aggregation rule; its grant must be exactly its rules", role.Name)
	}
	got := flattenGrants(t, role.Rules)
	if len(got) != len(wantNetserveGrants) {
		t.Errorf("ClusterRole %s grants %d group/resources %v, want exactly %v", role.Name, len(got), got, wantNetserveGrants)
	}
	for _, gr := range wantNetserveGrants {
		if verbs, ok := got[gr]; !ok || verbs != "get,list,watch" {
			t.Errorf("ClusterRole %s: %s verbs = %q (present %v), want get,list,watch", role.Name, gr, verbs, ok)
		}
	}
	for gr, verbs := range got {
		for _, forbidden := range []string{"create", "update", "patch", "delete", "deletecollection", "escalate", "bind", "impersonate"} {
			if strings.Contains(","+verbs+",", ","+forbidden+",") {
				t.Errorf("ClusterRole %s grants %s on %s; the netserve identity is read-only", role.Name, forbidden, gr)
			}
		}
		for _, forbidden := range []string{"/secrets", "/configmaps", "/nodes"} {
			if gr == forbidden {
				t.Errorf("ClusterRole %s grants %s on %s; the datapath reads none of them", role.Name, verbs, gr)
			}
		}
	}

	b, err := cs.RbacV1().ClusterRoleBindings().Get(ctx, wantNetserveRole, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get the %s ClusterRoleBinding: %v", wantNetserveRole, err)
	}
	if b.Labels["k3sm.io/managed"] != "true" {
		t.Errorf("ClusterRoleBinding %s labels = %v, want k3sm.io/managed=true", b.Name, b.Labels)
	}
	if b.RoleRef != (rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: wantNetserveRole}) {
		t.Errorf("ClusterRoleBinding %s roleRef = %+v, want ClusterRole %s", b.Name, b.RoleRef, wantNetserveRole)
	}
	want := rbacv1.Subject{APIGroup: rbacv1.GroupName, Kind: "Group", Name: wantNetserveGroup}
	if len(b.Subjects) != 1 || b.Subjects[0] != want {
		t.Errorf("ClusterRoleBinding %s subjects = %+v, want exactly the %s group", b.Name, b.Subjects, wantNetserveGroup)
	}
}

// TestWorkerNodeGrantsAreProvisionedAndMinimal is the gate for the netserve
// identity: every node's datapath authenticates as CN=k3sm:netserve:<node> in
// the k3sm:netservers group, and Provision lays down the one grant it holds. The
// ClusterRole is exactly get/list/watch on services, endpointslices, namespaces,
// networkpolicies and pods, cluster-wide, with no write verb and no secrets,
// configmaps or nodes; the binding's only subject is the group; both carry the
// managed label. Provisioning is idempotent (a second run writes nothing) and
// repairs a drifted copy rather than trusting the name. The two bindings once
// applied by hand to grant the node group what this identity now holds are
// neither provisioned nor deleted by code.
func TestWorkerNodeGrantsAreProvisionedAndMinimal(t *testing.T) {
	ctx := context.Background()

	t.Run("provisioned and exactly the five read grants", func(t *testing.T) {
		cs := fake.NewClientset()
		if err := Provision(ctx, cs); err != nil {
			t.Fatalf("Provision: %v", err)
		}
		assertNetserveGraph(t, cs)
	})

	t.Run("idempotent: a second Provision writes nothing", func(t *testing.T) {
		cs := fake.NewClientset()
		if err := Provision(ctx, cs); err != nil {
			t.Fatalf("Provision: %v", err)
		}
		cs.ClearActions()
		if err := Provision(ctx, cs); err != nil {
			t.Fatalf("second Provision: %v", err)
		}
		for _, a := range cs.Actions() {
			if a.GetResource().Resource != "clusterroles" && a.GetResource().Resource != "clusterrolebindings" {
				continue
			}
			switch a.GetVerb() {
			case "update", "delete", "patch":
				t.Errorf("a second Provision issued %s %s; an in-shape grant must be left alone", a.GetVerb(), a.GetResource().Resource)
			}
		}
		assertNetserveGraph(t, cs)
	})

	t.Run("repairs a drifted role and binding", func(t *testing.T) {
		cs := fake.NewClientset(
			&rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: wantNetserveRole, Labels: map[string]string{"team": "ops"}},
				Rules: []rbacv1.PolicyRule{
					{APIGroups: []string{""}, Resources: []string{"services", "secrets"}, Verbs: []string{"get", "list", "watch", "create"}},
				},
			},
			&rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: wantNetserveRole},
				RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: wantNetserveRole},
				Subjects: []rbacv1.Subject{
					{APIGroup: rbacv1.GroupName, Kind: "Group", Name: wantNetserveGroup},
					{APIGroup: rbacv1.GroupName, Kind: "Group", Name: "system:authenticated"},
				},
			},
		)
		if err := Provision(ctx, cs); err != nil {
			t.Fatalf("Provision: %v", err)
		}
		assertNetserveGraph(t, cs)
		role, _ := cs.RbacV1().ClusterRoles().Get(ctx, wantNetserveRole, metav1.GetOptions{})
		if role.Labels["team"] != "ops" {
			t.Errorf("the repair dropped an operator label: %v", role.Labels)
		}
	})

	t.Run("repairs a binding whose roleRef drifted", func(t *testing.T) {
		cs := fake.NewClientset(&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: wantNetserveRole, Labels: map[string]string{"k3sm.io/managed": "true"}},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects:   []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: "Group", Name: wantNetserveGroup}},
		})
		if err := Provision(ctx, cs); err != nil {
			t.Fatalf("Provision: %v", err)
		}
		assertNetserveGraph(t, cs)
	})

	t.Run("the hand-applied bindings are neither provisioned nor deleted", func(t *testing.T) {
		handApplied := []string{"k3sm:worker-nodes-system-node", "k3sm:worker-node-informers"}
		cs := fake.NewClientset()
		if err := Provision(ctx, cs); err != nil {
			t.Fatalf("Provision: %v", err)
		}
		for _, name := range handApplied {
			if _, err := cs.RbacV1().ClusterRoleBindings().Get(ctx, name, metav1.GetOptions{}); err == nil {
				t.Errorf("Provision created %s; it is the operator's to remove, never code's to recreate", name)
			}
		}

		seeded := fake.NewClientset(
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: handApplied[0]}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "system:node"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: handApplied[1]}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "k3sm:worker-node-informers"}},
		)
		if err := Provision(ctx, seeded); err != nil {
			t.Fatalf("Provision over the hand-applied bindings: %v", err)
		}
		for _, name := range handApplied {
			if _, err := seeded.RbacV1().ClusterRoleBindings().Get(ctx, name, metav1.GetOptions{}); err != nil {
				t.Errorf("Provision deleted %s (%v); deleting it is the operator's step, not code's", name, err)
			}
		}
	})
}
