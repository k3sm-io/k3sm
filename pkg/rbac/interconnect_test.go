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
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/client-go/kubernetes/fake"

	"k3sm.io/apis/config/crd"
)

// grantsInterconnect reports whether any rule allows any verb on the
// Interconnect resource or its subresources (wildcards included).
func grantsInterconnect(rules []rbacv1.PolicyRule) bool {
	resource, group, _ := strings.Cut(crd.InterconnectCRDName, ".") // "interconnects", "net.k3sm.io"
	matches := func(set []string, want func(string) bool) bool {
		for _, s := range set {
			if s == "*" || want(s) {
				return true
			}
		}
		return false
	}
	for _, r := range rules {
		if len(r.Verbs) == 0 {
			continue
		}
		if matches(r.APIGroups, func(s string) bool { return s == group }) &&
			matches(r.Resources, func(s string) bool { return s == resource || strings.HasPrefix(s, resource+"/") }) {
			return true
		}
	}
	return false
}

// TestNodeGroupHasNoInterconnectGrant pins the B524 no-new-RBAC promise: nodes
// never read the Interconnect object (they report and read desired state
// through annotations on their own Node), so no binding that reaches a node
// identity may grant any verb on interconnects.net.k3sm.io. A grant there would
// widen what a node identity may read, which is a human decision.
func TestNodeGroupHasNoInterconnectGrant(t *testing.T) {
	if !grantsInterconnect([]rbacv1.PolicyRule{{APIGroups: []string{"net.k3sm.io"}, Resources: []string{"interconnects"}, Verbs: []string{"get"}}}) ||
		!grantsInterconnect([]rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"list"}}}) ||
		!grantsInterconnect([]rbacv1.PolicyRule{{APIGroups: []string{"net.k3sm.io"}, Resources: []string{"interconnects/status"}, Verbs: []string{"patch"}}}) ||
		grantsInterconnect([]rbacv1.PolicyRule{{APIGroups: []string{"net.k3sm.io"}, Resources: []string{"meshpeers"}, Verbs: []string{"list"}}}) {
		t.Fatal("grantsInterconnect misclassifies a rule; the assertion below would be vacuous")
	}

	cs := fake.NewClientset()
	if err := Provision(context.Background(), cs); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	objs := createdObjects(t, cs.Actions())
	roles := map[string]GoldenObject{}
	for _, o := range objs {
		if o.Kind == "ClusterRole" || o.Kind == "Role" {
			roles[o.Kind+"/"+o.Namespace+"/"+o.Name] = o
		}
	}
	var checked int
	for _, o := range objs {
		if o.RoleRef == nil || !bindsNodesOrEveryone(o.Subjects) {
			continue
		}
		ns := ""
		if o.RoleRef.Kind == "Role" {
			ns = o.Namespace
		}
		role, ok := roles[o.RoleRef.Kind+"/"+ns+"/"+o.RoleRef.Name]
		if !ok {
			t.Errorf("%s %s binds %s %s, which Provision did not create; its rules cannot be checked", o.Kind, o.Name, o.RoleRef.Kind, o.RoleRef.Name)
			continue
		}
		checked++
		if grantsInterconnect(role.Rules) {
			t.Errorf("%s %s grants %s %s, which allows a verb on %s, to a node identity", o.Kind, o.Name, role.Kind, role.Name, crd.InterconnectCRDName)
		}
	}
	if checked == 0 {
		t.Fatal("no binding reaches the node group; the assertion checked nothing")
	}
}
