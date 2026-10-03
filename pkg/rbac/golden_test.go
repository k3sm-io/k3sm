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
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// updateGolden regenerates testdata/rbac-graph.golden. Regenerating it is a grant
// change and belongs only in a reviewed commit that says why.
var updateGolden = flag.Bool("update", false, "rewrite testdata/rbac-graph.golden from the current Provision output")

// rbacGraphGolden is the golden file both this test and the e2e no-new-grant leg
// read: one pinned description of the grant set, not two copies that can drift.
const rbacGraphGolden = "testdata/rbac-graph.golden"

// GoldenObject is the serialized shape of one object Provision creates. Only the
// fields that carry authority (or name the object) are kept, so the golden changes
// exactly when the grant set does.
type GoldenObject struct {
	Kind      string              `json:"kind"`
	Namespace string              `json:"namespace,omitempty"`
	Name      string              `json:"name"`
	Labels    map[string]string   `json:"labels,omitempty"`
	Rules     []rbacv1.PolicyRule `json:"rules,omitempty"`
	RoleRef   *rbacv1.RoleRef     `json:"roleRef,omitempty"`
	Subjects  []rbacv1.Subject    `json:"subjects,omitempty"`
}

// TestRBACGrantSetGolden pins the WHOLE set of objects Provision creates, byte for
// byte, against a golden captured before the in-process node moved off the admin
// identity. That move must not be paid for with a grant: if a later change adds a
// role, a binding, or a rule anywhere in the graph, this test is the one that says
// so, and the diff of the golden is the review artifact.
//
// It also asserts the specific widening that change would be tempted into, by
// name: no created binding gives the upstream system:node ClusterRole, or any role
// that can list or watch secrets or configmaps cluster-wide, to the node group or
// to every authenticated identity.
func TestRBACGrantSetGolden(t *testing.T) {
	cs := fake.NewClientset()
	if err := Provision(context.Background(), cs); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	objs := createdObjects(t, cs.Actions())
	if len(objs) == 0 {
		t.Fatal("Provision created no objects; the golden would pin an empty set")
	}

	got, err := json.MarshalIndent(objs, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')

	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(rbacGraphGolden), 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(rbacGraphGolden, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	want, err := os.ReadFile(rbacGraphGolden)
	if err != nil {
		t.Fatalf("read golden (regenerate with -update in a reviewed commit): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("the provisioned RBAC graph differs from %s; a grant changed.\n--- got ---\n%s\n--- want ---\n%s", rbacGraphGolden, got, want)
	}

	rolesByRef := map[string]GoldenObject{}
	for _, o := range objs {
		if o.Kind == "ClusterRole" || o.Kind == "Role" {
			rolesByRef[o.Kind+"/"+o.Namespace+"/"+o.Name] = o
		}
	}
	for _, o := range objs {
		if o.RoleRef == nil || !bindsNodesOrEveryone(o.Subjects) {
			continue
		}
		if o.RoleRef.Kind == "ClusterRole" && o.RoleRef.Name == "system:node" {
			t.Errorf("%s %s binds the upstream system:node ClusterRole to the node group or to every authenticated identity", o.Kind, o.Name)
		}
		if o.Kind != "ClusterRoleBinding" {
			continue // a RoleBinding is namespace-scoped by construction
		}
		role, ok := rolesByRef["ClusterRole//"+o.RoleRef.Name]
		if !ok {
			// A binding to a role this package did not create is the upstream
			// system:node case above or an outright new grant; both are reds.
			t.Errorf("ClusterRoleBinding %s binds a ClusterRole Provision did not create (%s) to the node group or to every authenticated identity", o.Name, o.RoleRef.Name)
			continue
		}
		if grantsClusterWideSecretOrConfigMapRead(role.Rules) {
			t.Errorf("ClusterRoleBinding %s grants a cluster-wide list/watch of secrets or configmaps (via %s) to the node group or to every authenticated identity", o.Name, role.Name)
		}
	}
}

// createdObjects turns the fake clientset's create actions into GoldenObjects,
// sorted by kind, namespace and name so the golden does not depend on the order
// the provisioner happens to create in.
func createdObjects(t *testing.T, actions []ktesting.Action) []GoldenObject {
	t.Helper()
	var out []GoldenObject
	for _, a := range actions {
		ca, ok := a.(ktesting.CreateAction)
		if !ok || a.GetVerb() != "create" {
			continue
		}
		switch obj := ca.GetObject().(type) {
		case *rbacv1.ClusterRole:
			out = append(out, GoldenObject{Kind: "ClusterRole", Name: obj.Name, Labels: obj.Labels, Rules: obj.Rules})
		case *rbacv1.ClusterRoleBinding:
			ref := obj.RoleRef
			out = append(out, GoldenObject{Kind: "ClusterRoleBinding", Name: obj.Name, Labels: obj.Labels, RoleRef: &ref, Subjects: obj.Subjects})
		case *rbacv1.Role:
			out = append(out, GoldenObject{Kind: "Role", Namespace: obj.Namespace, Name: obj.Name, Labels: obj.Labels, Rules: obj.Rules})
		case *rbacv1.RoleBinding:
			ref := obj.RoleRef
			out = append(out, GoldenObject{Kind: "RoleBinding", Namespace: obj.Namespace, Name: obj.Name, Labels: obj.Labels, RoleRef: &ref, Subjects: obj.Subjects})
		case *corev1.Namespace:
			out = append(out, GoldenObject{Kind: "Namespace", Name: obj.Name, Labels: obj.Labels})
		default:
			t.Fatalf("Provision created an object of an unexpected type %T; extend the golden serializer deliberately", obj)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// bindsNodesOrEveryone reports whether subjects reach a node identity: the
// system:nodes group, any system:node:<name> user, or the two groups every
// identity (authenticated or not) belongs to.
func bindsNodesOrEveryone(subjects []rbacv1.Subject) bool {
	for _, s := range subjects {
		switch {
		case s.Kind == "Group" && (s.Name == systemNodesGroup || s.Name == "system:authenticated" || s.Name == "system:unauthenticated"):
			return true
		case s.Kind == "User" && len(s.Name) > len("system:node:") && s.Name[:len("system:node:")] == "system:node:":
			return true
		}
	}
	return false
}

// grantsClusterWideSecretOrConfigMapRead reports whether rules allow list or watch
// on secrets or configmaps (wildcards included). Called only for a ClusterRole
// bound by a ClusterRoleBinding, where any such rule is cluster-wide.
func grantsClusterWideSecretOrConfigMapRead(rules []rbacv1.PolicyRule) bool {
	has := func(set []string, want ...string) bool {
		for _, s := range set {
			if s == "*" {
				return true
			}
			for _, w := range want {
				if s == w {
					return true
				}
			}
		}
		return false
	}
	for _, r := range rules {
		if has(r.APIGroups, "") && has(r.Resources, "secrets", "configmaps") && has(r.Verbs, "list", "watch") {
			return true
		}
	}
	return false
}
