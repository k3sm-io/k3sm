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
	"slices"
	"sort"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// grantLine is one authority-bearing fact Provision creates, flattened to a
// comparable string: a role's rule ("rule <kind> <ns>/<name> <groups> <resources>
// <verbs> <names>") or a binding's edge ("bind <kind> <ns>/<name> -> <roleKind>
// <roleName> <subjectKind> <subjectNS>/<subjectName>").
func grantLines(objs []GoldenObject) []string {
	var out []string
	for _, o := range objs {
		id := o.Kind + " " + o.Namespace + "/" + o.Name
		for _, r := range o.Rules {
			out = append(out, fmt.Sprintf("rule %s %v %v %v %v", id, r.APIGroups, r.Resources, r.Verbs, r.ResourceNames))
		}
		if o.RoleRef != nil {
			for _, s := range o.Subjects {
				out = append(out, fmt.Sprintf("bind %s -> %s %s %s %s/%s", id, o.RoleRef.Kind, o.RoleRef.Name, s.Kind, s.Namespace, s.Name))
			}
		}
		if o.Kind == "Namespace" {
			out = append(out, "namespace "+o.Name)
		}
	}
	sort.Strings(out)
	return out
}

// TestProvisionSubjectsUnchanged pins, by explicit assertion and with no -update
// path, every subject, role and verb pkg/rbac.Provision creates. It exists so a
// change to the apiserver's trust flags (the request-header front-proxy trust in
// particular) can be shown to add no grant: the aggregator's front-proxy identity
// is verified by an extension apiserver, never authorized here, so no subject
// named system:auth-proxy may appear anywhere in the graph. Changing the list
// below is a grant change and is reviewed as one.
func TestProvisionSubjectsUnchanged(t *testing.T) {
	cs := fake.NewClientset()
	if err := Provision(context.Background(), cs); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	objs := createdObjects(t, cs.Actions())

	want := []string{
		"bind ClusterRoleBinding /k3sm:node-datapath -> ClusterRole k3sm:node-datapath Group /system:nodes",
		"bind RoleBinding default/k3sm:in-pod-reader -> Role k3sm:in-pod-reader ServiceAccount default/snapshot-manager",
		"bind RoleBinding k3sm-registry/k3sm-registry-advert-reader -> Role k3sm-registry-advert-reader Group /system:nodes",
		"namespace k3sm-registry",
		"rule ClusterRole /k3sm:node-datapath [] [services] [get list watch] []",
		"rule ClusterRole /k3sm:node-datapath [discovery.k8s.io] [endpointslices] [get list watch] []",
		"rule ClusterRole /k3sm:node-datapath [net.k3sm.io] [meshpeers] [get list watch] []",
		"rule Role default/k3sm:in-pod-reader [] [pods configmaps services] [get list watch] []",
		"rule Role k3sm-registry/k3sm-registry-advert-reader [] [configmaps] [get list watch] []",
	}
	sort.Strings(want)
	got := grantLines(objs)
	if !slices.Equal(got, want) {
		t.Errorf("the provisioned grant set changed.\n--- got ---\n%s\n--- want ---\n%s",
			strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	for _, o := range objs {
		for _, s := range o.Subjects {
			if strings.Contains(s.Name, "auth-proxy") {
				t.Errorf("%s %s/%s binds a front-proxy subject %s %q", o.Kind, o.Namespace, o.Name, s.Kind, s.Name)
			}
		}
		for _, r := range o.Rules {
			if slices.Contains(r.Verbs, "impersonate") || slices.Contains(r.Verbs, rbacv1.VerbAll) {
				t.Errorf("%s %s/%s grants %v", o.Kind, o.Namespace, o.Name, r.Verbs)
			}
		}
	}
}
