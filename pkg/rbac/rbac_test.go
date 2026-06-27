package rbac

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	netv1 "k3sm.io/apis/net/v1"
)

// readVerbs is the get/list/watch set the datapath / in-pod reads require.
var readVerbs = map[string]bool{"get": true, "list": true, "watch": true}

// TestRBACNodeDatapathClusterRole proves the node-datapath ClusterRole grants
// exactly the services / endpointslices / meshpeers READ verbs and is bound to the
// system:nodes GROUP — the grant that keeps a joined worker's Service proxy + DNS
// resolver + mesh watcher (system:node:<name>) alive after the Node,RBAC flip — and
// that the provisioner authors only its own k3sm-named objects, never a system:*
// default the apiserver reconciles.
func TestRBACNodeDatapathClusterRole(t *testing.T) {
	cs := fake.NewClientset()
	ctx := context.Background()
	if err := Provision(ctx, cs); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	role, err := cs.RbacV1().ClusterRoles().Get(ctx, nodeDatapathRole, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get node-datapath cluster role: %v", err)
	}

	// The grant is exactly the three read targets, each read-only.
	want := map[string]string{
		"services":       "",                 // core
		"endpointslices": "discovery.k8s.io", // EndpointSlice
		"meshpeers":      netv1.GroupName,    // the net.k3sm.io CRD
	}
	got := map[string]string{}
	for _, r := range role.Rules {
		for _, v := range r.Verbs {
			if !readVerbs[v] {
				t.Errorf("node-datapath rule on %v has non-read verb %q (must be read-only)", r.Resources, v)
			}
		}
		if len(r.APIGroups) != 1 || len(r.Resources) != 1 {
			t.Fatalf("rule must be one group + one resource for an exact assertion, got %+v", r)
		}
		got[r.Resources[0]] = r.APIGroups[0]
	}
	for res, grp := range want {
		if g, ok := got[res]; !ok || g != grp {
			t.Errorf("node-datapath role missing read on %q in group %q (got group %q, present=%v)", res, grp, g, ok)
		}
	}
	for res := range got {
		if _, ok := want[res]; !ok {
			t.Errorf("node-datapath role grants an unexpected resource %q (keep it minimal)", res)
		}
	}

	// Bound to the system:nodes GROUP via our own ClusterRole.
	binding, err := cs.RbacV1().ClusterRoleBindings().Get(ctx, nodeDatapathRole, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get node-datapath cluster role binding: %v", err)
	}
	if binding.RoleRef.Kind != "ClusterRole" || binding.RoleRef.Name != nodeDatapathRole {
		t.Errorf("binding roleRef = %s/%s, want ClusterRole/%s", binding.RoleRef.Kind, binding.RoleRef.Name, nodeDatapathRole)
	}
	if len(binding.Subjects) != 1 || binding.Subjects[0].Kind != "Group" || binding.Subjects[0].Name != systemNodesGroup {
		t.Errorf("binding subjects = %+v, want the single Group %q", binding.Subjects, systemNodesGroup)
	}

	// The provisioner authored only k3sm-named cluster-scoped objects: it must NEVER
	// create/mutate an apiserver default system:* role/binding (two writers fight).
	assertNoSystemObjects(t, cs)
}

// TestRBACInPodReaderBinding proves the minimal namespaced in-pod reader Role +
// RoleBinding: read-only on pods/configmaps/services in the conformance namespace,
// bound to the conformance ServiceAccount — the binding that keeps the M2
// in-pod-kubectl path green under default-deny.
func TestRBACInPodReaderBinding(t *testing.T) {
	cs := fake.NewClientset()
	ctx := context.Background()
	if err := Provision(ctx, cs); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	role, err := cs.RbacV1().Roles(ConformanceNamespace).Get(ctx, inPodReaderRole, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get in-pod reader role: %v", err)
	}
	if len(role.Rules) != 1 {
		t.Fatalf("in-pod reader must have one rule, got %+v", role.Rules)
	}
	for _, v := range role.Rules[0].Verbs {
		if !readVerbs[v] {
			t.Errorf("in-pod reader has non-read verb %q (must be read-only so the SA is denied writes)", v)
		}
	}
	if !sameSet(role.Rules[0].Resources, []string{"pods", "configmaps", "services"}) {
		t.Errorf("in-pod reader resources = %v, want pods/configmaps/services (minimal)", role.Rules[0].Resources)
	}

	binding, err := cs.RbacV1().RoleBindings(ConformanceNamespace).Get(ctx, inPodReaderRole, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get in-pod reader role binding: %v", err)
	}
	if binding.RoleRef.Kind != "Role" || binding.RoleRef.Name != inPodReaderRole {
		t.Errorf("binding roleRef = %s/%s, want Role/%s", binding.RoleRef.Kind, binding.RoleRef.Name, inPodReaderRole)
	}
	s := binding.Subjects
	if len(s) != 1 || s[0].Kind != "ServiceAccount" || s[0].Name != ConformanceServiceAccount || s[0].Namespace != ConformanceNamespace {
		t.Errorf("binding subjects = %+v, want SA %s/%s", s, ConformanceNamespace, ConformanceServiceAccount)
	}
}

// TestRBACProvisionIdempotent confirms a re-run is an AlreadyExists no-op: no error,
// no double-create, and no extra (default) object is authored.
func TestRBACProvisionIdempotent(t *testing.T) {
	cs := fake.NewClientset()
	ctx := context.Background()
	if err := Provision(ctx, cs); err != nil {
		t.Fatalf("first Provision: %v", err)
	}
	if err := Provision(ctx, cs); err != nil {
		t.Fatalf("second Provision (idempotent): %v", err)
	}

	// Exactly one of each object — a double-create would have surfaced as either an
	// error above or a duplicate here.
	roles, err := cs.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list cluster roles: %v", err)
	}
	if len(roles.Items) != 1 || roles.Items[0].Name != nodeDatapathRole {
		t.Errorf("cluster roles = %d %v, want exactly [%s]", len(roles.Items), names(roles.Items), nodeDatapathRole)
	}
	bindings, err := cs.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list cluster role bindings: %v", err)
	}
	if len(bindings.Items) != 1 {
		t.Errorf("cluster role bindings = %d, want exactly 1 (no default-role mutation)", len(bindings.Items))
	}
	assertNoSystemObjects(t, cs)
}

// TestRBACProvisionFailClosed proves the fail-closed contract: when a Create errors
// (here the cluster role, simulating an apiserver that never recovers), Provision
// returns an error and ABORTS — it does not silently continue to the in-pod reader.
func TestRBACProvisionFailClosed(t *testing.T) {
	cs := fake.NewClientset()
	cs.PrependReactor("create", "clusterroles", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewInternalError(errors.New("apiserver still warming"))
	})

	// Bounded so the test is fast (the production Provision retries 6× over ~10s).
	err := provision(context.Background(), cs, 3, time.Millisecond)
	if err == nil {
		t.Fatal("Provision must FAIL CLOSED on a Create error, got nil (would silently lock workers out)")
	}
	if !strings.Contains(err.Error(), "node-datapath cluster role") {
		t.Errorf("error should name the failing object, got %v", err)
	}

	// Aborted before the in-pod reader — never a partial apply that continues.
	if _, err := cs.RbacV1().Roles(ConformanceNamespace).Get(context.Background(), inPodReaderRole, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("in-pod reader must NOT be created after a node-datapath failure, get err = %v", err)
	}
}

// assertNoSystemObjects fails if the provisioner authored any system:* cluster-scoped
// object — it must reference the system:nodes group, never create/mutate a default
// the apiserver reconciles.
func assertNoSystemObjects(t *testing.T, cs *fake.Clientset) {
	t.Helper()
	ctx := context.Background()
	roles, _ := cs.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	for _, r := range roles.Items {
		if strings.HasPrefix(r.Name, "system:") {
			t.Errorf("provisioner authored a system:* ClusterRole %q (must never touch apiserver defaults)", r.Name)
		}
	}
	bindings, _ := cs.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	for _, b := range bindings.Items {
		if strings.HasPrefix(b.Name, "system:") {
			t.Errorf("provisioner authored a system:* ClusterRoleBinding %q (must never touch apiserver defaults)", b.Name)
		}
	}
}

func names(items []rbacv1.ClusterRole) []string {
	out := make([]string, 0, len(items))
	for _, i := range items {
		out = append(out, i.Name)
	}
	return out
}

// sameSet reports whether a and b contain the same elements (order-independent).
func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		m[x]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}
