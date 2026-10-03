//go:build e2e

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

package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"

	"k3sm.io/k3sm/pkg/executor"
)

// The server node-identity gate. A `k3sm server` runs a Virtual Kubelet node in its
// own process; this file proves that node talks to the apiserver as
// system:node:<name> in the system:nodes group, under the Node authorizer and
// NodeRestriction, and that the identity reaches no secret or configmap it is not
// referenced to.
//
// TestB4_InProcessNodeIdentityScoped is the integration tier (a single-node server,
// no root; hack/acceptance/B4.sh). Its first leg is the one that is red on a server
// whose node still rides the admin identity; the policy legs are tripwires that are
// green on either build and go red only if a later change widens a grant.
// TestB4_ServerNodeResolvesReferencedSecret is the lab tier: pods on a real node
// (runtimed) still resolve their Secret and ConfigMap references.

const (
	// b4TripwireUA marks the requests this test itself makes AS the node identity,
	// so the audit legs can tell them from the node's own traffic.
	b4TripwireUA = "k3sm-e2e-b4-tripwire"
	// b4StatusInterval is the Virtual Kubelet node status update interval at the
	// pinned module version (node.DefaultStatusUpdateInterval).
	b4StatusInterval = time.Minute
	// vkLastAppliedObjectMeta is the annotation Virtual Kubelet keeps its last
	// applied Node metadata in; its three-way status patch diffs against it.
	vkLastAppliedObjectMeta = "virtual-kubelet.io/last-applied-object-meta"
	b4OperatorTaintKey      = "k3sm.io/b4-operator"
	b4ControlPlaneLabel     = "node-role.kubernetes.io/control-plane"
	b4RestrictedRoleLabel   = "kubernetes.io/role"
	b4ManagedLabel          = "k3sm.io/managed"
)

// b4AuditEvent is the audit.k8s.io/v1 Event subset the B4 legs read.
type b4AuditEvent struct {
	Stage     string `json:"stage"`
	Verb      string `json:"verb"`
	UserAgent string `json:"userAgent"`
	User      struct {
		Username string   `json:"username"`
		Groups   []string `json:"groups"`
	} `json:"user"`
	ObjectRef *struct {
		Resource    string `json:"resource"`
		Namespace   string `json:"namespace"`
		Name        string `json:"name"`
		APIGroup    string `json:"apiGroup"`
		Subresource string `json:"subresource"`
	} `json:"objectRef"`
	ResponseStatus *struct {
		Code int `json:"code"`
	} `json:"responseStatus"`
	StageTimestamp time.Time `json:"stageTimestamp"`
}

func (e b4AuditEvent) code() int {
	if e.ResponseStatus == nil {
		return 0
	}
	return e.ResponseStatus.Code
}

func (e b4AuditEvent) ok() bool { return e.code() >= 200 && e.code() < 300 }

func (e b4AuditEvent) isWrite() bool { return e.Verb == "update" || e.Verb == "patch" }

func (e b4AuditEvent) completed() bool { return e.Stage == "ResponseComplete" }

// isNodeUser reports an event authenticated as exactly system:node:<node> in the
// system:nodes group, excluding this test's own requests made as that identity.
func (e b4AuditEvent) isNodeUser(node string) bool {
	return e.User.Username == "system:node:"+node && slices.Contains(e.User.Groups, "system:nodes") && e.UserAgent != b4TripwireUA
}

func (e b4AuditEvent) isLeaseWrite(node string) bool {
	r := e.ObjectRef
	return r != nil && e.isWrite() && e.completed() && r.Resource == "leases" && r.APIGroup == "coordination.k8s.io" &&
		r.Namespace == "kube-node-lease" && r.Name == node && r.Subresource == ""
}

func (e b4AuditEvent) isNodeStatusWrite(node string) bool {
	r := e.ObjectRef
	return r != nil && e.isWrite() && e.completed() && r.Resource == "nodes" && r.APIGroup == "" && r.Subresource == "status" && r.Name == node
}

// readB4Audit parses every complete line of the audit log.
func readB4Audit(t *testing.T) []b4AuditEvent {
	t.Helper()
	path := executor.AuditLogPath(serverWorkDir())
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open audit log %s (set K3SM_WORK_DIR to the server work dir): %v", path, err)
	}
	defer f.Close()
	var out []b4AuditEvent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var ev b4AuditEvent
		if json.Unmarshal(sc.Bytes(), &ev) != nil {
			continue // a partial trailing write
		}
		out = append(out, ev)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read audit log %s: %v", path, err)
	}
	return out
}

// b4ServerNode is the server node under test: $K3SM_B4_NODE, or the cluster's only
// node when it has exactly one.
func b4ServerNode(t *testing.T, c *Cluster) string {
	t.Helper()
	if n := os.Getenv("K3SM_B4_NODE"); n != "" {
		return n
	}
	nodes, err := c.Client.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	if len(nodes.Items) != 1 {
		t.Fatalf("set K3SM_B4_NODE: the cluster has %d nodes, so the server node is ambiguous", len(nodes.Items))
	}
	return nodes.Items[0].Name
}

// b4PinnedPod is a native pod pinned to node by nodeName AND the darwin
// nodeSelector, tolerating only the provider taint.
func b4PinnedPod(name, node string, policy corev1.RestartPolicy, command ...string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: conformanceNS},
		Spec: corev1.PodSpec{
			NodeName:      node,
			NodeSelector:  map[string]string{"kubernetes.io/os": "darwin"},
			Tolerations:   []corev1.Toleration{{Key: "k3sm.io/provider", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule}},
			RestartPolicy: policy,
			Containers:    []corev1.Container{{Name: "c", Image: "native", Command: command}},
		},
	}
}

// TestB4_InProcessNodeIdentityScoped is the integration gate for the server node's
// identity. Legs, in order:
//
//  1. identity (the red witness): the node's own Lease and nodes/status are written
//     by system:node:<node> in system:nodes, and never by anyone else after that.
//     It is also the anchor every absence below depends on.
//  4. no new grant: the bindings a node identity is authorized through are exactly
//     the pkg/rbac golden (managed) plus the upstream allowlist.
//  2. policy tripwire: SARs and direct requests as the node identity — no
//     cluster-wide secret/configmap list or watch; a referenced Secret is readable.
//  5. upgrade: after B4.sh seeds a stale restricted label and restarts the
//     server, the boot clears it, status writes succeed as the node, and operator
//     labels and taints survive.
//  3. no attempt: the node never tried a cluster-wide secret/configmap list/watch.
func TestB4_InProcessNodeIdentityScoped(t *testing.T) {
	c := Up(t)
	node := b4ServerNode(t, c)
	nodeUser := "system:node:" + node
	t.Logf("server node %q, audit log %s", node, executor.AuditLogPath(serverWorkDir()))

	anchored := t.Run("leg1 identity: the node's Lease and status are written as system:node", func(t *testing.T) {
		b4LegIdentity(t, node)
	})

	t.Run("leg4 no new grant: node-reachable bindings are the golden plus the upstream allowlist", func(t *testing.T) {
		b4LegNoNewGrant(t, c)
	})

	t.Run("leg2 tripwire: no cluster-wide secret/configmap read; referenced Secret readable", func(t *testing.T) {
		b4LegPolicy(t, c, node, nodeUser)
	})

	t.Run("leg5 upgrade: a stale restricted label does not break status writes after a restart", func(t *testing.T) {
		if !anchored {
			t.Fatal("leg 1 found no write by the node identity, so this leg's absences would be vacuous")
		}
		b4LegUpgrade(t, c, node)
	})

	t.Run("leg3 no attempt: zero cluster-wide secret/configmap list/watch by the node", func(t *testing.T) {
		if !anchored {
			t.Fatal("leg 1 found no write by the node identity, so this leg's absences would be vacuous")
		}
		b4LegNoAttempt(t, node)
	})
}

// b4LegIdentity is leg 1. When the gate restarted the server (K3SM_B4_BOOTED_AT),
// only the current boot counts: while the node was down the node lifecycle
// controller may legitimately have marked its status Unknown, and that is not a
// second heartbeat writer.
func b4LegIdentity(t *testing.T, node string) {
	var since time.Time
	if raw := os.Getenv("K3SM_B4_BOOTED_AT"); raw != "" {
		var err error
		if since, err = time.Parse(time.RFC3339, raw); err != nil {
			t.Fatalf("parse K3SM_B4_BOOTED_AT %q: %v", raw, err)
		}
	}
	var lease, status int
	var first time.Time
	deadline := time.Now().Add(3 * b4StatusInterval)
	for {
		lease, status, first = 0, 0, time.Time{}
		for _, ev := range readB4Audit(t) {
			if !ev.isNodeUser(node) || !ev.ok() || ev.StageTimestamp.Before(since) {
				continue
			}
			isLease, isStatus := ev.isLeaseWrite(node), ev.isNodeStatusWrite(node)
			if isLease {
				lease++
			}
			if isStatus {
				status++
			}
			if (isLease || isStatus) && (first.IsZero() || ev.StageTimestamp.Before(first)) {
				first = ev.StageTimestamp
			}
		}
		if lease > 0 && status > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("within %s: %d Lease writes and %d nodes/status writes by system:node:%s (system:nodes); want at least one of each — the server node is not running on its node identity", 3*b4StatusInterval, lease, status, node)
		}
		time.Sleep(5 * time.Second)
	}
	t.Logf("node identity wrote its Lease %d times and its status %d times; first at %s", lease, status, first.Format(time.RFC3339Nano))

	for _, ev := range readB4Audit(t) {
		if ev.User.Username == "system:node:"+node || !ev.ok() || !ev.StageTimestamp.After(first) {
			continue
		}
		if ev.isLeaseWrite(node) || ev.isNodeStatusWrite(node) {
			t.Errorf("%s %s/%s %s by %q (groups %v) at %s, after the node identity took over; the node's heartbeat must have one writer",
				ev.Verb, ev.ObjectRef.Resource, ev.ObjectRef.Subresource, ev.ObjectRef.Name, ev.User.Username, ev.User.Groups, ev.StageTimestamp.Format(time.RFC3339Nano))
		}
	}
}

// b4Binding is the comparable shape of a binding for leg 4.
type b4Binding struct {
	Kind, Namespace, Name string
	RoleRef               rbacv1.RoleRef
	Subjects              []rbacv1.Subject
}

func (b b4Binding) key() string {
	ns := b.Namespace
	if ns == "" {
		ns = "-"
	}
	return fmt.Sprintf("%s %s %s %s/%s", b.Kind, ns, b.Name, b.RoleRef.Kind, b.RoleRef.Name)
}

func (b b4Binding) subjects() string {
	var s []string
	for _, x := range b.Subjects {
		s = append(s, x.Kind+"/"+x.Namespace+"/"+x.Name)
	}
	sort.Strings(s)
	return strings.Join(s, ",")
}

// b4ReachesNode reports whether subjects include a subject a node identity is
// authorized through.
func b4ReachesNode(subjects []rbacv1.Subject) bool {
	for _, s := range subjects {
		switch {
		case s.Kind == "Group" && (s.Name == "system:nodes" || s.Name == "system:authenticated" || s.Name == "system:unauthenticated"):
			return true
		case s.Kind == "User" && strings.HasPrefix(s.Name, "system:node:"):
			return true
		}
	}
	return false
}

// b4LegNoNewGrant is leg 4.
func b4LegNoNewGrant(t *testing.T, c *Cluster) {
	ctx := context.Background()
	golden, err := os.ReadFile(filepath.Join("..", "pkg", "rbac", "testdata", "rbac-graph.golden"))
	if err != nil {
		t.Fatalf("read the pkg/rbac golden: %v", err)
	}
	var objs []struct {
		Kind      string           `json:"kind"`
		Namespace string           `json:"namespace"`
		Name      string           `json:"name"`
		RoleRef   *rbacv1.RoleRef  `json:"roleRef"`
		Subjects  []rbacv1.Subject `json:"subjects"`
	}
	if err := json.Unmarshal(golden, &objs); err != nil {
		t.Fatalf("parse the pkg/rbac golden: %v", err)
	}
	wantManaged := map[string]string{}
	for _, o := range objs {
		if o.RoleRef == nil || !b4ReachesNode(o.Subjects) {
			continue
		}
		b := b4Binding{Kind: o.Kind, Namespace: o.Namespace, Name: o.Name, RoleRef: *o.RoleRef, Subjects: o.Subjects}
		wantManaged[b.key()] = b.subjects()
	}
	if len(wantManaged) == 0 {
		t.Fatal("the golden pins no node-reachable binding; the comparison would be vacuous")
	}

	allow := map[string]bool{}
	raw, err := os.ReadFile(filepath.Join("testdata", "b4-upstream-node-bindings.txt"))
	if err != nil {
		t.Fatalf("read the upstream allowlist: %v", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		allow[strings.Join(strings.Fields(line), " ")] = true
	}

	var live []b4Binding
	crbs, err := c.Client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list clusterrolebindings: %v", err)
	}
	managed := map[string]bool{}
	for _, b := range crbs.Items {
		live = append(live, b4Binding{Kind: "ClusterRoleBinding", Name: b.Name, RoleRef: b.RoleRef, Subjects: b.Subjects})
		managed[live[len(live)-1].key()] = b.Labels[b4ManagedLabel] == "true"
	}
	rbs, err := c.Client.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list rolebindings: %v", err)
	}
	for _, b := range rbs.Items {
		live = append(live, b4Binding{Kind: "RoleBinding", Namespace: b.Namespace, Name: b.Name, RoleRef: b.RoleRef, Subjects: b.Subjects})
		managed[live[len(live)-1].key()] = b.Labels[b4ManagedLabel] == "true"
	}

	gotManaged := map[string]string{}
	upstream := 0
	for _, b := range live {
		if !b4ReachesNode(b.Subjects) {
			continue
		}
		if managed[b.key()] {
			gotManaged[b.key()] = b.subjects()
			continue
		}
		upstream++
		if !allow[b.key()] {
			t.Errorf("binding %q reaches a node identity (subjects %s) and is neither k3sm-managed nor on the upstream allowlist: a new grant", b.key(), b.subjects())
		}
	}
	if upstream == 0 {
		t.Error("no upstream binding reaches a node identity; the enumeration is broken (system:basic-user at least must match)")
	}
	for k, subj := range wantManaged {
		if got, ok := gotManaged[k]; !ok {
			t.Errorf("managed binding %q (golden) is missing live", k)
		} else if got != subj {
			t.Errorf("managed binding %q subjects = %s, golden %s", k, got, subj)
		}
	}
	for k := range gotManaged {
		if _, ok := wantManaged[k]; !ok {
			t.Errorf("managed binding %q reaches a node identity live but is not in the pkg/rbac golden", k)
		}
	}
	t.Logf("node-reachable bindings: %d managed (== golden), %d upstream (all allowlisted)", len(gotManaged), upstream)
}

// b4LegPolicy is leg 2.
func b4LegPolicy(t *testing.T, c *Cluster, node, nodeUser string) {
	ctx := context.Background()
	run := fmt.Sprintf("%d", time.Now().Unix())
	refName, unrefName, podName := "b4-referenced-"+run, "b4-unreferenced-"+run, "b4-ref-"+run
	for _, name := range []string{refName, unrefName} {
		sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: conformanceNS}, StringData: map[string]string{"key": "b4"}}
		if _, err := c.Client.CoreV1().Secrets(conformanceNS).Create(ctx, sec, metav1.CreateOptions{}); err != nil {
			t.Fatalf("create secret %s: %v", name, err)
		}
		t.Cleanup(func() {
			_ = c.Client.CoreV1().Secrets(conformanceNS).Delete(context.Background(), name, metav1.DeleteOptions{})
		})
	}
	pod := b4PinnedPod(podName, node, corev1.RestartPolicyNever, "/bin/sh", "-c", "exec /usr/bin/tail -f /dev/null")
	pod.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "B4_SECRET", ValueFrom: &corev1.EnvVarSource{
		SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: refName}, Key: "key"},
	}}}
	if _, err := c.Client.CoreV1().Pods(conformanceNS).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create pod %s bound to %s: %v", podName, node, err)
	}
	t.Cleanup(func() { deletePod(context.Background(), c.Client, podName) })

	sar := func(ra authzv1.ResourceAttributes) bool {
		t.Helper()
		r, err := c.Client.AuthorizationV1().SubjectAccessReviews().Create(ctx, &authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{
			User: nodeUser, Groups: []string{"system:nodes", "system:authenticated"}, ResourceAttributes: &ra,
		}}, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("SubjectAccessReview %s %s %s/%s: %v", ra.Verb, ra.Resource, ra.Namespace, ra.Name, err)
		}
		return r.Status.Allowed
	}
	for _, tc := range []struct {
		name string
		ra   authzv1.ResourceAttributes
	}{
		{"list secrets cluster-wide", authzv1.ResourceAttributes{Verb: "list", Resource: "secrets"}},
		{"watch secrets cluster-wide", authzv1.ResourceAttributes{Verb: "watch", Resource: "secrets"}},
		{"list configmaps cluster-wide", authzv1.ResourceAttributes{Verb: "list", Resource: "configmaps"}},
		{"watch configmaps cluster-wide", authzv1.ResourceAttributes{Verb: "watch", Resource: "configmaps"}},
		{"list secrets in default", authzv1.ResourceAttributes{Verb: "list", Resource: "secrets", Namespace: conformanceNS}},
		{"get an unreferenced secret", authzv1.ResourceAttributes{Verb: "get", Resource: "secrets", Namespace: conformanceNS, Name: unrefName}},
	} {
		if sar(tc.ra) {
			t.Errorf("SAR as %s: %s is ALLOWED; want denied", nodeUser, tc.name)
		}
	}
	// Positive control: the Node authorizer's graph learns the pod->secret edge
	// asynchronously, so poll; a timeout is a failure, never a skip.
	refGet := authzv1.ResourceAttributes{Verb: "get", Resource: "secrets", Namespace: conformanceNS, Name: refName}
	if !b4Poll(90*time.Second, func() bool { return sar(refGet) }) {
		t.Fatalf("SAR as %s: get of the referenced secret %s/%s never became allowed within 90s (positive control)", nodeUser, conformanceNS, refName)
	}

	// The same policy, by direct request as the node identity (requests tagged so
	// the audit legs exclude them).
	cfg, ok := nodeIdentityConfig(t, node)
	if !ok {
		t.Fatalf("no signing CA under K3SM_WORK_DIR=%q; this leg mints the node identity from it", serverWorkDir())
	}
	cfg.UserAgent = b4TripwireUA
	ncs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("build the node identity client: %v", err)
	}
	if _, err := ncs.CoreV1().Secrets("").List(ctx, metav1.ListOptions{}); !apierrors.IsForbidden(err) {
		t.Errorf("as %s, LIST secrets cluster-wide: err = %v, want Forbidden", nodeUser, err)
	}
	if w, err := ncs.CoreV1().Secrets("").Watch(ctx, metav1.ListOptions{}); !apierrors.IsForbidden(err) {
		if w != nil {
			w.Stop()
		}
		t.Errorf("as %s, WATCH secrets cluster-wide: err = %v, want Forbidden", nodeUser, err)
	}
	if _, err := ncs.CoreV1().ConfigMaps("").List(ctx, metav1.ListOptions{}); !apierrors.IsForbidden(err) {
		t.Errorf("as %s, LIST configmaps cluster-wide: err = %v, want Forbidden", nodeUser, err)
	}
	if w, err := ncs.CoreV1().ConfigMaps("").Watch(ctx, metav1.ListOptions{}); !apierrors.IsForbidden(err) {
		if w != nil {
			w.Stop()
		}
		t.Errorf("as %s, WATCH configmaps cluster-wide: err = %v, want Forbidden", nodeUser, err)
	}
	if _, err := ncs.CoreV1().Secrets(conformanceNS).Get(ctx, unrefName, metav1.GetOptions{}); !apierrors.IsForbidden(err) {
		t.Errorf("as %s, GET the unreferenced secret: err = %v, want Forbidden", nodeUser, err)
	}
	var lastErr error
	if !b4Poll(90*time.Second, func() bool {
		_, lastErr = ncs.CoreV1().Secrets(conformanceNS).Get(ctx, refName, metav1.GetOptions{})
		return lastErr == nil
	}) {
		t.Fatalf("as %s, GET the referenced secret %s/%s never succeeded within 90s: %v", nodeUser, conformanceNS, refName, lastErr)
	}

	// The pod the reference hangs off is bound and running on the node. (Under the
	// hostprocess runtime the node does not itself read the Secret; the lab tier's
	// TestB4_ServerNodeResolvesReferencedSecret proves the node's own reads.)
	c.WaitPodPhase(t, conformanceNS, podName, corev1.PodRunning, 120*time.Second)
}

// b4LegUpgrade is leg 5, the upgrade case. A server Node registered while the
// in-process node ran as the admin identity can carry kubernetes.io/role both as a
// live label and in the Virtual Kubelet last-applied annotation; under its node
// identity the node may not remove it (NodeRestriction), so its status patch would
// be refused on every interval. hack/acceptance/B4.sh reproduces that Node as admin
// (plus an operator control-plane label and taint), then RESTARTS the server on the
// same work dir, and exports the restart time as K3SM_B4_BOOTED_AT. This leg checks
// that boot: the stale label is gone from both places, the operator's label and
// taint survive, the node stays Ready, writes its status as itself, and is refused
// nothing on nodes.
func b4LegUpgrade(t *testing.T, c *Cluster, node string) {
	ctx := context.Background()
	raw := os.Getenv("K3SM_B4_BOOTED_AT")
	if raw == "" {
		t.Fatal("K3SM_B4_BOOTED_AT is unset: this leg checks the boot after hack/acceptance/B4.sh seeds the upgrade state and restarts the server")
	}
	booted, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		t.Fatalf("parse K3SM_B4_BOOTED_AT %q: %v", raw, err)
	}
	nodes := c.Client.CoreV1().Nodes()
	t.Cleanup(func() {
		_ = retry.RetryOnConflict(retry.DefaultRetry, func() error {
			n, err := nodes.Get(context.Background(), node, metav1.GetOptions{})
			if err != nil {
				return err
			}
			delete(n.Labels, b4ControlPlaneLabel)
			n.Spec.Taints = slices.DeleteFunc(n.Spec.Taints, func(x corev1.Taint) bool { return x.Key == b4OperatorTaintKey })
			_, err = nodes.Update(context.Background(), n, metav1.UpdateOptions{})
			return err
		})
	})

	n, err := nodes.Get(ctx, node, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get node %s: %v", node, err)
	}
	if _, ok := n.Labels[b4ControlPlaneLabel]; !ok {
		t.Fatalf("the seeded operator label %s is absent: B4.sh's upgrade seed did not run (or was lost), so this leg would prove nothing", b4ControlPlaneLabel)
	}
	if v, ok := n.Labels[b4RestrictedRoleLabel]; ok {
		t.Errorf("the stale %s=%s label survived the boot; the node cannot remove it under NodeRestriction", b4RestrictedRoleLabel, v)
	}
	var meta metav1.ObjectMeta
	if err := json.Unmarshal([]byte(n.Annotations[vkLastAppliedObjectMeta]), &meta); err != nil {
		t.Fatalf("parse %s: %v", vkLastAppliedObjectMeta, err)
	}
	if _, ok := meta.Labels[b4RestrictedRoleLabel]; ok {
		t.Errorf("the stale %s label is still in %s, so the node's status patch keeps trying to remove it", b4RestrictedRoleLabel, vkLastAppliedObjectMeta)
	}

	window := 3*b4StatusInterval + 15*time.Second
	end := time.Now().Add(window)
	var notReady, lostLabel, lostTaint int
	for time.Now().Before(end) {
		n, err := nodes.Get(ctx, node, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get node %s: %v", node, err)
		}
		ready := false
		for _, cond := range n.Status.Conditions {
			if cond.Type == corev1.NodeReady && cond.Status == corev1.ConditionTrue {
				ready = true
			}
		}
		if !ready {
			notReady++
		}
		if _, ok := n.Labels[b4ControlPlaneLabel]; !ok {
			lostLabel++
		}
		if !slices.ContainsFunc(n.Spec.Taints, func(x corev1.Taint) bool { return x.Key == b4OperatorTaintKey }) {
			lostTaint++
		}
		time.Sleep(10 * time.Second)
	}
	if notReady > 0 {
		t.Errorf("node %s was not Ready in %d samples over %s", node, notReady, window)
	}
	if lostLabel > 0 {
		t.Errorf("the operator label %s was gone in %d samples; the node must not delete labels it does not own", b4ControlPlaneLabel, lostLabel)
	}
	if lostTaint > 0 {
		t.Errorf("the operator taint %s was gone in %d samples", b4OperatorTaintKey, lostTaint)
	}

	writes, forbidden := 0, 0
	for _, ev := range readB4Audit(t) {
		if !ev.isNodeUser(node) || !ev.StageTimestamp.After(booted) {
			continue
		}
		if ev.isNodeStatusWrite(node) && ev.ok() {
			writes++
		}
		if ev.ObjectRef != nil && ev.ObjectRef.Resource == "nodes" && ev.code() == 403 {
			forbidden++
			t.Errorf("403 to the node identity: %s nodes/%s %s at %s", ev.Verb, ev.ObjectRef.Subresource, ev.ObjectRef.Name, ev.StageTimestamp.Format(time.RFC3339Nano))
		}
	}
	if writes == 0 {
		t.Errorf("no successful nodes/status write by the node identity since the boot at %s (positive control); want at least one", raw)
	}
	t.Logf("since the boot at %s: %d node-identity status writes, %d 403s on nodes", raw, writes, forbidden)
}

// b4LegNoAttempt is leg 3.
func b4LegNoAttempt(t *testing.T, node string) {
	var events int
	for _, ev := range readB4Audit(t) {
		if !ev.isNodeUser(node) {
			continue
		}
		events++
		r := ev.ObjectRef
		if r == nil || r.APIGroup != "" || (r.Resource != "secrets" && r.Resource != "configmaps") || (ev.Verb != "list" && ev.Verb != "watch") {
			continue
		}
		if r.Namespace == "" && r.Name == "" {
			t.Errorf("the node identity issued a cluster-wide %s on %s (stage %s, code %d) at %s", ev.Verb, r.Resource, ev.Stage, ev.code(), ev.StageTimestamp.Format(time.RFC3339Nano))
		}
		if ev.code() == 403 {
			t.Errorf("403 to the node identity on %s %s in %q at %s", ev.Verb, r.Resource, r.Namespace, ev.StageTimestamp.Format(time.RFC3339Nano))
		}
	}
	if events == 0 {
		t.Fatal("the audit log holds no event by the node identity at all; the absence above is vacuous")
	}
	t.Logf("scanned %d audit events by the node identity", events)
}

// b4Poll calls cond every 2s until it is true or timeout passes.
func b4Poll(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(2 * time.Second)
	}
}

// TestB4_ServerNodeResolvesReferencedSecret is the lab-tier regression pin: pods
// pinned to $K3SM_B4_NODE (the runtimed runtime on a real node) resolve a
// secretKeyRef env, a Secret volume and a ConfigMap volume; a restartPolicy Never
// pod with the same references Succeeds (a transient authorization race must never
// fail it); and a Secret update reaches the running pod's volume within two
// refresh ticks.
//
// The pods read their mounts with shell builtins only: a platform binary such as
// /bin/cat, run as a child, does not see the pod's volume paths.
func TestB4_ServerNodeResolvesReferencedSecret(t *testing.T) {
	c := Up(t)
	node := os.Getenv("K3SM_B4_NODE")
	if node == "" {
		t.Fatal("set K3SM_B4_NODE to the node the pods are pinned to")
	}
	ctx := context.Background()
	run := fmt.Sprintf("%d", time.Now().Unix())
	secName, cmName := "b4-rig-sec-"+run, "b4-rig-cm-"+run
	v1, v2, cv := "b4v1"+run, "b4v2"+run, "b4cm"+run

	if _, err := c.Client.CoreV1().Secrets(conformanceNS).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secName, Namespace: conformanceNS}, StringData: map[string]string{"key": v1},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create secret: %v", err)
	}
	t.Cleanup(func() {
		_ = c.Client.CoreV1().Secrets(conformanceNS).Delete(context.Background(), secName, metav1.DeleteOptions{})
	})
	if _, err := c.Client.CoreV1().ConfigMaps(conformanceNS).Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: cmName, Namespace: conformanceNS}, Data: map[string]string{"key": cv},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create configmap: %v", err)
	}
	t.Cleanup(func() {
		_ = c.Client.CoreV1().ConfigMaps(conformanceNS).Delete(context.Background(), cmName, metav1.DeleteOptions{})
	})

	withRefs := func(p *corev1.Pod) *corev1.Pod {
		p.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "B4_ENV", ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: secName}, Key: "key"},
		}}}
		p.Spec.Volumes = []corev1.Volume{
			{Name: "sec", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: secName}}},
			{Name: "cm", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: cmName}}}},
		}
		p.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{
			{Name: "sec", MountPath: "/b4/sec", ReadOnly: true},
			{Name: "cm", MountPath: "/b4/cm", ReadOnly: true},
		}
		return p
	}

	reader := "b4-rig-reader-" + run
	readerPod := withRefs(b4PinnedPod(reader, node, corev1.RestartPolicyAlways, "/bin/sh", "-c",
		`while :; do s=; m=; read -r s < /b4/sec/key; read -r m < /b4/cm/key; echo "B4 env=$B4_ENV sec=$s cm=$m"; sleep 5; done`))
	if _, err := c.Client.CoreV1().Pods(conformanceNS).Create(ctx, readerPod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create reader pod: %v", err)
	}
	t.Cleanup(func() { deletePod(context.Background(), c.Client, reader) })

	once := "b4-rig-never-" + run
	oncePod := withRefs(b4PinnedPod(once, node, corev1.RestartPolicyNever, "/bin/sh", "-c",
		fmt.Sprintf(`s=; m=; read -r s < /b4/sec/key; read -r m < /b4/cm/key; [ "$B4_ENV" = %q ] && [ "$s" = %q ] && [ "$m" = %q ]`, v1, v1, cv)))
	if _, err := c.Client.CoreV1().Pods(conformanceNS).Create(ctx, oncePod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create Never pod: %v", err)
	}
	t.Cleanup(func() { deletePod(context.Background(), c.Client, once) })

	c.WaitPodPhase(t, conformanceNS, reader, corev1.PodRunning, 120*time.Second)
	want := fmt.Sprintf("B4 env=%s sec=%s cm=%s", v1, v1, cv)
	if line := b4WaitLog(t, c, reader, want, 90*time.Second); line == "" {
		t.Fatalf("reader pod never printed %q", want)
	}
	c.WaitPodPhase(t, conformanceNS, once, corev1.PodSucceeded, 120*time.Second)

	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		s, err := c.Client.CoreV1().Secrets(conformanceNS).Get(ctx, secName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		s.StringData = map[string]string{"key": v2}
		_, err = c.Client.CoreV1().Secrets(conformanceNS).Update(ctx, s, metav1.UpdateOptions{})
		return err
	}); err != nil {
		t.Fatalf("update secret: %v", err)
	}
	updated := fmt.Sprintf("sec=%s ", v2)
	if line := b4WaitLog(t, c, reader, updated, 2*time.Minute+30*time.Second); line == "" {
		t.Fatalf("the Secret update never reached the running pod's volume within two refresh ticks (want a line containing %q)", updated)
	}
}

// b4WaitLog polls the pod's recent log lines for one containing want.
func b4WaitLog(t *testing.T, c *Cluster, pod, want string, timeout time.Duration) string {
	t.Helper()
	tail := int64(20)
	var found string
	b4Poll(timeout, func() bool {
		raw, err := c.Client.CoreV1().Pods(conformanceNS).GetLogs(pod, &corev1.PodLogOptions{TailLines: &tail}).DoRaw(context.Background())
		if err != nil {
			return false
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.Contains(line, want) {
				found = line
				return true
			}
		}
		return false
	})
	return found
}
