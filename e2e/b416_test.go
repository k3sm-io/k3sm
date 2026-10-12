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
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"k3sm.io/k3sm/pkg/svclb"
)

// TestNodePoolSelection is the real-apiserver half of the multi-node ServiceLB
// gate (the table and fake-clientset half is pkg/svclb's test of the same
// name). It proves the report channel the design rests on, under k3sm's
// Node,RBAC authorizer and the NodeRestriction admission plugin:
//
//   - a system:node:<X> identity may merge-patch svclb.k3sm.io/bound on Node X,
//     through the hoster's own write function (svclb.PatchBoundReport);
//   - the same identity is DENIED that patch on another Node Y;
//   - the same identity is DENIED a write to a Service (the node never writes
//     the stamp or the status: no grant was widened for this design);
//   - the node's own Virtual Kubelet status heartbeat leaves the annotation
//     intact (its status patch carries no metadata the annotation is lost in).
//
// Integration tier: a single-node `k3sm server` (hostprocess, --network none, so
// no hoster runs and nothing else writes the annotation), booted by
// hack/lab/b416.sh. The node identity is minted from the server's signing CA
// under $K3SM_WORK_DIR, exactly as the node's own client is.
func TestNodePoolSelection(t *testing.T) {
	c := Up(t)
	ctx := context.Background()
	node := b416ServerNode(t, c)

	t.Run("report channel: own Node patch allowed, other Node denied, heartbeat keeps it", func(t *testing.T) {
		cfg, ok := nodeIdentityConfig(t, node)
		if !ok {
			t.Fatalf("no signing CA under K3SM_WORK_DIR=%q; this leg mints the node identity from it", serverWorkDir())
		}
		cfg.UserAgent = "k3sm-e2e-b416"
		ncs, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			t.Fatalf("build the node identity client: %v", err)
		}

		// Another Node, created as admin, for the cross-node denial.
		other := fmt.Sprintf("b416-other-%d", time.Now().Unix())
		if _, err := c.Client.CoreV1().Nodes().Create(ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: other}}, metav1.CreateOptions{}); err != nil {
			t.Fatalf("create node %s: %v", other, err)
		}
		t.Cleanup(func() { _ = c.Client.CoreV1().Nodes().Delete(context.Background(), other, metav1.DeleteOptions{}) })
		t.Cleanup(func() {
			patch := []byte(`{"metadata":{"annotations":{"` + svclb.BoundAnnotation + `":null}}}`)
			_, _ = c.Client.CoreV1().Nodes().Patch(context.Background(), node, types.MergePatchType, patch, metav1.PatchOptions{})
		})

		value := fmt.Sprintf("e2e-%d;default/b416:uid-1", time.Now().UnixNano())
		if err := svclb.PatchBoundReport(ctx, ncs, node, value); err != nil {
			t.Fatalf("as system:node:%s, patch %s on its OWN Node: %v (want allowed: the Node authorizer and NodeRestriction admit a node's annotation patch on itself)", node, svclb.BoundAnnotation, err)
		}
		got, err := c.Client.CoreV1().Nodes().Get(ctx, node, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get node %s: %v", node, err)
		}
		if got.Annotations[svclb.BoundAnnotation] != value {
			t.Fatalf("node %s %s = %q after the patch, want %q", node, svclb.BoundAnnotation, got.Annotations[svclb.BoundAnnotation], value)
		}

		if err := svclb.PatchBoundReport(ctx, ncs, other, value); !apierrors.IsForbidden(err) {
			t.Errorf("as system:node:%s, patch %s on node %s: err = %v, want Forbidden (a node must not report for another node)", node, svclb.BoundAnnotation, other, err)
		}

		// The node never writes a Service: neither the stamp nor the status.
		svcName := fmt.Sprintf("b416-%d", time.Now().Unix())
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: svcName, Namespace: conformanceNS},
			Spec: corev1.ServiceSpec{
				Type:     corev1.ServiceTypeClusterIP,
				Ports:    []corev1.ServicePort{{Port: 18080, Protocol: corev1.ProtocolTCP}},
				Selector: map[string]string{"app": "b416-none"},
			},
		}
		if _, err := c.Client.CoreV1().Services(conformanceNS).Create(ctx, svc, metav1.CreateOptions{}); err != nil {
			t.Fatalf("create service %s: %v", svcName, err)
		}
		t.Cleanup(func() {
			_ = c.Client.CoreV1().Services(conformanceNS).Delete(context.Background(), svcName, metav1.DeleteOptions{})
		})
		stampPatch := []byte(`{"metadata":{"annotations":{"` + svclb.HostsAnnotation + `":"` + node + `"}}}`)
		if _, err := ncs.CoreV1().Services(conformanceNS).Patch(ctx, svcName, types.MergePatchType, stampPatch, metav1.PatchOptions{}); !apierrors.IsForbidden(err) {
			t.Errorf("as system:node:%s, patch a Service's %s: err = %v, want Forbidden", node, svclb.HostsAnnotation, err)
		}
		statusPatch := []byte(`{"status":{"loadBalancer":{"ingress":[{"ip":"192.0.2.1"}]}}}`)
		if _, err := ncs.CoreV1().Services(conformanceNS).Patch(ctx, svcName, types.MergePatchType, statusPatch, metav1.PatchOptions{}, "status"); !apierrors.IsForbidden(err) {
			t.Errorf("as system:node:%s, patch a Service's status: err = %v, want Forbidden", node, err)
		}

		// Wait for the node's own status heartbeat to land AFTER the report, then
		// require the report intact.
		before := readyHeartbeat(got)
		deadline := time.Now().Add(3 * time.Minute)
		var after *corev1.Node
		for {
			after, err = c.Client.CoreV1().Nodes().Get(ctx, node, metav1.GetOptions{})
			if err == nil && readyHeartbeat(after).After(before) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("node %s posted no status heartbeat within 3m of the report (Ready heartbeat still %s, err %v); the heartbeat leg cannot be judged", node, before, err)
			}
			time.Sleep(2 * time.Second)
		}
		if v := after.Annotations[svclb.BoundAnnotation]; v != value {
			t.Errorf("after the node's status heartbeat at %s, %s = %q, want the report %q intact", readyHeartbeat(after), svclb.BoundAnnotation, v, value)
		}
		t.Logf("node %s: report written as itself, denied on %s and on Services, intact across the heartbeat at %s", node, other, readyHeartbeat(after))
	})
}

// b416ServerNode is the server node under test: $K3SM_B416_NODE, or the
// cluster's only node when it has exactly one.
func b416ServerNode(t *testing.T, c *Cluster) string {
	t.Helper()
	if n := os.Getenv("K3SM_B416_NODE"); n != "" {
		return n
	}
	nodes, err := c.Client.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	if len(nodes.Items) != 1 {
		t.Fatalf("set K3SM_B416_NODE: the cluster has %d nodes, so the server node is ambiguous", len(nodes.Items))
	}
	return nodes.Items[0].Name
}

// readyHeartbeat is the Ready condition's LastHeartbeatTime (zero if absent).
func readyHeartbeat(n *corev1.Node) time.Time {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.LastHeartbeatTime.Time
		}
	}
	return time.Time{}
}
