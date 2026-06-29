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

// M3 synthetic conformance criteria (DESIGN §9 M3). The SINGLE-NODE-testable
// criteria — TestM3_NodePort and TestM3_PVCPersistsAcrossRestart — run at the
// integration tier in hack/acceptance/m3.sh (which brings up a single-node
// `k3sm server` with a datapath that binds *:nodePort directly). The cross-node
// criterion TestM3_InPodKubectlAndDNSOnWorker is lab-only (two Macs): it SKIPS
// unless $K3SM_WORKER names a joined worker node, and runs under hack/lab/m3.sh.
package e2e

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	storagev1 "k3sm.io/apis/storage/v1"
	"k3sm.io/k3sm/pkg/rbac"
)

// TestM3_NodePort proves a Deployment behind a NodePort Service is reachable on
// the node's *:nodePort wildcard listener — the VSCode SSH NodePort / snapshot
// gRPC range stockkitty feature. It dials the node InternalIP:nodePort and asserts
// the backend answered. Needs routable pod IPs + the NodePort listener (the
// runtimed runtime + a direct/helper datapath, NOT --network none).
func TestM3_NodePort(t *testing.T) {
	c := Up(t)
	ctx := context.Background()
	bin := helperBin(t, "hello-http")
	const name = "m3-nodeport"

	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: conformanceNS},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr(int32(1)),
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": name}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
				Spec: corev1.PodSpec{
					NodeSelector: map[string]string{"kubernetes.io/os": "darwin"},
					Tolerations:  []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
					Containers: []corev1.Container{{
						Name:    "app",
						Image:   "native",
						Command: []string{bin, "-id", "np-ok", "-addr", ":8080"},
						Ports:   []corev1.ContainerPort{{ContainerPort: 8080}},
					}},
				},
			},
		},
	}
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: conformanceNS},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeNodePort,
			Selector: map[string]string{"app": name},
			Ports:    []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromInt32(8080), Protocol: corev1.ProtocolTCP}},
		},
	}

	_ = c.Client.AppsV1().Deployments(conformanceNS).Delete(ctx, name, metav1.DeleteOptions{})
	_ = c.Client.CoreV1().Services(conformanceNS).Delete(ctx, name, metav1.DeleteOptions{})
	if _, err := c.Client.AppsV1().Deployments(conformanceNS).Create(ctx, dep, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create deployment: %v", err)
	}
	created, err := c.Client.CoreV1().Services(conformanceNS).Create(ctx, svc, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create nodeport service: %v", err)
	}
	t.Cleanup(func() {
		_ = c.Client.AppsV1().Deployments(conformanceNS).Delete(ctx, name, metav1.DeleteOptions{})
		_ = c.Client.CoreV1().Services(conformanceNS).Delete(ctx, name, metav1.DeleteOptions{})
	})

	nodePort := created.Spec.Ports[0].NodePort
	if nodePort == 0 {
		t.Fatalf("service %s/%s got no NodePort allocated: %+v", conformanceNS, name, created.Spec)
	}
	url := "http://" + hostPort(darwinNodeIP(t, c), nodePort) + "/"
	waitHTTPBody(t, url, "np-ok", 120*time.Second)
}

// TestM3_PVCPersistsAcrossRestart proves StatefulSet+PVC data survives a pod
// restart — the Postgres / compile-artifacts PVC feature. The pod writes a unique
// marker to its PVC on first start; after the pod is deleted and the StatefulSet
// recreates it (same PVC, Retain), the marker is unchanged.
//
// Canonical criterion name (synced across docs/stockkitty-readiness.md,
// hack/acceptance/conformance/README.md, hack/acceptance/m3.sh, hack/lab/m3.sh).
func TestM3_PVCPersistsAcrossRestart(t *testing.T) {
	c := Up(t)
	ctx := context.Background()
	const name, pod0 = "m3-pvc", "m3-pvc-0"

	// A headless governing Service (StatefulSet requires .spec.serviceName).
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: conformanceNS},
		Spec: corev1.ServiceSpec{
			ClusterIP: corev1.ClusterIPNone,
			Selector:  map[string]string{"app": name},
			Ports:     []corev1.ServicePort{{Port: 80}},
		},
	}
	sc := storagev1.DefaultStorageClassName
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: conformanceNS},
		Spec: appsv1.StatefulSetSpec{
			ServiceName: name,
			Replicas:    ptr(int32(1)),
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": name}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
				Spec: corev1.PodSpec{
					NodeSelector: map[string]string{"kubernetes.io/os": "darwin"},
					Tolerations:  []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
					Containers: []corev1.Container{{
						Name:         "app",
						Image:        "native",
						Command:      []string{"/bin/sh", "-c", `f=/data/marker; [ -f "$f" ] || echo "v-$(date +%s)-$$" > "$f"; echo "MARKER=$(cat "$f")"; exec /usr/bin/tail -f /dev/null`},
						VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/data"}},
					}},
				},
			},
			VolumeClaimTemplates: []corev1.PersistentVolumeClaim{{
				ObjectMeta: metav1.ObjectMeta{Name: "data"},
				Spec: corev1.PersistentVolumeClaimSpec{
					AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
					StorageClassName: &sc,
					Resources:        corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("1Gi")}},
				},
			}},
		},
	}

	_ = c.Client.AppsV1().StatefulSets(conformanceNS).Delete(ctx, name, metav1.DeleteOptions{})
	_ = c.Client.CoreV1().Services(conformanceNS).Delete(ctx, name, metav1.DeleteOptions{})
	if _, err := c.Client.CoreV1().Services(conformanceNS).Create(ctx, svc, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create headless service: %v", err)
	}
	if _, err := c.Client.AppsV1().StatefulSets(conformanceNS).Create(ctx, sts, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create statefulset: %v", err)
	}
	t.Cleanup(func() {
		_ = c.Client.AppsV1().StatefulSets(conformanceNS).Delete(ctx, name, metav1.DeleteOptions{})
		_ = c.Client.CoreV1().Services(conformanceNS).Delete(ctx, name, metav1.DeleteOptions{})
	})

	first := c.WaitPodPhase(t, conformanceNS, pod0, corev1.PodRunning, 120*time.Second)
	marker1 := markerFromLogs(t, c, conformanceNS, pod0)
	if marker1 == "" {
		t.Fatal("no MARKER= in pod logs on first start")
	}

	// Delete pod-0; the StatefulSet recreates it (a NEW UID) against the SAME PVC.
	if err := c.Client.CoreV1().Pods(conformanceNS).Delete(ctx, pod0, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete %s: %v", pod0, err)
	}
	waitPodRecreatedRunning(t, c, conformanceNS, pod0, first.UID, 120*time.Second)

	marker2 := markerFromLogs(t, c, conformanceNS, pod0)
	if marker2 != marker1 {
		t.Errorf("PVC did not persist across restart: marker before=%q after=%q", marker1, marker2)
	}
}

// TestM3_InPodKubectlAndDNSOnWorker proves a pod scheduled on the JOINED worker
// (not the control-plane Mac) resolves cluster DNS and reaches the apiserver via
// the node-local API VIP — the M3.3 infra-VIP mesh-exemption behavior. It is
// LAB-ONLY: skipped unless $K3SM_WORKER names a Ready worker node, so the
// single-node integration gate (hack/acceptance/m3.sh) does not require it while
// the two-Mac lab gate (hack/lab/m3.sh) does.
func TestM3_InPodKubectlAndDNSOnWorker(t *testing.T) {
	c := Up(t)
	ctx := context.Background()
	worker := os.Getenv("K3SM_WORKER")
	if worker == "" {
		t.Skip("LAB-ONLY: set $K3SM_WORKER to a joined worker node (two-Mac rig) — single-node gates do not run this")
	}
	bin := helperBin(t, "conftool")
	ns, sa := rbac.ConformanceNamespace, rbac.ConformanceServiceAccount

	if _, err := c.Client.CoreV1().ServiceAccounts(ns).Create(ctx,
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: sa}}, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create conformance SA %s/%s: %v", ns, sa, err)
	}

	// One pod, pinned to the worker, that BOTH resolves the cluster names AND calls
	// the apiserver (DNS + API VIP both answered node-locally on the worker).
	pod := nativePod("m3-worker-access", "/bin/sh", "-c",
		fmt.Sprintf(`%s resolve -name kubernetes.default.svc && %s apicall -path /api/v1/namespaces/%s/pods -expect-status 200`, bin, bin, ns))
	pod.Spec.ServiceAccountName = sa
	pod.Spec.NodeSelector = nil // pin explicitly to the worker, not the os=darwin scheduler default
	pod.Spec.NodeName = worker
	applyAndWaitSucceeded(t, c, pod, 120*time.Second)
}

// --- M3 helpers ---------------------------------------------------------------

// markerFromLogs returns the MARKER= value the StatefulSet pod logs on start.
func markerFromLogs(t *testing.T, c *Cluster, ns, name string) string {
	t.Helper()
	return parseKV(podLogs(t, c, ns, name))["MARKER"]
}

// waitPodRecreatedRunning blocks until ns/name exists again with a UID different
// from oldUID and phase Running (the StatefulSet recreated pod-0), or fails.
func waitPodRecreatedRunning(t *testing.T, c *Cluster, ns, name string, oldUID types.UID, timeout time.Duration) {
	t.Helper()
	if pollUntil(timeout, func() bool {
		p, err := c.Client.CoreV1().Pods(ns).Get(context.Background(), name, metav1.GetOptions{})
		return err == nil && p.UID != oldUID && p.Status.Phase == corev1.PodRunning
	}) {
		return
	}
	t.Fatalf("StatefulSet did not recreate %s/%s (new UID, Running) within %s", ns, name, timeout)
}
