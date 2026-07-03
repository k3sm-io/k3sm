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

// M2 synthetic conformance criteria (DESIGN §9 M2; docs/stockkitty-readiness.md →
// the assertion→feature map). Each TestM2_<Criterion> is a fails-before/passes-
// after unit named so a red test points to exactly one stockkitty feature class;
// the integration gate hack/acceptance/m2.sh enumerates this set and turns a
// missing OR skipped required criterion RED (the non-vacuous guard). These assert
// real k8s transition semantics (mount mode, downward-API == status.podIP,
// readiness→endpoint removal, liveness→restartCount), not API round-trips, against
// a single-node `k3sm server` brought up with the runtimed runtime + datapath.
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"k3sm.io/k3sm/pkg/rbac"
)

// TestM2_ConfigMapMount proves a ConfigMap is mounted as a file with its content
// intact — the nats-server-config (nats.conf) stockkitty feature. The pod checks a
// sentinel line of the golden testdata/nats.conf payload at the mount path.
func TestM2_ConfigMapMount(t *testing.T) {
	c := Up(t)
	ctx := context.Background()
	const cmName, mountPath = "m2-natsconf", "/etc/nats"

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: cmName, Namespace: conformanceNS},
		Data:       map[string]string{"nats.conf": "port: 4222\njetstream {\n  store_dir: \"/data/jetstream\"\n}\n"},
	}
	_ = c.Client.CoreV1().ConfigMaps(conformanceNS).Delete(ctx, cmName, metav1.DeleteOptions{})
	if _, err := c.Client.CoreV1().ConfigMaps(conformanceNS).Create(ctx, cm, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create configmap: %v", err)
	}
	t.Cleanup(func() { _ = c.Client.CoreV1().ConfigMaps(conformanceNS).Delete(ctx, cmName, metav1.DeleteOptions{}) })

	pod := shellPod("m2-configmap-mount",
		fmt.Sprintf(`f=%s/nats.conf; test -f "$f" || { echo "missing $f"; exit 1; }; grep -q 'port: 4222' "$f" || { echo "content mismatch"; cat "$f"; exit 1; }; echo configmap-ok`, mountPath))
	pod.Spec.Volumes = []corev1.Volume{{
		Name:         "config",
		VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: cmName}}},
	}}
	pod.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "config", MountPath: mountPath, ReadOnly: true}}

	applyAndWaitSucceeded(t, c, pod, 90*time.Second)
}

// TestM2_SecretMount proves a Secret is mounted read-only with mode 0400 — the
// git-ssh-key stockkitty feature. The pod asserts the exact octal mode and content.
func TestM2_SecretMount(t *testing.T) {
	c := Up(t)
	ctx := context.Background()
	const secName, mountPath = "m2-gitssh", "/etc/git"

	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secName, Namespace: conformanceNS},
		StringData: map[string]string{"id_rsa": "SENTINEL-PRIVATE-KEY"},
	}
	_ = c.Client.CoreV1().Secrets(conformanceNS).Delete(ctx, secName, metav1.DeleteOptions{})
	if _, err := c.Client.CoreV1().Secrets(conformanceNS).Create(ctx, sec, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create secret: %v", err)
	}
	t.Cleanup(func() { _ = c.Client.CoreV1().Secrets(conformanceNS).Delete(ctx, secName, metav1.DeleteOptions{}) })

	mode := int32(0o400)
	pod := shellPod("m2-secret-mount",
		fmt.Sprintf(`f=%s/id_rsa; m=$(stat -f %%Lp "$f"); [ "$m" = "400" ] || { echo "mode $m, want 400"; exit 1; }; grep -q SENTINEL "$f" || { echo "content mismatch"; exit 1; }; echo secret-ok`, mountPath))
	pod.Spec.Volumes = []corev1.Volume{{
		Name:         "git",
		VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: secName, DefaultMode: &mode}},
	}}
	pod.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "git", MountPath: mountPath, ReadOnly: true}}

	applyAndWaitSucceeded(t, c, pod, 90*time.Second)
}

// TestM2_EmptyDir proves an emptyDir scratch volume is writable and readable — the
// /dev/shm (snapshot gRPC) stockkitty feature.
func TestM2_EmptyDir(t *testing.T) {
	c := Up(t)
	pod := shellPod("m2-emptydir",
		`d=/scratch; echo conformance > "$d/probe" || exit 1; [ "$(cat "$d/probe")" = conformance ] || exit 1; echo emptydir-ok`)
	pod.Spec.Volumes = []corev1.Volume{{Name: "scratch", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}
	pod.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "scratch", MountPath: "/scratch"}}
	applyAndWaitSucceeded(t, c, pod, 90*time.Second)
}

// TestM2_DownwardAPIEnv proves the downward-API env (spec.nodeName, status.podIP,
// metadata.name) is injected with the RUNTIME-correct values — the mother
// downward-API feature. It asserts the in-pod $MY_POD_IP equals the pod's
// status.podIP (a real reflection of the assigned IP, not a literal round-trip).
func TestM2_DownwardAPIEnv(t *testing.T) {
	c := Up(t)
	const name = "m2-downward-env"
	pod := shellPod(name, `echo "PODIP=$MY_POD_IP NODE=$MY_NODE_NAME NAME=$MY_NAME"; exit 0`)
	pod.Spec.Containers[0].Env = []corev1.EnvVar{
		{Name: "MY_POD_IP", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.podIP"}}},
		{Name: "MY_NODE_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"}}},
		{Name: "MY_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}},
	}
	applyAndWaitSucceeded(t, c, pod, 90*time.Second)

	pod, err := c.Client.CoreV1().Pods(conformanceNS).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get pod: %v", err)
	}
	logs := podLogs(t, c, conformanceNS, name)
	kv := parseKV(logs)
	if kv["PODIP"] == "" || kv["PODIP"] != pod.Status.PodIP {
		t.Errorf("downward $MY_POD_IP = %q, want status.podIP %q", kv["PODIP"], pod.Status.PodIP)
	}
	if kv["NODE"] != pod.Spec.NodeName {
		t.Errorf("downward $MY_NODE_NAME = %q, want spec.nodeName %q", kv["NODE"], pod.Spec.NodeName)
	}
	if kv["NAME"] != name {
		t.Errorf("downward $MY_NAME = %q, want %q", kv["NAME"], name)
	}
}

// TestM2_EnvFrom proves envFrom (configMapRef + secretRef) populates the container
// environment — the bulk-config stockkitty pattern.
func TestM2_EnvFrom(t *testing.T) {
	c := Up(t)
	ctx := context.Background()
	const cmName, secName = "m2-envfrom-cm", "m2-envfrom-sec"

	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: cmName, Namespace: conformanceNS}, Data: map[string]string{"CM_KEY": "cmval"}}
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secName, Namespace: conformanceNS}, StringData: map[string]string{"SECRET_KEY": "secval"}}
	for _, o := range []struct{ del, create func() error }{
		{func() error {
			return c.Client.CoreV1().ConfigMaps(conformanceNS).Delete(ctx, cmName, metav1.DeleteOptions{})
		},
			func() error {
				_, e := c.Client.CoreV1().ConfigMaps(conformanceNS).Create(ctx, cm, metav1.CreateOptions{})
				return e
			}},
		{func() error {
			return c.Client.CoreV1().Secrets(conformanceNS).Delete(ctx, secName, metav1.DeleteOptions{})
		},
			func() error {
				_, e := c.Client.CoreV1().Secrets(conformanceNS).Create(ctx, sec, metav1.CreateOptions{})
				return e
			}},
	} {
		_ = o.del()
		if err := o.create(); err != nil {
			t.Fatalf("create envFrom source: %v", err)
		}
	}
	t.Cleanup(func() {
		_ = c.Client.CoreV1().ConfigMaps(conformanceNS).Delete(ctx, cmName, metav1.DeleteOptions{})
		_ = c.Client.CoreV1().Secrets(conformanceNS).Delete(ctx, secName, metav1.DeleteOptions{})
	})

	pod := shellPod("m2-envfrom",
		`[ "$CM_KEY" = cmval ] || { echo "CM_KEY=$CM_KEY"; exit 1; }; [ "$SECRET_KEY" = secval ] || { echo "SECRET_KEY=$SECRET_KEY"; exit 1; }; echo envfrom-ok`)
	pod.Spec.Containers[0].EnvFrom = []corev1.EnvFromSource{
		{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: cmName}}},
		{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: secName}}},
	}
	applyAndWaitSucceeded(t, c, pod, 90*time.Second)
}

// TestM2_Probes proves the provider-served probe TRANSITIONS (M2.2): a readiness
// failure removes the pod from its Service's Ready endpoints, and a liveness
// failure increments restartCount — the NATS/compile-server probe features. Both
// legs need a routable pod IP (the runtimed runtime), so the gate brings that up.
func TestM2_Probes(t *testing.T) {
	c := Up(t)
	ctx := context.Background()
	bin := helperBin(t, "hello-http")

	t.Run("readiness fail removes endpoint", func(t *testing.T) {
		const name = "m2-probe-readiness"
		pod := nativePod(name, bin, "-id", "ready", "-addr", ":8080", "-healthy-for", "12s")
		pod.Spec.Containers[0].Ports = []corev1.ContainerPort{{ContainerPort: 8080}}
		pod.Spec.Containers[0].ReadinessProbe = httpProbe("/healthz", 8080, 2, 2)

		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: conformanceNS},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": name},
				Ports:    []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromInt32(8080), Protocol: corev1.ProtocolTCP}},
			},
		}
		_ = c.Client.CoreV1().Services(conformanceNS).Delete(ctx, name, metav1.DeleteOptions{})
		if _, err := c.Client.CoreV1().Services(conformanceNS).Create(ctx, svc, metav1.CreateOptions{}); err != nil {
			t.Fatalf("create service: %v", err)
		}
		t.Cleanup(func() { _ = c.Client.CoreV1().Services(conformanceNS).Delete(ctx, name, metav1.DeleteOptions{}) })

		running := applyAndWaitPhase(t, c, pod, corev1.PodRunning, 90*time.Second)
		ip := running.Status.PodIP
		if ip == "" {
			t.Fatal("running pod has no PodIP (need the runtimed runtime + datapath for routable pod IPs)")
		}
		waitEndpointReady(t, c, conformanceNS, name, ip, 60*time.Second)
		// After healthy-for elapses /healthz flips to 503; the readiness probe fails
		// and the address must drop out of the Ready endpoint set.
		waitEndpointNotReady(t, c, conformanceNS, name, ip, 60*time.Second)
	})

	t.Run("liveness fail increments restartCount", func(t *testing.T) {
		const name = "m2-probe-liveness"
		pod := nativePod(name, bin, "-id", "live", "-addr", ":8081", "-live-for", "8s")
		pod.Spec.RestartPolicy = corev1.RestartPolicyAlways
		pod.Spec.Containers[0].Ports = []corev1.ContainerPort{{ContainerPort: 8081}}
		pod.Spec.Containers[0].LivenessProbe = httpProbe("/livez", 8081, 2, 2)

		applyAndWaitPhase(t, c, pod, corev1.PodRunning, 90*time.Second)
		if !pollUntil(60*time.Second, func() bool { return restartCount(t, c, conformanceNS, name) >= 1 }) {
			t.Fatalf("restartCount never reached >=1 (liveness failure did not restart the container)")
		}
	})
}

// TestM2_FsGroup proves securityContext.fsGroup owns the writable mount — the
// postgres fsGroup feature. The pod asserts the mount's group gid equals fsGroup.
func TestM2_FsGroup(t *testing.T) {
	c := Up(t)
	const fsGroup = int64(2000)
	pod := shellPod("m2-fsgroup",
		fmt.Sprintf(`g=$(stat -f %%g /data); [ "$g" = "%d" ] || { echo "gid $g, want %d"; exit 1; }; echo fsgroup-ok`, fsGroup, fsGroup))
	pod.Spec.SecurityContext = &corev1.PodSecurityContext{FSGroup: ptr(fsGroup)}
	pod.Spec.Volumes = []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}
	pod.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "data", MountPath: "/data"}}
	applyAndWaitSucceeded(t, c, pod, 90*time.Second)
}

// TestM2_GracefulStop proves SIGTERM is honored within the grace period — the
// terminationGracePeriodSeconds: 30 feature. The pod traps TERM and exits 0
// promptly; deleting it then completes WELL UNDER the 30s grace, proving the
// container was sent SIGTERM and exited (not SIGKILLed at the grace deadline).
func TestM2_GracefulStop(t *testing.T) {
	c := Up(t)
	const name = "m2-graceful-stop"
	const grace = int64(30)
	pod := shellPod(name, `trap 'echo caught-term; exit 0' TERM; echo ready; while :; do sleep 1; done`)
	pod.Spec.TerminationGracePeriodSeconds = ptr(grace)
	applyAndWaitPhase(t, c, pod, corev1.PodRunning, 90*time.Second)

	start := time.Now()
	if err := c.Client.CoreV1().Pods(conformanceNS).Delete(context.Background(), name, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete pod: %v", err)
	}
	waitPodGone(t, c, conformanceNS, name, time.Duration(grace+15)*time.Second)
	if elapsed := time.Since(start); elapsed >= time.Duration(grace-10)*time.Second {
		t.Errorf("pod took %s to terminate (grace %ds) — SIGTERM not honored, likely SIGKILLed at the deadline", elapsed, grace)
	}
}

// TestM2_ResourceLimitsOOMKilled proves resources.limits.memory enforcement: a pod
// that allocates past its limit is killed with reason OOMKilled (phase Failed) —
// the M2.3 userspace memory-limit kill.
func TestM2_ResourceLimitsOOMKilled(t *testing.T) {
	c := Up(t)
	const name = "m2-oomkilled"
	pod := nativePod(name, helperBin(t, "conftool"), "memhog", "-mb", "512")
	pod.Spec.Containers[0].Resources = corev1.ResourceRequirements{
		Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("64Mi")},
	}
	applyAndWaitPhase(t, c, pod, corev1.PodFailed, 120*time.Second)

	got, err := c.Client.CoreV1().Pods(conformanceNS).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get pod: %v", err)
	}
	if r := terminatedReason(got); r != "OOMKilled" {
		t.Errorf("container terminated reason = %q, want OOMKilled", r)
	}
}

// TestM2_KubectlTop proves the kubelet Summary API reports a real footprint for a
// running pod (the M2.3 ri_phys_footprint → working-set surface that `kubectl top`
// reads). It queries the node's /stats/summary via the apiserver proxy and asserts
// a non-zero working-set for the pod.
func TestM2_KubectlTop(t *testing.T) {
	c := Up(t)
	const name = "m2-top"
	pod := nativePod(name, "/usr/bin/tail", "-f", "/dev/null")
	applyAndWaitPhase(t, c, pod, corev1.PodRunning, 90*time.Second)
	node := darwinNode(t, c).Name

	if !pollUntil(60*time.Second, func() bool { return podWorkingSet(t, c, node, conformanceNS, name) > 0 }) {
		t.Fatalf("kubelet Summary API never reported a non-zero working-set for %s/%s on node %s", conformanceNS, name, node)
	}
}

// TestM2_InPodKubectl proves an in-pod client reaches the apiserver with its
// projected bound SA token + the published CA over kubernetes.default.svc, and is
// AUTHORIZED under the default Node,RBAC for the in-pod-reader grant yet DENIED
// what it was not granted — the snapshotManager in-pod kubectl feature. It binds
// the SAME SA names the M4.1 k3sm:in-pod-reader RoleBinding grants (rbac.Conformance*).
func TestM2_InPodKubectl(t *testing.T) {
	c := Up(t)
	ctx := context.Background()
	bin := helperBin(t, "conftool")
	ns, sa := rbac.ConformanceNamespace, rbac.ConformanceServiceAccount

	if _, err := c.Client.CoreV1().ServiceAccounts(ns).Create(ctx,
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: sa}}, metav1.CreateOptions{}); err != nil && !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("create conformance SA %s/%s: %v", ns, sa, err)
	}

	t.Run("granted read authorized", func(t *testing.T) {
		pod := nativePod("m2-inpod-kubectl", bin, "apicall",
			"-path", "/api/v1/namespaces/"+ns+"/pods", "-expect-status", "200")
		pod.Spec.ServiceAccountName = sa
		applyAndWaitSucceeded(t, c, pod, 90*time.Second)
	})

	t.Run("ungranted read denied 403", func(t *testing.T) {
		pod := nativePod("m2-inpod-kubectl-deny", bin, "apicall",
			"-path", "/api/v1/namespaces/"+ns+"/secrets", "-expect-status", "403")
		pod.Spec.ServiceAccountName = sa
		applyAndWaitSucceeded(t, c, pod, 90*time.Second)
	})
}

// TestM2_InPodDNS proves cluster DNS resolves inside a pod (the getaddrinfo shim
// against the per-node resolver) for the kubernetes Service names — the in-pod DNS
// half of the snapshotManager / mother in-cluster access.
func TestM2_InPodDNS(t *testing.T) {
	c := Up(t)
	pod := nativePod("m2-inpod-dns", helperBin(t, "conftool"), "resolve",
		"-name", "kubernetes.default.svc", "-name", "kubernetes.default.svc.cluster.local")
	applyAndWaitSucceeded(t, c, pod, 90*time.Second)
}

// TestM2_DenyUsers (negative) proves the default-deny Seatbelt profile blocks a pod
// from reading host user data and writing outside its own volumes — the isolation
// contract. The pod ESCAPES (exit 1) if either succeeds; a confined pod exits 0.
// Meaningful only under the runtimed Seatbelt runtime (hostprocess has no sandbox).
func TestM2_DenyUsers(t *testing.T) {
	c := Up(t)
	pod := shellPod("m2-deny-users",
		`if ls /Users >/dev/null 2>&1; then echo "ESCAPE: read /Users"; exit 1; fi; `+
			`if echo x >/k3sm-escape 2>/dev/null; then echo "ESCAPE: wrote outside sandbox"; exit 1; fi; `+
			`echo deny-ok`)
	applyAndWaitSucceeded(t, c, pod, 90*time.Second)
}

// TestM2_ImagePullSecrets is a DEFERRED criterion whose canonical home is now
// TestM10_ImagePullSecret (B80): the imagePullSecrets private-registry pull-auth
// criterion moved to the M10 conformance set once the pull path landed (resolver.go +
// runtimed/pkg/image/pull.go, M2.6). This stub is retained only as the M2 checklist-of-
// record reference (hack/acceptance/conformance/README.md, hack/acceptance/m2.sh);
// the single owning criterion lives in e2e/m10_test.go.
func TestM2_ImagePullSecrets(t *testing.T) {
	Up(t)
	t.Skip("superseded by TestM10_ImagePullSecret — B80 (imagePullSecrets pull-auth criterion; see e2e/m10_test.go)")
}

// TestM2_DaemonSet is a DEFERRED criterion: DaemonSet scheduling is not yet a k3sm
// feature class (single darwin node per Mac; the DaemonSet controller's node-fanout
// is untested under the VK provider). Kept visible as a checklist item.
func TestM2_DaemonSet(t *testing.T) {
	Up(t)
	t.Skip("DEFERRED: DaemonSet scheduling is not yet a k3sm feature class (see docs/stockkitty-readiness.md); tracked, not yet implemented")
}

// --- M2 helpers ---------------------------------------------------------------

// httpProbe builds an httpGet probe on path:port with the given period and failure
// threshold (seconds/count), success threshold 1.
func httpProbe(path string, port int32, periodSeconds, failureThreshold int32) *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler:     corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: path, Port: intstr.FromInt32(port)}},
		PeriodSeconds:    periodSeconds,
		FailureThreshold: failureThreshold,
		SuccessThreshold: 1,
		TimeoutSeconds:   1,
	}
}

// restartCount returns the first container's restartCount (0 if absent).
func restartCount(t *testing.T, c *Cluster, ns, name string) int32 {
	t.Helper()
	pod, err := c.Client.CoreV1().Pods(ns).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil || len(pod.Status.ContainerStatuses) == 0 {
		return 0
	}
	return pod.Status.ContainerStatuses[0].RestartCount
}

// terminatedReason returns the first container's terminated reason (from the
// current or last termination state), "" if the container has not terminated.
func terminatedReason(pod *corev1.Pod) string {
	if len(pod.Status.ContainerStatuses) == 0 {
		return ""
	}
	st := pod.Status.ContainerStatuses[0]
	if st.State.Terminated != nil {
		return st.State.Terminated.Reason
	}
	if st.LastTerminationState.Terminated != nil {
		return st.LastTerminationState.Terminated.Reason
	}
	return ""
}

// summary is the minimal slice of the kubelet Summary API JSON the top criterion
// reads: each pod's working-set bytes.
type summary struct {
	Pods []struct {
		PodRef struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"podRef"`
		Memory struct {
			WorkingSetBytes int64 `json:"workingSetBytes"`
		} `json:"memory"`
	} `json:"pods"`
}

// podWorkingSet returns the working-set bytes the kubelet Summary API reports for
// ns/name on node (0 on any error or if the pod is not yet present in the summary).
func podWorkingSet(t *testing.T, c *Cluster, node, ns, name string) int64 {
	t.Helper()
	raw, err := c.Client.CoreV1().RESTClient().Get().
		AbsPath(fmt.Sprintf("/api/v1/nodes/%s/proxy/stats/summary", node)).DoRaw(context.Background())
	if err != nil {
		return 0
	}
	var s summary
	if json.Unmarshal(raw, &s) != nil {
		return 0
	}
	for _, p := range s.Pods {
		if p.PodRef.Namespace == ns && p.PodRef.Name == name {
			return p.Memory.WorkingSetBytes
		}
	}
	return 0
}

// parseKV parses "K=V K2=V2" tokens (whitespace-separated) from a log line into a
// map; the last occurrence of a key wins.
func parseKV(s string) map[string]string {
	out := map[string]string{}
	for _, f := range strings.Fields(s) {
		if k, v, ok := strings.Cut(f, "="); ok {
			out[k] = v
		}
	}
	return out
}

// ptr returns a pointer to v (for the *int32/*int64 spec fields).
func ptr[T any](v T) *T { return &v }
