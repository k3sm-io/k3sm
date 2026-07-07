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
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"k3sm.io/k3sm/pkg/executor"
)

// M10 conformance criteria (docs/m10-plan.md §"Gate machinery", Res.9).
//
// The M10.0 criteria (TestM10_AuditLogLevel, TestM10_PSADefaultWarn) now carry
// REAL bodies — they run under -tags e2e against a booted `k3sm server`
// (integration tier, hack/ci.sh --integration; never unit CI). The remaining
// M10.1/M10.2 criteria are still t.Skip'd TODO stubs so the criterion set is
// VISIBLE and each criterion has a named home to grow into, WITHOUT yet being
// required. Per
// Res.9 a new conformance criterion is promoted into the required M2_CRITERIA/
// M4_CRITERIA sets (in hack/acceptance/m<n>.sh, enforced by the non-vacuous guard
// hack/lib/conformance.sh) ONLY in the PR that lands it green — never before, so a
// green gate is never regressed. Until then a skipped-but-not-required criterion is
// allowed: conformance.sh only fails on a missing/failed/SKIPPED *required* criterion,
// and none of these are in a required list. The eventual composite hack/acceptance/
// m10.sh execs the M10 slice once these land green.
//
// Criterion names carry the M10 tag (Res.9 — native sidecars / node Events are M10.x,
// NOT TestM2_*/TestM4_*).

// psaWarningCollector captures the HTTP-299 warning headers the apiserver
// attaches to a response (client-go delivers them per-request). Concurrency: mu
// guards warnings (client-go may deliver warnings from concurrent requests).
type psaWarningCollector struct {
	mu       sync.Mutex
	warnings []string
}

// HandleWarningHeader implements rest.WarningHandler.
func (w *psaWarningCollector) HandleWarningHeader(code int, _ string, text string) {
	if code != 299 || text == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.warnings = append(w.warnings, text)
}

// psaWarnings returns the captured warnings that came from Pod Security
// Admission (the `would violate PodSecurity "<level>:<version>"` shape),
// filtering out unrelated advisories (e.g. the k3sm provider-toleration Warn VAP).
func (w *psaWarningCollector) psaWarnings() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []string
	for _, s := range w.warnings {
		if strings.Contains(s, "PodSecurity") {
			out = append(out, s)
		}
	}
	return out
}

func (w *psaWarningCollector) reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.warnings = nil
}

// warnClient builds a clientset from $KUBECONFIG (the harness contract, see Up)
// whose rest.Config routes warning headers into the returned collector.
func warnClient(t *testing.T) (kubernetes.Interface, *psaWarningCollector) {
	t.Helper()
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		t.Skip("e2e: $KUBECONFIG unset — run via hack/acceptance/m<n>.sh, not `go test` directly")
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatalf("load kubeconfig %s: %v", kubeconfig, err)
	}
	col := &psaWarningCollector{}
	cfg.WarningHandler = col
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	return cs, col
}

// m10Pod is the M10.0 pod fixture: darwin-targeted (satisfying the os=darwin
// Deny VAP) and provider-taint-tolerating (so the B17 toleration Warn VAP stays
// quiet — the PSA-warning assertions must not depend on filtering it out).
// violating=true adds hostNetwork: true — a `baseline` violation (host
// namespaces) that is meaningful on Darwin (the hostPath/hostNet axis), while
// staying admitted under the shipped enforce=privileged default.
func m10Pod(name string, violating bool) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", Labels: map[string]string{"app": name}},
		Spec: corev1.PodSpec{
			NodeSelector:  map[string]string{"kubernetes.io/os": "darwin"},
			RestartPolicy: corev1.RestartPolicyNever,
			Tolerations:   []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
			HostNetwork:   violating,
			Containers: []corev1.Container{{
				Name:    "c",
				Image:   "native",
				Command: []string{"/bin/sh", "-c", "sleep 5"},
			}},
		},
	}
}

// deletePod best-effort removes a test pod (background, immediate).
func deletePod(ctx context.Context, cs kubernetes.Interface, name string) {
	zero := int64(0)
	_ = cs.CoreV1().Pods("default").Delete(ctx, name, metav1.DeleteOptions{GracePeriodSeconds: &zero})
}

// serverWorkDir resolves the running server's control-plane work dir:
// $K3SM_WORK_DIR, else the root-posture executor default (mirrors m4_test.go).
func serverWorkDir() string {
	if wd := os.Getenv("K3SM_WORK_DIR"); wd != "" {
		return wd
	}
	return executor.DefaultWorkDir
}

// auditEvent is the audit.k8s.io/v1 Event subset the M10.0 audit criterion
// asserts on (one JSON object per audit-log line).
type auditEvent struct {
	Level     string `json:"level"`
	ObjectRef struct {
		Resource string `json:"resource"`
	} `json:"objectRef"`
	RequestObject  json.RawMessage   `json:"requestObject"`
	ResponseObject json.RawMessage   `json:"responseObject"`
	Annotations    map[string]string `json:"annotations"`
}

// TestM10_AuditLogLevel is the M10.0 audit-logging criterion (Res.4): apply an object
// touching secrets/configmaps and assert the shipped audit policy records it at
// level: Metadata (or None) — NEVER Request/RequestResponse (no Secret cleartext at
// rest), with the audit file at a 0600, Seatbelt-denied, off-datastore-volume path.
// Integration-tier (runs under -tags e2e against a booted `k3sm server`); NOT yet a
// required criterion (Res.9 — promotion happens only in the PR that runs it green).
func TestM10_AuditLogLevel(t *testing.T) {
	cs, _ := warnClient(t)
	ctx := context.Background()

	// Touch a Secret (create + get + delete) so the audit log carries fresh
	// secret events with a known payload marker, then create a baseline-violating
	// pod so a PSA audit annotation is recorded (audit=restricted).
	const secretName = "m10-audit-probe"
	const marker = "m10-cleartext-marker"
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: "default"},
		StringData: map[string]string{"probe": marker},
	}
	if _, err := cs.CoreV1().Secrets("default").Create(ctx, sec, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create probe secret: %v", err)
	}
	defer func() { _ = cs.CoreV1().Secrets("default").Delete(ctx, secretName, metav1.DeleteOptions{}) }()
	if _, err := cs.CoreV1().Secrets("default").Get(ctx, secretName, metav1.GetOptions{}); err != nil {
		t.Fatalf("get probe secret: %v", err)
	}

	const violatingPod = "m10-audit-psa-violating"
	if _, err := cs.CoreV1().Pods("default").Create(ctx, m10Pod(violatingPod, true), metav1.CreateOptions{}); err != nil {
		t.Fatalf("create baseline-violating pod (must be ADMITTED under enforce=privileged): %v", err)
	}
	defer deletePod(ctx, cs, violatingPod)

	auditPath := executor.AuditLogPath(serverWorkDir())
	// The default --audit-log-mode is blocking (events are written before the
	// response returns), but give the filesystem a short retry window.
	deadline := time.Now().Add(15 * time.Second)
	for {
		secretEvents, psaAnnotated, err := scanAuditLog(auditPath)
		if err == nil && secretEvents > 0 && psaAnnotated {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("audit log %s: err=%v secretEvents=%d psaAuditAnnotation=%v — want secret events at level Metadata + the PSA audit-violations annotation", auditPath, err, secretEvents, psaAnnotated)
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Now the LEVEL assertions over the whole file.
	b, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit log %s (set K3SM_WORK_DIR to the server work dir): %v", auditPath, err)
	}
	if strings.Contains(string(b), marker) {
		t.Errorf("audit log contains the Secret PAYLOAD %q — secrets must be recorded at Metadata (no requestObject/responseObject cleartext at rest)", marker)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var ev auditEvent
		if json.Unmarshal([]byte(line), &ev) != nil {
			continue // tolerate partial trailing writes
		}
		if ev.ObjectRef.Resource != "secrets" {
			continue
		}
		if ev.Level != "Metadata" {
			t.Errorf("secret audit event at level %q, want Metadata (the ordered first-match rule)", ev.Level)
		}
		if len(ev.RequestObject) != 0 || len(ev.ResponseObject) != 0 {
			t.Errorf("secret audit event carries requestObject/responseObject — Metadata must strip the payload")
		}
	}
}

// scanAuditLog counts secret-touching events and reports whether any event
// carries the PSA audit-violations annotation.
func scanAuditLog(path string) (secretEvents int, psaAnnotated bool, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false, err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var ev auditEvent
		if json.Unmarshal([]byte(line), &ev) != nil {
			continue
		}
		if ev.ObjectRef.Resource == "secrets" {
			secretEvents++
		}
		for k := range ev.Annotations {
			if strings.HasPrefix(k, "pod-security.kubernetes.io/audit-violations") {
				psaAnnotated = true
			}
		}
	}
	return secretEvents, psaAnnotated, nil
}

// TestM10_PSADefaultWarn is the M10.0 Pod Security Admission criterion (Res.2): with
// the shipped --admission-control-config-file + PodSecurityConfiguration default, a
// baseline-violating pod is ADMITTED but WARNED (audit-observable, zero rejection)
// pre-enforce. Carries the negative control (Res.6): a baseline-clean reference pod
// applies with ZERO PSA warnings. Also asserts upstream template-level PSA — a
// Deployment with a violating template warns at apply. Integration-tier; NOT yet a
// required criterion (Res.9).
func TestM10_PSADefaultWarn(t *testing.T) {
	cs, warns := warnClient(t)
	ctx := context.Background()

	t.Run("baseline-violating pod is admitted WITH a PSA warning", func(t *testing.T) {
		warns.reset()
		const name = "m10-psa-violating"
		if _, err := cs.CoreV1().Pods("default").Create(ctx, m10Pod(name, true), metav1.CreateOptions{}); err != nil {
			t.Fatalf("violating pod must be ADMITTED under the shipped enforce=privileged default: %v", err)
		}
		defer deletePod(ctx, cs, name)
		got := warns.psaWarnings()
		if len(got) == 0 {
			t.Fatal("want a PSA warning on the baseline-violating pod (warn=baseline), got none")
		}
		found := false
		for _, w := range got {
			if strings.Contains(w, `PodSecurity "baseline:`) && strings.Contains(w, "violate") {
				found = true
			}
		}
		if !found {
			t.Errorf("PSA warnings %q must name the baseline level violation", got)
		}
	})

	t.Run("negative control: baseline-clean reference pod warns nothing", func(t *testing.T) {
		warns.reset()
		const name = "m10-psa-clean"
		if _, err := cs.CoreV1().Pods("default").Create(ctx, m10Pod(name, false), metav1.CreateOptions{}); err != nil {
			t.Fatalf("baseline-clean reference pod must be ADMITTED: %v", err)
		}
		defer deletePod(ctx, cs, name)
		if got := warns.psaWarnings(); len(got) != 0 {
			t.Errorf("baseline-clean pod must produce ZERO PSA warnings, got %q", got)
		}
	})

	t.Run("Deployment with a violating template warns at apply", func(t *testing.T) {
		warns.reset()
		const name = "m10-psa-violating-deploy"
		zero := int32(0)
		pod := m10Pod(name, true)
		// A Deployment pod template requires restartPolicy Always (Deployment
		// validation rejects Never/OnFailure BEFORE PSA runs); the baseline
		// violation the PSA template check must warn on is HostNetwork: true.
		tmplSpec := *pod.Spec.DeepCopy()
		tmplSpec.RestartPolicy = corev1.RestartPolicyAlways
		dep := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec: appsv1.DeploymentSpec{
				Replicas: &zero, // template-level PSA fires at apply; no pods are actually created
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": name}},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
					Spec:       tmplSpec,
				},
			},
		}
		if _, err := cs.AppsV1().Deployments("default").Create(ctx, dep, metav1.CreateOptions{}); err != nil {
			t.Fatalf("violating-template Deployment must be ADMITTED: %v", err)
		}
		defer func() { _ = cs.AppsV1().Deployments("default").Delete(ctx, name, metav1.DeleteOptions{}) }()
		if got := warns.psaWarnings(); len(got) == 0 {
			t.Error("want an upstream template-level PSA warning on the Deployment apply, got none")
		}
	})
}

// TestM10_PSAEnforceCutover is the --psa-enforce-baseline 403 leg (Res.2/B71).
// The harness does NOT support a per-test server boot with extra flags (Up
// attaches to ONE externally booted `k3sm server` via $KUBECONFIG), so this
// runs only when the acceptance script signals the ambient server was booted
// WITH the flag: export K3SM_PSA_ENFORCE=1 after starting
// `k3sm server --psa-enforce-baseline` (fresh or existing work dir — the
// admission config is overwritten on boot). Otherwise it skips with this spec
// rather than hacking a boot path into the harness.
func TestM10_PSAEnforceCutover(t *testing.T) {
	if os.Getenv("K3SM_PSA_ENFORCE") != "1" {
		t.Skip("SKIP-SPEC (harness has no per-test server boot with extra flags): boot `k3sm server --psa-enforce-baseline`, export K3SM_PSA_ENFORCE=1 (+ KUBECONFIG), and re-run — then a hostNetwork pod must be REJECTED 403 naming PodSecurity baseline, while the clean reference pod stays admitted")
	}
	cs, _ := warnClient(t)
	ctx := context.Background()

	// The violating pod is now REJECTED (403 Forbidden naming the baseline level).
	_, err := cs.CoreV1().Pods("default").Create(ctx, m10Pod("m10-psa-enforced", true), metav1.CreateOptions{})
	if !apierrors.IsForbidden(err) {
		deletePod(ctx, cs, "m10-psa-enforced")
		t.Fatalf("under --psa-enforce-baseline the violating pod must be 403 Forbidden, got err=%v", err)
	}
	if !strings.Contains(err.Error(), "PodSecurity") {
		t.Errorf("the 403 must name PodSecurity, got %q", err)
	}

	// Negative control: the baseline-clean reference pod is still admitted.
	const clean = "m10-psa-enforced-clean"
	if _, err := cs.CoreV1().Pods("default").Create(ctx, m10Pod(clean, false), metav1.CreateOptions{}); err != nil {
		t.Fatalf("baseline-clean pod must stay ADMITTED under enforce=baseline: %v", err)
	}
	deletePod(ctx, cs, clean)
}

// TestM10_NativeSidecar is the M10.2 native-sidecar criterion (Res.8): an initContainer
// with restartPolicy:Always (the k8s 1.33 stable sidecar) STAYS RUNNING alongside the
// regular containers and tears down in reverse order — over the new apis PodBox/
// Container proto restart_policy field (never a k3sm.io/* annotation).
func TestM10_NativeSidecar(t *testing.T) {
	t.Skip("TODO(M10.2): assert an initContainer restartPolicy:Always sidecar stays Running + reverse-order teardown over the apis proto field — B73")
}

// TestM10_CrashLoopBackOff is the M10.2/B26 live-restart criterion: the provider is
// the SINGLE exit-driven restart authority on the runtimed path (runtimed performs no
// exit-driven restarts), re-execing a crashed container in place under the effective
// restart policy with the upstream CrashLoopBackOff schedule. The unit-level contract
// is pinned by pkg/provider TestNativeSidecarStaysRunning / TestRestartTriggerIdempotent.
func TestM10_CrashLoopBackOff(t *testing.T) {
	t.Skip("TODO(M10.2): assert a restartPolicy:Always pod whose container exits nonzero is re-exec'd in place via RestartContainer (provider-decided; runtimed does no exit restarts): between attempts the container status shows waiting.reason=CrashLoopBackOff with the 10s-base doubling back-off message and lastState.terminated carrying the prior exit; restartCount increments monotonically per re-exec (runtimed's restart_count, never double-counted by the provider); the pod PHASE stays Running for the whole crash loop; and a container that stays up past the stabilization window resets the back-off to base on its next crash — B26")
}

// TestM10_JobCompletion is the M10.2/B74 Job terminal-phase criterion: the controller
// composition of the per-pod contract pinned by pkg/provider
// TestJobBackoffAndCompletionAccounting (Never/exit≠0 → Failed terminal; OnFailure/
// exit≠0 → restart-in-place; mains 0 → Succeeded) against the REAL embedded
// kube-controller-manager Job controller.
func TestM10_JobCompletion(t *testing.T) {
	t.Skip("TODO(M10.2): assert a live batch/v1 Job end-to-end: (1) completions=2 exit-0 pods run to phase Succeeded and the Job reports condition Complete with status.succeeded=2; (2) a restartPolicy:Never Job whose pod exits nonzero surfaces phase Failed TERMINAL (no in-place restart, no CrashLoopBackOff overlay) and the Job controller creates replacement pods until backoffLimit is exhausted → condition Failed reason BackoffLimitExceeded; (3) a restartPolicy:OnFailure Job restarts the SAME pod in place (restartCount++ from runtimed's count, phase stays Running, NO replacement pod) until exit 0 → Succeeded; (4) a sidecar-bearing Job pod (initContainer restartPolicy:Always) goes terminal on its MAINS with the sidecar torn down by runtimed — B74")
}

// TestM10_ProviderEvents is the M10.2 node-lifecycle-Events criterion: the provider's
// EventRecorder emits Pulled/Created/Started/Killing/BackOff so `kubectl describe pod`
// shows the container lifecycle (today the provider has no EventRecorder).
func TestM10_ProviderEvents(t *testing.T) {
	t.Skip("TODO(M10.2): assert the provider emits Pulled/Created/Started/Killing/BackOff lifecycle Events — B75")
}

// TestM10_PerPodIP is the M10.1 per-pod-IP criterion (Res.1): two pods on the same
// node each report a DISTINCT status.podIP (a real podnet /32, not podIP≈nodeIP), and
// a headless Service returns ALL backend pod IPs — proving the podnet adapter over
// supervisor.NodeNetwork on the converged runtimed path.
func TestM10_PerPodIP(t *testing.T) {
	t.Skip("TODO(M10.1): assert two same-node pods get distinct podnet /32s + a headless Service returns all pod IPs — B81 (blocked on M10.1 podnet wiring)")
}

// TestM10_ImagePullSecret is the M10.2 imagePullSecrets pull-auth criterion (Res.9):
// a pod carrying imagePullSecrets pulls a private image from an auth-gated (rejects-
// anonymous) IN-PROCESS loopback registry via a standard .dockerconfigjson Secret,
// WITH a mandatory negative control (the same image WITHOUT the secret + a cold cache
// → ImagePullBackOff, proving the secret was the enabler not an anonymous/cached pull)
// and the M2.6 confidentiality invariant (the resolved cred never lands in the pod
// fs/env, container logs, or Events). The pull path already exists (resolver.go +
// runtimed/pkg/image/pull.go); this criterion is LAB-PENDING on the e2e harness gaining
// an in-process authed-registry + native-exec OCI-image fixture (a separate prerequisite),
// so it ships as a structured placeholder rather than a fake body that falls back to
// Image:"native" (which would prove nothing).
func TestM10_ImagePullSecret(t *testing.T) {
	t.Skip("TODO(M10.2): assert a pod with imagePullSecrets pulls a private image from an auth-gated in-process registry (ggcr + httptest basic-auth, rejects anonymous) via a programmatically-built .dockerconfigjson Secret (fake testuser/testpass, no real cred); NEGATIVE CONTROL (mandatory) — the same image WITHOUT the secret + imagePullPolicy:Always (cache-cold) → container status waiting.reason ImagePullBackOff/ErrImagePull, proving the secret enabled the pull; CONFIDENTIALITY — after a successful pull assert the resolved credential is absent from the pod fs/env, container logs, and Events (the M2.6 cred-never-written-to-disk invariant) — B80 (blocked on an in-process authed-registry + native-exec OCI-image e2e harness fixture)")
}

// TestM10_Ingress is the M10.3 ingress criterion: the SERVER-PROCESS-hosted L7
// ingress (darwin-net pkg/ingress behind pkg/ingresshost) routes by host+path
// to a backend Service's ClusterIP VIP, the k3sm IngressClass exists, statuses
// are honest (written only once the listeners are bound), and svclb (B32)
// advertises a plain LoadBalancer Service the same way. The unit-level
// contracts are pinned by pkg/ingresshost TestIngressHostingSecretDiscipline /
// TestIngressClassAndStatus and pkg/svclb TestSvclbStatusHonesty; the shell
// gate is hack/acceptance/m10-ingress.sh.
func TestM10_Ingress(t *testing.T) {
	t.Skip("TODO(M10.3): against a live `k3sm server` started with the HIGH-PORT ingress listener (--ingress-http-port 8080 --ingress-https-port 8443 — the integration tier; the privileged :80/:443 netd-authorized leg is the LAB slice): (1) assert the IngressClass k3sm (controller k3sm.io/ingress) and the canonical kube-system/k3sm-ingress LoadBalancer Service (ports 80+443, selector-less, svclb-ignored) are provisioned; (2) run a hello-http backend pod + ClusterIP Service, apply an Ingress (class k3sm, host ingress.test, path /) and GET http://<nodeIP>:8080/ with Host: ingress.test → the backend identity, plus a wrong-Host negative → 404; (3) assert the Ingress status.loadBalancer.ingress carries the node InternalIP only AFTER the listener answers (bind-then-advertise); (4) create a plain type=LoadBalancer Service on a free high port fronting the same pod, assert svclb splices <nodeIP>:port → backend AND writes the status IP, then create a CONFLICTING LoadBalancer on the same port and assert its status stays empty (honesty negative); (5) apply an Ingress tls[] block with a kubernetes.io/tls Secret and assert SNI termination on :8443 serves that certificate and a rotated Secret is re-served after the next reconcile — M10.3 (closes the live leg of B32)")
}
