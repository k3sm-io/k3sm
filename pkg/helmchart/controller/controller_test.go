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

package controller

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"

	helmv1 "k3sm.io/apis/helm/v1"
	"k3sm.io/k3sm/pkg/helmchart"
	"k3sm.io/k3sm/pkg/rbac"
)

const (
	testNS    = "kube-system"
	testChart = "podinfo"
	testHelm  = "/var/lib/k3sm/server/bin/helm-v4.3.0"
	testUID   = "11111111-2222-3333-4444-555555555555"
)

var fixedNow = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

// newChart builds a HelmChart, applying each mutation in turn.
func newChart(mutate ...func(*helmv1.HelmChart)) *helmv1.HelmChart {
	c := &helmv1.HelmChart{
		ObjectMeta: metav1.ObjectMeta{Name: testChart, Namespace: testNS, UID: testUID},
		Spec: helmv1.HelmChartSpec{
			Chart:        testChart,
			ChartContent: "aGVsbG8=",
		},
	}
	for _, fn := range mutate {
		fn(c)
	}
	return c
}

// listKinds is what the fake dynamic client needs to list the two resources
// (an empty scheme, as pkg/mlx/operator's tests explain).
func listKinds() map[schema.GroupVersionResource]string {
	return map[schema.GroupVersionResource]string{
		helmChartResource:       "HelmChartList",
		helmChartConfigResource: "HelmChartConfigList",
	}
}

type harness struct {
	ctrl     *Controller
	kube     *kubefake.Clientset
	dyn      *dynamicfake.FakeDynamicClient
	recorder *record.FakeRecorder
}

func newHarness(t *testing.T, c *helmv1.HelmChart) *harness {
	t.Helper()
	var seed []runtime.Object
	if c != nil {
		u, err := toUnstructured(c)
		if err != nil {
			t.Fatal(err)
		}
		seed = append(seed, u)
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds(), seed...)
	kube := kubefake.NewClientset()
	rec := record.NewFakeRecorder(32)
	ctrl, err := New(Config{Client: kube, Dynamic: dyn, HelmPath: testHelm, Identity: "k3sm-test", Recorder: rec})
	if err != nil {
		t.Fatal(err)
	}
	ctrl.now = func() time.Time { return fixedNow }
	return &harness{ctrl: ctrl, kube: kube, dyn: dyn, recorder: rec}
}

func (h *harness) reconcile(t *testing.T) {
	t.Helper()
	if err := h.ctrl.Reconcile(context.Background(), testNS+"/"+testChart); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
}

func (h *harness) chart(t *testing.T) *helmv1.HelmChart {
	t.Helper()
	u, err := h.dyn.Resource(helmChartResource).Namespace(testNS).Get(context.Background(), testChart, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("read back helmchart: %v", err)
	}
	c, err := toChart(u)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// update rewrites the stored chart through mutate (the spec half, as kubectl
// would).
func (h *harness) update(t *testing.T, mutate func(*helmv1.HelmChart)) {
	t.Helper()
	c := h.chart(t)
	mutate(c)
	u, err := toUnstructured(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.dyn.Resource(helmChartResource).Namespace(testNS).Update(context.Background(), u, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) job(t *testing.T, name string) *batchv1.Job {
	t.Helper()
	j, err := h.kube.BatchV1().Jobs(testNS).Get(context.Background(), name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return j
}

// finishJob stands in for the Job controller, which the fake does not run.
func (h *harness) finishJob(t *testing.T, name string, ct batchv1.JobConditionType) {
	t.Helper()
	j := h.job(t, name)
	if j == nil {
		t.Fatalf("job %s does not exist", name)
	}
	j.Status.Conditions = append(j.Status.Conditions, batchv1.JobCondition{Type: ct, Status: corev1.ConditionTrue})
	if _, err := h.kube.BatchV1().Jobs(testNS).UpdateStatus(context.Background(), j, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) crbExists(t *testing.T) bool {
	t.Helper()
	_, err := h.kube.RbacV1().ClusterRoleBindings().Get(context.Background(), rbac.HelmJobBindingName(testNS, testChart), metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatal(err)
	}
	return err == nil
}

func (h *harness) events() []string {
	var out []string
	for {
		select {
		case e := <-h.recorder.Events:
			out = append(out, e)
		default:
			return out
		}
	}
}

func condition(c *helmv1.HelmChart, t helmv1.HelmChartConditionType) *helmv1.HelmChartCondition {
	return helmchart.FindCondition(c.Status.Conditions, t)
}

func TestHelmChartReconcile(t *testing.T) {
	t.Run("create: configmaps, identity, job, finalizer, JobCreated", func(t *testing.T) {
		h := newHarness(t, newChart(func(c *helmv1.HelmChart) { c.Spec.ValuesContent = "a: 1\n" }))
		h.reconcile(t)
		c := h.chart(t)
		if !slices.Contains(c.Finalizers, helmchart.Finalizer) {
			t.Errorf("finalizers = %v, want %s", c.Finalizers, helmchart.Finalizer)
		}
		values, err := h.kube.CoreV1().ConfigMaps(testNS).Get(context.Background(), "chart-values-podinfo", metav1.GetOptions{})
		if err != nil || values.Data[helmchart.ValuesFile] != "a: 1\n" {
			t.Errorf("values configmap = %v, %v", values, err)
		}
		content, err := h.kube.CoreV1().ConfigMaps(testNS).Get(context.Background(), "chart-content-podinfo", metav1.GetOptions{})
		if err != nil || string(content.BinaryData[helmchart.ChartFile]) != "hello" {
			t.Errorf("content configmap = %v, %v", content, err)
		}
		if _, err := h.kube.CoreV1().ServiceAccounts(testNS).Get(context.Background(), "helm-podinfo", metav1.GetOptions{}); err != nil {
			t.Errorf("job service account: %v", err)
		}
		if !h.crbExists(t) {
			t.Error("the job identity's ClusterRoleBinding was not created")
		}
		job := h.job(t, "helm-install-podinfo")
		if job == nil {
			t.Fatal("no install Job")
		}
		if job.Spec.Template.Spec.Containers[0].Command[0] != testHelm {
			t.Errorf("command[0] = %q, want %q", job.Spec.Template.Spec.Containers[0].Command[0], testHelm)
		}
		if c.Status.JobName != "helm-install-podinfo" {
			t.Errorf("status.jobName = %q", c.Status.JobName)
		}
		if jc := condition(c, helmv1.HelmChartJobCreated); jc == nil || jc.Status != metav1.ConditionTrue {
			t.Errorf("JobCreated = %+v, want True", jc)
		}
		// A second pass changes nothing.
		rv := job.ResourceVersion
		h.reconcile(t)
		if again := h.job(t, "helm-install-podinfo"); again.ResourceVersion != rv {
			t.Error("an unchanged chart rewrote its Job")
		}
	})

	t.Run("spec change: job replaced with the new hash", func(t *testing.T) {
		h := newHarness(t, newChart())
		h.reconcile(t)
		before := h.job(t, "helm-install-podinfo").Annotations[helmchart.AnnotationConfigHash]
		h.update(t, func(c *helmv1.HelmChart) { c.Spec.ValuesContent = "replicas: 3\n" })
		h.reconcile(t)
		job := h.job(t, "helm-install-podinfo")
		if job == nil {
			t.Fatal("no install Job after the spec change")
		}
		if after := job.Annotations[helmchart.AnnotationConfigHash]; after == before {
			t.Errorf("config hash unchanged (%s) after a spec change; the Job was not replaced", after)
		}
	})

	t.Run("config change: overlay applied, job replaced, config events enqueue the chart", func(t *testing.T) {
		h := newHarness(t, newChart())
		h.reconcile(t)
		before := h.job(t, "helm-install-podinfo").Annotations[helmchart.AnnotationConfigHash]
		cfg := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": helmv1.SchemeGroupVersion.String(),
			"kind":       "HelmChartConfig",
			"metadata":   map[string]any{"name": testChart, "namespace": testNS},
			"spec":       map[string]any{"valuesContent": "b: 2\n"},
		}}
		if _, err := h.dyn.Resource(helmChartConfigResource).Namespace(testNS).Create(context.Background(), cfg, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		q := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]())
		defer q.ShutDown()
		enqueue(q, cfg, h.ctrl.log)
		if got, _ := q.Get(); got != testNS+"/"+testChart {
			t.Errorf("a HelmChartConfig event enqueued %q, want the same-named chart", got)
		}
		h.reconcile(t)
		job := h.job(t, "helm-install-podinfo")
		if job.Annotations[helmchart.AnnotationConfigHash] == before {
			t.Error("the overlay did not replace the Job")
		}
		if !slices.Contains(job.Spec.Template.Spec.Containers[0].Command, "/chart/"+helmchart.ConfigValuesFile) {
			t.Errorf("argv %q does not read the overlay", job.Spec.Template.Spec.Containers[0].Command)
		}
		values, _ := h.kube.CoreV1().ConfigMaps(testNS).Get(context.Background(), "chart-values-podinfo", metav1.GetOptions{})
		if values.Data[helmchart.ConfigValuesFile] != "b: 2\n" {
			t.Errorf("values configmap = %v, want the overlay key", values.Data)
		}
	})

	t.Run("job failed under abort: Failed condition and event, job kept", func(t *testing.T) {
		h := newHarness(t, newChart(func(c *helmv1.HelmChart) { c.Spec.FailurePolicy = helmv1.FailurePolicyAbort }))
		h.reconcile(t)
		h.finishJob(t, "helm-install-podinfo", batchv1.JobFailed)
		h.reconcile(t)
		h.reconcile(t)
		c := h.chart(t)
		if f := condition(c, helmv1.HelmChartFailed); f == nil || f.Status != metav1.ConditionTrue || f.Reason != helmchart.ReasonJobFailed {
			t.Errorf("Failed = %+v, want True/%s", f, helmchart.ReasonJobFailed)
		}
		if h.job(t, "helm-install-podinfo") == nil {
			t.Error("abort deleted the failed Job")
		}
		ev := h.events()
		if len(ev) != 1 || !strings.Contains(ev[0], EventReasonInstallFailed) {
			t.Errorf("events = %q, want exactly one %s", ev, EventReasonInstallFailed)
		}
	})

	t.Run("job failed under reinstall: Failed recorded, job deleted and recreated", func(t *testing.T) {
		h := newHarness(t, newChart())
		h.reconcile(t)
		h.finishJob(t, "helm-install-podinfo", batchv1.JobFailed)
		h.reconcile(t)
		if f := condition(h.chart(t), helmv1.HelmChartFailed); f == nil || f.Status != metav1.ConditionTrue {
			t.Errorf("Failed = %+v, want True before the reinstall", f)
		}
		if h.job(t, "helm-install-podinfo") != nil {
			t.Fatal("the failed Job was not deleted")
		}
		h.reconcile(t)
		again := h.job(t, "helm-install-podinfo")
		if again == nil {
			t.Fatal("the install Job was not recreated")
		}
		if len(again.Status.Conditions) != 0 {
			t.Error("the recreated Job carries the old Job's state")
		}
		if f := condition(h.chart(t), helmv1.HelmChartFailed); f == nil || f.Status != metav1.ConditionFalse {
			t.Errorf("Failed = %+v, want False once a new Job runs", f)
		}
	})

	t.Run("insecure repo: Failed InsecureRepo, no job", func(t *testing.T) {
		h := newHarness(t, newChart(func(c *helmv1.HelmChart) {
			c.Spec.ChartContent = ""
			c.Spec.Repo = " http://charts.example"
		}))
		h.reconcile(t)
		h.reconcile(t)
		if h.job(t, "helm-install-podinfo") != nil {
			t.Error("an http:// repo got an install Job")
		}
		if h.crbExists(t) {
			t.Error("an http:// repo got a cluster-admin identity")
		}
		c := h.chart(t)
		if f := condition(c, helmv1.HelmChartFailed); f == nil || f.Status != metav1.ConditionTrue || f.Reason != helmchart.ReasonInsecureRepo {
			t.Errorf("Failed = %+v, want True/InsecureRepo", f)
		}
		if ev := h.events(); len(ev) != 1 || !strings.Contains(ev[0], EventReasonInstallFailed) {
			t.Errorf("events = %q, want one %s", ev, EventReasonInstallFailed)
		}
	})

	t.Run("deletion: delete job, complete, identity gone, finalizer removed", func(t *testing.T) {
		h := newHarness(t, newChart())
		h.reconcile(t)
		markDeleted(t, h)
		h.reconcile(t)
		if h.job(t, "helm-install-podinfo") != nil {
			t.Error("the install Job survived the chart's deletion")
		}
		del := h.job(t, "helm-delete-podinfo")
		if del == nil {
			t.Fatal("no delete Job")
		}
		if got := del.Spec.Template.Spec.Containers[0].Command; !slices.Equal(got[1:], []string{"uninstall", testChart, "-n", testNS, "--ignore-not-found"}) {
			t.Errorf("delete argv = %q", got)
		}
		h.reconcile(t)
		if !slices.Contains(h.chart(t).Finalizers, helmchart.Finalizer) {
			t.Fatal("the finalizer was removed while the delete Job still runs")
		}
		h.finishJob(t, "helm-delete-podinfo", batchv1.JobComplete)
		h.reconcile(t)
		if h.crbExists(t) {
			t.Error("the cluster-admin binding survives the uninstall")
		}
		if f := h.chart(t).Finalizers; slices.Contains(f, helmchart.Finalizer) {
			t.Errorf("finalizers = %v, want %s removed", f, helmchart.Finalizer)
		}
		if ev := h.events(); len(ev) != 0 {
			t.Errorf("a clean uninstall recorded events %q", ev)
		}
	})

	t.Run("delete job failed: finalizer force-cleared with a warning", func(t *testing.T) {
		h := newHarness(t, newChart())
		h.reconcile(t)
		markDeleted(t, h)
		h.reconcile(t)
		h.finishJob(t, "helm-delete-podinfo", batchv1.JobFailed)
		h.reconcile(t)
		if f := h.chart(t).Finalizers; slices.Contains(f, helmchart.Finalizer) {
			t.Errorf("finalizers = %v, want force-cleared", f)
		}
		if h.crbExists(t) {
			t.Error("the cluster-admin binding survives a force-clear")
		}
		ev := h.events()
		if len(ev) != 1 || !strings.Contains(ev[0], EventReasonUninstallFailed) || !strings.Contains(ev[0], "helm uninstall podinfo -n kube-system") {
			t.Errorf("events = %q, want one %s naming the manual helm uninstall", ev, EventReasonUninstallFailed)
		}
	})

	t.Run("a stale delete job from an earlier chart is replaced", func(t *testing.T) {
		h := newHarness(t, newChart())
		h.reconcile(t)
		stale := helmchart.RenderJob(newChart(func(c *helmv1.HelmChart) {
			now := metav1.NewTime(fixedNow)
			c.DeletionTimestamp = &now
			c.UID = "old-uid"
		}), nil, testHelm, "")
		stale.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
		if _, err := h.kube.BatchV1().Jobs(testNS).Create(context.Background(), stale, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		markDeleted(t, h)
		h.reconcile(t)
		if !slices.Contains(h.chart(t).Finalizers, helmchart.Finalizer) {
			t.Fatal("an earlier chart's Complete delete Job released this chart's finalizer")
		}
		if del := h.job(t, "helm-delete-podinfo"); del == nil || del.Annotations[helmchart.AnnotationChartUID] != testUID {
			t.Errorf("delete Job = %+v, want one for uid %s", del, testUID)
		}
	})
}

// markDeleted gives the stored chart a deletionTimestamp, as the apiserver does
// for an object with finalizers (the fake does not).
func markDeleted(t *testing.T, h *harness) {
	t.Helper()
	h.update(t, func(c *helmv1.HelmChart) {
		now := metav1.NewTime(fixedNow)
		c.DeletionTimestamp = &now
	})
}
