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

package helmchart

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	helmv1 "k3sm.io/apis/helm/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/policy"
)

const testHelm = "/var/lib/k3sm/server/bin/helm-v4.3.0"

// chart builds a HelmChart in kube-system, applying each mutation in turn.
func chart(mutate ...func(*helmv1.HelmChart)) *helmv1.HelmChart {
	c := &helmv1.HelmChart{
		ObjectMeta: metav1.ObjectMeta{Name: "podinfo", Namespace: "kube-system", UID: "uid-1"},
		Spec: helmv1.HelmChartSpec{
			Chart: "podinfo",
			Repo:  "https://stefanprodan.github.io/podinfo",
		},
	}
	for _, fn := range mutate {
		fn(c)
	}
	return c
}

func TestRenderJob(t *testing.T) {
	deleting := metav1.NewTime(time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC))
	cases := []struct {
		name     string
		chart    *helmv1.HelmChart
		cfg      *helmv1.HelmChartConfig
		wantName string
		wantArgs []string
		egress   bool
		deadline int64
		backoff  int32
		volumes  []string
	}{
		{
			name:     "repo chart: fetched, egress, default timeout and backoff",
			chart:    chart(),
			wantName: "helm-install-podinfo",
			wantArgs: []string{"upgrade", "--install", "podinfo", "podinfo", "--namespace", "kube-system",
				"--repo", "https://stefanprodan.github.io/podinfo", "-f", "/chart/values.yaml",
				"--timeout", "5m0s", "--wait"},
			egress:   true,
			deadline: 600,
			backoff:  1000,
			volumes:  []string{"helm-home", "chart"},
		},
		{
			name: "every flag: target namespace, version, overlay, set, conflicts, ownership",
			chart: chart(func(c *helmv1.HelmChart) {
				c.Spec.TargetNamespace = "apps"
				c.Spec.CreateNamespace = true
				c.Spec.Version = "6.5.0"
				c.Spec.Timeout = &metav1.Duration{Duration: 90 * time.Second}
				c.Spec.BackOffLimit = ptr.To(int32(3))
				c.Spec.ForceConflicts = true
				c.Spec.TakeOwnership = true
				c.Spec.Set = map[string]intstr.IntOrString{
					"replicaCount": intstr.FromInt32(2),
					"ui.message":   intstr.FromString("a,b"),
					"ingress.on":   intstr.FromString("True"),
				}
			}),
			cfg:      &helmv1.HelmChartConfig{Spec: helmv1.HelmChartConfigSpec{ValuesContent: "x: 1\n"}},
			wantName: "helm-install-podinfo",
			wantArgs: []string{"upgrade", "--install", "podinfo", "podinfo", "--namespace", "apps", "--create-namespace",
				"--repo", "https://stefanprodan.github.io/podinfo", "--version", "6.5.0",
				"-f", "/chart/values.yaml", "-f", "/chart/values-10_HelmChartConfig.yaml",
				"--set", "ingress.on=True", "--set", "replicaCount=2", "--set-string", `ui.message=a\,b`,
				"--timeout", "1m30s", "--wait", "--force-conflicts", "--take-ownership"},
			egress:   true,
			deadline: 180,
			backoff:  3,
			volumes:  []string{"helm-home", "chart"},
		},
		{
			name: "chartContent wins over chart: no egress, no repo, archive under /chart",
			chart: chart(func(c *helmv1.HelmChart) {
				c.Spec.ChartContent = "H4sI"
				c.Spec.Version = "ignored"
			}),
			wantName: "helm-install-podinfo",
			wantArgs: []string{"upgrade", "--install", "podinfo", "/chart/chart.tgz", "--namespace", "kube-system",
				"-f", "/chart/values.yaml", "--timeout", "5m0s", "--wait"},
			egress:   false,
			deadline: 600,
			backoff:  1000,
			volumes:  []string{"helm-home", "chart"},
		},
		{
			name: "deleting: delete Job, uninstall argv, no egress, no chart volume",
			chart: chart(func(c *helmv1.HelmChart) {
				c.DeletionTimestamp = &deleting
				c.Spec.TargetNamespace = "apps"
			}),
			wantName: "helm-delete-podinfo",
			wantArgs: []string{"uninstall", "podinfo", "-n", "apps", "--ignore-not-found"},
			egress:   false,
			deadline: 600,
			backoff:  1000,
			volumes:  []string{"helm-home"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			job := RenderJob(tc.chart, tc.cfg, testHelm, "sha256:abc")
			if job.Name != tc.wantName || job.Namespace != "kube-system" {
				t.Errorf("job = %s/%s, want kube-system/%s", job.Namespace, job.Name, tc.wantName)
			}
			pod := job.Spec.Template.Spec
			if len(pod.Containers) != 1 {
				t.Fatalf("containers = %d, want 1", len(pod.Containers))
			}
			ctr := pod.Containers[0]
			if ctr.Image != "native" || ctr.Command[0] != testHelm {
				t.Errorf("image/command[0] = %q/%q, want native/%s", ctr.Image, ctr.Command[0], testHelm)
			}
			if got := ctr.Command[1:]; !reflect.DeepEqual(got, tc.wantArgs) {
				t.Errorf("argv =\n  %q\nwant\n  %q", got, tc.wantArgs)
			}
			if pod.ServiceAccountName != "helm-podinfo" {
				t.Errorf("serviceAccountName = %q, want helm-podinfo", pod.ServiceAccountName)
			}
			if pod.NodeSelector[corev1.LabelOSStable] != "darwin" {
				t.Errorf("nodeSelector = %v, want kubernetes.io/os=darwin", pod.NodeSelector)
			}
			if len(pod.Tolerations) != 1 || pod.Tolerations[0].Key != policy.ProviderTaintKey ||
				pod.Tolerations[0].Operator != corev1.TolerationOpExists {
				t.Errorf("tolerations = %+v, want the provider taint tolerated", pod.Tolerations)
			}
			if pod.RestartPolicy != corev1.RestartPolicyOnFailure {
				t.Errorf("restartPolicy = %q, want OnFailure", pod.RestartPolicy)
			}
			for _, labels := range []map[string]string{job.Labels, job.Spec.Template.Labels} {
				if labels[LabelChart] != "podinfo" || labels["app.kubernetes.io/managed-by"] != "k3sm" {
					t.Errorf("labels = %v, want %s=podinfo and the managed-by label", labels, LabelChart)
				}
			}
			_, egress := job.Spec.Template.Annotations[runtimev1.AnnotationInternetEgress]
			if egress != tc.egress {
				t.Errorf("internet-egress annotation present = %v, want %v", egress, tc.egress)
			}
			if got := ptr.Deref(job.Spec.ActiveDeadlineSeconds, 0); got != tc.deadline {
				t.Errorf("activeDeadlineSeconds = %d, want %d", got, tc.deadline)
			}
			if got := ptr.Deref(job.Spec.BackoffLimit, 0); got != tc.backoff {
				t.Errorf("backoffLimit = %d, want %d", got, tc.backoff)
			}
			var vols []string
			for _, v := range pod.Volumes {
				vols = append(vols, v.Name)
			}
			if !reflect.DeepEqual(vols, tc.volumes) {
				t.Errorf("volumes = %v, want %v", vols, tc.volumes)
			}
			env := map[string]string{}
			for _, e := range ctr.Env {
				env[e.Name] = e.Value
			}
			for _, k := range []string{"HELM_CACHE_HOME", "HELM_CONFIG_HOME", "HELM_DATA_HOME"} {
				if !strings.HasPrefix(env[k], "/helm/") {
					t.Errorf("%s = %q, want a path under the /helm emptyDir", k, env[k])
				}
			}
			if tc.chart.DeletionTimestamp == nil {
				if job.Annotations[AnnotationConfigHash] != "sha256:abc" {
					t.Errorf("install Job config hash = %q, want sha256:abc", job.Annotations[AnnotationConfigHash])
				}
				if o := metav1.GetControllerOfNoCopy(job); o == nil || o.Kind != "HelmChart" || o.UID != "uid-1" {
					t.Errorf("install Job controller owner = %+v, want the HelmChart", o)
				}
				if job.Spec.TTLSecondsAfterFinished != nil {
					t.Error("install Job carries a TTL; only the delete Job outlives its chart")
				}
			} else {
				if len(job.OwnerReferences) != 0 {
					t.Errorf("delete Job ownerReferences = %+v, want none (a foreground cascade would delete it)", job.OwnerReferences)
				}
				if job.Annotations[AnnotationChartUID] != "uid-1" {
					t.Errorf("delete Job chart-uid = %q, want uid-1", job.Annotations[AnnotationChartUID])
				}
				if ptr.Deref(job.Spec.TTLSecondsAfterFinished, 0) != DeleteJobTTLSeconds {
					t.Errorf("delete Job TTL = %v, want %d", job.Spec.TTLSecondsAfterFinished, DeleteJobTTLSeconds)
				}
			}
		})
	}
}

func TestValidateSource(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*helmv1.HelmChart)
		refuse bool
	}{
		{"https repo", nil, false},
		{"oci chart", func(c *helmv1.HelmChart) { c.Spec.Repo = ""; c.Spec.Chart = "oci://ghcr.io/x/y" }, false},
		{"http repo", func(c *helmv1.HelmChart) { c.Spec.Repo = "http://charts.example" }, true},
		{"HTTP chart URL", func(c *helmv1.HelmChart) { c.Spec.Repo = ""; c.Spec.Chart = "HTTP://x/y.tgz" }, true},
		{"leading space the CRD rule misses", func(c *helmv1.HelmChart) { c.Spec.Repo = " http://charts.example" }, true},
		{"http repo ignored under chartContent", func(c *helmv1.HelmChart) {
			c.Spec.Repo = "http://charts.example"
			c.Spec.ChartContent = "H4sI"
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := chart()
			if tc.mutate != nil {
				tc.mutate(c)
			}
			err := ValidateSource(c.Spec)
			if got := errors.Is(err, ErrInsecureRepo); got != tc.refuse {
				t.Errorf("ValidateSource = %v, want refused=%v", err, tc.refuse)
			}
		})
	}
}

func TestRenderConfigMaps(t *testing.T) {
	c := chart(func(c *helmv1.HelmChart) {
		c.Spec.ValuesContent = "a: 1\n"
		c.Spec.ChartContent = "aGVsbG8=" // "hello"
	})
	values, content, err := RenderConfigMaps(c, &helmv1.HelmChartConfig{Spec: helmv1.HelmChartConfigSpec{ValuesContent: "b: 2\n"}})
	if err != nil {
		t.Fatal(err)
	}
	if values.Name != "chart-values-podinfo" || values.Data[ValuesFile] != "a: 1\n" || values.Data[ConfigValuesFile] != "b: 2\n" {
		t.Errorf("values ConfigMap = %s %v", values.Name, values.Data)
	}
	if content == nil || content.Name != "chart-content-podinfo" || string(content.BinaryData[ChartFile]) != "hello" {
		t.Errorf("content ConfigMap = %+v, want chart-content-podinfo carrying the decoded archive", content)
	}
	for _, cm := range []*corev1.ConfigMap{values, content} {
		if o := metav1.GetControllerOfNoCopy(cm); o == nil || o.UID != "uid-1" {
			t.Errorf("%s owner = %+v, want the HelmChart", cm.Name, o)
		}
	}

	_, content, err = RenderConfigMaps(chart(), nil)
	if err != nil || content != nil {
		t.Errorf("no chartContent: content = %v, err = %v; want nil, nil", content, err)
	}
	_, _, err = RenderConfigMaps(chart(func(c *helmv1.HelmChart) { c.Spec.ChartContent = "!!not base64" }), nil)
	if !errors.Is(err, ErrInvalidChartContent) {
		t.Errorf("bad chartContent err = %v, want ErrInvalidChartContent", err)
	}
}

func TestConfigHash(t *testing.T) {
	base := chart().Spec
	cfg := &helmv1.HelmChartConfig{Spec: helmv1.HelmChartConfigSpec{ValuesContent: "a: 1\n"}}
	h := ConfigHash(base, cfg)
	if !strings.HasPrefix(h, "sha256:") || len(h) != len("sha256:")+64 {
		t.Fatalf("ConfigHash = %q, want sha256:<64 hex>", h)
	}
	if ConfigHash(base, cfg) != h {
		t.Error("ConfigHash is not deterministic")
	}
	set := func(m map[string]intstr.IntOrString) helmv1.HelmChartSpec { s := base; s.Set = m; return s }
	if ConfigHash(set(map[string]intstr.IntOrString{"a": intstr.FromInt32(1), "b": intstr.FromString("x")}), nil) !=
		ConfigHash(set(map[string]intstr.IntOrString{"b": intstr.FromString("x"), "a": intstr.FromInt32(1)}), nil) {
		t.Error("ConfigHash depends on map insertion order")
	}
	changed := []struct {
		name string
		spec helmv1.HelmChartSpec
		cfg  *helmv1.HelmChartConfig
	}{
		{"version", func() helmv1.HelmChartSpec { s := base; s.Version = "2"; return s }(), cfg},
		{"values", func() helmv1.HelmChartSpec { s := base; s.ValuesContent = "z: 1"; return s }(), cfg},
		{"overlay", base, &helmv1.HelmChartConfig{Spec: helmv1.HelmChartConfigSpec{ValuesContent: "a: 2\n"}}},
		{"overlay removed", base, nil},
		{"set", set(map[string]intstr.IntOrString{"k": intstr.FromInt32(1)}), cfg},
	}
	for _, tc := range changed {
		t.Run(tc.name, func(t *testing.T) {
			if ConfigHash(tc.spec, tc.cfg) == h {
				t.Errorf("changing the %s did not change the hash", tc.name)
			}
		})
	}
	// The overlay's other fields are not applied, so they do not move the hash.
	ignored := &helmv1.HelmChartConfig{Spec: helmv1.HelmChartConfigSpec{ValuesContent: "a: 1\n", FailurePolicy: "abort"}}
	if ConfigHash(base, ignored) != h {
		t.Error("an overlay field the controller does not apply changed the hash")
	}
}

func TestStatusConditions(t *testing.T) {
	t0 := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Minute)
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "helm-install-podinfo", Namespace: "kube-system"}}
	withCond := func(ct batchv1.JobConditionType) *batchv1.Job {
		j := job.DeepCopy()
		j.Status.Conditions = []batchv1.JobCondition{{Type: ct, Status: corev1.ConditionTrue}}
		return j
	}

	t.Run("StateOf", func(t *testing.T) {
		for _, tc := range []struct {
			job  *batchv1.Job
			want JobState
		}{{job, JobRunning}, {withCond(batchv1.JobComplete), JobComplete}, {withCond(batchv1.JobFailed), JobFailed}} {
			if got := StateOf(tc.job); got != tc.want {
				t.Errorf("StateOf(%v) = %v, want %v", tc.job.Status.Conditions, got, tc.want)
			}
		}
	})

	t.Run("running Job: JobCreated True with k3s's reason, Failed False", func(t *testing.T) {
		st := InstallStatus(chart(), job, JobRunning, t0)
		if st.JobName != "helm-install-podinfo" {
			t.Errorf("jobName = %q", st.JobName)
		}
		jc := FindCondition(st.Conditions, helmv1.HelmChartJobCreated)
		if jc == nil || jc.Status != metav1.ConditionTrue || jc.Reason != "Job created" ||
			jc.Message != "Applying HelmChart using Job kube-system/helm-install-podinfo" {
			t.Errorf("JobCreated = %+v", jc)
		}
		if f := FindCondition(st.Conditions, helmv1.HelmChartFailed); f == nil || f.Status != metav1.ConditionFalse {
			t.Errorf("Failed = %+v, want False", f)
		}
	})

	t.Run("failed Job: Failed True, transition stamped once", func(t *testing.T) {
		c := chart()
		c.Status = InstallStatus(c, job, JobRunning, t0)
		st := InstallStatus(c, job, JobFailed, t1)
		f := FindCondition(st.Conditions, helmv1.HelmChartFailed)
		if f == nil || f.Status != metav1.ConditionTrue || f.Reason != "Job failed" || !f.LastTransitionTime.Time.Equal(t1) {
			t.Fatalf("Failed = %+v, want True/Job failed transitioned at t1", f)
		}
		jc := FindCondition(st.Conditions, helmv1.HelmChartJobCreated)
		if !jc.LastTransitionTime.Time.Equal(t0) || !jc.LastUpdateTime.Time.Equal(t0) {
			t.Errorf("an unchanged JobCreated was restamped: %+v", jc)
		}
		c.Status = st
		again := InstallStatus(c, job, JobFailed, t1.Add(time.Hour))
		if !reflect.DeepEqual(again, st) {
			t.Error("a repeated identical status is not equal, so every resync would rewrite it")
		}
	})

	t.Run("refused: Failed True with the reason, JobCreated False, no jobName", func(t *testing.T) {
		c := chart()
		c.Status = InstallStatus(c, job, JobRunning, t0)
		st := RefusedStatus(c, ReasonInsecureRepo, "spec.repo is http://", t1)
		if st.JobName != "" {
			t.Errorf("jobName = %q, want empty", st.JobName)
		}
		if f := FindCondition(st.Conditions, helmv1.HelmChartFailed); f == nil || f.Reason != ReasonInsecureRepo || f.Status != metav1.ConditionTrue {
			t.Errorf("Failed = %+v", f)
		}
		if jc := FindCondition(st.Conditions, helmv1.HelmChartJobCreated); jc == nil || jc.Status != metav1.ConditionFalse {
			t.Errorf("JobCreated = %+v, want False", jc)
		}
	})

	t.Run("failure policy", func(t *testing.T) {
		for _, tc := range []struct {
			policy string
			state  JobState
			want   bool
		}{
			{"", JobFailed, true},
			{helmv1.FailurePolicyReinstall, JobFailed, true},
			{helmv1.FailurePolicyAbort, JobFailed, false},
			{"", JobRunning, false},
			{"", JobComplete, false},
		} {
			spec := helmv1.HelmChartSpec{FailurePolicy: tc.policy}
			if got := ShouldReinstall(spec, tc.state); got != tc.want {
				t.Errorf("ShouldReinstall(%q, %v) = %v, want %v", tc.policy, tc.state, got, tc.want)
			}
		}
	})
}

func TestValidateHelmPin(t *testing.T) {
	if err := ValidateHelmPin(); err != nil {
		t.Fatalf("the compiled-in pin is malformed: %v", err)
	}
	if HelmPath("/w/bin") != "/w/bin/"+HelmBinaryName || !strings.HasSuffix(HelmBinaryName, HelmVersion) {
		t.Errorf("HelmPath = %q, want the versioned name under the bin dir", HelmPath("/w/bin"))
	}
	if HelmChecksumURL() != "https://get.helm.sh/"+HelmAsset+".sha256sum" {
		t.Errorf("HelmChecksumURL = %q", HelmChecksumURL())
	}
	good := []string{"v4.3.0", "helm-v4.3.0-darwin-arm64.tar.gz", strings.Repeat("a", 64), "helm-v4.3.0"}
	for i, bad := range [][4]string{
		{"4.3.0", good[1], good[2], good[3]},
		{good[0], "helm-v4.2.0-darwin-arm64.tar.gz", good[2], good[3]},
		{good[0], good[1], strings.Repeat("A", 64), good[3]},
		{good[0], good[1], good[2][:63], good[3]},
		{good[0], good[1], good[2], "helm"},
	} {
		if err := validateHelmPin(bad[0], bad[1], bad[2], bad[3]); err == nil {
			t.Errorf("case %d: validateHelmPin(%q) = nil, want an error", i, bad)
		}
	}
	if !slices.Contains([]string{"darwin-arm64/helm"}, HelmTarballMember) {
		t.Errorf("HelmTarballMember = %q", HelmTarballMember)
	}
}
