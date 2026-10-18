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
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestM10_JobCompletion is the M10.2/B74 Job terminal-phase criterion: the controller
// composition of the per-pod contract pinned by pkg/provider
// TestJobBackoffAndCompletionAccounting (Never/exit≠0 → Failed terminal; OnFailure/
// exit≠0 → restart-in-place; mains 0 → Succeeded) against the REAL embedded
// kube-controller-manager Job controller.
//
// Four Jobs, one per leg, run in parallel in one namespace:
//
//  1. completions=2 of an exit-0 pod: both pods reach Succeeded, the Job reports
//     condition Complete with status.succeeded=2;
//  2. restartPolicy:Never, exit 2, backoffLimit=1: every pod is Failed and
//     terminal (restartCount 0, never a CrashLoopBackOff waiting state), the
//     controller creates a replacement, and once two pods have failed the Job
//     reports condition Failed reason BackoffLimitExceeded;
//  3. restartPolicy:OnFailure, exiting 1 twice then 0: ONE pod for the whole
//     run, restarted in place (restartCount reaches 2, the phase never leaves
//     Pending/Running until it is Succeeded), the Job Complete with
//     status.succeeded=1;
//  4. a pod with a native sidecar (initContainer restartPolicy:Always) goes
//     Succeeded when its main exits 0, the sidecar terminated by the node (its
//     log shows it received SIGTERM), and the Job reports Complete.
func TestM10_JobCompletion(t *testing.T) {
	c := Up(t)
	node := m10Node(t, c)
	ns := m10Namespace(t, c)

	t.Run("completions=2 succeed", func(t *testing.T) {
		t.Parallel()
		job := m10Job(ns, "complete", node, corev1.RestartPolicyNever, `echo done; exit 0`)
		job.Spec.Completions = ptr(int32(2))
		job.Spec.Parallelism = ptr(int32(1))
		createJob(t, c, job)
		j := waitJobCondition(t, c, ns, job.Name, batchv1.JobComplete, 3*time.Minute)
		if j.Status.Succeeded != 2 {
			t.Errorf("job %s: status.succeeded=%d, want 2", job.Name, j.Status.Succeeded)
		}
		pods := jobPods(t, c, ns, job.Name)
		if len(pods) != 2 {
			t.Errorf("job %s created %d pod(s), want 2 (no failure, no replacement)", job.Name, len(pods))
		}
		for _, p := range pods {
			if p.Status.Phase != corev1.PodSucceeded {
				t.Errorf("job pod %s phase %s, want Succeeded", p.Name, p.Status.Phase)
			}
		}
	})

	t.Run("Never: failed pods are terminal until BackoffLimitExceeded", func(t *testing.T) {
		t.Parallel()
		job := m10Job(ns, "never", node, corev1.RestartPolicyNever, `sleep 1; exit 2`)
		job.Spec.BackoffLimit = ptr(int32(1))
		createJob(t, c, job)

		// Watch every pod of the Job while the controller works: none may ever
		// show a restart or a CrashLoopBackOff, and a Failed pod stays Failed.
		failedSeen := map[string]bool{}
		var j *batchv1.Job
		deadline := time.Now().Add(4 * time.Minute)
		for {
			for _, p := range jobPods(t, c, ns, job.Name) {
				st := m10Status(&p, "c")
				if st != nil && st.RestartCount != 0 {
					t.Errorf("pod %s restartCount %d under restartPolicy Never, want 0 (no in-place restart)", p.Name, st.RestartCount)
				}
				if st != nil && st.State.Waiting != nil && st.State.Waiting.Reason == "CrashLoopBackOff" {
					t.Errorf("pod %s shows CrashLoopBackOff under restartPolicy Never", p.Name)
				}
				if failedSeen[p.Name] && p.Status.Phase != corev1.PodFailed {
					t.Errorf("pod %s left Failed for %s: a Failed pod is terminal", p.Name, p.Status.Phase)
				}
				if p.Status.Phase == corev1.PodFailed {
					failedSeen[p.Name] = true
				}
			}
			var cond *batchv1.JobCondition
			j, cond = jobCondition(t, c, ns, job.Name, batchv1.JobFailed)
			if cond != nil {
				if cond.Reason != "BackoffLimitExceeded" {
					t.Errorf("job %s Failed with reason %q, want BackoffLimitExceeded", job.Name, cond.Reason)
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("job %s: no Failed condition within 4m; status %+v", job.Name, j.Status)
			}
			time.Sleep(time.Second)
		}
		if t.Failed() {
			return
		}
		pods := jobPods(t, c, ns, job.Name)
		if len(pods) != 2 {
			t.Errorf("job %s created %d pod(s), want 2 (the first plus one replacement at backoffLimit=1)", job.Name, len(pods))
		}
		for _, p := range pods {
			st := m10Status(&p, "c")
			if p.Status.Phase != corev1.PodFailed {
				t.Errorf("pod %s phase %s, want Failed", p.Name, p.Status.Phase)
			}
			if st == nil || st.State.Terminated == nil || st.State.Terminated.ExitCode != 2 {
				t.Errorf("pod %s: want container terminated with exit 2, got %s", p.Name, podFailureDetail(&p))
			}
		}
		if j.Status.Failed != 2 {
			t.Errorf("job %s status.failed=%d, want 2", job.Name, j.Status.Failed)
		}
	})

	t.Run("OnFailure: one pod restarts in place until it succeeds", func(t *testing.T) {
		t.Parallel()
		job := m10Job(ns, "onfailure", node, corev1.RestartPolicyOnFailure, `n=$(cat /data/runs 2>/dev/null || echo 0); n=$((n+1)); echo $n > /data/runs
echo "run=$n"; sleep 1
[ $n -ge 3 ] && exit 0
exit 1`)
		job.Spec.Template.Spec.Volumes = []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}
		job.Spec.Template.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "data", MountPath: "/data"}}
		createJob(t, c, job)

		var maxRestarts int32
		var podName string
		sawRunning := false
		deadline := time.Now().Add(4 * time.Minute)
		for {
			pods := jobPods(t, c, ns, job.Name)
			if len(pods) > 1 {
				names := make([]string, 0, len(pods))
				for _, p := range pods {
					names = append(names, p.Name)
				}
				t.Fatalf("job %s has %d pods %v: an OnFailure failure must restart the SAME pod, not create a replacement", job.Name, len(pods), names)
			}
			if len(pods) == 1 {
				p := pods[0]
				if podName != "" && p.Name != podName {
					t.Fatalf("job %s pod changed %s -> %s: a replacement, not an in-place restart", job.Name, podName, p.Name)
				}
				podName = p.Name
				if p.Status.Phase == corev1.PodFailed {
					t.Fatalf("pod %s went Failed under OnFailure: %s", p.Name, podFailureDetail(&p))
				}
				if sawRunning && p.Status.Phase != corev1.PodRunning && p.Status.Phase != corev1.PodSucceeded {
					t.Errorf("pod %s left Running for %s while restarting in place", p.Name, p.Status.Phase)
				}
				if p.Status.Phase == corev1.PodRunning {
					sawRunning = true
				}
				if st := m10Status(&p, "c"); st != nil && st.RestartCount > maxRestarts {
					maxRestarts = st.RestartCount
				}
				if p.Status.Phase == corev1.PodSucceeded {
					break
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("job %s: pod not Succeeded within 4m (max restartCount %d)", job.Name, maxRestarts)
			}
			time.Sleep(500 * time.Millisecond)
		}
		if maxRestarts != 2 {
			t.Errorf("pod %s: restartCount reached %d, want 2 (two failed runs restarted in place)", podName, maxRestarts)
		}
		j := waitJobCondition(t, c, ns, job.Name, batchv1.JobComplete, time.Minute)
		if j.Status.Succeeded != 1 {
			t.Errorf("job %s status.succeeded=%d, want 1", job.Name, j.Status.Succeeded)
		}
		if logs := m10ContainerLogs(c, ns, podName, "c"); m10Line(logs, "run") != "3" {
			t.Errorf("pod %s: the succeeding run reports run=%q, want 3 (the emptyDir count of executions)\n%s", podName, m10Line(logs, "run"), logs)
		}
	})

	t.Run("sidecar Job goes terminal on its main", func(t *testing.T) {
		t.Parallel()
		job := m10Job(ns, "sidecar", node, corev1.RestartPolicyNever, `sleep 3; echo main-done; exit 0`)
		always := corev1.ContainerRestartPolicyAlways
		job.Spec.Template.Spec.InitContainers = []corev1.Container{{
			Name:          "sidecar",
			Image:         "native",
			RestartPolicy: &always,
			Command:       []string{"/bin/sh", "-c", `trap 'echo sidecar-term; exit 0' TERM; echo sidecar-up; while :; do sleep 1; done`},
		}}
		createJob(t, c, job)
		j := waitJobCondition(t, c, ns, job.Name, batchv1.JobComplete, 3*time.Minute)
		if j.Status.Succeeded != 1 {
			t.Errorf("job %s status.succeeded=%d, want 1", job.Name, j.Status.Succeeded)
		}
		pods := jobPods(t, c, ns, job.Name)
		if len(pods) != 1 {
			t.Fatalf("job %s created %d pod(s), want 1", job.Name, len(pods))
		}
		p := pods[0]
		if p.Status.Phase != corev1.PodSucceeded {
			t.Errorf("pod %s phase %s, want Succeeded", p.Name, p.Status.Phase)
		}
		if st := m10Status(&p, "c"); st == nil || st.State.Terminated == nil || st.State.Terminated.ExitCode != 0 {
			t.Errorf("pod %s: main must be terminated with exit 0: %s", p.Name, podFailureDetail(&p))
		}
		st := m10Status(&p, "sidecar")
		if st == nil || st.State.Terminated == nil {
			t.Errorf("pod %s: the sidecar is not terminated in a Succeeded pod (state %+v): the node did not tear it down", p.Name, st)
		}
		if logs := m10ContainerLogs(c, ns, p.Name, "sidecar"); !strings.Contains(logs, "sidecar-term") {
			t.Errorf("pod %s: the sidecar log lacks sidecar-term, so it was not sent SIGTERM at teardown:\n%s", p.Name, logs)
		}
	})
}

// m10Job is a batch/v1 Job whose pod template is the pinned M10 pod spec.
func m10Job(ns, name, node string, policy corev1.RestartPolicy, script string) *batchv1.Job {
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"m10-job": name}},
				Spec:       m10PodSpec(node, policy, script),
			},
		},
	}
}

func createJob(t *testing.T, c *Cluster, job *batchv1.Job) {
	t.Helper()
	if _, err := c.Client.BatchV1().Jobs(job.Namespace).Create(context.Background(), job, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create job %s/%s: %v", job.Namespace, job.Name, err)
	}
}

// jobPods lists the pods the Job controller created for job.
func jobPods(t *testing.T, c *Cluster, ns, job string) []corev1.Pod {
	t.Helper()
	pods, err := c.Client.CoreV1().Pods(ns).List(context.Background(), metav1.ListOptions{LabelSelector: "m10-job=" + job})
	if err != nil {
		t.Fatalf("list pods of job %s: %v", job, err)
	}
	return pods.Items
}

// jobCondition returns the Job and its condition of type ct when True, else nil.
func jobCondition(t *testing.T, c *Cluster, ns, name string, ct batchv1.JobConditionType) (*batchv1.Job, *batchv1.JobCondition) {
	t.Helper()
	j, err := c.Client.BatchV1().Jobs(ns).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get job %s/%s: %v", ns, name, err)
	}
	for i := range j.Status.Conditions {
		if j.Status.Conditions[i].Type == ct && j.Status.Conditions[i].Status == corev1.ConditionTrue {
			return j, &j.Status.Conditions[i]
		}
	}
	return j, nil
}

// waitJobCondition waits for condition ct on the Job, failing fast when the
// opposite terminal condition appears.
func waitJobCondition(t *testing.T, c *Cluster, ns, name string, ct batchv1.JobConditionType, timeout time.Duration) *batchv1.Job {
	t.Helper()
	other := batchv1.JobFailed
	if ct == batchv1.JobFailed {
		other = batchv1.JobComplete
	}
	deadline := time.Now().Add(timeout)
	for {
		j, cond := jobCondition(t, c, ns, name, ct)
		if cond != nil {
			return j
		}
		if _, bad := jobCondition(t, c, ns, name, other); bad != nil {
			t.Fatalf("job %s/%s reached %s (%s: %s), want %s; pods: %s", ns, name, other, bad.Reason, bad.Message, ct, describeJobPods(t, c, ns, name))
		}
		if time.Now().After(deadline) {
			t.Fatalf("job %s/%s: no %s condition within %s; status %+v; pods: %s", ns, name, ct, timeout, j.Status, describeJobPods(t, c, ns, name))
		}
		time.Sleep(time.Second)
	}
}

func describeJobPods(t *testing.T, c *Cluster, ns, job string) string {
	t.Helper()
	var b strings.Builder
	for _, p := range jobPods(t, c, ns, job) {
		fmt.Fprintf(&b, "[%s %s] ", p.Name, podFailureDetail(&p))
	}
	return b.String()
}
