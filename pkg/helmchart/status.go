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
	"fmt"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	helmv1 "k3sm.io/apis/helm/v1"
)

// Condition reasons and messages. JobCreated and Failed carry k3s's own reason
// strings (helm-controller's "Job created" and "Job failed"), so a status reads
// the same as on k3s. InsecureRepo and InvalidChartContent are k3sm refusals
// k3s has no counterpart for.
const (
	// ReasonJobCreated is JobCreated's reason while a Job exists.
	ReasonJobCreated = "Job created"
	// ReasonJobFailed is Failed's reason when the Job ran out of retries or time.
	ReasonJobFailed = "Job failed"
	// ReasonInsecureRepo is Failed's reason when the chart would be fetched over
	// http:// (ValidateSource). No Job is created.
	ReasonInsecureRepo = "InsecureRepo"
	// ReasonInvalidChartContent is Failed's reason when chartContent is not
	// base64. No Job is created.
	ReasonInvalidChartContent = "InvalidChartContent"

	// messageJobFailed is k3s's message for a failed Job.
	messageJobFailed = "Job has reached configured number of retries without succeeding"
)

// JobState is what a Job's status says about the helm run it carries.
type JobState int

const (
	// JobRunning is a Job that has neither completed nor failed yet.
	JobRunning JobState = iota
	// JobComplete is a Job whose Complete condition is True.
	JobComplete
	// JobFailed is a Job whose Failed condition is True: backoffLimit reached,
	// or activeDeadlineSeconds exceeded.
	JobFailed
)

// String names the state for logs.
func (s JobState) String() string {
	switch s {
	case JobComplete:
		return "Complete"
	case JobFailed:
		return "Failed"
	default:
		return "Running"
	}
}

// StateOf reads a Job's terminal conditions. A Job with neither Complete nor
// Failed True is still running.
func StateOf(job *batchv1.Job) JobState {
	for _, c := range job.Status.Conditions {
		if c.Status != corev1.ConditionTrue {
			continue
		}
		switch c.Type {
		case batchv1.JobComplete:
			return JobComplete
		case batchv1.JobFailed:
			return JobFailed
		}
	}
	return JobRunning
}

// EffectiveFailurePolicy is the failure policy for a chart with spec and its
// same-named HelmChartConfig cfg (nil when there is none): the config's
// failurePolicy when set, else the chart's, defaulting to reinstall (k3s).
func EffectiveFailurePolicy(spec helmv1.HelmChartSpec, cfg *helmv1.HelmChartConfig) string {
	policy := spec.FailurePolicy
	if cfg != nil && cfg.Spec.FailurePolicy != "" {
		policy = cfg.Spec.FailurePolicy
	}
	if policy == helmv1.FailurePolicyAbort {
		return helmv1.FailurePolicyAbort
	}
	return helmv1.FailurePolicyReinstall
}

// ShouldReinstall reports whether a failed install Job is deleted so the next
// reconcile runs the install again. Under abort the failed Job (and its pods'
// logs) is left for the operator; under reinstall it is replaced.
func ShouldReinstall(spec helmv1.HelmChartSpec, cfg *helmv1.HelmChartConfig, state JobState) bool {
	return state == JobFailed && EffectiveFailurePolicy(spec, cfg) == helmv1.FailurePolicyReinstall
}

// InstallStatus is the status of chart c whose install Job job is in state.
// JobCreated is True naming the Job; Failed is True with k3s's reason and
// message when the Job failed, and False otherwise (a new or running Job clears
// a previous failure, as in k3s).
func InstallStatus(c *helmv1.HelmChart, job *batchv1.Job, state JobState, now time.Time) helmv1.HelmChartStatus {
	status := *c.Status.DeepCopy()
	status.JobName = job.Name
	status.Conditions = SetCondition(status.Conditions, helmv1.HelmChartCondition{
		Type:    helmv1.HelmChartJobCreated,
		Status:  metav1.ConditionTrue,
		Reason:  ReasonJobCreated,
		Message: fmt.Sprintf("Applying HelmChart using Job %s/%s", job.Namespace, job.Name),
	}, now)
	failed := helmv1.HelmChartCondition{Type: helmv1.HelmChartFailed, Status: metav1.ConditionFalse}
	if state == JobFailed {
		failed.Status = metav1.ConditionTrue
		failed.Reason = ReasonJobFailed
		failed.Message = messageJobFailed
	}
	status.Conditions = SetCondition(status.Conditions, failed, now)
	return status
}

// RefusedStatus is the status of chart c refused before any Job exists: Failed
// True with reason and message, JobCreated False, and no jobName.
func RefusedStatus(c *helmv1.HelmChart, reason, message string, now time.Time) helmv1.HelmChartStatus {
	status := *c.Status.DeepCopy()
	status.JobName = ""
	status.Conditions = SetCondition(status.Conditions, helmv1.HelmChartCondition{
		Type:   helmv1.HelmChartJobCreated,
		Status: metav1.ConditionFalse,
	}, now)
	status.Conditions = SetCondition(status.Conditions, helmv1.HelmChartCondition{
		Type:    helmv1.HelmChartFailed,
		Status:  metav1.ConditionTrue,
		Reason:  reason,
		Message: message,
	}, now)
	return status
}

// SetCondition returns conds with want set in place of the condition of the
// same type (appended if absent). Nothing changes when status, reason and
// message already match, so an unchanged status compares equal and is not
// rewritten; otherwise LastUpdateTime is now, and LastTransitionTime is now
// only when the status itself changed.
func SetCondition(conds []helmv1.HelmChartCondition, want helmv1.HelmChartCondition, now time.Time) []helmv1.HelmChartCondition {
	out := append([]helmv1.HelmChartCondition(nil), conds...)
	ts := metav1.NewTime(now.UTC().Truncate(time.Second))
	for i := range out {
		if out[i].Type != want.Type {
			continue
		}
		if out[i].Status == want.Status && out[i].Reason == want.Reason && out[i].Message == want.Message {
			return out
		}
		want.LastUpdateTime = ts
		want.LastTransitionTime = out[i].LastTransitionTime
		if out[i].Status != want.Status {
			want.LastTransitionTime = ts
		}
		out[i] = want
		return out
	}
	want.LastUpdateTime = ts
	want.LastTransitionTime = ts
	return append(out, want)
}

// FindCondition returns the condition of type t, or nil.
func FindCondition(conds []helmv1.HelmChartCondition, t helmv1.HelmChartConditionType) *helmv1.HelmChartCondition {
	for i := range conds {
		if conds[i].Type == t {
			return &conds[i]
		}
	}
	return nil
}
