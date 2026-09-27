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
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
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

// Object identity. The label and the Job, ServiceAccount and ConfigMap names are
// k3s's (helmcharts.helm.cattle.io/chart becomes helm.k3sm.io/chart); an
// operator who knows k3s finds each object where they expect it.
const (
	// LabelChart names the HelmChart a Job (and its pods) runs helm for. The
	// controller's Job informer selects on it and maps an event back to the
	// chart through its value.
	LabelChart = "helm.k3sm.io/chart"
	// AnnotationConfigHash carries ConfigHash on the install Job. A Job whose
	// hash differs from the chart's current one is replaced.
	AnnotationConfigHash = "helm.k3sm.io/config-hash"
	// AnnotationChartUID carries the HelmChart's UID on the delete Job, which
	// has no ownerReference (see RenderJob). It is how a finalize tells its own
	// delete Job from one a previous HelmChart of the same name left behind.
	AnnotationChartUID = "helm.k3sm.io/chart-uid"
	// Finalizer holds a deleted HelmChart until its release is uninstalled.
	Finalizer = "helm.k3sm.io/uninstall"

	// DefaultBackOffLimit is the install Job's backoffLimit when the spec sets
	// none (k3s's default).
	DefaultBackOffLimit int32 = 1000
	// DefaultTimeout is the helm --timeout when the spec sets none (helm's own
	// default, and k3s's).
	DefaultTimeout = 300 * time.Second
	// DeleteJobTTLSeconds is how long a finished delete Job is kept for
	// inspection before the Job TTL controller removes it. The delete Job
	// outlives its HelmChart by design, so nothing else would.
	DeleteJobTTLSeconds int32 = 600

	// ValuesFile, ConfigValuesFile and ChartFile are the keys of the chart
	// ConfigMaps, and the file names the Job reads under /chart.
	ValuesFile       = "values.yaml"
	ConfigValuesFile = "values-10_HelmChartConfig.yaml"
	ChartFile        = "chart.tgz"

	// chartMountPath is where the chart ConfigMaps are projected; helmHomePath
	// is the emptyDir helm's cache, config and data homes live in.
	chartMountPath = "/chart"
	helmHomePath   = "/helm"

	// containerName is the Job's one container.
	containerName = "helm"

	// managedByLabelKey / managedByLabelValue mark the Job's pods as
	// controller-stamped. pkg/policy's internet-egress Warn policy reads exactly
	// this pair to tell a controller-set egress annotation from a hand-set one;
	// the pair is restated (unexported there) as pkg/mlx restates it.
	managedByLabelKey   = "app.kubernetes.io/managed-by"
	managedByLabelValue = "k3sm"

	// labelOSDarwin is the kubernetes.io/os value on every k3sm node.
	labelOSDarwin = "darwin"
)

// InstallJobName is the install Job's name for a chart.
func InstallJobName(chart string) string { return "helm-install-" + chart }

// DeleteJobName is the delete Job's name for a chart.
func DeleteJobName(chart string) string { return "helm-delete-" + chart }

// ServiceAccountName is the ServiceAccount a chart's Jobs run as.
func ServiceAccountName(chart string) string { return "helm-" + chart }

// ValuesConfigMapName is the ConfigMap holding a chart's values files.
func ValuesConfigMapName(chart string) string { return "chart-values-" + chart }

// ContentConfigMapName is the ConfigMap holding a chart's chartContent archive.
func ContentConfigMapName(chart string) string { return "chart-content-" + chart }

// TargetNamespace is the namespace the release is installed into: the spec's
// targetNamespace, else the HelmChart's own.
func TargetNamespace(c *helmv1.HelmChart) string {
	if c.Spec.TargetNamespace != "" {
		return c.Spec.TargetNamespace
	}
	return c.Namespace
}

// Fetches reports whether installing spec downloads the chart, i.e. whether it
// comes from a repo, an OCI registry or a URL rather than from chartContent.
// chartContent wins when both are set (k3s semantics).
func Fetches(spec helmv1.HelmChartSpec) bool {
	return spec.ChartContent == "" && spec.Chart != ""
}

// Timeout is the helm --timeout for spec.
func Timeout(spec helmv1.HelmChartSpec) time.Duration {
	if spec.Timeout != nil && spec.Timeout.Duration > 0 {
		return spec.Timeout.Duration
	}
	return DefaultTimeout
}

// ErrInsecureRepo means the chart would be fetched over cleartext http.
var ErrInsecureRepo = errors.New("chart source is http://")

// ErrInvalidChartContent means spec.chartContent is not base64.
var ErrInvalidChartContent = errors.New("chartContent is not valid base64")

// ValidateSource refuses a spec whose chart would be fetched over http://,
// returning an error wrapping ErrInsecureRepo that names the field. The check
// trims and lower-cases first, so it catches what the CRD's literal prefix rule
// lets through. A chart that is not fetched (chartContent set) is not checked:
// spec.chart is ignored then.
func ValidateSource(spec helmv1.HelmChartSpec) error {
	if !Fetches(spec) {
		return nil
	}
	for _, f := range []struct{ name, value string }{{"spec.repo", spec.Repo}, {"spec.chart", spec.Chart}} {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(f.value)), "http://") {
			return fmt.Errorf("%w: %s is %q; the install Job runs as cluster-admin and must not fetch a chart over cleartext (use https:// or oci://)",
				ErrInsecureRepo, f.name, f.value)
		}
	}
	return nil
}

// ownerRef is the controller ownerReference a chart's install Job and
// ConfigMaps carry, so garbage collection removes them with the chart.
func ownerRef(c *helmv1.HelmChart) metav1.OwnerReference {
	return metav1.OwnerReference{
		APIVersion:         helmv1.SchemeGroupVersion.String(),
		Kind:               "HelmChart",
		Name:               c.Name,
		UID:                c.UID,
		Controller:         ptr.To(true),
		BlockOwnerDeletion: ptr.To(true),
	}
}

// RenderConfigMaps renders the chart's values ConfigMap and, when the spec
// carries chartContent, its content ConfigMap (nil otherwise). The values
// ConfigMap always exists because the install argv always reads values.yaml;
// the HelmChartConfig overlay is a second key, present only when non-empty. A
// chartContent that is not base64 is an error wrapping ErrInvalidChartContent.
func RenderConfigMaps(c *helmv1.HelmChart, cfg *helmv1.HelmChartConfig) (values, content *corev1.ConfigMap, err error) {
	meta := func(name string) metav1.ObjectMeta {
		return metav1.ObjectMeta{
			Name:            name,
			Namespace:       c.Namespace,
			Labels:          map[string]string{LabelChart: c.Name, managedByLabelKey: managedByLabelValue},
			OwnerReferences: []metav1.OwnerReference{ownerRef(c)},
		}
	}
	values = &corev1.ConfigMap{
		ObjectMeta: meta(ValuesConfigMapName(c.Name)),
		Data:       map[string]string{ValuesFile: c.Spec.ValuesContent},
	}
	if overlay := configValues(cfg); overlay != "" {
		values.Data[ConfigValuesFile] = overlay
	}
	if c.Spec.ChartContent == "" {
		return values, nil, nil
	}
	archive, err := base64.StdEncoding.DecodeString(strings.TrimSpace(c.Spec.ChartContent))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidChartContent, err)
	}
	content = &corev1.ConfigMap{
		ObjectMeta: meta(ContentConfigMapName(c.Name)),
		BinaryData: map[string][]byte{ChartFile: archive},
	}
	return values, content, nil
}

// configValues is the HelmChartConfig's values overlay, or "" without one.
func configValues(cfg *helmv1.HelmChartConfig) string {
	if cfg == nil {
		return ""
	}
	return cfg.Spec.ValuesContent
}

// ForceConflicts is whether the install passes --force-conflicts: the
// HelmChartConfig's forceConflicts when set, else the chart's (k3s semantics,
// the config wins when set; a bool field can only be set to true).
func ForceConflicts(spec helmv1.HelmChartSpec, cfg *helmv1.HelmChartConfig) bool {
	if cfg != nil && cfg.Spec.ForceConflicts {
		return true
	}
	return spec.ForceConflicts
}

// RenderJob renders the Job that runs helm for c: the install Job while c is
// live, the delete Job once c carries a deletionTimestamp. helmPath is the
// staged helm binary (HelmPath under the work dir's bin); hash is ConfigHash of
// c and cfg, stamped on the install Job so a changed spec replaces it.
//
// The install Job is owned by c (garbage collected with it). The delete Job is
// NOT: a foreground cascade on the HelmChart would otherwise delete the very Job
// that is uninstalling it. It carries c's UID in an annotation instead, and a
// TTL so the Job controller removes it once it has been inspectable for a while.
func RenderJob(c *helmv1.HelmChart, cfg *helmv1.HelmChartConfig, helmPath, hash string) *batchv1.Job {
	deleting := c.DeletionTimestamp != nil
	timeout := Timeout(c.Spec)

	labels := map[string]string{LabelChart: c.Name, managedByLabelKey: managedByLabelValue}
	podAnnotations := map[string]string{}
	if !deleting && Fetches(c.Spec) {
		// Only a fetched chart needs the network beyond the cluster; chartContent
		// is read from a ConfigMap. Stamped on the pod template, which is where
		// the provider reads it, beside the managed-by label pkg/policy's Warn
		// policy expects on a controller-stamped egress annotation.
		podAnnotations[runtimev1.AnnotationInternetEgress] = "true"
	}

	volumes := []corev1.Volume{{
		Name:         "helm-home",
		VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
	}}
	mounts := []corev1.VolumeMount{{Name: "helm-home", MountPath: helmHomePath}}

	job := &batchv1.Job{
		TypeMeta: metav1.TypeMeta{APIVersion: "batch/v1", Kind: "Job"},
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   c.Namespace,
			Labels:      labels,
			Annotations: map[string]string{},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:          ptr.To(backOffLimit(c.Spec)),
			ActiveDeadlineSeconds: ptr.To(int64(2 * timeout / time.Second)),
		},
	}

	var args []string
	if deleting {
		job.Name = DeleteJobName(c.Name)
		job.Annotations[AnnotationChartUID] = string(c.UID)
		job.Spec.TTLSecondsAfterFinished = ptr.To(DeleteJobTTLSeconds)
		args = DeleteArgs(c)
	} else {
		job.Name = InstallJobName(c.Name)
		job.Annotations[AnnotationConfigHash] = hash
		podAnnotations[AnnotationConfigHash] = hash
		job.OwnerReferences = []metav1.OwnerReference{ownerRef(c)}
		sources := []corev1.VolumeProjection{{ConfigMap: &corev1.ConfigMapProjection{
			LocalObjectReference: corev1.LocalObjectReference{Name: ValuesConfigMapName(c.Name)},
		}}}
		if c.Spec.ChartContent != "" {
			sources = append(sources, corev1.VolumeProjection{ConfigMap: &corev1.ConfigMapProjection{
				LocalObjectReference: corev1.LocalObjectReference{Name: ContentConfigMapName(c.Name)},
			}})
		}
		volumes = append(volumes, corev1.Volume{
			Name:         "chart",
			VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: sources}},
		})
		mounts = append(mounts, corev1.VolumeMount{Name: "chart", MountPath: chartMountPath, ReadOnly: true})
		args = InstallArgs(c, cfg)
	}

	job.Spec.Template = corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{Labels: copyMap(labels), Annotations: podAnnotations},
		Spec: corev1.PodSpec{
			RestartPolicy:                corev1.RestartPolicyOnFailure,
			ServiceAccountName:           ServiceAccountName(c.Name),
			AutomountServiceAccountToken: ptr.To(true),
			// Both are required on every k3sm pod: the nodeSelector is enforced at
			// admission, and the toleration clears the provider taint every k3sm
			// node carries.
			NodeSelector: map[string]string{corev1.LabelOSStable: labelOSDarwin},
			Tolerations: []corev1.Toleration{{
				Key:      policy.ProviderTaintKey,
				Operator: corev1.TolerationOpExists,
				Effect:   corev1.TaintEffectNoSchedule,
			}},
			Containers: []corev1.Container{{
				Name: containerName,
				// A native pod with no image: command[0] is the staged host helm.
				Image:   "native",
				Command: append([]string{helmPath}, args...),
				// helm's own state and client-go's discovery cache ($HOME/.kube)
				// both land in the Job's emptyDir, never in a shared host path.
				Env: []corev1.EnvVar{
					{Name: "HOME", Value: helmHomePath},
					{Name: "HELM_CACHE_HOME", Value: helmHomePath + "/cache"},
					{Name: "HELM_CONFIG_HOME", Value: helmHomePath + "/config"},
					{Name: "HELM_DATA_HOME", Value: helmHomePath + "/data"},
				},
				VolumeMounts: mounts,
			}},
			Volumes: volumes,
		},
	}
	return job
}

// backOffLimit is the spec's backOffLimit, else DefaultBackOffLimit.
func backOffLimit(spec helmv1.HelmChartSpec) int32 {
	if spec.BackOffLimit != nil {
		return *spec.BackOffLimit
	}
	return DefaultBackOffLimit
}

// InstallArgs is the helm argv (after the binary) that installs or upgrades c:
//
//	upgrade --install <release> <chart> --namespace <ns> [--create-namespace]
//	  [--repo <repo>] [--version <v>] -f /chart/values.yaml
//	  [-f /chart/values-10_HelmChartConfig.yaml] [--set k=v | --set-string k=v]...
//	  --timeout <d> --wait [--force-conflicts] [--take-ownership]
//
// The release is named after the HelmChart (k3s). --repo and --version apply
// only to a fetched chart; a chartContent install names the archive under
// /chart. cfg is the same-named HelmChartConfig, or nil: its values overlay is
// a second values file, after the chart's own, so it wins (--set overrides
// both), and its forceConflicts overrides the chart's (ForceConflicts). --set follows k3s exactly:
// integers, booleans and null use --set, every other string --set-string with
// its unescaped commas escaped, keys in sorted order.
func InstallArgs(c *helmv1.HelmChart, cfg *helmv1.HelmChartConfig) []string {
	spec := c.Spec
	chart := spec.Chart
	if spec.ChartContent != "" {
		chart = chartMountPath + "/" + ChartFile
	}
	args := []string{"upgrade", "--install", c.Name, chart, "--namespace", TargetNamespace(c)}
	if spec.CreateNamespace {
		args = append(args, "--create-namespace")
	}
	if Fetches(spec) {
		if spec.Repo != "" {
			args = append(args, "--repo", spec.Repo)
		}
		if spec.Version != "" {
			args = append(args, "--version", spec.Version)
		}
	}
	args = append(args, "-f", chartMountPath+"/"+ValuesFile)
	if configValues(cfg) != "" {
		args = append(args, "-f", chartMountPath+"/"+ConfigValuesFile)
	}
	keys := make([]string, 0, len(spec.Set))
	for k := range spec.Set {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		v := spec.Set[k]
		if typedVal(v) {
			args = append(args, "--set", k+"="+v.String())
		} else {
			args = append(args, "--set-string", k+"="+commaRE.ReplaceAllStringFunc(v.String(), escapeComma))
		}
	}
	args = append(args, "--timeout", Timeout(spec).String(), "--wait")
	if ForceConflicts(spec, cfg) {
		args = append(args, "--force-conflicts")
	}
	if spec.TakeOwnership {
		args = append(args, "--take-ownership")
	}
	return args
}

// DeleteArgs is the helm argv (after the binary) that uninstalls c's release.
// --ignore-not-found makes a rerun, or a delete of a chart whose install never
// succeeded, a success rather than a stuck finalizer.
func DeleteArgs(c *helmv1.HelmChart) []string {
	return []string{"uninstall", c.Name, "-n", TargetNamespace(c), "--ignore-not-found"}
}

// commaRE matches a run of backslashes followed by a comma (k3s's).
var commaRE = regexp.MustCompile(`\\*,`)

// escapeComma escapes a comma helm would otherwise split --set-string on: an
// odd-length match (an unescaped comma) gets one more backslash (k3s's rule).
func escapeComma(match string) string {
	if len(match)%2 == 1 {
		return `\` + match
	}
	return match
}

// typedVal reports whether helm should parse v as a typed value (--set) rather
// than a string (--set-string): integers, booleans and null (k3s's rule).
func typedVal(v intstr.IntOrString) bool {
	if v.Type == intstr.Int {
		return true
	}
	switch strings.ToLower(v.StrVal) {
	case "true", "false", "null":
		return true
	}
	return false
}

// copyMap returns a shallow copy of m, so the Job's and the pod template's
// label maps are distinct.
func copyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
