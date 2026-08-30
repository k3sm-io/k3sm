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

package mlx

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	"k3sm.io/k3sm/pkg/policy"
)

const (
	testUID     = types.UID("6f0d5c2a-1f37-4a4e-9a2f-0b3f2a7d5c11")
	testImage   = "ghcr.io/k3sm-io/mlx-serve@sha256:0000000000000000000000000000000000000000000000000000000000000000"
	testDefPort = int32(8080)
)

// testOptions are the operator-level defaults a render needs. They are the
// SUPPLIED ones, never package defaults — Render invents neither an image nor a
// port (see the ErrNoImage / ErrNoPort rows).
func testOptions() Options {
	return Options{DefaultImage: testImage, DefaultPort: testDefPort}
}

// newModel returns the full-featured MLXModel the happy-path assertions render:
// every optional field set, so an assertion that a field FLOWS cannot pass by
// accident on a zero value.
//
// Except spec.quantization, which is deliberately unset: the serving engine has
// no expression for it, so a spec that states it is REFUSED rather than rendered
// (ErrQuantizationUnsupported). That refusal has its own row in
// TestEngineArgsMatchTheMeasuredSurface.
func newModel() *mlxv1alpha1.MLXModel {
	return &mlxv1alpha1.MLXModel{
		ObjectMeta: metav1.ObjectMeta{Name: "qwen3", Namespace: "models", UID: testUID},
		Spec: mlxv1alpha1.MLXModelSpec{
			Model:    "mlx-community/Qwen3-0.6B-4bit",
			Revision: "0f1e2d3c4b5a69788796a5b4c3d2e1f001234567",
			Memory:   resource.MustParse("24Gi"),
			Replicas: ptr.To(int32(2)),
			Port:     9123,
			Runtime: mlxv1alpha1.MLXRuntime{
				Image: "ghcr.io/k3sm-io/mlx-serve@sha256:1111111111111111111111111111111111111111111111111111111111111111",
				Args:  []string{"--max-tokens", "512"},
			},
			Cache: &mlxv1alpha1.MLXCache{
				Size:             resource.MustParse("64Gi"),
				StorageClassName: "k3sm-local-path",
			},
			NodeSelector: map[string]string{mlxv1alpha1.LabelChipFamily: "m4"},
		},
	}
}

// TestReconcileRendersStatefulSetFromMLXModel is the render contract: an
// MLXModel spec becomes a StatefulSet + a headless governing Service + a stable
// ClusterIP Service, all owned by the model, all carrying the fixed guardrail
// stanza, with a readiness probe and NO liveness probe, and with the cache
// flowing into a volumeClaimTemplate whose PVCs are deleted with the model.
func TestReconcileRendersStatefulSetFromMLXModel(t *testing.T) {
	t.Run("statefulset_identity_and_shape", func(t *testing.T) {
		m := newModel()
		objs, err := Render(m, testOptions())
		if err != nil {
			t.Fatalf("Render() error = %v, want nil", err)
		}
		sts := objs.StatefulSet
		if sts == nil {
			t.Fatal("Render() returned no StatefulSet")
		}
		if got, want := sts.Name, StatefulSetName(m.Name); got != want {
			t.Errorf("StatefulSet name = %q, want %q (deterministic from the MLXModel name)", got, want)
		}
		if got, want := sts.Namespace, m.Namespace; got != want {
			t.Errorf("StatefulSet namespace = %q, want %q", got, want)
		}
		if got, want := sts.Spec.ServiceName, HeadlessServiceName(m.Name); got != want {
			t.Errorf("StatefulSet serviceName = %q, want the headless Service %q", got, want)
		}
		if sts.Spec.Replicas == nil || *sts.Spec.Replicas != 2 {
			t.Errorf("StatefulSet replicas = %v, want 2 (from spec.replicas)", sts.Spec.Replicas)
		}
		if sts.Spec.Selector == nil || !reflect.DeepEqual(sts.Spec.Selector.MatchLabels, selectorLabels(m.Name)) {
			t.Errorf("StatefulSet selector = %v, want %v", sts.Spec.Selector, selectorLabels(m.Name))
		}
		for k, v := range sts.Spec.Selector.MatchLabels {
			if got := sts.Spec.Template.Labels[k]; got != v {
				t.Errorf("pod template label %s = %q, want %q — the selector must match the template it selects", k, got, v)
			}
		}
		if got := sts.Spec.PodManagementPolicy; got != appsv1.ParallelPodManagement {
			t.Errorf("podManagementPolicy = %q, want %q (ordered start-up serializes one weight download per replica)",
				got, appsv1.ParallelPodManagement)
		}
		if len(sts.Spec.Template.Spec.Containers) != 1 {
			t.Fatalf("pod template has %d containers, want exactly 1", len(sts.Spec.Template.Spec.Containers))
		}
	})

	t.Run("replicas_default_to_one_when_unset", func(t *testing.T) {
		m := newModel()
		m.Spec.Replicas = nil
		objs, err := Render(m, testOptions())
		if err != nil {
			t.Fatalf("Render() error = %v, want nil", err)
		}
		if objs.StatefulSet.Spec.Replicas == nil || *objs.StatefulSet.Spec.Replicas != 1 {
			t.Errorf("replicas = %v, want 1 (nil spec.replicas means one)", objs.StatefulSet.Spec.Replicas)
		}
	})

	t.Run("scale_to_zero_is_honoured_not_defaulted", func(t *testing.T) {
		m := newModel()
		m.Spec.Replicas = ptr.To(int32(0))
		objs, err := Render(m, testOptions())
		if err != nil {
			t.Fatalf("Render() error = %v, want nil", err)
		}
		if objs.StatefulSet.Spec.Replicas == nil || *objs.StatefulSet.Spec.Replicas != 0 {
			t.Errorf("replicas = %v, want 0 — an explicit 0 is scale-to-zero, not 'unset'", objs.StatefulSet.Spec.Replicas)
		}
	})

	t.Run("owner_references_on_every_object", func(t *testing.T) {
		m := newModel()
		objs, err := Render(m, testOptions())
		if err != nil {
			t.Fatalf("Render() error = %v, want nil", err)
		}
		for _, o := range []struct {
			what string
			refs []metav1.OwnerReference
		}{
			{"StatefulSet", objs.StatefulSet.OwnerReferences},
			{"headless Service", objs.HeadlessService.OwnerReferences},
			{"ClusterIP Service", objs.ClusterIPService.OwnerReferences},
		} {
			if len(o.refs) != 1 {
				t.Errorf("%s has %d ownerReferences, want exactly 1 (deleting the MLXModel must cascade)", o.what, len(o.refs))
				continue
			}
			ref := o.refs[0]
			if got, want := ref.APIVersion, mlxv1alpha1.SchemeGroupVersion.String(); got != want {
				t.Errorf("%s ownerRef apiVersion = %q, want %q", o.what, got, want)
			}
			if ref.Kind != "MLXModel" {
				t.Errorf("%s ownerRef kind = %q, want MLXModel", o.what, ref.Kind)
			}
			if ref.Name != m.Name {
				t.Errorf("%s ownerRef name = %q, want %q", o.what, ref.Name, m.Name)
			}
			if ref.UID != m.UID {
				t.Errorf("%s ownerRef uid = %q, want %q", o.what, ref.UID, m.UID)
			}
			if ref.Controller == nil || !*ref.Controller {
				t.Errorf("%s ownerRef controller = %v, want true", o.what, ref.Controller)
			}
			if ref.BlockOwnerDeletion == nil || !*ref.BlockOwnerDeletion {
				t.Errorf("%s ownerRef blockOwnerDeletion = %v, want true", o.what, ref.BlockOwnerDeletion)
			}
		}
	})

	t.Run("guardrail_stanza_is_fixed_template_content", func(t *testing.T) {
		m := newModel()
		objs, err := Render(m, testOptions())
		if err != nil {
			t.Fatalf("Render() error = %v, want nil", err)
		}
		pod := objs.StatefulSet.Spec.Template.Spec

		// The two fixed selectors, keyed off the OWNING packages' constants — a
		// literal here would pass while disagreeing with the node advertiser.
		if got := pod.NodeSelector[corev1.LabelOSStable]; got != "darwin" {
			t.Errorf("nodeSelector[%s] = %q, want darwin", corev1.LabelOSStable, got)
		}
		if got := pod.NodeSelector[mlxv1alpha1.LabelGPUPresent]; got != "true" {
			t.Errorf("nodeSelector[%s] = %q, want true", mlxv1alpha1.LabelGPUPresent, got)
		}
		// The caller's own selector survives the merge.
		if got := pod.NodeSelector[mlxv1alpha1.LabelChipFamily]; got != "m4" {
			t.Errorf("nodeSelector[%s] = %q, want m4 (spec.nodeSelector must be preserved)", mlxv1alpha1.LabelChipFamily, got)
		}

		var tolerated bool
		for _, tol := range pod.Tolerations {
			if tol.Key == policy.ProviderTaintKey && tol.Operator == corev1.TolerationOpExists && tol.Effect == corev1.TaintEffectNoSchedule {
				tolerated = true
			}
		}
		if !tolerated {
			t.Errorf("tolerations = %v, want one for %s:NoSchedule (on EVERY k3sm node — without it the pod never schedules)",
				pod.Tolerations, policy.ProviderTaintKey)
		}

		res := pod.Containers[0].Resources
		gpu := corev1.ResourceName(mlxv1alpha1.ResourceGPU)
		for _, side := range []struct {
			what string
			list corev1.ResourceList
		}{{"requests", res.Requests}, {"limits", res.Limits}} {
			q, ok := side.list[gpu]
			if !ok {
				t.Errorf("resources.%s is missing %s — it must appear in BOTH requests and limits", side.what, gpu)
				continue
			}
			if q.Value() != 1 {
				t.Errorf("resources.%s[%s] = %s, want 1", side.what, gpu, q.String())
			}
		}
	})

	t.Run("memory_request_equals_limit_from_spec", func(t *testing.T) {
		m := newModel()
		objs, err := Render(m, testOptions())
		if err != nil {
			t.Fatalf("Render() error = %v, want nil", err)
		}
		res := objs.StatefulSet.Spec.Template.Spec.Containers[0].Resources
		req, okReq := res.Requests[corev1.ResourceMemory]
		lim, okLim := res.Limits[corev1.ResourceMemory]
		if !okReq || !okLim {
			t.Fatalf("memory request/limit present = %v/%v, want both (unified memory is plain memory, request==limit)", okReq, okLim)
		}
		if req.Cmp(m.Spec.Memory) != 0 || lim.Cmp(m.Spec.Memory) != 0 {
			t.Errorf("memory request/limit = %s/%s, want both %s (from spec.memory)", req.String(), lim.String(), m.Spec.Memory.String())
		}
	})

	t.Run("readiness_probe_only_no_liveness_or_startup", func(t *testing.T) {
		m := newModel()
		objs, err := Render(m, testOptions())
		if err != nil {
			t.Fatalf("Render() error = %v, want nil", err)
		}
		c := objs.StatefulSet.Spec.Template.Spec.Containers[0]
		if c.ReadinessProbe == nil || c.ReadinessProbe.HTTPGet == nil {
			t.Fatalf("readinessProbe = %v, want an HTTP GET probe", c.ReadinessProbe)
		}
		if got, want := c.ReadinessProbe.HTTPGet.Port.StrVal, portName; got != want {
			t.Errorf("readinessProbe port = %q, want the named port %q", got, want)
		}
		if c.LivenessProbe != nil {
			t.Errorf("livenessProbe = %v, want NONE — a liveness kill during a multi-minute weight load restarts the download from zero", c.LivenessProbe)
		}
		if c.StartupProbe != nil {
			t.Errorf("startupProbe = %v, want NONE — the first start is an unbounded download window with no deadline to bound it by", c.StartupProbe)
		}
	})

	t.Run("cache_flows_into_the_volume_claim_template", func(t *testing.T) {
		m := newModel()
		objs, err := Render(m, testOptions())
		if err != nil {
			t.Fatalf("Render() error = %v, want nil", err)
		}
		sts := objs.StatefulSet
		if len(sts.Spec.VolumeClaimTemplates) != 1 {
			t.Fatalf("volumeClaimTemplates = %d, want 1 (spec.cache is set)", len(sts.Spec.VolumeClaimTemplates))
		}
		vct := sts.Spec.VolumeClaimTemplates[0]
		if vct.Name != cacheVolumeName {
			t.Errorf("volumeClaimTemplate name = %q, want %q", vct.Name, cacheVolumeName)
		}
		size := vct.Spec.Resources.Requests[corev1.ResourceStorage]
		if size.Cmp(m.Spec.Cache.Size) != 0 {
			t.Errorf("claim storage request = %s, want %s (from spec.cache.size)", size.String(), m.Spec.Cache.Size.String())
		}
		if vct.Spec.StorageClassName == nil || *vct.Spec.StorageClassName != m.Spec.Cache.StorageClassName {
			t.Errorf("claim storageClassName = %v, want %q", vct.Spec.StorageClassName, m.Spec.Cache.StorageClassName)
		}

		c := sts.Spec.Template.Spec.Containers[0]
		var mounted bool
		for _, vm := range c.VolumeMounts {
			if vm.Name == cacheVolumeName && vm.MountPath == CacheMountPath {
				mounted = true
			}
		}
		if !mounted {
			t.Errorf("volumeMounts = %v, want %s at %s", c.VolumeMounts, cacheVolumeName, CacheMountPath)
		}
		var hfHome string
		for _, e := range c.Env {
			if e.Name == hfHomeEnv {
				hfHome = e.Value
			}
		}
		if !strings.HasPrefix(hfHome, CacheMountPath) {
			t.Errorf("%s = %q, want a path under the cache mount %s — otherwise the weights land outside the volume and are re-downloaded every restart",
				hfHomeEnv, hfHome, CacheMountPath)
		}
	})

	t.Run("pvc_retention_deletes_with_the_model", func(t *testing.T) {
		m := newModel()
		objs, err := Render(m, testOptions())
		if err != nil {
			t.Fatalf("Render() error = %v, want nil", err)
		}
		pol := objs.StatefulSet.Spec.PersistentVolumeClaimRetentionPolicy
		if pol == nil {
			t.Fatal("persistentVolumeClaimRetentionPolicy = nil, want whenDeleted: Delete (ownerRefs do NOT cascade through StatefulSet PVCs)")
		}
		if got, want := pol.WhenDeleted, appsv1.DeletePersistentVolumeClaimRetentionPolicyType; got != want {
			t.Errorf("whenDeleted = %q, want %q", got, want)
		}
		if got, want := pol.WhenScaled, appsv1.RetainPersistentVolumeClaimRetentionPolicyType; got != want {
			t.Errorf("whenScaled = %q, want %q (a scale-down is reversible; the weights are expensive to re-fetch)", got, want)
		}
	})

	t.Run("no_cache_renders_no_claim_and_no_hf_home", func(t *testing.T) {
		m := newModel()
		m.Spec.Cache = nil
		// No cache volume means no HF_HOME to name, which is exactly why a pinned
		// revision needs one (ErrRevisionNeedsCache); this row is about the
		// volume, so it renders the unpinned shape.
		m.Spec.Revision = ""
		objs, err := Render(m, testOptions())
		if err != nil {
			t.Fatalf("Render() error = %v, want nil", err)
		}
		sts := objs.StatefulSet
		if len(sts.Spec.VolumeClaimTemplates) != 0 {
			t.Errorf("volumeClaimTemplates = %d, want 0 when spec.cache is absent", len(sts.Spec.VolumeClaimTemplates))
		}
		c := sts.Spec.Template.Spec.Containers[0]
		if len(c.VolumeMounts) != 0 {
			t.Errorf("volumeMounts = %v, want none when there is no cache volume", c.VolumeMounts)
		}
		for _, e := range c.Env {
			if e.Name == hfHomeEnv {
				t.Errorf("%s = %q, want unset when there is no cache volume to point it at", hfHomeEnv, e.Value)
			}
		}
	})

	t.Run("container_image_port_and_args", func(t *testing.T) {
		m := newModel()
		objs, err := Render(m, testOptions())
		if err != nil {
			t.Fatalf("Render() error = %v, want nil", err)
		}
		c := objs.StatefulSet.Spec.Template.Spec.Containers[0]
		if c.Image != m.Spec.Runtime.Image {
			t.Errorf("image = %q, want spec.runtime.image %q", c.Image, m.Spec.Runtime.Image)
		}
		if len(c.Ports) != 1 || c.Ports[0].ContainerPort != m.Spec.Port || c.Ports[0].Name != portName {
			t.Errorf("ports = %v, want one %s port %d (from spec.port)", c.Ports, portName, m.Spec.Port)
		}
		args := strings.Join(c.Args, " ")
		// The model is a POSITIONAL and a pinned revision is a path, not an
		// option — see modelReference and TestEngineArgsMatchTheMeasuredSurface,
		// which owns the full argv contract.
		for _, want := range []string{
			"models--mlx-community--Qwen3-0.6B-4bit/snapshots/" + m.Spec.Revision,
			"--port 9123",
		} {
			if !strings.Contains(args, want) {
				t.Errorf("args = %q, want it to contain %q", args, want)
			}
		}
		if got, want := c.Args[len(c.Args)-2:], m.Spec.Runtime.Args; !reflect.DeepEqual(got, want) {
			t.Errorf("trailing args = %v, want the caller's spec.runtime.args %v LAST (so an operator can override)", got, want)
		}
	})

	t.Run("image_and_port_fall_back_to_the_operator_defaults", func(t *testing.T) {
		m := newModel()
		m.Spec.Runtime.Image = ""
		m.Spec.Port = 0
		objs, err := Render(m, testOptions())
		if err != nil {
			t.Fatalf("Render() error = %v, want nil", err)
		}
		c := objs.StatefulSet.Spec.Template.Spec.Containers[0]
		if c.Image != testImage {
			t.Errorf("image = %q, want the configured default %q", c.Image, testImage)
		}
		if c.Ports[0].ContainerPort != testDefPort {
			t.Errorf("containerPort = %d, want the configured default %d", c.Ports[0].ContainerPort, testDefPort)
		}
		if objs.ClusterIPService.Spec.Ports[0].Port != testDefPort {
			t.Errorf("Service port = %d, want %d", objs.ClusterIPService.Spec.Ports[0].Port, testDefPort)
		}
	})

	t.Run("headless_and_clusterip_services", func(t *testing.T) {
		m := newModel()
		objs, err := Render(m, testOptions())
		if err != nil {
			t.Fatalf("Render() error = %v, want nil", err)
		}
		hl, cip := objs.HeadlessService, objs.ClusterIPService
		if hl == nil || cip == nil {
			t.Fatalf("services = %v/%v, want both a governing headless Service and a stable ClusterIP Service", hl, cip)
		}
		if hl.Name == cip.Name {
			t.Errorf("both Services are named %q — the governing Service and the endpoint Service are distinct objects", hl.Name)
		}
		if got, want := hl.Name, HeadlessServiceName(m.Name); got != want {
			t.Errorf("headless Service name = %q, want %q", got, want)
		}
		if got, want := cip.Name, ServiceName(m.Name); got != want {
			t.Errorf("ClusterIP Service name = %q, want %q", got, want)
		}
		if hl.Spec.ClusterIP != corev1.ClusterIPNone {
			t.Errorf("headless Service clusterIP = %q, want %q", hl.Spec.ClusterIP, corev1.ClusterIPNone)
		}
		if !hl.Spec.PublishNotReadyAddresses {
			t.Error("headless Service publishNotReadyAddresses = false, want true — per-replica DNS identity must exist before the replica is ready")
		}
		if cip.Spec.ClusterIP == corev1.ClusterIPNone {
			t.Error("ClusterIP Service is headless, want an allocated ClusterIP (it is the endpoint clients call)")
		}
		if cip.Spec.PublishNotReadyAddresses {
			t.Error("ClusterIP Service publishNotReadyAddresses = true, want false — a request routed to a still-loading replica hangs")
		}
		for _, s := range []*corev1.Service{hl, cip} {
			if s.Namespace != m.Namespace {
				t.Errorf("Service %s namespace = %q, want %q", s.Name, s.Namespace, m.Namespace)
			}
			if !reflect.DeepEqual(s.Spec.Selector, selectorLabels(m.Name)) {
				t.Errorf("Service %s selector = %v, want %v", s.Name, s.Spec.Selector, selectorLabels(m.Name))
			}
			if len(s.Spec.Ports) != 1 || s.Spec.Ports[0].Port != m.Spec.Port || s.Spec.Ports[0].TargetPort.StrVal != portName {
				t.Errorf("Service %s ports = %v, want one port %d targeting %q", s.Name, s.Spec.Ports, m.Spec.Port, portName)
			}
		}
	})

	t.Run("render_is_pure_and_deterministic", func(t *testing.T) {
		m := newModel()
		before := m.DeepCopy()
		first, err := Render(m, testOptions())
		if err != nil {
			t.Fatalf("Render() error = %v, want nil", err)
		}
		// Mutating the first result must not reach a later render (no shared maps
		// or slices between calls).
		first.StatefulSet.Spec.Template.Spec.NodeSelector["injected"] = "yes"
		first.StatefulSet.Spec.Template.Spec.Containers[0].Args[0] = "--clobbered"
		second, err := Render(m, testOptions())
		if err != nil {
			t.Fatalf("Render() second call error = %v, want nil", err)
		}
		if _, bad := second.StatefulSet.Spec.Template.Spec.NodeSelector["injected"]; bad {
			t.Error("a mutation of one render leaked into the next — the render shares state between calls")
		}
		if second.StatefulSet.Spec.Template.Spec.Containers[0].Args[0] == "--clobbered" {
			t.Error("args are shared between renders")
		}
		if !reflect.DeepEqual(m, before) {
			t.Error("Render() mutated its input MLXModel; it must be pure")
		}
		third, err := Render(m, testOptions())
		if err != nil {
			t.Fatalf("Render() third call error = %v, want nil", err)
		}
		if !reflect.DeepEqual(second, third) {
			t.Error("two renders of the same spec differ — the render is not deterministic")
		}
	})

	t.Run("invalid_specs_are_typed_errors_and_render_nothing", func(t *testing.T) {
		longName := strings.Repeat("m", 60) // + "-headless" exceeds 63
		cases := []struct {
			name     string
			mutate   func(*mlxv1alpha1.MLXModel)
			opts     Options
			nilModel bool
			want     error
		}{
			{name: "nil_mlxmodel", nilModel: true, want: ErrNoModel},
			{name: "no_name", mutate: func(m *mlxv1alpha1.MLXModel) { m.Name = "" }, want: ErrNoModel},
			{name: "no_namespace", mutate: func(m *mlxv1alpha1.MLXModel) { m.Namespace = "" }, want: ErrNoModel},
			{name: "no_uid", mutate: func(m *mlxv1alpha1.MLXModel) { m.UID = "" }, want: ErrNoUID},
			{name: "name_too_long_for_a_dns_label", mutate: func(m *mlxv1alpha1.MLXModel) { m.Name = longName }, want: ErrNameTooLong},
			{name: "missing_spec_model", mutate: func(m *mlxv1alpha1.MLXModel) { m.Spec.Model = "" }, want: ErrNoSpecModel},
			{name: "missing_memory", mutate: func(m *mlxv1alpha1.MLXModel) { m.Spec.Memory = resource.Quantity{} }, want: ErrNoMemory},
			{name: "zero_memory", mutate: func(m *mlxv1alpha1.MLXModel) { m.Spec.Memory = resource.MustParse("0") }, want: ErrNoMemory},
			{name: "negative_memory", mutate: func(m *mlxv1alpha1.MLXModel) { m.Spec.Memory = resource.MustParse("-1Gi") }, want: ErrNoMemory},
			{
				name:   "missing_image_with_no_default",
				mutate: func(m *mlxv1alpha1.MLXModel) { m.Spec.Runtime.Image = "" },
				opts:   Options{DefaultPort: testDefPort},
				want:   ErrNoImage,
			},
			{
				name:   "missing_port_with_no_default",
				mutate: func(m *mlxv1alpha1.MLXModel) { m.Spec.Port = 0 },
				opts:   Options{DefaultImage: testImage},
				want:   ErrNoPort,
			},
			{name: "port_out_of_range", mutate: func(m *mlxv1alpha1.MLXModel) { m.Spec.Port = 70000 }, want: ErrInvalidPort},
			{name: "negative_port", mutate: func(m *mlxv1alpha1.MLXModel) { m.Spec.Port = -1 }, want: ErrInvalidPort},
			{name: "negative_replicas", mutate: func(m *mlxv1alpha1.MLXModel) { m.Spec.Replicas = ptr.To(int32(-1)) }, want: ErrInvalidReplicas},
			{
				name:   "zero_cache_size",
				mutate: func(m *mlxv1alpha1.MLXModel) { m.Spec.Cache = &mlxv1alpha1.MLXCache{Size: resource.MustParse("0")} },
				want:   ErrInvalidCacheSize,
			},
			{
				name: "node_selector_fights_the_os_guardrail",
				mutate: func(m *mlxv1alpha1.MLXModel) {
					m.Spec.NodeSelector = map[string]string{corev1.LabelOSStable: "linux"}
				},
				want: ErrGuardrailConflict,
			},
			{
				name: "node_selector_fights_the_gpu_guardrail",
				mutate: func(m *mlxv1alpha1.MLXModel) {
					m.Spec.NodeSelector = map[string]string{mlxv1alpha1.LabelGPUPresent: "false"}
				},
				want: ErrGuardrailConflict,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				var m *mlxv1alpha1.MLXModel
				if !tc.nilModel {
					m = newModel()
					if tc.mutate != nil {
						tc.mutate(m)
					}
				}
				opts := tc.opts
				if opts == (Options{}) {
					opts = testOptions()
				}
				objs, err := Render(m, opts)
				if !errors.Is(err, tc.want) {
					t.Fatalf("Render() error = %v, want one wrapping %v", err, tc.want)
				}
				if objs != nil {
					t.Errorf("Render() returned %+v alongside an error, want no partial object set", objs)
				}
			})
		}
	})

	t.Run("restating_a_guardrail_verbatim_is_not_a_conflict", func(t *testing.T) {
		m := newModel()
		m.Spec.NodeSelector = map[string]string{
			corev1.LabelOSStable:        "darwin",
			mlxv1alpha1.LabelGPUPresent: "true",
		}
		if _, err := Render(m, testOptions()); err != nil {
			t.Errorf("Render() error = %v, want nil — restating a guardrail with the SAME value is harmless, only a different value is a conflict", err)
		}
	})
}
