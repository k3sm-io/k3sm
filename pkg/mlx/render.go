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
	"fmt"
	"maps"
	"strconv"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	"k3sm.io/k3sm/pkg/policy"
)

// Render errors. They are sentinels so a caller can branch on the CLASS of a bad
// spec (surfacing it as a condition reason) without matching on message text;
// every one of them is returned wrapped with the object's namespace/name, so use
// errors.Is, never string comparison.
var (
	// ErrNoModel is returned for a nil MLXModel, or one with no name or
	// namespace. Such an object cannot own anything: an ownerReference needs a
	// name and the rendered objects need a namespace to land in.
	ErrNoModel = errors.New("mlxmodel is nil or unnamed")
	// ErrNoUID is returned when the MLXModel carries no UID. The UID is what
	// makes an ownerReference a reference; an ownerReference without one is
	// rejected by the apiserver, so rendering objects that cannot be owned is
	// worse than refusing to render.
	ErrNoUID = errors.New("mlxmodel has no uid, so no ownerreference can be stamped")
	// ErrNameTooLong is returned when the derived governing-Service name exceeds
	// the 63-character DNS-label limit. A Service name is a DNS label, and the
	// apiserver rejects an over-long one at create time — on the controller's
	// behalf, where the operator does not see it.
	ErrNameTooLong = errors.New("derived service name exceeds the 63-character dns label limit")
	// ErrNoSpecModel is returned when spec.model is empty. There is nothing to
	// serve, and the serving container would start, find no model, and fail.
	ErrNoSpecModel = errors.New("spec.model is required")
	// ErrNoMemory is returned when spec.memory is unset or non-positive. On Apple
	// Silicon the GPU shares system memory, so this is the real scheduling
	// constraint; there is deliberately no default, because a guessed one
	// schedules successfully and then dies at load time on the node.
	ErrNoMemory = errors.New("spec.memory is required and must be positive")
	// ErrNoImage is returned when neither spec.runtime.image nor
	// Options.DefaultImage names a serving image.
	ErrNoImage = errors.New("no serving image: spec.runtime.image is empty and no default image was configured")
	// ErrNoPort is returned when neither spec.port nor Options.DefaultPort names
	// a port. The render does not invent one: the port has to agree with the
	// serving image the operator pinned, and only the operator knows both.
	ErrNoPort = errors.New("no serving port: spec.port is 0 and no default port was configured")
	// ErrInvalidPort is returned for a port outside 1-65535.
	ErrInvalidPort = errors.New("port is out of range")
	// ErrInvalidReplicas is returned for a negative spec.replicas. Zero is legal
	// and means scale-to-zero (stop serving without deleting the cache).
	ErrInvalidReplicas = errors.New("spec.replicas must not be negative")
	// ErrInvalidCacheSize is returned when spec.cache is set with a non-positive
	// size. A zero-sized claim is accepted by no provisioner, so the StatefulSet
	// would never produce a running pod.
	ErrInvalidCacheSize = errors.New("spec.cache.size must be positive")
	// ErrGuardrailConflict is returned when spec.nodeSelector tries to give a
	// guardrail key a different value. The guardrail stanza is fixed template
	// content; silently overriding the caller would place the pod where it cannot
	// run, and silently ignoring the caller would look like the selector took
	// effect.
	ErrGuardrailConflict = errors.New("spec.nodeSelector conflicts with a fixed guardrail selector")
)

// Fixed rendering constants. Each is the render's side of a contract with
// something outside this package, so each is named rather than inlined.
const (
	// mlxModelKind is the Kind an ownerReference names. The apis package
	// registers the type but publishes no Kind constant, and an ownerReference
	// carries the Kind as a string.
	mlxModelKind = "MLXModel"

	// labelOSDarwin is the value of the kubernetes.io/os node label on every
	// k3sm node. k8s.io/api exports the KEY (corev1.LabelOSStable) but not the
	// GOOS values.
	labelOSDarwin = "darwin"

	// gpuPresentTrue is the value of the GPU presence node label. The label is
	// absent rather than "false" on a node without a GPU, so this is the only
	// value a selector ever matches.
	gpuPresentTrue = "true"

	// gpuDeviceCount is the units of the GPU extended resource one serving
	// replica requests. Apple Silicon exposes ONE integrated GPU per host and the
	// node advertises 1, so requesting 1 makes the resource a mutex: a second
	// model server on the same Mac stays Pending instead of contending for the
	// same Metal device.
	gpuDeviceCount = 1

	// containerName is the serving container's name, stable so that logs, exec,
	// and status derivation address it by a name that never moves.
	containerName = "mlx-serve"

	// portName is the named container/Service port. Named because the Service and
	// the readiness probe both target it by name, which keeps them correct when
	// the number changes.
	portName = "http"

	// cacheVolumeName is the volumeClaimTemplate name, and therefore the stable
	// prefix of every generated PVC name.
	cacheVolumeName = "cache"

	// CacheMountPath is where the weight-cache volume is mounted in the serving
	// container.
	CacheMountPath = "/var/lib/mlx/cache"

	// hfHomeEnv is the environment variable the serving runtime reads to decide
	// where downloaded weights live. Pointing it INTO the cache volume is what
	// makes the volume a cache at all: left at its default the weights land on
	// the container filesystem and are re-downloaded on every restart.
	hfHomeEnv = "HF_HOME"

	// hfHomePath is the HF_HOME value: a subdirectory of the mount, not the mount
	// root, so the volume can hold other state later without colliding with the
	// hub's own layout.
	hfHomePath = CacheMountPath + "/huggingface"

	// healthPath is the readiness endpoint. It is part of the serving image's
	// OpenAI-compatible surface, which is the only thing this render assumes
	// about the engine — the image is swappable as long as it answers here.
	healthPath = "/health"

	// dnsLabelMaxLen is the Kubernetes DNS-label limit a Service name obeys.
	dnsLabelMaxLen = 63

	// headlessSuffix distinguishes the governing Service from the ClusterIP one.
	headlessSuffix = "-headless"
)

// Readiness-probe timings. A model server answers /health quickly once it is up,
// but may take tens of minutes to get there; readiness has no kill semantics, so
// a generous initial delay buys nothing and a short period costs nothing.
const (
	readinessPeriodSeconds    = 10
	readinessTimeoutSeconds   = 5
	readinessFailureThreshold = 3
	readinessSuccessThreshold = 1
)

// Options carries the operator-level defaults a render needs and an MLXModel
// spec does not have to state.
//
// Both fields are REQUIRED unless the spec supplies the value itself: the
// serving image is a digest the release pins, and the port has to agree with
// that image. A render that invented either would produce a StatefulSet that
// looks right and serves nothing, which is precisely the failure the operator's
// own configuration exists to prevent.
type Options struct {
	// DefaultImage is the pinned serving image used when spec.runtime.image is
	// empty.
	DefaultImage string
	// DefaultPort is the serving port used when spec.port is 0.
	DefaultPort int32
}

// Objects are the API objects that serve one MLXModel. Every one of them carries
// a controller ownerReference to that MLXModel, so deleting the model deletes
// all of them.
type Objects struct {
	// StatefulSet runs the serving replicas. A StatefulSet rather than a
	// Deployment because each replica owns a node-pinned cache volume: a
	// Deployment's replica set would strand replica 2 on replica 1's volume.
	StatefulSet *appsv1.StatefulSet
	// HeadlessService is the StatefulSet's governing Service, giving each replica
	// a stable DNS identity. It is also the seam multi-node sharded serving will
	// need.
	HeadlessService *corev1.Service
	// ClusterIPService is the stable endpoint clients use. It is a separate
	// object from the governing Service on purpose: the governing one publishes
	// not-ready addresses (identity), and a client must not be load-balanced onto
	// a replica that is still downloading weights.
	ClusterIPService *corev1.Service
}

// StatefulSetName returns the name of the StatefulSet rendered for the MLXModel
// called name. Every rendered name is a pure function of the MLXModel's name so
// that a reconcile can find its own objects without a live lookup.
func StatefulSetName(name string) string { return name }

// HeadlessServiceName returns the name of the governing (headless) Service
// rendered for the MLXModel called name.
func HeadlessServiceName(name string) string { return name + headlessSuffix }

// ServiceName returns the name of the stable ClusterIP Service rendered for the
// MLXModel called name — the address published as the model's endpoint.
func ServiceName(name string) string { return name }

// Labels returns the labels every object rendered for the MLXModel called name
// carries. Only the recommended app.kubernetes.io keys are used: they identify
// the objects for humans and for the pod selector without minting a new
// k3sm-owned label key that would then have to live in apis.
func Labels(name string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "mlx-model",
		"app.kubernetes.io/instance":   name,
		"app.kubernetes.io/managed-by": "k3sm",
	}
}

// selectorLabels returns the immutable subset of Labels used as the StatefulSet
// and Service selector. It is deliberately narrower than Labels: a selector is
// immutable after create, so managed-by (which may be re-branded) must not be in
// it.
func selectorLabels(name string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":     "mlx-model",
		"app.kubernetes.io/instance": name,
	}
}

// Render turns an MLXModel spec into the objects that serve it. It is pure: it
// performs no IO, does not mutate m, and returns the same objects for the same
// input. An invalid or incomplete spec yields a wrapped sentinel error (see the
// Err* vars) and NO partial object set — a half-rendered model is worse than an
// unrendered one, because the applied half looks like progress.
func Render(m *mlxv1alpha1.MLXModel, opts Options) (*Objects, error) {
	if m == nil || m.Name == "" || m.Namespace == "" {
		return nil, ErrNoModel
	}
	if m.UID == "" {
		return nil, renderErr(m, ErrNoUID)
	}
	if len(HeadlessServiceName(m.Name)) > dnsLabelMaxLen {
		return nil, renderErr(m, fmt.Errorf("%w: %q is %d characters", ErrNameTooLong,
			HeadlessServiceName(m.Name), len(HeadlessServiceName(m.Name))))
	}
	if m.Spec.Model == "" {
		return nil, renderErr(m, ErrNoSpecModel)
	}
	if m.Spec.Memory.Sign() <= 0 {
		return nil, renderErr(m, ErrNoMemory)
	}

	image := m.Spec.Runtime.Image
	if image == "" {
		image = opts.DefaultImage
	}
	if image == "" {
		return nil, renderErr(m, ErrNoImage)
	}

	port := m.Spec.Port
	if port == 0 {
		port = opts.DefaultPort
	}
	if port == 0 {
		return nil, renderErr(m, ErrNoPort)
	}
	if port < 0 || port > 65535 {
		return nil, renderErr(m, fmt.Errorf("%w: %d", ErrInvalidPort, port))
	}

	replicas := int32(1)
	if m.Spec.Replicas != nil {
		replicas = *m.Spec.Replicas
		if replicas < 0 {
			return nil, renderErr(m, fmt.Errorf("%w: %d", ErrInvalidReplicas, replicas))
		}
	}

	if m.Spec.Cache != nil && m.Spec.Cache.Size.Sign() <= 0 {
		return nil, renderErr(m, ErrInvalidCacheSize)
	}

	nodeSelector, err := podNodeSelector(m.Spec.NodeSelector)
	if err != nil {
		return nil, renderErr(m, err)
	}

	owner := ownerReference(m)
	return &Objects{
		StatefulSet:      statefulSet(m, owner, image, port, replicas, nodeSelector),
		HeadlessService:  headlessService(m, owner, port),
		ClusterIPService: clusterIPService(m, owner, port),
	}, nil
}

// renderErr wraps err with the model it came from, so a caller logging one error
// knows which object produced it without threading the name separately.
func renderErr(m *mlxv1alpha1.MLXModel, err error) error {
	return fmt.Errorf("render mlxmodel %s/%s: %w", m.Namespace, m.Name, err)
}

// ownerReference builds the CONTROLLER ownerReference every rendered object
// carries. controller and blockOwnerDeletion are both true: the first makes this
// the one controller adopting the object (a second controller claiming it is
// then a reportable conflict rather than a silent fight), the second keeps the
// MLXModel alive until its children are actually gone.
func ownerReference(m *mlxv1alpha1.MLXModel) metav1.OwnerReference {
	return metav1.OwnerReference{
		APIVersion:         mlxv1alpha1.SchemeGroupVersion.String(),
		Kind:               mlxModelKind,
		Name:               m.Name,
		UID:                m.UID,
		Controller:         ptr.To(true),
		BlockOwnerDeletion: ptr.To(true),
	}
}

// podNodeSelector merges the caller's spec.nodeSelector under the FIXED
// guardrail selectors. The guardrails are not defaults the caller may override:
// a pod that lands on a non-darwin node, or on a node with no GPU, cannot serve
// at all, so a conflicting value is an error rather than a silent win for either
// side. An identical value is not a conflict — restating a guardrail is harmless.
func podNodeSelector(specSelector map[string]string) (map[string]string, error) {
	guardrails := map[string]string{
		corev1.LabelOSStable:        labelOSDarwin,
		mlxv1alpha1.LabelGPUPresent: gpuPresentTrue,
	}
	out := make(map[string]string, len(specSelector)+len(guardrails))
	maps.Copy(out, specSelector)
	for k, v := range guardrails {
		if got, ok := out[k]; ok && got != v {
			return nil, fmt.Errorf("%w: %s=%q, fixed to %q", ErrGuardrailConflict, k, got, v)
		}
		out[k] = v
	}
	return out, nil
}

// podResources builds the container resource requirements. Two rules, both from
// the resource model:
//
//   - The GPU extended resource is in requests AND limits. Kubernetes requires
//     the two to be equal for an extended resource, and k3sm's admission policy
//     rejects a GPU pod that states only one of them.
//   - memory request == limit == spec.memory. Unified memory is plain memory —
//     there is no second extended resource for it, because that would
//     double-account the same bytes and let the scheduler admit a combination
//     that jetsam then kills. Equal request and limit is what keeps the
//     control-plane hold-back protecting the daemons.
func podResources(memory resource.Quantity) corev1.ResourceRequirements {
	gpu := *resource.NewQuantity(gpuDeviceCount, resource.DecimalSI)
	list := corev1.ResourceList{
		corev1.ResourceMemory:                        memory.DeepCopy(),
		corev1.ResourceName(mlxv1alpha1.ResourceGPU): gpu,
	}
	return corev1.ResourceRequirements{
		Requests: list.DeepCopy(),
		Limits:   list.DeepCopy(),
	}
}

// engineArgs builds the serving container's argument vector: what to serve and
// where to listen, then the caller's own arguments LAST so an operator can
// override any of it without this package growing a flag per knob.
func engineArgs(spec mlxv1alpha1.MLXModelSpec, port int32) []string {
	args := []string{
		"--model", spec.Model,
		"--port", strconv.FormatInt(int64(port), 10),
	}
	if spec.Revision != "" {
		args = append(args, "--revision", spec.Revision)
	}
	if spec.Quantization != "" {
		args = append(args, "--quantization", spec.Quantization)
	}
	return append(args, spec.Runtime.Args...)
}

// statefulSet renders the serving StatefulSet.
func statefulSet(m *mlxv1alpha1.MLXModel, owner metav1.OwnerReference, image string, port, replicas int32, nodeSelector map[string]string) *appsv1.StatefulSet {
	container := corev1.Container{
		Name:  containerName,
		Image: image,
		Args:  engineArgs(m.Spec, port),
		Ports: []corev1.ContainerPort{{
			Name:          portName,
			ContainerPort: port,
			Protocol:      corev1.ProtocolTCP,
		}},
		Resources: podResources(m.Spec.Memory),
		// READINESS ONLY. There is deliberately no LivenessProbe and no
		// StartupProbe: see the package doc — the first start is an unbounded
		// download, and a probe with kill semantics turns it into a crash loop
		// that re-downloads from zero.
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: healthPath,
					Port: intstr.FromString(portName),
				},
			},
			PeriodSeconds:    readinessPeriodSeconds,
			TimeoutSeconds:   readinessTimeoutSeconds,
			FailureThreshold: readinessFailureThreshold,
			SuccessThreshold: readinessSuccessThreshold,
		},
	}

	var claims []corev1.PersistentVolumeClaim
	if c := m.Spec.Cache; c != nil {
		container.Env = append(container.Env, corev1.EnvVar{Name: hfHomeEnv, Value: hfHomePath})
		container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
			Name:      cacheVolumeName,
			MountPath: CacheMountPath,
		})
		claims = append(claims, cacheClaim(m, *c))
	}

	return &appsv1.StatefulSet{
		TypeMeta: metav1.TypeMeta{APIVersion: appsv1.SchemeGroupVersion.String(), Kind: "StatefulSet"},
		ObjectMeta: metav1.ObjectMeta{
			Name:            StatefulSetName(m.Name),
			Namespace:       m.Namespace,
			Labels:          Labels(m.Name),
			OwnerReferences: []metav1.OwnerReference{owner},
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas:    ptr.To(replicas),
			ServiceName: HeadlessServiceName(m.Name),
			Selector:    &metav1.LabelSelector{MatchLabels: selectorLabels(m.Name)},
			// Parallel, not the OrderedReady default: readiness here is gated on a
			// weight download, so ordered start-up would serialize N downloads and
			// leave replica N waiting for a window measured in hours.
			PodManagementPolicy: appsv1.ParallelPodManagement,
			// whenDeleted Delete is the deletion contract: ownerReferences do not
			// cascade through these PVCs. whenScaled stays Retain — a scale-down is
			// reversible and the weights are expensive to re-fetch.
			PersistentVolumeClaimRetentionPolicy: &appsv1.StatefulSetPersistentVolumeClaimRetentionPolicy{
				WhenDeleted: appsv1.DeletePersistentVolumeClaimRetentionPolicyType,
				WhenScaled:  appsv1.RetainPersistentVolumeClaimRetentionPolicyType,
			},
			VolumeClaimTemplates: claims,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: Labels(m.Name)},
				Spec: corev1.PodSpec{
					NodeSelector: nodeSelector,
					// The k3sm provider taint is on EVERY k3sm node; without this
					// toleration the pod is simply unschedulable.
					Tolerations: []corev1.Toleration{{
						Key:      policy.ProviderTaintKey,
						Operator: corev1.TolerationOpExists,
						Effect:   corev1.TaintEffectNoSchedule,
					}},
					Containers: []corev1.Container{container},
				},
			},
		},
	}
}

// cacheClaim renders the per-replica weight-cache volumeClaimTemplate. The
// generated PVCs are the v1 cache home: one volume per replica, node-pinned by
// the storage class, holding the downloaded weights across restarts.
func cacheClaim(m *mlxv1alpha1.MLXModel, cache mlxv1alpha1.MLXCache) corev1.PersistentVolumeClaim {
	claim := corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:   cacheVolumeName,
			Labels: Labels(m.Name),
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceStorage: cache.Size.DeepCopy()},
			},
		},
	}
	// An empty storage class means the CLUSTER DEFAULT, which is not the same as
	// the empty-string class (that one means "no dynamic provisioning"), so the
	// field is left nil rather than set to "".
	if cache.StorageClassName != "" {
		claim.Spec.StorageClassName = ptr.To(cache.StorageClassName)
	}
	return claim
}

// headlessService renders the governing Service. It publishes not-ready
// addresses because its job is stable per-replica DNS identity, which a replica
// needs before it is ready — not load balancing.
func headlessService(m *mlxv1alpha1.MLXModel, owner metav1.OwnerReference, port int32) *corev1.Service {
	svc := service(m, owner, HeadlessServiceName(m.Name), port)
	svc.Spec.ClusterIP = corev1.ClusterIPNone
	svc.Spec.PublishNotReadyAddresses = true
	return svc
}

// clusterIPService renders the stable endpoint clients call. It does NOT publish
// not-ready addresses: a request routed to a replica that is still loading is a
// hung request, not a served one.
func clusterIPService(m *mlxv1alpha1.MLXModel, owner metav1.OwnerReference, port int32) *corev1.Service {
	return service(m, owner, ServiceName(m.Name), port)
}

// service renders the shape both Services share.
func service(m *mlxv1alpha1.MLXModel, owner metav1.OwnerReference, name string, port int32) *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{APIVersion: corev1.SchemeGroupVersion.String(), Kind: "Service"},
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       m.Namespace,
			Labels:          Labels(m.Name),
			OwnerReferences: []metav1.OwnerReference{owner},
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: selectorLabels(m.Name),
			Ports: []corev1.ServicePort{{
				Name:       portName,
				Port:       port,
				TargetPort: intstr.FromString(portName),
				Protocol:   corev1.ProtocolTCP,
			}},
		},
	}
}
