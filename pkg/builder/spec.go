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

package builder

import (
	_ "embed"
	"fmt"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	storagev1 "k3sm.io/apis/storage/v1"
	"k3sm.io/k3sm/pkg/images"
	"k3sm.io/k3sm/pkg/runtimeclass"
)

// entrypointScript is the whole in-pod payload, embedded so the binary carries
// its own builder image bring-up. It is delivered as the Pod's command; see
// assets/entrypoint.sh for the platform facts it satisfies.
//
//go:embed assets/entrypoint.sh
var entrypointScript string

// Defaults for the builder stack. Each is overridable through Config; the
// defaults are chosen so a plain `k3sm builder up` on a single node works with no
// token today (see DefaultImage on the direct-upstream pull decision).
const (
	// DefaultNamespace is where the builder stack lives. Its own namespace keeps
	// the one long-lived engine out of a workload namespace's blast radius.
	DefaultNamespace = "k3sm-builder"
	// DefaultName is the shared name of the Pod, Service and PVC.
	DefaultName = "k3sm-builder"
	// DefaultTCPPort is the buildkitd tcp listener the ClusterIP Service fronts
	// and a buildx remote driver dials.
	DefaultTCPPort = 1234
	// DefaultCacheSize is the build-cache PVC size. Half is headroom: the ext4
	// image, the buildkit --root, $TMPDIR and the buildx state all live on it, so
	// "no space left" should mean a genuine runaway, not steady state.
	DefaultCacheSize = "40Gi"
	// DefaultGCKeepBytes is the buildkit gc ceiling written into buildkitd.toml.
	DefaultGCKeepBytes = 20_000_000_000
	// DefaultCPU / DefaultMemory size the vm the batch builds run in. requests ==
	// limits: a builder either gets the machine it needs or should not start.
	DefaultCPU    = "4"
	DefaultMemory = "8Gi"

	// portName is the named container/Service port for the buildkitd listener.
	portName = "buildkitd"
	// containerName is the buildkitd container's name (the Execer targets it).
	containerName = "buildkitd"
	// managedLabel marks every object this package owns.
	managedLabel = "k3sm.io/managed"
	// appLabel selects the Pod from the Service.
	appLabel = "app.kubernetes.io/name"
)

// DefaultImage is the buildkitd image a plain bring-up uses: the UPSTREAM
// moby/buildkit reference at the SAME digest the k3sm GHCR mirror pins.
//
// The default is upstream-direct, not the mirror, on purpose. The
// ghcr.io/k3sm-io/mirror/* namespace is currently PRIVATE and its populate
// workflow is dormant, so an anonymous mirror pull fails today and the pod would
// need an imagePullSecret it cannot get. The digest is byte-identical either way
// (m12-plan Resolution 12: the mirror copy preserves upstream's digest), so this
// is exactly the documented GHCR-outage runbook — pull the same digest from
// upstream — made the default. `Config.UseMirror` flips to the mirror ref for a
// deployment that has published the package and holds a read:packages token.
func DefaultImage() string {
	digest := images.Buildkitd
	if i := strings.LastIndex(digest, "@"); i >= 0 {
		digest = digest[i:]
	}
	return "docker.io/moby/buildkit" + digest
}

// Config is the desired builder stack. The zero value is not usable; call
// Normalize to fill defaults, then the renderers.
type Config struct {
	// Namespace, Name locate the Pod/Service/PVC. Empty => the defaults.
	Namespace string
	Name      string
	// NodeName pins the engine to one node (kubernetes.io/hostname). Empty lets
	// the scheduler place it on any vm-capable darwin node.
	NodeName string
	// Image overrides the buildkitd image. Empty => DefaultImage (upstream digest)
	// unless UseMirror is set.
	Image string
	// UseMirror selects the k3sm GHCR mirror ref (images.Buildkitd) instead of the
	// upstream-direct default. It needs a published package and, if private, a
	// PullSecret.
	UseMirror bool
	// PullSecret names an imagePullSecret for a private registry. Empty => none
	// (the default upstream-direct pull is anonymous).
	PullSecret string
	// TCPPort is the buildkitd tcp port. 0 => DefaultTCPPort.
	TCPPort int
	// CacheSize is the build-cache PVC size. Empty => DefaultCacheSize.
	CacheSize string
	// StorageClassName is the PVC class. Empty => the k3sm local-path class.
	StorageClassName string
	// GCKeepBytes is the buildkit gc ceiling. 0 => DefaultGCKeepBytes.
	GCKeepBytes int64
	// CPU, Memory size the builder pod. Empty => the defaults.
	CPU    string
	Memory string
}

// Normalize returns a copy with every empty field defaulted. It never mutates the
// receiver, so a Config value can be reused.
func (c Config) Normalize() Config {
	n := c
	if n.Namespace == "" {
		n.Namespace = DefaultNamespace
	}
	if n.Name == "" {
		n.Name = DefaultName
	}
	if n.Image == "" {
		if n.UseMirror {
			n.Image = images.Buildkitd
		} else {
			n.Image = DefaultImage()
		}
	}
	if n.TCPPort == 0 {
		n.TCPPort = DefaultTCPPort
	}
	if n.CacheSize == "" {
		n.CacheSize = DefaultCacheSize
	}
	if n.StorageClassName == "" {
		n.StorageClassName = storagev1.DefaultStorageClassName
	}
	if n.GCKeepBytes == 0 {
		n.GCKeepBytes = DefaultGCKeepBytes
	}
	if n.CPU == "" {
		n.CPU = DefaultCPU
	}
	if n.Memory == "" {
		n.Memory = DefaultMemory
	}
	return n
}

// Validate checks a normalized Config for values the renderers cannot express.
func (c Config) Validate() error {
	n := c.Normalize()
	if n.TCPPort < 1 || n.TCPPort > 65535 {
		return fmt.Errorf("builder: tcp port %d out of range", n.TCPPort)
	}
	if _, err := resource.ParseQuantity(n.CacheSize); err != nil {
		return fmt.Errorf("builder: cache size %q: %w", n.CacheSize, err)
	}
	if _, err := resource.ParseQuantity(n.CPU); err != nil {
		return fmt.Errorf("builder: cpu %q: %w", n.CPU, err)
	}
	if _, err := resource.ParseQuantity(n.Memory); err != nil {
		return fmt.Errorf("builder: memory %q: %w", n.Memory, err)
	}
	if n.UseMirror && !strings.Contains(n.Image, "@sha256:") {
		return fmt.Errorf("builder: mirror image %q is not digest-pinned", n.Image)
	}
	return nil
}

// labels are the identifying labels every object carries.
func (c Config) labels() map[string]string {
	return map[string]string{
		appLabel:                       c.Name,
		managedLabel:                   "true",
		"app.kubernetes.io/component":  "image-build",
		"app.kubernetes.io/part-of":    "k3sm",
		"app.kubernetes.io/managed-by": "k3sm",
	}
}

// selector is the subset the Service matches on — never the whole label set, so
// an added descriptive label never silently changes what the Service selects.
func (c Config) selector() map[string]string {
	return map[string]string{appLabel: c.Name}
}

func (c Config) meta() metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: c.Name, Namespace: c.Namespace, Labels: c.labels()}
}

// Namespace renders the namespace the builder stack lives in. It carries the
// same managed labels as the objects inside it, matching how the server
// provisions its own namespaces (pkg/rbac). Its own name is namespace-scoped,
// so its ObjectMeta is bare of a Namespace field.
func (c Config) NamespaceObject() *corev1.Namespace {
	n := c.Normalize()
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: n.Namespace, Labels: n.labels()},
	}
}

// PersistentVolumeClaim renders the build-cache claim. It is ReadWriteOnce (one
// node holds the engine) and is KEPT across Down so a rebuilt engine finds a warm
// cache.
func (c Config) PersistentVolumeClaim() *corev1.PersistentVolumeClaim {
	n := c.Normalize()
	return &corev1.PersistentVolumeClaim{
		ObjectMeta: n.meta(),
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			StorageClassName: ptr.To(n.StorageClassName),
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse(n.CacheSize)},
			},
		},
	}
}

// Service renders the ClusterIP Service that fronts the buildkitd tcp listener.
// It is a stable endpoint across a Pod reschedule, and k3sm's userspace proxy
// makes its ClusterIP host-dialable via an lo0 alias — the address Endpoint
// returns and a buildx remote driver dials.
func (c Config) Service() *corev1.Service {
	n := c.Normalize()
	return &corev1.Service{
		ObjectMeta: n.meta(),
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: n.selector(),
			Ports: []corev1.ServicePort{{
				Name:       portName,
				Port:       int32(n.TCPPort),
				TargetPort: intstr.FromInt(n.TCPPort),
				Protocol:   corev1.ProtocolTCP,
			}},
		},
	}
}

// Pod renders the long-lived buildkitd engine Pod.
//
// It carries NO securityContext by design (m12-plan Resolution 5): the vm
// RuntimeClass boots it under Virtualization.framework and the image's own root
// IS guest root with full caps — the VM is the isolation boundary, and buildkitd
// + runc need real root to mount cgroups and create build containers. restartPolicy
// is Always because this is a server, not a batch job.
func (c Config) Pod() *corev1.Pod {
	n := c.Normalize()

	nodeSelector := map[string]string{corev1.LabelOSStable: "darwin"}
	if n.NodeName != "" {
		nodeSelector[corev1.LabelHostname] = n.NodeName
	}

	q := resource.MustParse(n.CPU)
	mem := resource.MustParse(n.Memory)
	resources := corev1.ResourceRequirements{
		Requests: corev1.ResourceList{corev1.ResourceCPU: q, corev1.ResourceMemory: mem},
		Limits:   corev1.ResourceList{corev1.ResourceCPU: q, corev1.ResourceMemory: mem},
	}

	pod := &corev1.Pod{
		ObjectMeta: n.meta(),
		Spec: corev1.PodSpec{
			RuntimeClassName: ptr.To(runtimeclass.Name),
			RestartPolicy:    corev1.RestartPolicyAlways,
			NodeSelector:     nodeSelector,
			Tolerations: []corev1.Toleration{{
				Key:      "k3sm.io/provider",
				Operator: corev1.TolerationOpExists,
				Effect:   corev1.TaintEffectNoSchedule,
			}},
			Containers: []corev1.Container{{
				Name:  containerName,
				Image: n.Image,
				// Digest-pinned, so IfNotPresent is exact: a digest cannot drift,
				// and re-resolving it every start would cost a registry round trip
				// for an immutable reference.
				ImagePullPolicy: corev1.PullIfNotPresent,
				Command:         []string{"/bin/sh", "-c", entrypointScript},
				Env:             n.env(),
				Ports: []corev1.ContainerPort{{
					Name:          portName,
					ContainerPort: int32(n.TCPPort),
					Protocol:      corev1.ProtocolTCP,
				}},
				Resources: resources,
				VolumeMounts: []corev1.VolumeMount{{
					Name:      "cache",
					MountPath: "/cache",
				}},
			}},
			Volumes: []corev1.Volume{{
				Name: "cache",
				VolumeSource: corev1.VolumeSource{
					PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: n.Name},
				},
			}},
		},
	}
	if n.PullSecret != "" {
		pod.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: n.PullSecret}}
	}
	return pod
}

// env is the Pod's environment: the buildx pin (so it lives ONLY in Go) and the
// tcp port and cache facts the entrypoint reads.
func (c Config) env() []corev1.EnvVar {
	return []corev1.EnvVar{
		{Name: "BUILDX_VERSION", Value: BuildxVersion},
		{Name: "BUILDX_ASSET", Value: BuildxAsset},
		{Name: "BUILDX_SHA256", Value: BuildxSHA256},
		{Name: "BUILDX_URL", Value: BuildxURL()},
		{Name: "K3SM_BUILDER_TCP_PORT", Value: strconv.Itoa(c.TCPPort)},
		{Name: "K3SM_BUILDER_CACHE", Value: "/cache"},
		{Name: "K3SM_BUILDER_GC_KEEP_BYTES", Value: strconv.FormatInt(c.GCKeepBytes, 10)},
	}
}
