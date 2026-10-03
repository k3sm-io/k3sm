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

package provider

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/clock"

	"k3sm.io/k3sm/pkg/provider/vkadapter"
)

// errNotReferenced is returned, with no apiserver call, for a Secret or
// ConfigMap that no pod registered on this node references.
//
// It is hygiene, not authorization: the apiserver's Node authorizer stays the
// only enforcement, and no server-side check may be loosened because the node
// already refuses. It is deliberately NOT os.ErrNotExist and not an apiserver
// NotFound, so an optional env or volume source never reads it as "absent";
// it fails the read.
var errNotReferenced = errors.New("not referenced by any pod on this node")

// The create-path Forbidden retry. A by-name GET right after a pod is bound
// can race the Node authorizer's graph, which the apiserver fills from its
// own pod informer, and a CreatePod error marks a restartPolicy: Never pod
// Failed for good. So on the create path a Forbidden is retried with backoff,
// inside ONE budget for the whole CreatePod fetch phase.
const (
	createFetchBudget     = 15 * time.Second
	forbiddenBackoffStart = 250 * time.Millisecond
	forbiddenBackoffMax   = 4 * time.Second
)

// objectReader reads one Secret or ConfigMap by namespace and name. The
// kubeResolver and kubeCredentials read through it; podRefManager is the
// production one.
type objectReader interface {
	secret(ctx context.Context, namespace, name string) (*corev1.Secret, error)
	configMap(ctx context.Context, namespace, name string) (*corev1.ConfigMap, error)
}

// podRefManager is this node's registry of the Secrets and ConfigMaps its pods
// reference, and the only path through which the provider reads them: one GET
// by name, for a referenced object only. It is the kubelet's secret/configmap
// manager shape with the Get change-detection strategy: the projected-volume
// refresh tick re-reads each referenced object once per tick (coalesced by
// refreshCache) and no watch is ever opened. A change therefore reaches a
// running pod's volume within one tick plus a GET, where the kubelet's default
// Watch strategy is near-immediate.
//
// The reference set per pod is the upstream VisitPodSecretNames /
// VisitPodConfigmapNames set (visitPodSecretNames below). ServiceAccount token,
// downwardAPI, clusterTrustBundle and podCertificate projections are not
// Secret/ConfigMap references and are not registered; nor are transitive
// references (pod -> PVC -> PV -> Secret).
//
// Locking: mu guards byPod and refs, and nothing else. It is never held across
// an apiserver call, so a pod create or delete never queues behind a slow read
// or a refresh tick.
type podRefManager struct {
	cs  kubernetes.Interface
	clk clock.Clock
	log *slog.Logger

	mu sync.Mutex
	// byPod is each registered pod's reference set.
	byPod map[types.UID]map[sourceKey]struct{}
	// refs counts, per reference, the registered pods holding it.
	refs map[sourceKey]int
}

// newPodRefManager returns an empty manager reading through cs.
func newPodRefManager(cs kubernetes.Interface, clk clock.Clock, log *slog.Logger) *podRefManager {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &podRefManager{
		cs:    cs,
		clk:   clk,
		log:   log,
		byPod: map[types.UID]map[sourceKey]struct{}{},
		refs:  map[sourceKey]int{},
	}
}

var (
	_ objectReader           = (*podRefManager)(nil)
	_ vkadapter.ObjectGetter = (*podRefManager)(nil)
)

// podReferences returns the Secret and ConfigMap keys pod references.
func podReferences(pod *corev1.Pod) map[sourceKey]struct{} {
	set := map[sourceKey]struct{}{}
	visitPodSecretNames(pod, func(name string) bool {
		set[sourceKey{kind: kindSecret, namespace: pod.Namespace, name: name}] = struct{}{}
		return true
	})
	visitPodConfigMapNames(pod, func(name string) bool {
		set[sourceKey{kind: kindConfigMap, namespace: pod.Namespace, name: name}] = struct{}{}
		return true
	})
	return set
}

// RegisterPod records pod's references. A pod already registered under the
// same UID has its set REPLACED, so a spec change (an ephemeral container
// added later) re-registers through the same call. A nil manager does nothing.
func (m *podRefManager) RegisterPod(pod *corev1.Pod) {
	if m == nil || pod == nil {
		return
	}
	next := podReferences(pod)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dropLocked(pod.UID)
	m.byPod[pod.UID] = next
	for k := range next {
		m.refs[k]++
	}
}

// UnregisterPod drops pod uid's references; an object no other pod references
// is fetchable no more. A nil manager does nothing.
func (m *podRefManager) UnregisterPod(uid types.UID) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dropLocked(uid)
}

// dropLocked removes uid's set. Callers hold mu.
func (m *podRefManager) dropLocked(uid types.UID) {
	for k := range m.byPod[uid] {
		if m.refs[k]--; m.refs[k] <= 0 {
			delete(m.refs, k)
		}
	}
	delete(m.byPod, uid)
}

// referenced reports whether any registered pod references k.
func (m *podRefManager) referenced(k sourceKey) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.refs[k] > 0
}

// distinct returns D, the number of distinct objects referenced on this node:
// the GETs one refresh tick may cost.
func (m *podRefManager) distinct() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.refs)
}

// Secret implements vkadapter.ObjectGetter.
func (m *podRefManager) Secret(ctx context.Context, namespace, name string) (*corev1.Secret, error) {
	return m.secret(ctx, namespace, name)
}

// ConfigMap implements vkadapter.ObjectGetter.
func (m *podRefManager) ConfigMap(ctx context.Context, namespace, name string) (*corev1.ConfigMap, error) {
	return m.configMap(ctx, namespace, name)
}

func (m *podRefManager) secret(ctx context.Context, namespace, name string) (*corev1.Secret, error) {
	return fetchReferenced(ctx, m, sourceKey{kind: kindSecret, namespace: namespace, name: name},
		func(ctx context.Context, opts metav1.GetOptions) (*corev1.Secret, error) {
			return m.cs.CoreV1().Secrets(namespace).Get(ctx, name, opts)
		})
}

func (m *podRefManager) configMap(ctx context.Context, namespace, name string) (*corev1.ConfigMap, error) {
	return fetchReferenced(ctx, m, sourceKey{kind: kindConfigMap, namespace: namespace, name: name},
		func(ctx context.Context, opts metav1.GetOptions) (*corev1.ConfigMap, error) {
			return m.cs.CoreV1().ConfigMaps(namespace).Get(ctx, name, opts)
		})
}

// fetchReferenced is the one read path. An unreferenced key is errNotReferenced
// with no apiserver call. Inside a refresh tick the read is served from the
// apiserver's watch cache (resourceVersion "0") and is never retried: the next
// tick is the retry. On the create path a Forbidden is retried with backoff
// until the create's fetch budget runs out; a NotFound is never retried (it is
// the optional-source answer). Any other read is one consistent GET.
func fetchReferenced[T any](ctx context.Context, m *podRefManager, k sourceKey, get func(context.Context, metav1.GetOptions) (T, error)) (T, error) {
	var zero T
	if !m.referenced(k) {
		return zero, fmt.Errorf("%s %s/%s: %w", k.kind, k.namespace, k.name, errNotReferenced)
	}
	if inRefreshTick(ctx) {
		return get(ctx, metav1.GetOptions{ResourceVersion: "0"})
	}
	deadline, retry := createFetchDeadline(ctx)
	backoff := forbiddenBackoffStart
	for {
		obj, err := get(ctx, metav1.GetOptions{})
		if err == nil || !retry || !apierrors.IsForbidden(err) {
			return obj, err
		}
		remaining := deadline.Sub(m.clk.Now())
		if remaining <= 0 {
			return zero, fmt.Errorf("%s %s/%s still forbidden after the %s create budget: %w", k.kind, k.namespace, k.name, createFetchBudget, err)
		}
		m.log.Debug("by-name read forbidden on pod create; retrying", "kind", k.kind, "namespace", k.namespace, "name", k.name, "backoff", min(backoff, remaining))
		select {
		case <-ctx.Done():
			return zero, fmt.Errorf("%s %s/%s: %w (last error: %w)", k.kind, k.namespace, k.name, ctx.Err(), err)
		case <-m.clk.After(min(backoff, remaining)):
		}
		backoff = min(backoff*2, forbiddenBackoffMax)
		// The pod may have been deleted while this read waited.
		if !m.referenced(k) {
			return zero, fmt.Errorf("%s %s/%s: %w", k.kind, k.namespace, k.name, errNotReferenced)
		}
	}
}

// inRefreshTick reports whether ctx belongs to a projected-volume refresh
// tick, which binds a refreshCache on it.
func inRefreshTick(ctx context.Context) bool {
	c, ok := ctx.Value(refreshCacheKey{}).(*refreshCache)
	return ok && c != nil
}

// createFetchKey is the context key a CreatePod's fetch deadline is bound under.
type createFetchKey struct{}

// withCreateFetchBudget marks ctx as a pod create's and binds the deadline of
// its whole fetch phase: createFetchBudget from now, by m's clock. A nil
// manager returns ctx unchanged.
func (m *podRefManager) withCreateFetchBudget(ctx context.Context) context.Context {
	if m == nil {
		return ctx
	}
	return context.WithValue(ctx, createFetchKey{}, m.clk.Now().Add(createFetchBudget))
}

// createFetchDeadline returns the create deadline bound on ctx, if any.
func createFetchDeadline(ctx context.Context) (time.Time, bool) {
	d, ok := ctx.Value(createFetchKey{}).(time.Time)
	return d, ok
}

// podVisitor is called with each referenced object name and returns whether
// visiting should continue.
type podVisitor func(name string) (shouldContinue bool)

// skipEmptyNames wraps visitor so an empty name is skipped.
func skipEmptyNames(visitor podVisitor) podVisitor {
	return func(name string) bool {
		if len(name) == 0 {
			return true
		}
		return visitor(name)
	}
}

// visitAllContainers calls visitor with every init, regular and ephemeral
// container of spec, in that order, until it returns false.
func visitAllContainers(spec *corev1.PodSpec, visitor func(*corev1.Container) bool) bool {
	for i := range spec.InitContainers {
		if !visitor(&spec.InitContainers[i]) {
			return false
		}
	}
	for i := range spec.Containers {
		if !visitor(&spec.Containers[i]) {
			return false
		}
	}
	for i := range spec.EphemeralContainers {
		if !visitor((*corev1.Container)(&spec.EphemeralContainers[i].EphemeralContainerCommon)) {
			return false
		}
	}
	return true
}

// visitPodSecretNames is a line-for-line port of upstream
// k8s.io/kubernetes/pkg/api/v1/pod.VisitPodSecretNames (v1.36.2): every
// Secret a pod spec names, across imagePullSecrets, every container's env and
// envFrom (init, regular, ephemeral), and every volume plugin's secret
// reference including CSI nodePublishSecretRef and projected secret sources.
// k3sm does not import k8s.io/kubernetes, hence the copy. Volume types k3sm
// cannot mount stay rejected where they are; registering their names costs
// nothing and fetches nothing.
func visitPodSecretNames(pod *corev1.Pod, visitor podVisitor) bool {
	visitor = skipEmptyNames(visitor)
	for _, reference := range pod.Spec.ImagePullSecrets {
		if !visitor(reference.Name) {
			return false
		}
	}
	visitAllContainers(&pod.Spec, func(c *corev1.Container) bool {
		return visitContainerSecretNames(c, visitor)
	})
	var source *corev1.VolumeSource
	for i := range pod.Spec.Volumes {
		source = &pod.Spec.Volumes[i].VolumeSource
		switch {
		case source.AzureFile != nil:
			if len(source.AzureFile.SecretName) > 0 && !visitor(source.AzureFile.SecretName) {
				return false
			}
		case source.CephFS != nil:
			if source.CephFS.SecretRef != nil && !visitor(source.CephFS.SecretRef.Name) {
				return false
			}
		case source.Cinder != nil:
			if source.Cinder.SecretRef != nil && !visitor(source.Cinder.SecretRef.Name) {
				return false
			}
		case source.FlexVolume != nil:
			if source.FlexVolume.SecretRef != nil && !visitor(source.FlexVolume.SecretRef.Name) {
				return false
			}
		case source.Projected != nil:
			for j := range source.Projected.Sources {
				if source.Projected.Sources[j].Secret != nil {
					if !visitor(source.Projected.Sources[j].Secret.Name) {
						return false
					}
				}
			}
		case source.RBD != nil:
			if source.RBD.SecretRef != nil && !visitor(source.RBD.SecretRef.Name) {
				return false
			}
		case source.Secret != nil:
			if !visitor(source.Secret.SecretName) {
				return false
			}
		case source.ScaleIO != nil:
			if source.ScaleIO.SecretRef != nil && !visitor(source.ScaleIO.SecretRef.Name) {
				return false
			}
		case source.ISCSI != nil:
			if source.ISCSI.SecretRef != nil && !visitor(source.ISCSI.SecretRef.Name) {
				return false
			}
		case source.StorageOS != nil:
			if source.StorageOS.SecretRef != nil && !visitor(source.StorageOS.SecretRef.Name) {
				return false
			}
		case source.CSI != nil:
			if source.CSI.NodePublishSecretRef != nil && !visitor(source.CSI.NodePublishSecretRef.Name) {
				return false
			}
		}
	}
	return true
}

// visitContainerSecretNames is the upstream per-container half: envFrom
// secretRef and env valueFrom.secretKeyRef.
func visitContainerSecretNames(container *corev1.Container, visitor podVisitor) bool {
	for _, env := range container.EnvFrom {
		if env.SecretRef != nil {
			if !visitor(env.SecretRef.Name) {
				return false
			}
		}
	}
	for _, envVar := range container.Env {
		if envVar.ValueFrom != nil && envVar.ValueFrom.SecretKeyRef != nil {
			if !visitor(envVar.ValueFrom.SecretKeyRef.Name) {
				return false
			}
		}
	}
	return true
}

// visitPodConfigMapNames is a line-for-line port of upstream
// k8s.io/kubernetes/pkg/api/v1/pod.VisitPodConfigmapNames (v1.36.2): every
// ConfigMap named by any container's env or envFrom, a configMap volume, or a
// projected configMap source.
func visitPodConfigMapNames(pod *corev1.Pod, visitor podVisitor) bool {
	visitor = skipEmptyNames(visitor)
	visitAllContainers(&pod.Spec, func(c *corev1.Container) bool {
		return visitContainerConfigMapNames(c, visitor)
	})
	var source *corev1.VolumeSource
	for i := range pod.Spec.Volumes {
		source = &pod.Spec.Volumes[i].VolumeSource
		switch {
		case source.Projected != nil:
			for j := range source.Projected.Sources {
				if source.Projected.Sources[j].ConfigMap != nil {
					if !visitor(source.Projected.Sources[j].ConfigMap.Name) {
						return false
					}
				}
			}
		case source.ConfigMap != nil:
			if !visitor(source.ConfigMap.Name) {
				return false
			}
		}
	}
	return true
}

// visitContainerConfigMapNames is the upstream per-container half: envFrom
// configMapRef and env valueFrom.configMapKeyRef.
func visitContainerConfigMapNames(container *corev1.Container, visitor podVisitor) bool {
	for _, env := range container.EnvFrom {
		if env.ConfigMapRef != nil {
			if !visitor(env.ConfigMapRef.Name) {
				return false
			}
		}
	}
	for _, envVar := range container.Env {
		if envVar.ValueFrom != nil && envVar.ValueFrom.ConfigMapKeyRef != nil {
			if !visitor(envVar.ValueFrom.ConfigMapKeyRef.Name) {
				return false
			}
		}
	}
	return true
}
