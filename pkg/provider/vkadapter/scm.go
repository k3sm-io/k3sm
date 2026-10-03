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

package vkadapter

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	corev1informers "k8s.io/client-go/informers/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

// ObjectGetter reads one Secret or ConfigMap by namespace and name. It is the
// seam through which the node's Secret and ConfigMap listers answer: a node
// identity may read such an object only by name, and only for a pod bound to
// it, so the listers never list and never watch. The provider's pod-reference
// manager implements it.
type ObjectGetter interface {
	// Secret returns the named Secret.
	Secret(ctx context.Context, namespace, name string) (*corev1.Secret, error)
	// ConfigMap returns the named ConfigMap.
	ConfigMap(ctx context.Context, namespace, name string) (*corev1.ConfigMap, error)
}

var (
	// errListUnsupported is returned by every List on the node's Secret,
	// ConfigMap and Service listers.
	errListUnsupported = errors.New("vkadapter: listing is not supported on a node identity (objects are read by name only)")
	// errServiceReadUnsupported is returned by a by-name Get on the node's
	// Service lister: no k3sm path reads a Service through Virtual Kubelet.
	errServiceReadUnsupported = errors.New("vkadapter: reading a Service through the node's lister is not supported")
	// errNoObjectGetter is returned by a by-name Get when the node was built
	// without NodeConfig.Objects.
	errNoObjectGetter = errors.New("vkadapter: no ObjectGetter configured on this node (NodeConfig.Objects is nil)")
	// errNeverRun is what the placeholder informer's list/watch would return if
	// anything ever ran it. Nothing does: it is never registered with a factory.
	errNeverRun = errors.New("vkadapter: the node's Secret/ConfigMap/Service informers are never run")
)

// listerGetTimeout bounds one by-name read made through a lister. The lister
// contract carries no context, so this is where the read gets its deadline.
const listerGetTimeout = 30 * time.Second

// scmAdapters are the Secret, ConfigMap and Service informers the node hands
// Virtual Kubelet's PodController, which refuses nil ones. VK reads them only
// through its downward-API env resolution, which k3sm disables
// (SkipDownwardAPIResolution), so on k3sm's path nothing reads them at all.
// They exist so that the node assembly starts no cluster-wide informer, and so
// that a future VK that does read them gets a by-name answer or a loud error,
// never a list.
//
// informerCalls counts Informer() calls across the three; a VK that starts
// asking for the underlying informer shows up as a non-zero count in the
// adapter's canary test.
type scmAdapters struct {
	objects       ObjectGetter
	informerCalls atomic.Int64
}

// placeholderInformer returns a SharedIndexInformer that is never registered
// with any factory and never run. Its list/watch error if called.
func (s *scmAdapters) placeholderInformer(example runtime.Object) cache.SharedIndexInformer {
	s.informerCalls.Add(1)
	lw := &cache.ListWatch{
		ListWithContextFunc: func(context.Context, metav1.ListOptions) (runtime.Object, error) {
			return nil, errNeverRun
		},
		WatchFuncWithContext: func(context.Context, metav1.ListOptions) (watch.Interface, error) {
			return nil, errNeverRun
		},
	}
	return cache.NewSharedIndexInformer(lw, example, 0, cache.Indexers{})
}

// get runs one by-name read through the configured ObjectGetter.
func get[T any](s *scmAdapters, kind, namespace, name string, read func(ObjectGetter, context.Context, string, string) (T, error)) (T, error) {
	var zero T
	if s.objects == nil {
		return zero, fmt.Errorf("get %s %s/%s: %w", kind, namespace, name, errNoObjectGetter)
	}
	ctx, cancel := context.WithTimeout(context.Background(), listerGetTimeout)
	defer cancel()
	return read(s.objects, ctx, namespace, name)
}

// scopedSecretInformer is the node's SecretInformer. See scmAdapters.
type scopedSecretInformer struct{ s *scmAdapters }

var _ corev1informers.SecretInformer = scopedSecretInformer{}

func (i scopedSecretInformer) Informer() cache.SharedIndexInformer {
	return i.s.placeholderInformer(&corev1.Secret{})
}

func (i scopedSecretInformer) Lister() corev1listers.SecretLister { return secretLister(i) }

// secretLister answers Get by name through the ObjectGetter and refuses List.
type secretLister struct{ s *scmAdapters }

func (l secretLister) List(labels.Selector) ([]*corev1.Secret, error) { return nil, errListUnsupported }

func (l secretLister) Secrets(namespace string) corev1listers.SecretNamespaceLister {
	return secretNamespaceLister{s: l.s, namespace: namespace}
}

type secretNamespaceLister struct {
	s         *scmAdapters
	namespace string
}

func (l secretNamespaceLister) List(labels.Selector) ([]*corev1.Secret, error) {
	return nil, errListUnsupported
}

func (l secretNamespaceLister) Get(name string) (*corev1.Secret, error) {
	return get(l.s, "secret", l.namespace, name, ObjectGetter.Secret)
}

// scopedConfigMapInformer is the node's ConfigMapInformer. See scmAdapters.
type scopedConfigMapInformer struct{ s *scmAdapters }

var _ corev1informers.ConfigMapInformer = scopedConfigMapInformer{}

func (i scopedConfigMapInformer) Informer() cache.SharedIndexInformer {
	return i.s.placeholderInformer(&corev1.ConfigMap{})
}

func (i scopedConfigMapInformer) Lister() corev1listers.ConfigMapLister { return configMapLister(i) }

// configMapLister answers Get by name through the ObjectGetter and refuses List.
type configMapLister struct{ s *scmAdapters }

func (l configMapLister) List(labels.Selector) ([]*corev1.ConfigMap, error) {
	return nil, errListUnsupported
}

func (l configMapLister) ConfigMaps(namespace string) corev1listers.ConfigMapNamespaceLister {
	return configMapNamespaceLister{s: l.s, namespace: namespace}
}

type configMapNamespaceLister struct {
	s         *scmAdapters
	namespace string
}

func (l configMapNamespaceLister) List(labels.Selector) ([]*corev1.ConfigMap, error) {
	return nil, errListUnsupported
}

func (l configMapNamespaceLister) Get(name string) (*corev1.ConfigMap, error) {
	return get(l.s, "configmap", l.namespace, name, ObjectGetter.ConfigMap)
}

// scopedServiceInformer is the node's ServiceInformer. It exists only to
// satisfy VK's non-nil check: no k3sm path reads a Service through VK. Its
// lister refuses List and Get alike.
type scopedServiceInformer struct{ s *scmAdapters }

var _ corev1informers.ServiceInformer = scopedServiceInformer{}

func (i scopedServiceInformer) Informer() cache.SharedIndexInformer {
	return i.s.placeholderInformer(&corev1.Service{})
}

func (i scopedServiceInformer) Lister() corev1listers.ServiceLister { return serviceLister{} }

// serviceLister refuses every read.
type serviceLister struct{}

func (serviceLister) List(labels.Selector) ([]*corev1.Service, error) {
	return nil, errListUnsupported
}

func (serviceLister) Services(namespace string) corev1listers.ServiceNamespaceLister {
	return serviceNamespaceLister{namespace: namespace}
}

type serviceNamespaceLister struct{ namespace string }

func (serviceNamespaceLister) List(labels.Selector) ([]*corev1.Service, error) {
	return nil, errListUnsupported
}

func (l serviceNamespaceLister) Get(name string) (*corev1.Service, error) {
	return nil, fmt.Errorf("get service %s/%s: %w", l.namespace, name, errServiceReadUnsupported)
}
