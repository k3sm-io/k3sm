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

package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/darwin-net/pkg/proxy"

	"k3sm.io/k3sm/pkg/kubeclient"
	"k3sm.io/k3sm/pkg/provider"
)

// The published-vm-pod bind class (netdsvc.PortPolicy.VMPodPorts) needs one
// fact the root daemon cannot take from its requester: which addresses on this
// node are vm pods' published addresses, and which ports each is relayed on.
// The provider that feeds the Service proxy's relay runs in the unprivileged
// node process, and a set pushed from there over the netd socket would be the
// requester vouching for its own bind. So netd reads the same facts from the
// apiserver, where the provider published them: a vm pod's status.podIP is the
// /32 the provider's transport feed keys the relay on, its declared TCP ports are
// provider.DeclaredTCPPorts (the one function the feed uses), and the
// Service-targeted ports are the EndpointSlices the node's proxy routes on.
//
// The pods are read with the credential netd already holds for the Service set.
// On a worker that is the node's own identity, which the Node authorizer lets
// list pods only with a spec.nodeName=<self> field selector, so the informer is
// scoped to the node named in the client certificate; on a server it is the
// admin credential and the list is cluster-wide, bounded afterwards by the node
// pod /24 the authorizer checks first. EndpointSlices are readable by every node
// through the node-datapath ClusterRole the Service proxy already relies on, so
// this adds no RBAC.
//
// COST. Both caches are indexed by address (status.podIP for pods, every
// endpoint address for slices), so one authorization reads only the objects
// that name the requested address, never the whole cache; and cached pods are
// trimmed (trimPodForRelay) to the fields the predicate reads, so the root
// daemon does not hold every pod's full spec on a server's cluster-wide list.

// vmPodSetSyncTimeout bounds one attempt's wait for the initial Pods and
// EndpointSlices cache sync, as serviceInformerSyncTimeout does for Services.
const vmPodSetSyncTimeout = 10 * time.Second

// The informer index names: a pod by its status.podIP, a slice by every
// endpoint address it carries. One lookup is one map read.
const (
	podIPIndex     = "status.podIP"
	sliceAddrIndex = "endpoints.addresses"
)

// vmPodSet holds the indexers the published-vm-pod predicate reads. Both are
// nil until activation syncs them, and ports answers nil (deny) until then.
type vmPodSet struct {
	mu     sync.RWMutex
	pods   cache.Indexer
	slices cache.Indexer
}

// install hands the synced indexers over.
func (s *vmPodSet) install(pods, eps cache.Indexer) {
	s.mu.Lock()
	s.pods, s.slices = pods, eps
	s.mu.Unlock()
}

// ports is the netdsvc VMPodPorts predicate over the synced caches: it reads the
// pods and slices indexed under addr only.
func (s *vmPodSet) ports(addr netip.Addr) []uint16 {
	s.mu.RLock()
	pi, si := s.pods, s.slices
	s.mu.RUnlock()
	if pi == nil || si == nil {
		return nil
	}
	key := addr.Unmap().String()
	rawPods, err := pi.ByIndex(podIPIndex, key)
	if err != nil {
		return nil
	}
	rawSlices, err := si.ByIndex(sliceAddrIndex, key)
	if err != nil {
		return nil
	}
	pods := make([]*corev1.Pod, 0, len(rawPods))
	for _, o := range rawPods {
		if p, ok := o.(*corev1.Pod); ok {
			pods = append(pods, p)
		}
	}
	eps := make([]*discoveryv1.EndpointSlice, 0, len(rawSlices))
	for _, o := range rawSlices {
		if e, ok := o.(*discoveryv1.EndpointSlice); ok {
			eps = append(eps, e)
		}
	}
	return vmPodRelayPorts(pods, eps, addr)
}

// buildVMPodSet returns the VMPodPorts predicate and starts its activation in
// the background, the way buildServiceSet does: netd serves before the server
// writes its kubeconfig, so the set starts empty (deny) and fills once the
// informers sync. With no kubeconfig the predicate is nil and the class denies.
func buildVMPodSet(ctx context.Context, kubeconfig string, logger *slog.Logger) func(netip.Addr) []uint16 {
	if kubeconfig == "" {
		return nil
	}
	set := &vmPodSet{}
	go activateVMPodSet(ctx, kubeconfig, logger, set.install)
	return set.ports
}

// activateVMPodSet retries startVMPodInformers until it syncs or ctx ends. A
// failure stays at Debug except a 403, which is an RBAC fact rather than the
// boot race and is warned once per distinct error: until it clears, a vm pod's
// privileged relay ports stay refused while every other netd verb works.
func activateVMPodSet(ctx context.Context, kubeconfig string, logger *slog.Logger, install func(pods, eps cache.Indexer)) {
	const retry = 2 * time.Second
	lastWarned := ""
	for {
		if ctx.Err() != nil {
			return
		}
		pods, eps, err := startVMPodInformers(ctx, kubeconfig)
		if err == nil {
			install(pods, eps)
			logger.Info("vm pod set ready: privileged (<1024) relay binds on published vm pod addresses now authorized against this node's pods",
				"kubeconfig", kubeconfig)
			return
		}
		if apierrors.IsForbidden(err) && err.Error() != lastWarned {
			lastWarned = err.Error()
			logger.Warn("vm pod set cannot start: the apiserver refused netd's credential access to pods or EndpointSlices (403 Forbidden); privileged relay ports on vm pod addresses stay refused",
				"kubeconfig", kubeconfig)
		} else {
			logger.Debug("vm pod set not ready; privileged relay binds on vm pod addresses denied until it is",
				"kubeconfig", kubeconfig, "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(retry):
		}
	}
}

// startVMPodInformers loads kubeconfig and hands off to runVMPodInformers, with
// the pods scoped to the node the credential names, if it names one.
func startVMPodInformers(ctx context.Context, kubeconfig string) (pods, eps cache.Indexer, err error) {
	if _, err := os.Stat(kubeconfig); err != nil {
		return nil, nil, fmt.Errorf("stat kubeconfig: %w", kubeconfigUnusableError{err: err, missing: errors.Is(err, fs.ErrNotExist)})
	}
	cfg, cs, err := kubeclient.FromPath(kubeconfig)
	if err != nil {
		return nil, nil, fmt.Errorf("load kubeconfig: %w", kubeconfigUnusableError{err: err})
	}
	node, err := credentialNodeName(cfg)
	if err != nil {
		return nil, nil, err
	}
	return runVMPodInformers(ctx, cs, node, vmPodSetSyncTimeout)
}

// credentialNodeName returns the node a client certificate authenticates as
// (the name after "system:node:" in its CommonName), or "" for a credential
// that is not a node's (the server's admin kubeconfig, a token).
func credentialNodeName(cfg *rest.Config) (string, error) {
	data := cfg.TLSClientConfig.CertData
	if len(data) == 0 && cfg.TLSClientConfig.CertFile != "" {
		b, err := os.ReadFile(cfg.TLSClientConfig.CertFile)
		if err != nil {
			return "", fmt.Errorf("read client certificate: %w", kubeconfigUnusableError{err: err})
		}
		data = b
	}
	if len(data) == 0 {
		return "", nil
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse client certificate: %w", kubeconfigUnusableError{err: err})
	}
	name, ok := strings.CutPrefix(cert.Subject.CommonName, "system:node:")
	if !ok {
		return "", nil
	}
	return name, nil
}

// indexPodByIP indexes a pod under its status.podIP (canonical form).
func indexPodByIP(obj any) ([]string, error) {
	p, ok := obj.(*corev1.Pod)
	if !ok {
		return nil, nil
	}
	ip, err := netip.ParseAddr(p.Status.PodIP)
	if err != nil {
		return nil, nil
	}
	return []string{ip.Unmap().String()}, nil
}

// indexSliceByAddress indexes a slice under every endpoint address it carries
// (canonical form, de-duplicated).
func indexSliceByAddress(obj any) ([]string, error) {
	s, ok := obj.(*discoveryv1.EndpointSlice)
	if !ok {
		return nil, nil
	}
	var keys []string
	for _, ep := range s.Endpoints {
		for _, a := range ep.Addresses {
			if ip, err := netip.ParseAddr(a); err == nil {
				keys = append(keys, ip.Unmap().String())
			}
		}
	}
	slices.Sort(keys)
	return slices.Compact(keys), nil
}

// trimPodForRelay is the Pods informer's transform: it keeps only what
// vmPodRelayPorts reads (identity, deletion, hostNetwork, runtimeClassName, each
// container's ports and restart policy, phase and podIP), so a cluster-wide list
// on a server costs the root daemon a few hundred bytes per pod, not the full
// object. A non-pod passes through untouched.
func trimPodForRelay(obj any) (any, error) {
	p, ok := obj.(*corev1.Pod)
	if !ok {
		return obj, nil
	}
	trimC := func(cs []corev1.Container) []corev1.Container {
		if len(cs) == 0 {
			return nil
		}
		out := make([]corev1.Container, len(cs))
		for i := range cs {
			out[i] = corev1.Container{Name: cs[i].Name, Ports: cs[i].Ports, RestartPolicy: cs[i].RestartPolicy}
		}
		return out
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         p.Namespace,
			Name:              p.Name,
			UID:               p.UID,
			ResourceVersion:   p.ResourceVersion,
			DeletionTimestamp: p.DeletionTimestamp,
		},
		Spec: corev1.PodSpec{
			NodeName:         p.Spec.NodeName,
			HostNetwork:      p.Spec.HostNetwork,
			RuntimeClassName: p.Spec.RuntimeClassName,
			Containers:       trimC(p.Spec.Containers),
			InitContainers:   trimC(p.Spec.InitContainers),
		},
		Status: corev1.PodStatus{Phase: p.Status.Phase, PodIP: p.Status.PodIP},
	}, nil
}

// runVMPodInformers starts the Pods and EndpointSlices informers and blocks on
// their initial sync, tearing a failed attempt down entirely (the
// runServiceInformer discipline: a retry must not stack reflectors). node, when
// set, scopes the Pods list to spec.nodeName=node.
func runVMPodInformers(ctx context.Context, cs kubernetes.Interface, node string, syncTimeout time.Duration) (pods, eps cache.Indexer, err error) {
	podFactory := informers.NewSharedInformerFactoryWithOptions(cs, 30*time.Second,
		informers.WithTweakListOptions(func(o *metav1.ListOptions) {
			if node != "" {
				o.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", node).String()
			}
		}))
	sliceFactory := informers.NewSharedInformerFactory(cs, 30*time.Second)
	podInformer := podFactory.Core().V1().Pods().Informer()
	sliceInformer := sliceFactory.Discovery().V1().EndpointSlices().Informer()

	runCtx, cancel := context.WithCancel(ctx)
	keep := false
	defer func() {
		if keep {
			return
		}
		cancel()
		podFactory.Shutdown()
		sliceFactory.Shutdown()
	}()

	if err := podInformer.SetTransform(trimPodForRelay); err != nil {
		return nil, nil, fmt.Errorf("set the pod informer's transform: %w", err)
	}
	if err := podInformer.AddIndexers(cache.Indexers{podIPIndex: indexPodByIP}); err != nil {
		return nil, nil, fmt.Errorf("index pods by address: %w", err)
	}
	if err := sliceInformer.AddIndexers(cache.Indexers{sliceAddrIndex: indexSliceByAddress}); err != nil {
		return nil, nil, fmt.Errorf("index EndpointSlices by address: %w", err)
	}

	var (
		lastMu  sync.Mutex
		lastErr error
	)
	handler := func(ctx context.Context, r *cache.Reflector, err error) {
		lastMu.Lock()
		lastErr = err
		lastMu.Unlock()
		cache.DefaultWatchErrorHandler(ctx, r, err)
	}
	for _, inf := range []cache.SharedIndexInformer{podInformer, sliceInformer} {
		if err := inf.SetWatchErrorHandlerWithContext(handler); err != nil {
			return nil, nil, fmt.Errorf("set the vm pod set's watch error handler: %w", err)
		}
	}

	podFactory.Start(runCtx.Done())
	sliceFactory.Start(runCtx.Done())
	syncCtx, cancelSync := context.WithTimeout(runCtx, syncTimeout)
	defer cancelSync()
	if !cache.WaitForCacheSync(syncCtx.Done(), podInformer.HasSynced, sliceInformer.HasSynced) {
		lastMu.Lock()
		cause := lastErr
		lastMu.Unlock()
		if cause != nil {
			return nil, nil, fmt.Errorf("pod and EndpointSlice caches did not sync within %s: %w", syncTimeout, cause)
		}
		return nil, nil, fmt.Errorf("pod and EndpointSlice caches did not sync within %s", syncTimeout)
	}
	keep = true
	return podInformer.GetIndexer(), sliceInformer.GetIndexer(), nil
}

// vmPodRelayPorts is the published-vm-pod predicate: when exactly one live,
// non-hostNetwork pod publishes addr as its status.podIP and that pod resolves
// to the vm backend, it returns that pod's declared TCP ports
// (provider.DeclaredTCPPorts) together with every TCP port an IPv4
// EndpointSlice in the pod's own namespace targets at that pod by UID, sorted
// and de-duplicated. Every other case answers nil, which the authorizer reads as
// "not a published vm pod address": no pod, a native pod, a terminal or
// terminating pod, two live pods claiming one address (a stale view the daemon
// must not guess through), or a port set over the relay's per-pod ceiling
// (proxy.MaxRelayPorts), which the relay refuses to serve at all and so the
// daemon must not authorize any part of.
func vmPodRelayPorts(pods []*corev1.Pod, eps []*discoveryv1.EndpointSlice, addr netip.Addr) []uint16 {
	addr = addr.Unmap()
	var owner *corev1.Pod
	for _, p := range pods {
		if !podPublishes(p, addr) {
			continue
		}
		if owner != nil {
			return nil
		}
		owner = p
	}
	if owner == nil || !podIsVMBacked(owner) {
		return nil
	}
	ports := provider.DeclaredTCPPorts(owner)
	for _, s := range eps {
		if s.AddressType != discoveryv1.AddressTypeIPv4 || s.Namespace != owner.Namespace {
			continue
		}
		for _, ep := range s.Endpoints {
			if !endpointTargets(ep, addr, owner) {
				continue
			}
			for _, sp := range s.Ports {
				if sp.Port == nil || *sp.Port < 1 || *sp.Port > 65535 {
					continue
				}
				if sp.Protocol != nil && *sp.Protocol != corev1.ProtocolTCP {
					continue
				}
				ports = append(ports, uint16(*sp.Port))
			}
		}
	}
	slices.Sort(ports)
	ports = slices.Compact(ports)
	if len(ports) > proxy.MaxRelayPorts {
		return nil
	}
	return ports
}

// podPublishes reports whether p is a live, not-terminating pod-network pod
// whose status.podIP is addr. A pod with a DeletionTimestamp is never an owner:
// its address is on its way out, and a relay bind authorized now would outlive it.
func podPublishes(p *corev1.Pod, addr netip.Addr) bool {
	if p.DeletionTimestamp != nil || p.Spec.HostNetwork ||
		p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
		return false
	}
	ip, err := netip.ParseAddr(p.Status.PodIP)
	return err == nil && ip.Unmap() == addr
}

// podIsVMBacked resolves p's runtimeClassName through the same handler table
// the provider uses to pick the sandbox backend.
func podIsVMBacked(p *corev1.Pod) bool {
	var handler runtimev1.HandlerName
	if p.Spec.RuntimeClassName != nil {
		handler = runtimev1.HandlerName(*p.Spec.RuntimeClassName)
	}
	backend, err := runtimev1.DefaultHandlerConfig().Backend(handler)
	return err == nil && backend == runtimev1.SandboxBackend_SANDBOX_BACKEND_VM
}

// endpointTargets reports whether ep vouches for owner at addr. It does only
// when its TargetRef is a Pod reference carrying owner's UID AND it lists addr.
// A nil ref, a non-Pod kind or an empty UID never falls through to the address
// match: a selector-less Service's hand-written EndpointSlice can name any /32,
// and a slice written by whoever may create EndpointSlices must not authorize a
// root-brokered bind on another pod's address. (The caller has already required
// the slice to be in owner's namespace.)
func endpointTargets(ep discoveryv1.Endpoint, addr netip.Addr, owner *corev1.Pod) bool {
	ref := ep.TargetRef
	if ref == nil || ref.Kind != "Pod" || ref.UID == "" || ref.UID != owner.UID {
		return false
	}
	for _, a := range ep.Addresses {
		if ip, err := netip.ParseAddr(a); err == nil && ip.Unmap() == addr {
			return true
		}
	}
	return false
}
