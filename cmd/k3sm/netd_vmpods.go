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
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	runtimev1 "k3sm.io/apis/runtime/v1"

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

// vmPodSetSyncTimeout bounds one attempt's wait for the initial Pods and
// EndpointSlices cache sync, as serviceInformerSyncTimeout does for Services.
const vmPodSetSyncTimeout = 10 * time.Second

// vmPodSet holds the listers the published-vm-pod predicate reads. Both are nil
// until activation syncs them, and ports answers nil (deny) until then.
type vmPodSet struct {
	mu     sync.RWMutex
	pods   corev1listers.PodLister
	slices discoverylisters.EndpointSliceLister
}

// install hands the synced listers over.
func (s *vmPodSet) install(pods corev1listers.PodLister, eps discoverylisters.EndpointSliceLister) {
	s.mu.Lock()
	s.pods, s.slices = pods, eps
	s.mu.Unlock()
}

// ports is the netdsvc VMPodPorts predicate over the synced caches.
func (s *vmPodSet) ports(addr netip.Addr) []uint16 {
	s.mu.RLock()
	pl, el := s.pods, s.slices
	s.mu.RUnlock()
	if pl == nil || el == nil {
		return nil
	}
	pods, err := pl.List(labels.Everything())
	if err != nil {
		return nil
	}
	eps, err := el.List(labels.Everything())
	if err != nil {
		return nil
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
func activateVMPodSet(ctx context.Context, kubeconfig string, logger *slog.Logger, install func(corev1listers.PodLister, discoverylisters.EndpointSliceLister)) {
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
func startVMPodInformers(ctx context.Context, kubeconfig string) (corev1listers.PodLister, discoverylisters.EndpointSliceLister, error) {
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

// runVMPodInformers starts the Pods and EndpointSlices informers and blocks on
// their initial sync, tearing a failed attempt down entirely (the
// runServiceInformer discipline: a retry must not stack reflectors). node, when
// set, scopes the Pods list to spec.nodeName=node.
func runVMPodInformers(ctx context.Context, cs kubernetes.Interface, node string, syncTimeout time.Duration) (corev1listers.PodLister, discoverylisters.EndpointSliceLister, error) {
	podFactory := informers.NewSharedInformerFactoryWithOptions(cs, 30*time.Second,
		informers.WithTweakListOptions(func(o *metav1.ListOptions) {
			if node != "" {
				o.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", node).String()
			}
		}))
	sliceFactory := informers.NewSharedInformerFactory(cs, 30*time.Second)
	podInformer := podFactory.Core().V1().Pods().Informer()
	sliceInformer := sliceFactory.Discovery().V1().EndpointSlices().Informer()
	pods := podFactory.Core().V1().Pods().Lister()
	eps := sliceFactory.Discovery().V1().EndpointSlices().Lister()

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
	return pods, eps, nil
}

// vmPodRelayPorts is the published-vm-pod predicate: when exactly one live,
// non-hostNetwork pod publishes addr as its status.podIP and that pod resolves
// to the vm backend, it returns that pod's declared TCP ports
// (provider.DeclaredTCPPorts) together with every TCP port an IPv4
// EndpointSlice targets at addr for that pod, sorted and de-duplicated. Every
// other case answers nil, which the authorizer reads as "not a published vm pod
// address": no pod, a native pod, a terminal pod, or two live pods claiming one
// address (a stale view the daemon must not guess through).
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
		if s.AddressType != discoveryv1.AddressTypeIPv4 {
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
	return slices.Compact(ports)
}

// podPublishes reports whether p is a live pod-network pod whose status.podIP
// is addr.
func podPublishes(p *corev1.Pod, addr netip.Addr) bool {
	if p.Spec.HostNetwork || p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
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

// endpointTargets reports whether ep carries addr and, when it names a target
// pod, names owner: an endpoint left over for a pod that held the address before
// owner is not owner's Service port.
func endpointTargets(ep discoveryv1.Endpoint, addr netip.Addr, owner *corev1.Pod) bool {
	if ref := ep.TargetRef; ref != nil && ref.Kind == "Pod" && ref.UID != "" && ref.UID != owner.UID {
		return false
	}
	for _, a := range ep.Addresses {
		if ip, err := netip.ParseAddr(a); err == nil && ip.Unmap() == addr {
			return true
		}
	}
	return false
}
