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

// Package vkadapter is the SINGLE seam through which k3sm touches the
// github.com/virtual-kubelet/virtual-kubelet module. Every other package in this
// repo imports vkadapter, never virtual-kubelet directly, so the VK coupling is
// confined to one file and one edit site (enforced by
// provider.TestVKImportsConfinedToAdapter). See docs/vk-exit.md for the ceiling
// this achieves (import-confinement) and what a true VK swap still costs.
//
// The re-exports are deliberately TYPE ALIASES (=), not fresh wrapper types: the
// VK type IDENTITY must be preserved. The provider's streaming verbs (exec/attach)
// hand VK's own AttachIO/ContainerLogOpts to the VK PodHandler over the kubelet
// HTTP API; a structurally-identical-but-distinct wrapper type would not satisfy
// that contract. Confinement here means "one import site", not "decoupled".
package vkadapter

import (
	"crypto/tls"
	"errors"
	"net/http"

	"github.com/virtual-kubelet/virtual-kubelet/errdefs"
	vknode "github.com/virtual-kubelet/virtual-kubelet/node"
	"github.com/virtual-kubelet/virtual-kubelet/node/api"
	"github.com/virtual-kubelet/virtual-kubelet/node/nodeutil"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// The VK provider/node contract types, re-exported as aliases so consumers name
// vkadapter.X in their signatures while keeping VK's exact type identity.
type (
	// Provider is the full Virtual Kubelet provider contract (pod lifecycle, logs,
	// exec/attach/port-forward, stats/metrics) the VK node drives.
	Provider = nodeutil.Provider
	// ProviderConfig holds the listers/Node object VK hands a provider at bootstrap.
	ProviderConfig = nodeutil.ProviderConfig
	// Node is a running Virtual Kubelet node (its lifecycle: Run, Ready).
	Node = nodeutil.Node
	// PodLifecycleHandler is the create/update/delete/get pod contract.
	PodLifecycleHandler = vknode.PodLifecycleHandler
	// PodNotifier is the async pod-status callback registration contract.
	PodNotifier = vknode.PodNotifier
	// NodeProvider is the node-status/heartbeat contract (nil ⇒ NaiveNodeProvider).
	NodeProvider = vknode.NodeProvider
	// AttachIO is the exec/attach stdio+resize stream VK hands the streaming verbs.
	AttachIO = api.AttachIO
	// ContainerLogOpts is the kubectl-logs options (tail, follow, …) VK passes through.
	ContainerLogOpts = api.ContainerLogOpts
	// TermSize is a tty resize event delivered over an AttachIO Resize channel.
	TermSize = api.TermSize
)

// NotFound returns VK's own not-found error carrying msg. It MUST delegate to
// errdefs so the returned value implements the errdefs NotFound() bool interface —
// VK's PodController reconcile keys "pod is gone" detection on errdefs.IsNotFound,
// so a k3sm-local sentinel or fmt.Errorf substitute would silently break it.
func NotFound(msg string) error { return errdefs.NotFound(msg) }

// NotFoundf returns VK's own not-found error, formatted. See NotFound.
func NotFoundf(format string, args ...any) error { return errdefs.NotFoundf(format, args...) }

// IsNotFound reports whether err (or anything it wraps) is VK's not-found error,
// via the errdefs NotFound() bool interface. It is the exact predicate VK's own
// reconcile loop uses, so provider code and VK agree on "gone".
func IsNotFound(err error) bool { return errdefs.IsNotFound(err) }

// NodeConfig is the k3sm-shaped input to NewNode. It captures exactly the wiring
// the node command previously inlined against nodeutil: the apiserver client, the
// provider, the kubelet HTTP API listen/worker settings, an optional serving-TLS
// config, and a callback that stamps the registering Node object.
type NodeConfig struct {
	// Client is the apiserver client the VK node registers and syncs through.
	Client kubernetes.Interface
	// Provider is the pod-execution provider the node drives.
	Provider Provider
	// HTTPListenAddr is the address the kubelet HTTP API (logs/exec) listens on.
	HTTPListenAddr string
	// NumWorkers is the pod controller worker count.
	NumWorkers int
	// TLSConfig, when non-nil, serves the kubelet HTTP API over TLS AND attaches the
	// provider routes (logs/exec/attach/port-forward) behind NoAuth; nil is the
	// plain-HTTP path with no provider routes (the M0 posture).
	TLSConfig *tls.Config
	// ConfigureNode stamps the registering Node object (labels, capacity, taints)
	// at bring-up. It runs inside VK's provider-bootstrap callback.
	ConfigureNode func(*corev1.Node)
}

// NewNode builds a Virtual Kubelet node from a NodeConfig, encapsulating the
// nodeutil node-builder dance (NodeConfig options + NewNode + the nil-NodeProvider
// → NewNaiveNodeProvider auto-Ready+lease-heartbeat path) so callers import no VK.
//
// The kubelet HTTP API (logs/exec) only serves when BOTH a TLS config and a
// handler are set: when cfg.TLSConfig is non-nil a mux with the provider routes is
// wired behind NoAuth and instrumented, matching the pre-confinement behavior
// byte-for-byte.
func NewNode(nodeName string, cfg NodeConfig) (*Node, error) {
	// Fast-fail on a nil ConfigureNode: it is invoked inside VK's node-bootstrap
	// callback (a goroutine during bring-up), so a nil field would panic at startup
	// rather than surface as this constructor's error.
	if cfg.ConfigureNode == nil {
		return nil, errors.New("vkadapter: NodeConfig.ConfigureNode is required")
	}
	mux := http.NewServeMux()
	// providerRoutesEnabled is the SINGLE, security-load-bearing gate: the kubelet
	// HTTP provider routes (logs/exec/attach/port-forward) are served — behind
	// NoAuth (no client authn; identity rests on serving-TLS + network reach) and
	// instrumented — ONLY when TLS is configured, so exec/attach never rides plain
	// HTTP. Both wiring branches below MUST consult this predicate in lockstep so a
	// future edit cannot expose exec on the M0 plain-HTTP path.
	routes := providerRoutesEnabled(cfg)
	nodeOpts := []nodeutil.NodeOpt{
		func(c *nodeutil.NodeConfig) error {
			c.Client = cfg.Client
			c.HTTPListenAddr = cfg.HTTPListenAddr
			c.NumWorkers = cfg.NumWorkers
			c.TLSConfig = cfg.TLSConfig // nil = plain HTTP (M0 path); set = kubelet-serving TLS
			// k3sm resolves downward-API env in the provider itself (env.go
			// resolveDownwardEnv), AFTER the pod's /32 is allocated so status.podIP
			// carries the real IP. VK v1.12.0's own PopulateEnvironmentVariables runs
			// BEFORE CreatePod and hard-errors on status.podIP ("unsupported
			// fieldPath"), stranding such a pod Pending before it ever reaches the
			// provider — so skip VK's resolution and let the provider own it.
			c.SkipDownwardAPIResolution = true
			if routes {
				c.Handler = api.InstrumentHandler(nodeutil.WithAuth(nodeutil.NoAuth(), mux))
			}
			return nil
		},
	}
	if routes {
		nodeOpts = append(nodeOpts, nodeutil.AttachProviderRoutes(mux))
	}

	return nodeutil.NewNode(nodeName,
		func(pc nodeutil.ProviderConfig) (nodeutil.Provider, vknode.NodeProvider, error) {
			cfg.ConfigureNode(pc.Node)
			return cfg.Provider, nil, nil // nil NodeProvider -> NewNaiveNodeProvider (auto-Ready + lease heartbeat)
		},
		nodeOpts...,
	)
}

// providerRoutesEnabled reports whether NewNode serves the kubelet HTTP provider
// routes (logs/exec/attach/port-forward). It is TRUE only when TLS is configured,
// so the interactive exec/attach surface — which reaches the root-owned runtime —
// is never exposed on the plain-HTTP (M0) path. This is the invariant the security
// regression test pins; keep NewNode's two wiring branches routed through it.
func providerRoutesEnabled(cfg NodeConfig) bool { return cfg.TLSConfig != nil }
