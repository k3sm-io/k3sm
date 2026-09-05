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
	"fmt"
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
	// NaiveNodeProvider is VK's node provider that accepts pushed status updates
	// (UpdateStatus). A k3sm node provider embeds one rather than reimplementing the
	// notify plumbing.
	NaiveNodeProvider = vknode.NaiveNodeProviderV2
	// AttachIO is the exec/attach stdio+resize stream VK hands the streaming verbs.
	AttachIO = api.AttachIO
	// ContainerLogOpts is the kubectl-logs options (tail, follow, …) VK passes through.
	ContainerLogOpts = api.ContainerLogOpts
	// TermSize is a tty resize event delivered over an AttachIO Resize channel.
	TermSize = api.TermSize
)

// NewNaiveNodeProvider returns a NaiveNodeProvider ready to accept UpdateStatus
// calls. It MUST be built through this constructor: the zero value has no notify
// channel, so UpdateStatus on it blocks forever.
func NewNaiveNodeProvider() *NaiveNodeProvider { return vknode.NewNaiveNodeProvider() }

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
	// provider routes (logs/exec/attach/port-forward); nil is the plain-HTTP path
	// with no provider routes.
	//
	// When it is set it MUST require and verify a client certificate
	// (tls.RequireAndVerifyClientCert against a non-nil ClientCAs) — NewNode refuses
	// otherwise. See validateProviderRouteAuth.
	TLSConfig *tls.Config
	// AuthorizeHandler wraps the provider-route handler with the kubelet endpoint's
	// authorization predicate (provider.KubeletEndpointAuth.Handler). It is REQUIRED
	// whenever TLSConfig is set and ignored otherwise, because the only wiring that
	// serves the routes is the TLS one.
	AuthorizeHandler func(http.Handler) http.Handler
	// ConfigureNode stamps the registering Node object (labels, capacity, taints)
	// at bring-up. It runs inside VK's provider-bootstrap callback.
	ConfigureNode func(*corev1.Node)
	// NodeProvider, when non-nil, builds the node-status/heartbeat provider from the
	// registering Node object — called AFTER ConfigureNode has stamped it, so the
	// builder sees the node exactly as it will be registered and can copy the fields
	// it must preserve.
	//
	// Leaving it nil selects VK's NaiveNodeProvider (auto-Ready + lease heartbeat)
	// and, with it, VK's built-in ready callback. Supplying one REPLACES that
	// callback entirely: VK constructs it only for a nil node provider, so a
	// non-nil provider owns the Ready condition outright and must publish it.
	NodeProvider func(*corev1.Node) (NodeProvider, error)
}

// NewNode builds a Virtual Kubelet node from a NodeConfig, encapsulating the
// nodeutil node-builder dance (NodeConfig options + NewNode + the nil-NodeProvider
// → NewNaiveNodeProvider auto-Ready+lease-heartbeat path) so callers import no VK.
//
// The kubelet HTTP API (logs/exec) only serves when cfg.TLSConfig is non-nil: a
// mux with the provider routes is then wired behind cfg.AuthorizeHandler and
// instrumented. Both fields are required together — see validateProviderRouteAuth,
// which refuses to build a node whose routes would answer to anything that can
// reach the port.
func NewNode(nodeName string, cfg NodeConfig) (*Node, error) {
	// Fast-fail on a nil ConfigureNode: it is invoked inside VK's node-bootstrap
	// callback (a goroutine during bring-up), so a nil field would panic at startup
	// rather than surface as this constructor's error.
	if cfg.ConfigureNode == nil {
		return nil, errors.New("vkadapter: NodeConfig.ConfigureNode is required")
	}
	mux := http.NewServeMux()
	// providerRoutesEnabled is the SINGLE, security-load-bearing gate: the kubelet
	// HTTP provider routes (logs/exec/attach/port-forward) are served — mutually
	// authenticated and instrumented — ONLY when TLS is configured, so exec/attach
	// never rides plain HTTP. Both wiring branches below MUST consult this predicate
	// in lockstep so a future edit cannot expose exec on the plain-HTTP path.
	routes := providerRoutesEnabled(cfg)
	// And when they ARE served, they are served authenticated: refuse to build the
	// node at all rather than serve exec to whoever can reach the port.
	if routes {
		if err := validateProviderRouteAuth(cfg); err != nil {
			return nil, err
		}
	}
	nodeOpts := []nodeutil.NodeOpt{
		func(c *nodeutil.NodeConfig) error {
			c.Client = cfg.Client
			c.HTTPListenAddr = cfg.HTTPListenAddr
			c.NumWorkers = cfg.NumWorkers
			c.TLSConfig = cfg.TLSConfig // nil = plain HTTP; set = kubelet-serving TLS
			// k3sm resolves downward-API env in the provider itself (env.go
			// resolveDownwardEnv), AFTER the pod's /32 is allocated so status.podIP
			// carries the real IP. VK v1.12.0's own PopulateEnvironmentVariables runs
			// BEFORE CreatePod and hard-errors on status.podIP ("unsupported
			// fieldPath"), stranding such a pod Pending before it ever reaches the
			// provider — so skip VK's resolution and let the provider own it.
			c.SkipDownwardAPIResolution = true
			if routes {
				c.Handler = api.InstrumentHandler(cfg.AuthorizeHandler(mux))
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
			if cfg.NodeProvider == nil {
				return cfg.Provider, nil, nil // nil NodeProvider -> NewNaiveNodeProvider (auto-Ready + lease heartbeat)
			}
			np, err := cfg.NodeProvider(pc.Node)
			if err != nil {
				return nil, nil, err
			}
			return cfg.Provider, np, nil
		},
		nodeOpts...,
	)
}

// providerRoutesEnabled reports whether NewNode serves the kubelet HTTP provider
// routes (logs/exec/attach/port-forward). It is TRUE only when TLS is configured,
// so the interactive exec/attach surface — which reaches the root-owned runtime —
// is never exposed on the plain-HTTP path. This is the invariant the security
// regression test pins; keep NewNode's two wiring branches routed through it.
func providerRoutesEnabled(cfg NodeConfig) bool { return cfg.TLSConfig != nil }

// validateProviderRouteAuth is the fail-closed structural gate on the kubelet
// endpoint's authentication: when the provider routes are served, the listener
// must demand a verified client certificate AND an authorization predicate must
// be wrapped around them. A NodeConfig that satisfies neither is a construction
// ERROR, not a degraded mode.
//
// It is stated here, in the one constructor, rather than trusted to each caller,
// because the earlier posture — nodeutil.NoAuth() over a tls.NoClientCert
// listener — was reachable by simply not thinking about it: every field involved
// had a usable zero value. Requiring the three facts together means a regression
// on ANY of them (an authorizer dropped, ClientAuth relaxed back to NoClientCert
// or RequestClientCert, a nil CA pool) refuses to start the node instead of
// quietly re-opening exec to the LAN.
func validateProviderRouteAuth(cfg NodeConfig) error {
	if cfg.AuthorizeHandler == nil {
		return errors.New("vkadapter: NodeConfig.AuthorizeHandler is required when TLSConfig is set (the kubelet provider routes — logs/exec/attach/port-forward — are never served unauthorized)")
	}
	if cfg.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		return fmt.Errorf("vkadapter: NodeConfig.TLSConfig.ClientAuth is %v, want tls.RequireAndVerifyClientCert (the kubelet endpoint authenticates the apiserver by client certificate)", cfg.TLSConfig.ClientAuth)
	}
	if cfg.TLSConfig.ClientCAs == nil {
		return errors.New("vkadapter: NodeConfig.TLSConfig.ClientCAs is nil, so no client certificate could verify (the kubelet endpoint anchors on the cluster's client-identity CA)")
	}
	return nil
}
