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
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path"
	"time"

	vklog "github.com/virtual-kubelet/virtual-kubelet/log"
	vknode "github.com/virtual-kubelet/virtual-kubelet/node"
	"github.com/virtual-kubelet/virtual-kubelet/node/api"
	"github.com/virtual-kubelet/virtual-kubelet/node/nodeutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
)

// informerResyncPeriod is the pod informer's full-resync period, the value
// nodeutil.NewNode defaults InformerResyncPeriod to.
const informerResyncPeriod = time.Minute

// httpReadHeaderTimeout is the kubelet HTTP API server's ReadHeaderTimeout, as
// nodeutil sets it.
const httpReadHeaderTimeout = 30 * time.Second

// Node is a running k3sm node: Virtual Kubelet's node controller (registration,
// status, the Lease heartbeat) and pod controller (the pod reconcile loop),
// plus the kubelet HTTP API, assembled by NewNode and driven by Run.
//
// It replaces nodeutil.Node, whose builder registers cluster-wide Secret,
// ConfigMap and Service informers that cannot be switched off. The lifecycle
// below reproduces nodeutil v1.14.0's Node.Run step for step; only the informer
// set differs (one pod informer filtered to this node, and the scmAdapters).
//
// It must be built with NewNode and Run at most once.
type Node struct {
	nc *vknode.NodeController
	pc *vknode.PodController

	// readyCb runs once both controllers are ready and before Ready closes. It
	// is set only for a node built with a nil NodeProvider, where it marks the
	// node Ready through the naive node provider.
	readyCb func(context.Context) error

	ready chan struct{}

	podInformerFactory informers.SharedInformerFactory
	scm                *scmAdapters
	client             kubernetes.Interface

	listenAddr string
	h          http.Handler
	tlsConfig  *tls.Config
	// boundAddr is the kubelet HTTP API's listening address once Run has bound
	// it (nil when no listener is started). Written before ready closes, so a
	// reader that has received from Ready() may read it.
	boundAddr net.Addr

	workers int

	eb record.EventBroadcaster

	// vkLog is Virtual Kubelet's logger for this node; Run hands it to VK on
	// every context it passes down.
	vkLog *vkLogger
	// heartbeat records the node's last successful status post and Lease renewal.
	heartbeat *heartbeatRecorder
}

// Heartbeat returns when this node's status post and Lease renewal last
// succeeded. Safe to call from any goroutine.
func (n *Node) Heartbeat() Heartbeat { return n.heartbeat.snapshot() }

// Ready returns a channel that is closed once the node is ready: both
// controllers are running and, for a nil NodeProvider, the node was marked
// Ready.
func (n *Node) Ready() <-chan struct{} { return n.ready }

// Run starts the kubelet HTTP API, the pod informer and both controllers, and
// blocks until ctx ends or either controller exits. On return every controller
// has stopped: no controller writes to the apiserver after Run returns.
func (n *Node) Run(ctx context.Context) (retErr error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Every VK controller derives its context from this one, and VK reads its
	// logger from the context before falling back to the process default.
	ctx = vklog.WithLogger(ctx, n.vkLog)

	n.eb.StartLogging(vklog.G(ctx).Infof)
	n.eb.StartRecordingToSink(&corev1client.EventSinkImpl{Interface: n.client.CoreV1().Events(corev1.NamespaceAll)})
	defer n.eb.Shutdown()

	cancelHTTP, err := n.runHTTP(ctx)
	if err != nil {
		return err
	}
	defer cancelHTTP()

	go n.podInformerFactory.Start(ctx.Done())
	// The controllers' errors are read through Err after Done, below.
	go func() { _ = n.pc.Run(ctx, n.workers) }()

	defer func() {
		cancel()
		<-n.pc.Done()
	}()

	select {
	case <-ctx.Done():
		// nodeutil returns its (still nil) recorded error here, not ctx.Err();
		// kept as is so a caller sees the same result it always has.
		return nil
	case <-n.pc.Ready():
	case <-n.pc.Done():
		return n.pc.Err()
	}

	go func() { _ = n.nc.Run(ctx) }()

	defer func() {
		cancel()
		<-n.nc.Done()
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-n.nc.Ready():
	case <-n.nc.Done():
		return n.nc.Err()
	}

	if n.readyCb != nil {
		if err := n.readyCb(ctx); err != nil {
			return err
		}
	}
	close(n.ready)

	select {
	case <-n.nc.Done():
		cancel()
		return n.nc.Err()
	case <-n.pc.Done():
		cancel()
		return n.pc.Err()
	}
}

// runHTTP serves the kubelet HTTP API over TLS when the node has both a TLS
// config and a handler, and returns the function that stops it.
func (n *Node) runHTTP(ctx context.Context) (func(), error) {
	if n.tlsConfig == nil {
		vklog.G(ctx).Warn("TLS config not provided, not starting up http service")
		return func() {}, nil
	}
	if n.h == nil {
		vklog.G(ctx).Debug("No http handler, not starting up http service")
		return func() {}, nil
	}
	l, err := tls.Listen("tcp", n.listenAddr, n.tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("error starting http listener: %w", err)
	}
	n.boundAddr = l.Addr()
	srv := &http.Server{Handler: n.h, TLSConfig: n.tlsConfig, ReadHeaderTimeout: httpReadHeaderTimeout}
	// Serve returns ErrServerClosed on the Close below; nothing else ends it.
	go func() { _ = srv.Serve(l) }()
	return func() {
		_ = srv.Close() // best-effort shutdown; the listener close below is the backstop
		_ = l.Close()
	}, nil
}

// defaultNodeSpec is the Node object a node starts from before ConfigureNode
// stamps it, verbatim from nodeutil.NewNode v1.14.0.
func defaultNodeSpec(name string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"type":                   "virtual-kubelet",
				"kubernetes.io/role":     "agent",
				"kubernetes.io/hostname": name,
			},
		},
		Status: corev1.NodeStatus{
			Phase: corev1.NodePending,
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady},
				{Type: corev1.NodeDiskPressure},
				{Type: corev1.NodeMemoryPressure},
				{Type: corev1.NodePIDPressure},
				{Type: corev1.NodeNetworkUnavailable},
			},
		},
	}
}

// setNodeReady marks n Running and its Ready condition True, verbatim from
// nodeutil v1.14.0.
func setNodeReady(n *corev1.Node) {
	n.Status.Phase = corev1.NodeRunning
	for i, c := range n.Status.Conditions {
		if c.Type != "Ready" {
			continue
		}
		c.Message = "Kubelet is ready"
		c.Reason = "KubeletReady"
		c.Status = corev1.ConditionTrue
		c.LastHeartbeatTime = metav1.Now()
		c.LastTransitionTime = metav1.Now()
		n.Status.Conditions[i] = c
		return
	}
}

// NewNode builds a k3sm node from a NodeConfig, assembling it from Virtual
// Kubelet's node package constructors so callers import no VK.
//
// It starts exactly one informer: pods, filtered to spec.nodeName=<nodeName>.
// The Secret, ConfigMap and Service informers VK's PodController requires are
// the scmAdapters, which never list and never watch; a by-name read through
// them goes to cfg.Objects.
//
// The kubelet HTTP API (logs/exec) only serves when cfg.TLSConfig is non-nil: a
// mux with the provider routes is then wired behind cfg.AuthorizeHandler and
// instrumented. Both fields are required together — see validateProviderRouteAuth,
// which refuses to build a node whose routes would answer to anything that can
// reach the port.
func NewNode(nodeName string, cfg NodeConfig) (*Node, error) {
	return newNode(nodeName, cfg, defaultNodeTimings)
}

// newNode is NewNode with the node controller's intervals as a parameter.
func newNode(nodeName string, cfg NodeConfig, timings nodeTimings) (*Node, error) {
	// Fast-fail on a nil ConfigureNode rather than a nil-call panic at bring-up.
	if cfg.ConfigureNode == nil {
		return nil, errors.New("vkadapter: NodeConfig.ConfigureNode is required")
	}
	// providerRoutesEnabled is the SINGLE, security-load-bearing gate: the kubelet
	// HTTP provider routes (logs/exec/attach/port-forward) are served — mutually
	// authenticated and instrumented — ONLY when TLS is configured, so exec/attach
	// never rides plain HTTP. Every wiring step below consults this predicate so a
	// future edit cannot expose exec on the plain-HTTP path.
	routes := providerRoutesEnabled(cfg)
	// And when they ARE served, they are served authenticated: refuse to build the
	// node at all rather than serve exec to whoever can reach the port.
	if routes {
		if err := validateProviderRouteAuth(cfg); err != nil {
			return nil, err
		}
	}
	mux := http.NewServeMux()
	if routes {
		// Registered on the same mux VK's own routes are attached to below. A
		// pattern claimed twice is a ServeMux panic, never a silent shadow,
		// which is the right answer: VK registers "/" and k3sm registers subtree
		// patterns under it.
		for _, rt := range cfg.ExtraRoutes {
			if rt.Pattern == "" || rt.Handler == nil {
				return nil, fmt.Errorf("vkadapter: NodeConfig.ExtraRoutes entry %q needs both a pattern and a handler", rt.Pattern)
			}
			mux.Handle(rt.Pattern, rt.Handler)
		}
	}
	if _, _, err := net.SplitHostPort(cfg.HTTPListenAddr); err != nil {
		return nil, fmt.Errorf("error parsing http listen address: %w", err)
	}
	if cfg.Client == nil {
		return nil, errors.New("vkadapter: NodeConfig.Client is required")
	}
	if cfg.Provider == nil {
		return nil, errors.New("vkadapter: NodeConfig.Provider is required")
	}

	logger := cfg.Log
	if logger == nil {
		logger = slog.Default()
	}
	vkLog := newVKLogger(logger.With("node", nodeName, "component", "virtual-kubelet"))
	installVKLogger(vkLog)

	podInformerFactory := informers.NewSharedInformerFactoryWithOptions(
		cfg.Client,
		informerResyncPeriod,
		nodeutil.PodInformerFilter(nodeName),
	)
	podInformer := podInformerFactory.Core().V1().Pods()
	// Lister() registers the pod informer with the factory, so Run's Start
	// starts it.
	podLister := podInformer.Lister()

	nodeSpec := defaultNodeSpec(nodeName)
	cfg.ConfigureNode(nodeSpec)
	var np vknode.NodeProvider
	if cfg.NodeProvider != nil {
		var err error
		if np, err = cfg.NodeProvider(nodeSpec); err != nil {
			return nil, fmt.Errorf("error creating provider: %w", err)
		}
		np = &pingGuard{NodeProvider: np, budget: nodePingBudget, log: vkLog}
	}
	p := cfg.Provider

	var h http.Handler
	if routes {
		mux.Handle("/", api.PodHandler(api.PodHandlerConfig{
			RunInContainer:    p.RunInContainer,
			AttachToContainer: p.AttachToContainer,
			GetContainerLogs:  p.GetContainerLogs,
			GetPods:           p.GetPods,
			GetPodsFromKubernetes: func(context.Context) ([]*corev1.Pod, error) {
				return podLister.List(labels.Everything())
			},
			GetStatsSummary:    p.GetStatsSummary,
			GetMetricsResource: p.GetMetricsResource,
			PortForward:        p.PortForward,
		}, true))
		h = api.InstrumentHandler(cfg.AuthorizeHandler(mux))
	}

	// A nil NodeProvider selects VK's naive one, which never publishes Ready on
	// its own: the ready callback marks the node Ready once both controllers
	// are up. A supplied NodeProvider owns the Ready condition outright.
	var readyCb func(context.Context) error
	if np == nil {
		nnp := vknode.NewNaiveNodeProvider()
		np = nnp
		readyCb = func(ctx context.Context) error {
			setNodeReady(nodeSpec)
			if err := nnp.UpdateStatus(ctx, nodeSpec); err != nil {
				return fmt.Errorf("error marking node as ready: %w", err)
			}
			return nil
		}
	}

	// The liveness writes go through the heartbeat client and are recorded on
	// success, which is what Node.Heartbeat reports.
	hbClient := cfg.HeartbeatClient
	if hbClient == nil {
		hbClient = cfg.Client
	}
	rec := &heartbeatRecorder{now: time.Now}
	hbNodes := hbClient.CoreV1().Nodes()
	np = &statusResync{
		NodeProvider: np,
		interval:     timings.resyncInterval,
		rec:          rec,
		server: func(ctx context.Context) (*corev1.Node, error) {
			return hbNodes.Get(ctx, nodeName, metav1.GetOptions{ResourceVersion: "0"})
		},
		log: logger.With("node", nodeName),
	}
	nc, err := vknode.NewNodeController(
		np,
		nodeSpec,
		recordingNodes{NodeInterface: hbNodes, rec: rec},
		vknode.WithNodeEnableLeaseV1(recordingLeases{LeaseInterface: nodeutil.NodeLeaseV1Client(hbClient), rec: rec}, vknode.DefaultLeaseDuration),
		vknode.WithNodePingInterval(nodePingInterval),
		vknode.WithNodePingTimeout(nodePingTimeout),
		vknode.WithNodeStatusUpdateInterval(timings.statusInterval),
		// Record the failure (statusResync retries it) and return it unchanged,
		// so VK neither retries at once nor logs anything differently.
		vknode.WithNodeStatusUpdateErrorHandler(func(_ context.Context, err error) error {
			rec.statusPostFailed()
			return err
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating node controller: %w", err)
	}

	eb := record.NewBroadcaster()
	recorder := eb.NewRecorder(scheme.Scheme, corev1.EventSource{Component: path.Join(nodeName, "pod-controller")})

	scm := &scmAdapters{objects: cfg.Objects}
	pc, err := vknode.NewPodController(vknode.PodControllerConfig{
		PodClient:         cfg.Client.CoreV1(),
		EventRecorder:     recorder,
		Provider:          p,
		PodInformer:       podInformer,
		SecretInformer:    scopedSecretInformer{s: scm},
		ConfigMapInformer: scopedConfigMapInformer{s: scm},
		ServiceInformer:   scopedServiceInformer{s: scm},
		// k3sm resolves downward-API env in the provider itself (env.go
		// resolveDownwardEnv), AFTER the pod's /32 is allocated so status.podIP
		// carries the real IP. Virtual Kubelet's own PopulateEnvironmentVariables
		// (checked unchanged through v1.14.0) runs BEFORE CreatePod and
		// hard-errors on status.podIP ("unsupported fieldPath"), stranding such a
		// pod Pending before it ever reaches the provider — so skip VK's
		// resolution and let the provider own it. It is also VK's only reader of
		// the Secret/ConfigMap/Service listers above.
		SkipDownwardAPIResolution: true,
	})
	if err != nil {
		return nil, fmt.Errorf("error creating pod controller: %w", err)
	}

	return &Node{
		nc:                 nc,
		pc:                 pc,
		readyCb:            readyCb,
		ready:              make(chan struct{}),
		podInformerFactory: podInformerFactory,
		scm:                scm,
		client:             cfg.Client,
		listenAddr:         cfg.HTTPListenAddr,
		h:                  h,
		tlsConfig:          cfg.TLSConfig,
		workers:            cfg.NumWorkers,
		eb:                 eb,
		vkLog:              vkLog,
		heartbeat:          rec,
	}, nil
}
