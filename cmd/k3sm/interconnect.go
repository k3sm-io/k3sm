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
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/record"

	netv1 "k3sm.io/apis/net/v1"
	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	"k3sm.io/darwin-net/pkg/linkenum"
	"k3sm.io/darwin-net/pkg/netd/wire"
	"k3sm.io/darwin-net/pkg/podnet"

	"k3sm.io/k3sm/pkg/interconnect"
	"k3sm.io/k3sm/pkg/provider/vkadapter"
)

// meshPeerIndexSet returns a lister of every node's cluster index, from the pod
// /24 its MeshPeer holds — the index netd derives the node's interconnect
// address from (podnet.NodeIndex over the cluster pod aggregate), so the server's
// recomputed address and the helper's alias come from one derivation. A MeshPeer
// whose pod /24 yields no index is reported, never skipped silently.
func meshPeerIndexSet(list func(context.Context) ([]netv1.MeshPeerSpec, error)) func(context.Context) (interconnect.Indices, error) {
	return func(ctx context.Context) (interconnect.Indices, error) {
		peers, err := list(ctx)
		if err != nil {
			return interconnect.Indices{}, err
		}
		out := interconnect.Indices{Index: make(map[string]int, len(peers)), Invalid: map[string]string{}}
		for _, p := range peers {
			cidr, err := netip.ParsePrefix(p.PodCIDR)
			if err == nil {
				var idx int
				if idx, err = podnet.NodeIndex(podnet.ClusterPodCIDR, cidr); err == nil {
					out.Index[p.NodeName] = idx
					continue
				}
			}
			out.Invalid[p.NodeName] = fmt.Sprintf("pod CIDR %q: %v", p.PodCIDR, err)
		}
		return out, nil
	}
}

// meshPeerIndices is meshPeerIndexSet's index map alone (the node reporter
// probes only nodes that have an address).
func meshPeerIndices(list func(context.Context) ([]netv1.MeshPeerSpec, error)) func(context.Context) (map[string]int, error) {
	set := meshPeerIndexSet(list)
	return func(ctx context.Context) (map[string]int, error) {
		s, err := set(ctx)
		return s.Index, err
	}
}

// meshPeerListerFor is a MeshPeer LIST over cfg's identity: the server's admin
// client for the resolver, the node's own client (which may already list
// MeshPeers) for the reporter. No new RBAC.
func meshPeerListerFor(cfg *rest.Config) (func(context.Context) ([]netv1.MeshPeerSpec, error), error) {
	client, err := meshPeerRESTClient(cfg)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context) ([]netv1.MeshPeerSpec, error) { return listMeshPeers(ctx, client) }, nil
}

// slot0Peers turns cluster indices into every node's slot-0 interconnect
// address; a node whose index has no address (beyond the ceiling) is absent.
func slot0Peers(indices func(context.Context) (map[string]int, error)) interconnect.PeerSource {
	return func(ctx context.Context) (map[string]netip.Addr, error) {
		idx, err := indices(ctx)
		if err != nil {
			return nil, err
		}
		out := make(map[string]netip.Addr, len(idx))
		for name, i := range idx {
			a, err := netv1alpha1.InterconnectSlotAddress(i, netv1alpha1.InterconnectSlotNode)
			if err != nil {
				continue
			}
			out[name] = a
		}
		return out, nil
	}
}

// startInterconnectResolver is step 4f': the server's Interconnect resolver. It
// ensures the CRD, then reconciles while this server holds the resolver Lease,
// on the server's in-process admin client like the MLX operator, recording into
// plan.interconnectMetrics (which the in-process node serves). It is drained
// before the control plane stops (the caller defers the returned stop after
// exec.Stop's). A client that cannot be built is logged and nothing runs: the
// interconnect is an optional surface.
func startInterconnectResolver(ctx context.Context, plan serverPlan, restCfg *rest.Config, cs kubernetes.Interface, logger *slog.Logger) (stop func()) {
	dyn, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		logger.Error("interconnect resolver disabled: build its dynamic client", "err", err)
		return noStop
	}
	crd, err := apiextensionsclient.NewForConfig(restCfg)
	if err != nil {
		logger.Error("interconnect resolver disabled: build its apiextensions client", "err", err)
		return noStop
	}
	list, err := meshPeerListerFor(restCfg)
	if err != nil {
		logger.Error("interconnect resolver disabled: build its MeshPeer client", "err", err)
		return noStop
	}
	r := interconnect.NewResolver(interconnect.ResolverConfig{
		Client:   cs,
		Store:    interconnect.Store{Client: dyn},
		CRD:      crd,
		Indices:  meshPeerIndexSet(list),
		Identity: plan.opts.nodeName,
		// The interconnect-using MLXModels, read with the same admin client the
		// MLX operator uses; the desired annotation carries their references.
		MLXModels: interconnect.MLXModelLister(dyn),
		Metrics:   plan.interconnectMetrics,
		Log:       logger,
	})
	rCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := r.Run(rCtx); err != nil && rCtx.Err() == nil {
			logger.Error("interconnect resolver", "err", err)
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

// interconnectRoutes serves the interconnect metrics on the node's kubelet
// endpoint, beside /metrics/resource and behind the same authentication.
func interconnectRoutes(m *interconnect.Metrics) []vkadapter.Route {
	if m == nil {
		return nil
	}
	return []vkadapter.Route{{Pattern: interconnect.MetricsPath, Handler: m}}
}

// startInterconnectNode runs the node's interconnect reporter and desired
// handler: every node reports its Thunderbolt links on its own Node and applies
// the desired annotation the server writes there. They need the root helper
// (the interconnect alias verbs live only there), so a node without one runs
// neither and says so once. Nothing here reads the Interconnect object or
// writes anything but this node's own annotations.
func startInterconnectNode(ctx context.Context, opts nodeOptions, cs kubernetes.Interface, restCfg *rest.Config, recorder record.EventRecorder, metrics *interconnect.Metrics, logger *slog.Logger) (stop func()) {
	if !opts.netMode.UsesHelper() {
		logger.Info("interconnect disabled on this node: it needs the k3sm-netd root helper (an unprivileged --network auto node)", "node", opts.nodeName)
		return noStop
	}
	list, err := meshPeerListerFor(restCfg)
	if err != nil {
		logger.Error("interconnect disabled on this node: build its MeshPeer client", "err", err)
		return noStop
	}
	own := interconnect.NewOwnNode(cs, opts.nodeName)
	var rep *interconnect.Reporter
	prober := interconnect.NewMeshLiveness(func() { rep.Nudge() })
	nodeRef := &corev1.ObjectReference{Kind: "Node", Name: opts.nodeName, UID: types.UID(opts.nodeName)}
	rep = interconnect.NewReporter(interconnect.ReporterConfig{
		Node:       opts.nodeName,
		Discovery:  interconnect.LinkenumDiscovery{Enum: linkenum.Exec{}},
		Peers:      slot0Peers(meshPeerIndices(list)),
		Liveness:   prober,
		Annotation: own.For(netv1alpha1.AnnotationInterconnectReport),
		Events: func(reason, msg string) {
			recorder.Event(nodeRef, corev1.EventTypeWarning, reason, msg)
		},
		Metrics: metrics,
		Log:     logger,
	})
	handler := interconnect.NewDesiredHandler(interconnect.DesiredConfig{
		Node:      opts.nodeName,
		Desired:   own.For(netv1alpha1.AnnotationInterconnectDesired),
		Client:    wire.NewClient(opts.netMode.Socket),
		Reachable: opts.netMode.Probe,
		OnReason:  rep.SetHelperReason,
		Metrics:   metrics,
		Log:       logger,
	})
	icCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	for _, run := range []func(context.Context){
		own.Run,
		prober.Run,
		rep.Run,
		func(ctx context.Context) { handler.Run(ctx, own.Changed()) },
	} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			run(icCtx)
		}()
	}
	return func() {
		cancel()
		wg.Wait()
	}
}

const interconnectUsage = `Usage: k3sm interconnect enable|disable [name] [flags]

Arm or disarm the cable between nodes as an opt-in network (the
net.k3sm.io Interconnect; the only one is "thunderbolt").

  enable    set spec.enabled true. Nothing gets an interconnect address
            until an admin does this. Opted-in pod traffic then crosses the
            cable in plaintext, and any device on a cabled port can reach
            and spoof interconnect addresses.
  disable   set spec.enabled false; the server removes every node's
            interconnect address.

status.armedBy records the identity the apiserver authenticated this
command's kubeconfig as ("unknown" when it cannot be read). It is
informational, not an access control.

Flags:
  --kubeconfig <path>  kubeconfig to use (default: the k3sm admin kubeconfig,
                       else the k3sm context of ~/.kube/config)
`

// runInterconnect dispatches `k3sm interconnect`.
func runInterconnect(args []string) error {
	return runInterconnectWith(args, os.Stdout, os.Stderr, interconnectClients)
}

// interconnectClients builds the CLI's clients from kubeconfig ("" resolves
// the way `k3sm kubectl` does).
func interconnectClients(kubeconfig string) (kubernetes.Interface, dynamic.Interface, error) {
	var (
		cfg *rest.Config
		err error
	)
	if kubeconfig != "" {
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		home, _ := os.UserHomeDir()
		var kc kubectlConfig
		kc, err = resolveKubectlConfig(kubectlInputs{
			workDirOverride: os.Getenv("K3SM_WORK_DIR"),
			workDir:         workDirFromEnv(),
			kubeconfigEnv:   os.Getenv("KUBECONFIG"),
			home:            home,
			contextName:     installedContextName,
			exists:          fileExists,
		})
		if err != nil {
			return nil, nil, err
		}
		rules := clientcmd.NewDefaultClientConfigLoadingRules()
		if kc.kubeconfig != "" {
			rules.ExplicitPath = kc.kubeconfig
		}
		cfg, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules,
			&clientcmd.ConfigOverrides{CurrentContext: kc.context}).ClientConfig()
	}
	if err != nil {
		return nil, nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	return cs, dyn, nil
}

// runInterconnectWith is runInterconnect over injected clients.
func runInterconnectWith(args []string, stdout, stderr io.Writer, clients func(string) (kubernetes.Interface, dynamic.Interface, error)) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, interconnectUsage)
		return fmt.Errorf("missing subcommand (want: enable, disable)")
	}
	var enable bool
	switch args[0] {
	case "enable":
		enable = true
	case "disable":
	case "-h", "--help", "help":
		fmt.Fprint(stdout, interconnectUsage)
		return nil
	default:
		return fmt.Errorf("unknown subcommand %q (want: enable, disable)", args[0])
	}
	fs := flag.NewFlagSet("interconnect "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, interconnectUsage) }
	kubeconfig := fs.String("kubeconfig", "", "kubeconfig to use")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	name := interconnect.Name
	switch fs.NArg() {
	case 0:
	case 1:
		name = fs.Arg(0)
	default:
		return fmt.Errorf("takes at most one interconnect name (got %q)", fs.Args())
	}
	cs, dyn, err := clients(*kubeconfig)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	logger := slog.New(slog.NewTextHandler(stderr, nil))
	res, err := interconnect.SetEnabled(ctx, cs, interconnect.Store{Client: dyn}, name, enable, time.Now(), logger)
	if err != nil {
		return err
	}
	if enable {
		fmt.Fprintf(stdout, "interconnect %s armed by %s; opted-in pod traffic on the cable is plaintext\n", name, res.ArmedBy)
		return nil
	}
	fmt.Fprintf(stdout, "interconnect %s disarmed\n", name)
	return nil
}
