package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	vknode "github.com/virtual-kubelet/virtual-kubelet/node"
	"github.com/virtual-kubelet/virtual-kubelet/node/nodeutil"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"k3sm.io/k3sm/pkg/provider"
)

// compile-time check that the provider satisfies the full VK provider contract.
var _ nodeutil.Provider = (*provider.HostProcess)(nil)

// runNode registers this Mac as a Virtual Kubelet node and runs pods as native
// macOS processes via the HostProcess provider (M0 walking skeleton).
func runNode(args []string) error {
	fs := flag.NewFlagSet("node", flag.ExitOnError)
	kubeconfig := fs.String("kubeconfig", os.Getenv("KUBECONFIG"), "path to a kubeconfig for the cluster")
	nodeName := fs.String("node-name", defaultNodeName(), "node name to register")
	listen := fs.String("listen", "127.0.0.1:10250", "address for the kubelet HTTP API (logs/exec)")
	podRoot := fs.String("pod-root", filepath.Join(os.TempDir(), "k3sm-pods"), "directory for per-pod logs/state")
	nodeIP := fs.String("node-ip", "127.0.0.1", "node/pod IP to advertise")
	_ = fs.Parse(args)

	if *kubeconfig == "" {
		return fmt.Errorf("--kubeconfig (or $KUBECONFIG) is required")
	}
	restCfg, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		return fmt.Errorf("load kubeconfig: %w", err)
	}
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("build client: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hp := provider.NewHostProcess(*nodeName, *podRoot, *nodeIP)
	n, err := nodeutil.NewNode(*nodeName,
		func(pc nodeutil.ProviderConfig) (nodeutil.Provider, vknode.NodeProvider, error) {
			configureNode(pc.Node, *nodeName, *nodeIP)
			return hp, nil, nil // nil NodeProvider -> NewNaiveNodeProvider (auto-Ready + lease heartbeat)
		},
		func(c *nodeutil.NodeConfig) error {
			c.Client = cs
			c.HTTPListenAddr = *listen
			c.NumWorkers = 4
			return nil
		},
	)
	if err != nil {
		return fmt.Errorf("new node: %w", err)
	}

	errc := make(chan error, 1)
	go func() { errc <- n.Run(ctx) }()

	select {
	case <-n.Ready():
		log.Printf("k3sm node %q ready (runtime=hostprocess listen=%s pod-root=%s)", *nodeName, *listen, *podRoot)
	case err := <-errc:
		return fmt.Errorf("node exited during startup: %w", err)
	case <-ctx.Done():
		return ctx.Err()
	}

	select {
	case <-ctx.Done():
		return nil
	case err := <-errc:
		return err
	}
}

// configureNode stamps the registering Node object with darwin identity + capacity.
func configureNode(n *corev1.Node, name, ip string) {
	if n.Labels == nil {
		n.Labels = map[string]string{}
	}
	n.Labels["kubernetes.io/os"] = "darwin"
	n.Labels["kubernetes.io/arch"] = "arm64"
	n.Labels["kubernetes.io/hostname"] = name
	n.Labels["k3sm.io/native"] = "true"
	n.Labels["type"] = "k3sm"

	n.Status.NodeInfo.OperatingSystem = "darwin"
	n.Status.NodeInfo.Architecture = "arm64"
	n.Status.NodeInfo.KubeletVersion = "k3sm-m0"

	n.Status.Capacity = corev1.ResourceList{
		corev1.ResourceCPU:    resource.MustParse(strconv.Itoa(runtime.NumCPU())),
		corev1.ResourceMemory: resource.MustParse("8Gi"),
		corev1.ResourcePods:   resource.MustParse("110"),
	}
	n.Status.Allocatable = n.Status.Capacity.DeepCopy()
	n.Status.Addresses = []corev1.NodeAddress{
		{Type: corev1.NodeInternalIP, Address: ip},
		{Type: corev1.NodeHostName, Address: name},
	}
	n.Status.DaemonEndpoints.KubeletEndpoint.Port = 10250
	// NOTE: production adds a provider taint (k3sm.io/provider:NoSchedule) + a
	// ValidatingAdmissionPolicy requiring nodeSelector kubernetes.io/os=darwin so
	// stray Linux pods can't land here. Left off for the M0 demo so a plain
	// `kubectl run` schedules onto the only node.
}

func defaultNodeName() string {
	h, _ := os.Hostname()
	h = strings.TrimSuffix(strings.ToLower(h), ".local")
	if h == "" {
		h = "node"
	}
	return "k3sm-" + h
}
