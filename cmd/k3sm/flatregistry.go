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
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/kubeclient"
	"k3sm.io/k3sm/pkg/registrysvc"
	"k3sm.io/runtimed/pkg/image"
)

// flatRegistryHost is the cluster's ONE registry name, the authority every
// image reference that means "this cluster's registry" carries; its port is
// registrysvc.FlatServicePort (a test pins the two together). In a Pod it resolves through
// cluster DNS to the flat registry-k3sm Service; on a node, runtimed never
// resolves it, and maps it to the endpoint below instead (the k3s registries.yaml
// mirror-and-rewrite shape).
const flatRegistryHost = "registry-k3sm:6450"

// flatRegistryEndpoint is where this node's runtime fetches the flat registry
// name from. The zero value maps nothing.
//
// The server side provides: the registry on the server, serving zot on loopback
// at the server's --registry-port, and a TLS listener on the server's mesh
// address at the same port whose certificate is issued by the cluster CA and
// names registry-k3sm, published as the flat Service's EndpointSlice. This file depends on neither being up: an
// endpoint nothing answers fails the pull the way an unreachable registry does.
type flatRegistryEndpoint struct {
	// Addr is host:port.
	Addr string
	// CAPEM is the cluster CA the endpoint's certificate is verified against.
	// It is bytes, not a file, because an agent holds the cluster CA only as the
	// join returned it (it is embedded in the node kubeconfig, never written as a
	// file of its own).
	CAPEM []byte
	// TLS selects HTTPS. runtimed accepts plain HTTP only for a loopback Addr.
	TLS bool
	// aliasPort is the loopback port a reference on this node may spell the same
	// registry with (localhost:<port>/x), recorded under the flat name.
	aliasPort int
}

// serverFlatRegistry is the server's endpoint: the registry it runs itself, on
// loopback, over plain HTTP.
//
// Loopback HTTP rather than the TLS listener, deliberately: the TLS listener is
// the cluster-facing door and is reached by name from Pods and by mesh address
// from agents, but the server's own runtime is on the same Mac as zot, and a
// loopback hop never leaves it. TLS there would protect nothing a local root
// could not already read, and content integrity never rested on the transport:
// every blob is re-hashed against its manifest digest before it is committed.
// runtimed refuses plaintext to any address that is not loopback.
func serverFlatRegistry(registryPort int) flatRegistryEndpoint {
	if registryPort <= 0 {
		return flatRegistryEndpoint{}
	}
	return flatRegistryEndpoint{
		Addr:      net.JoinHostPort(registrysvc.LoopbackAddress, strconv.Itoa(registryPort)),
		aliasPort: registryPort,
	}
}

// Bounds on reading the cluster's flat registry endpoint at start. The wait
// covers a server that is restarting: a server retracts the EndpointSlice when
// it stops and republishes it once its registry serves again, while the Service
// itself stays. It is not spent when there is no Service at all (the registry is
// off), which is answered at once.
const (
	flatRegistryLookupWait     = 30 * time.Second
	flatRegistryLookupInterval = 2 * time.Second
)

// flatServiceGetter and flatSliceGetter are the two reads a node needs to find
// the cluster's one registry: the flat Service and its hand-written
// EndpointSlice, in registrysvc.FlatServiceNamespace. A namespaced client-go
// client satisfies each; a node identity holds get on both through the
// k3sm:node-datapath ClusterRole.
type flatServiceGetter interface {
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.Service, error)
}

type flatSliceGetter interface {
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*discoveryv1.EndpointSlice, error)
}

// clusterFlatRegistry is the endpoint the flat Service's EndpointSlice names:
// the publishing server's relay address at the port its relay listens on (the
// server's --registry-port, the Service's target port), over TLS verified
// against caPEM, the cluster CA. It is what every node other than the
// publishing server fetches the flat name from: a joined worker, and a server
// that joined an existing control plane, which must not split the one image
// store by serving the name from its own registry.
//
// The address and the port are both read from what the publisher wrote, never
// derived from a default: a server started on another port relays on that port.
// A slice with no ready IPv4 endpoint, no port, or a loopback address, and an
// empty caPEM, map nothing.
func clusterFlatRegistry(slice *discoveryv1.EndpointSlice, caPEM []byte) flatRegistryEndpoint {
	if slice == nil || len(caPEM) == 0 {
		return flatRegistryEndpoint{}
	}
	port := 0
	for _, p := range slice.Ports {
		if p.Port == nil || (p.Name != nil && *p.Name != registrysvc.ClusterServicePortName) {
			continue
		}
		port = int(*p.Port)
		break
	}
	if port <= 0 || port > 65535 {
		return flatRegistryEndpoint{}
	}
	for _, ep := range slice.Endpoints {
		if ep.Conditions.Ready == nil || !*ep.Conditions.Ready {
			continue
		}
		for _, a := range ep.Addresses {
			addr, err := netip.ParseAddr(a)
			if err != nil || !addr.Is4() || addr.IsLoopback() || addr.IsUnspecified() {
				continue
			}
			return flatRegistryEndpoint{
				Addr:      net.JoinHostPort(addr.String(), strconv.Itoa(port)),
				CAPEM:     caPEM,
				TLS:       true,
				aliasPort: port,
			}
		}
	}
	return flatRegistryEndpoint{}
}

// lookupClusterFlatRegistry reads the flat Service and its EndpointSlice and
// returns clusterFlatRegistry of what it finds.
//
// No Service means the cluster runs no registry (the bootstrap server opted out
// or predates it), and maps nothing at once. A Service whose slice is absent or
// names no ready endpoint is a publisher that is restarting, so the read is
// retried every interval until wait has passed; then it maps nothing and says
// so. A failed read is retried the same way. The result is fixed for the node's
// life: runtimed takes the mapping at start.
func lookupClusterFlatRegistry(ctx context.Context, svcs flatServiceGetter, slices flatSliceGetter, caPEM []byte, wait, interval time.Duration, logger *slog.Logger) flatRegistryEndpoint {
	if svcs == nil || slices == nil || len(caPEM) == 0 {
		return flatRegistryEndpoint{}
	}
	deadline := time.Now().Add(wait)
	var lastErr error
	for {
		_, err := svcs.Get(ctx, registrysvc.FlatServiceName, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			logger.Info("the cluster publishes no registry Service, so the flat registry name maps nothing on this node",
				"namespace", registrysvc.FlatServiceNamespace, "name", registrysvc.FlatServiceName)
			return flatRegistryEndpoint{}
		case err != nil:
			lastErr = fmt.Errorf("read the %s Service: %w", registrysvc.FlatServiceName, err)
		default:
			slice, serr := slices.Get(ctx, registrysvc.FlatServiceName, metav1.GetOptions{})
			switch {
			case serr == nil:
				if e := clusterFlatRegistry(slice, caPEM); e.Addr != "" {
					return e
				}
				lastErr = fmt.Errorf("the %s EndpointSlice names no ready relay address", registrysvc.FlatServiceName)
			case apierrors.IsNotFound(serr):
				lastErr = fmt.Errorf("the %s Service has no EndpointSlice yet", registrysvc.FlatServiceName)
			default:
				lastErr = fmt.Errorf("read the %s EndpointSlice: %w", registrysvc.FlatServiceName, serr)
			}
		}
		if !time.Now().Add(interval).Before(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return flatRegistryEndpoint{}
		case <-time.After(interval):
		}
	}
	logger.Warn("the cluster registry's endpoint could not be read, so the flat registry name maps nothing on this node until it restarts",
		"name", registrysvc.FlatAuthority(), "err", lastErr)
	return flatRegistryEndpoint{}
}

// agentFlatRegistry is a joined worker's endpoint: the cluster registry the
// flat Service names, read under the node's own credential (kubeconfigPath)
// and verified against the cluster CA the join returned.
func agentFlatRegistry(ctx context.Context, kubeconfigPath string, res *bootstrap.JoinResult, logger *slog.Logger) flatRegistryEndpoint {
	if res == nil || len(res.ClusterCAPEM) == 0 {
		return flatRegistryEndpoint{}
	}
	_, cs, err := kubeclient.FromPath(kubeconfigPath)
	if err != nil {
		logger.Warn("the flat registry name maps nothing on this node: its kubeconfig cannot be loaded", "err", err)
		return flatRegistryEndpoint{}
	}
	return lookupClusterFlatRegistry(ctx,
		cs.CoreV1().Services(registrysvc.FlatServiceNamespace),
		cs.DiscoveryV1().EndpointSlices(registrysvc.FlatServiceNamespace),
		res.ClusterCAPEM, flatRegistryLookupWait, flatRegistryLookupInterval, logger)
}

// mapping renders the endpoint as runtimed's flat registry mapping. The zero
// endpoint renders the zero mapping, which runtimed treats as off.
func (e flatRegistryEndpoint) mapping() image.FlatRegistry {
	if e.Addr == "" {
		return image.FlatRegistry{}
	}
	port := strconv.Itoa(e.aliasPort)
	return image.FlatRegistry{
		Host:     flatRegistryHost,
		Endpoint: image.RegistryEndpoint{Addr: e.Addr, CAPEM: e.CAPEM, TLS: e.TLS},
		Aliases:  []string{net.JoinHostPort("localhost", port), net.JoinHostPort(registrysvc.LoopbackAddress, port)},
	}
}
