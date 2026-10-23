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
	"net"
	"strconv"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/registrysvc"
	"k3sm.io/runtimed/pkg/image"
)

// flatRegistryHost is the cluster's ONE registry name, the authority every
// image reference that means "this cluster's registry" carries; its port is
// executor.DefaultRegistryPort (a test pins the two together). In a Pod it resolves through
// cluster DNS to the flat registry-k3sm Service; on a node, runtimed never
// resolves it, and maps it to the endpoint below instead (the k3s registries.yaml
// mirror-and-rewrite shape).
const flatRegistryHost = "registry-k3sm:6450"

// flatRegistryEndpoint is where this node's runtime fetches the flat registry
// name from. The zero value maps nothing.
//
// The server side provides: the registry on the server, serving zot on loopback
// at the server's --registry-port, and a TLS listener on the server's mesh
// address at the default registry port whose certificate is issued by the
// cluster CA and names registry-k3sm. This file depends on neither being up: an
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

// agentFlatRegistry is a joined worker's endpoint: the server's mesh address at
// the default registry port, over TLS verified against the cluster CA the join
// returned. The mesh address is the apiserver host the join advertised, which is
// the server's mesh IP; a join that advertised none (an old server) maps nothing,
// because the underlay --server address is not a name the registry certificate
// carries.
func agentFlatRegistry(res *bootstrap.JoinResult) flatRegistryEndpoint {
	host := advertisedAPIServerHost(res)
	if host == "" || len(res.ClusterCAPEM) == 0 {
		return flatRegistryEndpoint{}
	}
	return flatRegistryEndpoint{
		Addr:      net.JoinHostPort(host, strconv.Itoa(executor.DefaultRegistryPort)),
		CAPEM:     res.ClusterCAPEM,
		TLS:       true,
		aliasPort: executor.DefaultRegistryPort,
	}
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
