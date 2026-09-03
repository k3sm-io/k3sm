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
	"errors"
	"log/slog"
	"sync"
	"time"

	"k3sm.io/k3sm/pkg/registrysvc"
)

// Teardown and refresh timings for the ingest registry and the two cluster-facing
// listeners it brings with it.
const (
	// registryShutdownGrace bounds the ingest registry's teardown. It is shorter
	// than the control plane's 30s because the registry holds no datastore and
	// has nothing to drain — the only thing worth waiting for is the port coming
	// free.
	registryShutdownGrace = 10 * time.Second
	// registryAdvertiseRefresh is how often this node re-publishes its peer-facing
	// advertisement. It is a REFRESH, not a heartbeat: the object is already
	// correct, and re-writing it only repairs the cases a single publish at boot
	// cannot — an apiserver that was not answering yet, or an object something
	// else deleted. A publish that changes nothing issues no write at all.
	registryAdvertiseRefresh = 5 * time.Minute
	// registryRetractGrace bounds the best-effort retraction at shutdown.
	registryRetractGrace = 5 * time.Second
)

// registryService is the lifetime seam `k3sm server` drives the node-local ingest
// registry through.
//
// It is declared HERE, at the consumer, and not in pkg/registrysvc: what the
// server needs is three methods, and an interface owned by the caller is what
// lets this file's wiring be tested — start ordering, the never-fatal contract,
// the KEP-1755 publish, the teardown — without a zot binary, a Go toolchain, or a
// bound port anywhere in the test.
type registryService interface {
	Start(ctx context.Context) error
	Addr() string
	Shutdown(ctx context.Context) error
}

// registryConfig renders the ingest registry's configuration from the parsed
// server flags. It is PURE, so the flag-to-config mapping — most of all "0 means
// disabled", which is checked by the caller, and the payload dir a packaged
// install seeds the binary from — is assertable without a bring-up.
func registryConfig(opts serverOptions, payloadBinDir string, logger *slog.Logger) registrysvc.Config {
	return registrysvc.Config{
		WorkDir:       opts.workDir,
		PayloadBinDir: payloadBinDir,
		Port:          opts.registryPort,
		Logger:        logger,
	}
}

// ingestRegistry is everything `k3sm server` needs to bring the node-local
// registry up: the service itself, the port, and the three cluster facts that
// decide who — besides this node's own pods — can reach it.
//
// It is a struct rather than a parameter list because the fields are not
// interchangeable and several are same-typed strings: a node name, a mesh
// address and a NAT segment transposed at a call site would compile and would
// then advertise one node's registry under another node's name.
type ingestRegistry struct {
	// svc is the registry service to start and stop.
	svc registryService
	// port is the loopback port it serves on — the port the discovery document
	// names, the port peers are advertised at, and the port the relay binds.
	port int
	// nodeName is this node, the identity its advertisement is published under.
	nodeName string
	// meshIP is this node's wireguard address, or "" on a single-node server.
	// Empty publishes no advertisement and relays on no mesh address: there is no
	// address a peer could dial.
	meshIP string
	// vmNetSubnet is the NAT segment this node's Linux guests are attached to, or
	// "" on a node that hosts none. It contributes the gateway-address relay bind,
	// which is the only way a guest can reach a host listener (a guest cannot
	// reach loopback).
	vmNetSubnet string
	// hostingCMs writes the KEP-1755 discovery document, in kube-public.
	hostingCMs registrysvc.ConfigMapClient
	// advertCMs writes and retracts this node's own advertisement, in
	// registrysvc.AdvertisementNamespace. It is a SECOND client because the two
	// objects live in different namespaces on purpose: the advertisement set is
	// namespace-isolated so the read grant a node identity gets can be scoped to
	// it (pkg/rbac), and a namespaced client is bound to one namespace.
	advertCMs registrysvc.AdvertisementClient
	// clusterSvcs and clusterSlices write and retract this node's per-node
	// registry Service and its hand-written EndpointSlice, in the same
	// namespace as the advertisement. They are the ONE cluster address a native
	// Pod, a vm guest and the host all reach this node's registry at; nil on a
	// bring-up with no cluster to publish into leaves the Service unpublished and
	// the KEP-1755 document without a hostFromClusterNetwork.
	clusterSvcs   registrysvc.ServiceClient
	clusterSlices registrysvc.EndpointSliceClient
	// clusterDomain is the cluster DNS suffix the Service authority is rendered
	// with. Empty means dns.DefaultClusterDomain.
	clusterDomain string
	// logger receives bring-up and teardown events.
	logger *slog.Logger
}

// registryPullerWiring is everything runtimed's puller has to be told about THIS
// node's own ingest registry. It is one struct rather than two return values
// because the two fields are constrained by each other: runtimed refuses a
// LocalHost that is neither a loopback spelling nor one of ClusterRegistries, and
// that refusal fails the node's bring-up — so they are produced together, by the
// one component that knows both.
//
// The zero value is the complete, correct wiring for a node with no registry:
// runtimed's classification is then byte-identical to its pre-seam behavior.
type registryPullerWiring struct {
	// LocalHost is this node's ingest registry as a reference names it —
	// "localhost:<port>". It makes a bare "app:v1" resolve here first instead of
	// normalising straight to Docker Hub.
	LocalHost string
	// ClusterRegistries are the NON-loopback spellings of the same registry: the
	// per-node Service's four resolvable authorities and its VIP
	// (registrysvc.ClusterLocalAuthorities). Empty on a node that publishes no
	// Service.
	ClusterRegistries []string
}

// startIngestRegistry brings the registry up, publishes the KEP-1755 discovery
// ConfigMap, this node's peer-facing advertisement and its per-node cluster
// Service, starts the mesh/guest relay, and returns the teardown closure the
// caller defers. The closure is never nil, so the caller's `defer stop()` is
// unconditional.
//
// It ALSO returns the puller wiring: how runtimed should spell this node's own
// registry (registryPullerWiring). It is returned rather than published somewhere
// because runtimed's puller is the consumer — a reference carrying one of those
// authorities is node-relative in exactly the sense a loopback one is, and
// runtimed cannot derive them (they depend on a node name, a cluster domain and
// an assigned VIP it never sees). The zero value on a registry that never started
// leaves runtimed's classification byte for byte as it was.
//
// NOTHING HERE IS FATAL. A registry that cannot build, bind or serve leaves a
// cluster that cannot ingest images; a bring-up that aborted over it leaves a
// cluster that does nothing at all. This is the same log-and-continue posture the
// ingress listeners and svclb are started under, and the opposite of the
// fail-closed RBAC and MeshPeer-CRD steps, which decide whether there is a
// working control plane at all.
//
// EVERYTHING IS PUBLISHED ONLY AFTER THE REGISTRY IS SERVING, discovery document
// and advertisement alike. A document naming a port nothing answers on is worse
// than no document: a reader that finds it stops looking and then fails at the
// push, and a peer that finds it makes a pull wait on a dial that cannot succeed.
func startIngestRegistry(ctx context.Context, r ingestRegistry) (func(), registryPullerWiring) {
	logger := r.logger
	if err := r.svc.Start(ctx); err != nil {
		logger.Error("ingest registry disabled", "err", err)
		return func() {}, registryPullerWiring{}
	}
	// The per-node Service comes BEFORE the discovery document, because the
	// document's hostFromClusterNetwork is a claim about it: the address is
	// published exactly when a Service exists to answer it, and "" otherwise.
	clusterHost, clusterIP := r.publishClusterService(ctx)
	if err := registrysvc.PublishHosting(ctx, r.hostingCMs, r.port, clusterHost); err != nil {
		// The registry is serving and pushes to it work; only the DISCOVERY of it
		// failed. Reporting and continuing keeps the working half working.
		logger.Error("publish the local-registry-hosting ConfigMap", "err", err,
			"namespace", registrysvc.HostingNamespace, "name", registrysvc.HostingConfigMapName)
	} else {
		logger.Info("published local-registry-hosting for discovery",
			"namespace", registrysvc.HostingNamespace, "name", registrysvc.HostingConfigMapName,
			"addr", r.svc.Addr(), "hostFromClusterNetwork", clusterHost)
	}

	// A context of its own for the two cluster-facing goroutines, so the teardown
	// can stop them WITHOUT waiting on the caller's: they must be down before the
	// registry they front is, or a peer's in-flight pull outlives its target.
	auxCtx, stopAux := context.WithCancel(ctx)
	var aux sync.WaitGroup

	r.advertise(auxCtx, &aux)
	r.refreshClusterService(auxCtx, &aux)
	r.relay(auxCtx, &aux)

	// The registry is SERVING at this point, which is what makes the loopback
	// spelling true; the cluster spellings are added only when a Service was
	// actually published, so runtimed never admits an authority nothing answers.
	wiring := registryPullerWiring{LocalHost: registrysvc.LoopbackAuthority(r.port)}
	if clusterHost != "" {
		wiring.ClusterRegistries = registrysvc.ClusterLocalAuthorities(r.nodeName, r.clusterDomain, clusterIP, r.port)
	}

	return func() {
		stopAux()
		aux.Wait()
		// WithoutCancel throughout: this runs from a defer during shutdown, when
		// ctx is already cancelled, and a teardown that inherited the cancellation
		// would retract nothing and would SIGKILL the child immediately instead of
		// letting it close its storage.
		r.retract(context.WithoutCancel(ctx))
		r.retractClusterService(context.WithoutCancel(ctx))
		stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), registryShutdownGrace)
		defer cancel()
		if err := r.svc.Shutdown(stopCtx); err != nil {
			logger.Error("ingest registry shutdown", "err", err)
		}
	}, wiring
}

// advertise publishes this node's peer-facing advertisement and keeps it fresh
// until ctx ends.
//
// A node with no mesh address publishes nothing and says so once at Info: on a
// single-node cluster that is the whole truth, not a degradation.
func (r ingestRegistry) advertise(ctx context.Context, wg *sync.WaitGroup) {
	publish := func(ctx context.Context) {
		err := registrysvc.PublishAdvertisement(ctx, r.advertCMs, r.nodeName, r.meshIP, r.port)
		switch {
		case err == nil:
		case errors.Is(err, registrysvc.ErrNoMeshAddress):
		default:
			// The registry serves and this node's own pods pull from it; only the
			// PEERS' view of it failed. Reporting and continuing keeps the working
			// half working, exactly as the discovery publish above does.
			r.logger.Error("publish this node's registry advertisement", "err", err,
				"namespace", registrysvc.AdvertisementNamespace, "name", registrysvc.AdvertisementName(r.nodeName))
		}
	}
	if registrysvc.MeshHost(r.meshIP, r.port) == "" {
		r.logger.Info("this node's ingest registry is not advertised to peers: it has no mesh address (single-node)",
			"node", r.nodeName)
		return
	}
	publish(ctx)
	r.logger.Info("advertised this node's ingest registry to cluster peers",
		"node", r.nodeName, "meshHost", registrysvc.MeshHost(r.meshIP, r.port))
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(registryAdvertiseRefresh)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				publish(ctx)
			}
		}
	}()
}

// publishClusterService publishes this node's per-node registry Service and its
// hand-written EndpointSlice, and returns the in-cluster authority a caller dials
// — or "" when there is none, which is the value HostingDocument omits the field
// for — together with the ClusterIP the apiserver assigned, which is the other
// spelling of the same registry a workload may write into a reference.
//
// It returns "" and says why, once at Info, in the two states where there is
// nothing to publish: no cluster clients (a bring-up with no apiserver), and no
// relay address (a single Mac with no mesh and no vm network, where loopback
// already reaches everything that exists).
//
// A publish FAILURE also yields "", deliberately. The registry serves and this
// node's own pods pull from it; only the cluster-facing name failed, and
// publishing a hostFromClusterNetwork for a Service that does not exist would
// send every reader at a name that resolves to nothing.
func (r ingestRegistry) publishClusterService(ctx context.Context) (authority, clusterIP string) {
	if r.clusterSvcs == nil || r.clusterSlices == nil {
		return "", ""
	}
	addr, err := registrysvc.ClusterEndpointAddress(r.meshIP, r.vmNetSubnet)
	switch {
	case errors.Is(err, registrysvc.ErrNoClusterAddress):
		r.logger.Info("this node's ingest registry has no cluster address: no mesh address and no vm network, so loopback reaches everything that exists",
			"node", r.nodeName)
		return "", ""
	case err != nil:
		r.logger.Error("this node's ingest registry has no publishable cluster address", "err", err, "node", r.nodeName)
		return "", ""
	}
	clusterIP, err = registrysvc.PublishClusterService(ctx, r.clusterSvcs, r.clusterSlices, r.nodeName, r.port, addr)
	if err != nil {
		r.logger.Error("publish this node's registry Service", "err", err,
			"namespace", registrysvc.AdvertisementNamespace, "name", registrysvc.ClusterServiceName(r.nodeName))
		return "", ""
	}
	authority = registrysvc.ClusterServiceAuthority(r.nodeName, r.clusterDomain, r.port)
	r.logger.Info("published this node's ingest registry as a cluster Service",
		"namespace", registrysvc.AdvertisementNamespace, "name", registrysvc.ClusterServiceName(r.nodeName),
		"authority", authority, "clusterIP", clusterIP, "endpoint", addr.String())
	return authority, clusterIP
}

// refreshClusterService re-publishes the Service and its EndpointSlice on the
// same cadence, and for the same reason, as the advertisement: the relay address
// and the port are per-boot facts, and a repair is the only thing a re-publish
// can do — one that changes nothing issues no write at all.
func (r ingestRegistry) refreshClusterService(ctx context.Context, wg *sync.WaitGroup) {
	if r.clusterSvcs == nil || r.clusterSlices == nil {
		return
	}
	addr, err := registrysvc.ClusterEndpointAddress(r.meshIP, r.vmNetSubnet)
	if err != nil {
		return // publishClusterService already said why, once
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(registryAdvertiseRefresh)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, err := registrysvc.PublishClusterService(ctx, r.clusterSvcs, r.clusterSlices, r.nodeName, r.port, addr); err != nil {
					r.logger.Error("refresh this node's registry Service", "err", err,
						"name", registrysvc.ClusterServiceName(r.nodeName))
				}
			}
		}
	}()
}

// retractClusterService removes this node's Service and EndpointSlice, so a
// caller stops resolving a name whose backend is going away. Best effort, exactly
// as retract is.
func (r ingestRegistry) retractClusterService(ctx context.Context) {
	if r.clusterSvcs == nil || r.clusterSlices == nil {
		return
	}
	if _, err := registrysvc.ClusterEndpointAddress(r.meshIP, r.vmNetSubnet); err != nil {
		return // nothing was ever published
	}
	ctx, cancel := context.WithTimeout(ctx, registryRetractGrace)
	defer cancel()
	if err := registrysvc.RemoveClusterService(ctx, r.clusterSvcs, r.clusterSlices, r.nodeName); err != nil {
		r.logger.Warn("retract this node's registry Service", "err", err,
			"name", registrysvc.ClusterServiceName(r.nodeName))
	}
}

// relay starts the mesh/guest relay, or explains why there is none.
//
// The relay is the ONLY off-loopback exposure of the registry: the service itself
// refuses any non-loopback bind, so widening reachability is a decision made here
// and confined to the two addresses registrysvc.NewRelay admits.
func (r ingestRegistry) relay(ctx context.Context, wg *sync.WaitGroup) {
	relay, err := registrysvc.NewRelay(registrysvc.RelayConfig{
		Port:        r.port,
		MeshIP:      r.meshIP,
		VMNetSubnet: r.vmNetSubnet,
		Logger:      r.logger,
	})
	switch {
	case errors.Is(err, registrysvc.ErrNoRelayAddress):
		// Single node, no guests: loopback reaches everything that exists.
		r.logger.Info("this node's ingest registry is reachable on loopback only: no mesh address and no vm network")
		return
	case err != nil:
		r.logger.Error("ingest registry relay disabled", "err", err)
		return
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		relay.Run(ctx)
	}()
}

// retract removes this node's advertisement so a peer stops being told to dial a
// registry that is going away. Best effort by construction — a SIGKILLed node
// leaves its advertisement behind, and a peer that dials it gets the connection
// refusal its puller already reads as "this mirror does not have it".
func (r ingestRegistry) retract(ctx context.Context) {
	if registrysvc.MeshHost(r.meshIP, r.port) == "" {
		return // nothing was ever published
	}
	ctx, cancel := context.WithTimeout(ctx, registryRetractGrace)
	defer cancel()
	if err := registrysvc.RemoveAdvertisement(ctx, r.advertCMs, r.nodeName); err != nil {
		r.logger.Warn("retract this node's registry advertisement", "err", err,
			"name", registrysvc.AdvertisementName(r.nodeName))
	}
}
