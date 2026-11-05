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
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k3sm.io/k3sm/pkg/nodecred"
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
	// registryTeardownMargin is the slack on registryTeardownBound past the sum
	// of its steps' own graces: the aux goroutines' drain before the
	// retractions, and scheduling on a Mac stopping everything at once. Without
	// it a teardown that used every grace to the full would be cut off.
	registryTeardownMargin = 5 * time.Second
	// registryTeardownBound is the whole teardown startIngestRegistry returns:
	// the advertisement's retraction, the flat Service's endpoint retraction,
	// then the child's stop, run in that order, plus the margin. It is the bound the
	// control-plane stop waits on the teardown for (controlPlaneStopper.precede)
	// and the backstop's wait ends by (sharedStage), and pkg/install budgets the
	// same steps in the launchd ExitTimeOut.
	registryTeardownBound = 2*registryRetractGrace + registryShutdownGrace + registryTeardownMargin
)

// registryService is the lifetime seam `k3sm server` drives the node-local ingest
// registry through.
//
// It is declared HERE, at the consumer, and not in pkg/registrysvc: what the
// server needs is four methods, and an interface owned by the caller is what
// lets this file's wiring be tested — start ordering, the never-fatal contract,
// the KEP-1755 publish, the teardown — without a zot binary, a Go toolchain, or a
// bound port anywhere in the test.
type registryService interface {
	Start(ctx context.Context) error
	Addr() string
	Shutdown(ctx context.Context) error
	// GateCredential is the registry credential the push gate forwards an
	// authorized in-pod write with, held in memory only.
	GateCredential() registrysvc.Credential
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

// recordRegistryDisabled writes the registry's state record for a registry the
// server disabled before a Service existed to record it (the Service records its
// own transitions), so `k3sm status` reports this boot's refusal rather than a
// previous boot's state. A failed write is logged and survived.
func recordRegistryDisabled(opts serverOptions, reason string, logger *slog.Logger) {
	if opts.workDir == "" {
		return // no work dir to record in (New refuses this configuration)
	}
	st := registrysvc.State{
		State:  registrysvc.StateDisabled,
		Port:   opts.registryPort,
		Addr:   net.JoinHostPort(registrysvc.LoopbackAddress, strconv.Itoa(opts.registryPort)),
		Reason: reason,
		Since:  time.Now().UTC(),
	}
	if err := registrysvc.WriteState(opts.workDir, st); err != nil {
		logger.Warn("could not record the ingest registry state for `k3sm status`",
			"path", registrysvc.StatePath(opts.workDir), "err", err)
	}
}

// ingestRegistry is everything `k3sm server` needs to bring the node-local
// registry up: the service itself, the port, and the cluster facts that decide
// who, besides this node's own pods, can reach it and under what name.
//
// It is a struct rather than a parameter list because the fields are not
// interchangeable and several are same-typed strings: a node name, a mesh
// address and a NAT segment transposed at a call site would compile and would
// then publish one node's registry under another node's address.
type ingestRegistry struct {
	// svc is the registry service to start and stop.
	svc registryService
	// port is the loopback port it serves on: the port the discovery document
	// names for the runtime, the port peers are advertised at, the port the
	// relay binds and the flat Service's target port.
	port int
	// nodePort is --registry-node-port: the NodePort the flat Service is also
	// exposed on, or 0 for a ClusterIP Service. Only the publishing (bootstrap)
	// server's value matters, because only it writes the Service.
	nodePort int
	// nodeName is this node, the identity its advertisement and the flat
	// Service's publisher label are written under.
	nodeName string
	// nodes reads this server's own Node object, for the InternalIP addresses
	// the serving certificate names when nodePort is set. It is the retained
	// admin client the Service is written with, so it needs no new grant. nil
	// reads no Node.
	nodes registryNodeGetter
	// hostname reports the host's name for the serving certificate when
	// nodePort is set. nil is os.Hostname.
	hostname func() (string, error)
	// meshIP is this node's wireguard address, or "" on a single-node server.
	// Empty publishes no advertisement and relays on no mesh address: there is no
	// address a peer could dial.
	meshIP string
	// vmNetSubnet is the NAT segment this node's Linux guests are attached to, or
	// "" on a node that hosts none. It contributes the gateway-address relay bind,
	// which is the only way a guest can reach a host listener (a guest cannot
	// reach loopback).
	vmNetSubnet string
	// joined is a server that joined an existing control plane (--server-join).
	// It publishes neither the flat Service nor the discovery document: the
	// bootstrap server does, so two servers never fight over the one name's
	// endpoints. Its own registry still serves loopback pushes and its relay.
	joined bool
	// clusterCAPEM is the cluster CA a joined server verifies the cluster's one
	// registry against when it maps the flat name there (clusterFlatRegistry).
	// Unused on the bootstrap server, which maps the name to its own loopback.
	clusterCAPEM []byte
	// flatLookupWait bounds how long a joined server waits for the bootstrap
	// server's EndpointSlice. Zero is flatRegistryLookupWait.
	flatLookupWait time.Duration
	// workDir is where the registry's state record lives; the cluster-facing
	// facts (the published name, the certificate's expiry) are added to it.
	// Empty records nothing.
	workDir string
	// hostingCMs writes the KEP-1755 discovery document, in kube-public.
	hostingCMs registrysvc.ConfigMapClient
	// advertCMs writes and retracts this node's own advertisement, in
	// registrysvc.AdvertisementNamespace. It is a SECOND client because the two
	// objects live in different namespaces on purpose: the advertisement set is
	// namespace-isolated so the read grant a node identity gets can be scoped to
	// it (pkg/rbac), and a namespaced client is bound to one namespace.
	advertCMs registrysvc.AdvertisementClient
	// clusterSvcs and clusterSlices write the flat registry-k3sm Service and its
	// hand-written EndpointSlice in registrysvc.FlatServiceNamespace, and
	// remove this node's retired per-node Service. nil on a bring-up with no
	// cluster to publish into leaves the Service unpublished and the KEP-1755
	// document naming loopback only.
	clusterSvcs   registrysvc.ServiceClient
	clusterSlices registrysvc.EndpointSliceClient
	// clusterDomain is the cluster DNS suffix the certificate's fully
	// qualified SAN is rendered with. Empty means dns.DefaultClusterDomain.
	clusterDomain string
	// mintServing issues the relay's serving certificate for the given SANs
	// from the cluster CA, in memory. nil (no usable cluster CA) leaves the
	// relay off: it never serves plain HTTP.
	mintServing func(dnsNames []string, ips []net.IP) (tls.Certificate, error)
	// relayListen overrides how the relay binds an admitted address. nil is the
	// shipped TCP listener; a test points it at loopback.
	relayListen func(addr string) (net.Listener, error)
	// gateListen overrides how the loopback push gate binds 127.0.0.1. nil is
	// the shipped TCP listener; a test points it at a free port.
	gateListen func(addr string) (net.Listener, error)
	// gateAuth is the push gate's apiserver clients, under the gate's own
	// narrow identity (certs.RegistryGateSubject), never the admin client. An
	// incomplete one (the identity could not be minted) leaves reads served and
	// every write refused with 503.
	gateAuth registrysvc.GateAuth
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
	// ClusterRegistries are NON-loopback spellings of the same registry that
	// runtimed fetches over plain HTTP. It is empty: the relay now serves HTTPS
	// only, and the flat name is mapped by the runtime itself, verifying
	// against the cluster CA. The field stays so the seam is unchanged.
	ClusterRegistries []string
	// Flat is where this node's runtime fetches the cluster's one registry name
	// from: on the bootstrap server this registry, on loopback
	// (serverFlatRegistry); on a server that joined an existing control plane
	// the bootstrap server's, where the flat Service's EndpointSlice says it is
	// (clusterFlatRegistry), so the cluster keeps one image store. Zero on a node
	// with no registry.
	Flat flatRegistryEndpoint
}

// startIngestRegistry brings the registry up, publishes the flat registry-k3sm
// Service and the KEP-1755 discovery document (the bootstrap server only),
// this node's peer-facing advertisement, starts the HTTPS relay, and returns the
// teardown closure the caller defers. The closure is never nil, so the caller's
// `defer stop()` is unconditional.
//
// It ALSO returns the puller wiring: how runtimed should spell this node's own
// registry (registryPullerWiring), the loopback authority. The zero value on a
// registry that never started leaves runtimed's classification byte for byte as
// it was.
//
// NOTHING HERE IS FATAL. A registry that cannot build, bind or serve leaves a
// cluster that cannot ingest images; a bring-up that aborted over it leaves a
// cluster that does nothing at all. This is the same log-and-continue posture the
// ingress listeners and svclb are started under, and the opposite of the
// fail-closed RBAC and MeshPeer-CRD steps, which decide whether there is a
// working control plane at all. The one refusal that IS absolute is plain HTTP
// off loopback: with no serving certificate there is no relay.
//
// EVERYTHING IS PUBLISHED ONLY AFTER THE REGISTRY IS SERVING. A document naming
// a port nothing answers on is worse than no document: a reader that finds it
// stops looking and then fails at the push.
func startIngestRegistry(ctx context.Context, r ingestRegistry) (func(), registryPullerWiring) {
	logger := r.logger
	if err := r.svc.Start(ctx); err != nil {
		logger.Error("ingest registry disabled", "err", err)
		return func() {}, registryPullerWiring{}
	}
	r.retireNodeService(ctx)
	// The flat Service comes BEFORE the discovery document, because the
	// document's host and hostFromClusterNetwork are a claim about it, and
	// before the certificate, whose IP SANs carry its ClusterIP.
	clusterIP, published := r.publishFlatService(ctx)
	clusterHost := ""
	if published {
		clusterHost = registrysvc.FlatAuthority()
	}
	r.publishHosting(ctx, clusterHost)

	sans := &servingSANs{clusterIP: clusterIP, ext: r.nodePortSANs(ctx, registrysvc.NodePortSANs{})}
	serving := r.servingIdentity(sans, clusterHost)

	// A context of its own for the cluster-facing goroutines, so the teardown
	// can stop them WITHOUT waiting on the caller's: they must be down before the
	// registry they front is, or a peer's in-flight pull outlives its target.
	auxCtx, stopAux := context.WithCancel(ctx)
	var aux sync.WaitGroup

	r.advertise(auxCtx, &aux)
	r.refresh(auxCtx, &aux, published, sans, serving)
	r.relay(auxCtx, &aux, serving)
	r.loopbackGate(auxCtx, &aux)

	wiring := registryPullerWiring{LocalHost: registrysvc.LoopbackAuthority(r.port), Flat: r.flatRegistry(ctx)}

	return func() {
		stopAux()
		aux.Wait()
		// WithoutCancel throughout: this runs from a defer during shutdown, when
		// ctx is already cancelled, and a teardown that inherited the cancellation
		// would retract nothing and would SIGKILL the child immediately instead of
		// letting it close its storage.
		r.retract(context.WithoutCancel(ctx))
		if published {
			r.retractFlatEndpoints(context.WithoutCancel(ctx))
		}
		stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), registryShutdownGrace)
		defer cancel()
		if err := r.svc.Shutdown(stopCtx); err != nil {
			logger.Error("ingest registry shutdown", "err", err)
		}
	}, wiring
}

// flatRegistry is where this server's runtime fetches the flat name from. The
// bootstrap server publishes the name and serves it from its own registry on
// loopback. A joined server publishes nothing, and mapping the name to its own
// loopback registry would split the store: an image pushed to the cluster
// registry would be missing on it, and one pulled through it would land in a
// store no other node reads. It maps the name where every agent does instead,
// to the bootstrap server's relay, over TLS against the cluster CA.
func (r ingestRegistry) flatRegistry(ctx context.Context) flatRegistryEndpoint {
	if !r.joined {
		return serverFlatRegistry(r.port)
	}
	wait := r.flatLookupWait
	if wait == 0 {
		wait = flatRegistryLookupWait
	}
	var svcs flatServiceGetter
	if r.clusterSvcs != nil {
		svcs = r.clusterSvcs
	}
	var slices flatSliceGetter
	if r.clusterSlices != nil {
		slices = r.clusterSlices
	}
	return lookupClusterFlatRegistry(ctx, svcs, slices, r.clusterCAPEM, wait, flatRegistryLookupInterval, r.logger)
}

// servingSANs holds the SAN inputs that can change while the relay serves: the
// flat Service's ClusterIP, which a refresh may find re-assigned (the Service
// was deleted and recreated), and, with the NodePort on, the server's own
// addresses and names (registrysvc.NodePortSANs), which a refresh may find
// moved. It is guarded so the mint closure, called from TLS handshakes, reads
// it safely.
type servingSANs struct {
	mu        sync.Mutex
	clusterIP string
	ext       registrysvc.NodePortSANs
}

func (s *servingSANs) get() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clusterIP
}

// snapshot returns both inputs under one lock, so a mint never pairs one
// refresh's ClusterIP with another's NodePort names.
func (s *servingSANs) snapshot() (string, registrysvc.NodePortSANs) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clusterIP, s.ext
}

// setExt records the NodePort SANs and reports whether they changed.
func (s *servingSANs) setExt(ext registrysvc.NodePortSANs) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := !s.ext.Equal(ext)
	s.ext = ext
	return changed
}

// registryNodeGetter reads a Node object; the server's CoreV1().Nodes() is one.
type registryNodeGetter interface {
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.Node, error)
}

// registryNodeReadTimeout bounds one read of the server's own Node.
const registryNodeReadTimeout = 10 * time.Second

// nodePortSANs is the NodePort SAN set for the serving certificate: zero unless
// the registry is exposed on a NodePort, and otherwise derived from this
// server's own Node object and the host's name (registrysvc.NodePortServingSANs).
//
// A Node that is not registered yet contributes no address, which is the truth
// until it is; the next refresh picks it up and re-mints. Any other read
// failure keeps the addresses of prev, so an apiserver that is briefly not
// answering never re-mints the certificate without them.
func (r ingestRegistry) nodePortSANs(ctx context.Context, prev registrysvc.NodePortSANs) registrysvc.NodePortSANs {
	if r.nodePort == 0 {
		return registrysvc.NodePortSANs{}
	}
	hostnameFn := r.hostname
	if hostnameFn == nil {
		hostnameFn = os.Hostname
	}
	host, err := hostnameFn()
	if err != nil {
		r.logger.Warn("the registry's NodePort certificate names no hostname: the host's name cannot be read", "err", err)
		host = ""
	}
	var node *corev1.Node
	if r.nodes != nil {
		readCtx, cancel := context.WithTimeout(ctx, registryNodeReadTimeout)
		node, err = r.nodes.Get(readCtx, r.nodeName, metav1.GetOptions{})
		cancel()
		switch {
		case err == nil:
		case apierrors.IsNotFound(err):
			node = nil
		default:
			r.logger.Warn("read this server's Node for the registry's NodePort certificate; keeping the addresses it names", "err", err, "node", r.nodeName)
			ext := registrysvc.NodePortServingSANs(nil, host)
			ext.IPs = prev.IPs
			return ext
		}
	}
	return registrysvc.NodePortServingSANs(node, host)
}

// set records ip and reports whether it changed.
func (s *servingSANs) set(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := s.clusterIP != ip
	s.clusterIP = ip
	return changed
}

// publishHosting writes the KEP-1755 document on the bootstrap server.
func (r ingestRegistry) publishHosting(ctx context.Context, clusterHost string) {
	if r.joined {
		r.logger.Info("this server joined an existing control plane, so the bootstrap server publishes local-registry-hosting")
		return
	}
	if err := registrysvc.PublishHosting(ctx, r.hostingCMs, r.port, clusterHost); err != nil {
		// The registry is serving and pushes to it work; only the DISCOVERY of it
		// failed. Reporting and continuing keeps the working half working.
		r.logger.Error("publish the local-registry-hosting ConfigMap", "err", err,
			"namespace", registrysvc.HostingNamespace, "name", registrysvc.HostingConfigMapName)
		return
	}
	r.logger.Info("published local-registry-hosting for discovery",
		"namespace", registrysvc.HostingNamespace, "name", registrysvc.HostingConfigMapName,
		"addr", r.svc.Addr(), "hostFromClusterNetwork", clusterHost)
}

// servingIdentity mints the relay's serving certificate, or returns nil when
// there is no relay to serve it (no mesh address and no vm network) or no
// certificate can be minted, which leaves the relay off. Every mint is
// recorded in the state record with its expiry.
func (r ingestRegistry) servingIdentity(sans *servingSANs, clusterHost string) *registrysvc.ServingIdentity {
	if _, err := registrysvc.ClusterEndpointAddress(r.meshIP, r.vmNetSubnet); err != nil {
		return nil // no relay address: relay() says why, once
	}
	if r.mintServing == nil {
		r.logger.Error("the ingest registry relay is off: no cluster CA to issue its serving certificate, and it never serves plain HTTP")
		return nil
	}
	serving, err := registrysvc.NewServingIdentity(registrysvc.ServingConfig{
		Mint: func() (tls.Certificate, error) {
			return r.mintServing(r.servingSANSet(sans))
		},
		Margin: nodecred.ExpiryMargin,
		OnMint: func(notAfter time.Time) {
			dnsNames, ips := r.servingSANSet(sans)
			r.logger.Info("minted the ingest registry's serving certificate from the cluster CA (in memory, never written to disk)",
				"dns", dnsNames, "ips", ips, "clusterIP", sans.get(), "not_after", notAfter.UTC().Format(time.RFC3339))
			r.recordClusterFacing(registrysvc.ClusterFacing{Service: clusterHost, CertNotAfter: notAfter})
		},
		Logger: r.logger,
	})
	if err != nil {
		r.logger.Error("the ingest registry relay is off: its serving certificate could not be minted, and it never serves plain HTTP", "err", err)
		return nil
	}
	return serving
}

// servingSANSet is the SAN set the next serving certificate is minted with: the
// in-cluster set, plus the NodePort names when the NodePort is on
// (registrysvc.RelayServingSANs).
func (r ingestRegistry) servingSANSet(sans *servingSANs) ([]string, []net.IP) {
	clusterIP, ext := sans.snapshot()
	return registrysvc.RelayServingSANs(r.clusterDomain, clusterIP, r.meshIP, r.vmNetSubnet, ext)
}

// recordClusterFacing adds the cluster-facing facts to the state record. A
// failed write is logged and survived: the record is a report.
func (r ingestRegistry) recordClusterFacing(f registrysvc.ClusterFacing) {
	if r.workDir == "" {
		return
	}
	if err := registrysvc.UpdateClusterFacing(r.workDir, f); err != nil {
		r.logger.Warn("could not record the ingest registry's cluster-facing state for `k3sm status`",
			"path", registrysvc.StatePath(r.workDir), "err", err)
	}
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

// retireNodeService removes this node's per-node registry-<node> Service and
// its EndpointSlice, which earlier releases published. Best effort: nothing
// depends on it being gone, and a NotFound (every boot after the first) is
// success.
func (r ingestRegistry) retireNodeService(ctx context.Context) {
	if r.clusterSvcs == nil || r.clusterSlices == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, registryRetractGrace)
	defer cancel()
	if err := registrysvc.RemoveClusterService(ctx, r.clusterSvcs, r.clusterSlices, r.nodeName); err != nil {
		r.logger.Warn("remove this node's retired per-node registry Service", "err", err,
			"name", registrysvc.ClusterServiceName(r.nodeName))
	}
	if r.joined {
		return
	}
	// The bootstrap server also sweeps the retired Services of nodes that are
	// gone, which no surviving server would otherwise remove.
	if err := registrysvc.RemoveRetiredNodeServices(ctx, r.clusterSvcs, r.clusterSlices); err != nil {
		r.logger.Warn("sweep the retired per-node registry Services", "err", err)
	}
}

// publishFlatService publishes the flat registry-k3sm Service and its
// hand-written EndpointSlice, and returns the ClusterIP the apiserver assigned
// and whether the Service is published.
//
// It publishes nothing, and says why once at Info, when this server joined an
// existing control plane (the bootstrap server publishes), when there are no
// cluster clients, and when there is no relay address (a single Mac with no
// mesh and no vm network, where loopback already reaches everything that
// exists). A publish FAILURE also yields false: publishing a host for a
// Service that does not exist would send every reader at a name that
// resolves to nothing.
func (r ingestRegistry) publishFlatService(ctx context.Context) (clusterIP string, published bool) {
	if r.joined {
		r.logger.Info("this server joined an existing control plane, so the bootstrap server publishes the registry Service",
			"name", registrysvc.FlatServiceName)
		return "", false
	}
	if r.clusterSvcs == nil || r.clusterSlices == nil {
		return "", false
	}
	addr, err := registrysvc.ClusterEndpointAddress(r.meshIP, r.vmNetSubnet)
	switch {
	case errors.Is(err, registrysvc.ErrNoClusterAddress):
		r.logger.Info("the ingest registry has no cluster address: no mesh address and no vm network, so loopback reaches everything that exists",
			"node", r.nodeName)
		return "", false
	case err != nil:
		r.logger.Error("the ingest registry has no publishable cluster address", "err", err, "node", r.nodeName)
		return "", false
	}
	clusterIP, err = r.publishFlat(ctx, addr)
	if err != nil {
		r.logger.Error("publish the registry Service", "err", err,
			"namespace", registrysvc.FlatServiceNamespace, "name", registrysvc.FlatServiceName)
		return "", false
	}
	r.logger.Info("published the ingest registry as the cluster Service",
		"namespace", registrysvc.FlatServiceNamespace, "name", registrysvc.FlatServiceName,
		"authority", registrysvc.FlatAuthority(), "clusterIP", clusterIP, "endpoint", addr.String(),
		"nodePort", r.nodePort)
	return clusterIP, true
}

// publishFlat publishes the flat Service with the opt-in NodePort, and, when
// that publish fails, publishes it again without one. The NodePort is an extra
// way in for tools off the cluster; a port the apiserver will not allocate (one
// another Service holds) must not take the cluster's own registry name away with
// it, so the failure is reported at Error and the in-cluster Service still
// stands. The next refresh tries the NodePort again.
//
// The fallback is not silent: the caller sees success, because the in-cluster
// Service is published, but the state record carries the NodePort error
// (State.NodePortError) until a publish with the NodePort succeeds again.
func (r ingestRegistry) publishFlat(ctx context.Context, addr netip.Addr) (string, error) {
	ip, err := registrysvc.PublishFlatService(ctx, r.clusterSvcs, r.clusterSlices, r.nodeName, r.port, r.nodePort, addr)
	if r.nodePort == 0 {
		return ip, err
	}
	if err == nil {
		r.recordNodePortError("")
		return ip, nil
	}
	r.logger.Error("expose the registry on its NodePort; publishing the cluster Service without it",
		"err", err, "nodePort", r.nodePort, "name", registrysvc.FlatServiceName)
	r.recordNodePortError(fmt.Sprintf("publish NodePort %d: %v", r.nodePort, err))
	return registrysvc.PublishFlatService(ctx, r.clusterSvcs, r.clusterSlices, r.nodeName, r.port, 0, addr)
}

// recordNodePortError writes the NodePort publish outcome into the state
// record: reason when the Service fell back to ClusterIP, "" on success. A
// failed write is logged and survived: the record is a report.
func (r ingestRegistry) recordNodePortError(reason string) {
	if r.workDir == "" {
		return
	}
	if err := registrysvc.UpdateNodePortError(r.workDir, reason); err != nil {
		r.logger.Warn("could not record the ingest registry's NodePort state",
			"path", registrysvc.StatePath(r.workDir), "err", err)
	}
}

// refresh re-publishes the flat Service on the advertisement's cadence and
// keeps the serving certificate current: it is replaced inside its expiry
// margin, and at once when a re-publish finds the ClusterIP changed (an IP SAN
// would otherwise name the old VIP) or, with the NodePort on, when the server's
// own addresses or names moved. A re-publish that changes nothing issues no
// write at all.
func (r ingestRegistry) refresh(ctx context.Context, wg *sync.WaitGroup, published bool, sans *servingSANs, serving *registrysvc.ServingIdentity) {
	if !published && serving == nil {
		return
	}
	addr, addrErr := registrysvc.ClusterEndpointAddress(r.meshIP, r.vmNetSubnet)
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
			}
			rotate := false
			if published && addrErr == nil {
				ip, err := r.publishFlat(ctx, addr)
				switch {
				case err != nil:
					r.logger.Error("refresh the registry Service", "err", err, "name", registrysvc.FlatServiceName)
				case sans.set(ip):
					rotate = true
				}
			}
			if r.nodePort != 0 {
				_, prev := sans.snapshot()
				if sans.setExt(r.nodePortSANs(ctx, prev)) {
					rotate = true
				}
			}
			if rotate && serving != nil {
				if err := serving.Rotate(); err != nil {
					dnsNames, ips := r.servingSANSet(sans)
					r.logger.Error("re-mint the ingest registry's serving certificate for its changed names", "err", err, "dns", dnsNames, "ips", ips)
				}
			}
			if serving != nil {
				serving.Refresh()
			}
		}
	}()
}

// retractFlatEndpoints removes the flat Service's EndpointSlice and keeps the
// Service, so a caller fails fast while the server is down and the ClusterIP
// is the same when it is back. Best effort, exactly as retract is.
func (r ingestRegistry) retractFlatEndpoints(ctx context.Context) {
	if r.clusterSlices == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, registryRetractGrace)
	defer cancel()
	if err := registrysvc.RemoveFlatEndpointSlice(ctx, r.clusterSlices); err != nil {
		r.logger.Warn("retract the registry Service's endpoints", "err", err, "name", registrysvc.FlatServiceName)
	}
}

// relay starts the mesh/guest relay over HTTPS, or explains why there is none.
//
// The relay is the ONLY off-loopback exposure of the registry: the service itself
// refuses any non-loopback bind, so widening reachability is a decision made here
// and confined to the two addresses registrysvc.NewRelay admits. With no serving
// certificate NewRelay refuses (registrysvc.ErrNoServingIdentity): there is no
// plain-HTTP relay.
func (r ingestRegistry) relay(ctx context.Context, wg *sync.WaitGroup, serving *registrysvc.ServingIdentity) {
	relay, err := registrysvc.NewRelay(registrysvc.RelayConfig{
		Port:           r.port,
		MeshIP:         r.meshIP,
		VMNetSubnet:    r.vmNetSubnet,
		Auth:           r.gateAuth,
		GateCredential: r.svc.GateCredential(),
		Serving:        serving,
		Listen:         r.relayListen,
		Logger:         r.logger,
	})
	switch {
	case errors.Is(err, registrysvc.ErrNoRelayAddress):
		// Single node, no guests: loopback reaches everything that exists.
		r.logger.Info("this node's ingest registry is reachable on loopback only: no mesh address and no vm network")
		return
	case errors.Is(err, registrysvc.ErrNoServingIdentity):
		return // servingIdentity already said why, once
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

// loopbackGate serves the push gate on 127.0.0.1:GatePort(port) over HTTPS,
// whether or not a mesh or vm guests exist, so the k3sm CLI and Mac tools on
// this server push with a builder token the gate checks. Its certificate is
// its own, issued by the cluster CA for localhost, 127.0.0.1 and registry-k3sm,
// and is never written to disk. With no cluster CA there is no gate: it never
// serves plain HTTP. The port is recorded in the state record once bound, which
// is how the CLI finds it.
func (r ingestRegistry) loopbackGate(ctx context.Context, wg *sync.WaitGroup) {
	port := registrysvc.GatePort(r.port)
	if r.mintServing == nil {
		r.logger.Error("the loopback push gate is off: no cluster CA to issue its serving certificate, and it never serves plain HTTP")
		return
	}
	dnsNames, ips := registrysvc.LoopbackGateDNSNames(), registrysvc.LoopbackGateIPs()
	serving, err := registrysvc.NewServingIdentity(registrysvc.ServingConfig{
		Mint:   func() (tls.Certificate, error) { return r.mintServing(dnsNames, ips) },
		Margin: nodecred.ExpiryMargin,
		Logger: r.logger,
	})
	if err != nil {
		r.logger.Error("the loopback push gate is off: its serving certificate could not be minted", "err", err)
		return
	}
	gate, err := registrysvc.NewLoopbackGate(registrysvc.LoopbackGateConfig{
		RegistryPort:   r.port,
		Port:           port,
		Auth:           r.gateAuth,
		GateCredential: r.svc.GateCredential(),
		Serving:        serving,
		Listen:         r.gateListen,
		OnListen: func(addr string) {
			r.logger.Info("serving the push gate on loopback for this Mac's pushes", "addr", addr)
			if r.workDir == "" {
				return
			}
			if err := registrysvc.RecordGatePort(r.workDir, port); err != nil {
				r.logger.Warn("could not record the loopback push gate's port; this Mac's pushes cannot find it",
					"path", registrysvc.StatePath(r.workDir), "err", err)
			}
		},
		Logger: r.logger,
	})
	if err != nil {
		r.logger.Error("the loopback push gate is off", "err", err)
		return
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		gate.Run(ctx)
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
