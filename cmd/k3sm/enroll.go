package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/podnet"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
)

// meshEnroller is the server-side, controller-mediated mesh enroll
// (bootstrap.Enroller). It assigns the joining node a unique pod /24 from the cluster
// pod CIDR, derives its mesh-egress /32, writes THIS node's MeshPeer to the apiserver
// (named == nodeName, so bootstrap's write-guard holds — a node never writes a peer
// for any other node), and returns the current peer snapshot.
//
// Locking discipline: mu serializes the assign→write so two concurrent joins do not
// claim the same /24. podCIDR assignment is by current MeshPeer count (index 0 is
// reserved for the control-plane node); it is a dev-scale scheme — robust index
// recycling across node deletes is an M4 concern.
type meshEnroller struct {
	client     rest.Interface
	clusterPod netip.Prefix
	log        *slog.Logger
	mu         sync.Mutex
}

// newMeshEnroller builds the enroller over the cluster REST config (the typed
// MeshPeer client mirrors darwin-net's NewWatcher construction).
func newMeshEnroller(cfg *rest.Config, log *slog.Logger) (*meshEnroller, error) {
	client, err := meshPeerRESTClient(cfg)
	if err != nil {
		return nil, err
	}
	return &meshEnroller{client: client, clusterPod: podnet.ClusterPodCIDR, log: log}, nil
}

// Enroll implements bootstrap.Enroller.
func (e *meshEnroller) Enroll(ctx context.Context, nodeName string, req netv1.MeshEnrollRequest) (netv1.MeshEnrollResponse, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	existing, err := e.listPeers(ctx)
	if err != nil {
		return netv1.MeshEnrollResponse{}, fmt.Errorf("list mesh peers: %w", err)
	}

	// Reuse this node's already-assigned CIDR on a rejoin; else assign the next /24.
	podCIDR := ""
	for _, p := range existing {
		if p.NodeName == nodeName {
			podCIDR = p.PodCIDR
		}
	}
	if podCIDR == "" {
		cidr, err := podnet.NodeCIDR(e.clusterPod, len(existing)+1)
		if err != nil {
			return netv1.MeshEnrollResponse{}, fmt.Errorf("assign podCIDR: %w", err)
		}
		podCIDR = cidr.String()
	}
	prefix, err := netip.ParsePrefix(podCIDR)
	if err != nil {
		return netv1.MeshEnrollResponse{}, fmt.Errorf("parse assigned podCIDR %q: %w", podCIDR, err)
	}
	meshIP, err := podnet.MeshEgressIP(prefix)
	if err != nil {
		return netv1.MeshEnrollResponse{}, fmt.Errorf("derive mesh-egress IP: %w", err)
	}

	peer, err := bootstrap.BuildMeshPeer(nodeName, podCIDR, meshIP.String(), req)
	if err != nil {
		return netv1.MeshEnrollResponse{}, err
	}
	if err := e.writePeer(ctx, peer); err != nil {
		return netv1.MeshEnrollResponse{}, fmt.Errorf("write mesh peer %q: %w", nodeName, err)
	}

	// Snapshot the (now-current) peer set for the joining node to program immediately.
	peers, err := e.listPeers(ctx)
	if err != nil {
		return netv1.MeshEnrollResponse{}, fmt.Errorf("snapshot mesh peers: %w", err)
	}
	return netv1.MeshEnrollResponse{
		NodeName: nodeName,
		PodCIDR:  podCIDR,
		MeshIP:   meshIP.String(),
		Peers:    peers,
	}.WithDefaults(), nil
}

// listPeers returns the current MeshPeer specs from the apiserver.
func (e *meshEnroller) listPeers(ctx context.Context) ([]netv1.MeshPeerSpec, error) {
	var list netv1.MeshPeerList
	if err := e.client.Get().Resource(meshPeerResource).Do(ctx).Into(&list); err != nil {
		return nil, err
	}
	specs := make([]netv1.MeshPeerSpec, 0, len(list.Items))
	for i := range list.Items {
		specs = append(specs, list.Items[i].Spec)
	}
	return specs, nil
}

// writePeer creates the MeshPeer, or updates it in place on a rejoin (AlreadyExists).
func (e *meshEnroller) writePeer(ctx context.Context, peer *netv1.MeshPeer) error {
	err := e.client.Post().Resource(meshPeerResource).Body(peer).Do(ctx).Into(&netv1.MeshPeer{})
	if err == nil {
		return nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return err
	}
	var cur netv1.MeshPeer
	if err := e.client.Get().Resource(meshPeerResource).Name(peer.Name).Do(ctx).Into(&cur); err != nil {
		return err
	}
	peer.ResourceVersion = cur.ResourceVersion
	return e.client.Put().Resource(meshPeerResource).Name(peer.Name).Body(peer).Do(ctx).Into(&netv1.MeshPeer{})
}

// meshPeerResource is the MeshPeer CRD resource name within net.k3sm.io/v1.
const meshPeerResource = "meshpeers"

// meshPeerRESTClient builds a typed REST client for the MeshPeer GVK, registering the
// net.k3sm.io/v1 scheme (the same construction darwin-net's mesh watcher uses).
func meshPeerRESTClient(cfg *rest.Config) (rest.Interface, error) {
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("register net.k3sm.io scheme: %w", err)
	}
	codecs := serializer.NewCodecFactory(scheme)
	rc := rest.CopyConfig(cfg)
	rc.GroupVersion = &netv1.SchemeGroupVersion
	rc.APIPath = "/apis"
	rc.NegotiatedSerializer = codecs.WithoutConversion()
	return rest.RESTClientFor(rc)
}

// bootstrapPort is the dedicated TLS port the supervisor's worker-join endpoint binds
// on the mesh interface (separate from the apiserver secure port).
const bootstrapPort = 9345

// startBootstrapServer serves the worker-join endpoint on meshIP:bootstrapPort over a
// TLS listener presenting [serving-leaf, cluster-CA] so a joining node's CA-hash pin
// verifies. It blocks until ctx is cancelled, then shuts down. This is the live,
// mesh-bound supervisor — its end-to-end exercise is the two-Mac K3SM_LAB gate (the
// MeshPeer CRD must be installed for the enroller's write to land).
func startBootstrapServer(ctx context.Context, h *certs.Hierarchy, meshIP string, tokens bootstrap.TokenVerifier, enroller bootstrap.Enroller, log *slog.Logger) error {
	srv, err := bootstrap.NewServer(bootstrap.ServerConfig{
		ClusterCA:     h.Cluster,
		SigningCA:     h.Signing,
		Tokens:        tokens,
		NodePasswords: bootstrap.NewMemoryNodePasswords(),
		Enroller:      enroller,
		Logger:        log,
	})
	if err != nil {
		return fmt.Errorf("build bootstrap server: %w", err)
	}

	servingChain, err := h.Cluster.ServingChainTLS("k3sm-supervisor",
		[]string{"localhost"}, []net.IP{net.ParseIP(meshIP), net.ParseIP("127.0.0.1")}, 365*24*time.Hour)
	if err != nil {
		return fmt.Errorf("supervisor serving cert: %w", err)
	}

	hs := &http.Server{
		Addr:              net.JoinHostPort(meshIP, fmt.Sprintf("%d", bootstrapPort)),
		Handler:           srv.Handler(),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{servingChain}},
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(shutCtx)
	}()
	log.Info("bootstrap supervisor listening", "addr", hs.Addr)
	if err := hs.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("bootstrap server: %w", err)
	}
	return nil
}
