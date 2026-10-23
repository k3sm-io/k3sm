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

package registrysvc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"k3sm.io/darwin-net/pkg/dns"
)

// The FLAT REGISTRY SERVICE: one cluster name, registry-k3sm, at which the
// server's ingest registry answers every class of caller, a native Pod and a
// Linux vm guest alike, on every node of the cluster.
//
// It is a SELECTOR-LESS Service plus a hand-written EndpointSlice, which is the
// standard Kubernetes way to give a cluster name to something the cluster does
// not schedule. Nothing here selects a Pod because there is no Pod: the registry
// is a child process of the server, reached through the relay's non-loopback
// bind (relay.go), which terminates TLS in front of it. The Service is a NAME and
// a VIP; the relay is the thing that answers.
//
// ONE SERVICE FOR THE CLUSTER, published by one server. The server's registry
// is the cluster's one image store, so there is exactly one backend to name.
// With several servers, the bootstrap server (the one that did not join with
// --server-join) publishes it and the others publish nothing, so two servers
// never fight over its one EndpointSlice.
//
// THE NAME IS FLAT and lives in one namespace, but a bare Service name resolves
// only inside its own namespace through a standard resolv.conf. Cluster DNS
// answers registry-k3sm from every namespace (darwin-net's resolver), and the
// node runtime maps the same name to this registry; both spell it with the
// literals below, and a change here is a change there.
//
// WHY THE ENDPOINT IS A RELAY ADDRESS. EndpointSlice validation refuses a
// loopback address outright, so the registry's own 127.0.0.1 listener can never
// be an endpoint, and that refusal is the loopback invariant enforced by the
// apiserver rather than merely respected here. The address published is one the
// relay actually binds, taken from the same relayBinds that decides the binds:
// the mesh address when the server has one (reachable from every node), else
// the vm NAT gateway (reachable only from this Mac's own guests, which on a
// single Mac is every caller there is). A server with neither has no relay, so
// it publishes no Service; there is nothing that would answer.
//
// THE PER-NODE SERVICES ARE RETIRED. Earlier releases published one
// registry-<node> Service per node; a server now removes its own stale one at
// start (RemoveClusterService) and never publishes it again.
//
// RBAC: nothing new. The publisher is the server's retained admin client, the
// same one that writes the advertisement ConfigMaps, and the readers (a node's
// Service proxy and DNS resolver) already hold cluster-wide get/list/watch on
// services and endpointslices through the k3sm:node-datapath ClusterRole
// (pkg/rbac).
const (
	// FlatServiceName is the registry's one cluster name. darwin-net's cluster
	// DNS resolver and the node runtime's registry mapping spell the same
	// literal; change all three together or not at all.
	FlatServiceName = "registry-k3sm"
	// FlatServiceNamespace is the namespace the Service lives in. It is the
	// advertisement namespace (AdvertisementNamespace), spelled again here
	// because darwin-net and the runtime mapping read this literal; a test pins
	// that the two agree.
	FlatServiceNamespace = "k3sm-registry"
	// FlatServicePort is the Service port, and the port every image reference
	// carries: registry-k3sm:6450/<repo>. It is fixed whatever --registry-port
	// says, because a reference written into a Pod spec must not change with a
	// server flag; the target port follows the flag. darwin-net and the runtime
	// mapping use the same literal.
	FlatServicePort = 6450
	// ClusterServicePrefix prefixed the retired per-node registry Services
	// (registry-<node>). It is kept so a server can find and remove its own
	// stale one.
	ClusterServicePrefix = "registry-"
	// ClusterServicePortName names the single port on both objects. The Service
	// port name and the EndpointSlice port name MUST agree: that name is what
	// kube-proxy (and darwin-net's userspace proxy) matches a backend port by, so
	// a mismatch yields a Service with a VIP and no backends.
	ClusterServicePortName = "registry"
	// clusterServiceNodeLabel records the publishing server on both objects.
	clusterServiceNodeLabel = "k3sm.io/registry-node"
	// clusterServiceManagedLabel marks both objects as k3sm's, matching the
	// convention pkg/rbac and pkg/policy use for objects k3sm provisions.
	clusterServiceManagedLabel = "k3sm.io/managed"
	// clusterServiceManagedBy is the standard EndpointSlice "who writes this"
	// label. It is set because this slice is HAND-WRITTEN: the value tells an
	// operator (and any controller that reconciles slices) that no endpoint
	// controller owns it.
	clusterServiceManagedBy = "endpointslice.kubernetes.io/managed-by"
	// clusterServiceManager is this package, as the managed-by value. It is
	// spelled as a reverse-DNS NAME because this is a label VALUE: a value may
	// not contain "/", and the apiserver rejects the whole object if it does.
	clusterServiceManager = "registrysvc.k3sm.io"
)

// ErrNoClusterAddress reports that this node has no address a cluster caller
// could be sent to — no mesh address and no vm NAT segment — so there is no
// Service to publish.
//
// It is a SENTINEL for the same reason ErrNoMeshAddress is: on a single-Mac
// cluster that hosts no guests it is the expected non-event, not a failure. It
// wraps ErrNoRelayAddress, because it is the same fact seen from the other side —
// no relay bind means no endpoint.
var ErrNoClusterAddress = fmt.Errorf("%w, so the ingest registry has no cluster address", ErrNoRelayAddress)

// ServiceClient is the slice of the Kubernetes API the Service publisher needs,
// declared HERE at the consumer for the same reason AdvertisementClient is: a
// caller passes `cs.CoreV1().Services(AdvertisementNamespace)`, which satisfies it
// structurally, and a test passes a fake with no client-go machinery.
type ServiceClient interface {
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.Service, error)
	Create(ctx context.Context, svc *corev1.Service, opts metav1.CreateOptions) (*corev1.Service, error)
	Update(ctx context.Context, svc *corev1.Service, opts metav1.UpdateOptions) (*corev1.Service, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
}

// EndpointSliceClient is the slice of the Kubernetes API the EndpointSlice
// publisher needs. It is a SEPARATE interface from ServiceClient rather than a
// generic one because the two objects live in different API groups and a
// namespaced client is bound to one resource.
type EndpointSliceClient interface {
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*discoveryv1.EndpointSlice, error)
	Create(ctx context.Context, es *discoveryv1.EndpointSlice, opts metav1.CreateOptions) (*discoveryv1.EndpointSlice, error)
	Update(ctx context.Context, es *discoveryv1.EndpointSlice, opts metav1.UpdateOptions) (*discoveryv1.EndpointSlice, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
}

// ClusterServiceName returns the name of node's retired per-node registry
// Service (and its EndpointSlice), which a server removes at start.
func ClusterServiceName(node string) string {
	return ClusterServicePrefix + node
}

// FlatAuthority is the authority every image reference names the registry by:
// "registry-k3sm:6450". It carries the port on purpose, and must: a reference
// whose first component has no port and no dot is a Docker Hub repository by
// the OCI rule, so registry-k3sm/app would be pulled from Docker Hub.
func FlatAuthority() string {
	return net.JoinHostPort(FlatServiceName, strconv.Itoa(FlatServicePort))
}

// FlatServiceDNSNames returns every DNS name a caller in the cluster may reach
// the Service by: the flat name, then each search-suffixed form a standard Pod
// resolv.conf expands it through, ending with the fully qualified one. They are
// the DNS SANs of the relay's serving certificate, so a client verifies the
// registry under whichever spelling it dialled. An empty cluster domain means
// dns.DefaultClusterDomain.
func FlatServiceDNSNames(clusterDomain string) []string {
	domain := clusterDomain
	if domain == "" {
		domain = dns.DefaultClusterDomain
	}
	ns := FlatServiceName + "." + FlatServiceNamespace
	return []string{
		FlatServiceName,
		ns,
		ns + ".svc",
		ns + ".svc." + domain,
	}
}

// FlatServingIPs returns the IP SANs of the relay's serving certificate: the
// Service's ClusterIP (a caller that resolved the name, or has no DNS, dials
// it), then the server's mesh address and its vm NAT gateway (the addresses the
// relay itself binds, which the proxy dials as the endpoint). Each that is
// empty or unparsable is left out, never spliced in as text.
func FlatServingIPs(clusterIP, meshIP, vmNetSubnet string) []net.IP {
	var out []net.IP
	add := func(a netip.Addr) {
		if !a.IsValid() || a.IsUnspecified() {
			return
		}
		ip := net.IP(a.AsSlice())
		for _, have := range out {
			if have.Equal(ip) {
				return
			}
		}
		out = append(out, ip)
	}
	if a, err := netip.ParseAddr(clusterIP); err == nil {
		add(a)
	}
	if a, err := netip.ParseAddr(meshIP); err == nil {
		add(a)
	}
	if vmNetSubnet != "" {
		if gw, err := VMNetGateway(vmNetSubnet); err == nil {
			add(gw)
		}
	}
	return out
}

// LoopbackAuthority renders this node's own ingest registry as the loopback
// authority a reference names it by — "localhost:<port>".
//
// It is spelled `localhost` and not 127.0.0.1 for the same reason the KEP-1755
// document is: the OCI toolchain special-cases the literal name as an insecure
// registry, and this is the authority a bare-name pull is rewritten to, so it is
// the string that ends up in an image reference an operator reads back.
func LoopbackAuthority(port int) string {
	if port <= 0 || port > 65535 {
		return ""
	}
	return net.JoinHostPort("localhost", strconv.Itoa(port))
}

// ClusterEndpointAddress returns the address the flat Service sends a caller
// to: the mesh address when this node has one, else the vm NAT gateway.
//
// It is DERIVED from relayBinds rather than computed again, and that is the
// point: the endpoint is by construction an address the relay actually binds, in
// the relay's own preference order. It therefore inherits the relay's whole bind
// discipline — a loopback or wildcard "mesh address" is refused with
// ErrNonRelayableBind here exactly as it is there, so a Service can never be
// published pointing at the registry's own loopback listener (which the apiserver
// would refuse anyway) or at a network nobody enrolled.
//
// Neither address configured is ErrNoClusterAddress, the single-node non-event.
func ClusterEndpointAddress(meshIP, vmNetSubnet string) (netip.Addr, error) {
	binds, err := relayBinds(meshIP, vmNetSubnet)
	if errors.Is(err, ErrNoRelayAddress) {
		return netip.Addr{}, ErrNoClusterAddress
	}
	if err != nil {
		return netip.Addr{}, err
	}
	return binds[0], nil
}

// FlatService renders the registry's selector-less Service, published by the
// server named publisher, whose registry listens on targetPort.
//
// The Service port is FlatServicePort whatever the registry's own port is,
// because the port is part of every image reference; the target port is the
// port the relay listens on, which is the registry's.
func FlatService(publisher string, targetPort int) (*corev1.Service, error) {
	if publisher == "" {
		return nil, errors.New("publish the registry Service: the publishing server's node name is empty")
	}
	if targetPort <= 0 || targetPort > 65535 {
		return nil, fmt.Errorf("publish the registry Service: port %d is out of range 1-65535", targetPort)
	}
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      FlatServiceName,
			Namespace: FlatServiceNamespace,
			Labels:    clusterServiceLabels(publisher),
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			// No Selector, and that is the whole shape: there is no Pod behind
			// this Service, so the endpoints are written by hand below.
			Ports: []corev1.ServicePort{{
				Name:       ClusterServicePortName,
				Protocol:   corev1.ProtocolTCP,
				Port:       FlatServicePort,
				TargetPort: intstr.FromInt32(int32(targetPort)),
			}},
		},
	}, nil
}

// FlatEndpointSlice renders the hand-written EndpointSlice backing the Service
// with the single relay address addr, on targetPort.
//
// It REFUSES a loopback address with ErrNonRelayableBind. The apiserver refuses
// one too, so this is not the only guard; it is the guard that names the reason
// at the place the decision is made.
func FlatEndpointSlice(publisher string, targetPort int, addr netip.Addr) (*discoveryv1.EndpointSlice, error) {
	if publisher == "" {
		return nil, errors.New("publish the registry EndpointSlice: the publishing server's node name is empty")
	}
	if targetPort <= 0 || targetPort > 65535 {
		return nil, fmt.Errorf("publish the registry EndpointSlice: port %d is out of range 1-65535", targetPort)
	}
	if !addr.IsValid() || addr.IsUnspecified() {
		return nil, fmt.Errorf("%w: %q is not an address a cluster caller can be sent to", ErrNonRelayableBind, addr.String())
	}
	if addr.IsLoopback() {
		return nil, fmt.Errorf("%w: %s is loopback, which is every caller's own address", ErrNonRelayableBind, addr)
	}
	if !addr.Is4() {
		return nil, fmt.Errorf("%w: %s is not an IPv4 address, and the slice is IPv4", ErrNonRelayableBind, addr)
	}
	portName := ClusterServicePortName
	portNum := int32(targetPort)
	ready := true
	labels := clusterServiceLabels(publisher)
	labels[discoveryv1.LabelServiceName] = FlatServiceName
	labels[clusterServiceManagedBy] = clusterServiceManager
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      FlatServiceName,
			Namespace: FlatServiceNamespace,
			Labels:    labels,
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports: []discoveryv1.EndpointPort{{
			Name:     &portName,
			Protocol: ptrProtocol(corev1.ProtocolTCP),
			Port:     &portNum,
		}},
		Endpoints: []discoveryv1.Endpoint{{
			Addresses: []string{addr.String()},
			// Ready must be EXPLICIT: a nil Ready is read as not-ready by
			// Kubernetes and by darwin-net's proxy alike, which would leave the
			// Service with a VIP and no backend.
			Conditions: discoveryv1.EndpointConditions{Ready: &ready},
		}},
	}, nil
}

// PublishFlatService creates or refreshes the Service and its EndpointSlice.
//
// The SERVICE IS PUBLISHED FIRST so its ClusterIP exists before anything reports
// an address, and the assigned ClusterIP is RETURNED: it is the VIP a caller
// dials and an IP SAN of the relay's certificate.
//
// Both objects REFRESH rather than being created once: the target port and the
// relay address are per-boot facts, and a stale endpoint would send every caller
// to an address nothing answers on. A refresh mutates only the fields this
// package owns and is built from the object that was READ, so the
// resourceVersion is live and a concurrent writer loses the conflict instead of
// being silently overwritten, most of all the ClusterIP, which the apiserver
// assigned and which is immutable.
func PublishFlatService(ctx context.Context, svcs ServiceClient, slices EndpointSliceClient, publisher string, targetPort int, addr netip.Addr) (string, error) {
	wantSvc, err := FlatService(publisher, targetPort)
	if err != nil {
		return "", err
	}
	wantSlice, err := FlatEndpointSlice(publisher, targetPort, addr)
	if err != nil {
		return "", err
	}
	clusterIP, err := publishService(ctx, svcs, wantSvc)
	if err != nil {
		return "", err
	}
	if err := publishEndpointSlice(ctx, slices, wantSlice); err != nil {
		return clusterIP, err
	}
	return clusterIP, nil
}

// publishService creates or refreshes want and returns the live ClusterIP.
func publishService(ctx context.Context, c ServiceClient, want *corev1.Service) (string, error) {
	existing, err := c.Get(ctx, want.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		created, cerr := c.Create(ctx, want, metav1.CreateOptions{})
		if cerr != nil {
			return "", fmt.Errorf("create the %s Service: %w", want.Name, cerr)
		}
		return created.Spec.ClusterIP, nil
	}
	if err != nil {
		return "", fmt.Errorf("read the %s Service: %w", want.Name, err)
	}
	if samePorts(existing.Spec.Ports, want.Spec.Ports) && existing.Spec.Selector == nil {
		return existing.Spec.ClusterIP, nil
	}
	updated := existing.DeepCopy()
	updated.Spec.Ports = want.Spec.Ports
	// A selector arriving on this object would hand it to the EndpointSlice
	// controller, which would then delete the hand-written slice as orphaned.
	updated.Spec.Selector = nil
	if updated.Labels == nil {
		updated.Labels = map[string]string{}
	}
	for k, v := range want.Labels {
		updated.Labels[k] = v
	}
	out, uerr := c.Update(ctx, updated, metav1.UpdateOptions{})
	if uerr != nil {
		return existing.Spec.ClusterIP, fmt.Errorf("refresh the %s Service: %w", want.Name, uerr)
	}
	return out.Spec.ClusterIP, nil
}

// publishEndpointSlice creates or refreshes want.
func publishEndpointSlice(ctx context.Context, c EndpointSliceClient, want *discoveryv1.EndpointSlice) error {
	existing, err := c.Get(ctx, want.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		if _, cerr := c.Create(ctx, want, metav1.CreateOptions{}); cerr != nil {
			return fmt.Errorf("create the %s EndpointSlice: %w", want.Name, cerr)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read the %s EndpointSlice: %w", want.Name, err)
	}
	if sameSlice(existing, want) {
		return nil
	}
	updated := existing.DeepCopy()
	updated.AddressType = want.AddressType
	updated.Ports = want.Ports
	updated.Endpoints = want.Endpoints
	if updated.Labels == nil {
		updated.Labels = map[string]string{}
	}
	for k, v := range want.Labels {
		updated.Labels[k] = v
	}
	if _, uerr := c.Update(ctx, updated, metav1.UpdateOptions{}); uerr != nil {
		return fmt.Errorf("refresh the %s EndpointSlice: %w", want.Name, uerr)
	}
	return nil
}

// RemoveFlatService retracts the Service and its EndpointSlice: what a server
// started with the registry off (--registry-port 0) does, so no Pod resolves a
// name whose backend is gone for good. A NotFound is success: there is nothing
// to retract, which is the state this call wanted.
//
// The SLICE GOES FIRST, so the Service never survives its backing endpoints: a
// caller that resolves the name in the window between the two dials a VIP with
// no backend and fails fast.
//
// Retraction is BEST EFFORT by construction: a server that is SIGKILLed leaves
// both objects behind, and a caller that dials the stale VIP gets a connection
// refusal.
func RemoveFlatService(ctx context.Context, svcs ServiceClient, slices EndpointSliceClient) error {
	return removeServicePair(ctx, svcs, slices, FlatServiceName)
}

// RemoveFlatEndpointSlice retracts the Service's endpoints and keeps the
// Service. It is what a stopping server does: a caller that resolves the name
// meanwhile dials a VIP with no backend and fails fast, and the ClusterIP (an
// IP SAN of the serving certificate, and a value a caller may have resolved)
// stays the same across the restart. A NotFound is success.
func RemoveFlatEndpointSlice(ctx context.Context, slices EndpointSliceClient) error {
	if err := slices.Delete(ctx, FlatServiceName, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete the %s EndpointSlice: %w", FlatServiceName, err)
	}
	return nil
}

// RemoveClusterService removes node's retired per-node Service and its
// EndpointSlice, which an earlier release published. A NotFound is success. A
// node whose retired name would be the flat Service's (a node named "k3sm") is
// a no-op, so the cleanup can never take the flat Service with it.
func RemoveClusterService(ctx context.Context, svcs ServiceClient, slices EndpointSliceClient, node string) error {
	if node == "" || ClusterServiceName(node) == FlatServiceName {
		return nil
	}
	return removeServicePair(ctx, svcs, slices, ClusterServiceName(node))
}

// removeServicePair deletes the EndpointSlice and then the Service named name.
func removeServicePair(ctx context.Context, svcs ServiceClient, slices EndpointSliceClient, name string) error {
	var errs []error
	if err := slices.Delete(ctx, name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		errs = append(errs, fmt.Errorf("delete the %s EndpointSlice: %w", name, err))
	}
	if err := svcs.Delete(ctx, name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		errs = append(errs, fmt.Errorf("delete the %s Service: %w", name, err))
	}
	return errors.Join(errs...)
}

// clusterServiceLabels returns the labels both objects carry. It returns a fresh
// map per call, so a caller that adds to it (the slice adds two more) cannot
// mutate the other object's.
func clusterServiceLabels(node string) map[string]string {
	return map[string]string{
		clusterServiceManagedLabel: "true",
		clusterServiceNodeLabel:    node,
	}
}

// ptrProtocol returns a pointer to p, which the EndpointPort shape requires.
func ptrProtocol(p corev1.Protocol) *corev1.Protocol { return &p }

// samePorts reports whether two Service port lists carry the same entries.
func samePorts(a, b []corev1.ServicePort) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].Protocol != b[i].Protocol ||
			a[i].Port != b[i].Port || a[i].TargetPort != b[i].TargetPort {
			return false
		}
	}
	return true
}

// sameSlice reports whether the live EndpointSlice already carries the address,
// port and address type the publisher wants.
func sameSlice(a, b *discoveryv1.EndpointSlice) bool {
	if a == nil || b == nil {
		return false
	}
	if a.AddressType != b.AddressType {
		return false
	}
	if a.Labels[discoveryv1.LabelServiceName] != b.Labels[discoveryv1.LabelServiceName] {
		return false
	}
	if len(a.Ports) != len(b.Ports) || len(a.Endpoints) != len(b.Endpoints) {
		return false
	}
	for i := range a.Ports {
		if !samePort(a.Ports[i], b.Ports[i]) {
			return false
		}
	}
	for i := range a.Endpoints {
		if !sameEndpoint(a.Endpoints[i], b.Endpoints[i]) {
			return false
		}
	}
	return true
}

// samePort compares two EndpointPorts through their pointer fields.
func samePort(a, b discoveryv1.EndpointPort) bool {
	return derefString(a.Name) == derefString(b.Name) &&
		derefProtocol(a.Protocol) == derefProtocol(b.Protocol) &&
		derefInt32(a.Port) == derefInt32(b.Port)
}

// sameEndpoint compares two Endpoints on the two fields this publisher writes.
func sameEndpoint(a, b discoveryv1.Endpoint) bool {
	if len(a.Addresses) != len(b.Addresses) {
		return false
	}
	for i := range a.Addresses {
		if a.Addresses[i] != b.Addresses[i] {
			return false
		}
	}
	return derefBool(a.Conditions.Ready) == derefBool(b.Conditions.Ready)
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func derefInt32(p *int32) int32 {
	if p == nil {
		return 0
	}
	return *p
}

func derefBool(p *bool) bool { return p != nil && *p }

func derefProtocol(p *corev1.Protocol) corev1.Protocol {
	if p == nil {
		return ""
	}
	return *p
}
