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
	"strings"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/validation"

	"k3sm.io/darwin-net/pkg/dns"
)

// The PER-NODE CLUSTER SERVICE: one cluster address at which this node's ingest
// registry answers for every class of caller — a native Pod, a Linux vm guest,
// and the host itself.
//
// It is a SELECTOR-LESS Service plus a hand-written EndpointSlice, which is the
// standard Kubernetes way to give a cluster name to something the cluster does
// not schedule. Nothing here selects a Pod because there is no Pod: the registry
// is a child process of the server, reached through the relay's non-loopback
// bind (relay.go). The Service is a NAME and a VIP; the relay is the thing that
// answers.
//
// WHY PER NODE, and not one Service for the cluster. Every node runs its own
// registry with its own content, so an address that resolved to "some node" would
// be a coin flip. The obvious fix — one Service whose EndpointSlice carries every
// node, with internalTrafficPolicy: Local to pin a caller to its own node — does
// not work here: node locality is decided by whether the endpoint address falls
// in the node's podCIDR (darwin-net/pkg/proxy), and every k3sm mesh address is
// carved from the one cluster range, so every endpoint looks local on every node.
// Naming the node in the Service sidesteps a signal that cannot be made truthful.
//
// WHY THE ENDPOINT IS THE RELAY ADDRESS. EndpointSlice validation refuses a
// loopback address outright, so the registry's own 127.0.0.1 listener can never
// be an endpoint — and that refusal is the loopback invariant being enforced by
// the apiserver rather than merely respected here. The address published is
// therefore one the relay actually binds, taken from the same relayBinds that
// decides the binds: the mesh address when this node has one, else the vm NAT
// gateway. A node with neither has no relay, so it publishes no Service; there is
// nothing that would answer.
//
// WHAT IT IS FOR, and what it is not. This is a PULL address. `k3sm image push`
// authenticates only against a loopback target (credential.go), by design — the
// per-boot credential never leaves the machine that minted it — so a push still
// names localhost:<port>. Pull is anonymous, which is what lets a Pod name this
// Service with nothing configured.
//
// RBAC: nothing new. The publisher is the server's retained admin client, the
// same one that writes the advertisement ConfigMaps, and the readers — a node's
// Service proxy and DNS resolver — already hold cluster-wide get/list/watch on
// services and endpointslices through the k3sm:node-datapath ClusterRole
// (pkg/rbac). A namespace-scoped grant here would be a duplicate of a grant that
// already covers it.
const (
	// ClusterServicePrefix prefixes every per-node registry Service (and its
	// EndpointSlice, which carries the same name). A reader selects the set by
	// this prefix, and the prefix also guarantees the composed name starts with a
	// letter, which a Service name must.
	ClusterServicePrefix = "registry-"
	// ClusterServicePortName names the single port on both objects. The Service
	// port name and the EndpointSlice port name MUST agree — that name is what
	// kube-proxy (and darwin-net's userspace proxy) matches a backend port by, so
	// a mismatch yields a Service with a VIP and no backends.
	ClusterServicePortName = "registry"
	// clusterServiceNodeLabel records the advertising node on both objects, so
	// `kubectl get svc -n k3sm-registry -l k3sm.io/registry-node=<node>` reads back
	// the pair without anyone trimming a prefix off a name.
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
	// spelled as a reverse-DNS NAME and not as the "k3sm.io/registrysvc" path
	// form the rest of the repo uses for KEYS, because this is a label VALUE: a
	// value may not contain "/", and the apiserver rejects the whole object if it
	// does. Upstream's own controllers spell it the same way
	// ("endpointslice-controller.k8s.io").
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

// ClusterServiceName returns the Service (and EndpointSlice) name node's registry
// is published under.
func ClusterServiceName(node string) string {
	return ClusterServicePrefix + node
}

// ClusterServiceAuthority renders the in-cluster authority a caller dials —
// "registry-<node>.k3sm-registry.svc.<cluster-domain>:<port>".
//
// The FULLY QUALIFIED form is what gets published, not the short
// "registry-<node>.k3sm-registry" a Pod in another namespace could also use: the
// document this feeds is read by tools with no ndots context of their own, and a
// name that resolves for a Pod and not for the reader is worse than a long one.
//
// An empty cluster domain means dns.DefaultClusterDomain, matching every other
// in-cluster address k3sm renders.
func ClusterServiceAuthority(node, clusterDomain string, port int) string {
	domain := clusterDomain
	if domain == "" {
		domain = dns.DefaultClusterDomain
	}
	return fmt.Sprintf("%s.%s.svc.%s:%d", ClusterServiceName(node), AdvertisementNamespace, domain, port)
}

// ClusterLocalAuthorities returns every authority that names THIS node's own
// ingest registry through its cluster Service — the fully qualified name, the
// namespace-qualified ".svc" short form a Pod can resolve, and the VIP itself.
//
// It exists for runtimed's puller. runtimed decides whether a reference is
// node-relative (and therefore eligible for the cluster-mirror fallback, and for
// this node's own ingest registry's brokering) by asking whether its authority is
// a LOOPBACK spelling — see runtimed/pkg/image's clusterLocalRef. A Pod that
// names the Service address is asking for exactly the same registry by a
// different name, so those spellings have to be injected: the classifier cannot
// derive them, because they depend on a node name and a cluster domain runtimed
// has never heard of.
//
// clusterIP may be empty (the Service has not been assigned one yet), in which
// case only the name spellings are returned. Nothing here is a URL: each element
// is a bare host[:port] authority, the shape a reference's first component takes.
func ClusterLocalAuthorities(node, clusterDomain, clusterIP string, port int) []string {
	if node == "" || port <= 0 || port > 65535 {
		return nil
	}
	domain := clusterDomain
	if domain == "" {
		domain = dns.DefaultClusterDomain
	}
	name := ClusterServiceName(node)
	p := strconv.Itoa(port)
	out := []string{
		net.JoinHostPort(fmt.Sprintf("%s.%s.svc.%s", name, AdvertisementNamespace, domain), p),
		net.JoinHostPort(fmt.Sprintf("%s.%s.svc", name, AdvertisementNamespace), p),
	}
	if addr, err := netip.ParseAddr(clusterIP); err == nil && addr.IsValid() {
		out = append(out, net.JoinHostPort(addr.String(), p))
	}
	return out
}

// ClusterEndpointAddress returns the address the per-node Service sends a caller
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

// ClusterService renders node's selector-less registry Service.
//
// The port is BOTH the Service port and the target port, deliberately: the relay
// listens on the registry's own port on every address it binds, so a caller that
// dials the Service port reaches the same port it would have dialed directly.
//
// A node name that will not compose a valid Service name is an error rather than
// a truncation — a Service name is a DNS-1035 LABEL (63 characters, no dots),
// which is stricter than the DNS-1123 subdomain a node name may be, so the
// composition can fail on a node name that is itself perfectly legal.
func ClusterService(node string, port int) (*corev1.Service, error) {
	name, err := validClusterServiceName(node)
	if err != nil {
		return nil, err
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("publish the registry Service for %s: port %d is out of range 1-65535", node, port)
	}
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: AdvertisementNamespace,
			Labels:    clusterServiceLabels(node),
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			// No Selector, and that is the whole shape: there is no Pod behind
			// this Service, so the endpoints are written by hand below.
			Ports: []corev1.ServicePort{{
				Name:       ClusterServicePortName,
				Protocol:   corev1.ProtocolTCP,
				Port:       int32(port),
				TargetPort: intstr.FromInt32(int32(port)),
			}},
		},
	}, nil
}

// ClusterEndpointSlice renders the hand-written EndpointSlice backing node's
// registry Service with the single relay address addr.
//
// It REFUSES a loopback address with ErrNonRelayableBind. The apiserver refuses
// one too, so this is not the only guard — it is the guard that names the reason
// at the place the decision is made, instead of surfacing as a validation error
// from an object nobody reads.
func ClusterEndpointSlice(node string, port int, addr netip.Addr) (*discoveryv1.EndpointSlice, error) {
	name, err := validClusterServiceName(node)
	if err != nil {
		return nil, err
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("publish the registry EndpointSlice for %s: port %d is out of range 1-65535", node, port)
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
	portNum := int32(port)
	ready := true
	labels := clusterServiceLabels(node)
	labels[discoveryv1.LabelServiceName] = name
	labels[clusterServiceManagedBy] = clusterServiceManager
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: AdvertisementNamespace,
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

// PublishClusterService creates or refreshes node's Service and EndpointSlice.
//
// The SERVICE IS PUBLISHED FIRST so its ClusterIP exists before anything reports
// an address, and the assigned ClusterIP is RETURNED: it is the VIP a caller
// dials, and the spelling runtimed must also treat as cluster-local
// (ClusterLocalAuthorities).
//
// Both objects REFRESH rather than being created once, for the reason the
// advertisement does: the port and the relay address are per-boot facts, and a
// stale endpoint would send every caller to an address nothing answers on. A
// refresh mutates only the fields this package owns and is built from the object
// that was READ, so the resourceVersion is live and a concurrent writer loses the
// conflict instead of being silently overwritten — most of all the ClusterIP,
// which the apiserver assigned and which is immutable.
func PublishClusterService(ctx context.Context, svcs ServiceClient, slices EndpointSliceClient, node string, port int, addr netip.Addr) (string, error) {
	wantSvc, err := ClusterService(node, port)
	if err != nil {
		return "", err
	}
	wantSlice, err := ClusterEndpointSlice(node, port, addr)
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

// RemoveClusterService retracts node's Service and its EndpointSlice. A NotFound
// is success: there is nothing to retract, which is the state this call wanted.
//
// The SLICE GOES FIRST, so the Service never survives its backing endpoints — a
// caller that resolves the name in the window between the two dials a VIP with no
// backend and fails fast, where the other order would leave a slice the apiserver
// keeps and nothing consumes.
//
// Retraction is BEST EFFORT by construction, exactly as RemoveAdvertisement is: a
// node that is SIGKILLed leaves both objects behind, and a caller that dials the
// stale VIP gets a connection refusal it already handles.
func RemoveClusterService(ctx context.Context, svcs ServiceClient, slices EndpointSliceClient, node string) error {
	if node == "" {
		return nil
	}
	name := ClusterServiceName(node)
	var errs []error
	if err := slices.Delete(ctx, name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		errs = append(errs, fmt.Errorf("delete the %s EndpointSlice: %w", name, err))
	}
	if err := svcs.Delete(ctx, name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		errs = append(errs, fmt.Errorf("delete the %s Service: %w", name, err))
	}
	return errors.Join(errs...)
}

// validClusterServiceName composes and validates node's Service name.
func validClusterServiceName(node string) (string, error) {
	if node == "" {
		return "", errors.New("publish the registry Service: the node name is empty")
	}
	name := ClusterServiceName(node)
	if errs := validation.IsDNS1035Label(name); len(errs) > 0 {
		return "", fmt.Errorf("publish the registry Service: %q is not a valid Service name: %s", name, strings.Join(errs, "; "))
	}
	return name, nil
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
