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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// The PER-NODE ADVERTISEMENT: where a node publishes the address a PEER dials to
// pull from this node's ingest registry.
//
// It is a sibling of the KEP-1755 document and deliberately NOT part of it. That
// document answers "where do I PUSH an image for this cluster", is a singleton,
// and is read by tools outside the cluster; this one answers "where can another
// node PULL an image this cluster already holds", is one object per node, and is
// read only by k3sm's own image puller. Folding a per-node address into the
// singleton would make the last writer the only reachable node.
//
// It lives in its OWN namespace rather than beside the KEP-1755 document in
// kube-public, and the reason is the READER's grant, not the content. A node's
// image puller must list and watch these objects, and neither verb can be
// narrowed to a set of names — RBAC's resourceNames does not apply to list or
// watch — so whatever namespace holds them is the exact scope of the grant a
// node identity gets. In kube-public that grant would have read every object
// any component ever parks there; here it reads registry advertisements and
// nothing else. The KEP-1755 document STAYS in kube-public, which is its
// KEP-mandated home.
//
// The objects themselves remain address-only: a peer's pull inside the mesh is
// anonymous, and the push credential stays on loopback and is never distributed
// (see the package doc's access section). The namespace narrows who can read
// what, not what is safe to publish.
const (
	// AdvertisementNamespace is where a node publishes its advertisement. It is
	// provisioned at server bring-up (pkg/rbac) together with the Role that lets
	// a node identity read it.
	AdvertisementNamespace = "k3sm-registry"
	// AdvertisementPrefix prefixes every advertisement's ConfigMap name. A reader
	// selects the set by this prefix, so a name outside it is not an
	// advertisement however similar it looks.
	AdvertisementPrefix = "k3sm-node-registry-"
	// AdvertisementNodeKey names the advertising node. It is carried in the DATA
	// as well as in the object name so a reader never has to re-derive a node
	// name by trimming a prefix off a key it does not own.
	AdvertisementNodeKey = "node"
	// AdvertisementMeshHostKey is the registry authority a peer dials —
	// "<mesh-ip>:<registry-port>".
	AdvertisementMeshHostKey = "meshHost"
	// AdvertisementPlainHTTPKey is "true" when the authority speaks plain HTTP,
	// which a mesh peer always does: the ingest registry serves no TLS, and the
	// wireguard mesh already encrypts and authenticates the hop. It is published
	// as data rather than assumed by the reader because the reader's transport
	// decision must come from the node that knows what it is serving.
	AdvertisementPlainHTTPKey = "plainHTTP"
)

// ErrNoMeshAddress reports that this node has no mesh address, so it has no
// address a peer could dial and there is nothing to advertise.
//
// It is a SENTINEL rather than a silent no-op because the two callers want
// opposite things from it: the single-node server treats it as the expected
// non-event, while a caller that believed it was on a mesh wants to see why no
// peer can reach it. It is never a failure of publication.
var ErrNoMeshAddress = errors.New("this node has no mesh address to advertise")

// ErrMalformedAdvertisement reports that a ConfigMap in the advertisement set
// does not decode as one. A reader SKIPS such a peer; it never fails the read,
// because one node writing nonsense must not cost every other node its mirror.
var ErrMalformedAdvertisement = errors.New("malformed node registry advertisement")

// AdvertisementClient is the slice of the Kubernetes API the advertiser needs,
// declared HERE at the consumer for the same reason ConfigMapClient is: a caller
// passes `cs.CoreV1().ConfigMaps(AdvertisementNamespace)`, which satisfies it
// structurally, and a test passes a fake with no client-go machinery.
//
// It is a separate interface rather than four methods on ConfigMapClient because
// the KEP-1755 publisher never deletes: an advertisement is per-node state that
// must be retracted when the node goes away, and a singleton document is not.
type AdvertisementClient interface {
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.ConfigMap, error)
	Create(ctx context.Context, cm *corev1.ConfigMap, opts metav1.CreateOptions) (*corev1.ConfigMap, error)
	Update(ctx context.Context, cm *corev1.ConfigMap, opts metav1.UpdateOptions) (*corev1.ConfigMap, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
}

// Peer is a decoded advertisement: one node's mesh-reachable ingest registry.
type Peer struct {
	// Node is the advertising node's name.
	Node string
	// MeshHost is the registry authority to dial — host[:port].
	MeshHost string
	// PlainHTTP selects http:// rather than https:// for this peer.
	PlainHTTP bool
}

// AdvertisementName returns the ConfigMap name node advertises under.
func AdvertisementName(node string) string {
	return AdvertisementPrefix + node
}

// MeshHost renders the authority a peer dials this node's registry at, or ""
// when this node has none to render.
//
// An empty or unparseable mesh IP yields "", which is the single-node posture
// rather than an error: a Mac that is not on a mesh has no address any other
// node could reach it at, and publishing one would be a lie a peer then dials.
// A LOOPBACK address yields "" too, and that is the same statement — 127.0.0.1
// is every node's own address, so advertising it would send every peer to
// itself.
func MeshHost(meshIP string, port int) string {
	addr, err := netip.ParseAddr(meshIP)
	if err != nil || !addr.IsValid() || addr.IsLoopback() || addr.IsUnspecified() {
		return ""
	}
	if port <= 0 || port > 65535 {
		return ""
	}
	return net.JoinHostPort(addr.String(), strconv.Itoa(port))
}

// Advertisement renders node's advertisement ConfigMap.
//
// It returns ErrNoMeshAddress when this node has no mesh address (see MeshHost),
// and a plain error when the node name will not make a valid object name — a
// node name is a DNS subdomain and the prefix eats 19 of the 253 characters, so
// the composition can fail even though the node name itself is legal.
func Advertisement(node, meshIP string, port int) (*corev1.ConfigMap, error) {
	if node == "" {
		return nil, errors.New("advertise the node registry: the node name is empty")
	}
	host := MeshHost(meshIP, port)
	if host == "" {
		return nil, fmt.Errorf("%w (mesh ip %q, port %d)", ErrNoMeshAddress, meshIP, port)
	}
	name := AdvertisementName(node)
	if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 {
		return nil, fmt.Errorf("advertise the node registry: %q is not a valid ConfigMap name: %s", name, strings.Join(errs, "; "))
	}
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: AdvertisementNamespace,
		},
		Data: map[string]string{
			AdvertisementNodeKey:      node,
			AdvertisementMeshHostKey:  host,
			AdvertisementPlainHTTPKey: strconv.FormatBool(true),
		},
	}, nil
}

// ParseAdvertisement decodes one ConfigMap from the advertisement set.
//
// It is STRICT, and every rejection is a case where consulting the peer anyway
// would be worse than skipping it: an authority carrying a path, a scheme or
// userinfo would splice into the repository half of a rewritten reference and
// redirect a pull at a repository nobody named, and a name is refused outright
// because a peer address is an IP by construction — the advertiser renders it
// from its own mesh address, so anything that is not an IP is not something this
// cluster wrote. The node name in the data must match the one in the object
// name, so a node cannot publish an address under another node's identity by
// writing one object.
//
// Every failure wraps ErrMalformedAdvertisement so the caller can classify it
// with errors.Is and skip exactly this peer.
func ParseAdvertisement(cm *corev1.ConfigMap) (Peer, error) {
	if cm == nil {
		return Peer{}, fmt.Errorf("%w: no object", ErrMalformedAdvertisement)
	}
	if !strings.HasPrefix(cm.Name, AdvertisementPrefix) {
		return Peer{}, fmt.Errorf("%w: %q is not in the advertisement set", ErrMalformedAdvertisement, cm.Name)
	}
	node := cm.Data[AdvertisementNodeKey]
	if node == "" {
		return Peer{}, fmt.Errorf("%w: %s carries no %s", ErrMalformedAdvertisement, cm.Name, AdvertisementNodeKey)
	}
	if AdvertisementName(node) != cm.Name {
		return Peer{}, fmt.Errorf("%w: %s advertises node %q, which is not the node its name claims",
			ErrMalformedAdvertisement, cm.Name, node)
	}
	host := cm.Data[AdvertisementMeshHostKey]
	if err := validateMeshHost(host); err != nil {
		return Peer{}, fmt.Errorf("%w: %s: %w", ErrMalformedAdvertisement, cm.Name, err)
	}
	plain, err := strconv.ParseBool(cm.Data[AdvertisementPlainHTTPKey])
	if err != nil {
		return Peer{}, fmt.Errorf("%w: %s carries %s=%q, which is not a boolean",
			ErrMalformedAdvertisement, cm.Name, AdvertisementPlainHTTPKey, cm.Data[AdvertisementPlainHTTPKey])
	}
	return Peer{Node: node, MeshHost: host, PlainHTTP: plain}, nil
}

// validateMeshHost accepts exactly "<ip>:<port>" — the shape MeshHost renders.
func validateMeshHost(host string) error {
	if host == "" {
		return fmt.Errorf("no %s", AdvertisementMeshHostKey)
	}
	h, p, err := net.SplitHostPort(host)
	if err != nil {
		return fmt.Errorf("%s %q is not a host:port authority", AdvertisementMeshHostKey, host)
	}
	if _, err := netip.ParseAddr(h); err != nil {
		return fmt.Errorf("%s %q does not name an IP address", AdvertisementMeshHostKey, host)
	}
	port, err := strconv.Atoi(p)
	if err != nil || port <= 0 || port > 65535 {
		return fmt.Errorf("%s %q does not name a port", AdvertisementMeshHostKey, host)
	}
	return nil
}

// PublishAdvertisement creates or refreshes node's advertisement.
//
// It REFRESHES for the same reason PublishHosting does: the port and the mesh
// address are per-boot facts, and a stale object would send every peer's pull at
// an address nothing answers on. ErrNoMeshAddress is returned unchanged so the
// caller can treat "nothing to advertise" as the non-event it is.
func PublishAdvertisement(ctx context.Context, c AdvertisementClient, node, meshIP string, port int) error {
	want, err := Advertisement(node, meshIP, port)
	if err != nil {
		return err
	}
	existing, err := c.Get(ctx, want.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		if _, cerr := c.Create(ctx, want, metav1.CreateOptions{}); cerr != nil {
			return fmt.Errorf("create the %s ConfigMap: %w", want.Name, cerr)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read the %s ConfigMap: %w", want.Name, err)
	}
	if sameData(existing.Data, want.Data) {
		return nil
	}
	// Updated from the OBJECT WE READ, so the resourceVersion is live and a
	// concurrent writer loses the conflict instead of being silently overwritten.
	updated := existing.DeepCopy()
	updated.Data = want.Data
	if _, uerr := c.Update(ctx, updated, metav1.UpdateOptions{}); uerr != nil {
		return fmt.Errorf("refresh the %s ConfigMap: %w", want.Name, uerr)
	}
	return nil
}

// RemoveAdvertisement retracts node's advertisement. A NotFound is success:
// there is nothing to retract, which is the state this call wanted.
//
// Retraction is BEST EFFORT by construction — a node that is SIGKILLed leaves
// its advertisement behind, and a peer that dials it gets a connection refusal
// the puller already treats as "this mirror does not have it" and moves past. So
// a failure here costs a peer one dial, never a pull.
func RemoveAdvertisement(ctx context.Context, c AdvertisementClient, node string) error {
	if node == "" {
		return nil
	}
	name := AdvertisementName(node)
	if err := c.Delete(ctx, name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete the %s ConfigMap: %w", name, err)
	}
	return nil
}

// sameData reports whether two ConfigMap data maps carry the same entries.
func sameData(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
