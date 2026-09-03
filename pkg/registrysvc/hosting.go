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
	"fmt"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

// The KEP-1755 local-registry-hosting contract. A tool that wants to know where
// to push an image for THIS cluster reads this ConfigMap rather than guessing a
// port, which is the whole point of the KEP: the discovery is the cluster's to
// publish, not the tool's to assume.
const (
	// HostingNamespace is where KEP-1755 places the ConfigMap. kube-public is
	// world-readable by design, which is correct here — the document contains an
	// address, never a credential.
	HostingNamespace = "kube-public"
	// HostingConfigMapName is the ConfigMap's name, fixed by the KEP.
	HostingConfigMapName = "local-registry-hosting"
	// HostingDataKey is the single data key, fixed by the KEP.
	HostingDataKey = "localRegistryHosting.v1"
	// hostingHelp points a reader at the documentation for this registry, and
	// states the one transport fact the addresses themselves cannot.
	//
	// The two localhost addresses carry their transport in their name: the
	// docker/OCI toolchain special-cases the literal `localhost` as an insecure
	// (plain HTTP) registry. The in-cluster address is a Service name, which gets
	// no such treatment — a client handed it would infer HTTPS and fail the
	// handshake against a plain-HTTP listener. The KEP gives no field for
	// transport, so it is said here, where a reader of the document is already
	// looking. The FIELD NAME is deliberately not repeated in this sentence: a
	// reader (and a gate) greps the document for the key, and a help string
	// carrying it would answer that grep from the wrong line.
	hostingHelp = "https://k3sm.io/docs/user/registry/ — the in-cluster address serves plain HTTP, not TLS"
)

// hosting is the KEP-1755 document.
//
// hostFromClusterNetwork means "an address a workload inside the cluster network
// can pull from". k3sm publishes the node's per-node registry Service
// (clusterservice.go), which is one name that answers for all three classes of
// caller: a native Pod (a Darwin process, reaching the VIP through the node's
// lo0 alias), a Linux vm guest (whose own loopback answers nothing, and which
// reaches the VIP through the same userspace proxy every other Service is
// reached through), and the host.
//
// It is OMITTED when there is no such Service — a single-Mac cluster with no
// mesh address and no vm network has no relay, so nothing off loopback answers,
// and an address published there would be one no caller could use. Emptiness is
// therefore a statement, not a default: the field is present exactly when it is
// true.
type hosting struct {
	Host                     string `json:"host"`
	HostFromContainerRuntime string `json:"hostFromContainerRuntime"`
	HostFromClusterNetwork   string `json:"hostFromClusterNetwork,omitempty"`
	Help                     string `json:"help"`
}

// ConfigMapClient is the slice of the Kubernetes API the publisher needs. It is
// declared HERE, at the consumer, so this package depends on three methods rather
// than on a clientset: a caller passes `cs.CoreV1().ConfigMaps(HostingNamespace)`,
// which satisfies it structurally, and a test passes a fake with no client-go
// machinery at all.
type ConfigMapClient interface {
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.ConfigMap, error)
	Create(ctx context.Context, cm *corev1.ConfigMap, opts metav1.CreateOptions) (*corev1.ConfigMap, error)
	Update(ctx context.Context, cm *corev1.ConfigMap, opts metav1.UpdateOptions) (*corev1.ConfigMap, error)
}

// HostingDocument renders the KEP-1755 document for a registry on port, reachable
// from inside the cluster network at clusterNetworkHost.
//
// The first two addresses are "localhost:<port>" rather than "127.0.0.1:<port>",
// because the docker/OCI toolchain special-cases the literal name `localhost` to
// mean an insecure (plain HTTP) registry, and this one serves plain HTTP. A
// reader handed 127.0.0.1 would have to be told separately to disable TLS.
//
// clusterNetworkHost is the node's registry Service authority
// (ClusterServiceAuthority) — or "", which OMITS hostFromClusterNetwork. It is a
// parameter rather than something rendered here because only the caller knows
// whether the Service was actually published; rendering the name unconditionally
// would publish an address on a node that has no relay to answer it. That
// authority speaks PLAIN HTTP and does not say so in its name, which is why the
// help string does (see hostingHelp).
func HostingDocument(port int, clusterNetworkHost string) ([]byte, error) {
	addr := "localhost:" + strconv.Itoa(port)
	b, err := yaml.Marshal(hosting{
		Host:                     addr,
		HostFromContainerRuntime: addr,
		HostFromClusterNetwork:   clusterNetworkHost,
		Help:                     hostingHelp,
	})
	if err != nil {
		return nil, fmt.Errorf("render the %s document: %w", HostingDataKey, err)
	}
	return b, nil
}

// PublishHosting creates or refreshes the local-registry-hosting ConfigMap.
//
// It REFRESHES rather than creating once: the port is a per-boot fact (a `k3sm
// dev` instance allocates its own), so a ConfigMap left over from a previous boot
// would send every reader to a port nothing is listening on. An Update conflict
// is returned to the caller, which logs it — a losing writer in a two-server
// cluster is not an error worth retrying, because the winner published the same
// document.
func PublishHosting(ctx context.Context, c ConfigMapClient, port int, clusterNetworkHost string) error {
	doc, err := HostingDocument(port, clusterNetworkHost)
	if err != nil {
		return err
	}
	want := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      HostingConfigMapName,
			Namespace: HostingNamespace,
		},
		Data: map[string]string{HostingDataKey: string(doc)},
	}
	existing, err := c.Get(ctx, HostingConfigMapName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		if _, cerr := c.Create(ctx, want, metav1.CreateOptions{}); cerr != nil {
			return fmt.Errorf("create the %s ConfigMap: %w", HostingConfigMapName, cerr)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read the %s ConfigMap: %w", HostingConfigMapName, err)
	}
	if existing.Data[HostingDataKey] == want.Data[HostingDataKey] {
		return nil
	}
	// Updated from the OBJECT WE READ, so the resourceVersion is the live one and
	// a concurrent writer loses the conflict instead of being silently overwritten.
	updated := existing.DeepCopy()
	if updated.Data == nil {
		updated.Data = map[string]string{}
	}
	updated.Data[HostingDataKey] = want.Data[HostingDataKey]
	if _, uerr := c.Update(ctx, updated, metav1.UpdateOptions{}); uerr != nil {
		return fmt.Errorf("refresh the %s ConfigMap: %w", HostingConfigMapName, uerr)
	}
	return nil
}
