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
	"log/slog"
	"net"

	"k8s.io/client-go/kubernetes"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/registrysvc"
)

// serverRegistryServingMinter returns the function that issues the registry
// relay's serving certificate: a server-auth leaf from the CLUSTER CA, the CA
// the controller-manager republishes into every namespace as kube-root-ca.crt,
// so every Pod already trusts it through its service-account ca.crt. The key
// is generated and held in memory and is never written to disk; the identity
// re-mints before expiry with the other in-memory component certificates'
// validity and margin.
//
// It returns nil, and logs why, when the hierarchy cannot be loaded or carries
// no cluster CA key. The relay then stays off: there is no plain-HTTP relay to
// fall back to.
func serverRegistryServingMinter(opts serverOptions, logger *slog.Logger) func(dnsNames []string, ips []net.IP) (tls.Certificate, error) {
	h, err := certs.EnsureHierarchy(opts.workDir, opts.role(), opts.posture())
	if err != nil {
		logger.Error("the ingest registry relay is off: the CA hierarchy for its serving certificate cannot be loaded", "err", err)
		return nil
	}
	if h == nil || h.Cluster == nil || h.Cluster.Cert == nil || h.Cluster.Key == nil {
		logger.Error("the ingest registry relay is off: the work dir's PKI carries no usable cluster CA to issue its serving certificate")
		return nil
	}
	ca := h.Cluster
	return func(dnsNames []string, ips []net.IP) (tls.Certificate, error) {
		return ca.IssueRegistryServing(registrysvc.FlatServiceName, dnsNames, ips, executor.ComponentCertValidity)
	}
}

// retractOptedOutRegistryService removes the flat registry Service a previous
// boot published, on a bootstrap server started with --registry-port 0. A
// joined server never published it and leaves it alone. Best effort: a failure
// is logged, and the Service's endpoints already point at a relay that is no
// longer there.
func retractOptedOutRegistryService(ctx context.Context, opts serverOptions, cs kubernetes.Interface, logger *slog.Logger) {
	if opts.serverJoin || cs == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, registryRetractGrace)
	defer cancel()
	if err := registrysvc.RemoveFlatService(ctx, cs.CoreV1().Services(registrysvc.FlatServiceNamespace),
		cs.DiscoveryV1().EndpointSlices(registrysvc.FlatServiceNamespace)); err != nil {
		logger.Warn("remove the registry Service left by an earlier boot (the registry is off)", "err", err,
			"namespace", registrysvc.FlatServiceNamespace, "name", registrysvc.FlatServiceName)
	}
}
