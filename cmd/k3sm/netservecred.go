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
	"time"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/nodecred"
)

// netserveFetcher obtains a fresh netserve keypair for nodeName from the
// supervisor, authenticated by the node credential in res. It is a seam so the
// start decision is tested without a listener; production is fetchNetserveCert.
type netserveFetcher func(ctx context.Context, res *bootstrap.JoinResult, nodeName string) (certPEM, keyPEM []byte, err error)

// fetchNetserveCertFrom returns the production netserveFetcher for the
// supervisor at joinHost: the node's own client certificate presented over the
// CA-pinned client the endpoint refresh uses (bootstrap.NodeIdentityClient).
func fetchNetserveCertFrom(joinHost string) netserveFetcher {
	return func(ctx context.Context, res *bootstrap.JoinResult, nodeName string) ([]byte, []byte, error) {
		client, err := bootstrap.NodeIdentityClient(res.ClusterCAPEM, res.NodeClientCertPEM, res.NodeClientKeyPEM)
		if err != nil {
			return nil, nil, err
		}
		return bootstrap.FetchNetserveCert(ctx, client, "https://"+joinHost, nodeName)
	}
}

// netserveKubeconfigPath is the netserve kubeconfig, beside the node kubeconfig.
func (s nodeCredentialStore) netserveKubeconfigPath() string {
	return s.reader().NetserveKubeconfigPath()
}

// saveNetserve persists the netserve kubeconfig at the node kubeconfig's 0600,
// through the same atomic, no-op-on-identical-content install.
func (s nodeCredentialStore) saveNetserve(apiserverURL, nodeName string, caPEM, certPEM, keyPEM []byte) error {
	content := renderClientKubeconfig(apiserverURL, certs.NetserveUserPrefix+nodeName, caPEM, certPEM, keyPEM)
	if err := writeStoreFile(s.netserveKubeconfigPath(), content, 0o600); err != nil {
		return fmt.Errorf("write netserve kubeconfig: %w", err)
	}
	return nil
}

// ensureNetserveCredential leaves a usable netserve kubeconfig in the store and
// returns its path: the identity this node's datapath runs under.
//
// Three sources, in order:
//
//  1. the join that just ran issued one (res.NetserveClientCertPEM);
//  2. the store already holds one that is Valid for this node
//     (nodecred.Store.NetserveStatus: the right identity, chaining to the
//     client-identity CA, outside ExpiryMargin), which is rewritten only if the
//     apiserver URL moved;
//  3. otherwise it is fetched from the supervisor with the node credential. This
//     is how a node that joined before the identity existed obtains one without a
//     rejoin, and how an expiring one rotates: the server caps the issued
//     lifetime at the node certificate's, so the datapath identity never outlives
//     the node identity it was derived from.
//
// A fetch failure is returned: a datapath that cannot authenticate serves
// nothing, and the next start retries.
func ensureNetserveCredential(ctx context.Context, store nodeCredentialStore, nodeName, apiserverURL string, res *bootstrap.JoinResult, fetch netserveFetcher, now time.Time, logger *slog.Logger) (string, error) {
	path := store.netserveKubeconfigPath()
	if len(res.NetserveClientCertPEM) > 0 && len(res.NetserveClientKeyPEM) > 0 {
		if err := bootstrap.CheckNetserveKeyPair(res.NetserveClientCertPEM, res.NetserveClientKeyPEM, nodeName); err != nil {
			return "", fmt.Errorf("the netserve certificate the join issued: %w", err)
		}
		if err := store.saveNetserve(apiserverURL, nodeName, res.ClusterCAPEM, res.NetserveClientCertPEM, res.NetserveClientKeyPEM); err != nil {
			return "", err
		}
		logger.Info("stored the netserve identity the join issued", "cn", certs.NetserveUserPrefix+nodeName)
		return path, nil
	}

	state, cred, err := store.reader().NetserveStatus(now, nodeName, res.ClientCAPEM)
	if state == nodecred.Valid {
		if err := store.saveNetserve(apiserverURL, nodeName, res.ClusterCAPEM, cred.CertPEM, cred.KeyPEM); err != nil {
			return "", err
		}
		return path, nil
	}
	logger.Info("fetching this node's netserve identity with its node credential",
		"cn", certs.NetserveUserPrefix+nodeName, "stored", state.String(), "reason", err)

	certPEM, keyPEM, ferr := fetch(ctx, res, nodeName)
	if ferr != nil {
		return "", fmt.Errorf("obtain this node's netserve identity (the datapath's apiserver credential): %w", ferr)
	}
	if err := store.saveNetserve(apiserverURL, nodeName, res.ClusterCAPEM, certPEM, keyPEM); err != nil {
		return "", err
	}
	if _, notAfter, err := clientCertIdentity(certPEM); err == nil {
		logger.Info("obtained this node's netserve identity", "cn", certs.NetserveUserPrefix+nodeName,
			"not_after", notAfter.UTC().Format(time.RFC3339))
	}
	return path, nil
}
