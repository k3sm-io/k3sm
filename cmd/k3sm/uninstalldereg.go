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
	"fmt"
	"io/fs"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/nodecred"
)

// Leaving the cluster on `sudo k3sm uninstall`.
//
// An uninstalled worker used to stay in the cluster forever: its Node kept
// showing up in `kubectl get nodes` as NotReady, and — the expensive half —
// every remaining peer kept a wireguard entry and a route for a Mac that will
// never answer again, because the MeshPeer that programs them was still there.
// Nothing else removes them: the node is gone, and no controller reaps a
// MeshPeer.
//
// So the uninstall asks the cluster to forget this node before it tears the
// local install down. What it presents is the node's OWN certificate, the same
// credential the endpoint refresh uses and the only one a node still holds at
// uninstall time, through a server-side verb that deletes on its behalf
// (bootstrap.DeregisterPath). No RBAC changes: the node identity gains no delete
// verb on either object, and the verb can only ever reach the node its
// certificate names.
//
// The whole thing is best effort. A Mac is often uninstalled precisely because
// the cluster is gone, so every reason not to try is a log line and never a
// failure, and pkg/install's own contract treats the call the same way.

// nodeSystemPrefix is the CN prefix of a node's client certificate. A node's
// name is the rest of it.
const nodeSystemPrefix = "system:node:"

// deregisterEligible reports whether a stored node client certificate can still
// authenticate a deregistration at now.
//
// The rule is the certificate's RAW NotAfter, deliberately NOT the credential
// store's credentialValid verdict, which treats anything within
// credentialExpiryMargin (24h) of expiry as already expired. That margin exists
// to decide which FAILURE an agent start reports — inside it a token join is
// still available, so the node is told to supply a token rather than to rejoin.
// Nothing about it applies here: a certificate that is valid for one more hour
// authenticates a deregistration perfectly well for the few seconds the call
// takes, and refusing to try would leave a MeshPeer behind for no reason.
func deregisterEligible(clientNotAfter, now time.Time) bool {
	return clientNotAfter.After(now)
}

// nodeNameFromClientCert returns the node name a stored client certificate
// authenticates as: the CN with the system:node: prefix stripped.
//
// It is read from the CERTIFICATE rather than from the hostname, because the
// certificate is what the server checks the request body against. A Mac renamed
// since it joined still deregisters the node it actually is.
func nodeNameFromClientCert(certPEM []byte) (string, error) {
	leaf, err := nodecred.DecodeCertPEM(certPEM)
	if err != nil {
		return "", fmt.Errorf("parse the stored node client certificate: %w", err)
	}
	name := strings.TrimPrefix(leaf.Subject.CommonName, nodeSystemPrefix)
	if name == leaf.Subject.CommonName || name == "" {
		return "", fmt.Errorf("the stored node client certificate is CN=%q, which is not a %s<name> node identity", leaf.Subject.CommonName, nodeSystemPrefix)
	}
	return name, nil
}

// agentDeregister builds the closure install.Uninstall calls to remove this node
// from its cluster, or nil plus the one-sentence reason there is nothing to
// call.
//
// The reason is returned rather than logged here so the caller decides how loud
// it is, and an EMPTY reason means "say nothing": this Mac carries no agent
// daemon, so it is a control plane or an already-uninstalled machine and there
// was never anything to deregister. Every other arm produces a sentence — a Mac
// with no credential (never joined, or already wiped), a credential that will
// not parse, a certificate that has expired, an agent plist that does not name
// the control plane it joined. None of them is a failure of the uninstall, and
// each of them is something an operator wants to know before this node keeps a
// peer entry alive on another Mac.
//
// The agent plist is probed FIRST, before the credential, precisely so the
// control-plane case stays silent: on a server the credential is absent too, and
// reporting that absence would print a worker's diagnosis on a machine that is
// not a worker.
//
// now is a parameter for the same reason the credential store's Status takes
// one: the expiry decision is then testable without waiting a year.
func agentDeregister(sys install.System, dataRoot string, now time.Time) (func(context.Context) error, string) {
	host, err := install.AgentJoinServer(sys, install.Config{DataRoot: dataRoot})
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, "" // not a worker; nothing to say
	case err != nil:
		return nil, fmt.Sprintf("the control plane this node joined is unknown (%v), so a deregistration has nowhere to go", err)
	}

	store := nodeCredentialStore{dir: filepath.Dir(install.AgentCredentialPath(dataRoot))}
	status, cred, err := store.Status(now)
	switch {
	case err != nil:
		return nil, fmt.Sprintf("this node's stored credential cannot be read (%v), so it cannot authenticate a deregistration", err)
	case cred == nil:
		return nil, fmt.Sprintf("this node holds no usable credential (%s), so there is nothing to deregister with", status)
	case !deregisterEligible(cred.ClientNotAfter, now):
		return nil, fmt.Sprintf("this node's certificate expired at %s, so the control plane would refuse a deregistration", cred.ClientNotAfter.UTC().Format(time.RFC3339))
	}

	nodeName, err := nodeNameFromClientCert(cred.ClientCertPEM)
	if err != nil {
		return nil, err.Error()
	}
	client, err := bootstrap.NodeIdentityClient(cred.ClusterCAPEM, cred.ClientCertPEM, cred.ClientKeyPEM)
	if err != nil {
		return nil, fmt.Sprintf("this node's credential cannot be presented (%v), so it cannot authenticate a deregistration", err)
	}
	// The BOOTSTRAP listener, not the apiserver: the deregistration verb lives
	// beside join and the endpoint refresh on <host>:9345, and the host is the
	// underlay address this node joined over — the one address it is known to
	// have reached, and the one that still works once the mesh goes down.
	serverURL := "https://" + net.JoinHostPort(host, strconv.Itoa(bootstrapPort))
	return func(ctx context.Context) error {
		return bootstrap.DeregisterNode(ctx, client, serverURL, nodeName)
	}, ""
}
