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

package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// deregisterVerb names the deregistration verb in its rejection logs.
const deregisterVerb = "node deregistration"

// DeregisterTimeout bounds one deregistration call.
//
// It is deliberately shorter than NodeIdentityClient's own 30s: the caller is an
// uninstall an operator is watching at a terminal, and the control plane it is
// talking to may be off, asleep or on another network. Ten seconds is long
// enough for a LAN round trip through the bootstrap listener and short enough
// that a cluster which is simply not there costs the teardown a pause rather
// than a stall. The uninstall side bounds the whole attempt again; this is the
// per-call bound.
const DeregisterTimeout = 10 * time.Second

// handleDeregister serves the deregistration verb: it removes the calling node's
// MeshPeer and Node from the cluster.
//
// The authentication is the same as the endpoint refresh's, in the same order
// and through the same two helpers — verifiedNodeLeaf (401) then
// authorizeNodeSelf (403) — and for the same reason. A node that is being
// uninstalled still holds its system:node certificate, and that certificate is
// the only thing it can prove itself with: the join token is TTL-bounded and is
// deliberately not retained after the join, so a deregistration gated on it
// would work for a day and then leave every later uninstall stranded.
//
// The DELETE itself is performed by the SERVER's own client, through the
// Enroller. This is what keeps the verb from being an RBAC widening: the node
// identity gains no delete verb on MeshPeer or Node, here or in pkg/rbac, and
// the only object this route can ever reach is the one named by the certificate
// that authenticated the request.
//
// A deregistration of a node the cluster has already forgotten SUCCEEDS: the
// Enroller tolerates NotFound on both objects, so an uninstall re-run, or one
// following an operator's own `kubectl delete`, reports the state it wanted
// rather than an error it cannot act on.
func (s *Server) handleDeregister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	leaf := s.verifiedNodeLeaf(w, r, deregisterVerb)
	if leaf == nil {
		return
	}

	var req DeregisterRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "decode deregister request: "+err.Error(), http.StatusBadRequest)
		return
	}

	if !s.authorizeNodeSelf(w, leaf, req.NodeName, deregisterVerb) {
		return
	}

	if err := s.cfg.Enroller.Deregister(r.Context(), req.NodeName); err != nil {
		s.cfg.Logger.Error("node deregistration failed", "node", req.NodeName, "err", err)
		http.Error(w, "node deregistration failed", http.StatusInternalServerError)
		return
	}
	s.cfg.Logger.Info("node deregistered", "node", req.NodeName)
	w.WriteHeader(http.StatusOK)
}

// DeregisterNode POSTs this node's deregistration to the supervisor, removing
// its MeshPeer and Node from the cluster. serverURL is the bootstrap base URL
// (https://<host>:9345); client must present the node's own certificate
// (NodeIdentityClient).
//
// The call is bounded by DeregisterTimeout regardless of the client's own
// timeout, because its caller is an uninstall that must finish whether or not
// the control plane answers.
//
// A 404 is reported as what it is: a control plane that does not serve this
// route, i.e. one older than the node being removed. The remedy is the manual
// delete, so the error says so rather than reading as "the node was not found".
func DeregisterNode(ctx context.Context, client *http.Client, serverURL, nodeName string) error {
	if nodeName == "" {
		return fmt.Errorf("deregister: no node name")
	}
	ctx, cancel := context.WithTimeout(ctx, DeregisterTimeout)
	defer cancel()

	body, err := json.Marshal(DeregisterRequest{NodeName: nodeName})
	if err != nil {
		return fmt.Errorf("marshal deregister request: %w", err)
	}
	url := strings.TrimRight(serverURL, "/") + DeregisterPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build deregister request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post deregister for %q to %s: %w", nodeName, url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("the control plane at %s does not serve the deregistration verb (it runs an older k3sm); delete this node by hand: kubectl delete meshpeer/%s node/%s", serverURL, nodeName, nodeName)
	}
	if resp.StatusCode/100 != 2 {
		msg := make([]byte, 512)
		n, _ := resp.Body.Read(msg)
		return fmt.Errorf("deregister of %q rejected (%s): %s", nodeName, resp.Status, strings.TrimSpace(string(msg[:n])))
	}
	return nil
}
