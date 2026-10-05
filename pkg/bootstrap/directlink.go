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
	"errors"
	"fmt"
	"net/http"
	"strings"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
)

// directLinkVerb names the direct-link publish verb in its rejection logs.
const directLinkVerb = "direct link publish"

// ErrDomainUUIDClaimed reports that a port's domain UUID is already listed by
// another node's DirectLink. A collision is refused, never resolved by the last
// writer: two nodes claiming one cable end is a defect (a cloned identity, a
// misread enumeration) that a silent overwrite would hide. Compare with errors.Is.
var ErrDomainUUIDClaimed = errors.New("bootstrap: a direct-link domain UUID is already claimed by another node")

// ErrServerTooOld reports that the control plane does not serve a verb this node
// called (a 404 on a route a newer server serves). The caller logs it once and
// keeps running without the feature. Compare with errors.Is.
var ErrServerTooOld = errors.New("bootstrap: the control plane does not serve this verb (it runs an older k3sm)")

// DirectLinkWriter writes a node's DirectLink spec on the node's behalf, and reads
// the node's own object back. The implementation (cmd wiring) holds the apiserver
// client. ApplyDirectLink creates the object when absent, sets its owner to the
// Node, replaces the spec, never touches the status, refuses a domain UUID another
// node already lists (ErrDomainUUIDClaimed), and checks every link address against
// the node's index (the node's MeshPeer carries it). GetDirectLink returns the
// node's object, and false when there is none.
//
// The read is here, server-mediated, because the node identity holds no read verb
// on DirectLink and this verb deliberately does not give it one: the node learns
// its own resolved status through the certificate it already has, and can read
// no other node's object.
type DirectLinkWriter interface {
	ApplyDirectLink(ctx context.Context, spec netv1alpha1.DirectLinkSpec) error
	GetDirectLink(ctx context.Context, nodeName string) (*netv1alpha1.DirectLink, bool, error)
}

// DirectLinkRequest is the payload a joined node POSTs to DirectLinkPath: the
// spec of its own DirectLink. Spec.NodeName MUST equal the authenticated
// certificate's system:node:<name> identity; a mismatch is a 403.
type DirectLinkRequest struct {
	Spec netv1alpha1.DirectLinkSpec `json:"spec"`
}

// directLinkBodyLimit bounds the publish body. Eight ports of a few hundred
// bytes each fit many times over; the bound is the join verb's order of
// magnitude, not a tuned value.
const directLinkBodyLimit = 1 << 16

// handleDirectLink serves the direct-link publish verb.
//
// The order is the join listener's: the identity-blind pre-authentication bound
// FIRST, before the body is read, then the node certificate (verifiedNodeLeaf,
// 401), then the body under its limit, then the self-scoping guard
// (authorizeNodeSelf, 403), then the spec's own validation (400), then the write.
// The certificate is the only credential: the join token is TTL-bounded and is
// not retained.
func (s *Server) handleDirectLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.PreAuthAllow(w, r) {
		return
	}
	leaf := s.verifiedNodeLeaf(w, r, directLinkVerb)
	if leaf == nil {
		return
	}
	if r.Method == http.MethodGet {
		s.serveOwnDirectLink(w, r, leaf.Subject.CommonName)
		return
	}
	var req DirectLinkRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, directLinkBodyLimit)).Decode(&req); err != nil {
		http.Error(w, "decode direct link publish: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !s.authorizeNodeSelf(w, leaf, req.Spec.NodeName, directLinkVerb) {
		return
	}
	if err := req.Spec.Validate(); err != nil {
		s.cfg.Logger.Warn(directLinkVerb+" rejected", "reason", "invalid-spec", "node", req.Spec.NodeName, "err", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.cfg.DirectLinks.ApplyDirectLink(r.Context(), req.Spec); err != nil {
		switch {
		case errors.Is(err, ErrDomainUUIDClaimed):
			s.cfg.Logger.Warn(directLinkVerb+" rejected", "reason", "domain-uuid-claimed", "node", req.Spec.NodeName, "err", err)
			http.Error(w, "domain-uuid-claimed: "+err.Error(), http.StatusConflict)
		case errors.Is(err, ErrNoMeshPeer):
			s.cfg.Logger.Warn(directLinkVerb+" rejected", "reason", "no-such-peer", "node", req.Spec.NodeName)
			http.Error(w, "no MeshPeer for this node; rejoin the cluster", http.StatusNotFound)
		case errors.Is(err, netv1alpha1.ErrInvalid):
			s.cfg.Logger.Warn(directLinkVerb+" rejected", "reason", "invalid-spec", "node", req.Spec.NodeName, "err", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
		default:
			s.cfg.Logger.Error(directLinkVerb+" failed", "node", req.Spec.NodeName, "err", err)
			http.Error(w, "direct link publish failed", http.StatusInternalServerError)
		}
		return
	}
	w.WriteHeader(http.StatusOK)
}

// serveOwnDirectLink answers a GET with the calling node's own DirectLink: the
// node is the one the verified certificate names, never a parameter, so no node
// can read another's object.
func (s *Server) serveOwnDirectLink(w http.ResponseWriter, r *http.Request, cn string) {
	node := strings.TrimPrefix(cn, systemNodePrefix)
	if node == cn || node == "" {
		http.Error(w, "the presented identity is not a node", http.StatusForbidden)
		return
	}
	dl, ok, err := s.cfg.DirectLinks.GetDirectLink(r.Context(), node)
	if err != nil {
		s.cfg.Logger.Error(directLinkVerb+" read failed", "node", node, "err", err)
		http.Error(w, "direct link read failed", http.StatusInternalServerError)
		return
	}
	if !ok {
		w.WriteHeader(http.StatusNoContent) // the node has published nothing yet
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(dl)
}

// FetchDirectLink GETs this node's own DirectLink (spec and resolved status) from
// the supervisor; false when the server holds none yet. A server without the verb
// is ErrServerTooOld.
func FetchDirectLink(ctx context.Context, client *http.Client, serverURL string) (*netv1alpha1.DirectLink, bool, error) {
	url := strings.TrimRight(serverURL, "/") + DirectLinkPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, fmt.Errorf("build direct link read: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("get direct link from %s: %w", url, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNoContent:
		return nil, false, nil
	case resp.StatusCode == http.StatusNotFound:
		return nil, false, fmt.Errorf("%w: %s", ErrServerTooOld, DirectLinkPath)
	case resp.StatusCode/100 != 2:
		return nil, false, fmt.Errorf("direct link read rejected (%s)", resp.Status)
	}
	var dl netv1alpha1.DirectLink
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, directLinkBodyLimit)).Decode(&dl); err != nil {
		return nil, false, fmt.Errorf("decode direct link: %w", err)
	}
	return &dl, true, nil
}

// PublishDirectLink POSTs this node's DirectLink spec to the supervisor. client
// must present the node's own certificate (NodeIdentityClient).
//
// A 404 is ambiguous on this route: it is either a server that predates the verb
// or a server that has no MeshPeer for this node. The server's own body says which,
// so a body naming the MeshPeer maps to ErrNoMeshPeer and every other 404 to
// ErrServerTooOld. A 409 (another node claims a domain UUID) wraps
// ErrDomainUUIDClaimed.
func PublishDirectLink(ctx context.Context, client *http.Client, serverURL string, spec netv1alpha1.DirectLinkSpec) error {
	body, err := json.Marshal(DirectLinkRequest{Spec: spec})
	if err != nil {
		return fmt.Errorf("marshal direct link publish: %w", err)
	}
	url := strings.TrimRight(serverURL, "/") + DirectLinkPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build direct link publish: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post direct link publish to %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 == 2 {
		return nil
	}
	msg := make([]byte, 512)
	n, _ := resp.Body.Read(msg)
	text := strings.TrimSpace(string(msg[:n]))
	switch resp.StatusCode {
	case http.StatusNotFound:
		if strings.Contains(text, "MeshPeer") {
			return fmt.Errorf("%w: %s", ErrNoMeshPeer, text)
		}
		return fmt.Errorf("%w: %s", ErrServerTooOld, DirectLinkPath)
	case http.StatusConflict:
		return fmt.Errorf("%w: %s", ErrDomainUUIDClaimed, text)
	}
	return fmt.Errorf("direct link publish rejected (%s): %s", resp.Status, text)
}
