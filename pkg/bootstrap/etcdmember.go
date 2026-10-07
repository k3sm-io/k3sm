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
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"k3sm.io/k3sm/pkg/certs"
)

// The server-class etcd member routes. A server joining an embedded-etcd HA cluster
// asks an EXISTING server to add it as a learner and, once its member runs, to promote
// it. The existing server executes both against its OWN loopback etcd client, so no
// etcd client listener ever has to be reachable off-host: these two routes are the
// only remote door into membership, and they open only to the server-class token.
const (
	// EtcdMemberPath adds the caller as an etcd learner (EtcdMemberRequest →
	// EtcdMemberResponse).
	EtcdMemberPath = BundlePath + "/etcd-member"
	// EtcdMemberPromotePath promotes the caller's learner to a voting member
	// (EtcdPromoteRequest).
	EtcdMemberPromotePath = EtcdMemberPath + "/promote"
)

// EtcdMember is one etcd cluster member as the member routes see it.
//
// An UNSTARTED member — added to the cluster but never yet run — is the etcd
// convention of an empty Name AND no ClientURLs: a member publishes both only when
// it first starts. Unstarted reports exactly that.
type EtcdMember struct {
	ID         uint64
	Name       string
	PeerURLs   []string
	ClientURLs []string
	IsLearner  bool
}

// Unstarted reports whether m was added but has never run (etcd's convention: no
// name and no client URLs until the member's first start publishes them).
func (m EtcdMember) Unstarted() bool { return m.Name == "" && len(m.ClientURLs) == 0 }

// MemberJoiner is the membership API the member routes drive, defined here at its
// consumer so this package imports no etcd client. The server wires an
// implementation over its local member's loopback admin client.
type MemberJoiner interface {
	// MemberList lists the cluster's members.
	MemberList(ctx context.Context) ([]EtcdMember, error)
	// MemberAddAsLearner adds a non-voting member at peerURL and returns it with
	// the member list that resulted.
	MemberAddAsLearner(ctx context.Context, peerURL string) (EtcdMember, []EtcdMember, error)
	// MemberPromote makes a caught-up learner a voting member.
	MemberPromote(ctx context.Context, id uint64) error
	// MemberRemove removes a member.
	MemberRemove(ctx context.Context, id uint64) error
}

// EtcdMemberRequest is the body of EtcdMemberPath: the joining server's member name
// (its canonical node name) and its peer URL, https://<node IP>:<peer port>.
//
// NodePassword and MeshClaim are additive. A server that predates them ignores both
// (the decoder allows unknown fields), which is why a joiner that sends a claim
// refuses to continue unless the answer acknowledges it (EtcdMemberResponse.MeshClaim).
type EtcdMemberRequest struct {
	Name    string `json:"name"`
	PeerURL string `json:"peerURL"`
	// NodePassword is the joining server's own persisted node-password. The route
	// binds the member name to it first-write-wins, exactly as /join binds a
	// worker's, so a server name cannot be claimed by a second Mac holding the same
	// server token. Required whenever MeshClaim is set.
	NodePassword string `json:"nodePassword,omitempty"`
	// MeshClaim asks the serving server to reserve the joiner's mesh range BEFORE
	// the etcd member is added. Nil is a joiner with no mesh.
	MeshClaim *MeshClaim `json:"meshClaim,omitempty"`
}

// MeshClaim is the mesh identity a joining server asks the existing server to
// reserve: the /24 its --mesh-ip is the mesh-egress address of, written as that
// server's MeshPeer. It carries the wireguard PUBLIC key only; no private key
// material ever crosses this route.
type MeshClaim struct {
	// MeshIP is the joiner's --mesh-ip, the .1 of the node pod /24 it claims.
	MeshIP string `json:"meshIP"`
	// PublicKey is the joiner's wireguard public key.
	PublicKey string `json:"publicKey"`
	// Endpoint is the joiner's wireguard underlay endpoint, host:port. Its host must
	// be the host of the request's PeerURL: the route vouches for one address only.
	Endpoint string `json:"endpoint"`
}

// MeshClaimReserved is EtcdMemberResponse.MeshClaim when the serving server reserved
// the joiner's mesh range before adding its member.
const MeshClaimReserved = "reserved"

// EtcdMemberResponse answers EtcdMemberPath: the learner's member ID and the
// --initial-cluster set its first start must use (every member, the joiner included).
type EtcdMemberResponse struct {
	MemberID       uint64 `json:"memberID"`
	InitialCluster string `json:"initialCluster"`
	// MeshClaim is MeshClaimReserved when the request's MeshClaim was reserved. A
	// server that predates claims never sets it, and a joiner that sent a claim
	// treats its absence as a refusal (the capability handshake).
	MeshClaim string `json:"meshClaim,omitempty"`
}

// ServerMeshReserver reserves a joining server's mesh range for the member route.
// It is defined here, at its consumer; the server's mesh enroller implements it.
type ServerMeshReserver interface {
	// ReserveServerMesh claims the range claim.MeshIP names for nodeName and writes
	// nodeName's server MeshPeer. It refuses with ErrInvalidMeshClaim (a malformed
	// claim), ErrMeshRangeClaimed (another node holds the range) or
	// ErrMeshClaimRefused (the name holds a worker's row, a different range, or a
	// different key). The Allocation is what ReleaseServerMesh undoes.
	ReserveServerMesh(ctx context.Context, nodeName string, claim MeshClaim) (Allocation, error)
	// ReleaseServerMesh undoes a FRESH reservation whose member add then failed. It
	// is fenced exactly as Enroller.ReleaseAllocation is.
	ReleaseServerMesh(ctx context.Context, nodeName string, alloc Allocation) error
}

// The mesh-claim refusals. Compare with errors.Is.
var (
	// ErrInvalidMeshClaim refuses a claim whose mesh IP is not the mesh-egress
	// address of a node range, or whose key or endpoint does not validate (400).
	ErrInvalidMeshClaim = errors.New("bootstrap: invalid mesh claim")
	// ErrMeshRangeClaimed refuses a claim on a range another node already holds
	// (409). The holder is never evicted.
	ErrMeshRangeClaimed = errors.New("the server's mesh range is held by another node")
	// ErrMeshClaimRefused refuses a claim the name's existing row forbids: the name
	// holds a worker's MeshPeer, a different range, or a different public key (403).
	ErrMeshClaimRefused = errors.New("the mesh claim conflicts with this node name's existing MeshPeer")
)

// RefusalReasonHeader carries the machine-readable reason a server-class route
// refused a request, so a client can tell refusals that share a status code apart
// without reading the message text.
const RefusalReasonHeader = "K3sm-Refusal-Reason"

// The RefusalReasonHeader values the member route sets.
const (
	// RefusalMeshRangeClaimed: another node holds the claimed range.
	RefusalMeshRangeClaimed = "mesh-range-claimed"
	// RefusalMeshClaimRefused: the name's own row forbids the claim.
	RefusalMeshClaimRefused = "mesh-claim-refused"
	// RefusalMeshClaimInvalid: the claim does not validate.
	RefusalMeshClaimInvalid = "mesh-claim-invalid"
	// RefusalNodePassword: the member name is bound to a different node-password.
	RefusalNodePassword = "node-password"
)

// ServerMeshReserveTimeout bounds the mesh reservation the member route makes while
// it holds the member lock, so a slow apiserver cannot hold every other member
// request behind it for longer than this.
const ServerMeshReserveTimeout = 15 * time.Second

// EtcdPromoteRequest is the body of EtcdMemberPromotePath.
type EtcdPromoteRequest struct {
	Name string `json:"name"`
}

// ErrInvalidPeerURL is wrapped by every peer-URL refusal.
var ErrInvalidPeerURL = errors.New("bootstrap: invalid etcd peer URL")

// CanonicalPeerURL validates an etcd peer URL and returns its one canonical
// spelling, https://<ip>:<port> as net.JoinHostPort renders it. The host must be a
// literal, non-loopback, non-unspecified IP with no zone (a member advertises its
// node's LAN address; a name would resolve differently on every peer), the port a
// number in 1..65535, and nothing else may be present: no user info, path, query or
// fragment. A URL that is valid but not canonical is refused rather than rewritten,
// so the string a member is registered under is exactly the string the joiner sent.
func CanonicalPeerURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidPeerURL, err)
	}
	if u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("%w: want https://<ip>:<port>, got %q", ErrInvalidPeerURL, raw)
	}
	addr, err := netip.ParseAddr(u.Hostname())
	if err != nil || addr.Zone() != "" || addr.IsLoopback() || addr.IsUnspecified() {
		return "", fmt.Errorf("%w: the host of %q must be a non-loopback IP address", ErrInvalidPeerURL, raw)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("%w: the port of %q must be 1-65535", ErrInvalidPeerURL, raw)
	}
	canon := "https://" + net.JoinHostPort(addr.Unmap().String(), strconv.Itoa(port))
	if canon != raw {
		return "", fmt.Errorf("%w: %q is not in canonical form %q", ErrInvalidPeerURL, raw, canon)
	}
	return canon, nil
}

// InitialCluster renders the --initial-cluster set for a joining member: one
// name=peerURL entry per member peer URL, in member-list order. The joiner's own
// entry (joinerID) is named joinerName even while it is still unstarted and carries
// no name. Any OTHER unstarted member (a second server mid-join) is named
// "unstarted-<id hex>": etcd keys the set by name, so two nameless entries would merge
// into one member and fail its membership check, while the remote members' names
// themselves are not checked (they are matched to the cluster by peer URL).
func InitialCluster(members []EtcdMember, joinerID uint64, joinerName string) string {
	var parts []string
	for _, m := range members {
		name := m.Name
		switch {
		case m.ID == joinerID:
			name = joinerName
		case name == "":
			name = fmt.Sprintf("unstarted-%x", m.ID)
		}
		for _, p := range m.PeerURLs {
			parts = append(parts, name+"="+p)
		}
	}
	return strings.Join(parts, ",")
}

// authorizeServerRoute runs the server-class route preamble shared by both member
// routes: the method, the identity-blind pre-authentication bound (ahead of anything
// parsed, as for /join), and the server-class token (a worker token is refused with
// ErrNotServerToken). It writes the refusal and returns false when the request must
// stop.
func (s *Server) authorizeServerRoute(w http.ResponseWriter, r *http.Request, route string) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if ok, retryAfter := s.preauth.allow(preAuthSourceKey(r.RemoteAddr)); !ok {
		secs := retryAfterSeconds(retryAfter)
		s.cfg.Logger.Debug("server-bootstrap rejected", "route", route, "reason", "pre-auth-rate-limit",
			"retryAfterSeconds", secs, "remote", r.RemoteAddr)
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		http.Error(w, fmt.Sprintf("refused: too many requests; retry in %ds", secs), http.StatusTooManyRequests)
		return false
	}
	token := bearerToken(r)
	if token == "" {
		http.Error(w, "missing server bootstrap token", http.StatusUnauthorized)
		return false
	}
	if err := s.cfg.ServerAuth.AuthorizeServerToken(r.Context(), token); err != nil {
		s.cfg.Logger.Warn("server-bootstrap rejected", "route", route, "reason", "server-token", "err", err, "remote", r.RemoteAddr)
		http.Error(w, "server bootstrap token rejected", http.StatusForbidden)
		return false
	}
	return true
}

// memberName canonicalizes a requested member name exactly as /join does (a
// non-canonical spelling is refused, never folded) and refuses this server's own
// name: the existing server's member is registered under it, and the stale-member
// path would otherwise remove the very member serving the request.
func (s *Server) memberName(w http.ResponseWriter, r *http.Request, route, requested string) (string, bool) {
	name, err := CanonicalNodeName(requested)
	if err != nil || name != requested {
		s.cfg.Logger.Warn("server-bootstrap rejected", "route", route, "reason", "member-name", "err", err, "remote", r.RemoteAddr)
		http.Error(w, "refused: the member name must be the joining server's lowercase DNS-1123 node name", http.StatusBadRequest)
		return "", false
	}
	if selfNameClaimed(s.cfg.SelfNodeName, name) {
		s.cfg.Logger.Warn("server-bootstrap rejected", "route", route, "reason", "self-name", "member", name, "remote", r.RemoteAddr)
		http.Error(w, "refused: that member name is this server's own", http.StatusConflict)
		return "", false
	}
	return name, true
}

// handleEtcdMember adds the caller as an etcd learner, keyed on the member NAME:
//
//   - the name is unused: add a learner at peerURL;
//   - an unstarted learner already sits at peerURL (a joiner restarted between the
//     add and its member's first start): reuse it, with no second add;
//   - anything else under that name — a STARTED member (the joiner's data dir was
//     wiped, so its old identity can never start again), or an entry at a different
//     peer URL — is removed first, then the learner is added.
//
// Learner first is what keeps a two-server cluster safe: a voting add makes the
// cluster 2-of-2 the moment it returns, so a joiner that then failed to start would
// cost the existing server its quorum. The steps are serialized per server, so two
// requests for one name cannot interleave their list, remove and add.
//
// Two checks run BEFORE any membership change, so a refusal never creates a member:
//
//   - the node-password binding (bindMemberName): the member name is bound to the
//     joiner's node-password first-write-wins, as /join binds a worker's;
//   - the mesh reservation (reserveMemberMesh): the joiner's mesh range is claimed and
//     its server MeshPeer written. A range another node holds refuses the join (409)
//     and is never taken from its holder. The reservation is released again when the
//     member add that follows it fails.
//
// A request with no claim (a joiner that predates claims) skips the reservation and
// is answered exactly as before; one with a claim is acknowledged with
// MeshClaimReserved, which a joiner that sent a claim requires.
func (s *Server) handleEtcdMember(w http.ResponseWriter, r *http.Request) {
	const route = "etcd-member"
	if !s.authorizeServerRoute(w, r, route) {
		return
	}
	var req EtcdMemberRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "decode etcd member request: "+err.Error(), http.StatusBadRequest)
		return
	}
	name, ok := s.memberName(w, r, route, req.Name)
	if !ok {
		return
	}
	peerURL, err := CanonicalPeerURL(req.PeerURL)
	if err != nil {
		s.cfg.Logger.Warn("server-bootstrap rejected", "route", route, "reason", "peer-url", "member", name, "err", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.MeshClaim != nil && !s.checkMeshClaimShape(w, route, name, peerURL, req) {
		return
	}
	if !s.bindMemberName(w, r, route, name, req.NodePassword) {
		return
	}

	s.memberMu.Lock()
	defer s.memberMu.Unlock()
	log := s.cfg.Logger.With("route", route, "member", name, "peer-url", peerURL)
	ctx := r.Context()

	// The reservation comes first under the lock: nothing below may change the
	// membership for a joiner whose mesh range is not its own.
	reserved, alloc, ok := s.reserveMemberMesh(ctx, w, log, name, req.MeshClaim)
	if !ok {
		return
	}
	committed := false
	defer func() {
		if reserved && !committed {
			s.releaseMemberMesh(ctx, log, name, alloc)
		}
	}()
	ack := ""
	if reserved {
		ack = MeshClaimReserved
	}

	members, err := s.cfg.Members.MemberList(ctx)
	if err != nil {
		log.Error("etcd member list failed", "err", err)
		http.Error(w, "list etcd members: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	// An unstarted member has no name yet, so "this server's entry" is the member
	// under its name OR an unstarted one at its peer URL. Exactly one of those may be
	// kept (an unstarted learner at exactly this peer URL); every other is removed
	// first, so the reused entry never shares the name with a stale one.
	var reuse *EtcdMember
	kept := make([]EtcdMember, 0, len(members))
	for _, m := range members {
		if m.Name != name && !(m.Unstarted() && slices.Contains(m.PeerURLs, peerURL)) {
			kept = append(kept, m)
			continue
		}
		if reuse == nil && m.Unstarted() && m.IsLearner && slices.Equal(m.PeerURLs, []string{peerURL}) {
			reuse = &m
			kept = append(kept, m)
			continue
		}
		log.Info("removing the stale etcd member registered under this server's name or peer URL",
			"member-id", memberHex(m.ID), "started", !m.Unstarted(), "learner", m.IsLearner, "registered-peer-urls", m.PeerURLs)
		if err := s.cfg.Members.MemberRemove(ctx, m.ID); err != nil {
			log.Error("etcd member remove failed", "member-id", memberHex(m.ID), "err", err)
			http.Error(w, "remove the stale etcd member: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		if m.Unstarted() {
			log.Info("removed the stale etcd member", "member-id", memberHex(m.ID))
			continue
		}
		// A STARTED member is one that once ran and may still hold a vote: removing it
		// changes the cluster's quorum, so it is said at WARN with what was removed.
		log.Warn("removed a started etcd member so the joining server can re-join under its name",
			"member-id", memberHex(m.ID), "removed-name", m.Name, "removed-peer-urls", m.PeerURLs, "learner", m.IsLearner)
	}
	if reuse != nil {
		committed = true
		log.Info("reusing the unstarted etcd learner already registered for this server", "member-id", memberHex(reuse.ID))
		s.writeMemberResponse(w, EtcdMemberResponse{MemberID: reuse.ID, InitialCluster: InitialCluster(kept, reuse.ID, name), MeshClaim: ack})
		return
	}

	added, after, err := s.cfg.Members.MemberAddAsLearner(ctx, peerURL)
	if err != nil {
		log.Error("etcd learner add failed", "err", err)
		http.Error(w, "add the etcd learner: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	committed = true
	log.Info("added an etcd learner for the joining server", "member-id", memberHex(added.ID), "members", len(after))
	s.writeMemberResponse(w, EtcdMemberResponse{MemberID: added.ID, InitialCluster: InitialCluster(after, added.ID, name), MeshClaim: ack})
}

// checkMeshClaimShape refuses, before anything is bound or reserved, a claim the
// route cannot vouch for: one sent without a node-password (a claim writes a server
// MeshPeer under the name, so the name must be bound first), one sent to a server
// that runs no mesh reserver, and one whose wireguard endpoint is not on the host of
// the request's peer URL — the one address the joiner has already declared.
func (s *Server) checkMeshClaimShape(w http.ResponseWriter, route, name, peerURL string, req EtcdMemberRequest) bool {
	refuse := func(reason, msg string) bool {
		s.cfg.Logger.Warn("server-bootstrap rejected", "route", route, "reason", reason, "member", name)
		w.Header().Set(RefusalReasonHeader, RefusalMeshClaimInvalid)
		http.Error(w, msg, http.StatusBadRequest)
		return false
	}
	if req.NodePassword == "" {
		return refuse("mesh-claim-no-node-password", "refused: a mesh claim must carry the joining server's node-password")
	}
	if s.cfg.ServerMesh == nil {
		return refuse("mesh-claim-no-mesh", "refused: this server runs no mesh, so it cannot reserve a mesh range for a joining server")
	}
	u, err := url.Parse(peerURL)
	if err != nil {
		return refuse("mesh-claim-endpoint", "refused: the peer URL does not parse")
	}
	host, _, err := net.SplitHostPort(req.MeshClaim.Endpoint)
	if err != nil {
		return refuse("mesh-claim-endpoint", "refused: the mesh claim's endpoint is not host:port")
	}
	ep, err := netip.ParseAddr(host)
	if err != nil || ep.Unmap().String() != u.Hostname() {
		return refuse("mesh-claim-endpoint", "refused: the mesh claim's endpoint host must be the host of the etcd peer URL")
	}
	return true
}

// bindMemberName binds the member name to the joiner's node-password, first write
// wins, through the same store /join binds workers in. A mismatch is a verdict (403);
// a store that cannot answer is not (503 + Retry-After). An empty password is the
// joiner that predates the binding, and is let through unbound: checkMeshClaimShape
// has already refused one that carries a claim.
func (s *Server) bindMemberName(w http.ResponseWriter, r *http.Request, route, name, password string) bool {
	if password == "" {
		return true
	}
	if len(password) > MaxNodePasswordLength {
		http.Error(w, fmt.Sprintf("refused: nodePassword is longer than %d bytes", MaxNodePasswordLength), http.StatusBadRequest)
		return false
	}
	if err := s.cfg.NodePasswords.Ensure(r.Context(), name, password); err != nil {
		if errors.Is(err, ErrNodePasswordMismatch) {
			s.cfg.Logger.Warn("server-bootstrap rejected", "route", route, "reason", "node-password", "member", name, "err", err)
			w.Header().Set(RefusalReasonHeader, RefusalNodePassword)
			http.Error(w, "node-password rejected: that server name is bound to another Mac", http.StatusForbidden)
			return false
		}
		s.cfg.Logger.Warn("server-bootstrap rejected", "route", route, "reason", "node-password-store-unavailable", "member", name, "err", err)
		w.Header().Set("Retry-After", strconv.Itoa(nodePasswordStoreRetryAfterSeconds))
		http.Error(w, "refused: the control plane could not check this server's name binding; retry later", http.StatusServiceUnavailable)
		return false
	}
	return true
}

// reserveMemberMesh reserves the joiner's mesh range under the member lock, bounded
// by ServerMeshReserveTimeout. reserved reports whether a reservation was made (false
// for a request with no claim); ok false means the refusal has been written.
func (s *Server) reserveMemberMesh(ctx context.Context, w http.ResponseWriter, log *slog.Logger, name string, claim *MeshClaim) (reserved bool, alloc Allocation, ok bool) {
	if claim == nil {
		return false, Allocation{}, true
	}
	rctx, cancel := context.WithTimeout(ctx, ServerMeshReserveTimeout)
	defer cancel()
	alloc, err := s.cfg.ServerMesh.ReserveServerMesh(rctx, name, *claim)
	switch {
	case err == nil:
		log.Info("reserved the joining server's mesh range before its member add", "mesh-ip", claim.MeshIP, "fresh", alloc.Fresh)
		return true, alloc, true
	case errors.Is(err, ErrInvalidMeshClaim):
		log.Warn("server-bootstrap rejected", "reason", "mesh-claim-invalid", "err", err)
		w.Header().Set(RefusalReasonHeader, RefusalMeshClaimInvalid)
		http.Error(w, "refused: "+err.Error(), http.StatusBadRequest)
	case errors.Is(err, ErrMeshRangeClaimed):
		log.Warn("server-bootstrap rejected", "reason", "mesh-range-claimed", "err", err)
		w.Header().Set(RefusalReasonHeader, RefusalMeshRangeClaimed)
		http.Error(w, "refused: "+err.Error()+"; choose a free --mesh-ip, or remove the stale MeshPeer and its claim", http.StatusConflict)
	case errors.Is(err, ErrMeshClaimRefused):
		log.Warn("server-bootstrap rejected", "reason", "mesh-claim-refused", "err", err)
		w.Header().Set(RefusalReasonHeader, RefusalMeshClaimRefused)
		http.Error(w, "refused: "+err.Error(), http.StatusForbidden)
	default:
		log.Error("mesh reservation failed", "err", err)
		http.Error(w, "reserve the mesh range: "+err.Error(), http.StatusServiceUnavailable)
	}
	return false, Allocation{}, false
}

// releaseMemberMesh undoes a FRESH reservation whose member step then failed, so the
// range of a server that never joined is not left reserved. A reservation that
// re-asserted an existing row is never released: that row predates this request.
func (s *Server) releaseMemberMesh(ctx context.Context, log *slog.Logger, name string, alloc Allocation) {
	if !alloc.Fresh {
		return
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ServerMeshReserveTimeout)
	defer cancel()
	if err := s.cfg.ServerMesh.ReleaseServerMesh(rctx, name, alloc); err != nil {
		log.Error("could not release the mesh reservation of a server whose member add failed; delete its MeshPeer and claim by hand", "err", err)
		return
	}
	log.Info("released the mesh reservation of a server whose member add failed")
}

// handleEtcdMemberPromote promotes the named learner. It is idempotent: a member
// that already votes is answered 200, so a joiner whose earlier promote landed but
// whose response was lost converges. A learner that is not yet caught up is refused
// by etcd; the 503 tells the joiner to retry.
func (s *Server) handleEtcdMemberPromote(w http.ResponseWriter, r *http.Request) {
	const route = "etcd-member-promote"
	if !s.authorizeServerRoute(w, r, route) {
		return
	}
	var req EtcdPromoteRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "decode etcd promote request: "+err.Error(), http.StatusBadRequest)
		return
	}
	name, ok := s.memberName(w, r, route, req.Name)
	if !ok {
		return
	}

	s.memberMu.Lock()
	defer s.memberMu.Unlock()
	log := s.cfg.Logger.With("route", route, "member", name)
	ctx := r.Context()

	members, err := s.cfg.Members.MemberList(ctx)
	if err != nil {
		log.Error("etcd member list failed", "err", err)
		http.Error(w, "list etcd members: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	i := slices.IndexFunc(members, func(m EtcdMember) bool { return m.Name == name })
	if i < 0 {
		// An unstarted learner has no name yet; the joiner retries once its member
		// has started and published it.
		http.Error(w, "no started etcd member is registered under that name", http.StatusNotFound)
		return
	}
	m := members[i]
	if !m.IsLearner {
		log.Info("the etcd member is already a voting member", "member-id", memberHex(m.ID))
		w.WriteHeader(http.StatusOK)
		return
	}
	if err := s.cfg.Members.MemberPromote(ctx, m.ID); err != nil {
		log.Info("etcd learner promotion refused; the joiner retries", "member-id", memberHex(m.ID), "err", err)
		http.Error(w, "promote the etcd learner: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	log.Info("promoted the etcd learner to a voting member", "member-id", memberHex(m.ID))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) writeMemberResponse(w http.ResponseWriter, resp EtcdMemberResponse) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.cfg.Logger.Warn("write etcd member response", "err", err)
	}
}

// memberHex renders a member ID the way etcdctl prints it.
func memberHex(id uint64) string { return strconv.FormatUint(id, 16) }

// RequestEtcdMember asks the existing server at serverURL (its bootstrap base URL) to
// add this server as an etcd learner at req.PeerURL, over the same CA-hash-pinned TLS
// and server-token bearer credential as the CA-bundle fetch. client nil builds the
// pinned client from the token.
func RequestEtcdMember(ctx context.Context, serverURL, token string, req EtcdMemberRequest, client *http.Client) (EtcdMemberResponse, error) {
	var out EtcdMemberResponse
	body, err := postServerRoute(ctx, serverURL, EtcdMemberPath, token, req, client)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, fmt.Errorf("decode etcd member response: %w", err)
	}
	if out.InitialCluster == "" {
		return out, errors.New("etcd member response carries no initial cluster")
	}
	return out, nil
}

// PromoteEtcdMember asks the existing server to promote this server's learner.
func PromoteEtcdMember(ctx context.Context, serverURL, token, name string, client *http.Client) error {
	_, err := postServerRoute(ctx, serverURL, EtcdMemberPromotePath, token, EtcdPromoteRequest{Name: name}, client)
	return err
}

// ServerRouteError is a server-class route's non-2xx answer, as the client helpers
// (RequestEtcdMember, PromoteEtcdMember) return it. StatusCode is what a caller
// classifies on (Permanent), never the message text.
type ServerRouteError struct {
	// Path is the route that answered; Status the HTTP status line.
	Path, Status string
	// StatusCode is the HTTP status code.
	StatusCode int
	// Message is the first bytes of the answer's body, trimmed.
	Message string
	// Reason is the answer's RefusalReasonHeader, empty when it set none. It is what
	// a caller tells refusals sharing a status code apart by.
	Reason string
}

func (e *ServerRouteError) Error() string {
	return fmt.Sprintf("%s rejected (%s): %s", e.Path, e.Status, e.Message)
}

// Permanent reports whether retrying the same request cannot change the answer: a
// 4xx refusal of the request itself (400 a malformed or refused name or peer URL, 401
// no credential, 403 a token this cluster rejects, 409 a name that is the existing
// server's own). A 404 (no started member yet), 408, 429 (rate limited) and every 5xx
// (503 an unhealthy cluster or a learner not caught up) are transient.
func (e *ServerRouteError) Permanent() bool {
	switch e.StatusCode {
	case http.StatusNotFound, http.StatusRequestTimeout, http.StatusTooManyRequests:
		return false
	}
	return e.StatusCode >= 400 && e.StatusCode < 500
}

// IsPermanentServerRouteFailure reports whether err, from a server-class client
// helper, is a failure no retry can heal: a permanent refusal (ServerRouteError's
// Permanent), a token that does not parse or is not the server class, or an existing
// server whose CA does not match the token's pin (the wrong cluster). Every other
// error — a network failure, a transient status — is worth retrying.
func IsPermanentServerRouteFailure(err error) bool {
	if re, ok := errors.AsType[*ServerRouteError](err); ok {
		return re.Permanent()
	}
	return errors.Is(err, ErrMalformedToken) || errors.Is(err, ErrNotServerToken) || errors.Is(err, certs.ErrPinMismatch)
}

// postServerRoute POSTs a JSON body to a server-class route and returns the 2xx
// response body. A non-2xx answer is a *ServerRouteError.
func postServerRoute(ctx context.Context, serverURL, path, token string, body any, client *http.Client) ([]byte, error) {
	tok, err := ParseServerToken(token)
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = PinnedClient(tok.CAHash)
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("encode %s request: %w", path, err)
	}
	u := strings.TrimRight(serverURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build %s request: %w", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("post %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, &ServerRouteError{Path: path, Status: resp.Status, StatusCode: resp.StatusCode,
			Message: strings.TrimSpace(string(msg)), Reason: resp.Header.Get(RefusalReasonHeader)}
	}
	out, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("read %s response: %w", path, err)
	}
	return out, nil
}
