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

package pairing

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"

	"k3sm.io/k3sm/pkg/bootstrap"
)

// TokenTTL is the lifetime of a token the pair verb mints: long enough for the
// joiner to run its join (and a retry), short enough that a token that leaked
// off the cable is dead before anyone could carry it elsewhere.
const TokenTTL = 2 * time.Minute

// AcceptInterval is the least time between two accepted pair requests on one
// interface.
const AcceptInterval = 10 * time.Second

// pairBodyLimit bounds the pair request body; a node name fits many times over.
const pairBodyLimit = 4 << 10

// Reason names why a pair request was refused. Each is distinct so a log line,
// a Node Event and the refused client all say the same thing.
type Reason string

const (
	// ReasonNotLinkLocal: the connection's local address is not fe80::/10.
	ReasonNotLinkLocal Reason = "not-link-local"
	// ReasonNotThunderbolt: the local zone does not name a Thunderbolt hardware
	// port (bridge0, Wi-Fi, Ethernet, a dock's Ethernet Adapter, a utun).
	ReasonNotThunderbolt Reason = "not-thunderbolt"
	// ReasonRemoteNotSameLink: the remote is not a link-local address on the
	// same zone.
	ReasonRemoteNotSameLink Reason = "remote-not-same-link"
	// ReasonWindowClosed: no window, or its time has passed.
	ReasonWindowClosed Reason = "window-closed"
	// ReasonWindowFull: the window's completed joins reached maxJoins.
	ReasonWindowFull Reason = "window-full"
	// ReasonRateLimited: this interface was accepted less than AcceptInterval ago.
	ReasonRateLimited Reason = "rate-limited"
	// ReasonMintCap: the window minted all the tokens it may.
	ReasonMintCap Reason = "mint-cap"
	// ReasonMalformed: the request body is not a decodable pair request, or is
	// over the body limit.
	ReasonMalformed Reason = "malformed"
	// ReasonBadName: the requested node name is not a canonical node name.
	ReasonBadName Reason = "invalid-node-name"
)

// status is the HTTP status a refusal answers with.
func (r Reason) status() int {
	switch r {
	case ReasonRateLimited:
		return http.StatusTooManyRequests
	case ReasonBadName, ReasonMalformed:
		return http.StatusBadRequest
	default:
		return http.StatusForbidden
	}
}

// Decision is the outcome of the connection-level trust checks (a) and (b).
type Decision struct {
	// Iface is the local Thunderbolt interface the request arrived on, when the
	// checks passed.
	Iface string
	// Refused is the reason, or "" when the connection is trusted.
	Refused Reason
}

// Decide is checks (a) and (b) of the trust decision, pure: the LOCAL address
// must be fe80::/10 with a zone the hardware-port mapping names a Thunderbolt
// port (ports maps an interface to its receptacle, exactly as
// linkenum.HardwarePorts reports it — "Thunderbolt Bridge" and every other port
// are absent from it), and the REMOTE must be fe80 on the same zone. For TCP the
// zone IS the interface the kernel received the connection on, so neither check
// trusts anything the client chose.
func Decide(local, remote netip.Addr, ports map[string]int) Decision {
	if !local.Is6() || !local.IsLinkLocalUnicast() {
		return Decision{Refused: ReasonNotLinkLocal}
	}
	zone := local.Zone()
	if _, ok := ports[zone]; !ok || zone == "" {
		return Decision{Refused: ReasonNotThunderbolt}
	}
	if !remote.Is6() || !remote.IsLinkLocalUnicast() || remote.Zone() != zone {
		return Decision{Refused: ReasonRemoteNotSameLink}
	}
	return Decision{Iface: zone}
}

// Minter mints a one-shot, name-bound join token (bootstrap.FileTokenStore).
type Minter interface {
	CreateBound(ttl time.Duration, nodeName string, window time.Time) (user, secret string, expiry time.Time, err error)
	// OutstandingOneShot counts the unconsumed, unexpired tokens of a window.
	OutstandingOneShot(window time.Time) (int, error)
}

// Recorder records a pairing outcome as a Node Event. Refusals are rate-limited
// by the handler before they reach it.
type Recorder interface {
	Record(eventType, reason, message string)
}

// Handler serves the pairing verb. Every field but Logger, Now and Events is
// required.
//
// Locking: mu guards lastAccept and lastEvent only. mintMu serializes the
// outstanding-token count, the reserve and the mint, so two requests cannot both
// count the same free slot.
type Handler struct {
	// Gate is the join listener's shared pre-authentication bound
	// (bootstrap.Server.PreAuthAllow); it runs before the body is read.
	Gate func(w http.ResponseWriter, r *http.Request) bool
	// HardwarePorts is the system's Thunderbolt mapping (linkenum.HardwarePorts).
	HardwarePorts func(ctx context.Context) (map[string]int, error)
	// Windows is the pairing window, read on every request.
	Windows WindowStore
	// Tokens mints the one-shot token.
	Tokens Minter
	// ClusterPin is the cluster CA pin the minted token carries.
	ClusterPin string
	// JoinPort is the join listener's port, for the returned URL.
	JoinPort int
	// LinkIP returns this server's direct-link address on iface, or "".
	LinkIP func(iface string) string
	// Now is the clock; time.Now when nil.
	Now func() time.Time
	// Logger receives one Warn line per refusal and one Info line per accept.
	Logger *slog.Logger
	// Events records Node Events; nil records none.
	Events Recorder

	mintMu     sync.Mutex
	mu         sync.Mutex
	lastAccept map[string]time.Time
	lastEvent  map[Reason]time.Time
}

// refusalEventInterval rate-limits refusal Events per reason, so a flooder on a
// cable cannot turn the server's event stream into a flood.
const refusalEventInterval = 30 * time.Second

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Handler) log() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.New(slog.DiscardHandler)
}

// ServeHTTP runs the pair verb (see the package doc for the order).
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.Gate != nil && !h.Gate(w, r) {
		return
	}
	local, remote := connAddrs(r)
	ports, err := h.HardwarePorts(r.Context())
	if err != nil {
		// No mapping is no Thunderbolt port: refuse rather than guess.
		ports = nil
		h.log().Warn("pairing: the hardware-port mapping could not be read; refusing", "err", err)
	}
	d := Decide(local, remote, ports)
	if d.Refused != "" {
		h.refuse(w, d.Refused, local, remote, "")
		return
	}
	now := h.now()
	win, ok, err := h.Windows.Load()
	switch {
	case err != nil:
		h.log().Error("pairing: the window could not be read; refusing", "err", err)
		h.refuse(w, ReasonWindowClosed, local, remote, d.Iface)
		return
	case !ok || !now.Before(win.Until):
		h.refuse(w, ReasonWindowClosed, local, remote, d.Iface)
		return
	case win.Completed >= win.MaxJoins:
		h.refuse(w, ReasonWindowFull, local, remote, d.Iface)
		return
	}
	if h.recentlyAccepted(d.Iface, now) {
		h.refuse(w, ReasonRateLimited, local, remote, d.Iface)
		return
	}
	// Everything the connection already tells is decided above, so a request
	// from the wrong port or into a closed window is refused before its body is
	// read at all.
	var req netv1alpha1.PairRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, pairBodyLimit)).Decode(&req); err != nil {
		h.refuse(w, ReasonMalformed, local, remote, d.Iface)
		return
	}
	name, err := bootstrap.CanonicalNodeName(req.NodeName)
	if err != nil || name != req.NodeName || bootstrap.ValidateNodeName(name) != nil {
		h.refuse(w, ReasonBadName, local, remote, d.Iface)
		return
	}
	// The mint cap and the window are re-checked in one locked step, so the last
	// mint cannot be taken twice.
	h.mintMu.Lock()
	defer h.mintMu.Unlock()
	reserved, open, capped, err := h.Windows.ReserveMint(now, h.Tokens.OutstandingOneShot)
	switch {
	case err != nil:
		h.log().Error("pairing: the window could not be updated; refusing", "err", err)
		h.refuse(w, ReasonWindowClosed, local, remote, d.Iface)
		return
	case !open:
		h.refuse(w, ReasonWindowClosed, local, remote, d.Iface)
		return
	case capped:
		h.refuse(w, ReasonMintCap, local, remote, d.Iface)
		return
	}
	user, secret, _, err := h.Tokens.CreateBound(TokenTTL, name, reserved.Until)
	if err != nil {
		h.log().Error("pairing: minting the join token failed", "iface", d.Iface, "err", err)
		http.Error(w, "pairing failed", http.StatusInternalServerError)
		return
	}
	h.markAccepted(d.Iface, now)
	resp := netv1alpha1.PairResponse{
		Version:   netv1alpha1.PairVersion,
		Token:     bootstrap.FormatToken(h.ClusterPin, user, secret),
		ServerURL: "https://" + net.JoinHostPort(local.WithZone("").String(), strconv.Itoa(h.JoinPort)),
	}
	if h.LinkIP != nil {
		resp.ServerLinkIP = h.LinkIP(d.Iface)
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.log().Error("pairing: encode response", "err", err)
		return
	}
	h.log().Info("pairing: accepted a cabled Mac", "iface", d.Iface, "node", name, "remote", remote.String())
	if h.Events != nil {
		h.Events.Record("Normal", "DirectLinkPaired", fmt.Sprintf("minted a one-shot join token for %q over the cable on %s", name, d.Iface))
	}
}

// AdmitJoin is the join-time half of the window's bound
// (bootstrap.ServerConfig.OneShotAdmit): a one-shot token minted by the window
// generation window may complete a join only while that very window is open and
// has joins left. A token of an earlier window, a closed or expired window and a
// full one each refuse with their own reason, logged and recorded like a refused
// pair request.
func (h *Handler) AdmitJoin(window time.Time, node string) error {
	now := h.now()
	win, ok, err := h.Windows.Load()
	reason := Reason("")
	switch {
	case err != nil:
		h.log().Error("pairing: the window could not be read; refusing the join", "err", err)
		reason = ReasonWindowClosed
	case !ok || !now.Before(win.Until) || !win.Until.Equal(window):
		reason = ReasonWindowClosed
	case win.Completed >= win.MaxJoins:
		reason = ReasonWindowFull
	}
	if reason == "" {
		return nil
	}
	h.log().Warn("pairing: refused a join with a pairing token", "reason", string(reason), "node", node)
	if h.Events != nil && h.eventDue(reason) {
		h.Events.Record("Warning", "DirectLinkJoinRefused", fmt.Sprintf("refused a join of %q with a pairing token (%s)", node, reason))
	}
	return fmt.Errorf("the pairing window does not admit this join (%s)", reason)
}

// refuse answers a refused request and records it: a Warn line every time, a
// Node Event at most once per reason per refusalEventInterval.
func (h *Handler) refuse(w http.ResponseWriter, reason Reason, local, remote netip.Addr, iface string) {
	h.log().Warn("pairing: refused a pair request", "reason", string(reason), "iface", iface,
		"local", local.String(), "remote", remote.String())
	if h.Events != nil && h.eventDue(reason) {
		h.Events.Record("Warning", "DirectLinkPairRefused", fmt.Sprintf("refused a pair request (%s) local %s remote %s", reason, local, remote))
	}
	if reason == ReasonRateLimited {
		w.Header().Set("Retry-After", strconv.Itoa(int(AcceptInterval/time.Second)))
	}
	http.Error(w, "pairing refused: "+string(reason), reason.status())
}

func (h *Handler) recentlyAccepted(iface string, now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	last, ok := h.lastAccept[iface]
	return ok && now.Sub(last) < AcceptInterval
}

func (h *Handler) markAccepted(iface string, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.lastAccept == nil {
		h.lastAccept = map[string]time.Time{}
	}
	h.lastAccept[iface] = now
}

func (h *Handler) eventDue(reason Reason) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.lastEvent == nil {
		h.lastEvent = map[Reason]time.Time{}
	}
	now := h.now()
	if last, ok := h.lastEvent[reason]; ok && now.Sub(last) < refusalEventInterval {
		return false
	}
	h.lastEvent[reason] = now
	return true
}

// connAddrs returns the connection's local address (from the server's context)
// and its remote address, each with its zone. An unparseable one is the zero
// Addr, which every check refuses.
func connAddrs(r *http.Request) (local, remote netip.Addr) {
	if la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		local = addrOf(la.String())
	}
	remote = addrOf(r.RemoteAddr)
	return local, remote
}

// addrOf parses a host:port (or a bare host) into an address, keeping the zone.
func addrOf(hostport string) netip.Addr {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a
}
