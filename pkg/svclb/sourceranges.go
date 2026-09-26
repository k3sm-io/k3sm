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

package svclb

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
)

// SourceRangesAnnotation is the legacy, pre-field spelling of
// spec.loadBalancerSourceRanges: a comma-separated CIDR list. Upstream still
// honours it when the spec field is empty, and so does SourceRanges.
const SourceRangesAnnotation = "service.beta.kubernetes.io/load-balancer-source-ranges"

// EventReasonSourceRangesInvalid is the reason of the Warning Event recorded on a
// Service whose source ranges do not parse.
const EventReasonSourceRangesInvalid = "SourceRangesInvalid"

// ErrInvalidSourceRange is the sentinel every SourceRanges parse failure wraps.
var ErrInvalidSourceRange = errors.New("invalid source range")

// maxEntryRunes caps how much of an offending entry an error echoes. The error
// text reaches a Service Event, readable by anyone who can read Events, so an
// arbitrary annotation value is never reflected in full; the callers log the
// full value at Debug.
const maxEntryRunes = 48

// truncateEntry shortens e to maxEntryRunes runes.
func truncateEntry(e string) string {
	r := []rune(e)
	if len(r) <= maxEntryRunes {
		return e
	}
	return string(r[:maxEntryRunes]) + "..."
}

// Ranges is a parsed set of client source ranges for a LoadBalancer. A nil or
// empty Ranges allows every peer (upstream's 0.0.0.0/0 default).
type Ranges []netip.Prefix

// SourceRanges resolves svc's LoadBalancer source ranges, the ONE home of the
// rule for both svclb and the ingress host. Precedence is upstream's
// GetLoadBalancerSourceRanges: spec.loadBalancerSourceRanges when non-empty,
// else the legacy SourceRangesAnnotation, else allow-all (nil). Every entry is
// TrimSpace'd and parsed; the set is ALL-OR-NOTHING, so a single malformed entry
// fails the whole set with an error rather than enforcing a narrower or wider
// set than the author wrote. The caller decides what a failure means (fail
// closed on first provisioning, keep the last valid set on an edit).
func SourceRanges(svc *corev1.Service) (Ranges, error) {
	if svc == nil {
		return nil, nil
	}
	var (
		entries []string
		source  string
	)
	if len(svc.Spec.LoadBalancerSourceRanges) > 0 {
		entries, source = svc.Spec.LoadBalancerSourceRanges, "spec.loadBalancerSourceRanges"
	} else if v := strings.TrimSpace(svc.Annotations[SourceRangesAnnotation]); v != "" {
		entries, source = strings.Split(v, ","), "annotation "+SourceRangesAnnotation
	}
	if len(entries) == 0 {
		return nil, nil
	}
	out := make(Ranges, 0, len(entries))
	for _, e := range entries {
		// The netip error is deliberately NOT wrapped: its text quotes the whole
		// input, which would defeat the truncation.
		p, err := netip.ParsePrefix(strings.TrimSpace(e))
		if err != nil {
			return nil, fmt.Errorf("%s: %w: %q is not a CIDR", source, ErrInvalidSourceRange, truncateEntry(e))
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// Allows reports whether peer may use the LoadBalancer. An empty set allows
// everyone. The peer is Unmapped first: the wildcard accept is dual-stack, so an
// IPv4 client arrives as ::ffff:a.b.c.d and must still match an IPv4 range.
// There is deliberately no loopback exemption (upstream has none).
func (r Ranges) Allows(peer netip.Addr) bool {
	if len(r) == 0 {
		return true
	}
	peer = peer.Unmap()
	for _, p := range r {
		if p.Contains(peer) {
			return true
		}
	}
	return false
}

// AllowsConn applies Allows to conn's remote address. A peer address that cannot
// be read fails CLOSED when a range set is in force (nothing to match against)
// and open when none is.
func (r Ranges) AllowsConn(conn net.Conn) bool {
	if len(r) == 0 {
		return true
	}
	peer, ok := peerAddr(conn)
	return ok && r.Allows(peer)
}

// peerAddr extracts the remote IP of conn. The *net.TCPAddr branch is the only
// one reachable in production: both binders (netbind.Direct, and netbind.Netd's
// net.FileListener over the helper's TCP socket) hand back TCP listeners whose conns report a
// *net.TCPAddr. The ParseAddrPort fallback is defensive, for a wrapped conn
// whose address type is unknown.
func peerAddr(conn net.Conn) (netip.Addr, bool) {
	ra := conn.RemoteAddr()
	if ra == nil {
		return netip.Addr{}, false
	}
	if t, ok := ra.(*net.TCPAddr); ok {
		ap := t.AddrPort()
		return ap.Addr(), ap.Addr().IsValid()
	}
	ap, err := netip.ParseAddrPort(ra.String())
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr(), true
}

// SourceRangesLogArgs renders svc's UNTRUNCATED range inputs as slog key/value
// pairs for a Debug line; the SourceRanges error (and so the Event) carries only
// a truncated entry.
func SourceRangesLogArgs(svc *corev1.Service) []any {
	return []any{"spec", svc.Spec.LoadBalancerSourceRanges, "annotation", svc.Annotations[SourceRangesAnnotation]}
}

// NewEventRecorder builds a minimal Event recorder on client for component,
// returning it with the shutdown func that stops the broadcaster's goroutine.
// Both svclb and the ingress host use it to record EventReasonSourceRangesInvalid
// on the Service itself.
func NewEventRecorder(client kubernetes.Interface, component string) (record.EventRecorder, func()) {
	b := record.NewBroadcaster()
	b.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: client.CoreV1().Events("")})
	return b.NewRecorder(scheme.Scheme, corev1.EventSource{Component: component}), b.Shutdown
}
