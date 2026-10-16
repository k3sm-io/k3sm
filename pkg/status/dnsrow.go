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

package status

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"k3sm.io/darwin-net/pkg/dns"
	"k3sm.io/darwin-net/pkg/tcpseg"
	"k3sm.io/k3sm/pkg/dataroot"
)

// dnsProbeName is the name the dns row asks for. The kubernetes Service exists
// in every cluster from the apiserver's first start, so a resolver that is
// serving always has an address for it.
const dnsProbeName = "kubernetes.default.svc.cluster.local"

// dnsProbeTimeout bounds each query the dns row sends: the UDP one, and the TCP
// one that follows only when UDP did not answer.
const dnsProbeTimeout = 3 * time.Second

// ErrDNSNoAddress is the error a DNSQuerier wraps when the resolver answered
// but its reply carries no address for the name: an error rcode, a reply to
// another query, or an empty answer section.
var ErrDNSNoAddress = errors.New("no address in the reply")

// DNSQuerier sends one DNS question for name's A record to server over network
// ("udp" or "tcp") and returns the first address answered. A reply that names
// no address is an error wrapping ErrDNSNoAddress; any other error means no
// usable reply arrived before ctx ended.
type DNSQuerier interface {
	Query(ctx context.Context, network string, server netip.AddrPort, name string) (netip.Addr, error)
}

// dnsRow asks this node's resolver, at the cluster DNS VIP, for the kubernetes
// Service over UDP, the way pods and the host resolver ask. The node-resolver
// row says the host routes cluster names to the VIP; this row says something
// answers there. A UDP socket that stopped receiving while TCP 53 still answers
// is the failure it exists for, so when UDP is silent it asks over TCP too and
// names the TCP answer in wide.tcp. ok is false when no querier was wired in.
//
// The row needs no privilege: the VIP is a lo0 alias any account can reach.
func (c Collector) dnsRow(ctx context.Context, role dataroot.Role, installed bool, node Row) (Row, bool) {
	if c.DNS == nil {
		return Row{}, false
	}
	row := Row{Name: RowDNS}
	if !installed {
		row.State, row.Severity = StateSkip, SeveritySkip
		row.Detail = "k3sm is not installed, so there is no node resolver to ask"
		return row, true
	}
	if nodeStopped(node.State) {
		row.State, row.Severity = StateSkip, SeveritySkip
		row.Detail = fmt.Sprintf("%s is %s, so there is no node resolver to ask", c.nodeLabel(role), node.State)
		return row, true
	}
	vip, err := c.dnsVIP(role)
	if err != nil {
		row.State, row.Severity = StateUnknown, SeverityUnknown
		row.Detail = errText(err)
		return row, true
	}
	server := netip.AddrPortFrom(vip, dns.DefaultDNSPort)
	row.Wide = map[string]string{"vip": vip.String(), "name": dnsProbeName}

	addr, err := c.queryDNS(ctx, "udp", server)
	if err == nil {
		row.State, row.Severity = StateOK, SeverityOK
		row.Detail = fmt.Sprintf("%s answered %s over UDP for %s", vip, addr, dnsProbeName)
		row.Wide["answer"] = addr.String()
		return row, true
	}
	row.State, row.Severity = StateDown, SeverityWarn
	row.Remedy = c.nodeKickstart(role)
	if errors.Is(err, ErrDNSNoAddress) {
		row.State = StateUnhealthy
		row.Detail = fmt.Sprintf("the resolver at %s answered over UDP with no address for %s: %s", vip, dnsProbeName, errText(err))
		return row, true
	}
	row.Detail = fmt.Sprintf("the resolver at %s did not answer over UDP in %s", vip, durationText(dnsProbeTimeout))
	if tcpAddr, terr := c.queryDNS(ctx, "tcp", server); terr == nil {
		row.Wide["tcp"] = fmt.Sprintf("answered %s over TCP: the resolver is up and its UDP socket is not receiving", tcpAddr)
	}
	return row, true
}

// queryDNS sends one query through the wired querier, bounded by
// dnsProbeTimeout.
func (c Collector) queryDNS(ctx context.Context, network string, server netip.AddrPort) (netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, dnsProbeTimeout)
	defer cancel()
	return c.DNS.Query(ctx, network, server, dnsProbeName)
}

// durationText renders a whole-second timeout as "3 s".
func durationText(d time.Duration) string {
	return fmt.Sprintf("%d s", int(d/time.Second))
}

// nodeStopped reports whether a node daemon row's state means the daemon is
// not running, so the resolver it serves is not there either.
func nodeStopped(s RowState) bool {
	return downStates[s] || s == StateCrashLoop || s == StateFailed
}

// dnsVIP is the address this node's resolver serves on: the --dns-vip the
// installed node daemon runs with, else the default the daemon takes when the
// flag is absent (dns.DefaultDNSVIP, the tenth address of the default Service
// CIDR). install never writes the flag itself, so it is set only when the
// operator passed it.
func (c Collector) dnsVIP(role dataroot.Role) (netip.Addr, error) {
	value := dns.DefaultDNSVIP
	if c.NodeArgs != nil {
		if args, err := c.NodeArgs(role); err == nil {
			if v, ok := argValue(args, "dns-vip"); ok {
				value = v
			}
		}
	}
	vip, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("the node daemon's --dns-vip %q is not an address, so it serves no resolver", value)
	}
	return vip, nil
}

// argValue is the value of flag name in args (as --name v, --name=v, -name v
// or -name=v), the way Go's flag package reads it; the last one wins.
func argValue(args []string, name string) (string, bool) {
	var value string
	found := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			continue
		}
		flagName, v, inline := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if flagName != name {
			continue
		}
		if !inline {
			if i+1 >= len(args) {
				continue
			}
			i++
			v = args[i]
		}
		value, found = v, true
	}
	return value, found
}

// NetDNS is the production DNSQuerier: one query over a real socket, dialled
// through the segment-clamped dialer (a no-op for UDP, and the clamp every TCP
// connection this process opens must carry).
type NetDNS struct{}

// dnsMaxUDP is the largest UDP reply NetDNS reads. The query carries no EDNS
// option, so a conforming server sends at most 512 bytes.
const dnsMaxUDP = 512

// Query implements DNSQuerier.
func (NetDNS) Query(ctx context.Context, network string, server netip.AddrPort, name string) (netip.Addr, error) {
	id := uint16(rand.Uint32())
	query, err := buildDNSQuery(id, name)
	if err != nil {
		return netip.Addr{}, err
	}
	conn, err := (&tcpseg.Dialer{}).DialContext(ctx, network, server.String())
	if err != nil {
		return netip.Addr{}, err
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(dl); err != nil {
			return netip.Addr{}, err
		}
	}
	var reply []byte
	if network == "tcp" {
		framed := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
		if _, err := conn.Write(append(framed, query...)); err != nil {
			return netip.Addr{}, err
		}
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return netip.Addr{}, err
		}
		reply = make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err := io.ReadFull(conn, reply); err != nil {
			return netip.Addr{}, err
		}
	} else {
		if _, err := conn.Write(query); err != nil {
			return netip.Addr{}, err
		}
		buf := make([]byte, dnsMaxUDP)
		n, err := conn.Read(buf)
		if err != nil {
			return netip.Addr{}, err
		}
		reply = buf[:n]
	}
	return parseDNSAnswer(id, reply)
}

// buildDNSQuery is a recursive A query for name with the given id.
func buildDNSQuery(id uint16, name string) ([]byte, error) {
	qname, err := dnsmessage.NewName(strings.TrimSuffix(name, ".") + ".")
	if err != nil {
		return nil, fmt.Errorf("dns query name %q: %w", name, err)
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: qname, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	return msg.Pack()
}

// parseDNSAnswer returns the first A record of a reply to query id. A reply
// that does not parse, answers another id, carries an error rcode or holds no
// A record wraps ErrDNSNoAddress.
func parseDNSAnswer(id uint16, reply []byte) (netip.Addr, error) {
	var p dnsmessage.Parser
	h, err := p.Start(reply)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%w: unparsable reply: %v", ErrDNSNoAddress, err)
	}
	if !h.Response || h.ID != id {
		return netip.Addr{}, fmt.Errorf("%w: the reply answers another query", ErrDNSNoAddress)
	}
	if h.RCode != dnsmessage.RCodeSuccess {
		return netip.Addr{}, fmt.Errorf("%w: rcode %s", ErrDNSNoAddress, h.RCode)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return netip.Addr{}, fmt.Errorf("%w: unparsable reply: %v", ErrDNSNoAddress, err)
	}
	for {
		ah, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			return netip.Addr{}, fmt.Errorf("%w: empty answer section", ErrDNSNoAddress)
		}
		if err != nil {
			return netip.Addr{}, fmt.Errorf("%w: unparsable reply: %v", ErrDNSNoAddress, err)
		}
		if ah.Type != dnsmessage.TypeA {
			if err := p.SkipAnswer(); err != nil {
				return netip.Addr{}, fmt.Errorf("%w: unparsable reply: %v", ErrDNSNoAddress, err)
			}
			continue
		}
		a, err := p.AResource()
		if err != nil {
			return netip.Addr{}, fmt.Errorf("%w: unparsable reply: %v", ErrDNSNoAddress, err)
		}
		return netip.AddrFrom4(a.A), nil
	}
}
