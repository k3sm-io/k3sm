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
	"net/netip"
	"strconv"
	"time"

	"golang.org/x/net/ipv6"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
)

const (
	// BeaconPort is the UDP port beacons are sent to and received on.
	BeaconPort = 9346
	// BeaconInterval is how often the server sends a beacon on each port.
	BeaconInterval = 2 * time.Second
	// maxBeaconBytes bounds a received datagram; a beacon is a few hundred bytes.
	maxBeaconBytes = 1024
)

// allNodes is ff02::1, the link-local all-nodes group the beacon is sent to.
var allNodes = net.ParseIP("ff02::1")

// Sender sends this server's beacon on one interface every BeaconInterval until
// ctx ends. The beacon is rebuilt every time (Beacon), so the pairing state it
// carries follows the window file.
type Sender struct {
	// Iface is the cable interface to send on.
	Iface string
	// Beacon returns the beacon to send now.
	Beacon func() netv1alpha1.Beacon
	// Logger receives send failures at Debug (an interface without a link-local
	// address yet fails until DAD completes, which is not news).
	Logger *slog.Logger
}

// Run sends until ctx ends. A socket that cannot be opened is retried on the next
// tick rather than ending the sender: the interface may still be completing DAD.
func (s Sender) Run(ctx context.Context) {
	log := s.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	t := time.NewTicker(BeaconInterval)
	defer t.Stop()
	for {
		if err := s.sendOnce(); err != nil {
			log.Debug("pairing: beacon not sent", "iface", s.Iface, "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s Sender) sendOnce() error {
	b, err := json.Marshal(s.Beacon())
	if err != nil {
		return fmt.Errorf("encode beacon: %w", err)
	}
	c, err := net.ListenPacket("udp6", "[::]:0")
	if err != nil {
		return fmt.Errorf("open beacon socket on %s: %w", s.Iface, err)
	}
	defer c.Close()
	ifi, err := net.InterfaceByName(s.Iface)
	if err != nil {
		return fmt.Errorf("find %s: %w", s.Iface, err)
	}
	pc := ipv6.NewPacketConn(c)
	if err := pc.SetMulticastInterface(ifi); err != nil {
		return fmt.Errorf("select %s for multicast: %w", s.Iface, err)
	}
	_ = pc.SetMulticastHopLimit(1) // link-local; a router never forwards it anyway
	if _, err := c.WriteTo(b, &net.UDPAddr{IP: allNodes, Port: BeaconPort, Zone: s.Iface}); err != nil {
		return fmt.Errorf("send beacon on %s: %w", s.Iface, err)
	}
	return nil
}

// Heard is one beacon a receiver accepted for consideration: what it claims, the
// link-local address it came from and the interface it arrived on.
type Heard struct {
	Beacon netv1alpha1.Beacon
	Src    netip.Addr
	Iface  string
}

// PairAddress is the join listener the beacon's sender answers on, as this Mac
// reaches it: the sender's link-local address with THIS Mac's arrival interface
// as its zone.
func (h Heard) PairAddress() string {
	port := int(h.Beacon.JoinPort)
	if port <= 0 {
		port = 9345
	}
	return net.JoinHostPort(h.Src.WithZone(h.Iface).String(), strconv.Itoa(port))
}

// Receive listens for beacons on [::]:BeaconPort, joins ff02::1 on every named
// interface, and delivers each parsed beacon that arrived on one of them, with
// its arrival interface taken from IPV6_RECVPKTINFO (never from the datagram).
// The channel closes when ctx ends.
func Receive(ctx context.Context, ifaces []string, log *slog.Logger) (<-chan Heard, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	c, err := net.ListenPacket("udp6", net.JoinHostPort("::", strconv.Itoa(BeaconPort)))
	if err != nil {
		return nil, fmt.Errorf("listen for beacons on port %d: %w", BeaconPort, err)
	}
	pc := ipv6.NewPacketConn(c)
	if err := pc.SetControlMessage(ipv6.FlagInterface, true); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("enable IPV6_RECVPKTINFO: %w", err)
	}
	allowed := map[int]string{}
	for _, name := range ifaces {
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			log.Debug("pairing: not listening on an absent interface", "iface", name, "err", err)
			continue
		}
		if err := pc.JoinGroup(ifi, &net.UDPAddr{IP: allNodes}); err != nil {
			log.Debug("pairing: could not join ff02::1", "iface", name, "err", err)
		}
		allowed[ifi.Index] = ifi.Name
	}
	out := make(chan Heard, 16)
	go func() {
		<-ctx.Done()
		_ = c.Close()
	}()
	go func() {
		defer close(out)
		buf := make([]byte, maxBeaconBytes)
		for {
			n, cm, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if cm == nil {
				continue
			}
			iface, ok := allowed[cm.IfIndex]
			if !ok {
				continue
			}
			ua, ok := from.(*net.UDPAddr)
			if !ok {
				continue
			}
			src, ok := netip.AddrFromSlice(ua.IP)
			if !ok || !src.IsLinkLocalUnicast() {
				continue
			}
			var b netv1alpha1.Beacon
			if json.Unmarshal(buf[:n], &b) != nil {
				continue
			}
			select {
			case out <- Heard{Beacon: b, Src: src.WithZone(""), Iface: iface}:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}
