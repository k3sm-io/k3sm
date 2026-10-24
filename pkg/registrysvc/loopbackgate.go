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

package registrysvc

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
)

// THE LOOPBACK GATE: the push gate served over HTTPS on this server's own
// loopback, at GatePort(registry port), so the k3sm CLI and any OCI tool on the
// server push the way a worker does, with a builder token the gate checks,
// instead of with the registry's per-boot credential.
//
// It is a separate construction from NewRelay on purpose. NewRelay refuses a
// loopback bind, because relaying loopback to loopback for the CLUSTER-facing
// relay exposes nothing new while looking like it does; that refusal stands.
// This gate binds 127.0.0.1 only, never the wildcard and never another
// address, and fronts the same loopback registry on a DIFFERENT port: the
// registry's own listener keeps serving the node's runtime and the gate's own
// upstream, and is never where a user's write is sent.
//
// It shares the relay's mechanics whole: TLS under a certificate the cluster
// CA issues (names localhost, 127.0.0.1 and registry-k3sm), the token-checking
// gate, the connection caps and the per-source limits (every caller is
// 127.0.0.1 here, so the shares are one Mac's).

// GatePortOffset is how far above the registry's loopback port the loopback
// gate listens: the default registry port 6450 puts the gate on 6451.
const GatePortOffset = 1

// GatePort is the loopback gate's port for a registry serving on registryPort.
func GatePort(registryPort int) int { return registryPort + GatePortOffset }

// ErrLoopbackGatePort reports a loopback gate port that cannot be served: out
// of range, or the registry's own port.
var ErrLoopbackGatePort = errors.New("the loopback push gate needs a port of its own")

// LoopbackGateConfig configures the loopback gate.
type LoopbackGateConfig struct {
	// RegistryPort is the registry's loopback port, the gate's upstream.
	RegistryPort int
	// Port is the port the gate binds on 127.0.0.1 (GatePort(RegistryPort)).
	Port int
	// Auth, GateCredential and Serving are as for RelayConfig. Serving is
	// required: the gate never serves plain HTTP.
	Auth           GateAuth
	GateCredential Credential
	Serving        *ServingIdentity
	// Listen overrides how the one admitted address is bound (tests). nil is
	// the shipped TCP listener.
	Listen func(addr string) (net.Listener, error)
	// OnListen is called with the address once it is bound.
	OnListen func(addr string)
	// Logger receives bind and push-decision events. nil means slog.Default.
	Logger *slog.Logger
}

// NewLoopbackGate validates cfg and returns the loopback gate, a Relay whose
// one bind is 127.0.0.1:cfg.Port.
func NewLoopbackGate(cfg LoopbackGateConfig) (*Relay, error) {
	if cfg.RegistryPort <= 0 || cfg.RegistryPort > 65535 {
		return nil, fmt.Errorf("serve the loopback push gate: registry port %d is out of range 1-65535", cfg.RegistryPort)
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return nil, fmt.Errorf("%w: %d is out of range 1-65535", ErrLoopbackGatePort, cfg.Port)
	}
	if cfg.Port == cfg.RegistryPort {
		return nil, fmt.Errorf("%w: %d is the registry's own port", ErrLoopbackGatePort, cfg.Port)
	}
	if cfg.Serving == nil {
		return nil, ErrNoServingIdentity
	}
	bind := netip.MustParseAddr(LoopbackAddress)
	r := newRelay(cfg.Port, cfg.RegistryPort, []netip.Addr{bind}, cfg.Logger, cfg.Auth, cfg.GateCredential)
	r.tls = cfg.Serving.TLSConfig()
	if cfg.Listen != nil {
		r.listen = cfg.Listen
	}
	r.onListen = cfg.OnListen
	return r, nil
}

// LoopbackGateDNSNames are the DNS SANs of the loopback gate's certificate:
// localhost, which a Mac tool dials, and the flat registry name, which the k3sm
// CLI verifies every cluster-registry endpoint against.
func LoopbackGateDNSNames() []string { return []string{"localhost", FlatServiceName} }

// LoopbackGateIPs are the IP SANs of the loopback gate's certificate.
func LoopbackGateIPs() []net.IP { return []net.IP{net.ParseIP(LoopbackAddress)} }
