// Package hostnet makes the ONE construction-time decision for k3sm's
// privileged host-network datapath, selected by the `--network` backend (the
// network analog of the `--runtime` selector):
//
//   - auto (production default): root → direct lo0/utun ops; unprivileged (the
//     _k3sm control plane) → route those ops through the root k3sm-netd helper
//     over its unix socket, with a startup reachability probe that FAILS FAST
//     when no helper is present (so a missing helper never silently wedges pods
//     in ContainerCreating).
//   - none: NO host-network datapath at all (no lo0/utun plumbing) and NO probe
//     — a control-plane-only / CI bring-up backend, analogous to kubelet
//     --network-plugin=none. It is an EXPLICIT testing backend the operator
//     selects, NOT a production fallback: production uses auto, which still
//     fail-fasts when unprivileged with no helper. The sre-flagged pod-wedge
//     hazard is a SILENT no-helper fallback; none is loud and opt-in.
//   - direct: force the direct root ops (requires root).
//   - helper: force the netd helper path (+ probe).
//
// The resolved Mode threads the helper option into each component's constructor
// (darwin-net's WithNetdHelper), reports whether the datapath runs at all
// (DataPath), and probes the helper when one is required.
package hostnet

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"k3sm.io/darwin-net/pkg/mesh"
	"k3sm.io/darwin-net/pkg/netd"
	"k3sm.io/darwin-net/pkg/proxy"
)

// The `--network` flag values.
const (
	// NetworkAuto resolves by privilege: root → direct, unprivileged → helper.
	NetworkAuto = "auto"
	// NetworkNone disables the host-network datapath (control-plane-only / CI).
	NetworkNone = "none"
	// NetworkDirect forces the direct root ops (requires root).
	NetworkDirect = "direct"
	// NetworkHelper forces the netd helper path (+ probe).
	NetworkHelper = "helper"
)

// probeTimeout bounds the startup helper-socket dial so an unreachable helper
// reports quickly rather than hanging server bring-up.
const probeTimeout = 3 * time.Second

// ErrHelperUnreachable is the actionable error a failed startup Probe wraps: the
// unprivileged control plane could not reach the root k3sm-netd helper, so its
// privileged network ops (pod/Service VIP aliases, mesh) cannot run. Proceeding
// would wedge every pod in ContainerCreating, so the daemon fails fast.
var ErrHelperUnreachable = fmt.Errorf("k3sm-netd helper unreachable — run 'sudo k3sm install' and check the io.k3sm.netd daemon (launchctl print system/io.k3sm.netd)")

// Backend is the resolved host-network datapath backend.
type Backend int

const (
	// BackendNone runs no host-network datapath (and no helper probe).
	BackendNone Backend = iota
	// BackendDirect runs the direct, root-gated lo0/utun operations.
	BackendDirect
	// BackendHelper routes the privileged operations through the root k3sm-netd
	// daemon over its unix socket.
	BackendHelper
)

// String renders the backend for logs.
func (b Backend) String() string {
	switch b {
	case BackendNone:
		return "none"
	case BackendDirect:
		return "direct"
	case BackendHelper:
		return "helper"
	default:
		return "unknown"
	}
}

// Mode is the resolved host-network posture.
type Mode struct {
	// Backend is the resolved datapath backend.
	Backend Backend
	// Socket is the k3sm-netd unix socket used when Backend is BackendHelper.
	Socket string
}

// Resolve maps a `--network` flag value to a Mode for the current process. An
// empty value is treated as auto. It errors on an unknown value, or on direct
// when not root.
func Resolve(network string) (Mode, error) {
	return resolveMode(network, os.Geteuid(), netd.DefaultSocketPath)
}

// resolveMode is the testable core of Resolve.
func resolveMode(network string, euid int, defaultSocket string) (Mode, error) {
	switch network {
	case "", NetworkAuto:
		if euid == 0 {
			return Mode{Backend: BackendDirect}, nil
		}
		return Mode{Backend: BackendHelper, Socket: defaultSocket}, nil
	case NetworkNone:
		return Mode{Backend: BackendNone}, nil
	case NetworkDirect:
		if euid != 0 {
			return Mode{}, fmt.Errorf("--network direct requires root (euid 0), got %d; use 'auto' or 'none'", euid)
		}
		return Mode{Backend: BackendDirect}, nil
	case NetworkHelper:
		return Mode{Backend: BackendHelper, Socket: defaultSocket}, nil
	default:
		return Mode{}, fmt.Errorf("unknown --network %q (want %s, %s, %s, or %s)", network, NetworkAuto, NetworkNone, NetworkDirect, NetworkHelper)
	}
}

// DataPath reports whether the host-network datapath runs at all. It is false
// only for BackendNone (control-plane-only / CI): callers skip the Service proxy
// and the mesh entirely rather than plumbing lo0/utun.
func (m Mode) DataPath() bool { return m.Backend != BackendNone }

// UsesHelper reports whether privileged ops route through the netd helper (the
// unprivileged production posture). It gates helper-only concerns (e.g. the
// foreign-runAsUser admission policy, which exists because the unprivileged
// runtime runs every pod as the single _k3sm uid).
func (m Mode) UsesHelper() bool { return m.Backend == BackendHelper }

// ProxyOptions returns the darwin-net Service-proxy options for this mode: the
// netd-helper option (wiring BOTH the lo0 VIP alias manager and the
// privileged-port binder through the daemon) for BackendHelper, else none (the
// direct path for BackendDirect; BackendNone callers do not run the proxy).
func (m Mode) ProxyOptions() []proxy.Option {
	if m.Backend != BackendHelper {
		return nil
	}
	return []proxy.Option{proxy.WithNetdHelper(m.Socket)}
}

// MeshOptions returns the darwin-net mesh options for this mode: the netd-helper
// option (the daemon owns the utun/wireguard datapath and resolves privKeyRef to
// the node's private key root-side, so the key never crosses the socket) for
// BackendHelper, else none (the direct run-as-root wireguard device for
// BackendDirect; BackendNone callers do not run the mesh). privKeyRef is the
// opaque reference the daemon resolves; it is ignored in the direct mode.
func (m Mode) MeshOptions(privKeyRef string) []mesh.Option {
	if m.Backend != BackendHelper {
		return nil
	}
	return []mesh.Option{mesh.WithNetdHelper(m.Socket, privKeyRef)}
}

// Probe verifies the helper is reachable at startup when (and only when) the
// helper backend is selected: it dials the unix socket (a successful connect
// proves the daemon is listening) and returns ErrHelperUnreachable on failure so
// bring-up aborts with an actionable message rather than silently proceeding.
// For BackendDirect and BackendNone it is a no-op (no helper to reach).
func (m Mode) Probe(ctx context.Context) error {
	if m.Backend != BackendHelper {
		return nil
	}
	d := net.Dialer{Timeout: probeTimeout}
	dialCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	conn, err := d.DialContext(dialCtx, "unix", m.Socket)
	if err != nil {
		return fmt.Errorf("%w: dial %s: %v", ErrHelperUnreachable, m.Socket, err)
	}
	_ = conn.Close()
	return nil
}
