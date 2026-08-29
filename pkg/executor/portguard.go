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

package executor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// ErrDatastorePortHeld is returned when the datastore (kine) listen port is
// already held by another process at bring-up. It is a sentinel so a caller can
// distinguish "someone else owns this datastore port" from any other start
// failure with errors.Is.
var ErrDatastorePortHeld = errors.New("executor: datastore port already held by another process")

// holderProbeTimeout bounds the best-effort lsof lookup that names the holder.
// The refusal itself never depends on it — a slow or absent lsof must not turn a
// fail-closed refusal into a hang.
const holderProbeTimeout = 2 * time.Second

// preflightDatastorePort fail-closes bring-up when the kine listen port is
// already bound.
//
// This is the guard against the WORST failure mode in this package, which is not
// a bind error. kine is started, then bring-up waits for "the datastore port
// accepts a connection" — a condition ANOTHER server's kine already satisfies.
// So a second control plane started against a held port observes an instantly
// ready datastore, points its apiserver at 127.0.0.1:<port>, and comes up
// REPORTING HEALTHY (Ready node, healthy apiserver) while serving the INCUMBENT's
// database and never creating its own state.db. Two clusters then believe they
// own one datastore, and it looks like success. Refusing before the spawn is the
// only place that distinction can still be made: after it, every downstream
// signal is indistinguishable from a correct boot.
//
// Nothing of ours can legitimately hold the port here — this runs immediately
// before we spawn our own kine, so any listener is by definition foreign (a
// second `k3sm server`, a second dev instance, an orphaned kine, or an unrelated
// etcd). The probe is a real bind of 127.0.0.1:<port>, which also catches a
// holder bound on the wildcard, and it fails closed: any bind error at all is a
// refusal, because a port we cannot take is a port our kine cannot take either.
//
// The bind is released before returning, so a racer could still take the port in
// the gap; that window is microseconds against a condition that persists for the
// life of an incumbent cluster, and kine's own bind error remains the backstop
// for it.
func preflightDatastorePort(ctx context.Context, port int) error {
	if port <= 0 {
		return nil
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		return ln.Close()
	}
	holder := portHolder(ctx, port)
	if holder == "" {
		holder = "an unidentified process"
	}
	return fmt.Errorf("%w: %s is held by %s — this control plane would be served from that process's datastore instead of its own; stop it or run with a different datastore port (probe: %v)",
		ErrDatastorePortHeld, addr, holder, err)
}

// ErrComponentPortHeld is returned when a co-located control-plane component's
// own loopback secure port is already held at bring-up. Separate sentinel from
// ErrDatastorePortHeld because the consequence differs: a held datastore port
// means serving someone else's DATA, a held component port means running without
// that component at all.
var ErrComponentPortHeld = errors.New("executor: control-plane component port already held by another process")

// preflightComponentPort fail-closes bring-up when the port a component is about
// to bind is already taken.
//
// The readiness wait after the spawn cannot cover this case, and the reason is
// worth stating because it is the same trap the datastore had: the wait's ready
// condition is "the port accepts a connection", which the INCUMBENT satisfies.
// So the component dies on `bind: address already in use`, the probe succeeds
// against the other process's listener, and bring-up continues — reporting
// healthy while running with no scheduler, or with no controller-manager and
// therefore no service-account controller, whose absence then surfaces as a
// namespace bootstrap that never completes. Observed exactly that way.
//
// Refusing before the spawn is the only point where the distinction can still be
// made, and here it needs no ownership heuristic: our own component has not
// started, so any listener is foreign by construction. The probe is a real bind
// (which also catches a wildcard holder) and fails closed on any bind error at
// all. The bind is released before returning, so a racer could take the port in
// the gap; the component's own bind error plus the readiness wait remain the
// backstop for that window.
func preflightComponentPort(ctx context.Context, name string, port int) error {
	if port <= 0 {
		return nil
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		return ln.Close()
	}
	holder := portHolder(ctx, port)
	if holder == "" {
		holder = "an unidentified process"
	}
	return fmt.Errorf("%w: %s wants %s, which is held by %s — it would die on the bind while this control plane came up without it; stop that process or give this server its own %s port (probe: %v)",
		ErrComponentPortHeld, name, addr, holder, name, err)
}

// portHolder best-effort names the process listening on port, as
// "pid 4711 (kine)", so the refusal points at what to stop. lsof is the only way
// to map a listening socket to a pid on Darwin without a private SPI; it is run
// with a short deadline and ANY failure (absent, slow, no permission to see the
// owner) yields "" rather than an error, because the refusal must stand on the
// bind result alone. With several holders the last reported one is named — the
// message is a pointer for a human, not an inventory.
func portHolder(ctx context.Context, port int) string {
	ctx, cancel := context.WithTimeout(ctx, holderProbeTimeout)
	defer cancel()
	// -F p,c is lsof's machine-readable form: one field per line, tagged by its
	// first byte ('p' = pid, 'c' = command).
	out, err := exec.CommandContext(ctx, "lsof", "-nP", "-Fpc",
		"-iTCP:"+strconv.Itoa(port), "-sTCP:LISTEN").Output()
	if err != nil {
		return ""
	}
	var pid, comm string
	for _, line := range strings.Split(string(out), "\n") {
		if len(line) < 2 {
			continue
		}
		switch line[0] {
		case 'p':
			pid, comm = line[1:], ""
		case 'c':
			comm = line[1:]
		}
	}
	switch {
	case pid == "":
		return ""
	case comm == "":
		return "pid " + pid
	default:
		return "pid " + pid + " (" + comm + ")"
	}
}
