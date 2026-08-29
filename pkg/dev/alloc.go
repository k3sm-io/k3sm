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

package dev

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
)

// Port-allocation bounds. The dev tier deliberately avoids the fixed-port
// defaults the acceptance gates use (6444/2379/10250 — see hack/lib/clusterup.sh)
// so a dev instance never collides with an acceptance run or a second dev
// instance. The window is high (ephemeral-ish) and wide enough for many parallel
// rootless instances.
const (
	apiPortBase  = 16440
	kinePortBase = 12379
	// kubeletPortBase seeds the node's kubelet-API port (logs/exec/stats). It is
	// clear of the fixed control-plane singletons the base must not overlap —
	// 10250 itself, and the scheduler/controller-manager 10259/10257 — so a probe
	// that walks the whole span still never lands on one of them.
	kubeletPortBase = 10450
	// portSpan bounds the linear probe from each base — 512 candidate ports is
	// far more than the realistic parallel-instance count, and keeps the search
	// bounded so a wedged host fails fast rather than scanning 64k ports.
	portSpan = 512
	// portStride separates an instance's per-port hash seeds so a hash collision
	// on one port does not also collide the next.
	portStride = 2
)

// allocatePorts picks a free (apiPort, kinePort, kubeletPort) triple for name,
// deterministically SEEDED from (name × euid) so re-running `up <name>` prefers
// the same ports (a stable dev loop), then linearly probing forward past any that
// are currently bound (System.PortFree) so parallel rootless instances never
// collide. It errors only if the whole window is saturated. The three ports are
// drawn from disjoint bases so they cannot alias each other.
//
// EVERY singleton listener an instance owns has to be in here. The kubelet API
// port joined the pair because it is the node's own listener: two instances that
// each bind the one fixed default contend for it, and the loser's node exits
// bring-up with "bind: address already in use" — the same defect the datastore
// port had, one process further down.
func allocatePorts(sys System, name string, euid int) (apiPort, kinePort, kubeletPort int, err error) {
	seed := hashSeed(name, euid)
	apiPort, err = probeFreePort(sys, apiPortBase, int(seed%portSpan))
	if err != nil {
		return 0, 0, 0, fmt.Errorf("allocate apiserver port: %w", err)
	}
	kinePort, err = probeFreePort(sys, kinePortBase, int((seed/portStride)%portSpan))
	if err != nil {
		return 0, 0, 0, fmt.Errorf("allocate kine port: %w", err)
	}
	kubeletPort, err = probeFreePort(sys, kubeletPortBase, int((seed/(portStride*portStride))%portSpan))
	if err != nil {
		return 0, 0, 0, fmt.Errorf("allocate kubelet port: %w", err)
	}
	// A degenerate hash could land two of them on the same absolute number only if
	// their bases were less than a span apart; the closest two bases are 1929
	// apart, so this cannot happen — but assert it so a future base change can't
	// silently break it.
	for _, c := range []struct {
		a, b   string
		pa, pb int
	}{
		{"apiserver", "kine", apiPort, kinePort},
		{"apiserver", "kubelet", apiPort, kubeletPort},
		{"kine", "kubelet", kinePort, kubeletPort},
	} {
		if c.pa == c.pb {
			return 0, 0, 0, fmt.Errorf("allocated %s and %s ports collide on %d", c.a, c.b, c.pa)
		}
	}
	return apiPort, kinePort, kubeletPort, nil
}

// probeFreePort linear-scans base+offset, base+offset+1, … (wrapping within
// [base, base+portSpan)) for the first port System reports free.
func probeFreePort(sys System, base, offset int) (int, error) {
	for i := 0; i < portSpan; i++ {
		p := base + (offset+i)%portSpan
		if sys.PortFree(p) {
			return p, nil
		}
	}
	return 0, fmt.Errorf("no free port in [%d,%d)", base, base+portSpan)
}

// hashSeed derives a stable non-negative seed from (name, euid) so an instance's
// preferred ports and workdir are reproducible across `up` runs but distinct per
// name and per user.
func hashSeed(name string, euid int) uint64 {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d", name, euid)))
	return binary.BigEndian.Uint64(h[:8])
}

// lo0FlushCIDRs sweeps the lo0 /32 aliases that fall inside any of the given
// CIDRs — the datapath teardown + pre-flight reclaim step. cluster_down (and the
// dev teardown) reaps PROCESSES but NOT kernel-global lo0 aliases, which outlive
// the process on the shared lo0; a stale Service/pod VIP alias would then absorb
// traffic or fail a re-boot's alias add. It lists lo0 (System.Lo0Aliases),
// removes only addresses inside a target CIDR (System.Lo0RemoveAlias), and
// returns the addresses it removed. Removing a lo0 alias needs root; the rootless
// tier (network=none) allocates none, so this is a no-op over an empty set there.
// Best-effort per alias: a remove error is collected but does not abort the sweep
// (one wedged alias must not block flushing the rest).
func lo0FlushCIDRs(sys System, cidrs ...string) (removed []string, err error) {
	var prefixes []netip.Prefix
	for _, c := range cidrs {
		if c == "" {
			continue
		}
		p, perr := netip.ParsePrefix(c)
		if perr != nil {
			return nil, fmt.Errorf("parse flush CIDR %q: %w", c, perr)
		}
		prefixes = append(prefixes, p)
	}
	if len(prefixes) == 0 {
		return nil, nil
	}
	aliases, lerr := sys.Lo0Aliases()
	if lerr != nil {
		return nil, lerr
	}
	var errs []error
	for _, a := range aliases {
		addr, aerr := netip.ParseAddr(a)
		if aerr != nil {
			continue // a non-IPv4 or malformed inet line — skip, never fatal
		}
		if !inAnyPrefix(addr, prefixes) {
			continue
		}
		if rerr := sys.Lo0RemoveAlias(a); rerr != nil {
			errs = append(errs, rerr)
			continue
		}
		removed = append(removed, a)
	}
	if len(errs) > 0 {
		return removed, fmt.Errorf("flush %d lo0 alias(es): %v", len(errs), errs[0])
	}
	return removed, nil
}

// inAnyPrefix reports whether addr falls inside any prefix.
func inAnyPrefix(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// hasAliasInCIDRs reports whether any current lo0 alias falls inside the given
// CIDRs — the --datapath singleton assert ("no 100.64.*/10.43.* lo0 alias
// present" before a second datapath `up`, so its pre-flight flush cannot tear a
// live datapath instance down).
func hasAliasInCIDRs(sys System, cidrs ...string) (bool, error) {
	var prefixes []netip.Prefix
	for _, c := range cidrs {
		if c == "" {
			continue
		}
		p, perr := netip.ParsePrefix(c)
		if perr != nil {
			return false, fmt.Errorf("parse CIDR %q: %w", c, perr)
		}
		prefixes = append(prefixes, p)
	}
	aliases, err := sys.Lo0Aliases()
	if err != nil {
		return false, err
	}
	for _, a := range aliases {
		addr, aerr := netip.ParseAddr(a)
		if aerr != nil {
			continue
		}
		if inAnyPrefix(addr, prefixes) {
			return true, nil
		}
	}
	return false, nil
}
