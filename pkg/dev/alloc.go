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
//
// The five bases are pairwise more than portSpan apart, so no two instances'
// windows can overlap and no port can be allocated for two roles:
//
//	kubelet             10450–10961
//	scheduler           11450–11961
//	kine (datastore)    12379–12890
//	controller-manager  13450–13961
//	registry (ingest)   14450–14961
//	apiserver           16440–16951
const (
	apiPortBase  = 16440
	kinePortBase = 12379
	// kubeletPortBase seeds the node's kubelet-API port (logs/exec/stats). It is
	// clear of the fixed control-plane singletons the base must not overlap —
	// 10250 itself, and the scheduler/controller-manager 10259/10257 — so a probe
	// that walks the whole span still never lands on one of them.
	kubeletPortBase = 10450
	// schedulerPortBase and controllerManagerPortBase seed the two co-located
	// control-plane components' secure-serving ports. Both windows likewise clear
	// the fixed defaults (10259/10257) they replace. The controller-manager's base
	// skips a decade because 12450 would fall inside the datastore window above.
	schedulerPortBase         = 11450
	controllerManagerPortBase = 13450
	// registryPortBase seeds the instance's node-local OCI ingest registry port.
	// Its window sits between the controller-manager's and the apiserver's, clear
	// of both by more than portSpan, and clear of the fixed 6450 a non-dev server
	// suggests — a dev instance must never contend with a hand-run `k3sm server`
	// for the port an image is pushed to.
	registryPortBase = 14450
	// portSpan bounds the linear probe from each base — 512 candidate ports is
	// far more than the realistic parallel-instance count, and keeps the search
	// bounded so a wedged host fails fast rather than scanning 64k ports.
	portSpan = 512
	// portStride separates an instance's per-port hash seeds so a hash collision
	// on one port does not also collide the next.
	portStride = 2
)

// instancePorts is every singleton TCP listener one dev instance owns. It is a
// STRUCT and not a tuple because the members are all ints: five positional int
// results, threaded through the spawn path and into an argv, is a shape where
// transposing two of them compiles cleanly and produces a cluster whose scheduler
// is listening on the datastore's port.
type instancePorts struct {
	api               int
	kine              int
	kubelet           int
	scheduler         int
	controllerManager int
	registry          int
}

// portClasses is the allocation order: one entry per listener, each with the base
// of its own window. Adding a listener is adding a row — which is the point, since
// this set has grown three times, once per singleton port discovered the hard way
// by a second instance failing to boot on it.
//
// The ORDER is load-bearing: each class consumes the next slice of the hash seed,
// so re-ordering or inserting above an existing row would move the preferred ports
// of instances that already exist. New classes go on the END.
var portClasses = []struct {
	name string
	base int
	set  func(*instancePorts, int)
}{
	{"apiserver", apiPortBase, func(p *instancePorts, v int) { p.api = v }},
	{"kine", kinePortBase, func(p *instancePorts, v int) { p.kine = v }},
	{"kubelet", kubeletPortBase, func(p *instancePorts, v int) { p.kubelet = v }},
	{"scheduler", schedulerPortBase, func(p *instancePorts, v int) { p.scheduler = v }},
	{"controller-manager", controllerManagerPortBase, func(p *instancePorts, v int) { p.controllerManager = v }},
	{"registry", registryPortBase, func(p *instancePorts, v int) { p.registry = v }},
}

// allocatePorts picks a free port for every listener an instance owns,
// deterministically SEEDED from (name × euid) so re-running `up <name>` prefers
// the same ports (a stable dev loop), then linearly probing forward past any that
// are currently bound (System.PortFree) so parallel rootless instances never
// collide. It errors only if a window is saturated.
//
// EVERY singleton listener an instance owns has to be in here, and the set is
// complete only because each omission was found by a boot that failed: the
// datastore port (a second instance silently sharing the first one's database),
// then the node's kubelet API (`bind: address already in use` after a healthy
// control plane), then the scheduler and controller-manager secure ports (a dead
// service-account controller, surfacing as a namespace bootstrap that never
// finishes). A fixed port shared by two instances is not a dev-ergonomics wart —
// it is a cluster silently wired to another cluster's process.
func allocatePorts(sys System, name string, euid int) (instancePorts, error) {
	var out instancePorts
	seed := hashSeed(name, euid)
	for _, c := range portClasses {
		p, err := probeFreePort(sys, c.base, int(seed%portSpan))
		if err != nil {
			return instancePorts{}, fmt.Errorf("allocate %s port: %w", c.name, err)
		}
		c.set(&out, p)
		seed /= portStride
	}
	// Two windows less than a span apart could hand the same absolute number to two
	// roles. The bases above are spaced so that cannot happen — assert it, so a
	// future base change cannot silently break it.
	allocated := []struct {
		name string
		port int
	}{
		{"apiserver", out.api},
		{"kine", out.kine},
		{"kubelet", out.kubelet},
		{"scheduler", out.scheduler},
		{"controller-manager", out.controllerManager},
		{"registry", out.registry},
	}
	for i := range allocated {
		for j := i + 1; j < len(allocated); j++ {
			if allocated[i].port == allocated[j].port {
				return instancePorts{}, fmt.Errorf("allocated %s and %s ports collide on %d", allocated[i].name, allocated[j].name, allocated[i].port)
			}
		}
	}
	return out, nil
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
