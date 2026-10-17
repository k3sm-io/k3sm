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
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
)

// ErrRebindAborted is what Rebind.Commit returns when the hoster abandoned the
// prepared swap first (its context ended while it waited for the decision), so
// the old address set is still the one in force.
var ErrRebindAborted = errors.New("svclb: the address swap was abandoned before it was committed")

// ErrHosterStopped is PrepareBindAddrs on a hoster whose Run has returned:
// it holds no listener to move.
var ErrHosterStopped = errors.New("svclb: the hoster is not running")

// rebindRequest is one PrepareBindAddrs call, handed to the Run goroutine.
type rebindRequest struct {
	addrs []netip.Addr
	reply chan rebindReply
}

// rebindReply is the Run goroutine's answer to a rebindRequest.
type rebindReply struct {
	rb  *Rebind
	err error
}

// Rebind is a prepared swap of the hoster's address set: every bound
// LoadBalancer listener already listens on the new addresses beside the old
// ones. Exactly one of Commit and Abort must be called, promptly: the hoster
// does nothing else until it is.
type Rebind struct {
	decide chan bool
	done   chan struct{}
	once   sync.Once
	// committed is written by the Run goroutine before done closes.
	committed bool
	// Unserved names the Services ("ns/name") a commit takes off this node:
	// a port of theirs cannot bind under the new set (a port below 1024 on a
	// specific set that the netd helper did not grant, see
	// ErrPrivilegedPortNotWildcard).
	Unserved []string
}

// Commit makes the prepared set the one in force. It returns ErrRebindAborted
// when the hoster had already abandoned the swap.
func (r *Rebind) Commit() error { return r.finish(true) }

// Abort drops the prepared set and keeps the old one.
func (r *Rebind) Abort() error { return r.finish(false) }

// finish hands the decision to the Run goroutine once and waits for it to be
// applied.
func (r *Rebind) finish(keep bool) error {
	r.once.Do(func() { r.decide <- keep })
	<-r.done
	if keep && !r.committed {
		return ErrRebindAborted
	}
	return nil
}

// PrepareBindAddrs starts swapping the address set every LoadBalancer
// listener binds for addrs (each port on every address of
// EffectiveBindAddrs). The Run goroutine binds every bound Service port on the
// addresses it does not yet listen on, all or nothing across every Service:
// any bind failure closes what it opened, keeps the old set, and is returned.
// The one exception is ErrPrivilegedPortNotWildcard, which takes that Service
// off this node at the commit (Rebind.Unserved) instead of failing the swap.
//
// The commit withdraws the unserved Services from this node's bound report
// BEFORE it closes their listeners, closes the old addresses (connections
// already accepted keep running), and the next reconcile re-reports what is
// bound. A hoster that has not synced yet only takes the new set.
func (h *Hoster) PrepareBindAddrs(ctx context.Context, addrs []netip.Addr) (*Rebind, error) {
	for _, a := range addrs {
		if !a.IsValid() {
			return nil, fmt.Errorf("svclb: invalid bind address %q", a)
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("svclb: %w", ErrNoBindAddress)
	}
	req := rebindRequest{addrs: slices.Clone(addrs), reply: make(chan rebindReply, 1)}
	select {
	case h.rebind <- req:
	case <-h.stopped:
		return nil, ErrHosterStopped
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case r := <-req.reply:
		return r.rb, r.err
	case <-ctx.Done():
		// The Run goroutine always answers; take the answer and undo it.
		r := <-req.reply
		if r.rb != nil {
			_ = r.rb.Abort()
		}
		return nil, ctx.Err()
	}
}

// BindAddrs returns a copy of the address set in force. It is for the Run
// goroutine's owner before Run starts and for tests; it is not synchronized
// with a concurrent swap.
func (h *Hoster) BindAddrs() []netip.Addr { return slices.Clone(h.addrs) }

// handleRebind runs one swap on the Run goroutine: prepare, answer, wait for
// the decision, apply it.
func (h *Hoster) handleRebind(ctx context.Context, req rebindRequest) {
	prepared, unserved, err := h.prepareRebind(ctx, req.addrs)
	if err != nil {
		req.reply <- rebindReply{err: err}
		return
	}
	rb := &Rebind{decide: make(chan bool, 1), done: make(chan struct{})}
	for key := range unserved {
		rb.Unserved = append(rb.Unserved, key)
	}
	sort.Strings(rb.Unserved)
	req.reply <- rebindReply{rb: rb}
	keep := false
	select {
	case keep = <-rb.decide:
	case <-ctx.Done():
	}
	if keep {
		h.commitRebind(ctx, req.addrs, prepared, unserved)
		rb.committed = true
	} else {
		for _, f := range prepared {
			f.set.Abort()
		}
	}
	close(rb.done)
}

// prepareRebind binds every forwarder on the new set beside its current one.
// A Service with a port that cannot bind for ErrPrivilegedPortNotWildcard is
// returned in unserved; any other failure aborts every prepared forwarder.
func (h *Hoster) prepareRebind(ctx context.Context, addrs []netip.Addr) (prepared []*forwarder, unserved map[string]bool, err error) {
	unserved = make(map[string]bool)
	keys := make([]string, 0, len(h.forwarders))
	for key := range h.forwarders {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		ports := h.forwarders[key]
		pnums := make([]int32, 0, len(ports))
		for p := range ports {
			pnums = append(pnums, p)
		}
		slices.Sort(pnums)
		for _, port := range pnums {
			f := ports[port]
			if perr := f.set.Prepare(ctx, addrs); perr != nil {
				if errors.Is(h.classifyRebindErr(addrs, port, perr), ErrPrivilegedPortNotWildcard) {
					unserved[key] = true
					continue
				}
				for _, p := range prepared {
					p.set.Abort()
				}
				return nil, nil, fmt.Errorf("svclb: service %s port %d: %w", key, port, perr)
			}
			prepared = append(prepared, f)
		}
	}
	// A Service taken off the node keeps nothing a prepare opened for it.
	kept := prepared[:0]
	for _, f := range prepared {
		if unserved[h.keyOf(f)] {
			f.set.Abort()
			continue
		}
		kept = append(kept, f)
	}
	return kept, unserved, nil
}

// keyOf returns the Service key a forwarder is filed under.
func (h *Hoster) keyOf(f *forwarder) string {
	for key, ports := range h.forwarders {
		for _, g := range ports {
			if g == f {
				return key
			}
		}
	}
	return ""
}

// commitRebind applies a prepared swap: withdraw the unserved Services from
// the report, then close their listeners (their connections drain), then
// commit every other forwarder onto the new set.
func (h *Hoster) commitRebind(ctx context.Context, addrs []netip.Addr, prepared []*forwarder, unserved map[string]bool) {
	if len(unserved) > 0 {
		var entries []string
		for key, e := range h.entries {
			if !unserved[key] {
				entries = append(entries, e)
			}
		}
		h.report(ctx, entries)
		for key := range unserved {
			for _, f := range h.forwarders[key] {
				f.retired.Store(true)
				_ = f.set.Close()
				h.draining = append(h.draining, f)
			}
			delete(h.forwarders, key)
			delete(h.entries, key)
			h.log.Info("svclb: loadbalancer service taken off this node by the address change; its connections finish, new ones are refused",
				"service", key, "bind", addrsString(addrs))
		}
	}
	for _, f := range prepared {
		f.set.Commit(addrs)
	}
	h.addrs = slices.Clone(addrs)
	h.log.Info("svclb: loadbalancer listeners moved to a new address set", "node", h.cfg.NodeName, "bind", addrsString(addrs))
}

// reapDraining stops the drained forwarders whose last connection ended.
func (h *Hoster) reapDraining() {
	kept := h.draining[:0]
	for _, f := range h.draining {
		if f.active.Load() == 0 {
			f.stop()
			continue
		}
		kept = append(kept, f)
	}
	h.draining = kept
}

// classifyBindErr maps a listener bind failure on port under the current set
// to the refusal the operator reads.
func (h *Hoster) classifyBindErr(port int32, err error) error {
	return h.classifyRebindErr(h.addrs, port, err)
}

// classifyRebindErr is classifyBindErr under the set addrs: a port below 1024
// refused by the netd helper's policy (on any set), or refused with EACCES or
// left with no address (loopback only) on a specific set, is
// ErrPrivilegedPortNotWildcard. A rebind then takes that Service off the node
// instead of failing the swap, and the next reconcile asks again.
func (h *Hoster) classifyRebindErr(addrs []netip.Addr, port int32, err error) error {
	if port <= privilegedPortMax && (isNetdPolicyRefusal(err) ||
		(!IsWildcard(addrs) && (errors.Is(err, syscall.EACCES) || errors.Is(err, ErrNoBindAddress)))) {
		return fmt.Errorf("svclb: port %d: %w: %w", port, ErrPrivilegedPortNotWildcard, err)
	}
	return err
}

// netdPolicyRefusal is the text the netd wire client puts on a BindPort the
// root helper refused by policy: "netd BindPort rejected: " followed by the
// daemon's own error, which starts with darwin-net's netd.ErrPolicy text. The
// helper does not send that refusal as a named reason, so the client returns
// it as a plain string and there is no sentinel to match with errors.Is; the
// documented text is the contract. A port the operator did not list, an
// address that is not this Mac's, and a netd too old to know the LoadBalancer
// port class all refuse this way.
const netdPolicyRefusal = "netd BindPort rejected: netd: request denied by policy"

// isNetdPolicyRefusal reports whether err carries the netd helper's policy
// refusal of a port bind.
func isNetdPolicyRefusal(err error) bool {
	return err != nil && strings.Contains(err.Error(), netdPolicyRefusal)
}

// addrsString renders an address set for a log line.
func addrsString(addrs []netip.Addr) string {
	parts := make([]string, 0, len(addrs))
	for _, a := range addrs {
		parts = append(parts, a.String())
	}
	return strings.Join(parts, ",")
}
