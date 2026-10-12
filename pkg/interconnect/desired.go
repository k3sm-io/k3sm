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

package interconnect

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"time"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	"k3sm.io/darwin-net/pkg/netd/wire"
)

const (
	// DesiredInterval is the level-triggered re-ensure period: the slot-0 alias
	// is ensured (or removed) on every tick, not only on a change, so an alias
	// configd or a helper restart dropped comes back within one interval.
	DesiredInterval = 60 * time.Second
	// HealthInterval is how often the handler checks the root helper's socket;
	// a return from unreachable to reachable is a reconnect, which re-ensures at
	// once.
	HealthInterval = 5 * time.Second
)

// netd verb labels for the result counter.
const (
	verbEnsure = "EnsureInterconnectAlias"
	verbRemove = "RemoveInterconnectAlias"
	resultOK   = "ok"
	resultErr  = "Error"
)

// AliasClient is the root helper's interconnect alias surface (darwin-net's
// wire.Client).
type AliasClient interface {
	EnsureInterconnectAlias(ctx context.Context, slot int) (netip.Addr, error)
	RemoveInterconnectAlias(ctx context.Context, slot int) error
}

// DesiredConfig is the desired handler's wiring.
type DesiredConfig struct {
	// Node is this node's name.
	Node string
	// Desired is this node's k3sm.io/interconnect-desired annotation.
	Desired Annotator
	// Client is the root helper.
	Client AliasClient
	// Reachable reports whether the root helper's socket answers; nil skips the
	// reconnect check (the tick still re-ensures).
	Reachable func(ctx context.Context) error
	// OnReason receives the helper verdict after every call ("" on success).
	OnReason func(reason string)
	// Metrics receives the netd verb results; nil records none.
	Metrics *Metrics
	// Log is the logger; nil uses slog.Default.
	Log *slog.Logger
	// Interval is the re-ensure period; zero means DesiredInterval.
	Interval time.Duration
	// HealthEvery is the helper reachability period; zero means HealthInterval.
	HealthEvery time.Duration
}

// DesiredHandler applies this node's desired annotation to the root helper,
// level-triggered: while the annotation names an interconnect it ensures slot 0
// on every reconcile, and while it is absent it removes slot 0. A named helper
// error is logged at Warn once per state change and waits for the next tick or
// trigger; it is never retried in a loop.
//
// Reconcile is called from one goroutine (Run, or a test); its state is not
// guarded.
type DesiredHandler struct {
	cfg  DesiredConfig
	last string
}

// NewDesiredHandler returns a DesiredHandler.
func NewDesiredHandler(cfg DesiredConfig) *DesiredHandler {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DesiredInterval
	}
	if cfg.HealthEvery <= 0 {
		cfg.HealthEvery = HealthInterval
	}
	return &DesiredHandler{cfg: cfg}
}

// reasonOf names a helper error: HelperTooOld, a netd Reason, or Error.
func reasonOf(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, wire.ErrHelperTooOld):
		return ReasonHelperTooOld
	}
	if r := wire.ReasonOf(err); r != "" {
		return r
	}
	return resultErr
}

// Reconcile applies the desired annotation once.
func (h *DesiredHandler) Reconcile(ctx context.Context) {
	value, synced := h.cfg.Desired.Current()
	if !synced {
		// An unsynced cache is not "absent": removing on it would tear down a
		// live alias on every daemon start.
		return
	}
	want := false
	invalid := false
	if value != "" {
		if _, err := netv1alpha1.ParseInterconnectDesired(value); err == nil {
			want = true
		} else {
			// A value this binary cannot read is treated as absent (the safe
			// direction); the server overwrites it on its next reconcile.
			invalid = true
		}
	}
	var (
		verb string
		addr netip.Addr
		err  error
	)
	if want {
		verb = verbEnsure
		addr, err = h.cfg.Client.EnsureInterconnectAlias(ctx, netv1alpha1.InterconnectSlotNode)
	} else {
		verb = verbRemove
		err = h.cfg.Client.RemoveInterconnectAlias(ctx, netv1alpha1.InterconnectSlotNode)
	}
	if ctx.Err() != nil {
		return
	}
	reason := reasonOf(err)
	result := resultOK
	if reason != "" {
		result = reason
	}
	h.cfg.Metrics.NetdResult(verb, result)
	if h.cfg.OnReason != nil {
		h.cfg.OnReason(reason)
	}
	state := verb + "/" + result + "/" + addr.String()
	if invalid {
		state += "/invalid"
	}
	if state == h.last {
		return
	}
	h.last = state
	switch {
	case err != nil:
		h.cfg.Log.Warn("interconnect: the root helper refused the slot-0 alias", "node", h.cfg.Node, "verb", verb, "reason", reason, "err", err)
	case want:
		h.cfg.Log.Info("interconnect: slot-0 alias ensured on bridge0", "node", h.cfg.Node, "address", addr.String())
	default:
		h.cfg.Log.Info("interconnect: no interconnect desired; slot-0 alias removed", "node", h.cfg.Node, "unreadableDesired", invalid)
	}
}

// Run reconciles at start, on every trigger, every Interval, and when
// the root helper comes back after being unreachable, until ctx ends.
func (h *DesiredHandler) Run(ctx context.Context, trigger <-chan struct{}) {
	tick := time.NewTicker(h.cfg.Interval)
	defer tick.Stop()
	health := time.NewTicker(h.cfg.HealthEvery)
	defer health.Stop()
	healthy := true
	h.Reconcile(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			h.Reconcile(ctx)
		case <-trigger:
			h.Reconcile(ctx)
		case <-health.C:
			if h.cfg.Reachable == nil {
				continue
			}
			ok := h.cfg.Reachable(ctx) == nil
			if ok && !healthy {
				h.cfg.Log.Info("interconnect: the root helper is reachable again; re-ensuring", "node", h.cfg.Node)
				h.Reconcile(ctx)
			}
			healthy = ok
		}
	}
}
