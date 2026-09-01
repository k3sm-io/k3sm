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

package provider

import (
	"context"
	"log/slog"
	"path/filepath"
	"time"

	"k3sm.io/runtimed/pkg/guestartifacts"
	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/sandbox"
)

// GuestArtifactsSubdir is the component under the runtimed on-disk root that
// holds this node's content-addressed guest boot artifact cache (B108). It
// cites the runtimed constant so the in-process node and the standalone lab
// twin can never derive different cache layouts.
//
// It is a SIBLING of the vm spine's other state (the orphan-record store's
// <root>/vmreap, the per-pod <root>/run/vm/<pod>) rather than a child of any of
// them, because its lifetime is the NODE's, not a pod's or a daemon run's: the
// cache is what lets an offline node still boot the set it verified yesterday,
// so nothing that clears per-run state may take it with it.
const GuestArtifactsSubdir = guestartifacts.GuestArtifactsSubdir

// GuestArtifactsDir returns the guest-artifact cache directory for a runtimed
// on-disk root, resolving an empty root to the runtimed default exactly as
// runtime.New does.
//
// The resolution is DUPLICATED here rather than read back off a constructed
// runtime for one reason: ensure runs BEFORE the runtime exists (its result is a
// construction input), so there is no runtime to ask. Keeping the fallback
// spelled as image.DefaultRoot — the same constant runtime.New defaults to — is
// what stops a daemon started with no --pod-root from caching artifacts in one
// tree while its runtime reads another.
func GuestArtifactsDir(root string) string {
	return filepath.Join(runtimeRoot(root), GuestArtifactsSubdir)
}

// runtimeRoot resolves the on-disk root runtimed will actually use.
func runtimeRoot(root string) string {
	if root == "" {
		return image.DefaultRoot
	}
	return root
}

// GuestArtifactSource is the node's guest-artifact ENSURE input: which pin to
// materialise, how to fetch it, and how long the whole attempt may take.
//
// Its ZERO VALUE IS THE PRODUCTION CONFIGURATION — the in-code active pin, a
// plain HTTPS fetcher, and the runtimed default budget — so the shipped call
// site passes no options at all and a test replaces exactly the seam it needs.
// The two seams are functions rather than a "test mode" flag because the thing
// under test is the DEGRADATION (an unminted pin, a fetch that fails, a fetch
// that outlives its budget), and each of those has to be produced deliberately.
type GuestArtifactSource struct {
	// Pin resolves the guest-kernel pin this build boots. nil selects
	// guestartifacts.Lookup(guestartifacts.ActiveGuestKernel) — the in-code pin,
	// which is a code fact and never an operator input.
	Pin func() (guestartifacts.GuestKernelPin, error)
	// Fetcher retrieves an artifact by url. nil selects guestartifacts.HTTPFetcher.
	Fetcher guestartifacts.Fetcher
	// Timeout bounds the WHOLE ensure — pin lookup, both fetches, both digest
	// passes. Zero or negative selects guestartifacts.DefaultFetchTimeout.
	Timeout time.Duration
}

// Ensure materialises this node's pinned guest boot artifacts under root and
// reports whether the node may advertise the vm-artifact capability.
//
// IT NEVER RETURNS AN ERROR, AND THAT IS THE CONTRACT, not an omission.
// EnsureGuestArtifacts' documented caller contract is that a failure means "the
// vm capability is off on this node", never "the daemon is broken": a Mac with
// no network, a build whose pin has not been minted, or a publisher outage must
// still run every native pod it has. Returning an error here would put that
// verdict in the hands of each call site, and the call site is daemon start —
// the one place where propagating it turns a withheld capability into a node
// that does not come up at all. So the degradation is decided ONCE, here, and
// the only thing a caller can do with the result is wire it or not.
//
// The false return is therefore the WHOLE failure surface, and it is the same
// answer for every cause: an unminted pin (the shipped state before the guest
// build has run), a fetch that failed, a digest that did not match, a budget
// that expired. The distinction lives in the Warn record, which names the cause
// for whoever is reading the log; nothing downstream branches on it.
//
// A false return leaves the vm backend's artifact locator UNSET, so CreateVM
// fails every vm pod closed with sandbox.ErrGuestArtifactsUnavailable — the
// fail-closed posture. It does not touch the host-process pod path.
func (s GuestArtifactSource) Ensure(ctx context.Context, root string, log *slog.Logger) (sandbox.GuestArtifacts, bool) {
	if log == nil {
		log = slog.Default()
	}
	var zero sandbox.GuestArtifacts

	pin, err := s.pin()
	if err != nil {
		// Info, not Warn: on every build shipped before the guest kernel build has
		// run this is the EXPECTED state, and a warning an operator is told to
		// ignore is a warning they will ignore when it matters. A pin that is
		// present but malformed reaches the same rung with a message that says so.
		log.Info("guest boot artifacts unavailable: no usable pin, so this node advertises no vm-artifact capability and every vm pod will fail closed",
			"guest_kernel", guestartifacts.ActiveGuestKernel, "err", err)
		return zero, false
	}

	dir := GuestArtifactsDir(root)
	ctx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()

	art, err := guestartifacts.EnsureGuestArtifacts(ctx, dir, pin, s.fetcher())
	if err != nil {
		log.Warn("guest boot artifacts could not be ensured; the vm capability is OFF on this node (native pods are unaffected, vm pods fail closed)",
			"dir", dir, "guest_kernel", guestartifacts.ActiveGuestKernel, "err", err)
		return zero, false
	}
	log.Info("guest boot artifacts verified",
		"dir", dir, "guest_kernel", guestartifacts.ActiveGuestKernel,
		"kernel", art.KernelPath, "initramfs", art.InitramfsPath)
	return art, true
}

// pin resolves the pin to ensure, defaulting to the in-code active one.
func (s GuestArtifactSource) pin() (guestartifacts.GuestKernelPin, error) {
	if s.Pin != nil {
		return s.Pin()
	}
	return guestartifacts.Lookup(guestartifacts.ActiveGuestKernel)
}

// fetcher resolves the fetcher, defaulting to a plain HTTPS GET.
func (s GuestArtifactSource) fetcher() guestartifacts.Fetcher {
	if s.Fetcher != nil {
		return s.Fetcher
	}
	return &guestartifacts.HTTPFetcher{Timeout: s.timeout()}
}

// timeout resolves the total ensure budget.
func (s GuestArtifactSource) timeout() time.Duration {
	if s.Timeout <= 0 {
		return guestartifacts.DefaultFetchTimeout
	}
	return s.Timeout
}

// guestArtifactLocator adapts an already-ensured artifact set to the
// sandbox.GuestArtifactLocator seam the vm backend takes.
//
// The set is captured BY VALUE at construction, so the locator is a constant
// function: ensure ran once, at daemon start, and re-deriving the paths per vm
// pod would either re-hash a hundred megabytes on every CreateVM or — worse —
// hand back paths nothing re-verified. The re-verification cadence is
// deliberately "once per daemon start" (see EnsureGuestArtifacts); this seam
// must not quietly change it.
func guestArtifactLocator(art sandbox.GuestArtifacts) sandbox.GuestArtifactLocator {
	return func() (sandbox.GuestArtifacts, error) { return art, nil }
}
