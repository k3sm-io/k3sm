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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/guestartifacts"
	runtimed "k3sm.io/runtimed/pkg/runtime"
	"k3sm.io/runtimed/pkg/sandbox"
)

// The guest-artifact wiring tests. Every one of them runs with NO NETWORK and no
// privilege: the only production seam replaced is the Fetcher, which is the whole
// of ensure's dependency on the outside world by design (guestartifacts.Fetcher
// is a one-method consumer interface for exactly this reason).
//
// They are wiring tests, deliberately. The MECHANISM — digest verification,
// atomic install, retention, the corrupt-byte reject — is runtimed's and is
// pinned by runtimed's own package tests; re-asserting it here would double the
// maintenance of a property with one owner. What is only provable HERE is the
// chain this repo owns: pin -> ensure -> RuntimedConfig -> the constructed
// runtime -> the advertised capability, and what happens to the rest of the node
// when any link of it fails.

// fakeArtifact is one artifact a fakeFetcher serves, with the digest the pin will
// name it by.
type fakeArtifact struct {
	body   []byte
	digest string
}

// newFakeArtifact builds an artifact body and its true sha256, so a test's pin
// and its fetcher agree by CONSTRUCTION rather than by a pasted literal that can
// rot.
func newFakeArtifact(content string) fakeArtifact {
	b := []byte(content)
	sum := sha256.Sum256(b)
	return fakeArtifact{body: b, digest: hex.EncodeToString(sum[:])}
}

// fakeFetcher serves a fixed url->artifact map with no socket.
//
// Its failure modes are per-INSTANCE, which is what makes the blast-radius test
// below possible: two runtimes in one process can be given two different network
// realities without any global state between them.
type fakeFetcher struct {
	// files maps a full artifact url to its bytes.
	files map[string][]byte
	// err, when non-nil, is returned for every fetch (the offline / outage node).
	err error
	// block, when true, makes every fetch hang until the context is done (the
	// stalled-publisher node the total budget exists to bound).
	block bool
	// calls counts fetch attempts, so a test can prove a cached set was NOT
	// re-fetched, or that a failing node tried at all.
	calls int
}

func (f *fakeFetcher) Fetch(ctx context.Context, url string) (io.ReadCloser, error) {
	f.calls++
	if f.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if f.err != nil {
		return nil, f.err
	}
	b, ok := f.files[url]
	if !ok {
		return nil, errors.New("fake fetcher: no artifact at " + url)
	}
	return io.NopCloser(strings.NewReader(string(b))), nil
}

// mintedPin returns a COMPLETE pin plus a fetcher that serves exactly the
// artifacts it names — the state this build is in once the guest kernel build has
// run and the digests have been minted into runtimed's pin table.
//
// The shipped pin is deliberately unminted (guestartifacts.ErrPinIncomplete), so
// a test that only ever exercised the shipped one would assert the degraded path
// forever and go quietly vacuous on the day the digests land. Synthesising a
// minted pin here is what makes both states testable TODAY, which is the whole
// requirement: the wiring has to be right before AND after the mint.
func mintedPin() (guestartifacts.GuestKernelPin, *fakeFetcher) {
	const release = "https://example.invalid/k3sm-guest/v6.18.48"
	kernel := newFakeArtifact("fake guest kernel image bytes")
	initrd := newFakeArtifact("fake guest initramfs cpio bytes")
	pin := guestartifacts.GuestKernelPin{
		KernelVersion:   "v6.18.48",
		ImageSHA256:     kernel.digest,
		InitramfsSHA256: initrd.digest,
		ReleaseURL:      release,
		Cmdline:         "console=hvc0 reboot=k panic=1",
	}
	f := &fakeFetcher{files: map[string][]byte{
		release + "/" + guestartifacts.ImageFileName:     kernel.body,
		release + "/" + guestartifacts.InitramfsFileName: initrd.body,
	}}
	return pin, f
}

// pinFunc adapts a fixed pin (or error) to the GuestArtifactSource.Pin seam.
func pinFunc(p guestartifacts.GuestKernelPin, err error) func() (guestartifacts.GuestKernelPin, error) {
	return func() (guestartifacts.GuestKernelPin, error) { return p, err }
}

// artifactDirEmpty reports whether the node's guest-artifact cache directory is
// absent or holds nothing.
//
// "Absent OR empty" is one predicate on purpose. Ensure creates the cache root
// before it fetches and only creates a SET directory after both artifacts verify,
// so a failed ensure legitimately leaves either shape depending on where it
// failed — and the property the caller cares about, in both cases, is that no
// bootable set is present.
func artifactDirEmpty(t *testing.T, root string) bool {
	t.Helper()
	entries, err := os.ReadDir(GuestArtifactsDir(root))
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	if err != nil {
		t.Fatalf("read guest artifact dir: %v", err)
	}
	return len(entries) == 0
}

// TestEnsureGuestArtifactsWiring is the pin -> ensure -> capability chain across
// the three states a node can be in, asserted through the PRODUCTION constructor
// NewRuntimed rather than through any helper this test also wrote.
//
// The two degraded cases are the load-bearing ones. EnsureGuestArtifacts'
// documented caller contract is that a failure means "the vm capability is off on
// this node", never "the daemon is broken" — so the assertion that matters is not
// that ensure returned false, it is that NewRuntimed still SUCCEEDED and the
// runtime still answers. Delete the degradation (propagate the ensure error out
// of buildProvider, say) and these go red on the constructor, which is exactly
// where the production regression would be.
func TestEnsureGuestArtifactsWiring(t *testing.T) {
	t.Run("a minted pin and a working fetcher land the artifacts and advertise the capability", func(t *testing.T) {
		stageExecShim(t)
		root := t.TempDir()
		pin, fetcher := mintedPin()

		src := GuestArtifactSource{Pin: pinFunc(pin, nil), Fetcher: fetcher, Timeout: 30 * time.Second}
		art, ok := src.Ensure(t.Context(), root, slog.New(slog.DiscardHandler))
		if !ok {
			t.Fatalf("Ensure reported unavailable with a minted pin and a fetcher serving both artifacts")
		}

		// The returned paths are inside THIS node's cache root — the derivation
		// under test, not a path the test supplied.
		setDir := filepath.Join(GuestArtifactsDir(root), pin.SetDigest())
		if want := filepath.Join(setDir, guestartifacts.ImageFileName); art.KernelPath != want {
			t.Errorf("kernel path = %q, want %q", art.KernelPath, want)
		}
		if want := filepath.Join(setDir, guestartifacts.InitramfsFileName); art.InitramfsPath != want {
			t.Errorf("initramfs path = %q, want %q", art.InitramfsPath, want)
		}
		if art.Cmdline != pin.Cmdline {
			t.Errorf("cmdline = %q, want the pin's %q", art.Cmdline, pin.Cmdline)
		}
		for _, p := range []string{art.KernelPath, art.InitramfsPath} {
			if _, err := os.Stat(p); err != nil {
				t.Errorf("artifact not on disk after a successful ensure: %v", err)
			}
		}

		rt := mustNewRuntimed(t, root, &art)
		if caps := rt.Capabilities(t.Context()); !caps.VMArtifacts {
			t.Errorf("Capabilities().VMArtifacts = false after a successful ensure; the node would advertise no %s", ConditionVMArtifactsAvailable)
		}
	})

	t.Run("an unminted pin leaves the node running with the capability withheld", func(t *testing.T) {
		stageExecShim(t)
		root := t.TempDir()
		// The SHIPPED state, spelled through the production lookup: no Pin seam, so
		// this is guestartifacts.Lookup(ActiveGuestKernel) itself. When the digests
		// are minted this case starts exercising a real fetch attempt against a
		// fetcher that serves nothing, which is still a withheld capability and a
		// live node — the same verdict, reached by the next cause along.
		src := GuestArtifactSource{Fetcher: &fakeFetcher{}, Timeout: 5 * time.Second}
		if _, ok := src.Ensure(t.Context(), root, slog.New(slog.DiscardHandler)); ok {
			t.Fatalf("Ensure reported the vm capability AVAILABLE from the shipped pin; it is unminted, so nothing verifiable could have been fetched")
		}
		if !artifactDirEmpty(t, root) {
			t.Errorf("a failed ensure left a guest-artifact set behind in %s", GuestArtifactsDir(root))
		}

		rt := mustNewRuntimed(t, root, nil)
		if caps := rt.Capabilities(t.Context()); caps.VMArtifacts {
			t.Errorf("Capabilities().VMArtifacts = true with no artifacts wired: the node would advertise %s falsely", ConditionVMArtifactsAvailable)
		}
		assertRuntimeStillServes(t, rt)
	})

	t.Run("a fetch that stalls is bounded and still leaves the node running", func(t *testing.T) {
		stageExecShim(t)
		root := t.TempDir()
		pin, _ := mintedPin()
		fetcher := &fakeFetcher{block: true}

		// The budget is the assertion. A stalled publisher is precisely the case a
		// per-read idle timeout cannot catch, so ensure's bound is a TOTAL one — and
		// this is the k3sm-side proof that the bound is actually applied at the one
		// call site that matters, daemon start.
		const budget = 150 * time.Millisecond
		src := GuestArtifactSource{Pin: pinFunc(pin, nil), Fetcher: fetcher, Timeout: budget}
		start := time.Now()
		if _, ok := src.Ensure(t.Context(), root, slog.New(slog.DiscardHandler)); ok {
			t.Fatalf("Ensure reported success against a fetcher that never returns a byte")
		}
		// A generous ceiling: the point is that daemon start is not blocked for the
		// production two-minute budget, not that the timer is precise.
		if elapsed := time.Since(start); elapsed > 30*time.Second {
			t.Fatalf("Ensure took %s against a stalled fetcher with a %s budget: the timeout is not being applied", elapsed, budget)
		}
		if fetcher.calls == 0 {
			t.Errorf("the stalled fetcher was never called, so the timeout proved nothing")
		}
		if !artifactDirEmpty(t, root) {
			t.Errorf("a timed-out ensure left a guest-artifact set behind in %s", GuestArtifactsDir(root))
		}

		rt := mustNewRuntimed(t, root, nil)
		if caps := rt.Capabilities(t.Context()); caps.VMArtifacts {
			t.Errorf("Capabilities().VMArtifacts = true after a timed-out ensure")
		}
		assertRuntimeStillServes(t, rt)
	})
}

// TestGuestArtifactFailureBlastRadiusIsOneNode is the BLAST-RADIUS proof: one
// node's guest-artifact failure withholds that node's vm capability and touches
// nothing else — not the other node's capability, and not its own native pod
// path.
//
// It runs IN-PROCESS, as two provider instances with two independently injected
// fetchers, and that is a deliberate choice rather than a convenience. The
// spawned-binary variant — bring up two real daemons and make ONE of them fail to
// fetch — is not implementable without adding a production seam by which an
// operator (or an env var, or a flag) can force a node's artifact fetch to fail.
// Such a seam is exactly the escape hatch the artifact design exists to deny: it
// would be a supported way to change what a node boots from, present on every
// shipped binary, in order to make a test easier to write. Two runtimes in one
// process prove the same isolation property — the failure is per-instance, not
// per-process, since ensure holds no global state — at no cost to the shipped
// surface. The genuinely cross-machine half (two Macs agreeing on the same
// verdict) is the integration-tier join test's, which asserts agreement without
// needing anyone to inject a failure.
func TestGuestArtifactFailureBlastRadiusIsOneNode(t *testing.T) {
	stageExecShim(t)
	pin, healthyFetcher := mintedPin()

	// The healthy node: a minted pin and a publisher that answers.
	healthyRoot := t.TempDir()
	healthyArt, ok := GuestArtifactSource{Pin: pinFunc(pin, nil), Fetcher: healthyFetcher, Timeout: 30 * time.Second}.
		Ensure(t.Context(), healthyRoot, slog.New(slog.DiscardHandler))
	if !ok {
		t.Fatalf("the healthy node's ensure failed; the test cannot show a contrast")
	}

	// The broken node: the SAME pin, a publisher that is down for it alone.
	brokenRoot := t.TempDir()
	brokenFetcher := &fakeFetcher{err: errors.New("connection refused")}
	if _, ok := (GuestArtifactSource{Pin: pinFunc(pin, nil), Fetcher: brokenFetcher, Timeout: 5 * time.Second}).
		Ensure(t.Context(), brokenRoot, slog.New(slog.DiscardHandler)); ok {
		t.Fatalf("the broken node's ensure reported success against a fetcher that refuses every connection")
	}

	healthy := mustNewRuntimed(t, healthyRoot, &healthyArt)
	broken := mustNewRuntimed(t, brokenRoot, nil)

	if caps := healthy.Capabilities(t.Context()); !caps.VMArtifacts {
		t.Errorf("the HEALTHY node lost its vm-artifact capability because a sibling node's fetch failed")
	}
	if caps := broken.Capabilities(t.Context()); caps.VMArtifacts {
		t.Errorf("the BROKEN node advertises %s after a failed fetch", ConditionVMArtifactsAvailable)
	}
	// The broken node's own cache is untouched by the failure — nothing half-
	// installed for a later start to find and mistake for a set.
	if !artifactDirEmpty(t, brokenRoot) {
		t.Errorf("the broken node left residue in %s", GuestArtifactsDir(brokenRoot))
	}
	// And the point of the whole degradation: it still runs pods.
	assertRuntimeStillServes(t, broken)
	assertRuntimeStillServes(t, healthy)
}

// mustNewRuntimed builds the production provider over root, optionally wiring an
// ensured artifact set, and fails the test if construction does not succeed.
//
// Construction succeeding IS an assertion in every degraded case here, which is
// why this helper never tolerates an error.
func mustNewRuntimed(t *testing.T, root string, art *sandbox.GuestArtifacts) *runtimedRuntime {
	t.Helper()
	rt, err := NewRuntimed(RuntimedConfig{
		NodeName:       "n1",
		Root:           root,
		GuestArtifacts: art,
		Logger:         slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("NewRuntimed: %v (a guest-artifact outcome must never fail daemon start)", err)
	}
	return rt
}

// assertRuntimeStillServes is the cheap "the rest of the node is fine" invariant:
// the runtime answers its runtime-info RPC and still reports a sandbox backend —
// the native host-process pod path's own precondition. A node that withheld the
// vm capability but lost this would have degraded far past what the contract
// permits.
func assertRuntimeStillServes(t *testing.T, rt *runtimedRuntime) {
	t.Helper()
	info, err := rt.GetRuntimeInfo(t.Context(), &runtimev1.GetRuntimeInfoRequest{})
	if err != nil {
		t.Fatalf("GetRuntimeInfo after a withheld vm capability: %v", err)
	}
	if info.GetRuntimeName() == "" {
		t.Errorf("runtime reports no name; it is not serving")
	}
	if findRuntimeCondition(info, runtimed.ConditionSandboxBackend) == nil {
		t.Errorf("runtime reports no SandboxBackend condition: the native pod path is not wired")
	}
}
