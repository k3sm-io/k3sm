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

package install

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/certs"
)

// writeCalls are the seam calls that put something on the Mac. A refusal that
// happens before any of them is a refusal that left nothing to unpick, which is
// the whole claim the preflight makes.
var writeCalls = []string{
	"EnsureServiceUser:", "CopyToRootOwned:", "WriteLaunchDaemon:", "EnsureLogDir:",
	"EnsureContainerLogDir:", "EnsureRunDir:", "EnsureVMRunDir:", "EnsureMeshKeyDir:",
	"WriteServiceUserFile:", "WriteRootOnlyFile:", "EnsureSymlink:", "Bootstrap:",
	"WriteUserKubeconfig:", "WriteAgentArgsRecord:", "Chown:",
}

// assertNothingWritten fails when any privileged write was recorded.
func assertNothingWritten(t *testing.T, calls []string) {
	t.Helper()
	for _, c := range calls {
		for _, prefix := range writeCalls {
			if strings.HasPrefix(c, prefix) {
				t.Errorf("the install wrote %q before refusing; a preflight that writes first is not a preflight (calls %v)", c, calls)
			}
		}
	}
}

// TestAgentInstallPreflightsTheJoinEndpoint is the gate for B334: the
// 2026-09-17 `k3sm install --agent --server <name>` that took a name resolving
// to an address nothing answered on, wrote the whole tree, and left the daemon
// crash-looping on "post mesh endpoint refresh: dial tcp <addr>:9345: connection
// refused" — a diagnosis that existed only inside the crash record, on a Mac
// that then had to be uninstalled.
//
// Two questions, asked before the first write, through seams a fake drives:
// can the endpoint be REACHED (on any address its host resolves to), and is it
// the cluster the operator's token PINS. The second is the one that matters
// most, because a join to the wrong cluster succeeds.
func TestAgentInstallPreflightsTheJoinEndpoint(t *testing.T) {
	// (a) A host resolving to two addresses — the shape the incident had: a LAN
	// address that answers and a public one that does not. The join works iff one
	// of them answers, so the preflight tries them in order and proceeds.
	t.Run("the first address refuses and the second answers, so the install proceeds", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		seedJoinedAgent(t, f)
		cfg := agentCfg(t)
		f.putJoinAddrs(cfg.JoinServer, "203.0.113.9", "192.168.1.24")
		f.putJoinDialErr("203.0.113.9:9345", fmt.Errorf("dial tcp 203.0.113.9:9345: connect: connection refused"))

		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		first := idx(f.calls, "DialJoinServer:203.0.113.9:9345")
		second := idx(f.calls, "DialJoinServer:192.168.1.24:9345")
		if first < 0 || second < 0 {
			t.Fatalf("both resolved addresses must be dialled; calls = %v", f.calls)
		}
		if first > second {
			t.Errorf("the addresses were dialled out of resolution order (%d then %d); calls = %v", first, second, f.calls)
		}
		// The identity question is asked of the address that ANSWERED, and of no
		// other: fetching from an address that refused the dial would report a
		// connection error as a cluster mismatch.
		if idx(f.calls, "FetchJoinCA:192.168.1.24:9345") < 0 {
			t.Errorf("the CA was not fetched from the address that answered; calls = %v", f.calls)
		}
		if idx(f.calls, "FetchJoinCA:203.0.113.9:9345") >= 0 {
			t.Errorf("the CA was fetched from an address that refused the dial; calls = %v", f.calls)
		}
		// ...and the install really did proceed past the preflight.
		if idx(f.calls, "EnsureServiceUser:_k3sm:"+DefaultDataRoot) < 0 {
			t.Errorf("the install stopped at the preflight it should have passed; calls = %v", f.calls)
		}
	})

	// (b) The incident itself: nothing answers. Nothing may be written, and the
	// operator must be told every address tried and what to do about it.
	t.Run("no address answers, so nothing is written and every one is named", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		seedJoinedAgent(t, f)
		cfg := agentCfg(t)
		f.putJoinAddrs(cfg.JoinServer, "203.0.113.9", "192.168.1.24")
		f.putJoinDialErr("203.0.113.9:9345", fmt.Errorf("connect: connection refused"))
		f.putJoinDialErr("192.168.1.24:9345", fmt.Errorf("connect: operation timed out"))

		err := Install(context.Background(), f, cfg)
		if err == nil {
			t.Fatal("Install accepted a --server no address of which answers: that is the crash-loop this gate exists for")
		}
		for _, want := range []string{
			"203.0.113.9:9345", "connection refused", // the first address, with its own error
			"192.168.1.24:9345", "operation timed out", // ...and the second, with its own
			cfg.JoinServer, // the name the operator typed
			"LAN address",  // the remedy: use the control-plane Mac's LAN address
			"firewall",     // ...check the firewall
			ServerLabel,    // ...and that the control plane is running there
			"Nothing has been written",
			"wait a minute and run this install again", // a just-installed control plane may still be opening its join listener
		} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("refusal %q does not carry %q", err, want)
			}
		}
		assertNothingWritten(t, f.calls)
	})

	// (c) The endpoint answers and belongs to another cluster — the join would
	// SUCCEED and be wrong, which is why this is refused before the tree exists.
	t.Run("the endpoint answers for a different cluster, so the install is refused", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		seedJoinedAgent(t, f)
		cfg := agentCfg(t)
		other := mintNodeCredential(t, t.TempDir())
		f.putJoinCA("", other.caPEM) // the address answers, for somebody else's cluster

		err := Install(context.Background(), f, cfg)
		if err == nil {
			t.Fatal("Install accepted an endpoint whose cluster CA is not the one the token pins")
		}
		servedPin, cerr := certs.CertPin(other.caPEM)
		if cerr != nil {
			t.Fatal(cerr)
		}
		for _, want := range []string{
			cfg.JoinServer + ":9345", // the address that answered
			"DIFFERENT cluster",
			cfg.TokenFile,       // the token file whose pin disagrees
			shortPin(servedPin), // enough of each hash to tell them apart...
		} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("refusal %q does not carry %q", err, want)
			}
		}
		// ...and never a whole one: a full pin printed at a terminal is a value
		// somebody pastes into a token file.
		if strings.Contains(err.Error(), servedPin) {
			t.Errorf("refusal %q printed a cluster-CA hash in full", err)
		}
		assertNothingWritten(t, f.calls)
	})

	// (d) The same endpoint, serving the cluster the token pins: the ordinary
	// worker install, which must pass without an operator saying anything.
	t.Run("the endpoint serves the cluster the token pins, so the install proceeds", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		seedJoinedAgent(t, f)
		cfg := agentCfg(t)

		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if idx(f.calls, "DialJoinServer:"+cfg.JoinServer+":9345") < 0 {
			t.Errorf("the join endpoint was never dialled; calls = %v", f.calls)
		}
		if idx(f.calls, "FetchJoinCA:"+cfg.JoinServer+":9345") < 0 {
			t.Errorf("the endpoint's cluster CA was never compared; calls = %v", f.calls)
		}
		// The preflight is a READ, and it precedes every write.
		probe := idx(f.calls, "DialJoinServer:"+cfg.JoinServer+":9345")
		user := idx(f.calls, "EnsureServiceUser:_k3sm:"+DefaultDataRoot)
		if user < 0 || probe > user {
			t.Errorf("the endpoint was probed at %d, after the first write at %d; calls = %v", probe, user, f.calls)
		}
	})

	// (f) A host behind a round-robin record: only the first joinProbeAddressCap
	// addresses are dialled, because an installer that spends a
	// timeout-per-address proving a typo is one an operator interrupts — and the
	// refusal SAYS how many it left alone rather than implying the list was
	// complete.
	t.Run("only the first four addresses are dialled, and the refusal says how many were not", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		seedJoinedAgent(t, f)
		cfg := agentCfg(t)
		all := []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4", "198.51.100.5", "198.51.100.6"}
		f.putJoinAddrs(cfg.JoinServer, all...)
		for _, a := range all {
			f.putJoinDialErr(a+":9345", fmt.Errorf("connect: connection refused"))
		}

		err := Install(context.Background(), f, cfg)
		if err == nil {
			t.Fatal("Install accepted a --server none of whose addresses answer")
		}
		for _, a := range all[:joinProbeAddressCap] {
			if idx(f.calls, "DialJoinServer:"+a+":9345") < 0 {
				t.Errorf("address %s was never dialled; calls = %v", a, f.calls)
			}
			if !strings.Contains(err.Error(), a+":9345") {
				t.Errorf("refusal %q does not name the tried address %s", err, a)
			}
		}
		for _, a := range all[joinProbeAddressCap:] {
			if idx(f.calls, "DialJoinServer:"+a+":9345") >= 0 {
				t.Errorf("address %s was dialled past the cap of %d; calls = %v", a, joinProbeAddressCap, f.calls)
			}
			if strings.Contains(err.Error(), a) {
				t.Errorf("refusal %q names %s, which it never tried", err, a)
			}
		}
		if want := fmt.Sprintf("%d more addresses not tried", len(all)-joinProbeAddressCap); !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not carry %q: an operator must not read a partial list as a complete one", err, want)
		}
		assertNothingWritten(t, f.calls)
	})

	// (g) The operator's token file is read ONCE. Everything that judges it —
	// the mode, the shape, the cluster it pins — happens at that read, before any
	// write; a file replaced afterwards must not reach the daemon, because
	// nothing compared those bytes to anything.
	t.Run("a token file swapped after the preflight does not change what is staged", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		validated := seedJoinedAgent(t, f)
		cfg := agentCfg(t)
		// Another cluster's token, dropped in the moment the preflight has read
		// the operator's file.
		swapped := mintNodeCredential(t, t.TempDir()).token
		f.putFileSwappedAfterRead(cfg.TokenFile, []byte(validated+"\n"), []byte(swapped+"\n"))

		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		staged := strings.TrimSpace(string(f.files[cfg.withDefaults().agentTokenPath()]))
		if staged != validated {
			t.Errorf("staged token = %q, want the bytes the preflight validated (%q)", staged, validated)
		}
		if staged == swapped {
			t.Error("the install staged a token nothing had validated: the file was read twice")
		}
		// ...and it was read exactly once, which is what makes the swap harmless.
		reads := 0
		for _, c := range f.calls {
			if c == "ReadRegularFileWithMode:"+cfg.TokenFile {
				reads++
			}
		}
		if reads != 1 {
			t.Errorf("the operator's token file was read %d times, want exactly 1 (calls %v)", reads, f.calls)
		}
		// ...and the swap really did happen, so this row is not passing because
		// nothing changed: the file on the fake now holds the other cluster's
		// token, and the install staged the earlier bytes anyway.
		if now := strings.TrimSpace(string(f.files[cfg.TokenFile])); now != swapped {
			t.Fatalf("the fixture never swapped the token file (it holds %q): this row would pass vacuously", now)
		}
	})

	// (e) A control plane joins nothing, so it asks nothing: a server install on
	// a Mac with no network at all must still install.
	t.Run("a server install runs no join preflight", func(t *testing.T) {
		f := &fakeSystem{}
		if err := Install(context.Background(), f, Config{BinarySource: "/tmp/k3sm", TargetUser: "alice"}); err != nil {
			t.Fatalf("Install: %v", err)
		}
		for _, c := range f.calls {
			for _, prefix := range []string{"ResolveJoinHost:", "DialJoinServer:", "FetchJoinCA:"} {
				if strings.HasPrefix(c, prefix) {
					t.Errorf("a control-plane install probed a join endpoint (%q): it joins nothing", c)
				}
			}
		}
	})
}
