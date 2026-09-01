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

package main

import (
	"flag"
	"strings"
	"testing"
)

// guestArtifactsDirFlag is the DEV-ONLY guest-artifact directory override named
// by the M11.2-d3 ledger row: a way to point a lab node at a locally-built
// kernel + initramfs instead of the pinned, published, digest-verified pair.
//
// It does not exist anywhere in this repo today, and this test is what keeps its
// eventual arrival honest rather than a discovery made in production.
const guestArtifactsDirFlag = "guest-artifacts-dir"

// TestGuestArtifactsDirOverrideIsDevOnly pins the STRUCTURAL half of the
// guest-artifact trust boundary: the three commands a real cluster runs —
// `k3sm server`, `k3sm agent`, `k3sm node` — must not offer any way to bypass
// the in-code digest pin.
//
// Why a structural test and not a behavioural one. Everything else about the
// artifact path is content-addressed: ensure hashes every byte it installs and
// re-hashes every byte it reuses, so no fetch, no cache and no mirror can put
// unpinned bytes under a vm pod. An artifact-DIRECTORY override defeats all of
// that at once, by construction — it does not weaken the verification, it
// removes the thing being verified against. There is therefore no assertion
// about its behaviour worth writing; the only safe property is that a daemon
// command cannot express it, and absence is provable only against the real
// registered flag set (which is exactly why registerServerFlags /
// registerAgentFlags / registerNodeFlags exist as functions).
//
// FAILS-BEFORE is a genuine future event, not a hypothetical: the moment someone
// adds the flag to the daemon surface — including by adding it "temporarily" so
// `k3sm dev` can thread it through the `k3sm server` it re-execs — this test goes
// red and names the command. That re-exec is the specific trap: `k3sm dev up`
// starts a real `k3sm server` child (newDevManager's Self), so a dev override
// CANNOT be implemented as a server flag without also handing it to every
// operator and every launchd job. It has to reach the child by some other route
// that a production bring-up structurally cannot take.
//
// The test asserts the flag's ABSENCE, never that some other flag is present, so
// it cannot be satisfied by renaming anything.
func TestGuestArtifactsDirOverrideIsDevOnly(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		cmd      string
		register func(fs *flag.FlagSet)
	}{
		{
			cmd: "server",
			register: func(fs *flag.FlagSet) {
				var opts serverOptions
				// The returned work-dir resolution error is irrelevant here: the
				// flags are registered either way, and this test reads the SET.
				_ = registerServerFlags(fs, &opts)
			},
		},
		{
			cmd: "agent",
			register: func(fs *flag.FlagSet) {
				var opts agentOptions
				registerAgentFlags(fs, &opts)
			},
		},
		{
			cmd: "node",
			register: func(fs *flag.FlagSet) {
				var opts nodeOptions
				registerNodeFlags(fs, &opts)
			},
		},
	} {
		t.Run(tc.cmd, func(t *testing.T) {
			t.Parallel()
			fs := flag.NewFlagSet(tc.cmd, flag.ContinueOnError)
			tc.register(fs)

			if f := fs.Lookup(guestArtifactsDirFlag); f != nil {
				t.Fatalf("`k3sm %s` defines --%s (%q). The guest-artifact directory override is DEV-ONLY: "+
					"it bypasses the in-code digest pin entirely, so a production daemon must have no way to express it. "+
					"Move it onto the `k3sm dev` subcommand tree — and note that `k3sm dev` re-execs `k3sm server`, "+
					"so it cannot be threaded as a server flag either.",
					tc.cmd, guestArtifactsDirFlag, f.Usage)
			}

			// A near-miss guard: the assertion above is an exact-name lookup, so a
			// flag spelled --guest-artifacts / --guest-artifact-dir would slip past
			// it while doing the identical thing. Anything carrying both halves of
			// the name is treated as the same escape hatch.
			fs.VisitAll(func(f *flag.Flag) {
				n := strings.ToLower(f.Name)
				if strings.Contains(n, "guest-artifact") && strings.Contains(n, "dir") {
					t.Errorf("`k3sm %s` defines --%s, which is a guest-artifact directory override under another name (%q)", tc.cmd, f.Name, f.Usage)
				}
			})
		})
	}
}
