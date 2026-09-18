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
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"k3sm.io/k3sm/pkg/certs"
)

// joinBootstrapPort is the port the control plane's bootstrap listener answers
// on — the one the join, the endpoint refresh and the deregistration all dial.
// It is a constant here rather than a config field because nothing in k3sm lets
// an operator move it: `k3sm agent --server <host>` takes a host and this port
// is implied by it (see Config.JoinServer).
const joinBootstrapPort = 9345

// joinProbeTimeout bounds each dial and each CA fetch. It is short on purpose:
// the preflight is answering "does this address answer at all", and an operator
// waiting on `sudo k3sm install` should learn that a name points nowhere in
// seconds, not after a kernel-length TCP timeout on every address it resolved.
const joinProbeTimeout = 3 * time.Second

// joinProbeAddressCap is how many of the addresses a join host resolves to are
// dialled. A name behind a round-robin record can carry a dozen, each costing up
// to joinProbeTimeout before it is written off, and an installer that spent
// forty seconds proving a typo is an installer an operator interrupts. Four is
// enough for every shape k3sm actually meets (a Mac with a v4 and a v6 address,
// plus a stale record or two), and the refusal SAYS how many were left untried
// rather than quietly pretending the list was complete.
const joinProbeAddressCap = 4

// preflightJoinEndpoint refuses an agent install whose --server cannot be
// reached, or which would join a DIFFERENT cluster than the operator's token
// pins — before a single byte is written.
//
// It exists because of the 2026-09-17 install that took a name resolving to an
// unreachable address, laid down the whole tree, and left the daemon
// crash-looping on "post mesh endpoint refresh: dial tcp <addr>:9345: connection
// refused" — a failure whose only witness was the crash record, on a Mac that
// then had to be uninstalled. Everything this checks is READ-ONLY and every
// answer is available before the install starts, so the cost of checking here is
// two round trips and the cost of not checking is a half-installed machine.
//
// The two questions are deliberately separate, because they have different
// remedies. REACHABILITY is asked of every resolved address in turn, and the
// first one that answers wins — a control-plane host commonly resolves to both a
// LAN address that works and a public or stale one that does not, and the join
// succeeds iff one of them answers. IDENTITY is then asked of that one address:
// the endpoint's own cluster CA is fetched and hashed, and it must equal the pin
// the operator's token carries. A mismatch is not a broken cluster — it is the
// wrong cluster, which is worth far more than a dial failure, because joining it
// would succeed and be wrong.
//
// Neither hash is ever printed in full. The pin identifies a cluster, an
// operator comparing two clusters only needs enough to tell them apart, and a
// truncated hash cannot be pasted anywhere it would be mistaken for a token.
//
// A server install returns immediately: it joins nothing. So does an agent
// install with no --token-file — a node that has already joined starts from its
// stored credential, and there is no pin to compare — but its reachability is
// still checked, because the daemon dials the same endpoint on every start.
//
// It RETURNS the operator's join token: the exact bytes it validated and pinned
// the endpoint against, which stageJoinToken later writes. The file is therefore
// read exactly once per install. Reading it a second time at staging — after the
// service user, the log trees and the run dir exist — would mean the bytes
// checked against the cluster and the bytes handed to the daemon came from two
// different reads, with privileged writes in between: a token file replaced in
// that window would be staged unvalidated, against a cluster nobody compared it
// to. The empty string is the answer when there is no token to stage.
func preflightJoinEndpoint(sys System, cfg Config) (string, error) {
	if cfg.Role != RoleAgent {
		return "", nil
	}
	if strings.TrimSpace(cfg.JoinServer) == "" {
		return "", fmt.Errorf("install: --server (the control-plane host this worker joins) is required with --agent")
	}
	// The pin FIRST, because reading it is the one step that can fail on this
	// Mac alone: a token file that is missing, exposed or malformed is refused
	// here rather than after two network round trips, and the message an
	// operator gets is the one about their own file.
	pin, token := "", ""
	if cfg.TokenFile != "" {
		text, tok, err := operatorJoinToken(sys, cfg)
		if err != nil {
			return "", err
		}
		// Normalised ONCE, here at the boundary where the token becomes a pin, so
		// the comparison below is a plain string equality: a case-insensitive
		// compare at the point of use invites the next comparison to be written
		// without it, and two rules for one hash is one rule too many.
		pin, token = strings.ToLower(strings.TrimSpace(tok.CAHash)), text
	}

	host := strings.TrimSpace(cfg.JoinServer)
	addrs, err := sys.ResolveJoinHost(host, joinProbeTimeout)
	if err != nil {
		return "", fmt.Errorf("install: %s (the --server this node would join) does not resolve: %w — name the control-plane Mac's LAN address (an underlay address: the join must reach <host>:%d before this node has any mesh)", host, err, joinBootstrapPort)
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("install: %s (the --server this node would join) resolves to no address at all — name the control-plane Mac's LAN address (an underlay address: the join must reach <host>:%d before this node has any mesh)", host, joinBootstrapPort)
	}

	untried := 0
	if len(addrs) > joinProbeAddressCap {
		untried = len(addrs) - joinProbeAddressCap
		addrs = addrs[:joinProbeAddressCap]
	}
	var (
		reached  string
		refusals []string
	)
	for _, a := range addrs {
		addr := net.JoinHostPort(a, strconv.Itoa(joinBootstrapPort))
		if err := sys.DialJoinServer(addr, joinProbeTimeout); err != nil {
			refusals = append(refusals, fmt.Sprintf("%s (%v)", addr, err))
			continue
		}
		reached = addr
		break
	}
	if reached == "" {
		tried := strings.Join(refusals, "; ")
		if untried > 0 {
			tried += fmt.Sprintf("; %d more addresses not tried", untried)
		}
		return "", fmt.Errorf("install: the control plane at %s cannot be reached, so this node could not join it: %s. Nothing has been written. Use the control-plane Mac's LAN address, check that its firewall lets %d through, and check that io.k3sm.server is running there (`sudo launchctl print system/%s` on that Mac); if that Mac was installed only moments ago, its join listener may still be starting, so wait a minute and run this install again",
			host, tried, joinBootstrapPort, ServerLabel)
	}
	if len(refusals) > 0 {
		cfg.Logger.Info("the join endpoint answered on one of the addresses this host resolves to",
			"reached", reached, "did-not-answer", strings.Join(refusals, "; "))
	}
	if pin == "" {
		cfg.Logger.Info("no --token-file was given, so the join endpoint's cluster was not compared: this node starts from the credential it already holds",
			"server", reached)
		return "", nil
	}

	caPEM, err := sys.FetchJoinCA(reached, joinProbeTimeout)
	if err != nil {
		return "", fmt.Errorf("install: the control plane at %s answered, but its cluster CA could not be read (%w), so this install cannot tell whether it is the cluster your token names. Nothing has been written. Check that io.k3sm.server — not some other service — is what answers on port %d there",
			reached, err, joinBootstrapPort)
	}
	servedPin, err := certs.CertPin(caPEM)
	if err != nil {
		return "", fmt.Errorf("install: the endpoint at %s served something that is not a cluster CA certificate (%w), so it is not a k3sm control plane. Nothing has been written. Check that port %d there belongs to io.k3sm.server",
			reached, err, joinBootstrapPort)
	}
	served := strings.ToLower(strings.TrimSpace(servedPin))
	if served != pin {
		return "", fmt.Errorf("install: the control plane at %s belongs to a DIFFERENT cluster than the join token in %s pins (that endpoint's cluster CA is %s…; the token pins %s…), so this node would have joined the wrong cluster. Nothing has been written. Either point --server at the Mac the token came from, or mint a token there with `k3sm token create` and write it into %s",
			reached, cfg.TokenFile, shortPin(served), shortPin(pin), cfg.TokenFile)
	}
	cfg.Logger.Info("the control plane answered and is the cluster this token pins", "server", reached, "cluster-ca", shortPin(served)+"…")
	return token, nil
}

// shortPin is how much of a cluster-CA hash an operator is shown: enough to tell
// two clusters apart, and never the whole value. A full pin is what a join token
// carries, and a message that prints one invites it to be pasted back into a
// file where a token belongs.
func shortPin(hash string) string {
	if len(hash) <= 8 {
		return hash
	}
	return hash[:8]
}
