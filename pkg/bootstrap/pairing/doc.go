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

// Package pairing is plug-and-join over a direct cable: a Mac that is not yet in
// the cluster is admitted while the server's pairing window is open, and
// physical presence on one of the server's cable ports is the credential.
//
// # The pieces
//
//   - The beacon (Sender, Receiver): every 2 s the server multicasts a small,
//     unsigned netv1alpha1.Beacon to ff02::1 port 9346 on each cable interface.
//     It is DATA: a hint that the receiver may ask to pair, never an instruction.
//     Its cluster pin is information, not authentication; every device on the
//     cable learns the pin and the server's node name.
//   - The window (WindowStore): <workDir>/pairing-window.json, {until, maxJoins,
//     completed}, written by `sudo k3sm pair --for <dur>` and read on every pair
//     request. It is a file, not a cluster object, because pairing must work
//     before the apiserver is reachable over the cable.
//   - The pair verb (Handler): POST /v1-k3sm/pair on the server's per-interface
//     link-local listeners. After the shared pre-authentication bound and a body
//     limit it decides, in order and each with its own refusal reason: the
//     connection's LOCAL address is fe80::/10 with a zone that the system's own
//     hardware-port mapping names a Thunderbolt port (Decide); the remote is fe80
//     on the same zone; the window is open with joins to spare; and the
//     interface has not been accepted in the last 10 s and the window's mint cap
//     is not spent. It then mints an ordinary worker join token, bound to the
//     requested node name, one-shot, with a 2-minute TTL, so the existing join is
//     reused unchanged.
//   - The joiner (Joiner): on the new Mac, armed for a bounded time by
//     `sudo k3sm install --auto-join`, it listens for beacons, skips any whose
//     pin differs from the operator's --cluster pin, asks the first open server
//     it hears for a token over TLS pinned to the beacon's pin, and hands the
//     result to the ordinary join. Unarmed or expired it does nothing.
//
// # The trust decision
//
// The server side authenticates the cable: a request is honoured only when the
// kernel says it arrived on a Thunderbolt port (the TCP connection's zone IS the
// interface), never by a source address or an interface name a client chose.
// The joiner side authenticates nothing without --cluster: it trusts the first
// open-pairing server it hears while armed, a documented limitation, and the pin
// is the mutual-authentication option. TestPairTrustDecision pins both halves.
package pairing
