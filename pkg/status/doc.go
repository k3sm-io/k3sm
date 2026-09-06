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

// Package status resolves and renders what k3sm is doing on this Mac: the two
// LaunchDaemons, the apiserver, the node, the workloads, the data root, the
// datastore, and the runtime daemon — as one verdict, a row per subsystem, and
// the next command to run for whatever is down.
//
// The package is a LIBRARY: every function returns a string or a struct and
// nothing here writes to stdout, opens a socket, or shells out. Everything the
// report needs from the machine arrives through the seams in probes.go, which
// cmd/k3sm wires to the real launchctl, filesystem, apiserver and sysctl at the
// main boundary. That split is what lets a unit test describe a crash-looping
// daemon on an unmounted data root — a posture no unprivileged test could
// create — and pin the exact screen an operator would read.
//
// Two invariants are load-bearing and are pinned by tests:
//
//   - Raw launchctl output NEVER reaches a Row. `launchctl print` echoes a
//     job's whole argv, and the server's argv carries the cluster join token.
//     Only the four parsed keys (state, pid, runs, last exit code) cross the
//     boundary, and any text taken from a log line goes through Redact first.
//   - The verdict is a machine contract. Verdict.ExitCode is what `k3sm status`
//     exits with, the numbers are additive-only, and Unknown ("could not
//     determine") is deliberately distinct from an internal error.
package status
