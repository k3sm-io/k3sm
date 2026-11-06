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

// Package updater is the root updater's stage path and swap state machine.
//
// Stager turns a release archive a less privileged user delivered into a
// verified versions/<ver> directory: it copies the archive and its signed
// manifest into a root-only work directory, closes the source, hands only the
// copy to the k3sm signature verifier, checks the manifest's rules and every
// extracted file, runs the Apple code check on the final paths and renames the
// set into place. Machine moves the node to a staged version and back: it
// writes a marker before every step, flips current, restarts the jobs, waits for
// health, and commits or rolls back. Both resume from what is on disk after a
// crash or a reboot, and every marker write reaches stable storage first.
//
// Everything operates on a root passed in and behind the interfaces in
// interfaces.go. The package owns no daemon, socket or launchd plist; the
// resident k3sm-updater program wires the production implementations.
package updater
