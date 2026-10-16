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

// Package update answers "is there a newer k3sm, and which nodes are not on
// it?". Check resolves the latest release exactly the way install.sh does,
// reads the version of this binary and of every Node, and compares them.
// Check only reads; the Watcher (below) is the half that installs a release.
//
// The tag a release index answers with is data. It is validated to the
// characters a git version tag carries and is never handed to a shell or a
// file path; the one place it is spliced is a URL path segment, escaped.
//
// # Applying a release on a node
//
// The Watcher is the node half of the managed cluster update: the part of
// every k3sm node daemon (server and agent alike) that installs the release
// the update controller asks its Node for.
//
// The controller hands a node over by setting two annotations on it in one
// patch (updatesv1alpha1.AnnotationUpdateVersion, the release tag, and
// AnnotationUpdatePayload, a JSON Payload naming the release archive, its
// sha256, the signature policy and the downgrade permission) and clearing
// AnnotationUpdatePhase. The Watcher sees the handover on its own Node and,
// when the tag is not the build it runs:
//
//   - refuses a payload that is malformed, an archive URL that is not https
//     on github.com or objects.githubusercontent.com, and a tag below the
//     running build unless the payload allows a downgrade;
//   - writes Downloading and fetches the archive (at most MaxArchiveBytes,
//     within DownloadTimeout) into a fresh directory under its own root, a
//     directory of the data root the service user owns;
//   - writes Verifying and checks the archive's sha256 against the payload
//     before a byte of it is unpacked, then extracts the build set (regular
//     files only, by an exact list of names) and computes its manifest;
//   - writes Installing and asks the k3sm-netd root helper, through its
//     ApplyUpdate verb, to install the set, mirroring the phases it streams.
//
// The installer restarts this daemon. The restarted daemon finds its own
// build on the tag and, once it is fully up (Config.Ready), writes Done; the
// controller then waits for the Node's kubeletVersion to carry it and its Ready
// condition to hold. Only the phase annotation is ever written here; the
// controller owns, and clears, every other update annotation.
//
// A refusal or a failed install writes Failed with the reason, and the
// download directory stays for diagnosis until the next attempt or the next
// start removes it. Nothing downloaded is ever run by
// this package: the only binary of the set that runs is the staged k3sm, and
// the root helper runs it after its own digest check.
//
// The phase annotation reads "<phase>" or "<phase>: <message>", the message
// at most MaxMessageBytes with control characters removed.
package update
