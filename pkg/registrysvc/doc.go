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

// Package registrysvc runs k3sm's node-local OCI ingest registry: a pinned zot
// child process bound to loopback, into which an operator pushes locally built
// images and out of which this node's runtime pulls them.
//
// It exists because a single-Mac cluster otherwise has no way to get a locally
// built image to a Pod without a public registry: `k3sm image load` reaches the
// node's store but bypasses every kubelet image semantic (imagePullPolicy, the
// ref->digest index, pull failures), so a Pod that says `imagePullPolicy: Always`
// against a locally loaded image is describing something that never happens. A
// real registry on loopback restores the whole path.
//
// # Shape
//
// zot is NOT linked in. It is a pinned CHILD PROCESS built on demand
// (`go install zotregistry.dev/zot/v2/cmd/zot@<pin>`, CGO_ENABLED=0, out of this
// module) or seeded from a packaged install's staged payload — exactly the
// treatment pkg/executor gives kine, and for the same two reasons: the registry's
// dependency tree never enters any k3sm.io go.mod, and the binary that runs is
// identified by a VERSION MARKER rather than by mere presence, so a pin change
// reaches machines that have already booted once.
//
// # Layout (all paths relative to the control-plane work dir)
//
//	<work-dir>/registry/                    the registry state root, mode 0700
//	<work-dir>/registry/config.json         the rendered zot config, mode 0600
//	<work-dir>/registry/htpasswd            the bcrypt push credential, mode 0600
//	<work-dir>/registry/push-credential.json the same credential in plaintext, mode 0600
//	<work-dir>/registry/<repo>/…            the OCI blob store (zot's rootDirectory)
//	<work-dir>/registry.log                 the child's stdout+stderr, mode 0600
//	<work-dir>/bin/zot                      the staged binary
//	<work-dir>/bin/zot.version              its version+variant marker
//
// CredentialPath names push-credential.json, and it is the CONTRACT this package
// publishes to the rest of k3sm: `k3sm image push` reads that file to authenticate
// a push at a loopback target whose address matches the one recorded in it. The
// file is rewritten with a freshly generated password on every boot, is never
// world-readable, and is never copied anywhere else — a credential that outlives
// the process that minted it is a credential nobody rotates.
//
// The credential and config files sit INSIDE zot's storage root. That is
// deliberate (one directory to create, chmod and remove) and it is safe: zot
// creates a repository as a DIRECTORY, so a push to a repository named after one
// of these files fails on the collision rather than overwriting it, and zot serves
// only the /v2/ dist-spec API — it never serves a file out of the storage root.
//
// # Access
//
// Push is authenticated, pull is anonymous. That asymmetry is the whole security
// posture: the node's own runtime pulls with no credential to distribute, while
// nothing that merely reached the port can write an image the cluster will then
// run. TLS is deliberately absent — the listener is loopback-only and a
// certificate would buy nothing against an attacker who is already on the host.
// Constructing a Service with a non-loopback bind address is an error, so the
// posture cannot be widened by configuration.
package registrysvc
