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

// Package api serves the OCI distribution API over the registry's on-disk
// store (pkg/ociregistry/store): the version check, the catalog, tag lists,
// manifests, blobs, upload sessions, cross-repository mounts and referrers.
//
// Every repository name, tag, digest and session id in a path or a query is
// validated through pkg/ociregistry/ref before the store is touched, reads
// included. Routing is github.com/gorilla/mux, manifests decode with
// encoding/json into the image-spec types, and digests verify with go-digest.
// Two pieces are written here because no maintained library implements them:
// the upload session state machine (session.go) and the parsing of the OCI
// chunked-upload Content-Range value, "<start>-<end>" rather than the RFC 9110
// form (crange.go). Both are bounded, fail closed and are fuzzed with
// committed seeds.
//
// Behaviour follows the registry this replaces where clients can tell:
//
//   - manifest GET and HEAD ignore Accept and answer with the media type the
//     manifest was pushed with, and Docker-Content-Digest; a HEAD by digest
//     of an untagged row restarts the manifest's garbage-collection grace
//     (store.TouchBlob, bounded as below), so a client that skips pushing an
//     index's child on a HEAD hit finds it at the index PUT, while a HEAD by
//     tag, a HEAD of a tagged row and every GET write nothing;
//   - a manifest PUT accepts the OCI manifest and index and the Docker v2
//     manifest and manifest list (415 otherwise), reads at most 4 MiB (413
//     above), requires the blobs an image manifest names to be in the
//     repository and never requires an index's children;
//   - a blob GET goes through http.ServeContent, so Range, 206 and 416 are
//     the standard library's; a blob HEAD restarts the blob's
//     garbage-collection grace (store.TouchBlob, bounded as below), so a
//     client that skips an upload on a HEAD hit finds the blob at its
//     manifest PUT;
//   - upload Location headers are path-only, a status GET answers 204 with
//     Range "0-<n-1>", and both Blob-Upload-UUID and Docker-Upload-UUID are set;
//   - a mount links the blob from the repository named by from and from no
//     other; anything else is a 202 upload session;
//   - a tag DELETE removes that tag's row, a digest DELETE every row of the
//     digest, and a digest an index in the repository names is not deleted;
//   - a DELETE with If-Match is conditional on the repository's index state
//     (store.IndexState of its rows, as a quoted entity tag), compared under
//     the repository lock; a state that no longer holds is 412 and deletes
//     nothing. The registry this replaces ignores If-Match;
//   - blobs are never deleted through the API; garbage collection removes
//     them.
//
// A HEAD is a read, anonymous where reads are, so the write it makes is
// bounded. It writes at most once per half of the collector's grace
// (Config.GCGrace) per object, never on a manifest any tagged row names, and
// takes the repository lock only to make that write; every other HEAD is
// answered from a stat. This does not stop a caller from keeping an untagged
// object alive: one HEAD just past every half-grace does it. Knowing the
// digest is the capability, as it is for the blob HEAD and as a push of the
// same content would be. A touch that fails for any reason other than the
// object being gone (a read-only or degraded store, a client that gave up
// waiting for the lock) is logged and the HEAD answers 200: the read
// succeeded, and the touch only protects a push that may follow. The object
// is then not touched again, and its lock not taken, for half the grace, and
// the failure is logged once for that window; the server remembers at most
// 4096 such objects, dropping the one whose window ends first. The trade is
// that a client that HEADs an object and then waits longer than half the
// grace before the PUT naming it, or HEADs on a store that cannot be written,
// is not protected by that HEAD and can find the object reaped; a push that
// fits in half the grace, the case the touch exists for, is protected as
// before.
//
// GCGrace is required, as gc.Options.Grace is, and New refuses a server
// without it. Whoever wires the server and the collector over one store must
// pass both the same value: a smaller GCGrace touches more often than needed,
// a larger one widens the window above in which a HEAD protects nothing.
//
// Limits, each a Config field with a default:
//
//   - at most MaxSessions upload sessions in use at once (503 beyond); only a
//     session the server created or the store confirmed counts, so an id a
//     client makes up takes no slot. There is no per-principal cap: one
//     client may use every slot;
//   - an upload session holds at most MaxUploadSize bytes: a known length over
//     it is refused before a write, and a chunk of unknown length that would
//     pass it is refused with 413 and cut back, so no byte past the cap stays;
//   - an upload is refused with 507 when the store volume would keep less than
//     MinFreeSpace free, checked against a known length before the first write
//     and again every 64 MiB while a body streams;
//   - a request body must bring BodyMinBytes in every BodyWindow, may not go
//     BodyIdle without a byte, and may not run past UploadTimeout (408);
//   - a header read timeout of 30 s, and a write deadline set per request
//     (ResponseTimeout, plus UploadTimeout for a request with a body, plus a
//     blob's size at MinWriteRate for a blob GET) instead of a server-wide
//     write timeout, so a large blob GET is not cut.
//
// The number of connections is not bounded here: that cap belongs to the
// listener the daemon wires. Every handler recovers from a panic with a 500,
// and an upload gives back its session entry and slot on every way out.
// Access decisions belong to the Authorizer the caller supplies, which New
// requires (AllowAll is the explicit open registry); the package classifies
// each request as a read, a write or a delete (an upload cancel is a delete).
package api
