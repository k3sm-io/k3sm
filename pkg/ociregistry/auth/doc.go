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

// Package auth is the registry server's authentication and access model: the
// api.Authorizer the k3sm registry runs with.
//
// There are three principals. The permission matrix is fixed:
//
//	                               anonymous   k3sm   k3sm-gate
//	read (GET, HEAD)               yes         yes    yes
//	upload, mount, manifest PUT    no          yes    yes
//	DELETE manifest or tag         no          yes    no
//	upload cancel                  no          yes    no
//
// k3sm is the local CLI's credential (push-credential.json); k3sm-gate is the
// push gate's, which forwards writes the cluster's RBAC already authorized
// and may never delete. Both secrets are 256-bit random values minted per
// boot by the daemon, which writes only their SHA-256 hashes into the serve
// config. Because the secrets carry full entropy, a slow password hash adds
// nothing, so the server neither parses an htpasswd file nor runs bcrypt: it
// hashes the presented secret once and compares the digests with
// crypto/subtle, and an unknown user runs the same compare against a dummy
// digest, so the answer's timing does not tell a known user from an unknown
// one.
//
// Answers:
//
//   - a request with no credentials that needs one (any write or delete) is
//     ErrUnauthenticated: 401 with a Basic challenge;
//   - a credential that does not verify, or an Authorization header this
//     package does not accept, is also ErrUnauthenticated, whatever the verb,
//     and is charged to the source's failure bucket;
//   - a verified principal without the permission is ErrDenied: 403 DENIED;
//   - a source whose failure bucket is empty gets ErrRateLimited (429) for any
//     request that presents credentials, before anything is compared. Requests
//     without credentials do not draw on the bucket.
//
// The bucket replaces the registry's earlier one-second failure delay without
// holding a goroutine per failed attempt. A source is the request's
// RemoteAddr host only: a forwarded-for header is never trusted. Every
// connection through the TLS relay arrives from loopback, so all relayed
// clients share one bucket; a client that exhausts it with wrong secrets can
// make the others wait for the refill, which is the price of not trusting a
// header the client writes.
//
// Limits, all fail-closed: one Authorization header of at most
// MaxAuthorizationBytes, a user name of at most MaxUserBytes and a secret of
// at most MaxSecretBytes, and at most MaxSources tracked sources (a new
// source beyond that, when no tracked one has refilled, is rate limited).
package auth
