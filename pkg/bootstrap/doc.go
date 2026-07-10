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

// Package bootstrap implements k3sm's multi-node worker join + trust (M3.0).
//
// It is the security-critical core of "a second Mac joins the cluster" (DESIGN
// §5c): the K10 CA-pinned join token (token.go), the TTL-bounded
// bootstrap-token store distinct from the system:masters admin token, the
// anti-impersonation node-password (hashed + constant-time + first-write-wins,
// nodepassword.go), the HTTP-CSR approver that mints a CN=system:node:<name>,
// O=system:nodes identity bound to the authenticated node + its InternalIP
// (csr.go), the MeshPeer write-guard (a node may write only its own MeshPeer,
// meshguard.go), and the join HTTP exchange — the supervisor-side Server (server.go)
// and the agent-side Join client (join.go).
//
// The PKI primitives it builds on live in k3sm.io/k3sm/pkg/certs; the mesh-enroll
// wire payloads are k3sm.io/apis/net/v1's version-stamped MeshEnrollRequest/Response.
package bootstrap
