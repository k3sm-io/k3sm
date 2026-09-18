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

// Package nodecred READS the node credential store: everything a joined worker
// keeps so a RESTART is not a rejoin.
//
// A join is a credential-issuing event — it costs a join token, which is
// TTL-bounded, and it re-mints this node's certificates. So `k3sm agent`
// persists the whole join outcome and presents it on restart, in five files
// under the agent work dir, because the halves are useless apart:
//
//   - node.kubeconfig        the cluster CA + this node's system:node client keypair
//   - kubelet-serving.crt    the cluster-CA-issued :10250 serving cert
//   - kubelet-serving.key    its private key (generated on the node, never on the wire)
//   - kubelet-client-ca.crt  the client-identity CA this node's :10250 verifies the apiserver against
//   - node-assignment.json   the mesh/apiserver assignment: pod /24, mesh-egress /32, peer snapshot, apiserver endpoints
//
// The assignment file is the non-obvious one. The three certificate artifacts
// reconstruct this node's IDENTITY, but a worker also needs the values the
// server ASSIGNED it — the pod /24 the mesh device is built from and the
// mesh-egress /32 the Service proxy sources — and those arrive only in a join
// response. They cannot be re-read from the apiserver at start either: a joined
// worker's kubeconfig points at the server's MESH address, which is reachable
// only once the mesh this data is needed to build is already up.
//
// # Why the read half is its own package
//
// Two callers must reach the SAME verdict about one directory: the agent, which
// decides whether it can start without a token, and `k3sm status` / `k3sm
// doctor`, which tell an operator whether this Mac is really in the cluster. A
// looser second check is not a smaller version of the first — it is a report
// that says "valid" about a credential the daemon refuses to start with, which
// sends an operator to the wrong Mac. So the five path names, the validation
// (both keypairs proven against their certificates, the client CA decoded, a
// non-empty assigned podCIDR, and the serving certificate's IP SANs compared
// with the assigned mesh address) and the ExpiryMargin live here exactly once.
//
// The WRITE half stays with the agent: it is the only process that has a join
// outcome to persist, and persisting it needs the join types this package is
// deliberately free of.
//
// The package is dependency-light on purpose — the standard library,
// client-go's kubeconfig loader, the shared apis mesh-peer type and k3sm's own
// pkg/certs — so a reporting leaf can import it without pulling the installer,
// the runtime or the bootstrap stack in behind one row.
package nodecred
