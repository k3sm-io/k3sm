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

// Package clustermirror tells this node's image puller which OTHER nodes'
// ingest registries it may fall back to.
//
// # The problem it solves
//
// Each node runs its own loopback ingest registry (pkg/registrysvc), so
// `localhost:<port>/app:v1` means a DIFFERENT registry on every node. Push the
// image on one Mac, schedule the Pod on another, and the pull fails: the
// reference is correct, and the node it landed on has simply never been fed.
//
// runtimed's puller already knows how to recover from that — when a
// NODE-RELATIVE reference misses on this node's own registry, it consults the
// cluster mirrors it was given (see runtimed/pkg/image's MirrorSource, whose doc
// comments own the contract). What it cannot do is learn who the peers are:
// runtimed neither reads the apiserver nor speaks the mesh. This package is the
// half that does, and it is deliberately the ONLY thing it does.
//
// # What it reads
//
// The per-node advertisements registrysvc publishes — one ConfigMap per node
// naming that node's mesh-reachable registry authority. They are watched through
// a shared informer, so a node that joins the cluster becomes a mirror candidate
// without anything here polling.
//
// # Three properties worth stating outright
//
// TRANSPORT, NEVER IDENTITY. This package returns hosts. The puller does the
// reference rewrite, ingests under the reference the POD asked for, and verifies
// every blob against its manifest digest exactly as it does on the primary path.
// So a peer can change where bytes come from and can never change which bytes.
//
// NO CREDENTIAL CROSSES THE SEAM. A peer's ingest registry serves anonymous
// pulls; its push credential is a per-boot 0600 file on the node that minted it
// and is never distributed. Nothing here holds, reads, or forwards one.
//
// IT DEGRADES, IT NEVER BLOCKS. An informer that has not synced, a cluster with
// no peers, an apiserver that is refusing the watch — all produce an empty
// candidate list, which restores exactly the single-node behavior: the primary
// pull error stands as the pull's answer. A pod is never held up waiting for this.
package clustermirror
