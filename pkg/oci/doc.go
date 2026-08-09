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

// Package oci is the one OCI-plumbing home for the k3sm CLI: it turns operator
// inputs into OCI images and writes them out. It is deliberately the ONLY site
// in this repo that assembles image bytes.
//
// # Division of labor against its neighbours
//
//   - k3sm/pkg/oci (here) — build/ingest plumbing for the CLI. Assembles a
//     v1.Image from operator inputs and writes it to a Sink.
//   - runtimed/pkg/image — the content-addressed store and the registry pull
//     path. Owns Cache.CommitBlob (the single home of the CAS digest-verification
//     invariant) and platform selection. This package CONSUMES it; it never
//     re-implements a store and never writes the store layout directly.
//
// Nothing here writes to the shared store. See "Output sinks" below.
//
// # The Dockerfile subset (the user-facing grammar)
//
// Parse implements a strict ALLOWLIST. Every construct outside the list below
// is an error naming what was rejected — the parser never guesses, and never
// silently ignores an instruction. A silently-dropped instruction would produce
// an image that looks built but whose content is not what the recipe said, which
// is the same defect class as executing a RUN would be.
//
// Accepted:
//
//	FROM scratch                  (the only base in v1 — see "Deliberate omissions")
//	COPY <src>... <dest>          shell and JSON-array forms
//	ADD  <src>... <dest>          an exact alias of COPY — see below
//	ENV  k=v [k=v...] | k v
//	ENTRYPOINT ["exec","form"] | shell form
//	CMD        ["exec","form"] | shell form
//	WORKDIR <path>                relative paths accumulate onto the previous WORKDIR
//	LABEL k=v [k=v...]
//	EXPOSE <port>[/tcp|/udp]...
//
// Rejected, each with its own named error: RUN (ErrRunUnsupported, naming the
// vm-backed builder as the RUN-capable path), every other standard Dockerfile
// verb (USER, VOLUME, HEALTHCHECK, SHELL, STOPSIGNAL, ONBUILD, ARG, MAINTAINER —
// ErrUnsupportedInstruction), unknown verbs (ErrUnknownInstruction), and the
// ambiguity classes a subset parser would otherwise mis-read: heredocs, the
// "# syntax=" / "# escape=" parser directives, per-instruction flags
// (--from=, --chown=, --chmod=), variable references in a COPY/ADD path, and a
// second FROM (multi-stage) — all ErrUnsupportedSyntax.
//
// # ADD is exactly COPY
//
// Docker's ADD additionally fetches remote URLs and auto-extracts local archives.
// This builder does NEITHER, and refuses rather than degrading: a URL source is
// ErrRemoteSource, an archive source is ErrArchiveAutoExtract. Both halves are
// attacker-reachable through the Dockerfile — which is the lower-trust of the two
// inputs, since it travels with a repository — and a URL fetch inside a builder
// documented as native and offline would be an unauthenticated, unpinned network
// read whose bytes land in an image the cluster later executes.
//
// # Build-context containment
//
// Every COPY/ADD source is resolved through exactly one helper (see
// (*Context).Open) that applies, in order: a lexical filepath.Join + containment
// check, a resolved-vs-resolved EvalSymlinks re-check, and an O_NOFOLLOW open
// whose fd is then fstat'd and read with a cap. There is no second resolution
// site. An absolute source is interpreted RELATIVE TO THE CONTEXT ROOT (Docker
// parity) — never as a host path.
//
// Without this, "COPY ../../../../var/lib/k3sm/server/tls/cluster-ca.key /"
// would package the cluster CA private key into an image.
//
// # Determinism
//
// BuildLayer is the single home of the normalization that makes a layer digest a
// function of the CONTENT, not of the machine that built it. See the constant
// block there for the pinned fields. The emitted image config likewise fixes
// Created and every History entry's Created to the epoch, so a rebuild of the
// same context yields the same image digest.
//
// # Output sinks
//
// A Sink is where an assembled image is written. v1 ships two, both writing
// operator-owned paths as the invoking user:
//
//   - TarballSink — a docker-save tarball (`docker load`-compatible).
//   - LayoutSink  — an OCI image layout directory.
//
// Deliberately NOT shipped in v1, each for a recorded reason:
//
//   - The shared local store (/var/lib/k3sm). The store is _k3sm-owned 0750 and
//     the invoking operator is a different uid; the writer-uid contract is an
//     undecided product question (see docs/privilege-model.md). Under sudo a blob
//     commits root:wheel 0600, which the daemon can never read — while Cache.Has
//     (an os.Lstat) still reports it PRESENT, so CommitBlob short-circuits
//     forever. Because this builder's digests are deterministic by requirement,
//     re-running the identical build re-derives the identical digest and hits the
//     same poisoned path: the wedge is permanently self-reproducing.
//   - push. Registry upload and its invoking-user credential contract belong to
//     the `k3sm image` verb group, not here; implementing it in both places would
//     create two sites deciding credential precedence.
//   - FROM <ref>. Resolving a base means selecting a manifest from a possibly
//     multi-arch index and verifying its config platform — logic that already
//     exists, exported and hardened, in runtimed/pkg/image. Cutting it from v1
//     removes the base-pull surface, foreign-descriptor URLs inheritance, and the
//     ability to declare a platform the payload does not satisfy.
//   - .dockerignore. Not implemented; COPY . therefore includes .git and .env.
//     Documented in docs/user/images.md rather than worked around with a
//     hard-coded denylist, which would be a second invisible divergence.
//
// # This builder never signs
//
// Signing is a runtime, policy-gated, pre-exec decision made where the pod's
// SignaturePolicy is known (runtimed/pkg/runtime). A build-time ad-hoc signature
// would travel with the image and be indistinguishable at exec from a publisher's
// real one, moving the decision to a machine that does not know the policy — and
// `codesign -f` would mutate the operator's source tree in place.
package oci
