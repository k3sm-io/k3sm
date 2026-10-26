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

// Package registryclient is a small, read-only, anonymous client for the OCI
// distribution API, written for one consumer: `k3sm image ls` and `k3sm image
// df`, which list what the cluster's registry holds.
//
// It speaks exactly the reads those verbs need: the catalog, a repository's tag
// list, a manifest or index by tag or digest, and a config blob (the only place
// a single-platform image records its platform). It never writes, never sends a
// credential, and follows a pagination link only on the host it was given.
//
// It is written in the repository rather than imported because the slice is
// narrow: four GET endpoints, the Link pagination header and two manifest
// shapes. Every body it reads is size-bounded and every manifest is re-hashed
// against the digest it was asked for or the one the registry reported, so a
// registry that answers with different bytes than it names is an error, not a
// listing.
package registryclient
