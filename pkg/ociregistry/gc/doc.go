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

// Package gc is the registry's online garbage collector: it reaps what no
// tag reaches from a store that is serving pushes at the same time, and never
// deletes something a push in flight still needs.
//
// What it reaps, as zot does, once an object is older than the grace period:
// untagged manifests that no kept index names and that carry no subject;
// blobs no kept manifest references; upload sessions not written within the
// grace; and the layout of an empty repository. It also reaps, at any age,
// two kinds of leftovers a crash makes: an upload session whose inode a commit
// linked into blobs/ before it could remove the session (a second link, which
// the store's session check refuses, so a cancel cannot), and a .tmp-<uuid>
// link a blob replacement left before its rename. A temp link is never counted
// as a blob.
//
// Protection is on disk. Every mount, link and upload commit touches the
// shared blob inode's mtime under the repository's lock, so age is the time
// since the last write that named the blob, and it survives a restart. A sweep
// marks each repository from a snapshot without the lock, then takes the
// repository lock to delete: it re-reads index.json and re-states every
// candidate, recomputes what is reachable, and deletes only what both passes
// agree on. Upload sessions are reaped only after taking their own lock
// without waiting, so a session an upload holds is never touched.
//
// Three brakes bound the damage of a mistake. No sweep runs within one grace
// period of the collector's start, so a write made just before a restart has
// had its full grace. The first sweep over a store without the
// registry-state/gc-ran marker only reports what it would reap, then writes
// the marker. A sweep that would delete more than half of a repository's
// blobs stops with ErrMassDelete, unless the repository has no rows left
// because its manifests were deleted. Anything the collector cannot read
// (a manifest body that is missing or does not parse) stops that
// repository's sweep: it never deletes on a guess.
package gc
