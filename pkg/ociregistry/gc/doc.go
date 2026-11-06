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
// What it reaps, once an object is older than the grace period:
// untagged manifests that no kept index names, a referrer (one that carries a
// subject) among them only when its subject is not kept, so a referrer whose
// subject is gone does not hold its repository. A referrer pushed before its
// subject (signed, then copied) is protected only by the grace period, and
// when a tag moves, the old digest's referrers are reaped with it once it is
// past the grace. A referrer whose subject digest does not parse is kept;
// blobs no kept manifest references; upload sessions not written within the
// grace; and the layout of an empty repository. It also reaps, at any age,
// two kinds of leftovers a crash makes: an upload session whose inode a commit
// linked into blobs/ before it could remove the session (a second link, which
// the store's session check refuses, so a cancel cannot), and a .tmp-<uuid>
// link a blob replacement left before its rename, in .temps or, from an earlier
// build, among the blobs. A temp link is never counted as a blob.
//
// Protection is on disk. Every mount, link and upload commit touches the
// shared blob inode's mtime under the repository's lock, so age is the time
// since the last write that named the blob, and it survives a restart. A sweep
// marks each repository from a snapshot without the lock, reading, verifying
// and parsing every manifest body it follows there, then takes the repository
// lock to delete: it re-reads index.json and re-states the repository,
// recomputes what is reachable from the bodies the mark read, and deletes only
// what both passes agree on. The lock is held for no manifest read. When the
// rows, or a manifest the mark read, changed in between, it deletes nothing
// and marks the repository again; one that keeps changing is skipped with
// ErrChanged. Upload sessions are reaped only after taking their own lock
// without waiting, so a session an upload holds is never touched.
//
// Three brakes bound the damage of a mistake. No sweep runs within one grace
// period of the collector's start, so a write made just before a restart has
// had its full grace. Review is per repository: the registry-state/gc-ran
// marker names the repositories a report-only sweep has reviewed, and a sweep
// only reports on any other, listing what it would reap. A repository joins the
// marker from a sweep that planned it with no brake stopping it, so one that
// is braked or fails, for any reason and for however long, holds no other
// repository, and once it can be planned it reports before it deletes. One the
// marker already names stays named through a brake or a failure. A name
// that leaves the store leaves the marker. A sweep that reviews nothing writes
// no marker over a store with none. The marker records the store id, a random
// 128-bit id the store keeps in its root (store.IDFile) and writes with the
// first marker, and a marker for another id, or an older one with no reviewed
// set, names no repository. A root restored from a backup taken before the id
// existed, even into the same directory, gets a new id and so a report-only
// sweep again; a backup or copy that carries the id file is the same store. A
// restore merged over a live root keeps the id and is not told apart from a
// push, in the repositories the marker names (see markerRecord). A sweep that
// would delete more than half of a repository's blobs stops with ErrMassDelete.
// While a row stays, only the blobs the rows describe count, on both sides of the
// half: each row's manifest and every digest in a manifest body the sweep read.
// A blob outside them is one no image in the repository uses, so blobs a pusher
// uploads beside a tagged image cannot hold the brake; they go by the grace rule.
// The brake does not stop the sweep when it
// empties the repository (it leaves no row and every blob it reaps is older
// than the last change to the rows) or the repository is an abandoned first
// push. The emptying rule does not free a first push's blobs while they are
// newer than its index, but any later write to the rows (another tag pushed
// or deleted in the repository) advances index.json past them, and from then
// on the brake does not tell them from what a removed image left. The grace
// period, not the brake, is what guards a push's blobs. A plan that leaves no row
// but names a blob not older than index.json, such as one a repository sharing its
// inode touched after the delete, does not stop: it reaps the blobs older than
// index.json and leaves that one out, unless that leaves it nothing to remove, as a
// first push's does. Removing rows moves index.json, so the next sweep reaps what
// was left out. With no rows to remove, it waits for the abandon horizon.
// A repository with no rows whose index.json,
// blobs and upload sessions have all gone unwritten for the abandon horizon
// (AbandonFactor grace periods unless Options.Abandon says otherwise) is an
// abandoned first push: the brake no longer applies to it, and its blobs are
// reaped by the grace rule, so it does not stop every sweep for ever.
// Anything the collector cannot read (a manifest body that is missing, does
// not parse, or is not an OCI or Docker v2 image manifest, index or manifest
// list, such as a Docker schema1 manifest or any body with a schema1 fsLayers
// field) stops that repository's sweep: it never deletes on a guess. The server
// refuses at PUT whatever Readable refuses, so a pusher cannot store such a row.
// A blob an index names as a child, with no row, stops the sweep too when it
// fails its hash. One over the size cap is no manifest, since the server neither
// stores nor serves one that large, so it is kept as a blob, not read, and stops
// nothing, whatever media type the index gives it. If it verifies but the strict
// read refuses it, it does not stop the sweep: it may be a blob or an older
// manifest, so it is kept along with every digest its JSON holds, and those
// digests are followed through whatever bodies the store has for them (see
// makePlan). One of those over the size cap or failing its hash is kept and stops
// nothing.
package gc
