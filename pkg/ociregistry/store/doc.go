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

// Package store reads and writes the registry's on-disk store: exactly the
// layout zot v2 leaves, so a store written here is one zot serves and the
// reverse.
//
// Under the root (<work-dir>/registry) each repository is an OCI image layout
// in the directory its name maps to (pkg/ociregistry/ref), nested by name
// component: oci-layout, index.json, blobs/<algorithm>/<hex> for every blob and
// every manifest body, and .uploads/<uuid> for upload sessions, each a plain
// file whose length is its offset. Tags are org.opencontainers.image.ref.name
// annotations on index.json rows, one row per (digest, tag); a manifest pushed
// by digest, an index's child among them, is an untagged row. Files are 0600
// and directories 0700, as zot makes them.
//
// zot's cache.db and meta.db stay in the root, never read, written or deleted,
// so a rollback finds them. A blob already present in another repository is
// shared by hardlink, never copied, and a blob file is never modified once in
// place: a link that would replace one keeps the existing file instead
// (link-or-keep), because the inode is shared across repositories. "Keep"
// is verified: an existing destination is kept only after its content hashes
// to the blob's digest. One that does not is replaced by a link of the
// verified source under a temp name in the same directory and a rename over
// it, so the bad inode is left unchanged for whoever else links it. A link is
// made by path only after re-checking that the path still names the inode
// that was hashed, and every upload session operation re-checks, after taking
// the session's flock, that the path names the opened inode and that inode has
// a single link; a session committed or cancelled meanwhile is gone, so a
// late chunk can never reach a published blob.
//
// Writes are durable in order: a blob is F_FULLFSYNCed before it is linked
// into blobs/, and index.json is written to a temp file under .uploads,
// F_FULLFSYNCed, renamed over and its directory synced, always after the blobs
// it names. index.json is rewritten under a per-repository flock in the state
// directory (<work-dir>/registry-state/locks), which holds across processes.
// The state directory is outside the root: nothing the store writes in the root
// is anything but the layout's own files, and the store id (IDFile), a random
// 128-bit id the garbage collector's first-sweep marker is bound to, which
// EnsureID writes once, atomically, the first time it is asked for.
//
// For garbage collection (pkg/ociregistry/gc), every mount, link and upload
// commit runs under the same repository lock and touches the blob inode's
// mtime there, so a blob's age is the time since a write last named it, on
// disk, across restarts. TouchBlob, which a blob HEAD calls, does the same
// for a blob a client found present and will name in a manifest. Session files are created under that lock too, and
// a write into a repository whose layout GC removed recreates it first. The
// lock-holding view GC deletes through is Locked (WithLock).
//
// Every path is resolved through ref, and a symlink anywhere inside the store is
// refused.
package store
