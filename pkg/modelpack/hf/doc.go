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

// Package hf imports a Hugging Face Hub model repository at a pinned commit.
//
// It is the one Hub client in the tree, and everything it reads comes from
// the internet, so it is written fail-closed: every response has a size
// bound, every list a count bound, and anything it does not recognise (an
// entry type, a hash format, a status code, a redirect target, a header that
// contradicts the listing) refuses the import rather than being skipped.
//
// An import resolves the revision to its 40-hex commit once and names that
// commit in every later request; it lists the tree at the commit and checks
// every file name with the model rules (modelpack.CheckPaths) before
// downloading any byte, so a code or pickle file is refused by its name. Each
// file is downloaded into a fresh scratch directory, opened through an
// os.Root with O_NOFOLLOW, resumed with a Range request when a transfer
// breaks, and verified before anything is pushed: an LFS file by the sha256
// the listing names (which becomes its OCI layer digest), a small file by its
// git blob id, sha1("blob <len>\x00" + bytes). Redirects are followed only to
// https URLs on the Hub's own host or its published CDN hosts.
//
// Access is anonymous. A gated repository is refused by name. The hashes the
// Hub serves catch transport corruption, not a compromised origin: an import
// trusts the Hub on first use, and a caller that knows a file's sha256 from
// elsewhere passes it to be checked as well.
//
// The bounds, all checked before the bytes they bound are kept:
//
//   - the tree listing: 16 MiB across all pages, 100,000 entries, 128 pages;
//   - the revision answer: 1 MiB; an error body: 64 KiB read and discarded,
//     an error message header shown truncated to 200 printable bytes;
//   - response headers: 64 KiB; redirects: 5 per request;
//   - a file: 256 GiB (an LFS file), 64 MiB (a small, non-LFS file); the whole
//     repository: 1 TiB; files: what modelpack accepts (4096);
//   - a path: the artifact/v1 path rules; a repository id: 96 bytes a part;
//     a revision: 255 bytes;
//   - a transfer: 5 attempts per file, each resuming where the last stopped.
package hf
