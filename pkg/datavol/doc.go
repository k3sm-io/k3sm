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

// Package datavol owns the lifecycle of the APFS volume k3sm's data root lives
// on: creating it, adopting one that already exists, migrating a plain data
// root onto it, mounting it at boot, and deleting it.
//
// It is the ONE home of every diskutil, security and mdutil command line k3sm
// runs, and of the two extended-attribute and marker-file mechanisms that
// stand in for tmutil. Nothing else in the tree shells out to those tools, so the
// argv of a privileged command is reviewable in one file (darwin.go) and
// fakeable at one seam (the Volumes, Keychain and Indexing interfaces in
// seams.go, with datavoltest.Fake as the single exported double).
//
// # The two-declaration rule
//
// A volume this package creates or adopts is declared twice: by the k3sm
// record (pkg/dataroot.Record, written only after a verified mount) and by an
// /etc/fstab line written on creation and kept on adoption. pkg/dataroot reads
// either. The pair is what makes rolling back to an older k3sm safe, and the
// reason EnsureFstabLine exists at all -- one declaration would be enough for
// this binary and not enough for the previous one. See pkg/dataroot's package
// comment for why the record is trustworthy as a source.
//
// # The quota is set once, at creation
//
// APFS has no verb that changes a volume's quota after the fact: diskutil apfs
// addVolume takes -quota, and nothing else does. So Ensure verifies the quota
// actually landed (diskutil apfs list reports it back as CapacityQuota) and
// deletes the volume it just made when it did not. A record that claims a
// bound the volume does not have would reproduce the very lie the feature
// exists to end -- the user docs have long said a separate volume "bounds"
// capacity, which was untrue while k3sm set no quota. Resizing means creating
// a new volume and copying; that is a documented operator procedure, not an
// operation here.
//
// # Keeping the data root out of Spotlight and Time Machine
//
// Neither exclusion goes through the obvious tool, because on a nobrowse
// volume neither tool works. Spotlight is turned off by writing an empty
// .metadata_never_index at the volume root, which every volume honours,
// because Spotlight does not track a nobrowse volume at all and `mdutil -i
// off` therefore fails with "unknown indexing state" (mdutil is still run
// afterwards, and that one answer is treated as success). Time Machine is
// excluded by setting the com.apple.metadata:com_apple_backup_excludeItem
// extended attribute directly -- the same thing `tmutil addexclusion` writes
// -- because tmutil itself is gated behind Full Disk Access and exits 80 even
// as root, so it cannot be called from a LaunchDaemon.
//
// # Passphrases
//
// An encrypted volume's passphrase is 32 bytes from crypto/rand, hex-encoded,
// and it reaches every tool on STDIN: diskutil takes -stdinpassphrase, and
// security reads a whole command line from stdin under -i. No code path in
// this package puts a passphrase in an argv, because Endpoint Security agents
// on managed Macs log every exec's argv centrally.
package datavol
