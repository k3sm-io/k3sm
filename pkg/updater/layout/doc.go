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

// Package layout is the model of the versioned install tree the k3sm root
// updater activates releases in, and the pure decisions over it.
//
// The tree, relative to a root that is /Library/k3sm in production and a
// temporary directory in tests:
//
//	versions/<ver>/             one full binary set per release
//	current -> versions/<ver>   what the launchd jobs run
//	previous -> versions/<ver>  the rollback target
//	updater/current             the updater's own pointer, a link to a version
//	updater/guard/              a pinned known-good updater the guard job runs
//	updater-state/              swap marker, high-water mark, bad list, journal
//	updater-work/               archives copied in during staging
//	run/updater.sock            the updater's socket
//	trust/cluster-ca.crt        the cluster CA the updater trusts
//	status/update.json          the user-readable update status
//
// The package computes paths, validates version directory names, resolves the
// active version from a symlink read through an injected seam, plans the atomic
// flip of current and previous as a list of steps, checks the ownership of a
// directory and its ancestors through an injected stat, and states the frozen
// program arguments every k3sm launchd job runs with. It executes nothing: it
// creates no file, renames nothing and restarts no job. The caller carries out
// a plan.
//
// It is a leaf that imports only the standard library, so the updater can use
// it without the installer's launchd renderer or client-go, and the installer
// can import it too.
package layout
