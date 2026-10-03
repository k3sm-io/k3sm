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

// Package shadow names the node's shadow binary set: ad-hoc re-signed copies of
// the host shells, tar and the common coreutils that `sudo k3sm install` makes
// under <InstallDir>/shadow, and the manifest that records which host binary
// each copy was made from. The members come from runtimed's shadowset list,
// the one declaration the runtime's exec swap also reads.
//
// Why the copies exist: dyld drops DYLD_INSERT_LIBRARIES for a restricted
// process (a platform binary, CS_RESTRICT, the hardened runtime), so a pod
// that starts through /bin/sh loses the DNS and path-rebase shims for the shell
// and everything it runs. An ad-hoc re-signed copy of the same binary is not
// restricted and keeps them; runtimed runs the copy in place of the host binary
// (runtime.Config.ShadowBinDir). The copies are root-owned and never writable
// by the daemon user, and they are made only by the privileged installer.
//
// Why the manifest exists: a macOS update replaces the host binaries, and
// the copies then lag the host until the next install. The manifest records
// each source's cdhash so `k3sm status` can compare it with the live binary and
// say "run sudo k3sm install" on drift, and so it can tell a set made by an
// older install (one that lists fewer copies) from a current one.
//
// This package is the one home of the set as k3sm consumes it, the manifest
// encoding, the cdhash read and the made-copy verification; pkg/install
// writes, pkg/status reads, and cmd/k3sm resolves the directory for the node
// daemon.
package shadow
