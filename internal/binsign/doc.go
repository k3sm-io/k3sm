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

// Package binsign is k3sm's one code-signing entry point for the binaries it
// stages: the control plane, kine, etcd, helm and zot, and the dev pod and exec
// shims. Its rule: a binary that is, or may be, mapped by a running process is
// never written in place. macOS caches a Mach-O's signature per vnode, so
// `codesign -f` on a live file (or any in-place rewrite) leaves the kernel holding
// the old signature, and every process that maps the file afterwards is killed
// with Code Signature Invalid. So signing happens on a temp copy that is then
// renamed over the target (atomicfile.InstallReader), and a binary whose signature
// already verifies is not touched at all.
package binsign
