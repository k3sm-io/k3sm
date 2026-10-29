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

// Package helmchild carries the wrapper module the pinned helm is built from.
//
// helm is built from helm.sh/helm/v4 at the pin rather than taken from the
// upstream release tarball, so it is compiled with the toolchain k3sm pins for
// every source-built child and links the dependency versions k3sm chooses. The
// wrapper requires helm at the pin, raises golang.org/x/net past the release
// helm's own go.mod names, and declares helm.sh/helm/v4/cmd/helm as a `tool`,
// so `go build helm.sh/helm/v4/cmd/helm` inside it builds upstream's own main
// from that one module graph.
//
// The files are embedded as text, not as go.mod/go.sum: a directory holding a
// go.mod is a nested module that //go:embed cannot reach into. go.sum.txt is the
// complete lockfile; the build runs with -mod=readonly, so every module is
// hash-checked against it before use. Regenerate both by writing go.mod.txt's
// requirements into a scratch go.mod and running `go mod tidy` there under the
// payload toolchain.
package helmchild

import _ "embed" // the wrapper files below

var (
	// GoMod is the wrapper's go.mod.
	//go:embed go.mod.txt
	GoMod []byte
	// GoSum is the wrapper's complete go.sum lockfile.
	//go:embed go.sum.txt
	GoSum []byte
)
