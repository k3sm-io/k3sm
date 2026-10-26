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

// Package zotchild carries the two-file wrapper module the registry builds the
// pinned zot from.
//
// The module requires nothing of its own: it declares upstream's
// zotregistry.dev/zot/v2/cmd/zot as a `tool` at DefaultZotVersion, so `go build
// zotregistry.dev/zot/v2/cmd/zot` inside it builds zot's own main package from
// zot's own module graph, with one change: the requirement raises of
// internal/childreq (golang.org/x/net v0.60.0) are required here too, and MVS
// selects them over the versions zot's tag pins. Nothing else moves; the
// registrysvc tests hold both facts against this go.mod.
//
// The files are embedded as text, not as go.mod/go.sum: a directory holding a go.mod
// is a nested module that //go:embed cannot reach into. go.sum.txt is the complete
// lockfile; the build runs with -mod=readonly, so every module is hash-checked
// against it before use. To regenerate both at a new pin, in an empty directory
// with GOWORK=off, GOTOOLCHAIN=local and GOFLAGS=-mod=mod: write "module
// k3sm.io/zot-child" and zot's go directive to go.mod, run `go get -tool
// zotregistry.dev/zot/v2/cmd/zot@<pin>`, then `go get` each childreq raise, then
// `go mod tidy`, and check with `go list -m all` that only the raised modules moved.
// Then vendor zot's own go.mod at the pin into pkg/registrysvc/testdata (from the
// module proxy, with the header TestZotWrapperGraphMatchesPinnedZot checks).
package zotchild

import _ "embed" // the wrapper files below

var (
	// GoMod is the wrapper's go.mod.
	//go:embed go.mod.txt
	GoMod []byte
	// GoSum is the wrapper's complete go.sum lockfile.
	//go:embed go.sum.txt
	GoSum []byte
)
