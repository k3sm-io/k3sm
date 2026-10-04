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

// Package etcdchild carries the three-file wrapper module the executor builds the
// pinned etcd server from.
//
// `go install go.etcd.io/etcd/server/v3@<pin>` cannot work: upstream's server/go.mod
// carries monorepo-relative replace directives, and `go install pkg@version` refuses
// any module that does. So the binary is built from a tiny module of our own that
// requires the server module at the pin and whose main is upstream's own
// server/main.go body (etcdmain.Main).
//
// The files are embedded as text, not as go.mod/main.go: a directory holding a go.mod
// is a nested module that //go:embed cannot reach into, and a .go file would be
// compiled into k3sm itself. go.sum.txt is the complete lockfile; the build runs with
// -mod=readonly, so every module is hash-checked against it before use. Regenerate
// all three with hack/etcd-wrapper.sh regen <version>.
package etcdchild

import _ "embed" // the wrapper files below

var (
	// GoMod is the wrapper's go.mod.
	//go:embed go.mod.txt
	GoMod []byte
	// GoSum is the wrapper's complete go.sum lockfile.
	//go:embed go.sum.txt
	GoSum []byte
	// MainGo is the wrapper's main.go: upstream's server/main.go, verbatim.
	//go:embed main.go.txt
	MainGo []byte
)
