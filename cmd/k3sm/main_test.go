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

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	_ "unsafe" // for go:linkname: the bootstrap work factors below

	"github.com/google/go-containerregistry/pkg/name"
	"golang.org/x/crypto/bcrypt"

	"k3sm.io/k3sm/pkg/bootstrap"
)

// The bootstrap package's two deliberate work factors: the bcrypt cost every
// bootstrap secret and node-password hash is minted at, and the PBKDF2 count a
// CA bundle is sealed at. They are unexported vars that pkg/bootstrap's own
// TestMain lowers for its tests; this package's join, enroll and node-password
// tests drive the same paths, so they name the vars here, in a test file only,
// and lower them the same way. The go:linkname below lives in a _test.go file,
// which never compiles into the shipped binary, so no shipped code writes either.
//
// Assumption: each directive is a pull-linkname of a non-std, module-internal
// unexported var, which Go 1.23+'s -checklinkname allows.
// TestShippedBootstrapWorkFactors is the check that the binding holds under the
// current toolchain.
//
//go:linkname bootstrapHashCost k3sm.io/k3sm/pkg/bootstrap.hashCost
var bootstrapHashCost int

//go:linkname bootstrapBundleSealIters k3sm.io/k3sm/pkg/bootstrap.bundleSealIters
var bootstrapBundleSealIters int

// bundleMinSealIters is the lowest PBKDF2 count bootstrap.OpenBundle accepts
// (bootstrap's bundleMinPBKDF2Iters); TestMain seals at it.
const bundleMinSealIters = 1_000

// shippedBundleSealIters is bootstrap's bundlePBKDF2Iters, the count a shipped
// server seals the CA bundle at. A mirror of the pin in pkg/bootstrap's own
// TestMain.
const shippedBundleSealIters = 600_000

// The work factors as the package initializers left them. TestMain captures them
// as its first act, after every init has run, so TestShippedBootstrapWorkFactors
// pins what a shipped binary uses rather than what a test lowered.
var (
	capturedHashCost        int
	capturedBundleSealIters int
)

// TestMain lowers the bootstrap work factors to their minimums for this
// package's tests. Under the race detector one DefaultCost bcrypt hash or compare
// takes about a second and one 600k-iteration bundle derivation about two, and
// the join and node-password tests pay several per case. No test here measures
// a work factor's cost.
func TestMain(m *testing.M) {
	capturedHashCost, capturedBundleSealIters = bootstrapHashCost, bootstrapBundleSealIters
	bootstrapHashCost = bcrypt.MinCost
	bootstrapBundleSealIters = bundleMinSealIters
	// No test reads this Mac's installed server: a server Mac's published
	// registry record would otherwise steer every push test to its gate.
	installedServerWorkDir = filepath.Join(os.TempDir(), fmt.Sprintf("k3sm-test-no-install-%d", os.Getpid()), "server")
	// No pull test copies an image to a real cluster registry: one that is
	// about the copy installs its own fake.
	pullMirrorer = func(context.Context, name.Reference, name.Reference, string) error {
		return errors.New("this test installed no cluster-registry mirrorer")
	}
	os.Exit(m.Run())
}

// TestShippedBootstrapWorkFactors checks the linkname binding and the defaults.
// That a shipped binary has no writer of either work factor is true by
// construction (the linkname lives in a _test.go file), not something this test
// proves. What it proves: the defaults captured in TestMain before lowering are
// bcrypt.DefaultCost and the shipped seal count, and the linkname bound the
// live variables, so bootstrap.HashCost() and a fresh SealBundle envelope read
// the lowered values rather than a stale copy.
func TestShippedBootstrapWorkFactors(t *testing.T) {
	if capturedHashCost != bcrypt.DefaultCost {
		t.Errorf("shipped bcrypt cost = %d, want bcrypt.DefaultCost (%d)", capturedHashCost, bcrypt.DefaultCost)
	}
	if capturedBundleSealIters != shippedBundleSealIters {
		t.Errorf("shipped bundle seal iterations = %d, want %d", capturedBundleSealIters, shippedBundleSealIters)
	}
	if got := bootstrap.HashCost(); got != bcrypt.MinCost {
		t.Errorf("bootstrap.HashCost() = %d under test, want the lowered bcrypt.MinCost (%d)", got, bcrypt.MinCost)
	}
	// The envelope header records the count it was sealed at, big-endian, after
	// the magic, version and KDF id bytes.
	env, err := bootstrap.SealBundle("work-factor-probe-secret", []byte("probe"))
	if err != nil {
		t.Fatalf("SealBundle: %v", err)
	}
	if len(env) < 10 {
		t.Fatalf("sealed envelope is %d bytes, too short for a header", len(env))
	}
	if got := int(binary.BigEndian.Uint32(env[6:10])); got != bundleMinSealIters {
		t.Errorf("SealBundle sealed at %d iterations under test, want the lowered %d", got, bundleMinSealIters)
	}
}
