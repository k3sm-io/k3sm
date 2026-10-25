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

package registrysvc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"

	"k3sm.io/k3sm/internal/childreq"
	"k3sm.io/k3sm/pkg/registrysvc/zotchild"
)

// goModRequires returns the version each module is required at in a go.mod.
func goModRequires(mod string) map[string]string {
	out := map[string]string{}
	block := false
	for _, l := range strings.Split(mod, "\n") {
		t := strings.TrimSpace(l)
		switch {
		case t == "require (":
			block = true
			continue
		case block && t == ")":
			block = false
			continue
		}
		f := strings.Fields(t)
		if !block {
			if len(f) < 3 || f[0] != "require" {
				continue
			}
			f = f[1:]
		}
		if len(f) >= 2 {
			out[f[0]] = f[1]
		}
	}
	return out
}

// TestZotWrapperPins holds the embedded wrapper module to the pin and the raises:
// zot's main package is its one tool, zot's module is required at
// DefaultZotVersion, every childreq raise is required at its version, and go.sum
// carries the raise's checksum-database hashes, so the -mod=readonly build links
// exactly that graph.
func TestZotWrapperPins(t *testing.T) {
	mod, sum := string(zotchild.GoMod), string(zotchild.GoSum)
	if !strings.HasPrefix(mod, "module k3sm.io/zot-child\n") {
		t.Error("the wrapper's module path is not k3sm.io/zot-child")
	}
	if !slices.Contains(strings.Split(mod, "\n"), "tool "+zotModulePath) {
		t.Errorf("the wrapper declares no 'tool %s'", zotModulePath)
	}
	req := goModRequires(mod)
	if got := req["zotregistry.dev/zot/v2"]; got != DefaultZotVersion {
		t.Errorf("the wrapper requires zot at %q, want DefaultZotVersion %s", got, DefaultZotVersion)
	}
	for _, r := range childreq.Raises {
		if got := req[r.Path]; got != r.Version {
			t.Errorf("the wrapper requires %s at %q, want the raise %s", r.Path, got, r.Version)
		}
		for _, line := range []string{r.Path + " " + r.Version + " " + r.Sum, r.Path + " " + r.Version + "/go.mod " + r.GoModSum} {
			if !slices.Contains(strings.Split(sum, "\n"), line) {
				t.Errorf("the wrapper go.sum lacks %q", line)
			}
		}
	}
	if strings.Contains(mod, "\nreplace") || strings.Contains(mod, "\nexclude") {
		t.Error("the wrapper carries a replace or exclude directive")
	}
}

// zotRaiseHistory records every raise set by the zot variant that named it. It is
// APPEND-ONLY for the reason pkg/executor's kinePatchSetHistory is: a node whose
// marker names a variant never re-stages, so a variant cannot be reused for
// another graph.
var zotRaiseHistory = map[string]string{
	"minimal+r1": "118badbd2badbebcd23b7c427288073c0f3820e006593d19c09e7a7ab0d5d80e",
}

// zotRaiseDigest is the sha256 of childreq.Raises' content.
func zotRaiseDigest() string {
	h := sha256.New()
	for _, r := range childreq.Raises {
		for _, f := range []string{r.Path, r.Version, r.Sum, r.GoModSum} {
			h.Write([]byte(f))
			h.Write([]byte{0})
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// TestZotVariantNamesRaises pins the link between the raises and the staging
// marker: the raises cannot change without zotBuildVariant changing, or every node
// that staged the earlier zot would keep it.
func TestZotVariantNamesRaises(t *testing.T) {
	got := zotRaiseDigest()
	want, ok := zotRaiseHistory[zotBuildVariant]
	switch {
	case !ok:
		t.Errorf("zotBuildVariant %q has no zotRaiseHistory entry; add %q: %q", zotBuildVariant, zotBuildVariant, got)
	case want != got:
		t.Errorf("childreq.Raises changed (digest %s) but zotBuildVariant is still %q, which names %s: bump the \"+r<n>\" suffix and add the new pair to zotRaiseHistory", got, zotBuildVariant, want)
	}
	if len(childreq.Raises) > 0 && zotBuildVariant == "minimal" {
		t.Errorf("zotBuildVariant = %q with raises carried: the unraised builds' marker would vouch for this one", zotBuildVariant)
	}
}

// TestZotBuildArgs pins the build argv: zot's own main package, hash-checked
// against the wrapper's go.sum, with no host path in the binary.
func TestZotBuildArgs(t *testing.T) {
	args := zotBuildArgs("/out/zot")
	for _, want := range []string{"build", "-trimpath", "-buildvcs=false", "-mod=readonly", "/out/zot", zotModulePath} {
		if !slices.Contains(args, want) {
			t.Errorf("zotBuildArgs = %q, missing %q", args, want)
		}
	}
	if args[len(args)-1] != zotModulePath {
		t.Errorf("zotBuildArgs builds %q, want %q", args[len(args)-1], zotModulePath)
	}
}

// TestZotWrapperRefusesAnotherVersion pins that the wrapper builds only its pin:
// its go.sum locks exactly one zot, so another version is refused before any Go
// command runs.
func TestZotWrapperRefusesAnotherVersion(t *testing.T) {
	_, err := buildZotWrapper(context.Background(), "v2.1.20", t.TempDir(), t.TempDir())
	if !errors.Is(err, ErrZotVersionUnpinned) {
		t.Fatalf("buildZotWrapper(v2.1.20) = %v, want ErrZotVersionUnpinned", err)
	}
}
