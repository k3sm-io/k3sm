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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"k3sm.io/k3sm/internal/childreq"
	"k3sm.io/k3sm/pkg/registrysvc/zotchild"
)

// pinnedZotGoModPath names the vendored copy of zot's own go.mod at a pin.
func pinnedZotGoModPath(version string) string {
	return filepath.Join("testdata", "zot-"+version+".go.mod")
}

// vendoredHeaderSum matches the digest line of the vendored copy's header.
var vendoredHeaderSum = regexp.MustCompile(`sha256 of the fetched file: ([0-9a-f]{64})`)

// pinnedZotGoMod reads the vendored copy of zot's go.mod at version and returns
// the fetched file below its header, after checking it against the digest the
// header records (so the copy cannot be edited without the header saying so).
func pinnedZotGoMod(version string) (string, error) {
	b, err := os.ReadFile(pinnedZotGoModPath(version))
	if err != nil {
		return "", fmt.Errorf("read zot's go.mod at %s (fetch https://proxy.golang.org/zotregistry.dev/zot/v2/@v/%s.mod into %s): %w", version, version, pinnedZotGoModPath(version), err)
	}
	header, body, ok := strings.Cut(string(b), "\n\n")
	if !ok {
		return "", fmt.Errorf("%s has no header", pinnedZotGoModPath(version))
	}
	if !strings.Contains(header, "/zot/v2/@v/"+version+".mod") {
		return "", fmt.Errorf("%s does not name its source URL at %s", pinnedZotGoModPath(version), version)
	}
	m := vendoredHeaderSum.FindStringSubmatch(header)
	if m == nil {
		return "", fmt.Errorf("%s does not record the fetched file's sha256", pinnedZotGoModPath(version))
	}
	sum := sha256.Sum256([]byte(body))
	if got := hex.EncodeToString(sum[:]); got != m[1] {
		return "", fmt.Errorf("%s: the body's sha256 is %s, the header records %s", pinnedZotGoModPath(version), got, m[1])
	}
	return body, nil
}

// goModDirectives returns the directive keyword of every top-level and block
// directive in a go.mod ("require", "replace", "exclude", ...).
func goModDirectives(mod string) []string {
	var out []string
	for _, l := range strings.Split(mod, "\n") {
		f := strings.Fields(l)
		if len(f) == 0 || strings.HasPrefix(f[0], "//") || l[0] == '\t' || l[0] == ' ' || f[0] == ")" {
			continue
		}
		out = append(out, f[0])
	}
	return out
}

// zotWrapperGraphProblems compares the wrapper go.mod against zot's own go.mod at
// version: zot's module is required at version, every other require is at the
// version zot's go.mod pins it at, except a childreq raise at its raised version,
// and neither file carries a replace or exclude (zot's own would be ignored for
// the wrapper, so its graph would not be zot's). One line per problem.
func zotWrapperGraphProblems(wrapper, upstream, version string, raises []childreq.Requirement) []string {
	var problems []string
	for _, f := range []struct{ name, mod string }{{"the wrapper", wrapper}, {"zot's go.mod", upstream}} {
		for _, d := range goModDirectives(f.mod) {
			if d == "replace" || d == "exclude" {
				problems = append(problems, fmt.Sprintf("%s carries a directive: %s", f.name, d))
			}
		}
	}
	if !strings.HasPrefix(strings.TrimSpace(upstream), "module zotregistry.dev/zot/v2\n") {
		problems = append(problems, "zot's go.mod is not zotregistry.dev/zot/v2's")
	}
	raised := map[string]string{}
	for _, r := range raises {
		raised[r.Path] = r.Version
	}
	want := goModRequires(upstream)
	got := goModRequires(wrapper)
	paths := make([]string, 0, len(got))
	for p := range got {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	for _, p := range paths {
		v := got[p]
		switch {
		case p == "zotregistry.dev/zot/v2":
			if v != version {
				problems = append(problems, fmt.Sprintf("the wrapper requires zot at %s, the pin is %s", v, version))
			}
		case raised[p] != "":
			if v != raised[p] {
				problems = append(problems, fmt.Sprintf("the wrapper requires %s at %s, the raise is %s", p, v, raised[p]))
			}
		case want[p] == "":
			problems = append(problems, fmt.Sprintf("the wrapper requires %s %s, which zot %s does not", p, v, version))
		case want[p] != v:
			problems = append(problems, fmt.Sprintf("the wrapper requires %s at %s, zot %s pins %s", p, v, version, want[p]))
		}
	}
	return problems
}

// TestZotWrapperGraphMatchesPinnedZot holds the zotchild wrapper go.mod to zot's
// own graph at DefaultZotVersion (a vendored copy of zot's go.mod, read through
// the module proxy at that tag): every require matches zot's, the only allowed
// difference is the documented childreq raise, and no replace or exclude.
func TestZotWrapperGraphMatchesPinnedZot(t *testing.T) {
	upstream, err := pinnedZotGoMod(DefaultZotVersion)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range zotWrapperGraphProblems(string(zotchild.GoMod), upstream, DefaultZotVersion, childreq.Raises) {
		t.Error(p)
	}
}

// TestZotWrapperGraphProblems proves the comparison refuses each drift.
func TestZotWrapperGraphProblems(t *testing.T) {
	upstream := "module zotregistry.dev/zot/v2\n\ngo 1.27.0\n\nrequire (\n\tgithub.com/a/b v1.0.0\n\tgolang.org/x/net v0.59.0 // indirect\n)\n"
	raises := []childreq.Requirement{{Path: "golang.org/x/net", Version: "v0.60.0"}}
	good := "module k3sm.io/zot-child\n\ngo 1.27.0\n\ntool zotregistry.dev/zot/v2/cmd/zot\n\nrequire (\n\tgithub.com/a/b v1.0.0 // indirect\n\tgolang.org/x/net v0.60.0 // indirect\n\tzotregistry.dev/zot/v2 v2.1.22 // indirect\n)\n"
	cases := []struct {
		name, wrapper, upstream, want string
	}{
		{"matching graph", good, upstream, ""},
		{"moved module", strings.Replace(good, "a/b v1.0.0", "a/b v1.0.1", 1), upstream, "github.com/a/b at v1.0.1, zot v2.1.22 pins v1.0.0"},
		{"added module", strings.Replace(good, ")\n", "\tgithub.com/evil/x v0.1.0\n)\n", 1), upstream, "github.com/evil/x v0.1.0, which zot v2.1.22 does not"},
		{"x/net not at the raise", strings.Replace(good, "net v0.60.0", "net v0.61.0", 1), upstream, "golang.org/x/net at v0.61.0, the raise is v0.60.0"},
		{"zot off the pin", strings.Replace(good, "v2 v2.1.22", "v2 v2.1.21", 1), upstream, "zot at v2.1.21, the pin is v2.1.22"},
		{"wrapper replace", good + "\nreplace github.com/a/b => github.com/c/b v1.0.0\n", upstream, "the wrapper carries a directive: replace"},
		{"wrapper replace block", good + "\nreplace (\n\tgithub.com/a/b => ./b\n)\n", upstream, "the wrapper carries a directive: replace"},
		{"wrapper exclude", good + "\nexclude github.com/a/b v0.9.0\n", upstream, "the wrapper carries a directive: exclude"},
		{"upstream replace", good, upstream + "\nreplace github.com/a/b => ./b\n", "zot's go.mod carries a directive: replace"},
		{"another module", good, strings.Replace(upstream, "zotregistry.dev/zot/v2", "example.com/zot", 1), "is not zotregistry.dev/zot/v2's"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := strings.Join(zotWrapperGraphProblems(c.wrapper, c.upstream, "v2.1.22", raises), "\n")
			if c.want == "" && got != "" {
				t.Errorf("problems = %q, want none", got)
			}
			if c.want != "" && !strings.Contains(got, c.want) {
				t.Errorf("problems = %q, want one containing %q", got, c.want)
			}
		})
	}
}
