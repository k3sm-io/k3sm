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

package version

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// corpusTag is one line of testdata/release-tags.txt.
type corpusTag struct {
	tag       string
	canonical bool
}

// readCorpus reads testdata/release-tags.txt.
func readCorpus(t *testing.T) []corpusTag {
	t.Helper()
	data, err := os.ReadFile("testdata/release-tags.txt")
	if err != nil {
		t.Fatal(err)
	}
	var tags []corpusTag
	for line := range strings.Lines(string(data)) {
		if f := strings.Fields(line); len(f) == 2 && !strings.HasPrefix(f[0], "#") {
			tags = append(tags, corpusTag{tag: f[1], canonical: f[0] == "canonical"})
		}
	}
	if len(tags) == 0 {
		t.Fatal("the corpus has no tags")
	}
	return tags
}

// publishPlan runs publish.sh --plan, which reads only its argument and answers
// before the script's refusal of an unattended run.
func publishPlan(t *testing.T, tag string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := exec.Command("bash", filepath.Join("..", "..", "hack", "release", "publish.sh"), "--plan", tag)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err = cmd.Run()
	return o.String(), e.String(), err
}

// TestReleaseTagReaders holds every reader of the release tag grammar in this
// repository, and the app's Swift when its checkout can be found, to one corpus.
// A reader that drifts wider would let a tag be cut and signed that a channel then
// refuses, and a tag is never reused.
func TestReleaseTagReaders(t *testing.T) {
	corpus := readCorpus(t)
	t.Run("go", func(t *testing.T) {
		for _, c := range corpus {
			if got := CanonicalTag(c.tag); got != c.canonical {
				t.Errorf("CanonicalTag(%q) = %v, corpus says canonical=%v", c.tag, got, c.canonical)
			}
		}
	})
	t.Run("publish.sh", func(t *testing.T) {
		// What a line-based corpus cannot carry goes first; the shell's $ must not
		// match before a trailing newline.
		for _, tag := range []string{"v0.3.0\n", "\nv0.3.0", "v0.3.0\nv0.3.1", " v0.3.0", "v0.3.0 "} {
			if _, stderr, err := publishPlan(t, tag); err == nil || !strings.Contains(stderr, "REFUSE: non-canonical-tag") {
				t.Errorf("publish.sh --plan %q: err=%v stderr=%q, want the non-canonical-tag refusal", tag, err, stderr)
			}
		}
		for _, c := range corpus {
			stdout, stderr, err := publishPlan(t, c.tag)
			switch {
			case c.canonical && err != nil:
				t.Errorf("publish.sh --plan %q refused a canonical tag: %v: %s", c.tag, err, stderr)
			case c.canonical && !strings.HasPrefix(stdout, "tag="+c.tag+"\n"):
				t.Errorf("publish.sh --plan %q printed %q", c.tag, stdout)
			case !c.canonical && (err == nil || !strings.Contains(stderr, "REFUSE: non-canonical-tag")):
				t.Errorf("publish.sh --plan %q: err=%v stderr=%q, want the non-canonical-tag refusal", c.tag, err, stderr)
			}
		}
	})
	t.Run("swift", func(t *testing.T) { testSwiftReaders(t, corpus) })
}

// TestPublishPlan pins what a release of each kind would publish. A candidate is
// never promoted latest, carries no stable index and no index alias.
func TestPublishPlan(t *testing.T) {
	const image = "image_alias=k3sm_darwin_arm64.dmg\n"
	tests := []struct{ tag, want string }{
		{"v0.3.0-rc.1", "tag=v0.3.0-rc.1\nlatest=--latest=false\nstable_index=no\nindex_alias=none\n" + image},
		{"v0.2.9-rc.1", "tag=v0.2.9-rc.1\nlatest=--latest=false\nstable_index=no\nindex_alias=none\n" + image},
		{"v0.3.0", "tag=v0.3.0\nlatest=--latest\nstable_index=yes\nindex_alias=k3sm_release-index.p7m\n" + image},
		{"v0.2.9", "tag=v0.2.9\nlatest=--latest\nstable_index=no\nindex_alias=none\n" + image},
	}
	for _, tt := range tests {
		got, stderr, err := publishPlan(t, tt.tag)
		if err != nil {
			t.Errorf("publish.sh --plan %s: %v: %s", tt.tag, err, stderr)
		}
		if got != tt.want {
			t.Errorf("publish.sh --plan %s = %q, want %q", tt.tag, got, tt.want)
		}
	}
}

// Where the app holds the grammar. The app cannot import this repository and this
// repository cannot import the app, so these are read from its checkout:
// K3SM_APP_DIR when set, else the sibling ../app.
const (
	swiftPlan    = "Sources/K3smStatus/UpdatePlan.swift"
	swiftVersion = "Sources/K3smStatus/Version.swift"
	swiftApp     = "Sources/K3smStatus/AppVersion.swift"
	swiftRoll    = "Sources/K3smInstall/BundledRoll.swift"
	appPayload   = "hack/release/payload-release.sh"
)

// swiftDriverSource is a program over the app's two Swift readers, lifted verbatim:
// it prints, for each line of its input, the two verdicts.
const swiftDriverSource = `import Foundation

enum BundledRollSupport {
%s
}

enum AppVersion {
%s
}

while let line = readLine() {
    print(BundledRollSupport.isReleaseTag(line), AppVersion.releaseTagVersion(line) != nil)
}
`

// swiftFunc lifts one function from Swift source by its signature line, up to the
// brace that closes it.
func swiftFunc(src, signature string) (string, error) {
	start := strings.Index(src, signature)
	if start < 0 {
		return "", fmt.Errorf("no %q", signature)
	}
	depth := 0
	for i := start; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[start : i+1], nil
			}
		}
	}
	return "", fmt.Errorf("%q does not close", signature)
}

// testSwiftReaders compiles and runs the app's own functions over the corpus, and
// checks the pattern its Swift renders into a script and its payload-release.sh.
// With no K3SM_APP_DIR and no
// sibling checkout it skips, since this repository builds alone; a caller who names
// a checkout asked for the check, so a missing one or a missing compiler fails.
func testSwiftReaders(t *testing.T, corpus []corpusTag) {
	named := os.Getenv("K3SM_APP_DIR")
	app := named
	if app == "" {
		app = filepath.Join("..", "..", "..", "app")
	}
	unavailable := func(format string, args ...any) {
		t.Helper()
		if named != "" {
			t.Fatalf(format, args...)
		}
		t.Skipf(format+"; set K3SM_APP_DIR to require it", args...)
	}
	read := func(rel string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(app, rel))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				unavailable("the app's %s is not at %s", rel, app)
			}
			t.Fatal(err)
		}
		return string(data)
	}
	planSrc, appSrc, rollSrc := read(swiftPlan), read(swiftApp), read(swiftRoll)
	_ = read(appPayload)
	swiftc, err := exec.LookPath("swiftc")
	if err != nil {
		unavailable("no swiftc on PATH: %v", err)
	}

	pat := regexp.MustCompile(`tagPattern = #"(.*)"#`).FindStringSubmatch(rollSrc)
	if pat == nil {
		t.Fatalf("no tagPattern in %s", swiftRoll)
	}
	shell, err := regexp.Compile(pat[1])
	if err != nil {
		t.Fatalf("%s tagPattern: %v", swiftRoll, err)
	}

	isTag, err := swiftFunc(planSrc, "public static func isReleaseTag(_ tag: String) -> Bool {")
	if err != nil {
		t.Fatalf("%s: %v", swiftPlan, err)
	}
	tagVersion, err := swiftFunc(appSrc, "public static func releaseTagVersion(_ tag: String) -> SemanticVersion? {")
	if err != nil {
		t.Fatalf("%s: %v", swiftApp, err)
	}
	dir := t.TempDir()
	main := filepath.Join(dir, "main.swift")
	if err := os.WriteFile(main, fmt.Appendf(nil, swiftDriverSource, isTag, tagVersion), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "readers")
	if out, err := exec.Command(swiftc, "-o", bin, main, filepath.Join(app, swiftVersion)).CombinedOutput(); err != nil {
		t.Fatalf("compiling the app's readers: %v\n%s", err, out)
	}

	var input strings.Builder
	for _, c := range corpus {
		input.WriteString(c.tag + "\n")
	}
	cmd := exec.Command(bin)
	cmd.Stdin = strings.NewReader(input.String())
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("running the app's readers: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) != len(corpus) {
		t.Fatalf("the app's readers answered %d lines for %d tags", len(lines), len(corpus))
	}
	for i, c := range corpus {
		want := fmt.Sprintf("%t %t", c.canonical, c.canonical)
		if lines[i] != want {
			t.Errorf("%q: isReleaseTag, releaseTagVersion = %s, corpus says canonical=%v", c.tag, lines[i], c.canonical)
		}
		if got := shell.MatchString(c.tag); got != c.canonical {
			t.Errorf("%q: BundledRollPlan.tagPattern = %v, corpus says canonical=%v", c.tag, got, c.canonical)
		}
		// check-tag also binds the tag to its core version, so a canonical tag is
		// asked with its own and a refused one with the one it would claim.
		core := strings.TrimPrefix(strings.SplitN(c.tag, "-", 2)[0], "v")
		err := exec.Command("bash", filepath.Join(app, appPayload), "check-tag", c.tag, core).Run()
		if got := err == nil; got != c.canonical {
			t.Errorf("%q: payload-release.sh check-tag = %v, corpus says canonical=%v", c.tag, got, c.canonical)
		}
	}
}
