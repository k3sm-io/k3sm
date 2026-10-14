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

package acceptance

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The spike and lab scripts run on real Macs, some of them as root. A script
// that pipes a download into a shell, or fetches an artifact and uses it
// without checking a digest, runs whatever the remote end serves that day.
// This gate holds every shell script under hack/spike/** and hack/lab* to two
// rules, over logical lines (backslash continuations joined, comment-only
// lines skipped):
//
//  1. no curl/wget piped into sh, bash, zsh or python*, unless every URL on
//     the line is a loopback one (127.0.0.1, localhost, [::1]);
//  2. a curl/wget that writes a file from a non-loopback URL (a URL held in a
//     variable counts as non-loopback) needs a sha256 check OF THAT FILE in
//     the same script: a line running `shasum -a 256 -c`, `sha256sum -c`, or
//     capturing a digest into a variable (`got=$(shasum -a 256 f ...)`) for
//     comparison, which names the download's output path (the -o/-O/redirect
//     target, literal or variable, as spelled at the download) as a whole
//     word. One check therefore never covers a second download. The helper
//     spike_fetch_pinned passes the same way: its curl and its check both
//     name "$dest", and its callers contain no curl at all;
//  3. `gh release download` is a download verb too. It must name each asset
//     it fetches (-p/--pattern, no glob characters) or write one file with
//     -O/--output, and each file it writes (the --dir/-D directory joined with
//     the pattern, or the pattern alone without --dir) must appear in a sha256
//     check as in rule 2. A gh download with no named asset, a glob pattern,
//     or --archive cannot be bound to a check and is a finding.
//
// A line carrying `# unpinned: <reason>` (on the line itself or the line
// directly above it) is exempt from both rules. The reason is required: a
// bare `# unpinned:` is itself a finding.

var (
	// fetchCmd finds curl or wget used as a command word.
	fetchCmd = regexp.MustCompile("(?:^|[\\s;&|(`\"'/])(curl|wget)(?:\\s|$)")
	// ghDownloadCmd finds `gh release download` used as a command.
	ghDownloadCmd = regexp.MustCompile("(?:^|[\\s;&|(`\"'/])gh\\s+release\\s+download(?:\\s|$)")
	// pipeToShell is a single pipe (not ||) into a shell or python, optionally
	// through sudo or env VAR=value assignments.
	pipeToShell = regexp.MustCompile(`[^|]\|\s*(?:sudo\s+)?(?:env\s+(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*)?(?:\S*/)?(?:sh|bash|zsh|python[0-9.]*)(?:["'\s;)]|$)`)
	urlRE       = regexp.MustCompile(`[a-z]+://[^\s"'|)]+`)
	// shaCheck is a digest verification: a -c/--check run, or a digest
	// captured into a variable for an explicit comparison.
	shaCheck = regexp.MustCompile(`(?:(?:shasum\s+-a\s*256|sha256sum)\b[^\n]*\s(?:-c|--check)\b|=\$\(\s*(?:shasum\s+-a\s*256|sha256sum)\b)`)
	// unpinnedRE matches the exemption marker; group 1 is the reason.
	unpinnedRE = regexp.MustCompile(`#\s*unpinned:(.*)$`)
	// redirectRE is a stdout redirect to something other than /dev/null.
	redirectRE = regexp.MustCompile(`(?:^|[^0-9&>])>{1,2}\s*([^\s&>]+)`)
	// shellShebang selects extensionless files run by sh, bash or zsh.
	shellShebang = regexp.MustCompile(`\b(?:ba|z)?sh\b`)
)

// logicalLine is one shell command line with its first physical line number.
type logicalLine struct {
	n    int
	text string
	prev string // the physical line directly above, for the marker
}

// logicalLines joins backslash-continued lines.
func logicalLines(src string) []logicalLine {
	phys := strings.Split(src, "\n")
	var out []logicalLine
	for i := 0; i < len(phys); i++ {
		start := i
		var b strings.Builder
		line := phys[i]
		for strings.HasSuffix(line, "\\") && i+1 < len(phys) {
			b.WriteString(strings.TrimSuffix(line, "\\"))
			b.WriteString(" ")
			i++
			line = phys[i]
		}
		b.WriteString(line)
		prev := ""
		if start > 0 {
			prev = phys[start-1]
		}
		out = append(out, logicalLine{n: start + 1, text: b.String(), prev: prev})
	}
	return out
}

// isLoopback reports whether rawURL names a loopback host literally.
func isLoopback(rawURL string) bool {
	rest := rawURL[strings.Index(rawURL, "://")+3:]
	if strings.HasPrefix(rest, "[") {
		end := strings.Index(rest, "]")
		return end > 0 && rest[1:end] == "::1"
	}
	host := rest
	if i := strings.IndexAny(host, ":/?#"); i >= 0 {
		host = host[:i]
	}
	return host == "127.0.0.1" || host == "localhost"
}

// allLoopback is true when s carries at least one URL and every URL is loopback.
func allLoopback(s string) bool {
	urls := urlRE.FindAllString(s, -1)
	if len(urls) == 0 {
		return false
	}
	for _, u := range urls {
		if !isLoopback(u) {
			return false
		}
	}
	return true
}

// downloadTarget reports whether the curl/wget command in seg (the text after
// the command word, up to the end of its pipeline stage) writes to a file, and
// the path it writes as spelled in the script (quotes stripped). A remote-name
// download (curl -O, wget without -O) targets the URL's last path segment. An
// empty target with writes set means the path could not be derived, so no
// check can be bound to it.
func downloadTarget(tool, seg string) (target string, writes bool) {
	if m := redirectRE.FindStringSubmatch(seg); m != nil && m[1] != "/dev/null" {
		return strings.Trim(m[1], `"'`), true
	}
	toks := strings.Fields(seg)
	outFlag := 'o'
	if tool == "wget" {
		outFlag = 'O'
	}
	remoteName := tool == "wget"
	for i, tok := range toks {
		var arg string
		switch {
		case tok == "--output" || tok == "--output-document":
			if i+1 < len(toks) {
				arg = toks[i+1]
			}
		case strings.HasPrefix(tok, "--output=") || strings.HasPrefix(tok, "--output-document="):
			arg = tok[strings.Index(tok, "=")+1:]
		case tok == "--remote-name" || tok == "--remote-name-all":
			if tool == "curl" {
				remoteName = true
			}
			continue
		case strings.HasPrefix(tok, "-") && !strings.HasPrefix(tok, "--") && len(tok) > 1:
			flags := tok[1:]
			if tool == "curl" && strings.ContainsRune(flags, 'O') {
				remoteName = true
				continue
			}
			j := strings.IndexRune(flags, outFlag)
			if j < 0 {
				continue
			}
			if j < len(flags)-1 {
				arg = flags[j+1:]
			} else if i+1 < len(toks) {
				arg = toks[i+1]
			}
		default:
			continue
		}
		arg = strings.Trim(arg, `"'`)
		if arg == "-" || arg == "/dev/null" || arg == "/dev/stdout" {
			remoteName = false
			continue
		}
		return arg, true
	}
	if !remoteName {
		return "", false
	}
	u := urlRE.FindString(seg)
	if u == "" {
		return "", true
	}
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		u = u[:i]
	}
	return u[strings.LastIndex(u, "/")+1:], true
}

// ghValueFlags are the gh release download flags that take a value.
var ghValueFlags = map[string]bool{
	"-p": true, "--pattern": true, "-D": true, "--dir": true, "-O": true, "--output": true,
	"-A": true, "--archive": true, "-R": true, "--repo": true,
}

// ghDownloadTargets parses the arguments of one `gh release download` stage
// and returns the files it writes, as spelled in the script (quotes
// stripped). bound is false when the download cannot be tied to named files:
// no pattern, a glob pattern, or --archive without -O. stdout is true for
// -O -, which writes no file.
func ghDownloadTargets(seg string) (targets []string, bound, stdout bool) {
	toks := strings.Fields(seg)
	var patterns []string
	var dir, output string
	archive := false
	for i := 0; i < len(toks); i++ {
		tok := toks[i]
		name, val, hasEq := strings.Cut(tok, "=")
		if !strings.HasPrefix(tok, "--") || !hasEq {
			name, val = tok, ""
			if ghValueFlags[tok] && i+1 < len(toks) {
				val = toks[i+1]
				i++
			}
		}
		val = strings.Trim(val, `"'`)
		switch name {
		case "-p", "--pattern":
			patterns = append(patterns, val)
		case "-D", "--dir":
			dir = val
		case "-O", "--output":
			output = val
		case "-A", "--archive":
			archive = true
		}
	}
	switch {
	case output == "-" || output == "/dev/stdout":
		return nil, true, true
	case output != "":
		return []string{output}, true, false
	case archive || len(patterns) == 0:
		return nil, false, false
	}
	for _, p := range patterns {
		if p == "" || strings.ContainsAny(p, "*?[") {
			return nil, false, false
		}
		if dir == "" || dir == "." {
			targets = append(targets, p)
		} else {
			targets = append(targets, strings.TrimSuffix(dir, "/")+"/"+p)
		}
	}
	return targets, true, false
}

// normVar spells ${name} as $name so either spelling binds to the other.
var normVar = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// pathChar reports whether c can continue a path or variable name, so a
// target matched next to one is part of a longer, different word.
func pathChar(c byte) bool {
	return c == '_' || c == '.' || c == '-' || c == '/' ||
		(c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// mentions reports whether line names target as a whole word.
func mentions(line, target string) bool {
	for off := 0; ; {
		i := strings.Index(line[off:], target)
		if i < 0 {
			return false
		}
		i += off
		j := i + len(target)
		if (i == 0 || !pathChar(line[i-1])) && (j == len(line) || !pathChar(line[j])) {
			return true
		}
		off = i + 1
	}
}

// stageAfter returns the text following the command word at idx, cut at the
// end of its pipeline stage.
func stageAfter(s string, idx int) string {
	rest := s[idx:]
	if j := strings.IndexAny(rest, "|;"); j >= 0 {
		rest = rest[:j]
	}
	if j := strings.Index(rest, "&&"); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// unchecked is the rule-2 finding.
const unchecked = "non-local download whose output is not sha256-checked in the script"

// unnamedAsset is the rule-3 finding for a gh download no check can bind to.
const unnamedAsset = "gh release download without an explicitly named asset"

// downloadFinding is one rule violation.
type downloadFinding struct {
	line int
	rule string
}

// scanDownloads applies both rules to one script's source. remote counts the
// non-loopback file-writing downloads seen (checked or not), so a caller can
// prove the scan saw the downloads it is meant to police.
func scanDownloads(src string) (findings []downloadFinding, remote int) {
	lines := logicalLines(src)
	var checks []string
	for _, ll := range lines {
		if shaCheck.MatchString(ll.text) {
			checks = append(checks, normVar.ReplaceAllString(ll.text, "$$$1"))
		}
	}
	checked := func(target string) bool {
		target = normVar.ReplaceAllString(target, "$$$1")
		if target == "" {
			return false
		}
		for _, c := range checks {
			if mentions(c, target) {
				return true
			}
		}
		return false
	}
	for _, ll := range lines {
		trimmed := strings.TrimSpace(ll.text)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}
		marker := unpinnedRE.FindStringSubmatch(ll.text)
		if marker == nil && strings.HasPrefix(strings.TrimSpace(ll.prev), "#") {
			marker = unpinnedRE.FindStringSubmatch(ll.prev)
		}
		if marker != nil {
			if strings.TrimSpace(marker[1]) == "" {
				findings = append(findings, downloadFinding{ll.n, "unpinned marker without a reason"})
			}
			continue
		}
		for _, loc := range ghDownloadCmd.FindAllStringIndex(ll.text, -1) {
			targets, bound, stdout := ghDownloadTargets(stageAfter(ll.text, loc[1]))
			if stdout {
				if pipeToShell.MatchString(ll.text[loc[0]:]) {
					findings = append(findings, downloadFinding{ll.n, "download piped into a shell"})
				}
				continue
			}
			remote++
			if !bound {
				findings = append(findings, downloadFinding{ll.n, unnamedAsset})
				continue
			}
			for _, t := range targets {
				if !checked(t) {
					findings = append(findings, downloadFinding{ll.n, unchecked})
				}
			}
		}
		locs := fetchCmd.FindAllStringSubmatchIndex(ll.text, -1)
		if len(locs) == 0 {
			continue
		}
		local := allLoopback(ll.text)
		if !local && pipeToShell.MatchString(ll.text[locs[0][2]:]) {
			findings = append(findings, downloadFinding{ll.n, "download piped into a shell"})
			continue
		}
		for _, loc := range locs {
			tool := ll.text[loc[2]:loc[3]]
			seg := stageAfter(ll.text, loc[3])
			if allLoopback(seg) {
				continue
			}
			target, writes := downloadTarget(tool, seg)
			if !writes {
				continue
			}
			remote++
			if !checked(target) {
				findings = append(findings, downloadFinding{ll.n, unchecked})
			}
		}
	}
	return findings, remote
}

// isShellScript selects the files the gate polices: *.sh, or a shell shebang.
func isShellScript(path string) bool {
	if strings.HasSuffix(path, ".sh") {
		return true
	}
	if filepath.Ext(path) != "" {
		return false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	first, _, _ := strings.Cut(string(b), "\n")
	return strings.HasPrefix(first, "#!") && shellShebang.MatchString(first)
}

// spikeScripts lists the shell scripts under hack/spike/** and hack/lab*.
func spikeScripts(t *testing.T) []string {
	t.Helper()
	hack := filepath.Join(repoRoot(t), "hack")
	roots := []string{filepath.Join(hack, "spike")}
	labs, err := filepath.Glob(filepath.Join(hack, "lab*"))
	if err != nil {
		t.Fatalf("glob hack/lab*: %v", err)
	}
	roots = append(roots, labs...)
	var out []string
	for _, root := range roots {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && isShellScript(p) {
				out = append(out, p)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	return out
}

func TestSpikeScriptsVerifyDownloads(t *testing.T) {
	t.Run("fixtures", func(t *testing.T) {
		cases := []struct {
			name string
			src  string
			want []string // the rule of each expected finding, in order
		}{
			{"curl piped to sh", "curl -LsSf https://example.com/install.sh | sh\n", []string{"download piped into a shell"}},
			{"curl piped to env sh", `curl -LsSf https://example.com/i.sh | env DIR="$P/bin" sh` + "\n", []string{"download piped into a shell"}},
			{"curl piped to sh -s", "curl -sSf https://example.com/r | sh -s -- -y\n", []string{"download piped into a shell"}},
			{"wget piped to bash", "wget -qO- https://example.com/i | bash\n", []string{"download piped into a shell"}},
			{"curl piped to sudo zsh", "curl -fsSL https://example.com/i | sudo zsh\n", []string{"download piped into a shell"}},
			{"curl piped to python3", "curl -fsSL https://example.com/get.py | python3 -\n", []string{"download piped into a shell"}},
			{"continued pipe", "curl -fsSL \\\n  https://example.com/i.sh \\\n  | bash\n", []string{"download piped into a shell"}},
			{"guarded pipe", "command -v uv || curl -LsSf https://example.com/uv.sh | sh >/dev/null 2>&1\n", []string{"download piped into a shell"}},
			{"curl -o unchecked", "curl -fsSL -o k.gz https://example.com/k.gz\n", []string{unchecked}},
			{"curl -O unchecked", "curl -fsSLO https://example.com/k.gz\n", []string{unchecked}},
			{"curl variable url unchecked", `curl -fsSL -o "$D/k" "$URL"` + "\n", []string{unchecked}},
			{"curl redirect unchecked", "curl -fsSL https://example.com/k > k\n", []string{unchecked}},
			{"wget default unchecked", "wget https://example.com/k.gz\n", []string{unchecked}},
			{"continued -o unchecked", "curl -fsSL \\\n  -o k.gz \\\n  https://example.com/k.gz\n", []string{unchecked}},
			{"echo of a digest is not a check", "curl -fsSL -o k https://example.com/k\necho \"sha: $(shasum -a 256 k)\"\n", []string{unchecked}},
			{"second download unchecked", "curl -fsSL -o k https://example.com/k\necho \"$SHA  k\" | shasum -a 256 -c -\ncurl -fsSL -o other https://example.com/other\n", []string{unchecked}},
			{"check names a different file", "curl -fsSL -o k https://example.com/k\necho \"$SHA  j\" | shasum -a 256 -c -\n", []string{unchecked}},
			{"capture of a different file", "curl -fsSL -o k https://example.com/k\ngot=$(shasum -a 256 other | awk '{print $1}')\n", []string{unchecked}},
			{"longer variable is not the target", "curl -fsSL -o \"$dest\" \"$url\"\necho \"$want  $destination\" | shasum -a 256 -c -\n", []string{unchecked}},
			{"suffix path is not the target", "curl -fsSL -o k.gz https://example.com/k.gz\necho \"$want  old-k.gz\" | shasum -a 256 -c -\n", []string{unchecked}},
			{"remote name without a url", "curl -fsSLO \"$URL\"\necho \"$S  k.gz\" | shasum -a 256 -c -\n", []string{unchecked}},
			{"empty unpinned marker", "curl -fsSL https://example.com/i | sh # unpinned:\n", []string{"unpinned marker without a reason"}},
			{"gh download with no check", `gh release download v1 --repo o/r --pattern kubectl --dir "$D"` + "\n", []string{unchecked}},
			{"gh check names a different asset", `gh release download v1 --repo o/r --pattern kubectl --dir "$D"` + "\n" + `echo "$S  $D/kube-apiserver" | shasum -a 256 -c -` + "\n", []string{unchecked}},
			{"gh check names the asset outside the dir", `gh release download v1 -p kubectl -D "$D"` + "\n" + `echo "$S  kubectl" | shasum -a 256 -c -` + "\n", []string{unchecked}},
			{"gh dir download with no pattern", `gh release download v1 --repo o/r --dir "$BIN" --clobber` + "\n", []string{unnamedAsset}},
			{"gh download of every asset", "gh release download v1 --repo o/r\n", []string{unnamedAsset}},
			{"gh glob pattern", `gh release download v1 --pattern '*.tar.gz' --dir "$D"` + "\n" + `echo "$S  $D/*.tar.gz" | shasum -a 256 -c -` + "\n", []string{unnamedAsset}},
			{"gh archive download", "gh release download v1 --archive zip\n", []string{unnamedAsset}},
			{"gh second pattern unchecked", `gh release download v1 -p a -p b -D "$D"` + "\n" + `echo "$S  $D/a" | shasum -a 256 -c -` + "\n", []string{unchecked}},
			{"gh piped to sh", "gh release download v1 -p i.sh -O - | sh\n", []string{"download piped into a shell"}},
			{"empty unpinned marker above", "# unpinned:   \ncurl -fsSL -o k https://example.com/k\n", []string{"unpinned marker without a reason"}},

			{"loopback pipe to python", `curl -s "http://127.0.0.1:$port/v1/models" | "$V/bin/python" -c 'print(1)'` + "\n", nil},
			{"localhost file", "curl -s -o out.json http://localhost:8080/x\n", nil},
			{"ipv6 loopback file", "curl -s -o out.json http://[::1]:8080/x\n", nil},
			{"discard output", `curl -fsS -m 3 -o /dev/null "$URL"` + "\n", nil},
			{"capture to variable", `OUT=$(curl -fsS -m 60 "http://$IP/v1/x" -H 'a: b')` + "\n", nil},
			{"or-or is not a pipe", "curl -fsS https://example.com/x >/dev/null || sh -c 'exit 1'\n", nil},
			{"pipe to shasum is not a shell", "curl -fsSL https://example.com/x | shasum -a 256\n", nil},
			{"checked with -c", "curl -fsSL -o k https://example.com/k\necho \"$SHA  k\" | shasum -a 256 -c -\n", nil},
			{"checked with sha256sum --check", "curl -fsSL -o k https://example.com/k\necho \"$SHA  k\" | sha256sum --check\n", nil},
			{"remote name checked", "curl -fsSLO https://example.com/d/k.gz\necho \"$S  k.gz\" | shasum -a 256 -c -\n", nil},
			{"variable target checked", "curl -fsSL -o \"$dest\" \"$url\"\nprintf '%s  %s\\n' \"$want\" \"$dest\" | shasum -a 256 -c -\n", nil},
			{"braced variable target checked", "curl -fsSL -o \"${dest}\" \"$url\"\necho \"$want  $dest\" | shasum -a 256 -c -\n", nil},
			{"helper call is not a download", "spike_fetch_pinned \"$URL\" \"$SHA\" \"$D/k\"\n", nil},
			{"checked by capture", "curl -fsSL -o k \"$URL\"\ngot=$(shasum -a 256 k | awk '{print $1}')\n[ \"$got\" = \"$want\" ]\n", nil},
			{"unpinned marker with reason", "curl -fsSL https://example.com/i | sh # unpinned: vendor publishes no checksum\n", nil},
			{"unpinned marker above with reason", "# unpinned: moving nightly, no published digest\ncurl -fsSL -o k https://example.com/k\n", nil},
			{"gh pattern in dir checked", `gh release download "$TAG" --repo o/r --pattern "$asset" --dir "$STAGE" --clobber` + "\n" + `printf '%s  %s\n' "$want" "$STAGE/$asset" | shasum -a 256 -c -` + "\n", nil},
			{"gh short flags checked", "gh release download v1 -R o/r -p kubectl -D \"${D}\"\ngot=$(shasum -a 256 \"$D/kubectl\" | awk '{print $1}')\n", nil},
			{"gh pattern without dir checked", "gh release download v1 --pattern=kubectl\necho \"$S  kubectl\" | shasum -a 256 -c -\n", nil},
			{"gh output file checked", "gh release download v1 -p k -O out.bin\necho \"$S  out.bin\" | shasum -a 256 -c -\n", nil},
			{"gh unpinned marker with reason", "# unpinned: moving nightly, no published digest\ngh release download v1 --dir d\n", nil},
			{"comment line", "# curl -fsSL https://example.com/i | sh\n", nil},
			{"preflight probe", "command -v curl >/dev/null || { echo \"curl not found\"; missing=1; }\n", nil},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got, _ := scanDownloads(tc.src)
				var rules []string
				for _, f := range got {
					rules = append(rules, f.rule)
				}
				if strings.Join(rules, "\n") != strings.Join(tc.want, "\n") {
					t.Fatalf("scanDownloads(%q) = %q, want %q", tc.src, rules, tc.want)
				}
			})
		}
	})

	t.Run("tree", func(t *testing.T) {
		scripts := spikeScripts(t)
		if len(scripts) == 0 {
			t.Fatal("no shell scripts found under hack/spike or hack/lab*; the gate would be vacuous")
		}
		root := repoRoot(t)
		remote := 0
		for _, p := range scripts {
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("read %s: %v", p, err)
			}
			findings, n := scanDownloads(string(b))
			remote += n
			rel, _ := filepath.Rel(root, p)
			for _, f := range findings {
				t.Errorf("%s:%d: %s", rel, f.line, f.rule)
			}
		}
		// The tree carries several pinned artifact fetches (guest kernels,
		// rootfs tarballs, toolchain installers). Seeing none means the
		// detector has stopped recognising them, not that they are gone.
		if remote < 4 {
			t.Errorf("saw %d non-local file downloads across %d scripts, want at least 4; the detector is not seeing the downloads it polices", remote, len(scripts))
		}
	})
}
