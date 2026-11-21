//go:build ignore

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

// testresults applies the flake quarantine registry (hack/quarantine.txt) to a
// `go test -json` stream. It is a sanctioned copy of the shared k3sm quarantine
// rules: every k3sm repository carries its own copy so a lone clone can gate
// itself, and a change to the rules updates every copy in the same change.
// Every copy runs the shared cases in hack/lib/testdata/quarantine-corpus (see its
// README.md and DISAGREEMENTS.md); here TestQuarantineCorpusParity runs them.
//
// Usage:
//
//	go test -json ./... | testresults -tier fast|full [-registry hack/quarantine.txt] [-today YYYY-MM-DD] [<edited package>...]
//
// The positional arguments are the import paths the change edits directly. The
// registry is validated on every run. A failing test is excused only in the fast
// tier (`affected` is accepted as its other name), only when it is listed, its
// package is not an edited one, every run of it that failed carries the recorded
// signature, its output carries no race or sanitizer report, and its entry is not
// past its deadline. A test id repeated by -count>1 holds one run per result event;
// a passing run's output never satisfies the signature, and a run that started and
// never reported a result reds the id whatever its other runs did. A failing parent
// of a Go subtest that is not listed itself is excused only when it has a failing
// subtest, every failing subtest below it is excused, and its own output carries
// nothing but the harness's framing lines for it and its subtests. A race or
// sanitizer report in a package's output outside any test reds, whatever the
// registry lists. A registry sig that occurs in the test id or in the harness's
// RUN or FAIL line for that test is refused. The full tier reds on every failure.
//
// Exit status: 0 green with no failing test; 3 green because every failure was
// excused by the registry (so go test itself exited 1); 1 red; 2 usage.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	maxEntries  = 10
	minSigChars = 12
	exitGreen   = 0
	exitRed     = 1
	exitUsage   = 2
	exitExcused = 3
)

var requiredKeys = []string{"sig", "owner", "filed", "deadline", "fix", "reason"}

// raceMarkers mark a race or sanitizer report, which is never quarantinable.
var raceMarkers = []string{
	"WARNING: DATA RACE",
	"race detected during execution of test",
	"ThreadSanitizer",
	"AddressSanitizer",
	"UndefinedBehaviorSanitizer",
	"LeakSanitizer",
	"MemorySanitizer",
}

// Trust surfaces: never quarantined. Over-refusal is the safe direction.
var (
	protectedPathSegments    = [][2]string{{"pkg", "certs"}, {"pkg", "bootstrap"}, {"pkg", "rbac"}}
	protectedPackages        = []string{"k3sm.io/runtimed/pkg/image"} // where the signature policy is enforced
	protectedPackagePrefixes = []string{"K3smInstall"}
	protectedNameKeywords    = []string{"signaturepolicy", "sigpolicy", "cosign", "rbac", "k3sminstall"}
)

var (
	dateRE    = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	goIDRE    = regexp.MustCompile(`^([A-Za-z0-9._~\-]+(?:/[A-Za-z0-9._~\-]+)*)::(Test[A-Za-z0-9_]*|Example[A-Za-z0-9_]*|Fuzz[A-Za-z0-9_]*)((?:/\S+)?)$`)
	swiftIDRE = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)/([A-Za-z_][A-Za-z0-9_]*)/(\S+)$`)
	keyRE     = regexp.MustCompile(`(?s)^([a-z]+)=(.*)$`)
	// framingRE matches a line the test harness itself writes for a test: the
	// RUN/PAUSE/CONT/NAME markers and the PASS/FAIL/SKIP verdicts. Group 1 is the
	// test name it names.
	framingRE  = regexp.MustCompile(`^\s*(?:=== (?:RUN|PAUSE|CONT|NAME)|--- (?:PASS|FAIL|SKIP):)\s+(\S+)`)
	durationRE = regexp.MustCompile(`\(\d+(?:\.\d+)?s\)?\s*$`)
	spaceRE    = regexp.MustCompile(`\s+`)
)

// harnessReason reports why sig would match the harness's own lines for the test
// rather than its failure: it occurs in the test id, or in the RUN or FAIL line the
// harness writes for the test. Whitespace runs compare as one space and a trailing
// duration is ignored.
func harnessReason(test, name, sig string) string {
	norm := func(s string) string { return strings.TrimSpace(spaceRE.ReplaceAllString(s, " ")) }
	s := norm(durationRE.ReplaceAllString(sig, "("))
	if s == "" {
		return ""
	}
	if strings.Contains(test, s) || strings.Contains(test, norm(sig)) {
		return "the test id"
	}
	for _, h := range []string{"=== RUN " + name, "--- FAIL: " + name + " ("} {
		if strings.Contains(h, s) {
			return "the harness line " + strings.TrimSuffix(h, " (")
		}
	}
	return ""
}

// ownFailure returns the first line of a parent test's own output that is neither
// blank, nor harness framing for the parent or one of its subtests, nor a line of a
// subtest's output. Any such line may be a failure the parent reported itself.
func ownFailure(name, output string, kidOutputs []string) string {
	kidLines := map[string]bool{}
	for _, o := range kidOutputs {
		for _, l := range strings.Split(o, "\n") {
			kidLines[l] = true
		}
	}
	for _, l := range strings.Split(output, "\n") {
		if strings.TrimSpace(l) == "" || kidLines[l] {
			continue
		}
		if m := framingRE.FindStringSubmatch(l); m != nil && (m[1] == name || strings.HasPrefix(m[1], name+"/")) {
			continue
		}
		return l
	}
	return ""
}

type entry struct {
	line          int
	test, pkg     string
	sig, owner    string
	fix, deadline string
	deadlineDate  time.Time
}

type result struct {
	test       string
	status     string   // pass, fail, skip, or "" for no result
	output     string   // every run's output
	failedRuns []string // the output of each run that failed, one element per run
	run        string   // the output of the run in progress
	open       bool     // a run has started and has not reported a result
}

// carriedByEveryRun reports whether every failed run's output holds sig. No failed
// run means no recorded failure to match, so it reports false.
func carriedByEveryRun(runs []string, sig string) bool {
	for _, r := range runs {
		if !strings.Contains(r, sig) {
			return false
		}
	}
	return len(runs) > 0
}

func parseDate(s string) (time.Time, bool) {
	if !dateRE.MatchString(s) {
		return time.Time{}, false
	}
	t, err := time.Parse("2006-01-02", s)
	return t, err == nil
}

func splitTestID(test string) (pkg, name string, ok bool) {
	if m := goIDRE.FindStringSubmatch(test); m != nil {
		return m[1], m[2] + m[3], true
	}
	if strings.Contains(test, "::") {
		return "", "", false
	}
	if m := swiftIDRE.FindStringSubmatch(test); m != nil {
		return m[1], m[2] + "/" + m[3], true
	}
	return "", "", false
}

func raceMarker(text string) string {
	for _, m := range raceMarkers {
		if strings.Contains(text, m) {
			return m
		}
	}
	return ""
}

func protectedReason(pkg, name string) string {
	segs := strings.Split(pkg, "/")
	for _, pair := range protectedPathSegments {
		for i := 0; i+1 < len(segs); i++ {
			if segs[i] == pair[0] && segs[i+1] == pair[1] {
				return fmt.Sprintf("trust surface %s/%s", pair[0], pair[1])
			}
		}
	}
	for _, p := range protectedPackages {
		if pkg == p || strings.HasPrefix(pkg, p+"/") {
			return fmt.Sprintf("trust surface %s (signature policy)", p)
		}
	}
	for _, p := range protectedPackagePrefixes {
		if strings.HasPrefix(pkg, p) {
			return "trust surface " + p
		}
	}
	low := strings.ToLower(name)
	for _, k := range protectedNameKeywords {
		if strings.Contains(low, k) {
			return fmt.Sprintf("trust surface: test name names %q", k)
		}
	}
	return ""
}

// stripComment drops a `#` comment that starts the line or follows whitespace,
// outside quotes.
func stripComment(line string) string {
	var quote rune
	prevSpace := true
	for i, ch := range line {
		switch {
		case quote != 0:
			if ch == quote {
				quote = 0
			}
		case ch == '"' || ch == '\'':
			quote = ch
		case ch == '#' && prevSpace:
			return line[:i]
		}
		prevSpace = ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '\v' || ch == '\f'
	}
	return line
}

// shellSplit splits a line into words the way a POSIX shell lexer does: blanks
// separate words, single quotes are literal, double quotes allow \" and \\, and a
// backslash outside quotes escapes the next character.
func shellSplit(s string) ([]string, error) {
	var words []string
	var cur strings.Builder
	inWord := false
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		ch := rs[i]
		switch {
		case ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		case ch == '\\':
			if i+1 >= len(rs) {
				return nil, errors.New("no escaped character")
			}
			i++
			cur.WriteRune(rs[i])
			inWord = true
		case ch == '\'':
			j := i + 1
			for j < len(rs) && rs[j] != '\'' {
				j++
			}
			if j >= len(rs) {
				return nil, errors.New("no closing quotation")
			}
			cur.WriteString(string(rs[i+1 : j]))
			i = j
			inWord = true
		case ch == '"':
			j := i + 1
			for ; j < len(rs) && rs[j] != '"'; j++ {
				if rs[j] == '\\' && j+1 < len(rs) && (rs[j+1] == '"' || rs[j+1] == '\\') {
					j++
				}
				cur.WriteRune(rs[j])
			}
			if j >= len(rs) {
				return nil, errors.New("no closing quotation")
			}
			i = j
			inWord = true
		default:
			cur.WriteRune(ch)
			inWord = true
		}
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words, nil
}

// parseRegistry returns the valid entries and every error; any error makes the
// registry invalid.
func parseRegistry(text string) ([]entry, []string) {
	var entries []entry
	var errs []string
	seen := map[string]int{}
	listed := 0
	for n, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		lineno := n + 1
		line := strings.TrimSpace(stripComment(raw))
		if line == "" {
			continue
		}
		listed++
		where := fmt.Sprintf("line %d", lineno)
		toks, err := shellSplit(line)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: unparseable (%v)", where, err))
			continue
		}
		test, rest := toks[0], toks[1:]
		pkg, name, ok := splitTestID(test)
		if !ok {
			errs = append(errs, fmt.Sprintf("%s: %q is not a Go <import path>::<TestName> or Swift <Target>/<Suite>/<test> id", where, test))
			continue
		}
		fields := map[string]string{}
		bad := false
		for _, t := range rest {
			m := keyRE.FindStringSubmatch(t)
			if m == nil {
				errs = append(errs, fmt.Sprintf("%s: token %q is not key=value", where, t))
				bad = true
				continue
			}
			k, v := m[1], m[2]
			switch {
			case !contains(requiredKeys, k):
				errs = append(errs, fmt.Sprintf("%s: unknown key %q", where, k))
				bad = true
			case fields[k] != "":
				errs = append(errs, fmt.Sprintf("%s: key %q repeats", where, k))
				bad = true
			case strings.TrimSpace(v) == "":
				errs = append(errs, fmt.Sprintf("%s: key %q is empty", where, k))
				bad = true
			default:
				fields[k] = v
			}
		}
		var missing []string
		for _, k := range requiredKeys {
			if _, ok := fields[k]; !ok {
				missing = append(missing, k)
			}
		}
		if len(missing) > 0 {
			errs = append(errs, fmt.Sprintf("%s: missing %s", where, strings.Join(missing, ", ")))
			bad = true
		}
		if bad {
			continue
		}
		filed, okF := parseDate(fields["filed"])
		deadline, okD := parseDate(fields["deadline"])
		switch {
		case !okF:
			errs = append(errs, fmt.Sprintf("%s: filed=%q is not a YYYY-MM-DD date", where, fields["filed"]))
			continue
		case !okD:
			errs = append(errs, fmt.Sprintf("%s: deadline=%q is not a YYYY-MM-DD date", where, fields["deadline"]))
			continue
		case deadline.Before(filed):
			errs = append(errs, fmt.Sprintf("%s: deadline %s is before filed %s", where, fields["deadline"], fields["filed"]))
			continue
		case len([]rune(fields["sig"])) < minSigChars:
			errs = append(errs, fmt.Sprintf("%s: sig is shorter than %d characters, so it would match nearly any failure", where, minSigChars))
			continue
		}
		if rm := raceMarker(fields["sig"]); rm != "" {
			errs = append(errs, fmt.Sprintf("%s: refused, a race or sanitizer report is never quarantinable (sig carries %q)", where, rm))
			continue
		}
		if hr := harnessReason(test, name, fields["sig"]); hr != "" {
			errs = append(errs, fmt.Sprintf("%s: sig occurs in %s, so it matches the harness's own lines, not a failure (harness)", where, hr))
			continue
		}
		if pr := protectedReason(pkg, name); pr != "" {
			errs = append(errs, fmt.Sprintf("%s: refused, %s can never be quarantined (%s)", where, test, pr))
			continue
		}
		if prev, dup := seen[test]; dup {
			errs = append(errs, fmt.Sprintf("%s: %s is already listed on line %d", where, test, prev))
			continue
		}
		seen[test] = lineno
		entries = append(entries, entry{line: lineno, test: test, pkg: pkg, sig: fields["sig"], owner: fields["owner"],
			fix: fields["fix"], deadline: fields["deadline"], deadlineDate: deadline})
	}
	if listed > maxEntries {
		errs = append(errs, fmt.Sprintf("registry lists %d entries; at most %d are allowed", listed, maxEntries))
	}
	return entries, errs
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// evaluate returns whether the run is red, how many failures the registry
// excused, and the report lines.
func evaluate(registry string, results []result, tier string, edited []string, today time.Time) (red bool, excused int, lines []string) {
	entries, errs := parseRegistry(registry)
	for _, e := range errs {
		lines = append(lines, "RED registry: "+e)
		red = true
	}
	byID := map[string]entry{}
	for _, e := range entries {
		if e.deadlineDate.Before(today) {
			lines = append(lines, fmt.Sprintf("RED %s: quarantine expired %s (owner %s, fix %s)", e.test, e.deadline, e.owner, e.fix))
			red = true
		}
		byID[e.test] = e
	}
	editedSet := map[string]bool{}
	for _, p := range edited {
		editedSet[p] = true
	}
	// An unlisted failure's line is decided after every result is read, because
	// whether its subtests cover it is known only then.
	var out []string
	quarantined := map[string]bool{}
	type pending struct {
		idx  int
		test string
	}
	var unlisted []pending
	unlistedIDs := map[string]bool{}
	var failing []string
	outputs := map[string]string{}
	for _, r := range results {
		switch r.status {
		case "pass", "skip":
			if _, ok := byID[r.test]; ok {
				out = append(out, fmt.Sprintf("ok  %s: quarantined test %sed", r.test, r.status))
			}
			continue
		case "fail":
		default:
			out = append(out, fmt.Sprintf("RED %s: no result", r.test))
			red = true
			continue
		}
		failing = append(failing, r.test)
		outputs[r.test] = r.output
		e, listed := byID[r.test]
		if !listed {
			unlisted = append(unlisted, pending{len(out), r.test})
			unlistedIDs[r.test] = true
			out = append(out, "")
			continue
		}
		switch rm := raceMarker(r.output); {
		case rm != "":
			out = append(out, fmt.Sprintf("RED %s: failed with a race or sanitizer report (%q); quarantine never applies", r.test, rm))
			red = true
		case tier == "full":
			out = append(out, fmt.Sprintf("RED %s: quarantined test failed; the full tier reds on it (fix %s, deadline %s)", r.test, e.fix, e.deadline))
			red = true
		case editedSet[e.pkg]:
			out = append(out, fmt.Sprintf("RED %s: quarantined, but the change edits %s directly", r.test, e.pkg))
			red = true
		case !carriedByEveryRun(r.failedRuns, e.sig):
			out = append(out, fmt.Sprintf("RED %s: quarantined, but the failure does not match the recorded signature", r.test))
			red = true
		default:
			quarantined[r.test] = true
			excused++
			out = append(out, fmt.Sprintf("QUARANTINED %s: failed with its recorded signature; reported, not red (owner %s, fix %s, deadline %s)",
				r.test, e.owner, e.fix, e.deadline))
		}
	}
	// A failing Go subtest fails every parent above it, so an unlisted failing parent
	// is covered when it has a failing subtest and each failing subtest is quarantined,
	// or is itself an unlisted parent with a failing subtest below it. Never the
	// reverse: a listed parent covers no subtest, a parent failing with no failing
	// subtest stays red, and so does a parent whose own output carries any line
	// besides the harness's framing (it may have failed on its own as well), or a race
	// or sanitizer report. go test attributes each output line to the test it belongs
	// to (the Test field), so a parent's own t.Error lands in its output even after its
	// subtests ran. The blind spot: a parent that fails through t.Fail or t.FailNow with
	// no output line, or whose only line repeats a subtest's line verbatim, leaves
	// nothing to attribute and reads as covered.
	for _, u := range unlisted {
		if rm := raceMarker(outputs[u.test]); rm != "" {
			out[u.idx] = fmt.Sprintf("RED %s: failed with a race or sanitizer report (%q); quarantine never applies", u.test, rm)
			red = true
			continue
		}
		var kids []string
		for _, c := range failing {
			if strings.HasPrefix(c, u.test+"/") {
				kids = append(kids, c)
			}
		}
		covered := len(kids) > 0
		for _, c := range kids {
			if quarantined[c] {
				continue
			}
			inner := false
			if unlistedIDs[c] {
				for _, g := range kids {
					if strings.HasPrefix(g, c+"/") {
						inner = true
						break
					}
				}
			}
			if !inner {
				covered = false
				break
			}
		}
		own := ""
		if covered {
			var kidOut []string
			for _, c := range kids {
				kidOut = append(kidOut, outputs[c])
			}
			_, name, _ := strings.Cut(u.test, "::")
			own = ownFailure(name, outputs[u.test], kidOut)
		}
		if covered && own != "" {
			out[u.idx] = fmt.Sprintf("RED %s: failed; its own output carries %q beside its quarantined subtests", u.test, strings.TrimSpace(own))
			red = true
		} else if covered {
			var q []string
			for _, c := range kids {
				if quarantined[c] {
					q = append(q, c)
				}
			}
			out[u.idx] = fmt.Sprintf("QUARANTINED %s: failed only through quarantined subtests (%s); reported, not red", u.test, strings.Join(q, ", "))
		} else {
			out[u.idx] = fmt.Sprintf("RED %s: failed", u.test)
			red = true
		}
	}
	return red, excused, append(lines, out...)
}

// event is one `go test -json` line. ImportPath carries the build events.
type event struct {
	Action     string
	Package    string
	ImportPath string
	Test       string
	Output     string
}

// collector turns a go test -json stream into per-test results, echoing the
// output a non-verbose go test would print: package lines, and a test's output
// when it fails.
type collector struct {
	w          io.Writer
	tests      map[string]*result
	order      []string
	errs       []string
	pkgFail    map[string]bool
	pkgHasFail map[string]bool
	pkgOrder   []string
	pkgText    map[string]string // each package's output outside any test
	pkgSeen    []string          // packages in the order their output appeared
	buildFail  []string
	text       []string // every output line, for the summary
}

func newCollector(w io.Writer) *collector {
	return &collector{w: w, tests: map[string]*result{}, pkgFail: map[string]bool{}, pkgHasFail: map[string]bool{}, pkgText: map[string]string{}}
}

func (c *collector) line(n int, raw string) {
	if strings.TrimSpace(raw) == "" {
		return
	}
	var ev event
	if err := json.Unmarshal([]byte(raw), &ev); err != nil {
		c.errs = append(c.errs, fmt.Sprintf("line %d: not JSON", n))
		return
	}
	if ev.Package == "" && ev.ImportPath != "" && strings.HasPrefix(ev.Action, "build-") {
		// Build events (no Package): output is echoed; a failed build reds.
		c.text = append(c.text, ev.Output)
		fmt.Fprint(c.w, ev.Output)
		if ev.Action == "build-fail" {
			c.buildFail = append(c.buildFail, ev.ImportPath)
		}
		return
	}
	if ev.Package == "" || ev.Action == "" {
		c.errs = append(c.errs, fmt.Sprintf("line %d: event without Package/Action", n))
		return
	}
	if ev.Test == "" {
		if ev.Action == "output" {
			if _, ok := c.pkgText[ev.Package]; !ok {
				c.pkgSeen = append(c.pkgSeen, ev.Package)
			}
			c.pkgText[ev.Package] += ev.Output
			c.text = append(c.text, ev.Output)
			if ev.Output != "PASS\n" { // -json implies -v; a plain go test omits it
				fmt.Fprint(c.w, ev.Output)
			}
		}
		if ev.Action == "fail" {
			if !c.pkgFail[ev.Package] {
				c.pkgOrder = append(c.pkgOrder, ev.Package)
			}
			c.pkgFail[ev.Package] = true
		}
		return
	}
	id := ev.Package + "::" + ev.Test
	t := c.tests[id]
	if t == nil {
		t = &result{test: id}
		c.tests[id] = t
		c.order = append(c.order, id)
	}
	switch ev.Action {
	case "run":
		t.open = true
	case "output":
		t.output += ev.Output
		t.run += ev.Output
		t.open = true
		c.text = append(c.text, ev.Output)
	case "pass", "skip":
		// A fail is sticky per test id: with -count>1 or a rerun, a later pass or
		// skip of the same id never turns an earlier failure green.
		if t.status != "fail" {
			t.status = ev.Action
		}
		t.run, t.open = "", false
	case "fail":
		t.status = "fail"
		t.failedRuns = append(t.failedRuns, t.run)
		c.pkgHasFail[ev.Package] = true
		fmt.Fprint(c.w, t.run)
		t.run, t.open = "", false
	}
}

func (c *collector) results() []result {
	var rs []result
	for _, id := range c.order {
		r := *c.tests[id]
		if r.open { // the last run never reported, so this id has no result
			r.status = ""
		}
		rs = append(rs, r)
	}
	// A race or sanitizer report outside any test reds its package whatever else
	// failed in it, so a quarantined failure beside it never excuses it.
	raced := map[string]bool{}
	for _, p := range c.pkgSeen {
		if rm := raceMarker(c.pkgText[p]); rm != "" {
			raced[p] = true
			rs = append(rs, result{test: p + "::(package)", status: "fail", output: "package output carries a race or sanitizer report outside any test: " + rm})
		}
	}
	for _, p := range c.pkgOrder {
		if !c.pkgHasFail[p] && !raced[p] {
			rs = append(rs, result{test: p + "::(package)", status: "fail", output: "package failed outside any test"})
		}
	}
	for _, p := range c.buildFail {
		rs = append(rs, result{test: p + "::(build)", status: "fail", output: "build failed"})
	}
	return rs
}

var summaryRE = regexp.MustCompile(`^[ \t]*--- FAIL:|^FAIL[ \t]|^panic:`)

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("testresults", flag.ContinueOnError)
	fs.SetOutput(stderr)
	registryPath := fs.String("registry", "hack/quarantine.txt", "the quarantine registry; a missing file is an empty registry")
	tier := fs.String("tier", "", "fast (also: affected) or full")
	todayFlag := fs.String("today", "", "the date deadlines are judged against (YYYY-MM-DD; default today)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	switch *tier {
	case "fast", "affected":
		*tier = "fast"
	case "full":
	default:
		fmt.Fprintln(stderr, "testresults: -tier must be fast or full")
		return exitUsage
	}
	today := time.Now()
	today = time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, time.UTC)
	if *todayFlag != "" {
		d, ok := parseDate(*todayFlag)
		if !ok {
			fmt.Fprintln(stderr, "testresults: -today is not a YYYY-MM-DD date")
			return exitUsage
		}
		today = d
	}
	registry := ""
	b, err := os.ReadFile(*registryPath)
	switch {
	case err == nil:
		registry = string(b)
	case errors.Is(err, os.ErrNotExist):
	default:
		fmt.Fprintf(stdout, "RED registry %s unreadable: %v\n", *registryPath, err)
		return exitRed
	}

	c := newCollector(stdout)
	sc := bufio.NewScanner(stdin)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	n := 0
	for sc.Scan() {
		n++
		c.line(n, sc.Text())
	}
	if err := sc.Err(); err != nil {
		c.errs = append(c.errs, fmt.Sprintf("reading the stream: %v", err))
	}
	results := c.results()
	red, excused, lines := evaluate(registry, results, *tier, fs.Args(), today)
	for i := len(c.errs) - 1; i >= 0; i-- {
		lines = append([]string{"RED test stream: " + c.errs[i]}, lines...)
		red = true
	}
	if len(results) == 0 && len(c.errs) == 0 {
		lines = append(lines, "RED test stream holds no results")
		red = true
	}

	failed := 0
	for _, r := range results {
		if r.status == "fail" {
			failed++
		}
	}
	entries, _ := parseRegistry(registry)
	fmt.Fprintf(stdout, "==> test results: tier %s, %d tests, %d failed, %d quarantine entr%s\n",
		*tier, len(results), failed, len(entries), map[bool]string{true: "y", false: "ies"}[len(entries) == 1])
	if failed > 0 {
		fmt.Fprintln(stdout, "    failing tests:")
		var sum []string
		for _, t := range strings.Split(strings.Join(c.text, ""), "\n") {
			if summaryRE.MatchString(t) {
				sum = append(sum, "    "+t)
			}
		}
		if len(sum) == 0 {
			sum = []string{"    (no FAIL line; read the output above)"}
		}
		fmt.Fprintln(stdout, strings.Join(sum, "\n"))
	}
	races := strings.Count(strings.Join(c.text, ""), "WARNING: DATA RACE")
	if races > 0 {
		fmt.Fprintf(stdout, "    data races reported: %d\n", races)
	}
	for _, l := range lines {
		fmt.Fprintln(stdout, l)
	}
	switch {
	case red:
		fmt.Fprintln(stdout, "RED")
		return exitRed
	case excused > 0:
		fmt.Fprintf(stdout, "ok (%d failure%s excused by the registry)\n", excused, map[bool]string{true: "", false: "s"}[excused == 1])
		return exitExcused
	case failed > 0:
		// Failures exist but none was excused directly: they are parents covered by
		// excused subtests, which cannot happen without an excused subtest.
		fmt.Fprintln(stdout, "RED")
		return exitRed
	}
	fmt.Fprintln(stdout, "ok")
	return exitGreen
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
