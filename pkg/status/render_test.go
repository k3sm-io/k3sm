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

package status

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/version"
)

// goldenTime, goldenVersion and goldenHost pin everything about a rendered
// report that would otherwise change between runs, so the goldens capture the
// LAYOUT and the WORDS and nothing else.
var (
	goldenTime    = time.Date(2026, 9, 5, 9, 30, 0, 0, time.UTC)
	goldenVersion = version.Info{Version: "v0.1.1", KubeVersion: "v1.36.2", KineVersion: "v1.14.2"}
)

const goldenHost = "26.1"

// report assembles a Report from rows exactly as Collect does — through
// Aggregate — so a golden can never show a summary or a Next block the real
// command would not produce.
func report(rows []Row, installed bool) Report {
	return roleReport(rows, installed, dataroot.RoleServer)
}

// roleReport is report for a Mac whose installed role is not the default: the
// same assembly, with the role the screens pick their rows from.
func roleReport(rows []Row, installed bool, role dataroot.Role) Report {
	v, summary, next := Aggregate(rows, installed, role)
	return Report{
		Verdict:   v,
		Role:      role,
		Summary:   summary,
		Rows:      rows,
		Next:      next,
		Version:   goldenVersion,
		Host:      goldenHost,
		Timestamp: goldenTime,
	}
}

// crashLoopServerRow is the server row of a Mac whose control plane will not
// start, log line and all.
func crashLoopServerRow() Row {
	r := serverRow(StateCrashLoop, SeverityFail, "497 runs, last exit 1",
		"sudo launchctl kickstart -k system/io.k3sm.server\nk3sm status logs server")
	r.Wide = map[string]string{
		"label":       "io.k3sm.server",
		"log":         `level=ERROR msg="control plane exited" err="listen tcp 127.0.0.1:6444: bind: address already in use"`,
		"log-repeats": "497",
	}
	return r
}

// goldenReports are the six screens the goldens pin: one per verdict, plus the
// two stopped shapes that send an operator to different places.
func goldenReports() map[string]Report {
	notMounted := replace(healthyRows(), crashLoopServerRow())
	notMounted = replace(notMounted, row(RowDataRoot, StateNotMounted, SeverityFail,
		"declared in /etc/fstab (apfs) but nothing is mounted there; a shadow directory (uid 0) holds run",
		"sudo rm -r /var/lib/k3sm/run && sudo diskutil mount -mountPoint /var/lib/k3sm <volume>   # the shadow holds only the netd socket\nsudo launchctl kickstart -k system/io.k3sm.netd && sudo launchctl kickstart -k system/io.k3sm.server"))

	unknown := []Row{
		row(RowInstall, StateOK, SeverityOK, "/Library/k3sm/k3sm · launcher /usr/local/bin/k3sm · 2 LaunchDaemons in /Library/LaunchDaemons", ""),
		row(RowNetd, StateUnknown, SeverityUnknown, "launchctl reported a state this build cannot read", "sudo k3sm status"),
		serverRow(StateUnknown, SeverityUnknown, "launchctl reported a state this build cannot read", "sudo k3sm status"),
		row(RowAPIServer, StateUnknown, SeverityUnknown, "no kubeconfig: no k3sm context in ~/.kube/config", "sudo k3sm install"),
		row(RowNode, StateUnknown, SeverityUnknown, "apiserver unreachable", ""),
		row(RowWorkloads, StateUnknown, SeverityUnknown, "apiserver unreachable", ""),
		row(RowDataRoot, StateUnknown, SeverityUnknown, "the data root was not probed", ""),
		row(RowDatastore, StateUnknown, SeverityUnknown, "state.db not readable as this user (re-run with sudo)", "sudo k3sm status"),
		row(RowKubeconfig, StateMissing, SeverityUnknown, "no k3sm context in ~/.kube/config", "k3sm kubeconfig --write"),
		row(RowRuntimed, StateUnknown, SeverityUnknown, "needs sudo (socket is owner-only)", ""),
	}

	return map[string]Report{
		"render_running.txt": report(healthyRows(), true),
		"render_stopped_crashloop.txt": report(replace(
			replace(healthyRows(), crashLoopServerRow()),
			row(RowAPIServer, StateDown, SeverityFail, "https://127.0.0.1:6444: connection refused",
				"sudo launchctl kickstart -k system/io.k3sm.server\nk3sm status logs server")), true),
		"render_stopped_not_mounted.txt": report(notMounted, true),
		"render_degraded.txt": report(replace(healthyRows(),
			row(RowKubeconfig, StateMissing, SeverityWarn, "no k3sm context in ~/.kube/config", "k3sm kubeconfig --write")), true),
		"render_not_installed.txt": report([]Row{
			row(RowInstall, StateAbsent, SeverityFail, "no k3sm install found on this Mac", "sudo k3sm install"),
			row(RowNetd, StateNotLoaded, SeverityFail, "io.k3sm.netd is not loaded in the system domain", "sudo k3sm install"),
			serverRow(StateNotLoaded, SeverityFail, "io.k3sm.server is not loaded in the system domain", "sudo k3sm install"),
			row(RowAPIServer, StateUnknown, SeverityUnknown, "no kubeconfig: no k3sm context in ~/.kube/config", "sudo k3sm install"),
		}, false),
		"render_unknown.txt": report(unknown, true),
	}
}

// TestRenderGoldens pins the plain screen byte for byte. The goldens are
// hand-reviewed files, not regenerated output: the whole point of this test is
// that a change to a row's wording or to the column layout has to be looked at
// by a human, which an --update flag would quietly remove.
func TestRenderGoldens(t *testing.T) {
	t.Parallel()
	for name, rep := range goldenReports() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			want, err := os.ReadFile(filepath.Join("testdata", name))
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}
			if got := Render(rep, Style{}); got != string(want) {
				t.Errorf("render mismatch for %s:\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
			}
		})
	}
}

// TestRenderContent asserts the load-bearing parts of the screen independently of
// the golden bytes, so a reviewed golden update cannot silently drop the verdict
// line, the cause of a stoppage, the quoted crash log, or the Next block.
func TestRenderContent(t *testing.T) {
	t.Parallel()
	reports := goldenReports()

	t.Run("running names the verdict and offers one non-repair next step", func(t *testing.T) {
		t.Parallel()
		out := Render(reports["render_running.txt"], Style{})
		if !strings.HasPrefix(out, "k3sm running: 1/1 nodes ready") {
			t.Errorf("first line is not the verdict line:\n%s", firstLine(out))
		}
		if !strings.Contains(out, "\nNext: k3sm kubectl get pods -A\n") {
			t.Errorf("healthy screen does not offer the one next step:\n%s", out)
		}
		if strings.Contains(out, "sudo") {
			t.Errorf("healthy screen suggests a repair:\n%s", out)
		}
	})

	t.Run("a crash loop names the cause and quotes the log once", func(t *testing.T) {
		t.Parallel()
		out := Render(reports["render_stopped_crashloop.txt"], Style{})
		for _, must := range []string{
			"k3sm stopped: io.k3sm.server is crash-looping (497 runs, last exit 1)",
			"log: level=ERROR",
			"(×497)",
			"Next: sudo launchctl kickstart -k system/io.k3sm.server",
			"      k3sm status logs server",
		} {
			if !strings.Contains(out, must) {
				t.Errorf("crash-loop screen missing %q:\n%s", must, out)
			}
		}
		if strings.Count(out, "log: level=ERROR") != 1 {
			t.Errorf("the crash log line is printed more than once:\n%s", out)
		}
	})

	t.Run("an unmounted data root spells out the mount recipe", func(t *testing.T) {
		t.Parallel()
		out := Render(reports["render_stopped_not_mounted.txt"], Style{})
		for _, must := range []string{
			"data-root   not-mounted",
			"declared in /etc/fstab",
			"sudo diskutil mount -mountPoint /var/lib/k3sm <volume>",
		} {
			if !strings.Contains(out, must) {
				t.Errorf("not-mounted screen missing %q:\n%s", must, out)
			}
		}
	})

	t.Run("every screen carries the provenance and every row's state word", func(t *testing.T) {
		t.Parallel()
		for name, rep := range reports {
			out := Render(rep, Style{})
			if !strings.Contains(out, "v0.1.1 · kube v1.36.2 · macOS 26.1") {
				t.Errorf("%s: provenance missing:\n%s", name, out)
			}
			for _, r := range rep.Rows {
				if r.Name == RowRuntimed {
					continue // deliberately not on the overview screen
				}
				if !strings.Contains(out, string(r.State)) {
					t.Errorf("%s: row %q state word %q is absent from the screen", name, r.Name, r.State)
				}
			}
		}
	})
}

// ansiPattern matches an ANSI SGR escape sequence.
var ansiPattern = regexp.MustCompile("\x1b\\[[0-9;]*m")

// TestRenderGlyphsAndColor is the decoration contract: colour and glyphs add
// nothing an operator NEEDS. Stripping the escapes and replacing each glyph with
// the space it occupies must reproduce the plain screen exactly — which is only
// true if every column was laid out on plain text and the STATE word is always
// present.
func TestRenderGlyphsAndColor(t *testing.T) {
	t.Parallel()
	// Every glyph the renderer can draw, as runes: the strip below is
	// rune-indexed because "✓" is three bytes and a byte slice would cut it.
	glyphRunes := map[rune]bool{'✓': true, '!': true, '✗': true, '-': true, '?': true}
	isGlyph := func(r rune) bool { return glyphRunes[r] }

	for name, rep := range goldenReports() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			plain := Render(rep, Style{})
			fancy := Render(rep, Style{Color: true, Glyphs: true})

			if fancy == plain {
				t.Fatal("the decorated screen is byte-identical to the plain one — the test is vacuous")
			}
			if !strings.Contains(fancy, "\x1b[") {
				t.Fatal("Style{Color:true} emitted no ANSI escape")
			}

			stripped := ansiPattern.ReplaceAllString(fancy, "")
			// The glyph occupies the first of the two columns the plain screen
			// leaves blank, so replacing glyph runes with a space is the exact
			// inverse of drawing them.
			var b strings.Builder
			for _, line := range strings.Split(stripped, "\n") {
				runes := []rune(line)
				if len(runes) > 3 && runes[0] == ' ' && runes[1] == ' ' && isGlyph(runes[2]) {
					runes[2] = ' '
				}
				b.WriteString(string(runes))
				b.WriteString("\n")
			}
			got := strings.TrimSuffix(b.String(), "\n")
			if got != plain {
				t.Errorf("decoration changed the layout:\n--- decorated, stripped ---\n%s\n--- plain ---\n%s", got, plain)
			}
		})
	}
}

// TestRenderDetailViews asserts the two detail views expand the wide columns the
// overview hides, and that the runtimed row — which the overview omits on purpose
// — is reachable from the cluster view.
func TestRenderDetailViews(t *testing.T) {
	t.Parallel()
	rep := goldenReports()["render_stopped_crashloop.txt"]

	daemons := RenderDaemons(rep, Style{})
	for _, must := range []string{"label", "io.k3sm.server", "fix: k3sm status logs server"} {
		if !strings.Contains(daemons, must) {
			t.Errorf("daemons view missing %q:\n%s", must, daemons)
		}
	}
	if strings.Contains(daemons, RowWorkloads) {
		t.Errorf("daemons view leaked a cluster row:\n%s", daemons)
	}

	cluster := RenderCluster(rep, Style{})
	if !strings.Contains(cluster, RowRuntimed) {
		t.Errorf("cluster view omits the runtimed row:\n%s", cluster)
	}
	if strings.Contains(cluster, RowNetd+"     ") {
		t.Errorf("cluster view leaked a daemon row:\n%s", cluster)
	}
}

// TestRenderWideAddsColumnsOnly asserts -o wide is additive: it may add lines,
// but every line the default screen prints is still there, unchanged.
func TestRenderWideAddsColumnsOnly(t *testing.T) {
	t.Parallel()
	rep := goldenReports()["render_running.txt"]
	plain := Render(rep, Style{})
	wide := Render(rep, Style{Wide: true})
	if len(wide) <= len(plain) {
		t.Fatalf("-o wide added nothing:\n%s", wide)
	}
	for _, line := range strings.Split(plain, "\n") {
		if line == "" {
			continue
		}
		if !strings.Contains(wide, line) {
			t.Errorf("-o wide dropped the plain line %q", line)
		}
	}
}

// TestRenderRowsKeepsTheCallersRows pins the one property that distinguishes
// RenderRows from Render: it lays out the rows the report carries, in order,
// including names that are in no shipped screen — which is the whole reason
// `k3sm doctor` can share this renderer. The headline, the state column and the
// Next block are the same ones Render produces.
func TestRenderRowsKeepsTheCallersRows(t *testing.T) {
	t.Parallel()

	rows := []Row{
		{Name: "arch", State: StateOK, Severity: SeverityOK, Detail: "arm64 (Apple Silicon)"},
		{Name: "macos", State: StateFailed, Severity: SeverityFail, Detail: "macOS 15.5 is below the floor", Remedy: "upgrade this Mac"},
	}
	v, summary, next := Aggregate(rows, true, dataroot.RoleServer)
	r := Report{Verdict: v, Role: dataroot.RoleServer, Summary: summary, Rows: rows, Next: next, Version: goldenVersion, Host: goldenHost, Timestamp: goldenTime}

	screen := RenderRows(r, Style{})
	for _, want := range []string{"arch", "macos", "arm64 (Apple Silicon)", "below the floor", "Next: upgrade this Mac"} {
		if !strings.Contains(screen, want) {
			t.Errorf("screen does not carry %q:\n%s", want, screen)
		}
	}
	if !strings.HasPrefix(screen, "k3sm "+v.String()+": ") {
		t.Errorf("screen does not lead with the shared headline:\n%s", screen)
	}
	// Render, which selects by the shipped vocabulary, shows none of them —
	// the difference the helper exists for.
	if overview := Render(r, Style{}); strings.Contains(overview, "arm64 (Apple Silicon)") {
		t.Errorf("Render rendered a row that is in no screen's vocabulary:\n%s", overview)
	}
}

// TestRowDetailStripsControlCharacters pins that cluster-sourced row text
// cannot put terminal control sequences on the operator's TTY: C0, C1 and DEL
// are removed from the human output while printable Unicode is kept.
func TestRowDetailStripsControlCharacters(t *testing.T) {
	row := Row{Name: "interconnect", State: "degraded", Detail: "node \x1b[2Jé世\x1b]0;pwned\x07 x\u009b31m y\x7f z\r\n\x00end"}
	row.Wide = map[string]string{"node": "n\x1b[31m1"}
	out := renderRow(row, Style{}) + wideLine(row)
	for _, r := range out {
		if r != '\n' && (r < 0x20 || (r >= 0x7f && r <= 0x9f)) {
			t.Fatalf("control character %U survived in %q", r, out)
		}
	}
	if !strings.Contains(out, "é世") {
		t.Errorf("printable Unicode was dropped: %q", out)
	}
	if strings.Count(out, "\n") != 2 {
		t.Errorf("stripped text still breaks the row across lines: %q", out)
	}
}

// TestStripControlsDropsBidiAndSeparators: every control character, every
// rune in the Unicode format category Cf (the bidi controls and marks, the
// zero-width characters, the soft hyphen, the interlinear annotation and tag
// characters) and the line and paragraph separators are removed, so record
// text cannot reorder, hide or break the line an operator reads. The code
// points just outside each range, U+FFFD and other printable Unicode are kept.
func TestStripControlsDropsBidiAndSeparators(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, in, want string
	}{
		{"LRE", "a\u202ab", "ab"},
		{"RLE", "a\u202bb", "ab"},
		{"PDF", "a\u202cb", "ab"},
		{"LRO", "a\u202db", "ab"},
		{"RLO", "a\u202eb", "ab"},
		{"LRI", "a\u2066b", "ab"},
		{"RLI", "a\u2067b", "ab"},
		{"FSI", "a\u2068b", "ab"},
		{"PDI", "a\u2069b", "ab"},
		{"LRM", "a\u200eb", "ab"},
		{"RLM", "a\u200fb", "ab"},
		{"ALM", "a\u061cb", "ab"},
		{"line separator", "a\u2028b", "ab"},
		{"paragraph separator", "a\u2029b", "ab"},
		{"trojan-source reorder", "rm \u202e/ fr-\u2066 x\u2069\u202c", "rm / fr- x"},
		{"hyphenation point below the separators is kept", "a\u2027b", "a\u2027b"},
		{"narrow no-break space is kept", "a\u202fb", "a\u202fb"},
		// Status values are identifiers and messages, so the joiner
		// characters are removed with the rest of the format category.
		{"zero width non-joiner", "a\u200cb", "ab"},
		{"zero width joiner", "a\u200db", "ab"},
		{"zero width space", "a\u200bb", "ab"},
		{"word joiner", "a\u2060b", "ab"},
		{"function application", "a\u2061b", "ab"},
		{"inhibit symmetric swapping", "a\u206ab", "ab"},
		{"byte order mark", "a\ufeffb", "ab"},
		{"soft hyphen", "a\u00adb", "ab"},
		{"interlinear annotation anchor", "a\ufff9b", "ab"},
		{"language tag", "a\U000E0001b", "ab"},
		{"tag latin capital letter A", "a\U000E0041b", "ab"},
		{"cancel tag", "a\U000E007Fb", "ab"},
		{"unassigned U+2065 below the isolates is kept", "a\u2065b", "a\u2065b"},
		{"replacement character is kept", "a\ufffdb", "a\ufffdb"},
		{"ordinary non-ASCII text is kept", "café Ελληνικά العربية", "café Ελληνικά العربية"},
		{"en space is kept", "a\u2002b", "a\u2002b"},
		{"C0 and C1 still go", "a\x1b\u009bb\x7f", "ab"},
		{"printable Unicode is kept", "é世→", "é世→"},
	} {
		if got := stripControls(tc.in); got != tc.want {
			t.Errorf("%s: stripControls(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

// TestNextStepsAreStripped: the Next block prints step text, and a step is a
// row's Remedy, so it carries no control byte, bidi control or separator on
// the overview or a detail view, whether the step came from Report.Next
// directly or from the aggregate's remedy list.
func TestNextStepsAreStripped(t *testing.T) {
	t.Parallel()
	const hostile = "first\x1b[2J \u202eevil\u202c step\u2028second\x07 line\u2029"
	const want = "first[2J evil stepsecond line"
	rows := []Row{{Name: RowServer, State: StateCrashLoop, Severity: SeverityFail, Detail: "d",
		Remedy: hostile + "\nthen\u2066 this\x1b]0;owned\x07", Wide: map[string]string{}}}
	_, _, aggregated := Aggregate(rows, true, dataroot.RoleServer)
	for name, next := range map[string][]string{
		"report next":    {hostile, "two\x1b[31m\u2067 steps\u2029"},
		"aggregate next": aggregated,
	} {
		r := Report{Role: dataroot.RoleServer, Rows: rows, Next: next}
		for view, out := range map[string]string{
			"overview": Render(r, Style{}),
			"daemons":  RenderDaemons(r, Style{}),
			"cluster":  RenderCluster(r, Style{}),
			"rows":     RenderRows(r, Style{}),
		} {
			for _, c := range out {
				if c != '\n' && (c < 0x20 || (c >= 0x7f && c <= 0x9f) ||
					(c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069) || c == 0x2028 || c == 0x2029 ||
					c == 0x200e || c == 0x200f || c == 0x061c) {
					t.Errorf("%s/%s: %U reaches the human output:\n%q", name, view, c, out)
					break
				}
			}
			if !strings.Contains(out, "Next: "+want+"\n") {
				t.Errorf("%s/%s: output lacks the stripped first step:\n%q", name, view, out)
			}
		}
	}
	if len(aggregated) != 2 {
		t.Fatalf("Aggregate produced %d steps, want 2: %q", len(aggregated), aggregated)
	}
}

// TestHeadlineSummaryIsStripped: the summary on the headline is row text on the
// degraded path, so ESC and the bidi override must not reach any human view,
// whether the summary is given directly or built by Aggregate from a row's detail.
func TestHeadlineSummaryIsStripped(t *testing.T) {
	const hostile = "evil\u001b[2J‮gnp.exe"
	degraded := report([]Row{
		{Name: RowInterconnect, State: "degraded", Severity: SeverityFail, Detail: hostile},
	}, true)
	direct := report(nil, true)
	direct.Summary = hostile
	for name, r := range map[string]Report{"aggregated": degraded, "direct": direct} {
		if !strings.Contains(r.Summary, "\u001b") {
			t.Fatalf("%s: fixture summary lost its escape: %q", name, r.Summary)
		}
		views := map[string]string{
			"overview": Render(r, Style{}),
			"rows":     RenderRows(r, Style{}),
			"daemons":  RenderDaemons(r, Style{}),
			"cluster":  RenderCluster(r, Style{}),
		}
		for view, out := range views {
			if strings.ContainsAny(out, "\u001b‮") {
				t.Errorf("%s/%s: control character survived: %q", name, view, out)
			}
			if !strings.Contains(out, "evil[2Jgnp.exe") {
				t.Errorf("%s/%s: printable text was dropped: %q", name, view, out)
			}
		}
	}
}
