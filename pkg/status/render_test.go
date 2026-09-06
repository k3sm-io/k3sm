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
	v, summary, next := Aggregate(rows, installed)
	return Report{
		Verdict:   v,
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
			row(RowWorkloads, StateNotReady, SeverityWarn, "1 running · 2 pending · 1 failed", "k3sm kubectl get pods -A")), true),
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
