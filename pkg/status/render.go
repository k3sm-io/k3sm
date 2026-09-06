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
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"
)

// Screen geometry. The name and state columns are fixed rather than computed so
// that a row's position does not shift as a daemon changes state — an operator
// re-running the command watches one column, not a reflowing table.
const (
	screenWidth = 96
	nameWidth   = 11
	stateWidth  = 11
	logIndent   = "      "
)

// ANSI colour codes. Colour is applied to the STATE WORD ONLY, and always AFTER
// the column has been padded from the plain text: tabwriter and every
// width computation count escape bytes as printable, so a coloured cell laid out
// by width would misalign. Padding first means stripping the escapes yields
// exactly the plain screen, which is what TestRenderGlyphsAndColor asserts.
const (
	ansiReset  = "\x1b[0m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiRed    = "\x1b[31m"
	ansiDim    = "\x1b[2m"
)

// overviewRows are the rows the default screen shows, in order. runtimed is
// deliberately absent: it is the row an ordinary account can almost never
// answer, and it would spend a line saying so on every healthy cluster. It is
// still in the JSON, still in the cluster view, and still in the verdict.
var overviewRows = []string{
	RowInstall, RowNetd, RowServer, RowAPIServer,
	RowNode, RowWorkloads, RowDataRoot, RowDatastore, RowKubeconfig,
}

// daemonViewRows are the rows `k3sm status daemons` expands.
var daemonViewRows = []string{RowInstall, RowNetd, RowServer, RowDataRoot}

// clusterViewRows are the rows `k3sm status cluster` expands.
//
// The control plane's CHILD processes (apiserver, scheduler, controller-manager,
// kine) are deliberately NOT listed: enumerating them needs a process-table
// child seam this report does not have, and inventing one to print four names
// the apiserver row already answers for would add a probe that can fail for a
// fact nothing depends on.
var clusterViewRows = []string{RowAPIServer, RowNode, RowWorkloads, RowDatastore, RowRuntimed}

// Render returns the overview screen: the verdict line with the binary's
// provenance right-aligned beside it, one line per subsystem, the server's last
// log line when it is crash-looping, and the ordered next commands.
func Render(r Report, s Style) string {
	var b strings.Builder
	b.WriteString(headline(r, s))
	b.WriteString("\n\n")
	for _, name := range overviewRows {
		row, ok := r.Row(name)
		if !ok {
			continue
		}
		b.WriteString(renderRow(row, s))
		if log := row.Wide["log"]; log != "" {
			b.WriteString(logIndent + "log: " + log + repeatSuffix(row.Wide["log-repeats"]) + "\n")
		}
		if s.Wide {
			b.WriteString(wideLine(row))
		}
	}
	b.WriteString(renderNext(r.Next))
	return b.String()
}

// RenderDaemons returns the launchd detail view: for each daemon row, every
// bookkeeping value launchctl reported plus the files it writes. This is the
// view an operator opens when the overview says a daemon is down and the next
// question is "since when, and how many times".
func RenderDaemons(r Report, s Style) string {
	return renderDetail(r, s, daemonViewRows, "daemons")
}

// RenderCluster returns the control-plane detail view: readiness, the node, the
// workloads, the datastore and the runtime daemon, with their wide columns.
func RenderCluster(r Report, s Style) string {
	return renderDetail(r, s, clusterViewRows, "cluster")
}

// renderDetail is the shared body of the two detail views: the same headline and
// Next block as the overview, with the named rows expanded into an aligned
// key/value table. tabwriter does the alignment here because these cells carry
// no colour — the width computation is over plain text, which is the one
// condition that makes tabwriter and ANSI safe together.
func renderDetail(r Report, s Style, names []string, view string) string {
	var b strings.Builder
	b.WriteString(headline(r, s))
	b.WriteString("\n\n")
	for _, name := range names {
		row, ok := r.Row(name)
		if !ok {
			continue
		}
		b.WriteString(renderRow(row, s))
		tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		for _, k := range sortedKeys(row.Wide) {
			fmt.Fprintf(tw, "%s%s\t%s\n", logIndent, k, row.Wide[k])
		}
		if err := tw.Flush(); err != nil {
			// tabwriter writes into a strings.Builder, whose Write never fails.
			b.WriteString(logIndent + "(detail unavailable)\n")
		}
		if row.Remedy != "" {
			for _, step := range strings.Split(row.Remedy, "\n") {
				b.WriteString(logIndent + "fix: " + strings.TrimSpace(step) + "\n")
			}
		}
		b.WriteString("\n")
	}
	if len(names) == 0 {
		b.WriteString("no rows in the " + view + " view\n")
	}
	// Each block ends in a blank line and renderNext opens with one, so the
	// separator is trimmed back to a single blank line here rather than being
	// conditionally omitted in two places.
	body := strings.TrimRight(b.String(), "\n") + "\n"
	return body + renderNext(r.Next)
}

// headline is the first line: `k3sm <verdict>: <summary>` with the build
// provenance right-aligned to the screen width. When the two would collide the
// provenance simply follows after two spaces — a truncated version string is
// worse than a long line.
func headline(r Report, s Style) string {
	left := "k3sm " + colorize(r.Verdict.String(), verdictColor(r.Verdict), s) + ": " + r.Summary
	plainLen := len("k3sm " + r.Verdict.String() + ": " + r.Summary)
	right := provenance(r)
	if right == "" {
		return left
	}
	gap := screenWidth - plainLen - len(right)
	if gap < 2 {
		gap = 2
	}
	return left + strings.Repeat(" ", gap) + colorize(right, ansiDim, s)
}

// provenance renders the build facts an operator needs in a bug report: the
// binary's version, the Kubernetes version it embeds, and this Mac's macOS
// version. A field that was not resolved is omitted rather than printed empty.
func provenance(r Report) string {
	var parts []string
	if r.Version.Version != "" {
		parts = append(parts, r.Version.Version)
	}
	if r.Version.KubeVersion != "" {
		parts = append(parts, "kube "+r.Version.KubeVersion)
	}
	if r.Host != "" {
		parts = append(parts, "macOS "+r.Host)
	}
	return strings.Join(parts, " · ")
}

// renderRow is one subsystem line. The STATE word is always present in plain
// text; the glyph and the colour are decoration layered on top of a screen that
// is already complete without them.
func renderRow(row Row, s Style) string {
	glyph := "  "
	if s.Glyphs {
		glyph = row.Severity.Glyph() + " "
	}
	return "  " + glyph +
		pad(row.Name, nameWidth) + " " +
		colorize(pad(string(row.State), stateWidth), severityColor(row.Severity), s) + " " +
		strings.TrimRight(row.Detail, " ") + "\n"
}

// wideLine renders a row's extra columns as sorted key=value pairs.
func wideLine(row Row) string {
	keys := sortedKeys(row.Wide)
	if len(keys) == 0 {
		return ""
	}
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		if k == "log" || k == "log-repeats" {
			continue // already printed on its own line
		}
		pairs = append(pairs, k+"="+row.Wide[k])
	}
	if len(pairs) == 0 {
		return ""
	}
	return logIndent + strings.Join(pairs, "  ") + "\n"
}

// renderNext is the trailing block of commands: the first on the `Next:` line
// itself, the rest aligned under it.
func renderNext(next []string) string {
	if len(next) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\nNext: " + next[0] + "\n")
	for _, step := range next[1:] {
		b.WriteString(logIndent + step + "\n")
	}
	return b.String()
}

// repeatSuffix renders the "× N" marker for a log line that repeats, and
// nothing at all when it does not.
func repeatSuffix(count string) string {
	if count == "" || count == "0" || count == "1" {
		return ""
	}
	return " (×" + count + ")"
}

// pad right-pads a plain-text cell to width, never truncating: a long node name
// pushes the line out rather than losing characters.
func pad(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}

// colorize wraps text in an ANSI code when the style allows it.
func colorize(text, code string, s Style) string {
	if !s.Color || code == "" {
		return text
	}
	return code + text + ansiReset
}

// severityColor maps a row's health onto its colour.
func severityColor(sev Severity) string {
	switch sev {
	case SeverityOK:
		return ansiGreen
	case SeverityWarn:
		return ansiYellow
	case SeverityFail:
		return ansiRed
	default:
		return ansiDim
	}
}

// verdictColor maps the overall verdict onto its colour.
func verdictColor(v Verdict) string {
	switch v {
	case VerdictRunning:
		return ansiGreen
	case VerdictDegraded:
		return ansiYellow
	case VerdictStopped, VerdictNotInstalled:
		return ansiRed
	default:
		return ansiDim
	}
}

// sortedKeys returns a map's keys in a stable order, so two runs of the same
// report render byte-identically.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
