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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"k3sm.io/k3sm/pkg/status"
)

// statusUsage is the canonical home of the `k3sm status` exit-code table. It is
// printed by `k3sm status --help`, and `main`'s own usage points here rather
// than restating the numbers, so there is exactly one place they are written
// down.
const statusUsage = `k3sm status — what k3sm is doing on this Mac

Usage: k3sm status [view] [flags]

Views:
  (none)      the one screen: install, daemons, apiserver, node, workloads, data root
  daemons     per-LaunchDaemon detail — state, pid, run count, last exit, plist and log paths
  cluster     control-plane detail — readyz, node, workloads by phase, datastore, runtime daemon
  logs [job]  tail the daemons' log files; job is netd or server, both when omitted

Flags:
  -o text|json|wide   output format (default text; json is the machine interface)
  --no-color          never emit colour or glyphs
  --wait              poll until the cluster is running, or --timeout elapses
  --timeout 90s       how long --wait waits
  --watch[=2s]        re-render in place until interrupted (requires a terminal)
  --lines 50          how many log lines ` + "`status logs`" + ` prints per file

Exit codes (a script may branch on these; the set is ADDITIVE ONLY and a number
is never reassigned):
  0  running        the control plane is serving and every subsystem is healthy
  1  internal error a probe itself failed — this is not a verdict about k3sm
  2  usage          a bad flag or view (also: --watch with output redirected)
  3  stopped        installed, and the control plane is not serving — cleanly
                    stopped or crash-looping; the summary says which
  4  degraded       serving, with at least one subsystem failing or warning
  5  not installed  there is no k3sm install on this Mac
  6  unknown        the state could not be determined — usually because this
                    account cannot read the daemons' files; re-run with sudo
`

// Timing defaults. The poll interval is fixed rather than flag-driven: --wait
// exists to be run in a script after a restart, and one more knob there buys
// nothing an operator wants.
const (
	waitPollInterval     = 2 * time.Second
	defaultWatchInterval = 2 * time.Second
	defaultWaitTimeout   = 90 * time.Second
	defaultLogLines      = 50
)

// clearScreen homes the cursor and erases the display between watch frames.
const clearScreen = "\x1b[H\x1b[2J"

// Process exit codes that are NOT verdicts. Every other code comes from
// status.Verdict.ExitCode.
const (
	exitInternalError = 1
	exitUsage         = 2
)

// statusOptions is the parsed command line.
type statusOptions struct {
	view    string
	target  string
	format  string
	noColor bool
	wait    bool
	timeout time.Duration
	watch   time.Duration
	lines   int
}

// watchFlag accepts both `--watch` (the default interval) and `--watch=5s`.
//
// It is a bool-shaped flag on purpose: Go's flag package only lets a bare
// `--flag` stand alone when the flag reports IsBoolFlag, and the alternative —
// a plain duration flag — would make `--watch` swallow the next argument. The
// cost is that the SPACE form `--watch 5s` does not set the interval; it leaves
// "5s" as a positional, which is then rejected as an unknown view rather than
// silently ignored.
type watchFlag struct{ d time.Duration }

// String renders the configured interval, or the empty string when watch is off.
func (w *watchFlag) String() string {
	if w == nil || w.d == 0 {
		return ""
	}
	return w.d.String()
}

// Set parses the interval. The empty and "true" values are what the flag package
// hands a bool-shaped flag given bare.
func (w *watchFlag) Set(v string) error {
	if v == "" || v == "true" {
		w.d = defaultWatchInterval
		return nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fmt.Errorf("invalid --watch interval %q (try --watch=2s)", v)
	}
	if d <= 0 {
		return fmt.Errorf("--watch interval must be positive, got %s", d)
	}
	w.d = d
	return nil
}

// IsBoolFlag lets `--watch` stand alone. See watchFlag's own comment.
func (w *watchFlag) IsBoolFlag() bool { return true }

// statusViews are the accepted first positional arguments.
var statusViews = map[string]bool{"daemons": true, "cluster": true, "logs": true}

// statusLogTargets are the accepted `status logs` arguments.
var statusLogTargets = map[string]bool{"netd": true, "server": true}

// parseStatusArgs parses the command line into options.
//
// Positionals are collected from BOTH ends of the flag parse — the leading run
// before any flag, and whatever fs.Parse stopped at — so `k3sm status daemons -o
// json` and `k3sm status -o json daemons` both work. Go's flag package stops at
// the first non-flag argument, and a status verb that only accepted one of those
// two orders would be a papercut on every use.
func parseStatusArgs(args []string, errOut io.Writer) (statusOptions, error) {
	o := statusOptions{format: "text", timeout: defaultWaitTimeout, lines: defaultLogLines}
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.Usage = func() { fmt.Fprint(errOut, statusUsage) }

	var watch watchFlag
	fs.StringVar(&o.format, "o", o.format, "output format: text, json or wide")
	fs.BoolVar(&o.noColor, "no-color", false, "never emit colour or glyphs")
	fs.BoolVar(&o.wait, "wait", false, "poll until the cluster is running")
	fs.DurationVar(&o.timeout, "timeout", o.timeout, "how long --wait waits")
	fs.IntVar(&o.lines, "lines", o.lines, "log lines per file for `status logs`")
	fs.Var(&watch, "watch", "re-render in place every interval")

	var positional []string
	for len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		positional = append(positional, args[0])
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	positional = append(positional, fs.Args()...)
	o.watch = watch.d

	if len(positional) > 0 {
		if !statusViews[positional[0]] {
			return o, fmt.Errorf("unknown view %q — expected daemons, cluster or logs", positional[0])
		}
		o.view = positional[0]
		positional = positional[1:]
	}
	if len(positional) > 0 {
		if o.view != "logs" {
			return o, fmt.Errorf("unexpected argument %q", positional[0])
		}
		if !statusLogTargets[positional[0]] {
			return o, fmt.Errorf("unknown log %q — expected netd or server", positional[0])
		}
		o.target = positional[0]
		positional = positional[1:]
	}
	if len(positional) > 0 {
		return o, fmt.Errorf("unexpected argument %q", positional[0])
	}
	switch o.format {
	case "text", "json", "wide":
	default:
		return o, fmt.Errorf("unknown -o format %q — expected text, json or wide", o.format)
	}
	if o.lines <= 0 {
		return o, fmt.Errorf("--lines must be positive, got %d", o.lines)
	}
	return o, nil
}

// statusRunner is the command with every side effect injected: where output
// goes, how a report is collected, whether a human is watching, how time passes,
// and how a log file is read. runStatus builds the production one; the tests
// build fakes and drive the same code.
type statusRunner struct {
	out       io.Writer
	errOut    io.Writer
	collect   func(context.Context) status.Report
	stdoutTTY bool
	stderrTTY bool
	color     bool
	// sleep waits for d and reports whether waiting may continue. False means
	// the deadline passed or the context was cancelled — the one signal both the
	// --wait timeout and the --watch stop condition are expressed in.
	sleep    func(context.Context, time.Duration) bool
	readLog  func(path string, lines int) ([]string, error)
	logPaths map[string]string
}

// run executes a parsed command and returns the process exit code.
func (r statusRunner) run(ctx context.Context, o statusOptions) int {
	if o.view == "logs" {
		return r.runLogs(o)
	}
	switch {
	case o.watch > 0:
		return r.runWatch(ctx, o)
	case o.wait:
		return r.runWait(ctx, o)
	default:
		return r.emit(r.collect(ctx), o)
	}
}

// emit writes one report in the requested format and returns its exit code.
func (r statusRunner) emit(rep status.Report, o statusOptions) int {
	if o.format == "json" {
		encoded, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			fmt.Fprintln(r.errOut, "k3sm status: encode report:", err)
			return exitInternalError
		}
		if _, err := fmt.Fprintln(r.out, string(encoded)); err != nil {
			fmt.Fprintln(r.errOut, "k3sm status: write report:", err)
			return exitInternalError
		}
		return rep.Verdict.ExitCode()
	}
	if _, err := io.WriteString(r.out, r.render(rep, o)); err != nil {
		fmt.Fprintln(r.errOut, "k3sm status: write report:", err)
		return exitInternalError
	}
	return rep.Verdict.ExitCode()
}

// render picks the screen for the requested view.
func (r statusRunner) render(rep status.Report, o statusOptions) string {
	style := status.Style{Color: r.color, Glyphs: r.color, Wide: o.format == "wide"}
	switch o.view {
	case "daemons":
		return status.RenderDaemons(rep, style)
	case "cluster":
		return status.RenderCluster(rep, style)
	default:
		return status.Render(rep, style)
	}
}

// runWait polls until the cluster reports running or the deadline passes, then
// prints the LAST report it collected and exits with that report's code. The
// progress dots go to stderr and only for a human — a script capturing stdout
// gets the report and nothing else.
func (r statusRunner) runWait(ctx context.Context, o statusOptions) int {
	dots := false
	for {
		rep := r.collect(ctx)
		if rep.Verdict == status.VerdictRunning {
			r.endDots(dots)
			return r.emit(rep, o)
		}
		if r.stderrTTY {
			fmt.Fprint(r.errOut, ".")
			dots = true
		}
		if !r.sleep(ctx, waitPollInterval) {
			r.endDots(dots)
			return r.emit(rep, o)
		}
	}
}

// endDots closes the progress line so the report does not start mid-line.
func (r statusRunner) endDots(dots bool) {
	if dots {
		fmt.Fprintln(r.errOut)
	}
}

// runWatch re-renders in place until the context ends. It REFUSES a redirected
// stdout: the escape sequences that make watching work would be written into
// whatever file or pipe is on the other end, which is never what the caller
// meant.
func (r statusRunner) runWatch(ctx context.Context, o statusOptions) int {
	if !r.stdoutTTY {
		fmt.Fprintln(r.errOut, "k3sm status: --watch needs a terminal (stdout is not one) — drop --watch, or use --wait for a script")
		return exitUsage
	}
	code := exitInternalError
	for {
		if _, err := io.WriteString(r.out, clearScreen); err != nil {
			fmt.Fprintln(r.errOut, "k3sm status: write report:", err)
			return exitInternalError
		}
		rep := r.collect(ctx)
		code = r.emit(rep, o)
		if !r.sleep(ctx, o.watch) {
			return code
		}
	}
}

// runLogs tails the daemons' log files, redacted. It is the one view whose
// output is not a report, so it carries the file headers on stderr: a caller
// redirecting stdout gets log lines and nothing else.
func (r statusRunner) runLogs(o statusOptions) int {
	names := []string{"netd", "server"}
	if o.target != "" {
		names = []string{o.target}
	}
	code := 0
	for _, name := range names {
		path := r.logPaths[name]
		lines, err := r.readLog(path, o.lines)
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				fmt.Fprintf(r.errOut, "k3sm status logs: %s is not readable as this user — run: sudo k3sm status logs %s\n", path, name)
				code = status.VerdictUnknown.ExitCode()
				continue
			}
			fmt.Fprintf(r.errOut, "k3sm status logs: read %s: %v\n", path, err)
			if code == 0 {
				code = exitInternalError
			}
			continue
		}
		if len(names) > 1 {
			fmt.Fprintf(r.errOut, "==> %s <==\n", path)
		}
		for _, line := range lines {
			if _, werr := fmt.Fprintln(r.out, status.Redact(line)); werr != nil {
				fmt.Fprintln(r.errOut, "k3sm status logs: write:", werr)
				return exitInternalError
			}
		}
	}
	return code
}

// runStatus is the `k3sm status` entry point. It returns the process exit code
// and prints its own errors, because the exit code IS the verdict here — the
// generic "print the error and exit 1" wrapper the other verbs use would
// collapse stopped, degraded and not-installed into one number.
func runStatus(args []string) int {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		fmt.Print(statusUsage)
		return 0
	}
	o, err := parseStatusArgs(args, os.Stderr)
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stderr, "k3sm status:", err)
		}
		return exitUsage
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if o.wait {
		ctx, cancel = context.WithTimeout(context.Background(), o.timeout)
		defer cancel()
	}
	return newStatusRunner(o).run(ctx, o)
}
