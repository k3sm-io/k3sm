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
	"os"

	"k3sm.io/k3sm/pkg/status"
)

// alertsUsage is printed by `k3sm alerts --help`.
const alertsUsage = `k3sm alerts: what needs attention on this Mac, and how to fix it

Usage: k3sm alerts [-o text|json] [--no-color]

Prints only the rows of k3sm status that are not ok, each with its alert: the
cause, the evidence, the numbered fix steps (a step marked administrator runs
under sudo) and the documentation page. It runs the same checks as k3sm status
and nothing more, so it is cheap enough to call before every question.

Flags:
  -o text|json   output format (default text; json is the machine interface)
  --no-color     never emit colour

Exit codes are k3sm status's: the code is the verdict (0 running, 3 stopped,
4 degraded, 5 not installed, 6 unknown; 1 internal error, 2 usage). See
k3sm status --help.
`

// alertsOptions is the parsed `k3sm alerts` command line.
type alertsOptions struct {
	format  string
	noColor bool
}

// parseAlertsArgs parses the command line. It takes no positional argument.
func parseAlertsArgs(args []string, errOut io.Writer) (alertsOptions, error) {
	o := alertsOptions{format: "text"}
	fs := flag.NewFlagSet("k3sm alerts", flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.Usage = func() {}
	fs.StringVar(&o.format, "o", o.format, "output format: text or json")
	fs.BoolVar(&o.noColor, "no-color", false, "never emit colour")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() > 0 {
		return o, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	switch o.format {
	case "text", "json":
	default:
		return o, fmt.Errorf("unknown -o format %q: expected text or json", o.format)
	}
	return o, nil
}

// alertsRunner is the command with its side effects injected, as statusRunner is.
type alertsRunner struct {
	out     io.Writer
	errOut  io.Writer
	collect func(context.Context) status.AlertsReport
	color   bool
}

// run collects once, writes the answer and returns the verdict's exit code. The
// answer goes to stdout whatever the verdict, so a caller that branches on the
// code still has it to read.
func (r alertsRunner) run(ctx context.Context, o alertsOptions) int {
	rep := r.collect(ctx)
	var text string
	if o.format == "json" {
		encoded, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			fmt.Fprintln(r.errOut, "k3sm alerts: encode report:", err)
			return exitInternalError
		}
		text = string(encoded) + "\n"
	} else {
		text = status.RenderAlerts(rep, status.Style{Color: r.color})
	}
	if _, err := io.WriteString(r.out, text); err != nil {
		fmt.Fprintln(r.errOut, "k3sm alerts: write report:", err)
		return exitInternalError
	}
	return rep.Verdict.ExitCode()
}

// runAlertsArgs parses args and runs the command against collect; it is the
// whole verb short of the production collector.
func runAlertsArgs(ctx context.Context, args []string, out, errOut io.Writer, collect func(context.Context) status.AlertsReport, color func(noColor bool) bool) int {
	o, err := parseAlertsArgs(args, errOut)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(out, alertsUsage)
			return 0
		}
		fmt.Fprintln(errOut, "k3sm alerts:", err)
		return exitUsage
	}
	return alertsRunner{out: out, errOut: errOut, collect: collect, color: o.format == "text" && color(o.noColor)}.run(ctx, o)
}

// runAlerts is the `k3sm alerts` entry point. It returns the process exit code,
// which is the verdict, for the reason runStatus does.
func runAlerts(args []string) int {
	if len(args) > 0 && args[0] == "help" {
		fmt.Print(alertsUsage)
		return 0
	}
	return runAlertsArgs(context.Background(), args, os.Stdout, os.Stderr,
		func(ctx context.Context) status.AlertsReport { return newStatusCollector().CollectAlerts(ctx) },
		func(noColor bool) bool { return status.ColorEnabled(os.Stdout, noColor, os.Getenv) })
}
