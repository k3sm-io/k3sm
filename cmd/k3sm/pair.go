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
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"k3sm.io/k3sm/pkg/bootstrap/pairing"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/executor"
)

const pairUsage = `usage:
  sudo k3sm pair --for <dur> [--max-joins N]   open the pairing window on this control plane
  sudo k3sm pair --close                       close it
  k3sm pair                                    show the window and the line to run on the new Mac
  sudo k3sm pair --listen <dur> [--cluster <pin>]
                                               re-arm an --auto-join Mac to listen for a server
`

// pairOptions is the parsed `k3sm pair` command line.
type pairOptions struct {
	open     time.Duration
	maxJoins int
	close    bool
	listen   time.Duration
	cluster  string
	workDir  string
}

func parsePairFlags(args []string, errOut io.Writer) (pairOptions, error) {
	var o pairOptions
	fs := flag.NewFlagSet("pair", flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.DurationVar(&o.open, "for", 0, "open the pairing window for this long (e.g. 10m)")
	fs.IntVar(&o.maxJoins, "max-joins", pairing.DefaultMaxJoins, "how many completed joins the window admits")
	fs.BoolVar(&o.close, "close", false, "close the pairing window")
	fs.DurationVar(&o.listen, "listen", 0, "on an --auto-join Mac: listen for a server's pairing beacon for this long")
	fs.StringVar(&o.cluster, "cluster", "", "with --listen: the cluster pin a server must carry (printed by `k3sm pair` on the server)")
	fs.StringVar(&o.workDir, "work-dir", "", "the role's work dir (default: the installed role's)")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	set := 0
	for _, b := range []bool{o.open > 0, o.close, o.listen > 0} {
		if b {
			set++
		}
	}
	switch {
	case set > 1:
		return o, errors.New("--for, --close and --listen are separate acts; give one\n" + strings.TrimSpace(pairUsage))
	case o.cluster != "" && o.listen <= 0:
		return o, errors.New("--cluster pins what a listening Mac accepts; it needs --listen\n" + strings.TrimSpace(pairUsage))
	case o.maxJoins < 1:
		return o, errors.New("--max-joins must be at least 1")
	}
	return o, nil
}

// runPair is `k3sm pair`.
func runPair(args []string) error {
	o, err := parsePairFlags(args, os.Stderr)
	if err != nil {
		return err
	}
	now := time.Now()
	switch {
	case o.listen > 0:
		dir := o.workDir
		if dir == "" {
			dir = agentCredentialDir()
		}
		a, err := pairing.WriteArm(pairing.ArmPath(dir), now, o.listen, o.cluster)
		if err != nil {
			return fmt.Errorf("%w (run with sudo)", err)
		}
		fmt.Printf("listening for a pairing beacon until %s", a.Until.Format(time.RFC3339))
		if a.Cluster == "" {
			fmt.Print(" from ANY cluster (no --cluster: the first open server heard is trusted)")
		}
		fmt.Println()
		return nil
	}
	dir := o.workDir
	if dir == "" {
		dir = executor.DefaultWorkDir
	}
	win := pairing.WindowStore{Path: pairing.WindowPath(dir)}
	switch {
	case o.open > 0:
		w, err := win.Open(now, o.open, o.maxJoins)
		if err != nil {
			return fmt.Errorf("%w (run with sudo)", err)
		}
		fmt.Printf("pairing window open until %s for %d join(s)\n", w.Until.Format(time.RFC3339), w.MaxJoins)
		return printPairHint(os.Stdout, dir)
	case o.close:
		if err := win.Close(); err != nil {
			return fmt.Errorf("%w (run with sudo)", err)
		}
		fmt.Println("pairing window closed")
		return nil
	}
	w, ok, err := win.Load()
	if err != nil {
		return fmt.Errorf("%w (run with sudo)", err)
	}
	fmt.Println(describeWindow(w, ok, now))
	return printPairHint(os.Stdout, dir)
}

// describeWindow is the one-line window state `k3sm pair` prints.
func describeWindow(w pairing.Window, ok bool, now time.Time) string {
	switch {
	case !ok:
		return "pairing window: closed (open it with `sudo k3sm pair --for 10m`)"
	case !now.Before(w.Until):
		return fmt.Sprintf("pairing window: closed (it ended %s)", w.Until.Format(time.RFC3339))
	case w.Completed >= w.MaxJoins:
		return fmt.Sprintf("pairing window: closed (%d of %d joins completed)", w.Completed, w.MaxJoins)
	}
	return fmt.Sprintf("pairing window: open until %s, %d of %d joins completed", w.Until.Format(time.RFC3339), w.Completed, w.MaxJoins)
}

// printPairHint prints the cluster pin and the exact line for the new Mac.
func printPairHint(out io.Writer, workDir string) error {
	pin, _, err := certs.LoadCAPins(workDir)
	if err != nil {
		return fmt.Errorf("read the cluster pin: %w (run with sudo on the control plane)", err)
	}
	fmt.Fprintf(out, "cluster pin: %s\n", pin)
	fmt.Fprintln(out, "on the new Mac, cabled to this one by Thunderbolt:")
	fmt.Fprintln(out, pairInstallLine(pin))
	return nil
}

// pairInstallLine is the exact command the new Mac runs.
func pairInstallLine(pin string) string {
	return "  sudo k3sm install --auto-join --cluster " + pin
}
