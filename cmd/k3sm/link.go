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
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"k3sm.io/darwin-net/pkg/linkenum"
	"k3sm.io/darwin-net/pkg/netd/wire"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
)

const linkUsage = `usage:
  sudo k3sm link reset
      release every direct-link port: its address and routes are removed and it
      goes back into bridge0 (the rollback step before an older k3sm is
      installed). A running node configures its cabled ports again within
      seconds, so stop its daemon first when the release must last.
  sudo k3sm link tunnel-only (--all | <iface>...) [--off]
      keep pod traffic off the cable (the per-port kill switch): the node
      republishes the port as tunnelOnly, the resolver reports it down, and the
      peers use the wireguard tunnel. --off clears the override.
`

// runLink dispatches `k3sm link`.
func runLink(args []string) error {
	if len(args) == 0 {
		return errors.New(strings.TrimSpace(linkUsage))
	}
	switch args[0] {
	case "reset":
		return runLinkReset(args[1:])
	case "tunnel-only":
		return runLinkTunnelOnly(args[1:], os.Stdout)
	case "-h", "--help", "help":
		fmt.Print(linkUsage)
		return nil
	default:
		return fmt.Errorf("unknown link subcommand %q\n%s", args[0], strings.TrimSpace(linkUsage))
	}
}

// linkResetAsService is the internal flag the root `k3sm link reset` re-executes
// itself with, as the service user: the network helper admits only that uid.
const linkResetAsService = "--as-service-user"

// runLinkReset releases every Thunderbolt port through the network helper.
func runLinkReset(args []string) error {
	fs := flag.NewFlagSet("link reset", flag.ContinueOnError)
	asService := fs.Bool(linkResetAsService[2:], false, "internal: run the helper calls as the service user")
	socket := fs.String("netd-socket", install.DefaultNetdSocket, "the network helper's socket")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*asService {
		if os.Geteuid() != 0 {
			return fmt.Errorf("k3sm link reset changes host networking through the network helper: run `sudo k3sm link reset`")
		}
		return reexecAsServiceUser([]string{"link", "reset", linkResetAsService, "--netd-socket", *socket})
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return releaseLinks(ctx, wire.NewClient(*socket), linkenum.HardwarePorts, os.Stdout)
}

// linkRemover is the helper's RemoveLink verb.
type linkRemover interface {
	RemoveLink(ctx context.Context, iface string) error
	HelperVersion() (wire.Version, bool)
}

// releaseLinks runs RemoveLink for every Thunderbolt port (idempotent: a port
// that was never configured is put back into the bridge, which it is already
// in). A helper that predates direct links has nothing to release.
func releaseLinks(ctx context.Context, c linkRemover, hw func(context.Context) (map[string]int, error), out io.Writer) error {
	ports, err := hw(ctx)
	if errors.Is(err, linkenum.ErrNoThunderboltService) {
		fmt.Fprintln(out, "no Thunderbolt network port is listed; nothing to release")
		return nil
	}
	if err != nil {
		return fmt.Errorf("list the Thunderbolt ports: %w", err)
	}
	names := make([]string, 0, len(ports))
	for name := range ports {
		names = append(names, name)
	}
	sort.Strings(names)
	var firstErr error
	for _, iface := range names {
		err := c.RemoveLink(ctx, iface)
		if v, seen := c.HelperVersion(); seen && !v.SupportsDirectLinks() {
			fmt.Fprintf(out, "the network helper (%d.%d) predates direct links; nothing to release\n", v.Major, v.Minor)
			return nil
		}
		if err != nil {
			fmt.Fprintf(out, "%s: not released: %v\n", iface, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		fmt.Fprintf(out, "%s: released (address and routes removed, back in bridge0)\n", iface)
	}
	return firstErr
}

// reexecAsServiceUser runs this binary again with args as the service user. A
// root caller cannot speak to the network helper itself (it admits one uid), and
// switching the whole Go process's uid is not something a multi-threaded runtime
// does safely, so the switch happens across an exec.
func reexecAsServiceUser(args []string) error {
	u, err := user.Lookup(install.DefaultServiceUser)
	if err != nil {
		return fmt.Errorf("look up the service user %s: %w", install.DefaultServiceUser, err)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return fmt.Errorf("service user uid %q: %w", u.Uid, err)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return fmt.Errorf("service user gid %q: %w", u.Gid, err)
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(self, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	return cmd.Run()
}

// runLinkTunnelOnly writes the node-local tunnel-only override file the node's
// direct-link loop reads on every tick.
func runLinkTunnelOnly(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("link tunnel-only", flag.ContinueOnError)
	all := fs.Bool("all", false, "every direct-link port")
	off := fs.Bool("off", false, "clear the override instead of setting it")
	workDir := fs.String("work-dir", "", "the node's work dir (default: the installed role's)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ifaces := fs.Args()
	if *all == (len(ifaces) > 0) {
		return errors.New("name the ports, or --all (not both)\n" + strings.TrimSpace(linkUsage))
	}
	dir := *workDir
	if dir == "" {
		dir = installedRoleWorkDir()
	}
	path := filepath.Join(dir, tunnelOnlyFile)
	cur, err := readTunnelOnly(path)
	if err != nil {
		return err
	}
	next := applyTunnelOnly(cur, *all, ifaces, !*off)
	if err := writeOwnedJSON(path, next); err != nil {
		return fmt.Errorf("write %s: %w (run with sudo)", path, err)
	}
	what := "every port"
	if !*all {
		what = fmt.Sprint(ifaces)
	}
	verb := "carries no pod traffic"
	if *off {
		verb = "may carry pod traffic again"
	}
	fmt.Fprintf(out, "%s %s; the node republishes within seconds (%s)\n", what, verb, path)
	return nil
}

// applyTunnelOnly folds one command into the override file.
func applyTunnelOnly(cur tunnelOnlyOverrides, all bool, ifaces []string, value bool) tunnelOnlyOverrides {
	if all {
		v := value
		// --all speaks for every port: per-port entries would otherwise outvote it.
		return tunnelOnlyOverrides{All: &v}
	}
	if cur.Ifaces == nil {
		cur.Ifaces = map[string]bool{}
	}
	for _, i := range ifaces {
		cur.Ifaces[i] = value
	}
	return cur
}

// installedRoleWorkDir is the work dir of the node daemon installed on this Mac.
func installedRoleWorkDir() string {
	if role, ok := installedRole(); ok && role == install.RoleAgent {
		return agentCredentialDir()
	}
	return executor.DefaultWorkDir
}

// writeOwnedJSON writes v to path 0644 through a rename; as root it hands the
// file to the owner of its directory (the service user reads it).
func writeOwnedJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		if st, err := os.Stat(filepath.Dir(path)); err == nil {
			if sys, ok := st.Sys().(*syscall.Stat_t); ok {
				_ = os.Chown(tmp, int(sys.Uid), int(sys.Gid))
			}
		}
	}
	return os.Rename(tmp, path)
}
