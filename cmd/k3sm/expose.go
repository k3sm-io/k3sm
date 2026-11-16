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
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"k3sm.io/k3sm/internal/hostacl"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/provider"
	"k3sm.io/runtimed/pkg/hostshare"
)

// exposeUsage is `k3sm expose --help`.
const exposeUsage = `Usage:
  sudo k3sm expose allow --user <name> --namespace <ns>[,<ns>...] [--access read|read-write]
                                        let pods in the namespaces publish a
                                        volume to the host account <name>
  sudo k3sm expose revoke --user <name> [--namespace <ns>[,<ns>...]]
                                        take the grant back (for those
                                        namespaces, or all of it), and the
                                        account's access to live exposures
  k3sm expose list                      print the grants (also: ls)

An exposure is the reverse of a host share: a native pod publishes one of its
volumes to a named host account, so a tool you run on the Mac can read (or
read and write) what the pod writes there, such as a Unix socket or a status
file. The pod asks for it with an inline CSI volume of driver expose.k3sm.io:

  volumes:
    - name: sockets
      csi:
        driver: expose.k3sm.io
        volumeAttributes:
          user: <name>          # required: the host account
          access: read          # optional: read (default) or read-write

The node admits it only while root has granted it here: a grant names the
account (by uid and current name, so a renamed or recycled uid inherits
nothing), the namespaces whose pods may expose to it, and the highest access
it may get. The grants live in ` + hostshare.DefaultFile + `, owned by root
and writable by root alone, beside the host shares. 'allow' merges the
namespaces into the account's grant; --access, when given, sets the grant's
access (a new grant is read). The list is read when a pod is created, so a
change applies to pods created after it.

An admitted volume lives at <data root>/expose/<namespace>/<pod>/<volume> for
the pod's lifetime, and the account gets an inheritable access-control entry on
it. Connecting to a Unix socket needs write permission on the socket, so a read
exposure reaches a socket the pod creates 0666, and a 0600 one needs read-write.

'revoke' removes the grant and then strips the account's entries from every
live exposure in the affected namespaces, never descending below the volume
directory or following a symlink. A pod that is running keeps its directory
until it is recreated, but the account can no longer enter it.

Exit codes: 0 done; 1 failed; 2 usage; 3 not permitted (not root).
`

// exposeEnv is what the expose verb touches, so a test can fake it.
type exposeEnv struct {
	file     string
	dataRoot string
	euid     func() int
	// readFile reads the root-owned node file (hostshare.LoadFile).
	readFile func(string) (hostshare.File, error)
	write    func(string, []byte) error
	lookup   func(name string) (account, error)
	// leaves lists the live exposure directories of namespace ns under
	// dataRoot, without following a symlink.
	leaves func(dataRoot, ns string) ([]string, error)
	// revoke removes uid's entries from one exposure directory.
	revoke func(dir string, uid uint32) error
	stdout io.Writer
	stderr io.Writer
}

func defaultExposeEnv(stdout, stderr io.Writer) exposeEnv {
	return exposeEnv{
		file:     hostshare.DefaultFile,
		dataRoot: install.DefaultDataRoot,
		euid:     os.Geteuid,
		readFile: hostshare.LoadFile,
		write:    writeShareFile,
		lookup:   lookupAccount,
		leaves:   exposureLeaves,
		revoke: func(dir string, uid uint32) error {
			_, err := hostacl.RevokeSearch(dir, uid)
			return err
		},
		stdout: stdout,
		stderr: stderr,
	}
}

func runExpose(args []string, stdout, stderr io.Writer) int {
	return runExposeWith(args, defaultExposeEnv(stdout, stderr))
}

func runExposeWith(args []string, env exposeEnv) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(env.stdout, exposeUsage)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	verb, rest := args[0], args[1:]
	switch verb {
	case "list", "ls":
		if len(rest) != 0 {
			fmt.Fprintln(env.stderr, "k3sm expose list: takes no arguments")
			return 2
		}
		return exposeList(env)
	case "allow", "revoke":
	default:
		fmt.Fprintf(env.stderr, "k3sm expose: unknown command %q\n\n%s", verb, exposeUsage)
		return 2
	}
	fs := flag.NewFlagSet("expose "+verb, flag.ContinueOnError)
	fs.SetOutput(env.stderr)
	var userName, namespaces, access string
	fs.StringVar(&userName, "user", "", "the host account")
	fs.StringVar(&namespaces, "namespace", "", "comma-separated namespaces")
	if verb == "allow" {
		fs.StringVar(&access, "access", "", "read or read-write (a new grant is read)")
	}
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	switch {
	case fs.NArg() != 0:
		fmt.Fprintf(env.stderr, "k3sm expose %s: unexpected argument %q\n", verb, fs.Arg(0))
		return 2
	case userName == "":
		fmt.Fprintf(env.stderr, "k3sm expose %s: --user is required\n", verb)
		return 2
	case verb == "allow" && namespaces == "":
		fmt.Fprintln(env.stderr, "k3sm expose allow: --namespace is required")
		return 2
	}
	if env.euid() != 0 {
		fmt.Fprintf(env.stderr, "k3sm expose %s: run as root (sudo k3sm expose %s ...): grants live in the root-owned %s\n", verb, verb, env.file)
		return 3
	}
	nss := hostshare.ParseNamespaces(namespaces)
	if verb == "allow" {
		return exposeAllow(env, userName, nss, access)
	}
	return exposeRevoke(env, userName, nss)
}

func exposeAllow(env exposeEnv, userName string, nss []string, access string) int {
	fail := func(err error) int {
		fmt.Fprintln(env.stderr, "k3sm expose allow:", err)
		return 1
	}
	acct, err := env.lookup(userName)
	if err != nil {
		return fail(fmt.Errorf("look up %s: %w", userName, err))
	}
	if acct.uid < hostshare.MinDelegateUID {
		return fail(fmt.Errorf("%s is a system account (uid %d): only a user account (uid %d or above) may receive exposures", acct.name, acct.uid, hostshare.MinDelegateUID))
	}
	nf, err := env.readFile(env.file)
	if err != nil {
		return fail(err)
	}
	g := hostshare.ExposeGrant{UID: acct.uid, User: acct.name}
	var kept []hostshare.ExposeGrant
	for _, x := range nf.Exposes {
		if x.UID != acct.uid {
			kept = append(kept, x)
			continue
		}
		for _, ns := range x.Namespaces {
			if !slices.Contains(g.Namespaces, ns) {
				g.Namespaces = append(g.Namespaces, ns)
			}
		}
		g.ReadWrite = g.ReadWrite || x.ReadWrite
	}
	for _, ns := range nss {
		if !slices.Contains(g.Namespaces, ns) {
			g.Namespaces = append(g.Namespaces, ns)
		}
	}
	if access != "" {
		if g.ReadWrite, err = hostshare.ParseAccess(access); err != nil {
			return fail(err)
		}
	}
	if err := hostshare.ValidateExposeGrant(g); err != nil {
		return fail(err)
	}
	nf.Exposes = append(kept, g)
	if err := env.write(env.file, hostshare.FormatFile(nf)); err != nil {
		return fail(err)
	}
	fmt.Fprintf(env.stdout, "wrote to %s: %s\n", env.file, g)
	fmt.Fprintf(env.stdout, "pods created from now on in %s may expose a volume to %s (driver %s, volumeAttributes.user: %s)\n",
		strings.Join(g.Namespaces, ", "), acct.name, provider.ExposeDriver, acct.name)
	return 0
}

func exposeRevoke(env exposeEnv, userName string, nss []string) int {
	fail := func(err error) int {
		fmt.Fprintln(env.stderr, "k3sm expose revoke:", err)
		return 1
	}
	nf, err := env.readFile(env.file)
	if err != nil {
		return fail(err)
	}
	// The grant is found by the account's uid, or by the recorded name when
	// the account no longer exists, so a removed account's grant can still be
	// taken back.
	match := func(g hostshare.ExposeGrant) bool { return g.User == userName }
	if acct, err := env.lookup(userName); err == nil {
		match = func(g hostshare.ExposeGrant) bool { return g.UID == acct.uid }
	}
	var kept []hostshare.ExposeGrant
	affected := map[uint32][]string{}
	for _, g := range nf.Exposes {
		if !match(g) {
			kept = append(kept, g)
			continue
		}
		var remain []string
		for _, ns := range g.Namespaces {
			if len(nss) == 0 || slices.Contains(nss, ns) {
				affected[g.UID] = append(affected[g.UID], ns)
			} else {
				remain = append(remain, ns)
			}
		}
		if len(remain) > 0 {
			g.Namespaces = remain
			kept = append(kept, g)
		}
	}
	if len(affected) == 0 {
		what := ""
		if len(nss) > 0 {
			what = " for " + strings.Join(nss, ", ")
		}
		return fail(fmt.Errorf("no exposure grant to %s%s", userName, what))
	}
	nf.Exposes = kept
	if err := env.write(env.file, hostshare.FormatFile(nf)); err != nil {
		return fail(err)
	}
	uids := make([]uint32, 0, len(affected))
	for uid := range affected {
		uids = append(uids, uid)
	}
	slices.Sort(uids)
	for _, uid := range uids {
		fmt.Fprintf(env.stdout, "removed the exposure grant to %s (uid %d) for %s from %s\n", userName, uid, strings.Join(affected[uid], ", "), env.file)
	}
	for _, uid := range uids {
		for _, ns := range affected[uid] {
			dirs, err := env.leaves(env.dataRoot, ns)
			if err != nil {
				return fail(fmt.Errorf("the grant is gone, but listing the live exposures of %s failed: %w", ns, err))
			}
			for _, dir := range dirs {
				if err := env.revoke(dir, uid); err != nil {
					return fail(fmt.Errorf("the grant is gone, but removing %s's access to %s failed: %w", userName, dir, err))
				}
				fmt.Fprintf(env.stdout, "acl: %s: removed the entries for uid %d\n", dir, uid)
			}
		}
	}
	return 0
}

func exposeList(env exposeEnv) int {
	nf, err := env.readFile(env.file)
	if err != nil {
		fmt.Fprintln(env.stderr, "k3sm expose list:", err)
		return 1
	}
	if len(nf.Exposes) == 0 {
		fmt.Fprintln(env.stdout, "no exposure grants (pods cannot expose a volume to a host account on this node)")
		return 0
	}
	gs := slices.Clone(nf.Exposes)
	slices.SortFunc(gs, func(a, b hostshare.ExposeGrant) int { return strings.Compare(a.String(), b.String()) })
	for _, g := range gs {
		fmt.Fprintln(env.stdout, g)
	}
	return 0
}

// exposureLeaves lists the live exposure directories of namespace ns:
// <dataRoot>/expose/<ns>/<pod>/<volume>. Each directory is opened with no
// symlink followed on the way (hostacl.OpenNoFollow) and listed through that
// descriptor; an entry that is not a directory is skipped, and nothing below
// a volume directory is read. A namespace with no exposures has none.
func exposureLeaves(dataRoot, ns string) ([]string, error) {
	nsDir, err := hostshare.ExposeDir(dataRoot, ns, "p", "v")
	if err != nil {
		return nil, err
	}
	nsDir = filepath.Dir(filepath.Dir(nsDir))
	pods, err := listDirsNoFollow(nsDir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, pod := range pods {
		podDir := filepath.Join(nsDir, pod)
		vols, err := listDirsNoFollow(podDir)
		if err != nil {
			return nil, err
		}
		for _, v := range vols {
			out = append(out, filepath.Join(podDir, v))
		}
	}
	return out, nil
}

// listDirsNoFollow returns the names of the subdirectories of dir, opened
// with hostacl.OpenNoFollow. A missing dir has none. Symlinks and other
// files are left out (the entry type is the link's own, never its target's).
func listDirsNoFollow(dir string) ([]string, error) {
	fd, err := hostacl.OpenNoFollow(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), dir)
	defer f.Close()
	ents, err := f.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", dir, err)
	}
	var out []string
	for _, e := range ents {
		if e.Type()&fs.ModeType == fs.ModeDir {
			out = append(out, e.Name())
		}
	}
	slices.Sort(out)
	return out, nil
}
