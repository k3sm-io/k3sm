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
	"path/filepath"
	"slices"
	"strings"

	"k3sm.io/runtimed/pkg/hostshare"
)

// shareUsage is `k3sm share --help`.
const shareUsage = `Usage:
  sudo k3sm share add <path>            share a directory read-write
  sudo k3sm share add --read-only <path>
                                        share a directory read-only
  sudo k3sm share add --socket <path>   share one Unix socket (connect only)
  sudo k3sm share remove <path>         stop sharing a path
  k3sm share list                       print the shares

A host share lets a native pod mount a host path with a hostPath volume. Native
pods have no mount namespace, so a share is visible only at its own path: the
pod mounts it with mountPath equal to hostPath.path, and no subPath. Without a
share, a hostPath volume is refused (FailedHostShare on the pod).

The list lives in ` + hostshare.DefaultFile + `, owned by root and writable by root
alone, so neither the k3sm daemons nor any pod can change it. It is read when a
pod is created, so a change applies to pods created after it; a pod that is
running keeps what it was given until it is recreated, and a removed share is
not given back to a pod the node re-attaches after a restart.

A directory share covers everything under it. Under /Users a share must be
below a home directory (a project, never the home itself), and may not name a
dot directory or the home's Library. System and k3sm trees are refused.

Pods run as the _k3sm user, not as you. Reading a share needs the usual
permissions for _k3sm; writing needs a grant. 'add' prints the chmod command
that gives _k3sm (and keeps giving you) access to everything under the path.
Files a pod creates are owned by _k3sm.

Every grant is recorded: a HostShareGranted Event on the pod, and a
"host share granted" line in the node log.

Exit codes: 0 done; 1 failed; 2 usage; 3 add/remove not run as root.
`

// shareEnv is what the share verb touches, so a test can fake it.
type shareEnv struct {
	file   string
	euid   func() int
	read   func(string) ([]hostshare.Entry, error)
	write  func(string, []byte) error
	stdout io.Writer
	stderr io.Writer
}

func defaultShareEnv(stdout, stderr io.Writer) shareEnv {
	return shareEnv{
		file:   hostshare.DefaultFile,
		euid:   os.Geteuid,
		read:   hostshare.Load,
		write:  writeRootFileAtomic,
		stdout: stdout,
		stderr: stderr,
	}
}

func runShare(args []string, stdout, stderr io.Writer) int {
	return runShareWith(args, defaultShareEnv(stdout, stderr))
}

func runShareWith(args []string, env shareEnv) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(env.stdout, shareUsage)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	verb, rest := args[0], args[1:]
	switch verb {
	case "list":
		entries, err := env.read(env.file)
		if err != nil {
			fmt.Fprintln(env.stderr, "k3sm share list:", err)
			return 1
		}
		if len(entries) == 0 {
			fmt.Fprintln(env.stdout, "no host shares (pods cannot mount a hostPath volume on this node)")
			return 0
		}
		for _, e := range entries {
			fmt.Fprintln(env.stdout, e.String())
		}
		return 0
	case "add", "remove":
	default:
		fmt.Fprintf(env.stderr, "k3sm share: unknown command %q\n\n%s", verb, shareUsage)
		return 2
	}

	fs := flag.NewFlagSet("share "+verb, flag.ContinueOnError)
	fs.SetOutput(env.stderr)
	readOnly := fs.Bool("read-only", false, "share the directory read-only")
	socket := fs.Bool("socket", false, "share one Unix socket")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(env.stderr, "k3sm share %s: want exactly one path\n", verb)
		return 2
	}
	if verb == "remove" && (*readOnly || *socket) {
		fmt.Fprintln(env.stderr, "k3sm share remove: takes only a path")
		return 2
	}
	if *readOnly && *socket {
		fmt.Fprintln(env.stderr, "k3sm share add: --read-only and --socket do not combine")
		return 2
	}
	if env.euid() != 0 {
		fmt.Fprintf(env.stderr, "k3sm share %s: run as root (sudo k3sm share %s ...): the share list is root-owned\n", verb, verb)
		return 3
	}
	path, err := resolveSharePath(fs.Arg(0), verb == "add")
	if err != nil {
		fmt.Fprintf(env.stderr, "k3sm share %s: %v\n", verb, err)
		return 1
	}
	entries, err := env.read(env.file)
	if err != nil {
		fmt.Fprintf(env.stderr, "k3sm share %s: %v\n", verb, err)
		return 1
	}
	if verb == "remove" {
		kept := slices.DeleteFunc(slices.Clone(entries), func(e hostshare.Entry) bool { return e.Path == path })
		if len(kept) == len(entries) {
			fmt.Fprintf(env.stderr, "k3sm share remove: %s is not shared\n", path)
			return 1
		}
		if err := env.write(env.file, hostshare.Format(kept)); err != nil {
			fmt.Fprintln(env.stderr, "k3sm share remove:", err)
			return 1
		}
		fmt.Fprintf(env.stdout, "stopped sharing %s; pods that already mount it keep it until they are recreated\n", path)
		return 0
	}
	mode := hostshare.ModeReadWrite
	switch {
	case *readOnly:
		mode = hostshare.ModeReadOnly
	case *socket:
		mode = hostshare.ModeSocket
	}
	e := hostshare.Entry{Mode: mode, Path: path}
	if err := hostshare.ValidateEntry(e); err != nil {
		fmt.Fprintln(env.stderr, "k3sm share add:", err)
		return 1
	}
	if err := checkShareKind(path, mode); err != nil {
		fmt.Fprintln(env.stderr, "k3sm share add:", err)
		return 1
	}
	kept := slices.DeleteFunc(slices.Clone(entries), func(x hostshare.Entry) bool { return x.Path == path })
	kept = append(kept, e)
	if err := env.write(env.file, hostshare.Format(kept)); err != nil {
		fmt.Fprintln(env.stderr, "k3sm share add:", err)
		return 1
	}
	fmt.Fprintf(env.stdout, "shared %s (%s)\n", path, mode)
	if mode == hostshare.ModeReadWrite {
		fmt.Fprint(env.stdout, shareACLHint(path, os.Getenv("SUDO_USER")))
	}
	return 0
}

// resolveSharePath makes p absolute and, when it must exist, resolves every
// symlink, because the node admits only a path that resolves to itself.
func resolveSharePath(p string, mustExist bool) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if !mustExist {
		return filepath.Clean(abs), nil
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("%s: %w", p, err)
	}
	return resolved, nil
}

func checkShareKind(path string, mode hostshare.Mode) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	switch {
	case mode == hostshare.ModeSocket && fi.Mode()&os.ModeSocket == 0:
		return fmt.Errorf("%s is not a Unix socket", path)
	case mode != hostshare.ModeSocket && !fi.IsDir():
		return fmt.Errorf("%s is not a directory", path)
	}
	return nil
}

// shareACLHint is the command that lets the pods' user write under path while
// the invoking user keeps full access to what pods create. It is printed, not
// run: it changes permissions on the user's own tree.
func shareACLHint(path, user string) string {
	if user == "" || user == "root" {
		user = "<you>"
	}
	const perms = "read,write,append,delete,add_file,add_subdirectory,delete_child,readattr,writeattr,readextattr,writeextattr,readsecurity,list,search,file_inherit,directory_inherit"
	var b strings.Builder
	b.WriteString("pods run as _k3sm; to let them write here (and keep your own access to what they create), run:\n")
	fmt.Fprintf(&b, "  chmod -R +a \"user:_k3sm allow %s\" %q\n", perms, path)
	fmt.Fprintf(&b, "  chmod -R +a \"user:%s allow %s\" %q\n", user, perms, path)
	return b.String()
}

// writeRootFileAtomic writes data to path through a temp file in the same
// directory and a rename, mode 0644, so a reader never sees a torn list. The
// file is created by root, which is what makes hostshare.Load trust it.
func writeRootFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return errors.Join(fmt.Errorf("install %s", path), err)
	}
	return nil
}
