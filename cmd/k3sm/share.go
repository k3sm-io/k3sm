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
	"os/user"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"k3sm.io/k3sm/internal/hostacl"
	"k3sm.io/k3sm/pkg/defaults"
	"k3sm.io/runtimed/pkg/hostshare"
)

// shareUsage is `k3sm share --help`. It is the command's own help, so it
// names the files the node reads.
const shareUsage = `Usage:
  k3sm share add [--read-only|--socket] [--no-acl] <path>
                                        share a directory read-write (or
                                        read-only, or one Unix socket)
  k3sm share remove [--no-acl] <path>   stop sharing a path
  k3sm share list                       print the shares and delegations (also: ls)
  sudo k3sm share delegate --user <name> [--modes rw,ro,socket] <prefix>
                                        let <name> add shares under <prefix>
                                        without sudo
  sudo k3sm share undelegate --user <name> [<prefix>]
                                        take a delegation back, and with it
                                        the shares <name> made under it

A host share lets a native pod mount a host path with a hostPath volume. Native
pods have no mount namespace, so a share is visible only at its own path: the
pod mounts it with mountPath equal to hostPath.path, and no subPath. Without a
share, a hostPath volume is refused (FailedHostShare on the pod).

Who may add a share. Root, with sudo, anywhere the rules below allow; the list
is ` + hostshare.DefaultFile + `, owned by root and writable by root alone. Or a
user root delegated a prefix to: that user runs 'k3sm share add' with no sudo
for paths under the prefix, and their list lives in a file they own,
` + hostshare.DefaultFile + `.d/<uid>/host-shares. The node re-checks every line
of that file on every pod create against the root-owned delegation: inside the
prefix, no symlink anywhere in the path, every directory from the prefix down
owned by that user. Editing the file by hand admits nothing more.

The list is read when a pod is created, so a change applies to pods created
after it; a pod that is running keeps what it was given until it is recreated,
and a removed share is not given back to a pod the node re-attaches after a
restart.

A directory share covers everything under it. Under /Users a share must be
below a home directory (a project, never the home itself), and may not name a
dot directory or the home's Library. System and k3sm trees are refused. A
delegated prefix follows the same rules.

Pods run as the _k3sm user, not as you. 'add' sets the access-control entries
_k3sm needs on the shared tree (read-write: an inheritable entry for _k3sm, and
the same for you, so you keep full access to what pods create; read-only: read
for _k3sm; socket: connect), and search on any parent directory you own that
_k3sm cannot pass through. It prints exactly what it changed. It never follows
a symlink or crosses a mount point, and it leaves hard-linked files and files
you do not own alone. Run as root, it leaves a socket's entry to the socket's
owner and prints the command. Paths on a case-sensitive volume are refused.
'remove' takes the _k3sm entries back, unless another share still covers the
path. --no-acl leaves permissions alone. Files a pod creates are owned by _k3sm.

Every grant is recorded: a HostShareGranted Event on the pod, and a
"host share granted" line in the node log (with the delegated uid, when a
delegated entry admitted it).

Exit codes: 0 done; 1 failed; 2 usage; 3 not permitted (not root, and no
delegation covers the path).
`

// aclOps is the permission half of a share, so a test can fake it.
type aclOps interface {
	GrantTree(root string, a hostacl.Access, podUID, owner uint32) (hostacl.Report, error)
	RevokeTree(root string, podUID, owner uint32) (hostacl.Report, error)
	GrantSocket(path string, podUID uint32) (bool, error)
	RevokeSocket(path string, podUID uint32) (bool, error)
	GrantSearch(dir string, podUID uint32) (bool, error)
	RevokeSearch(dir string, podUID uint32) (bool, error)
	Allowed(path string, uid uint32) (hostacl.Perm, error)
}

type realACL struct{}

func (realACL) GrantTree(r string, a hostacl.Access, p, o uint32) (hostacl.Report, error) {
	return hostacl.GrantTree(r, a, p, o)
}
func (realACL) RevokeTree(r string, p, o uint32) (hostacl.Report, error) {
	return hostacl.RevokeTree(r, p, o)
}
func (realACL) GrantSocket(p string, u uint32) (bool, error)  { return hostacl.GrantSocket(p, u) }
func (realACL) RevokeSocket(p string, u uint32) (bool, error) { return hostacl.RevokeSocket(p, u) }
func (realACL) GrantSearch(d string, u uint32) (bool, error)  { return hostacl.GrantSearch(d, u) }
func (realACL) RevokeSearch(d string, u uint32) (bool, error) { return hostacl.RevokeSearch(d, u) }
func (realACL) Allowed(p string, u uint32) (hostacl.Perm, error) {
	return hostacl.Allowed(p, u)
}

// account is a local user, as the share verb needs one.
type account struct {
	name string
	uid  uint32
	gid  uint32
	gids []uint32
}

// shareEnv is what the share verb touches, so a test can fake it.
type shareEnv struct {
	file string
	euid func() int
	uid  func() int
	// readFile reads the root-owned node file (entries and delegations).
	readFile func(string) (hostshare.File, error)
	// effective is what the node admits now (hostshare.LoadEffective).
	effective func(string) (hostshare.Effective, error)
	// readUser reads a delegated uid's own file as written.
	readUser func(file string, uid uint32) ([]hostshare.Entry, error)
	// checkDelegated is hostshare.CheckDelegated.
	checkDelegated func(hostshare.Delegation, hostshare.Entry) error
	write          func(string, []byte) error
	// makeUserDir creates <file>.d (root-owned) and <file>.d/<uid> owned
	// by the account; removeUserDir removes the latter.
	makeUserDir   func(file string, a account) error
	removeUserDir func(file string, uid uint32) error
	lookup        func(name string) (account, error)
	lookupUID     func(uid uint32) (account, error)
	acl           aclOps
	stdout        io.Writer
	stderr        io.Writer
}

func defaultShareEnv(stdout, stderr io.Writer) shareEnv {
	return shareEnv{
		file:           hostshare.DefaultFile,
		euid:           os.Geteuid,
		uid:            os.Getuid,
		readFile:       hostshare.LoadFile,
		effective:      loadEffectiveAsNode,
		readUser:       hostshare.LoadUserFile,
		checkDelegated: hostshare.CheckDelegated,
		write:          writeShareFile,
		makeUserDir:    makeUserDir,
		removeUserDir:  removeUserDir,
		lookup:         lookupAccount,
		lookupUID:      func(uid uint32) (account, error) { return lookupAccountUID(uid) },
		acl:            realACL{},
		stdout:         stdout,
		stderr:         stderr,
	}
}

func runShare(args []string, stdout, stderr io.Writer) int {
	return runShareWith(args, defaultShareEnv(stdout, stderr))
}

type shareFlags struct {
	readOnly, socket, noACL bool
	user, modes             string
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
	case "list", "ls":
		return shareList(env)
	case "add", "remove", "delegate", "undelegate":
	default:
		fmt.Fprintf(env.stderr, "k3sm share: unknown command %q\n\n%s", verb, shareUsage)
		return 2
	}
	fs := flag.NewFlagSet("share "+verb, flag.ContinueOnError)
	fs.SetOutput(env.stderr)
	var f shareFlags
	switch verb {
	case "add":
		fs.BoolVar(&f.readOnly, "read-only", false, "share the directory read-only")
		fs.BoolVar(&f.socket, "socket", false, "share one Unix socket")
		fs.BoolVar(&f.noACL, "no-acl", false, "leave file permissions alone")
	case "remove":
		fs.BoolVar(&f.noACL, "no-acl", false, "leave file permissions alone")
	case "delegate", "undelegate":
		fs.StringVar(&f.user, "user", "", "the account the prefix is delegated to")
		if verb == "delegate" {
			fs.StringVar(&f.modes, "modes", "rw,ro,socket", "the share modes the user may add")
		}
	}
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	switch {
	case verb == "undelegate" && fs.NArg() > 1, verb != "undelegate" && fs.NArg() != 1:
		fmt.Fprintf(env.stderr, "k3sm share %s: want exactly one path\n", verb)
		return 2
	case f.readOnly && f.socket:
		fmt.Fprintln(env.stderr, "k3sm share add: --read-only and --socket do not combine")
		return 2
	case (verb == "delegate" || verb == "undelegate") && f.user == "":
		fmt.Fprintf(env.stderr, "k3sm share %s: --user is required\n", verb)
		return 2
	}
	root := env.euid() == 0
	switch verb {
	case "delegate", "undelegate":
		if !root {
			fmt.Fprintf(env.stderr, "k3sm share %s: run as root (sudo k3sm share %s ...): delegations live in the root-owned %s\n", verb, verb, env.file)
			return 3
		}
		if verb == "delegate" {
			return shareDelegate(env, f, fs.Arg(0))
		}
		return shareUndelegate(env, f, fs.Arg(0))
	}
	s := &sharer{env: env, f: f, root: root}
	if verb == "add" {
		return s.add(fs.Arg(0))
	}
	return s.remove(fs.Arg(0))
}

// sharer runs add and remove, as root on the node file or as a delegated
// user on their own file.
type sharer struct {
	env  shareEnv
	f    shareFlags
	root bool
}

func (s *sharer) fail(verb string, err error) int {
	fmt.Fprintf(s.env.stderr, "k3sm share %s: %v\n", verb, err)
	return 1
}

func (s *sharer) add(arg string) int {
	mode := hostshare.ModeReadWrite
	switch {
	case s.f.readOnly:
		mode = hostshare.ModeReadOnly
	case s.f.socket:
		mode = hostshare.ModeSocket
	}
	path, err := canonicalSharePath(arg, mode)
	if err != nil {
		return s.fail("add", err)
	}
	e := hostshare.Entry{Mode: mode, Path: path}
	if err := hostshare.ValidateEntry(e); err != nil {
		return s.fail("add", err)
	}
	if err := checkShareKind(path, mode); err != nil {
		return s.fail("add", err)
	}
	if !hostshare.FoldsCase(path) {
		return s.fail("add", fmt.Errorf("%s is on a case-sensitive volume, which the node does not share: the sandbox matches paths without regard to case, so a share there would also reach other names", path))
	}
	nf, err := s.env.readFile(s.env.file)
	if err != nil {
		return s.fail("add", err)
	}
	var owner uint32
	if s.root {
		kept := slices.DeleteFunc(slices.Clone(nf.Entries), func(x hostshare.Entry) bool { return x.Path == path })
		nf.Entries = append(kept, e)
		if err := s.env.write(s.env.file, hostshare.FormatFile(nf)); err != nil {
			return s.fail("add", err)
		}
		fmt.Fprintf(s.env.stdout, "shared %s (%s)\n", path, mode)
		if owner, err = ownerOf(path); err != nil {
			return s.fail("add", err)
		}
	} else {
		owner = uint32(s.env.uid())
		mine := delegationsFor(nf, owner)
		if len(mine) == 0 {
			fmt.Fprintf(s.env.stderr, "k3sm share add: you are not root and no prefix is delegated to you (uid %d); "+
				"the node admin runs once: sudo k3sm share delegate --user <you> <prefix>\n", owner)
			return 3
		}
		var why error
		var by *hostshare.Delegation
		for i := range mine {
			err := s.env.checkDelegated(mine[i], e)
			if err == nil {
				by = &mine[i]
				break
			}
			if why == nil || hostshare.AtOrUnder(path, mine[i].Prefix) {
				why = err
			}
		}
		if by == nil {
			if !slices.ContainsFunc(mine, func(d hostshare.Delegation) bool { return hostshare.AtOrUnder(path, d.Prefix) }) {
				fmt.Fprintf(s.env.stderr, "k3sm share add: %s is outside your delegated prefixes (%s)\n", path, prefixes(mine))
				return 3
			}
			return s.fail("add", why)
		}
		entries, err := s.env.readUser(s.env.file, owner)
		if err != nil {
			return s.fail("add", err)
		}
		entries = slices.DeleteFunc(entries, func(x hostshare.Entry) bool { return x.Path == path })
		entries = append(entries, e)
		if err := s.env.write(hostshare.UserFile(s.env.file, owner), hostshare.FormatUser(entries)); err != nil {
			return s.fail("add", err)
		}
		fmt.Fprintf(s.env.stdout, "shared %s (%s), delegated under %s; listed in %s\n", path, mode, by.Prefix, hostshare.UserFile(s.env.file, owner))
	}
	if s.f.noACL {
		fmt.Fprintln(s.env.stdout, "acl: not changed (--no-acl); pods run as _k3sm and need permission to reach the path")
		return 0
	}
	if err := s.grantACL(e, owner); err != nil {
		fmt.Fprintf(s.env.stderr, "k3sm share add: the share is recorded, but setting permissions failed: %v\n", err)
		return 1
	}
	return 0
}

func (s *sharer) remove(arg string) int {
	path, err := resolveSharePath(arg, false)
	if err != nil {
		return s.fail("remove", err)
	}
	nf, err := s.env.readFile(s.env.file)
	if err != nil {
		return s.fail("remove", err)
	}
	var removed []hostshare.Entry
	var owner uint32
	if s.root {
		kept := slices.DeleteFunc(slices.Clone(nf.Entries), func(e hostshare.Entry) bool { return e.Path == path })
		for _, e := range nf.Entries {
			if e.Path == path {
				removed = append(removed, e)
			}
		}
		if len(removed) == 0 {
			fmt.Fprintf(s.env.stderr, "k3sm share remove: %s is not in the node's list\n", path)
			return 1
		}
		nf.Entries = kept
		if err := s.env.write(s.env.file, hostshare.FormatFile(nf)); err != nil {
			return s.fail("remove", err)
		}
		if owner, err = ownerOf(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return s.fail("remove", err)
		}
	} else {
		owner = uint32(s.env.uid())
		entries, err := s.env.readUser(s.env.file, owner)
		if err != nil {
			return s.fail("remove", err)
		}
		kept := slices.DeleteFunc(slices.Clone(entries), func(e hostshare.Entry) bool { return e.Path == path })
		for _, e := range entries {
			if e.Path == path {
				removed = append(removed, e)
			}
		}
		if len(removed) == 0 {
			if len(delegationsFor(nf, owner)) == 0 {
				fmt.Fprintf(s.env.stderr, "k3sm share remove: you are not root and no prefix is delegated to you (uid %d)\n", owner)
				return 3
			}
			fmt.Fprintf(s.env.stderr, "k3sm share remove: %s is not in your list\n", path)
			return 1
		}
		if err := s.env.write(hostshare.UserFile(s.env.file, owner), hostshare.FormatUser(kept)); err != nil {
			return s.fail("remove", err)
		}
	}
	fmt.Fprintf(s.env.stdout, "stopped sharing %s; pods that already mount it keep it until they are recreated\n", path)
	if s.f.noACL {
		fmt.Fprintln(s.env.stdout, "acl: not changed (--no-acl)")
		return 0
	}
	if _, err := os.Lstat(path); err != nil {
		fmt.Fprintf(s.env.stdout, "acl: %s is gone; nothing to revoke\n", path)
		return 0
	}
	eff, err := s.env.effective(s.env.file)
	if err != nil {
		return s.fail("remove", err)
	}
	if err := revokeACL(s.env, removed[0], owner, eff.Entries); err != nil {
		fmt.Fprintf(s.env.stderr, "k3sm share remove: the share is gone, but revoking permissions failed: %v\n", err)
		return 1
	}
	return 0
}

// grantACL sets what the pods' user needs to reach e and prints it.
func (s *sharer) grantACL(e hostshare.Entry, owner uint32) error {
	pod, err := s.env.lookup(defaults.ServiceUser)
	if err != nil {
		return fmt.Errorf("look up %s: %w", defaults.ServiceUser, err)
	}
	own, err := s.env.lookupUID(owner)
	if err != nil {
		own = account{name: strconv.FormatUint(uint64(owner), 10), uid: owner}
	}
	out := s.env.stdout
	switch e.Mode {
	case hostshare.ModeSocket:
		if s.root {
			// A socket cannot be opened, so its entry is set by path, and
			// a path through directories its owner controls can be raced
			// to another file while root acts on it. The owner sets it.
			fmt.Fprintf(out, "acl: %s: not changed as root; as its owner run: chmod +a \"user:%s allow read,write\" %q\n", e.Path, pod.name, e.Path)
			break
		}
		changed, err := s.env.acl.GrantSocket(e.Path, pod.uid)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "acl: %s: %s \"user:%s allow read,write\" (connect)\n", e.Path, addedWord(changed), pod.name)
	default:
		a := hostacl.ReadWrite
		if e.Mode == hostshare.ModeReadOnly {
			a = hostacl.ReadOnly
		}
		r, err := s.env.acl.GrantTree(e.Path, a, pod.uid, owner)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "acl: %s: added %q on %d directories and %q on %d files", e.Path, a.DirEntry(pod.name), r.Dirs, a.FileEntry(pod.name), r.Files)
		if a == hostacl.ReadWrite {
			fmt.Fprintf(out, ", and the same for user:%s", own.name)
		}
		fmt.Fprintf(out, "; %d already had it%s\n", r.Unchanged, skipped(r))
	}
	return s.grantParents(e.Path, owner, pod)
}

// grantParents gives the pods' user search on every directory above path
// that owner owns and that user cannot already pass through.
func (s *sharer) grantParents(path string, owner uint32, pod account) error {
	changed := 0
	for _, dir := range ancestors(path) {
		fi, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		uid, gid := statIDs(fi)
		if searchableBy(fi, pod) {
			continue
		}
		if uid != owner {
			if p, err := s.env.acl.Allowed(dir, pod.uid); err == nil && p&hostacl.Search != 0 {
				continue
			}
			fmt.Fprintf(s.env.stdout, "acl: warning: %s (owner uid %d, group %d) may not let %s pass, and is not yours to change\n", dir, uid, gid, pod.name)
			continue
		}
		added, err := s.env.acl.GrantSearch(dir, pod.uid)
		if err != nil {
			return fmt.Errorf("%s: %w", dir, err)
		}
		if added {
			changed++
			fmt.Fprintf(s.env.stdout, "acl: %s: added \"user:%s allow search\"\n", dir, pod.name)
		}
	}
	if changed == 0 {
		fmt.Fprintf(s.env.stdout, "acl: no parent directory needed a change (%s can pass through every directory above %s)\n", pod.name, path)
	}
	return nil
}

// revokeACL takes back what grantACL set for e, unless a share that remains
// (root's or any delegated user's) still covers e's path or lies under it,
// and removes the search entries on owner's parent directories that no
// remaining share needs.
func revokeACL(env shareEnv, e hostshare.Entry, owner uint32, remaining []hostshare.Entry) error {
	pod, err := env.lookup(defaults.ServiceUser)
	if err != nil {
		return fmt.Errorf("look up %s: %w", defaults.ServiceUser, err)
	}
	out := env.stdout
	for _, r := range remaining {
		if hostshare.AtOrUnder(e.Path, r.Path) || hostshare.AtOrUnder(r.Path, e.Path) {
			fmt.Fprintf(out, "acl: %s: left as it is; the share %s still covers it\n", e.Path, r)
			return nil
		}
	}
	if e.Mode == hostshare.ModeSocket && env.euid() == 0 {
		fmt.Fprintf(out, "acl: %s: not changed as root; its owner may run: chmod -a \"user:%s allow read,write\" %q\n", e.Path, pod.name, e.Path)
	} else if e.Mode == hostshare.ModeSocket {
		changed, err := env.acl.RevokeSocket(e.Path, pod.uid)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "acl: %s: %s the %s entries\n", e.Path, removedWord(changed), pod.name)
	} else {
		r, err := env.acl.RevokeTree(e.Path, pod.uid, owner)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "acl: %s: removed the user:%s entries from %d directories and %d files; %d had none%s; your own entries stay\n",
			e.Path, pod.name, r.Dirs, r.Files, r.Unchanged, skipped(r))
	}
	for _, dir := range ancestors(e.Path) {
		fi, err := os.Lstat(dir)
		if err != nil {
			continue
		}
		if uid, _ := statIDs(fi); uid != owner {
			continue
		}
		needed := slices.ContainsFunc(remaining, func(r hostshare.Entry) bool { return hostshare.AtOrUnder(r.Path, dir) })
		if needed {
			continue
		}
		if p, err := env.acl.Allowed(dir, pod.uid); err != nil || p&hostacl.Search == 0 {
			continue
		}
		if changed, err := env.acl.RevokeSearch(dir, pod.uid); err != nil {
			return fmt.Errorf("%s: %w", dir, err)
		} else if changed {
			fmt.Fprintf(out, "acl: %s: removed \"user:%s allow search\" (no remaining share is under it)\n", dir, pod.name)
		}
	}
	return nil
}

func shareDelegate(env shareEnv, f shareFlags, arg string) int {
	fail := func(err error) int {
		fmt.Fprintln(env.stderr, "k3sm share delegate:", err)
		return 1
	}
	acct, err := env.lookup(f.user)
	if err != nil {
		return fail(err)
	}
	modes, err := hostshare.ParseModes(f.modes)
	if err != nil {
		return fail(err)
	}
	prefix, err := canonicalSharePath(arg, hostshare.ModeReadWrite)
	if err != nil {
		return fail(err)
	}
	if !hostshare.FoldsCase(prefix) {
		return fail(fmt.Errorf("%s is on a case-sensitive volume, which the node does not share", prefix))
	}
	d := hostshare.Delegation{UID: acct.uid, User: acct.name, Modes: modes, Prefix: prefix}
	if err := hostshare.ValidateDelegation(d); err != nil {
		return fail(err)
	}
	fi, err := os.Lstat(prefix)
	if err != nil {
		return fail(err)
	}
	if uid, _ := statIDs(fi); !fi.IsDir() || uid != acct.uid {
		return fail(fmt.Errorf("%s must be a directory owned by %s (uid %d): a delegated user may share only what they own", prefix, acct.name, acct.uid))
	}
	nf, err := env.readFile(env.file)
	if err != nil {
		return fail(err)
	}
	nf.Delegations = slices.DeleteFunc(nf.Delegations, func(x hostshare.Delegation) bool {
		return x.UID == d.UID && x.Prefix == d.Prefix
	})
	nf.Delegations = append(nf.Delegations, d)
	if err := env.makeUserDir(env.file, acct); err != nil {
		return fail(err)
	}
	if err := env.write(env.file, hostshare.FormatFile(nf)); err != nil {
		return fail(err)
	}
	fmt.Fprintf(env.stdout, "delegated %s to %s (uid %d) for %s\n", prefix, acct.name, acct.uid, f.modes)
	fmt.Fprintf(env.stdout, "%s now runs 'k3sm share add <path>' (no sudo) for paths under %s; their list is %s\n",
		acct.name, prefix, hostshare.UserFile(env.file, acct.uid))
	return 0
}

func shareUndelegate(env shareEnv, f shareFlags, arg string) int {
	fail := func(err error) int {
		fmt.Fprintln(env.stderr, "k3sm share undelegate:", err)
		return 1
	}
	acct, err := env.lookup(f.user)
	if err != nil {
		return fail(err)
	}
	prefix := ""
	if arg != "" {
		if prefix, err = resolveSharePath(arg, false); err != nil {
			return fail(err)
		}
	}
	nf, err := env.readFile(env.file)
	if err != nil {
		return fail(err)
	}
	before, err := env.effective(env.file)
	if err != nil {
		return fail(err)
	}
	n := len(nf.Delegations)
	nf.Delegations = slices.DeleteFunc(nf.Delegations, func(d hostshare.Delegation) bool {
		return d.UID == acct.uid && (prefix == "" || d.Prefix == prefix)
	})
	if len(nf.Delegations) == n {
		return fail(fmt.Errorf("no delegation to %s%s", acct.name, map[bool]string{true: "", false: " of " + prefix}[prefix == ""]))
	}
	if err := env.write(env.file, hostshare.FormatFile(nf)); err != nil {
		return fail(err)
	}
	fmt.Fprintf(env.stdout, "took back %d delegation(s) from %s; their shares under it stop at the next pod create\n", n-len(nf.Delegations), acct.name)
	after, err := env.effective(env.file)
	if err != nil {
		return fail(err)
	}
	for e, uid := range before.Owners {
		if uid != acct.uid || slices.Contains(after.Entries, e) {
			continue
		}
		if _, err := os.Lstat(e.Path); err != nil {
			continue
		}
		if err := revokeACL(env, e, acct.uid, after.Entries); err != nil {
			fmt.Fprintf(env.stderr, "k3sm share undelegate: revoking permissions on %s: %v\n", e.Path, err)
		}
	}
	if len(delegationsFor(nf, acct.uid)) == 0 {
		if err := env.removeUserDir(env.file, acct.uid); err != nil {
			fmt.Fprintln(env.stderr, "k3sm share undelegate: warning:", err)
		} else {
			fmt.Fprintf(env.stdout, "removed %s\n", hostshare.UserDir(env.file, acct.uid))
		}
	}
	return 0
}

func shareList(env shareEnv) int {
	eff, err := env.effective(env.file)
	if err != nil {
		fmt.Fprintln(env.stderr, "k3sm share list:", err)
		return 1
	}
	if len(eff.Entries) == 0 && len(eff.Delegations) == 0 && len(eff.Dropped) == 0 {
		fmt.Fprintln(env.stdout, "no host shares (pods cannot mount a hostPath volume on this node)")
		return 0
	}
	names := map[uint32]string{}
	for _, d := range eff.Delegations {
		names[d.UID] = d.User
	}
	for _, e := range eff.Entries {
		if uid, ok := eff.Owners[e]; ok {
			fmt.Fprintf(env.stdout, "%s\t(added by %s, uid %d, under a delegation)\n", e, names[uid], uid)
		} else {
			fmt.Fprintf(env.stdout, "%s\t(root)\n", e)
		}
	}
	for _, d := range eff.Delegations {
		fmt.Fprintln(env.stdout, d)
	}
	sort.SliceStable(eff.Dropped, func(i, j int) bool { return eff.Dropped[i].UID < eff.Dropped[j].UID })
	for _, d := range eff.Dropped {
		what := "the user's list"
		if d.Entry.Path != "" {
			what = d.Entry.String()
		}
		fmt.Fprintf(env.stdout, "not admitted (uid %d): %s: %s\n", d.UID, what, d.Reason)
	}
	return 0
}

func delegationsFor(f hostshare.File, uid uint32) []hostshare.Delegation {
	var out []hostshare.Delegation
	for _, d := range f.Delegations {
		if d.UID == uid {
			out = append(out, d)
		}
	}
	return out
}

func prefixes(ds []hostshare.Delegation) string {
	var ps []string
	for _, d := range ds {
		ps = append(ps, d.Prefix)
	}
	return strings.Join(ps, ", ")
}

func addedWord(changed bool) string {
	if changed {
		return "added"
	}
	return "already had"
}

func removedWord(changed bool) string {
	if changed {
		return "removed"
	}
	return "found none of"
}

func skipped(r hostacl.Report) string {
	if len(r.Skipped) == 0 {
		return ""
	}
	var parts []string
	for why, n := range r.Skipped {
		parts = append(parts, fmt.Sprintf("%d %s", n, why))
	}
	sort.Strings(parts)
	return "; left alone: " + strings.Join(parts, ", ")
}

// ancestors lists the directories above path, from / down to its parent.
func ancestors(path string) []string {
	var out []string
	for d := filepath.Dir(path); ; d = filepath.Dir(d) {
		out = append([]string{d}, out...)
		if d == "/" {
			return out
		}
	}
}

func statIDs(fi os.FileInfo) (uid, gid uint32) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Uid, st.Gid
	}
	return ^uint32(0), ^uint32(0)
}

// searchableBy reports whether a's mode bits let it pass through the
// directory fi (owner, group or other execute bit, whichever applies).
func searchableBy(fi os.FileInfo, a account) bool {
	uid, gid := statIDs(fi)
	m := fi.Mode().Perm()
	switch {
	case uid == a.uid:
		return m&0o100 != 0
	case gid == a.gid || slices.Contains(a.gids, gid):
		return m&0o010 != 0
	}
	return m&0o001 != 0
}

func ownerOf(path string) (uint32, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}
	uid, _ := statIDs(fi)
	return uid, nil
}

func lookupAccount(name string) (account, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return account{}, err
	}
	return toAccount(u)
}

func lookupAccountUID(uid uint32) (account, error) {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return account{}, err
	}
	return toAccount(u)
}

func toAccount(u *user.User) (account, error) {
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return account{}, err
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return account{}, err
	}
	a := account{name: u.Username, uid: uint32(uid), gid: uint32(gid)}
	if ids, err := u.GroupIds(); err == nil {
		for _, s := range ids {
			if g, err := strconv.ParseUint(s, 10, 32); err == nil {
				a.gids = append(a.gids, uint32(g))
			}
		}
	}
	return a, nil
}

// makeUserDir creates <file>.d, root-owned and writable by root alone, and
// <file>.d/<uid> owned by the account, mode 0755, so the user can replace
// their own file atomically but can neither remove their directory nor
// create one for anyone else.
func makeUserDir(file string, a account) error {
	parent := file + ".d"
	if err := os.Mkdir(parent, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	fi, err := os.Lstat(parent)
	if err != nil {
		return err
	}
	if uid, _ := statIDs(fi); !fi.IsDir() || uid != 0 {
		return fmt.Errorf("%s is not a root-owned directory; remove it and delegate again", parent)
	}
	if err := os.Chmod(parent, 0o755); err != nil {
		return err
	}
	dir := hostshare.UserDir(file, a.uid)
	if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	fi, err = os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if err := os.Lchown(dir, int(a.uid), int(a.gid)); err != nil {
		return err
	}
	return os.Chmod(dir, 0o755)
}

// canonicalSharePath resolves p (resolveSharePath) and spells it the way its
// volume stores each name, because the node compares a pod's hostPath with
// an entry exactly. For a socket the parent directory is canonicalised and
// the name kept as given.
func canonicalSharePath(p string, mode hostshare.Mode) (string, error) {
	path, err := resolveSharePath(p, true)
	if err != nil {
		return "", err
	}
	if mode == hostshare.ModeSocket {
		dir, err := hostacl.CanonicalDir(filepath.Dir(path))
		if err != nil {
			return "", err
		}
		return filepath.Join(dir, filepath.Base(path)), nil
	}
	fi, err := os.Lstat(path)
	if err != nil || !fi.IsDir() {
		return path, nil
	}
	return hostacl.CanonicalDir(path)
}

// loadEffectiveAsNode is hostshare.LoadEffective as the node sees it, run by
// whoever calls `k3sm share`: the uid never admitted as a delegated user is
// the node's own service user, not the caller.
func loadEffectiveAsNode(file string) (hostshare.Effective, error) {
	pod, err := lookupAccount(defaults.ServiceUser)
	if err != nil {
		return hostshare.Effective{}, fmt.Errorf("look up %s: %w", defaults.ServiceUser, err)
	}
	return hostshare.LoadEffectiveFor(file, pod.uid)
}

// removeUserDir removes a delegated uid's directory as root without
// descending into it: only the user's list and the temp files the share verb
// leaves are unlinked, then the directory itself. Anything else the user put
// there (a mount point, another file) is left, and reported.
func removeUserDir(file string, uid uint32) error {
	dir := hostshare.UserDir(file, uid)
	fi, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	names, err := d.Readdirnames(-1)
	d.Close()
	if err != nil {
		return err
	}
	list := filepath.Base(hostshare.UserFile(file, uid))
	for _, n := range names {
		if n != list && !strings.HasPrefix(n, "."+list+".") {
			continue
		}
		p := filepath.Join(dir, n)
		if fi, err := os.Lstat(p); err == nil && (fi.Mode().IsRegular() || fi.Mode()&os.ModeSymlink != 0) {
			if err := os.Remove(p); err != nil {
				return err
			}
		}
	}
	if err := os.Remove(dir); err != nil {
		return fmt.Errorf("%s holds files the share verb did not write; left in place (the node ignores it without a delegation): %w", dir, err)
	}
	return nil
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

// writeShareFile writes data to path through a temp file in the same
// directory and a rename, mode 0644, so a reader never sees a torn list.
// Root writes the node file this way; a delegated user writes their own file
// in the directory root made for them.
func writeShareFile(path string, data []byte) error {
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
