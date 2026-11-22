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
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/keystore"
	keydeliver "k3sm.io/k3sm/pkg/keystore/deliver"
	"k3sm.io/k3sm/pkg/status"
)

// keysUsage is `k3sm keys --help`.
const keysUsage = `Usage:
  sudo k3sm keys put system/<name> [--kind opaque|ed25519] [--in FILE|-]
        create the entry at version 1; the value is read from FILE, or from
        stdin with "-" (the default), never from an argument
  sudo k3sm keys list [-o table|json]
        one line per entry: name, kind, current version, created (UTC),
        fingerprint and status (ok, or corrupt with the reason); exits 1 if
        any entry is corrupt
  sudo k3sm keys show system/<name> [--version N] [--reveal [--yes]]
        print an entry's metadata; with --reveal, print only the stored
        value, byte for byte, with no newline added (to a terminal, only
        with --yes)
  sudo k3sm keys rotate system/<name> [--in FILE|- | --from-version N]
        store a new version and make it current: a value read as put reads
        it, or with --from-version a copy of version N's bytes, made inside
        k3sm so the value is never printed
  sudo k3sm keys rm system/<name> --yes
        delete the entry and every version; irreversible
  sudo k3sm keys rewrap --key-out FILE | --key-in FILE
        re-seal every entry under a new master key. --key-out writes the new
        key k3sm mints to FILE (a new file, mode 0600, in a directory only
        root can write, never a synced or Time Machine path) before anything
        changes; keep it until rewrap reports success, then delete it. A
        rewrap that fails before sealing anything under the key deletes it.
        --key-in FILE only finishes an interrupted rewrap, with the key its
        --key-out saved: the recorded master.next.sha256, or a key some
        record already opens under; any other key is refused
  sudo k3sm keys floor merge [--keep system/<name>]... [--accept-drops]
        after a restore, before k3sm start: merge every deleted generation
        the floor you moved aside to keystore-floor.json.pre-restore in the
        data root records (the only file it reads) into the restored floor, so keys revoked since the backup stay
        refused. A restored entry deleted since the backup is deleted again
        (buried live); --keep, repeatable, keeps that entry's restored
        version live instead, for an entry you are restoring on purpose.
        Until it runs, put, rotate and rewrap refuse; once written, the
        file is renamed to keystore-floor.json.merged-<unix>. A merge that
        would drop a deletion since the backup to fit the floor refuses;
        --accept-drops writes it anyway, dropping the oldest deletions,
        printing each one, and exits 4
  sudo k3sm keys deliver system/<name> --namespace NS [--secret S] [--data-key K]
        declare that the server delivers the entry's current version as an
        Opaque Secret S (default: <name>) in NS, under data key K
        (default: value); the entry must exist. While secrets encryption is
        off the server refuses delivery unless it was started with
        --allow-plaintext-secrets-delivery
  sudo k3sm keys undeliver system/<name> --namespace NS [--secret S]
        withdraw the entry's delivery into NS (only into Secret S, with
        --secret). The Secret stays; delete it with kubectl, and rotate the
        entry to revoke

Names are scope-qualified: system/<name>, where <name> is 1 to 253 bytes of
dot-separated labels of lowercase letters, digits and '-'. This build
supports the system scope only.

A value never comes from the command line, where every local user could read
it with ps. Pipe it in, or keep it in a file only root can read:

  sudo k3sm keys put system/api-token --in /path/to/token
  issue-token-command | sudo k3sm keys put system/api-token --in -

Every verb runs as root. Values are capped at 64 KiB.

Flags:
  --work-dir <dir>  the server work dir (default ` + executor.DefaultWorkDir + `); the
                    data root is its parent

Exit codes: 0 done; 1 refused or failed; 2 usage; 3 rewrap completed an
earlier interrupted rewrap instead (run it again with a new key); 4 the verb
(put, rotate, rm, list, show or floor merge) is done, but the floor dropped a
recorded deletion to stay within its limits, so a copy of that deleted entry
put back is accepted; 5 floor merge written, input not renamed: rerun to
clear the guard (it wins over 4, and the report lists any drops).
`

// Exit codes of `k3sm keys`.
const (
	keysOK       = 0
	keysRefused  = 1
	keysBadUsage = 2
	// keysResumed is rewrap's ErrRewrapResumed: it finished an earlier
	// rewrap under a key the operator did not supply, so it must run again.
	keysResumed = 3
	// keysCommitted is a change that was made, but whose floor write
	// dropped a recorded deletion to stay within the floor's limits: a
	// committed keystore.ErrTombstoneEvicted from put, rotate or rm (its
	// tree left behind, or nothing found after a raise that pruned,
	// included), or a floor merge that reports a drop. list and show warn
	// of their floor raise's eviction on stderr and exit 0.
	keysCommitted = 4
	// keysNotRenamed is a floor merge that was written but whose input,
	// keystore-floor.json.pre-restore, was not renamed: the guard stays,
	// and a rerun clears it. It wins over keysCommitted; the report still
	// lists every burial dropped.
	keysNotRenamed = 5
)

// The keystore's two directories in the server work dir. pkg/keystore's
// Config documents them as <work dir>/keystore and
// <work dir>/cred/keystore-master; the cred dir comes from executor.CredDir,
// the same helper the secrets-encryption pair uses.
const (
	keystoreSubdir       = "keystore"
	keystoreMasterSubdir = "keystore-master"
)

// keysMasterSize is the master key's length, which Rewrap requires.
const keysMasterSize = 32

// keysStore is the slice of keystore.FileStore the keys verbs use: the Store
// contract, the floor raise the read verbs make at their start, and the two
// checks rewrap --key-in makes against an interrupted rewrap.
type keysStore interface {
	keystore.Store
	RaiseFloor(ctx context.Context) error
	InterruptedRewrap(ctx context.Context) (fingerprint [sha256.Size]byte, ok bool, err error)
	RecordsSealedUnder(ctx context.Context, key []byte) (bool, error)
	UserScopesExist(ctx context.Context) (bool, error)
	MergeFloor(ctx context.Context, opts keystore.MergeOptions) (keystore.MergeReport, error)
	MergePending() error
}

// keysEnv is what the keys verbs touch, so a test can fake it.
type keysEnv struct {
	euid func() int
	// serviceIDs resolves the service user the store's files belong to.
	serviceIDs func() (uid, gid uint32, err error)
	open       func(cfg keystore.Config) keysStore
	stdin      io.Reader
	stdinTTY   func() bool
	stdoutTTY  func() bool
	// rand is where rewrap draws a new master key.
	rand io.Reader
	// keyOutStep, when set, is called after each step of writing the
	// --key-out file ("chmod", "write", "sync"); a non-nil return fails the
	// write there, as the failing call would. Production leaves it nil.
	keyOutStep func(step string) error
	// deliveryCheck judges the opened delivery declaration; deliveryChown
	// hands a new one to root:wheel. A non-root test replaces both.
	deliveryCheck keydeliver.FileCheck
	deliveryChown func(f *os.File) error
	// deliveryLockBusy is the wait between attempts at the declaration's
	// lock while another writer holds it; nil is keydeliver.DefaultLockBusy.
	// deliveryRead, when set, is called after the declaration is read and
	// before it is written back, where a test parks a writer. Production
	// leaves both nil.
	deliveryLockBusy func() <-chan time.Time
	deliveryRead     func()
	// encryptionOn reports whether the server would start the work dir's
	// apiserver with secrets encryption.
	encryptionOn func(workDir string) bool
	stdout       io.Writer
	stderr       io.Writer
}

func defaultKeysEnv(stdout, stderr io.Writer) keysEnv {
	return keysEnv{
		euid:       os.Geteuid,
		serviceIDs: lookupServiceIDs,
		open:       func(cfg keystore.Config) keysStore { return keystore.New(cfg) },
		stdin:      os.Stdin,
		stdinTTY:   func() bool { return status.IsTerminal(os.Stdin) },
		stdoutTTY:  func() bool { return status.IsTerminal(os.Stdout) },
		rand:       rand.Reader,
		// The declaration is read with the manifest directory's check.
		deliveryCheck: keydeliver.RootCheck,
		deliveryChown: keydeliver.ChownRoot,
		encryptionOn:  encryptionOnAt,
		stdout:        stdout,
		stderr:        stderr,
	}
}

// lookupServiceIDs resolves the installed service user's uid and gid.
func lookupServiceIDs() (uid, gid uint32, err error) {
	u, err := user.Lookup(install.DefaultServiceUser)
	if err != nil {
		return 0, 0, fmt.Errorf("look up the service user %s (is k3sm installed?): %w", install.DefaultServiceUser, err)
	}
	id, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("uid of %s: %w", install.DefaultServiceUser, err)
	}
	g, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("gid of %s: %w", install.DefaultServiceUser, err)
	}
	return uint32(id), uint32(g), nil
}

func runKeys(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runKeysWith(ctx, args, defaultKeysEnv(stdout, stderr))
}

// keysVerb is one parsed verb: its flag set, its positional arguments, and
// the work dir every verb takes.
type keysVerb struct {
	name    string
	fs      *flag.FlagSet
	workDir *string
	env     keysEnv
	// badFlag is the defined flag whose value the last parse refused.
	badFlag string
	// roots are the work dir, MasterDir and DataRoot store derived from
	// --work-dir, in scrubPaths' order; failf scrubs them from every message.
	roots []string
}

// keysFlagValue wraps a defined flag's value so parse learns which flag
// refused its value, without reading the flag package's message, which
// quotes the value.
type keysFlagValue struct {
	flag.Value
	name string
	bad  *string
}

func (f keysFlagValue) Set(s string) error {
	err := f.Value.Set(s)
	if err != nil {
		*f.bad = f.name
	}
	return err
}

// IsBoolFlag keeps a wrapped bool flag usable without a value.
func (f keysFlagValue) IsBoolFlag() bool {
	b, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && b.IsBoolFlag()
}

func newKeysVerb(name string, env keysEnv) *keysVerb {
	fs := flag.NewFlagSet("keys "+name, flag.ContinueOnError)
	// The flag package's own messages quote the argument it refused, which
	// may be a value typed in the wrong place: parse prints its own.
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	return &keysVerb{
		name:    name,
		fs:      fs,
		workDir: fs.String("work-dir", executor.DefaultWorkDir, "the server work dir; the data root is its parent"),
		env:     env,
	}
}

// parse parses args with flags before, between or after the positional
// arguments (`show system/x --reveal`), and returns the positionals. A
// refusal is printed here, as a fixed line that names a defined flag at most
// and never echoes an argument.
func (v *keysVerb) parse(args []string) ([]string, error) {
	v.fs.VisitAll(func(f *flag.Flag) {
		if _, ok := f.Value.(keysFlagValue); !ok {
			f.Value = keysFlagValue{Value: f.Value, name: f.Name, bad: &v.badFlag}
		}
	})
	var pos []string
	for {
		if err := v.fs.Parse(args); err != nil {
			v.flagError(err)
			return nil, err
		}
		args = v.fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

// flagError prints a parse refusal: the usage for -h, else a fixed line.
func (v *keysVerb) flagError(err error) {
	switch {
	case errors.Is(err, flag.ErrHelp):
		fmt.Fprint(v.env.stderr, keysUsage)
	case v.badFlag != "":
		v.failf(keysBadUsage, "the value of --%s is not valid (it is not echoed); see k3sm keys --help", v.badFlag)
	default:
		v.failf(keysBadUsage, "a flag is not defined for this verb or is missing its value (it is not echoed); see k3sm keys --help")
	}
}

// failf prints a refusal. It is the one choke point for store errors: the
// message is scrubbed of the store's roots (scrubPaths) before it is printed.
func (v *keysVerb) failf(code int, format string, a ...any) int {
	fmt.Fprintf(v.env.stderr, "k3sm keys %s: %s\n", v.name, scrubPaths(fmt.Errorf(format, a...), v.roots...))
	return code
}

// evictedCode prints err and returns its exit code: keysCommitted for a
// change made whose floor write evicted tombstones (keystore.Committed and
// keystore.ErrTombstoneEvicted), which the verb then reports as done, and
// keysRefused for anything else.
func (v *keysVerb) evictedCode(err error) int {
	if keystore.Committed(err) && errors.Is(err, keystore.ErrTombstoneEvicted) {
		return v.failf(keysCommitted, "%v", err)
	}
	return v.failf(keysRefused, "%v", err)
}

// raiseForRead runs the floor raise list and show make first. Its write is
// not the change the operator asked for, so an eviction it made
// (keystore.ErrTombstoneEvicted) is a warning on stderr and keysOK; any
// other failure refuses the verb.
func (v *keysVerb) raiseForRead(ctx context.Context, s keysStore) int {
	err := s.RaiseFloor(ctx)
	switch {
	case err == nil:
		return keysOK
	case errors.Is(err, keystore.ErrTombstoneEvicted):
		fmt.Fprintf(v.env.stderr, "k3sm keys %s: warning: %s\n", v.name, scrubPaths(err, v.roots...))
		return keysOK
	}
	return v.failf(keysRefused, "%v", err)
}

// warnMergePending prints a warning on stderr while a restore is unfinished
// (s.MergePending): the read verbs still read the restored entries, which
// the merge may yet delete again.
func (v *keysVerb) warnMergePending(s keysStore) {
	if err := s.MergePending(); err != nil {
		fmt.Fprintf(v.env.stderr, "k3sm keys %s: warning: a restore is unfinished: these are the restored entries before sudo k3sm keys floor merge has run, which may delete some of them again (%s)\n", v.name, scrubPaths(err, v.roots...))
	}
}

// requireRoot refuses unless the verb runs as root: the master and entries
// belong to the service user, and the floor beside them to root.
func (v *keysVerb) requireRoot() int {
	if v.env.euid() == 0 {
		return keysOK
	}
	return v.failf(keysRefused, "run as root (sudo k3sm keys %s ...): the keystore belongs to the service user and its floor to root", v.name)
}

// store opens the store the install layout places under the work dir.
func (v *keysVerb) store() (keysStore, error) {
	work := filepath.Clean(*v.workDir)
	if !filepath.IsAbs(work) {
		return nil, errors.New("--work-dir is not an absolute path (the value given is not echoed)")
	}
	cfg := keystoreLayout(work)
	v.roots = []string{work, cfg.MasterDir, cfg.DataRoot}
	uid, gid, err := v.env.serviceIDs()
	if err != nil {
		return nil, err
	}
	cfg.UID, cfg.GID = uid, gid
	return v.env.open(cfg), nil
}

// keystoreLayout is the store's Config, without its owner, for the server
// work dir work (absolute and clean): the layout the keys verbs and the
// server's delivery reconciler both open.
func keystoreLayout(work string) keystore.Config {
	return keystore.Config{
		Dir:       filepath.Join(work, keystoreSubdir),
		MasterDir: filepath.Join(executor.CredDir(work), keystoreMasterSubdir),
		DataRoot:  executor.RuntimeRoot(work),
	}
}

// scrubTokens name scrubPaths' roots, by position.
var scrubTokens = []string{"<work-dir>", "<master-dir>", "<data-root>"}

// scrubPaths is err's text with every occurrence of each root, and of its
// resolved and /private-prefixed forms, replaced by its token: roots[0] the
// work dir (<work-dir>), roots[1] MasterDir (<master-dir>), roots[2]
// DataRoot (<data-root>). The store's errors name the paths it opened, all
// under --work-dir, which may be a value typed in the wrong place. Longer
// paths are replaced first, so a path inside another keeps its own token;
// a root is replaced only at a path boundary (replaceAtPathBoundary); "/" is
// never replaced.
func scrubPaths(err error, roots ...string) string {
	msg := err.Error()
	type sub struct{ from, to string }
	var subs []sub
	for i, r := range roots {
		if i >= len(scrubTokens) || r == "" || r == "/" {
			continue
		}
		forms := []string{r, "/private" + r}
		if real, err := filepath.EvalSymlinks(r); err == nil {
			forms = append(forms, real)
		}
		for _, f := range forms {
			subs = append(subs, sub{f, scrubTokens[i]})
		}
	}
	slices.SortStableFunc(subs, func(a, b sub) int { return len(b.from) - len(a.from) })
	for _, x := range subs {
		msg = replaceAtPathBoundary(msg, x.from, x.to)
	}
	return msg
}

// replaceAtPathBoundary replaces each from in msg that ends at a path
// boundary: followed by '/', the end, or a character no path component
// here holds. So a root /a/server is replaced in /a/server/x and in
// "/a/server: ...", but not in /a/server2/x, a different path.
func replaceAtPathBoundary(msg, from, to string) string {
	var b strings.Builder
	for {
		i := strings.Index(msg, from)
		if i < 0 {
			b.WriteString(msg)
			return b.String()
		}
		end := i + len(from)
		if end == len(msg) || !pathByte(msg[end]) {
			b.WriteString(msg[:i])
			b.WriteString(to)
		} else {
			b.WriteString(msg[:end])
		}
		msg = msg[end:]
	}
}

// pathByte reports whether c may continue a path component: a letter, a
// digit, or one of ._-~+@, the characters file names here use; '/' ends a
// component and so is a boundary.
func pathByte(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("._-~+@", c) >= 0
}

// errUserScope refuses a user/... name: the grammar exists, this build does
// not serve it.
var errUserScope = errors.New("user scopes are not supported by this build: use a system/<name> entry")

// errBadEntryName refuses a system/<name> whose name is not the store's
// grammar (keystore.CheckName), without echoing it.
var errBadEntryName = errors.New("the entry name is not valid (DNS-1123 subdomain); it is not echoed")

// parseKeyName turns a scope-qualified name into the store's entry name. It
// returns errUserScope for user/..., errBadEntryName for a system/<name>
// whose name the store would refuse, and a usage error for anything else that
// is not system/<name>. A refused argument is never echoed: it may be a value
// typed where the name belongs. A name it returns is valid, so it may be
// printed.
func parseKeyName(q string) (string, error) {
	scope, name, ok := strings.Cut(q, "/")
	switch {
	case !ok:
		return "", errors.New("entry names are scope-qualified: use system/<name>")
	case scope == "user":
		return "", errUserScope
	case scope != "system" || name == "" || strings.Contains(name, "/"):
		return "", errors.New("the argument is not a scope-qualified entry name: use system/<name>")
	}
	if keystore.CheckName(name) != nil {
		return "", errBadEntryName
	}
	return name, nil
}

// qualify is the display form of a system entry name.
func qualify(name string) string { return "system/" + name }

// nameArg takes the one positional a named verb accepts. A second positional
// is refused without echoing it: it may be a value typed where --in belongs.
func (v *keysVerb) nameArg(pos []string) (string, int) {
	switch {
	case len(pos) == 0:
		return "", v.failf(keysBadUsage, "missing the entry name (system/<name>)")
	case len(pos) > 1:
		return "", v.failf(keysBadUsage, "takes one entry name and no value argument: a value on the command line is visible to every local user; pass it with --in FILE, or --in - on stdin")
	}
	name, err := parseKeyName(pos[0])
	if errors.Is(err, errUserScope) {
		return "", v.failf(keysRefused, "%v", err)
	}
	if err != nil {
		return "", v.failf(keysBadUsage, "%v", err)
	}
	return name, keysOK
}

func runKeysWith(ctx context.Context, args []string, env keysEnv) int {
	if len(args) == 0 {
		fmt.Fprint(env.stderr, keysUsage)
		return keysBadUsage
	}
	verb, rest := args[0], args[1:]
	switch verb {
	case "-h", "--help", "help":
		fmt.Fprint(env.stdout, keysUsage)
		return keysOK
	case "put":
		return keysPut(ctx, rest, env)
	case "list", "ls":
		return keysList(ctx, rest, env)
	case "show":
		return keysShow(ctx, rest, env)
	case "rotate":
		return keysRotate(ctx, rest, env)
	case "rm":
		return keysRm(ctx, rest, env)
	case "rewrap":
		return keysRewrap(ctx, rest, env)
	case "floor":
		return keysFloor(ctx, rest, env)
	case "deliver":
		return keysDeliver(ctx, rest, env)
	case "undeliver":
		return keysUndeliver(ctx, rest, env)
	default:
		// The argument is not echoed: it may be a value typed in the wrong place.
		fmt.Fprintln(env.stderr, "k3sm keys: unknown subcommand (not echoed); see k3sm keys --help")
		return keysBadUsage
	}
}

// readValue reads a value from --in: a file, or "-" for stdin. A terminal on
// stdin is refused, because a value typed there is echoed and kept in
// scrollback. It reads at most one byte over the store's cap, so an
// oversized input is refused without reading it all, into one buffer the
// caller clears.
func (v *keysVerb) readValue(in string) ([]byte, error) {
	var r io.Reader
	switch in {
	case "":
		return nil, errors.New("--in is empty: pass --in FILE, or --in - to read stdin")
	case "-":
		if v.env.stdinTTY() {
			return nil, errors.New("stdin is a terminal: pipe the value in (... | sudo k3sm keys " + v.name + " system/<name> --in -), or pass --in FILE")
		}
		r = v.env.stdin
	default:
		f, err := v.openValueFile(in)
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }() // read-only
		r = f
	}
	// One buffer, allocated before the read and never grown, so the value
	// has no copy elsewhere on the heap and the caller's clear covers it.
	buf := make([]byte, keystore.MaxValueSize+1)
	n, err := io.ReadFull(r, buf)
	switch {
	case err == nil:
		clear(buf)
		return nil, fmt.Errorf("the value is over the %d-byte limit", keystore.MaxValueSize)
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return buf[:n], nil
	default:
		clear(buf)
		return nil, pathFailure("read", "--in", err)
	}
}

// pathFailure is an error about a path flag's file that never carries the
// path: a value typed where the path belongs would otherwise be printed.
// It names the operation and the flag, and the errno's text when there is
// one; err is not wrapped, since an fs.PathError in it holds the path.
func pathFailure(op, flagName string, err error) error {
	class := "it failed"
	var errno syscall.Errno
	if errors.As(err, &errno) {
		class = errno.Error()
	}
	return fmt.Errorf("%s %s: %s (the path is not echoed)", op, flagName, class)
}

// openValueFile opens --in FILE for reading: a regular file, reached without
// following a symlink, and opened non-blocking so a FIFO is refused rather
// than waited on. A file group or others can read is used, with a warning:
// the value is already exposed there. So is one group or others can write,
// or that another user than this process's (root) owns, with a warning that
// someone else could have chosen the value.
func (v *keysVerb) openValueFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, pathFailure("open", "--in", err)
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close() // read-only
		return nil, pathFailure("stat", "--in", err)
	}
	if !fi.Mode().IsRegular() {
		_ = f.Close() // read-only
		return nil, errors.New("--in is not a regular file")
	}
	if fi.Mode().Perm()&0o044 != 0 {
		fmt.Fprintf(v.env.stderr, "k3sm keys %s: warning: the --in file is mode %04o, readable by group or others: keep a value file readable by root only, and delete it once stored\n", v.name, fi.Mode().Perm())
	}
	if fi.Mode().Perm()&0o022 != 0 {
		fmt.Fprintf(v.env.stderr, "k3sm keys %s: warning: the --in file is mode %04o, writable by group or others, who could have chosen the value: keep a value file writable by root only\n", v.name, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int64(st.Uid) != int64(os.Geteuid()) {
		fmt.Fprintf(v.env.stderr, "k3sm keys %s: warning: the --in file is not owned by root, so its owner could have chosen the value: keep a value file owned by root\n", v.name)
	}
	return f, nil
}

func keysPut(ctx context.Context, args []string, env keysEnv) int {
	v := newKeysVerb("put", env)
	kindFlag := v.fs.String("kind", "opaque", "opaque or ed25519 (a 32-byte seed or a 64-byte private key)")
	in := v.fs.String("in", "-", "read the value from this file, or from stdin with -")
	pos, err := v.parse(args)
	if err != nil {
		return keysBadUsage
	}
	name, code := v.nameArg(pos)
	if code != keysOK {
		return code
	}
	var kind keystore.Kind
	switch *kindFlag {
	case "opaque":
		kind = keystore.KindOpaque
	case "ed25519":
		kind = keystore.KindEd25519
	default:
		return v.failf(keysBadUsage, "--kind: want opaque or ed25519 (the value given is not echoed)")
	}
	if code := v.requireRoot(); code != keysOK {
		return code
	}
	s, err := v.store()
	if err != nil {
		return v.failf(keysRefused, "%v", err)
	}
	value, err := v.readValue(*in)
	if err != nil {
		return v.failf(keysRefused, "%v", err)
	}
	defer clear(value)
	ver, err := s.Put(ctx, name, kind, value)
	code = keysOK
	if err != nil {
		if code = v.evictedCode(err); code == keysRefused {
			return code
		}
	}
	fmt.Fprintf(env.stdout, "created %s at version %d (%s, fingerprint %s)\n", qualify(name), ver.Version, ver.Kind, ver.Fingerprint)
	return code
}

func keysRotate(ctx context.Context, args []string, env keysEnv) int {
	v := newKeysVerb("rotate", env)
	in := v.fs.String("in", "-", "read the value from this file, or from stdin with -")
	from := v.fs.Uint64("from-version", 0, "store a copy of this version's bytes as the new version")
	pos, err := v.parse(args)
	if err != nil {
		return keysBadUsage
	}
	name, code := v.nameArg(pos)
	if code != keysOK {
		return code
	}
	var inSet, fromSet bool
	v.fs.Visit(func(f *flag.Flag) {
		inSet = inSet || f.Name == "in"
		fromSet = fromSet || f.Name == "from-version"
	})
	switch {
	case inSet && fromSet:
		return v.failf(keysBadUsage, "--in and --from-version are exclusive: the new value comes from one of them")
	case fromSet && *from == 0:
		return v.failf(keysBadUsage, "--from-version: versions start at 1")
	}
	if code := v.requireRoot(); code != keysOK {
		return code
	}
	s, err := v.store()
	if err != nil {
		return v.failf(keysRefused, "%v", err)
	}
	var value []byte
	if fromSet {
		_, value, err = s.Get(ctx, name, *from)
	} else {
		value, err = v.readValue(*in)
	}
	defer clear(value)
	if err != nil {
		return v.failf(keysRefused, "%v", err)
	}
	ver, err := s.Rotate(ctx, name, value)
	code = keysOK
	if err != nil {
		if code = v.evictedCode(err); code == keysRefused {
			return code
		}
	}
	if fromSet {
		fmt.Fprintf(env.stdout, "rotated %s to version %d, a copy of version %d (fingerprint %s)\n", qualify(name), ver.Version, *from, ver.Fingerprint)
		return code
	}
	fmt.Fprintf(env.stdout, "rotated %s to version %d (fingerprint %s)\n", qualify(name), ver.Version, ver.Fingerprint)
	return code
}

// keysListEntry is one entry of `keys list -o json`.
type keysListEntry struct {
	Name        string `json:"name"`
	Kind        string `json:"kind,omitempty"`
	Version     uint64 `json:"version,omitempty"`
	Versions    int    `json:"versions,omitempty"`
	Created     string `json:"created,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	// Status is ok, corrupt (the entry fails to open as stored), or error
	// (it could not be read, for want of permission or an I/O error).
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// keysEntryStatus is e's list row. Its error is a store error printed on
// stdout, so it is scrubbed of roots (scrubPaths) here, where it is built.
func keysEntryStatus(e keystore.Entry, roots ...string) keysListEntry {
	out := keysListEntry{Name: qualify(e.Name), Status: "ok"}
	if e.Err != nil {
		out.Status = "error"
		if errors.Is(e.Err, keystore.ErrCorrupt) {
			out.Status = "corrupt"
		}
		out.Error = scrubPaths(e.Err, roots...)
		return out
	}
	out.Kind = e.Current.Kind.String()
	out.Version = e.Current.Version
	out.Versions = len(e.Versions)
	out.Created = e.Current.Created.UTC().Format(time.RFC3339)
	out.Fingerprint = e.Current.Fingerprint
	return out
}

func keysList(ctx context.Context, args []string, env keysEnv) int {
	v := newKeysVerb("list", env)
	output := v.fs.String("o", "table", "output format: table or json")
	pos, err := v.parse(args)
	if err != nil {
		return keysBadUsage
	}
	if len(pos) > 0 {
		return v.failf(keysBadUsage, "takes no arguments")
	}
	if *output != "table" && *output != "json" {
		return v.failf(keysBadUsage, "-o: want table or json (the value given is not echoed)")
	}
	if code := v.requireRoot(); code != keysOK {
		return code
	}
	s, err := v.store()
	if err != nil {
		return v.failf(keysRefused, "%v", err)
	}
	v.warnMergePending(s)
	raised := v.raiseForRead(ctx, s)
	if raised != keysOK {
		return raised
	}
	entries, err := s.List(ctx)
	if err != nil {
		return v.failf(keysRefused, "%v", err)
	}
	rows := make([]keysListEntry, 0, len(entries))
	code := raised
	for _, e := range entries {
		r := keysEntryStatus(e, v.roots...)
		if r.Status != "ok" {
			code = keysRefused
		}
		rows = append(rows, r)
	}
	if *output == "json" {
		b, err := json.MarshalIndent(struct {
			Entries []keysListEntry `json:"entries"`
		}{rows}, "", "  ")
		if err != nil {
			return v.failf(keysRefused, "encode: %v", err)
		}
		fmt.Fprintf(env.stdout, "%s\n", b)
		return code
	}
	tw := tabwriter.NewWriter(env.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tKIND\tVERSION\tCREATED\tFINGERPRINT\tSTATUS")
	for _, r := range rows {
		if r.Status != "ok" {
			fmt.Fprintf(tw, "%s\t-\t-\t-\t-\t%s: %s\n", r.Name, r.Status, r.Error)
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\tok\n", r.Name, r.Kind, r.Version, r.Created, r.Fingerprint)
	}
	if err := tw.Flush(); err != nil {
		return v.failf(keysRefused, "write: %v", err)
	}
	return code
}

func keysShow(ctx context.Context, args []string, env keysEnv) int {
	v := newKeysVerb("show", env)
	version := v.fs.Uint64("version", 0, "show this version instead of the current one")
	reveal := v.fs.Bool("reveal", false, "print only the stored value, byte for byte")
	yes := v.fs.Bool("yes", false, "with --reveal, print the value even to a terminal")
	pos, err := v.parse(args)
	if err != nil {
		return keysBadUsage
	}
	name, code := v.nameArg(pos)
	if code != keysOK {
		return code
	}
	if code := v.requireRoot(); code != keysOK {
		return code
	}
	if *reveal && !*yes && env.stdoutTTY() {
		return v.failf(keysRefused, "stdout is a terminal, where --reveal would leave the value on screen and in scrollback: pipe it, or pass --yes")
	}
	s, err := v.store()
	if err != nil {
		return v.failf(keysRefused, "%v", err)
	}
	v.warnMergePending(s)
	raised := v.raiseForRead(ctx, s)
	if raised != keysOK {
		return raised
	}
	if !*reveal {
		ver, err := showMetadata(ctx, s, name, *version)
		if err != nil {
			return v.failf(keysRefused, "%v", err)
		}
		fmt.Fprintf(env.stdout, "name:        %s\n", qualify(name))
		fmt.Fprintf(env.stdout, "kind:        %s\n", ver.Kind)
		fmt.Fprintf(env.stdout, "version:     %d\n", ver.Version)
		fmt.Fprintf(env.stdout, "created:     %s\n", ver.Created.UTC().Format(time.RFC3339))
		fmt.Fprintf(env.stdout, "fingerprint: %s\n", ver.Fingerprint)
		return raised
	}
	var value []byte
	if *version != 0 {
		_, value, err = s.Get(ctx, name, *version)
	} else {
		_, value, err = s.Current(ctx, name)
	}
	defer clear(value)
	if err != nil {
		return v.failf(keysRefused, "%v", err)
	}
	if _, err := env.stdout.Write(value); err != nil {
		return v.failf(keysRefused, "write: %v", err)
	}
	return raised
}

// showMetadata is one version's metadata, taken from List so the verb never
// holds the value: version 0 is the current one. An entry List reports with
// Err is refused with that error. name is one parseKeyName validated, the
// only argument text its errors carry.
func showMetadata(ctx context.Context, s keysStore, name string, version uint64) (keystore.Version, error) {
	entries, err := s.List(ctx)
	if err != nil {
		return keystore.Version{}, err
	}
	for _, e := range entries {
		if e.Name != name {
			continue
		}
		if e.Err != nil {
			return keystore.Version{}, fmt.Errorf("%s: %w", name, e.Err)
		}
		if version == 0 {
			return e.Current, nil
		}
		for _, ver := range e.Versions {
			if ver.Version == version {
				return ver, nil
			}
		}
		return keystore.Version{}, fmt.Errorf("%s: version %d: %w", name, version, keystore.ErrVersionNotFound)
	}
	return keystore.Version{}, fmt.Errorf("%s: %w", qualify(name), keystore.ErrNotFound)
}

func keysRm(ctx context.Context, args []string, env keysEnv) int {
	v := newKeysVerb("rm", env)
	yes := v.fs.Bool("yes", false, "confirm: delete every version of the entry")
	pos, err := v.parse(args)
	if err != nil {
		return keysBadUsage
	}
	name, code := v.nameArg(pos)
	if code != keysOK {
		return code
	}
	if !*yes {
		return v.failf(keysBadUsage, "deleting %s removes every version and cannot be undone: pass --yes", qualify(name))
	}
	if code := v.requireRoot(); code != keysOK {
		return code
	}
	s, err := v.store()
	if err != nil {
		return v.failf(keysRefused, "%v", err)
	}
	// rm runs while a restore is unfinished, so it can make room for a
	// merge refused because the floor is full; it warns as list and show do.
	v.warnMergePending(s)
	code = keysOK
	if err := s.Delete(ctx, name); err != nil {
		// A Delete whose floor write evicted tombstones exits
		// keysCommitted; it is reported as done when it deleted the entry,
		// its tree left behind included (keystore.DeleteDone), and not when
		// only a floor raise before it wrote (ErrNotFound, say).
		if code = v.evictedCode(err); code == keysRefused {
			return code
		}
		if !keystore.DeleteDone(err) {
			return code
		}
	}
	fmt.Fprintf(env.stdout, "deleted %s\n", qualify(name))
	v.warnDeclared(name)
	return code
}

// keepFlag is floor merge's repeatable --keep system/<name>: the names whose
// restored generation the merge keeps live. A value parseKeyName refuses is
// refused without being echoed.
type keepFlag []string

func (k *keepFlag) String() string { return strings.Join(*k, ",") }

func (k *keepFlag) Set(q string) error {
	name, err := parseKeyName(q)
	if err != nil {
		return err
	}
	*k = append(*k, name)
	return nil
}

// keysFloor is "k3sm keys floor merge [--keep system/<name>]...
// [--accept-drops]": it
// merges the deleted generations the data root's moved-aside floor,
// keystore-floor.json.pre-restore, records into the live floor a restore put back (keystore.FileStore.MergeFloor),
// keeping live the restored generation of each entry --keep names, and
// prints a summary:
//
//	merged N
//	already present N
//	buried live N
//	kept N
//	retired N
//	dropped N
//	fenced N
//
// then one line per entry buried live ("buried live system/<name>: ..."),
// kept ("kept system/<name>: ..."), retired ("retired system/<name>: ...")
// and per burial dropped ("dropped
// system/<name>: ..."), preceded by "already merged" when the live floor
// already held everything the input records (a rerun: nothing is written,
// the input is only renamed). It exits 0 when the merge is written,
// keysCommitted, the report printed, when it is written but dropped a
// burial, and keysNotRenamed, the report printed, when it is written but
// its input could not be renamed (keystore.Committed), which wins.
func keysFloor(ctx context.Context, args []string, env keysEnv) int {
	if len(args) == 0 || args[0] != "merge" {
		fmt.Fprintln(env.stderr, "k3sm keys floor: want: sudo k3sm keys floor merge [--keep system/<name>]... [--accept-drops]")
		return keysBadUsage
	}
	v := newKeysVerb("floor merge", env)
	var keep keepFlag
	v.fs.Var(&keep, "keep", "keep this entry's restored version live (system/<name>; repeatable)")
	acceptDrops := v.fs.Bool("accept-drops", false, "write a merge that has to drop deletions since the backup to fit the floor, printing each one")
	pos, err := v.parse(args[1:])
	if err != nil {
		return keysBadUsage
	}
	if len(pos) != 0 {
		return v.failf(keysBadUsage, "takes no file: it reads only keystore-floor.json.pre-restore in the data root, the floor the restore recipe moves aside")
	}
	if code := v.requireRoot(); code != keysOK {
		return code
	}
	s, err := v.store()
	if err != nil {
		return v.failf(keysRefused, "%v", err)
	}
	r, err := s.MergeFloor(ctx, keystore.MergeOptions{Keep: keep, AcceptDrops: *acceptDrops})
	if err != nil && !keystore.Committed(err) {
		return v.failf(keysRefused, "%v", err)
	}
	if r.AlreadyMerged {
		fmt.Fprintln(env.stdout, "already merged")
	}
	fmt.Fprintf(env.stdout, "merged %d\nalready present %d\nburied live %d\nkept %d\nretired %d\ndropped %d\nfenced %d\n", r.Merged, r.AlreadyPresent, len(r.BuriedLive), len(r.Kept), len(r.Retired), len(r.Dropped), len(r.Fenced))
	for _, name := range r.BuriedLive {
		fmt.Fprintf(env.stdout, "buried live %s: deleted since the backup, so the restored entry is deleted again and refused; run sudo k3sm keys rm %s --yes to remove it\n", qualify(name), qualify(name))
	}
	for _, name := range r.Kept {
		fmt.Fprintf(env.stdout, "kept %s: deleted since the backup, and kept live as --keep asked\n", qualify(name))
		// A downgrade of what the floor refuses, so on stderr too.
		fmt.Fprintf(env.stderr, "k3sm keys floor merge: warning: %s is kept live as --keep asked, though the floor moved aside records it as deleted since the backup; if that deletion revoked the key, the revoked key is live again\n", qualify(name))
	}
	for _, name := range r.Retired {
		fmt.Fprintf(env.stdout, "retired %s: its version current before the restore is not the restored one, so a copy of it put back is refused\n", qualify(name))
	}
	for _, name := range r.Unverified {
		fmt.Fprintf(env.stdout, "unverified %s: the restored pointer did not authenticate under the master, or is more than one version past the restored floor's record, so its recorded sequence is left as the restored floor holds it and a copy past it is refused\n", qualify(name))
	}
	for _, name := range r.Dropped {
		fmt.Fprintf(env.stdout, "dropped %s: a deleted generation dropped to keep the floor within its caps; a copy of it put back is accepted\n", qualify(name))
	}
	if err != nil {
		// Written, but the input was not renamed: the report above stands,
		// drops included, and a rerun renames it.
		return v.failf(keysNotRenamed, "%v", err)
	}
	if len(r.Dropped) > 0 {
		return v.failf(keysCommitted, "the merge is written, but it dropped %d deleted generation(s) to keep the floor within its caps", len(r.Dropped))
	}
	return keysOK
}

// keyOutFile is a key file writeKeyOut wrote, held through the directory
// handle it checked, so a later delete removes that file and no other that
// came to have its path.
type keyOutFile struct {
	root *os.Root
	base string
}

// remove deletes the key file through the checked directory.
func (k *keyOutFile) remove() error { return k.root.Remove(k.base) }

// close releases the directory handle; the file stays.
func (k *keyOutFile) close() { _ = k.root.Close() } // read-only handle; writes were synced

// writeKeyOut creates path as a new root-only file holding key: O_EXCL, so an
// existing file or symlink there is refused rather than overwritten or
// followed, mode 0600, and fsynced with its directory before rewrap uses it.
// path must be absolute. The directory must be owned by root (the running
// user, which requireRoot made root) and closed to group and others for
// writing, judged on the descriptor the file is created through, so no other
// user can swap or unlink the file. A failure after the file is created
// removes it, so a refusal never leaves a partial key behind. On success the
// caller holds that descriptor in the returned keyOutFile and closes it.
func writeKeyOut(path string, key []byte, step func(string) error) (out *keyOutFile, err error) {
	if step == nil {
		step = func(string) error { return nil }
	}
	if !filepath.IsAbs(path) {
		return nil, errors.New("--key-out is a relative path: give an absolute path")
	}
	dir, base := filepath.Dir(path), filepath.Base(path)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, pathFailure("open the directory of", "--key-out", err)
	}
	defer func() {
		if err != nil {
			// No handle to a closed root, whatever a return above passed.
			out = nil
			_ = root.Close() // synced below when a file is written
		}
	}()
	if err := checkKeyOutDir(root); err != nil {
		return nil, err
	}
	f, err := root.OpenFile(base, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, pathFailure("create", "--key-out", err)
	}
	defer func() {
		if cerr := f.Close(); err == nil && cerr != nil {
			err = pathFailure("close", "--key-out", cerr)
		}
		if err != nil {
			if rerr := root.Remove(base); rerr != nil {
				err = fmt.Errorf("%w; and removing the partial key file failed, delete the --key-out file by hand: %w", err, pathFailure("remove", "--key-out", rerr))
			}
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return nil, pathFailure("chmod", "--key-out", err)
	}
	if err := step("chmod"); err != nil {
		return nil, err
	}
	if _, err := f.Write(key); err != nil {
		return nil, pathFailure("write", "--key-out", err)
	}
	if err := step("write"); err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, pathFailure("sync", "--key-out", err)
	}
	if err := step("sync"); err != nil {
		return nil, err
	}
	d, err := root.Open(".")
	if err != nil {
		return nil, pathFailure("open the directory of", "--key-out", err)
	}
	defer func() { _ = d.Close() }() // read-only; synced below
	if err := d.Sync(); err != nil {
		return nil, pathFailure("sync the directory of", "--key-out", err)
	}
	return &keyOutFile{root: root, base: base}, nil
}

// checkKeyOutDir refuses a --key-out directory that is not owned by the
// running user (root) or that group or others can write.
func checkKeyOutDir(root *os.Root) error {
	fi, err := root.Stat(".")
	if err != nil {
		return pathFailure("stat the directory of", "--key-out", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !ok || int64(st.Uid) != int64(os.Geteuid()):
		return errors.New("the --key-out file's directory is not owned by this user (root): name a directory only root can write")
	case fi.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("the --key-out file's directory is mode %04o, writable by group or others: name a directory only root can write", fi.Mode().Perm())
	}
	return nil
}

// readKeyIn reads a key saved by an earlier --key-out: a regular file, not a
// symlink, owned by this process's user and closed to group and others,
// holding exactly the master's 32 bytes. It opens non-blocking, as
// openValueFile does, so a FIFO is refused rather than waited on.
func readKeyIn(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, pathFailure("open", "--key-in", err)
	}
	defer func() { _ = f.Close() }() // read-only
	fi, err := f.Stat()
	if err != nil {
		return nil, pathFailure("stat", "--key-in", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.Mode().IsRegular():
		return nil, errors.New("--key-in is not a regular file")
	case !ok || int64(st.Uid) != int64(os.Geteuid()):
		return nil, errors.New("the --key-in file is not owned by this user (root)")
	case fi.Mode().Perm()&0o077 != 0:
		return nil, fmt.Errorf("the --key-in file is mode %04o: it must be closed to group and others (0600)", fi.Mode().Perm())
	}
	b, err := io.ReadAll(io.LimitReader(f, keysMasterSize+1))
	if err != nil {
		clear(b)
		return nil, pathFailure("read", "--key-in", err)
	}
	if len(b) != keysMasterSize {
		clear(b)
		return nil, fmt.Errorf("the --key-in file holds %d bytes, not a %d-byte key", len(b), keysMasterSize)
	}
	return b, nil
}

// checkKeyInRecorded refuses a --key-in key unless an interrupted rewrap
// used it: its SHA-256 is the recorded master.next.sha256, or some record
// already opens under it and not under the live master (a rewrap whose
// master.next was replaced or removed). --key-in finishes a rewrap k3sm
// started with a key it minted, and never makes an operator's key the
// master: no record opens under a key no rewrap sealed with.
func checkKeyInRecorded(ctx context.Context, s keysStore, key []byte) error {
	recorded, ok, err := s.InterruptedRewrap(ctx)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(key)
	if ok && subtle.ConstantTimeCompare(sum[:], recorded[:]) == 1 {
		return nil
	}
	sealed, err := s.RecordsSealedUnder(ctx, key)
	if err != nil {
		return err
	}
	if sealed {
		return nil
	}
	if !ok {
		return errors.New("no interrupted rewrap is recorded, and --key-in only finishes one: to change the master key, run sudo k3sm keys rewrap --key-out FILE")
	}
	return errors.New("the key file is not the key the interrupted rewrap used: pass the file its --key-out wrote")
}

func keysRewrap(ctx context.Context, args []string, env keysEnv) int {
	v := newKeysVerb("rewrap", env)
	keyOut := v.fs.String("key-out", "", "write the new master key to this new file (mode 0600) before re-sealing")
	keyIn := v.fs.String("key-in", "", "finish an interrupted rewrap with the key its --key-out saved in this file")
	pos, err := v.parse(args)
	if err != nil {
		return keysBadUsage
	}
	switch {
	case len(pos) > 0:
		return v.failf(keysBadUsage, "takes no arguments")
	case (*keyOut == "") == (*keyIn == ""):
		return v.failf(keysBadUsage, "pass exactly one of --key-out FILE (a fresh key, saved there first) or --key-in FILE (a key saved by an earlier rewrap)")
	}
	if code := v.requireRoot(); code != keysOK {
		return code
	}
	s, err := v.store()
	if err != nil {
		return v.failf(keysRefused, "%v", err)
	}
	// U101: while user scopes exist, say before the run and again after it
	// that Rewrap does not re-key them. The closing check is made again once
	// Rewrap returns, so a .user that appeared during the run is warned of.
	users, err := s.UserScopesExist(ctx)
	if err != nil {
		return v.failf(keysRefused, "%v; nothing was changed", err)
	}
	if users {
		fmt.Fprintln(env.stderr, keystore.UserScopeRewrapWarning)
	}
	defer func() {
		if !users {
			users, _ = s.UserScopesExist(ctx) // a check that fails warns of nothing new
		}
		if users {
			fmt.Fprintln(env.stderr, keystore.UserScopeRewrapWarning)
		}
	}()
	keyPath := *keyIn
	var key []byte
	var out *keyOutFile
	if keyPath != "" {
		key, err = readKeyIn(keyPath)
		if err != nil {
			return v.failf(keysRefused, "%v", err)
		}
		if err := checkKeyInRecorded(ctx, s, key); err != nil {
			clear(key)
			return v.failf(keysRefused, "%v; nothing was changed", err)
		}
	} else {
		keyPath = *keyOut
		key = make([]byte, keysMasterSize)
		if _, err := io.ReadFull(env.rand, key); err != nil {
			clear(key)
			return v.failf(keysRefused, "draw a new master key: %v", err)
		}
		out, err = writeKeyOut(keyPath, key, env.keyOutStep)
		if err != nil {
			clear(key)
			return v.failf(keysRefused, "%v; nothing was changed", err)
		}
		defer out.close()
		fmt.Fprintln(env.stderr, "k3sm keys rewrap: saved the new master key to the --key-out file (mode 0600). Keep this file until rewrap reports success, then delete it.")
	}
	defer clear(key)
	err = s.Rewrap(ctx, key)
	if err == nil {
		fmt.Fprintf(env.stdout, "rewrap complete: every entry is sealed under the new master key.\n"+
			"Now delete the %s file.\n"+
			"Backups of the keystore taken before this rewrap no longer open: back up the entries and the master key again.\n"+
			"Fingerprints of opaque entries have changed.\n", keyFlag(out))
		return keysOK
	}
	resumed := errors.Is(err, keystore.ErrRewrapResumed)
	code, next := keysRefused, ""
	if resumed {
		code, next = keysResumed, "\nrun rewrap again with a new key: sudo k3sm keys rewrap --key-out <new file>."
	}
	return v.failf(code, "%v%s\n%s", err, next, keyFileAfterFailure(err, out, resumed))
}

// keyFlag names the flag the run's key file came from: --key-out when this
// run wrote it (out set), else --key-in. Messages name the flag, never the
// path, which may be a value typed in the wrong place.
func keyFlag(out *keyOutFile) string {
	if out != nil {
		return "--key-out"
	}
	return "--key-in"
}

// keysResumeFailed is what rewrap says after keystore.ErrRewrapResumeFailed:
// the run was completing an earlier rewrap under that rewrap's key and
// failed partway, so the earlier key file finishes it.
const keysResumeFailed = "an earlier interrupted rewrap was advanced and did not finish; keep the earlier rewrap's key file; finish with: sudo k3sm keys rewrap --key-in <that earlier file>"

// keysSwapUnsynced is what rewrap says after keystore.ErrRewrapSwapUnsynced:
// the earlier rewrap's swap went through, so a new rewrap retires its key.
const keysSwapUnsynced = "the earlier rewrap's master swap completed but did not sync; run sudo k3sm keys rewrap --key-out FILE again; the earlier rewrap's key file is now a copy of the live master; delete it after this rewrap succeeds"

// keysOwnSwapUnsynced is what rewrap says after keystore.ErrRewrapSwapUnsynced
// on its own swap: the key file is kept, as the live master's only copy
// outside the store.
const keysOwnSwapUnsynced = "the master swap completed but did not sync; this run's key file is now a copy of the live master: keep it until a later rewrap succeeds, then delete it."

// keyFileAfterFailure decides, after a rewrap that did not succeed, what
// becomes of the key file, and says so. A file this run wrote (--key-out) is
// deleted only when the error is keystore.ErrRewrapNotStarted, which the
// store returns only before it writes anything under the key; after any
// other error a resume may need the file, so it is kept. After
// keystore.ErrRewrapResumeFailed the file is kept too, and the operator is
// sent to the earlier rewrap's key file, unless keystore.ErrRewrapSwapUnsynced
// says that rewrap completed: the unused file is deleted, and the operator
// runs a new rewrap. keystore.ErrRewrapSwapUnsynced alone is this run's own
// swap, complete: the file is the live master's copy and is kept. A --key-in file (out nil) is the
// operator's and is never deleted. The delete goes through out, the
// directory handle writeKeyOut checked, never through the path again. It
// names the flag, never the path.
func keyFileAfterFailure(err error, out *keyOutFile, resumed bool) string {
	wrote := out != nil
	if errors.Is(err, keystore.ErrRewrapSwapUnsynced) && !errors.Is(err, keystore.ErrRewrapResumeFailed) {
		// This run's own swap went through: its key is the live master.
		return keysOwnSwapUnsynced
	}
	if errors.Is(err, keystore.ErrRewrapSwapUnsynced) {
		// The earlier rewrap is complete; this run's key was never used.
		if !wrote {
			return keysSwapUnsynced
		}
		if rerr := out.remove(); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			return fmt.Sprintf("%s\nthis run's key was never used; delete the --key-out file by hand: %v", keysSwapUnsynced, pathFailure("remove", "--key-out", rerr))
		}
		return keysSwapUnsynced + "\nthis run's key was never used, so the --key-out file was deleted"
	}
	if errors.Is(err, keystore.ErrRewrapResumeFailed) {
		if wrote {
			return keysResumeFailed + "\nthis run's --key-out file was kept"
		}
		return keysResumeFailed
	}
	if !wrote || !errors.Is(err, keystore.ErrRewrapNotStarted) {
		return fmt.Sprintf("keep the %s file: a resume may need this file; finish with the same key: sudo k3sm keys rewrap --key-in <that file>", keyFlag(out))
	}
	what := "nothing was changed: nothing was sealed under the new key"
	if resumed {
		what = "the key this run drew was never used"
	}
	if rerr := out.remove(); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
		return fmt.Sprintf("%s; delete the --key-out file by hand: %v", what, pathFailure("remove", "--key-out", rerr))
	}
	return fmt.Sprintf("%s, so the --key-out file was deleted", what)
}
