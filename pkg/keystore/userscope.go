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

package keystore

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"

	keyentry "k3sm.io/apis/keystore/entry"
)

// This file is the user-scope store: docs/design/keystore.md § "User scope",
// "On-disk layout" and "Key hierarchy". A user scope lives under the entries'
// directory at
//
//	.user/<uid>/              0700, service user
//	  scope.key               0600, kind-0xFE record: K_u sealed under W
//	  entries/<name>/         same shape as a system entry, sealed under K_u
//
// and is reached only by descriptor from the entries' directory the store
// lock is held on: each directory is opened with openSubdir (Lstat, open,
// SameFile, owner and mode on the descriptor) and each file with readFile
// (O_NOFOLLOW, a regular file, a bounded read).
//
// The scope's delivery record (kind 0xFD) is deliveries.go, its quotas and
// rm quota.go, and Rewrap of scope.key rewrapscope.go. The user-scope floor
// (userlogs.go) holds a line per entry and per delivery record: a put
// appends its entry's line after the pointer, and a read refuses a pointer
// below its line (userfloor.go).
//
// The interrupted-put rule is not brought back yet: the system scope's rule
// needs the floor to tell a crashed Put (generation, maybe v1) from a
// committed entry whose current, or current and v1, were unlinked, and the
// user scope does not consult its floor for that. So it treats every entry
// directory without a current pointer as damage: ErrCorrupt, never
// ErrNotFound, and never removed, a crashed user Put included
// (openUserEntry, createUserEntry). No caller outside this package reaches
// the user scope before the socket does (TestUserScopeIsUnexported).

const (
	// scopeKeyName is a scope's wrapped key, scopeEntriesName its entries'
	// directory.
	scopeKeyName     = "scope.key"
	scopeEntriesName = "entries"
	// scopeKeyRecordName, scopeKeyEpoch and scopeKeySize are scope.key's
	// record name, its version (the key epoch) and its plaintext's size.
	scopeKeyRecordName = "scope"
	scopeKeyEpoch      = 1
	scopeKeySize       = 32
	// maxScopeKeyRecordSize bounds a read of scope.key: a record of its name
	// sealing a 32-byte key.
	maxScopeKeyRecordSize = headerSize + len(scopeKeyRecordName) + scopeKeySize + tagSize
)

// The uids a user scope may belong to: the socket's eligible peers
// (docs/design/keystore.md § "User scope", "The socket"). Below 501 are
// system accounts; at 2^31 and above, nobody among them, no login user, and
// a signed 32-bit reading would turn the uid negative.
const (
	minScopeUID = 501
	maxScopeUID = 2147483647
)

// MinLoginUID and MaxLoginUID are the login range, minScopeUID to
// maxScopeUID, for the socket listener, which takes its eligible peer
// range from them so the two cannot drift apart.
const (
	MinLoginUID = minScopeUID
	MaxLoginUID = maxScopeUID
)

// errIneligibleUID reports a uid that has no user scope.
var errIneligibleUID = errors.New("the uid has no user scope: a user scope belongs to a login uid from 501 to 2147483647 that is not the service user's")

// eligibleUID refuses a uid outside the eligible range, and the service
// uid, which every native Pod shares. The socket refuses such a peer first;
// this is the store's own layer.
func (s *FileStore) eligibleUID(uid uint32) error {
	if uid < minScopeUID || uid > maxScopeUID || uid == s.uid {
		return fmt.Errorf("%w: uid %d", errIneligibleUID, uid)
	}
	return nil
}

// errNoScopeKey is a scope with no scope.key, or no directory for it: the one
// absence a mutating operation mints over.
var errNoScopeKey = fmt.Errorf("%w: no scope key", ErrScopeAbsent)

// UserScope is one uid's view of the store: the caller's own user scope and
// nothing else. Every name it is given must be user/<its uid>/<name>; any
// other name, a system/ name or another uid's included, answers ErrNotFound,
// worded exactly as an absent entry of its own, so the answer is no oracle
// for another user's names.
type UserScope struct {
	s     *FileStore
	uid   uint32
	scope string
	// allowRemoved lets rm-scope open a scope key the removed-scopes record
	// already lists: a rerun after an rm-scope that recorded it and stopped.
	allowRemoved bool
	// origin is where the view's operations come from, for their audit
	// lines (WithOrigin); the zero Origin writes no via and no caller.
	origin Origin
	// guid is the uid's GeneratedUID lookup answer, taken before the store
	// lock (withGUID) and used for the whole hold; nil looks it up at use.
	guid *guidAnswer
}

// guidAnswer is one GeneratedUID lookup's answer: the GeneratedUID, or the
// lookup's error.
type guidAnswer struct {
	g   [generationSize]byte
	err error
}

// withGUID is a copy of u carrying the uid's GeneratedUID lookup, run now,
// before the caller takes the store lock: the lookup's deadline (250 ms)
// is never spent inside a hold, and the hold asks the directory service
// nothing (docs/design/keystore.md § "Lock modes and fairness", the
// hold-time bound). Every check under the hold reads the one answer, an
// error included, as it would have read a lookup made there.
func (u *UserScope) withGUID() *UserScope {
	c := *u
	g, err := u.s.generatedUIDOf(u.uid)
	c.guid = &guidAnswer{g: g, err: err}
	return &c
}

// liveGUID is the uid's live GeneratedUID: the answer withGUID took, or,
// on a view that took none, a lookup now.
func (u *UserScope) liveGUID() ([generationSize]byte, error) {
	if u.guid != nil {
		return u.guid.g, u.guid.err
	}
	return u.s.generatedUIDOf(u.uid)
}

// UserScope returns uid's view of the store. A uid outside 501 to
// 2147483647, or the service uid, is refused: root has no user scope, and
// neither has a system account, nobody or the service user. Until the
// server's start step has run (startUserScopes) it refuses every uid,
// errUserScopesNotStarted. A uid whose scope the start step quarantined
// still gets its view: its grant and read verbs refuse (quarantineErr), and
// its rm and withdraw run, since a revocation is never blocked by the
// floor's damage.
func (s *FileStore) UserScope(uid uint32) (*UserScope, error) {
	if s.userScopesStarted == nil || !s.userScopesStarted.Load() {
		return nil, errUserScopesNotStarted
	}
	scope := userScopeOf(uid)
	if err := checkScope(scope); err != nil {
		return nil, err
	}
	if err := s.eligibleUID(uid); err != nil {
		return nil, err
	}
	return &UserScope{s: s, uid: uid, scope: scope}, nil
}

// quarantineErr refuses a grant or a read in a scope the start step
// quarantined (startUserScopes), errFloorDegraded; nil otherwise. It is
// asked per call, so an acknowledgement that lifts the quarantine
// (ackFloorDamage) takes effect on a view already handed out. Delete and
// Withdraw never ask it.
func (u *UserScope) quarantineErr() error {
	if u.s.scopeQuarantined(u.uid) {
		return fmt.Errorf("%w: %w", errScopeQuarantined, errFloorDegraded)
	}
	return nil
}

// notFound is the one ErrNotFound a UserScope answers for op, whatever the
// name: it carries no name, so the caller's own absent entry and another
// scope's entry read the same.
func notFound(op string) error {
	return fmt.Errorf("user scope %s: %w", op, ErrNotFound)
}

// fail wraps err for op, collapsing every ErrNotFound to notFound(op).
func fail(op string, err error) error {
	if errors.Is(err, ErrNotFound) {
		return notFound(op)
	}
	return fmt.Errorf("user scope %s: %w", op, err)
}

// own parses input as an API entry and returns its name part when it is in
// the caller's scope; any other valid entry is notFound.
func (u *UserScope) own(op, input string) (string, error) {
	e, err := ParseEntry(input)
	if err != nil {
		return "", fmt.Errorf("user scope %s: %w", op, err)
	}
	if e.Scope != keyentry.ScopeUser || e.UID != u.uid {
		return "", notFound(op)
	}
	return e.Name, nil
}

// Put stores value as version 1 of input, minting the scope on the uid's
// first mutating operation: the scope key is bound to the uid's live
// GeneratedUID, and a lookup that fails mints nothing. It never mints the
// master, which root verbs create (ErrMasterMissing without one), and never
// writes while a Rewrap is half done (ErrRewrapInProgress).
//
// It is a grant: its audit line is appended before its first write, and a
// failed append refuses it with nothing written, the scope's mint included.
func (u *UserScope) Put(ctx context.Context, input string, kind Kind, value []byte) (Version, error) {
	name, err := u.own("put", input)
	if err != nil {
		u.auditBriefly(ctx, auditLine{op: "put", name: auditPlaceholder}, err)
		return Version{}, fail("put", err)
	}
	v, err := u.put(ctx, name, kind, value, u.grant("put", name, ""))
	if err != nil {
		// A put that committed stands: its version is answered with the
		// error, as Rotate answers its own.
		if Committed(err) {
			return v, fail("put", err)
		}
		return Version{}, fail("put", err)
	}
	return v, nil
}

// put audits its refusal while it holds the store lock (auditSink), or, for
// a refusal before it takes the lock, takes the lock briefly to audit it.
func (u *UserScope) put(ctx context.Context, name string, kind Kind, value []byte, g *grantAudit) (_ Version, err error) {
	if err := u.s.checkConfig(); err != nil {
		return Version{}, err
	}
	if err := checkValue(kind, value); err != nil {
		g.refusedBriefly(ctx, err)
		return Version{}, err
	}
	if err := u.quarantineErr(); err != nil {
		g.refusedBriefly(ctx, err)
		return Version{}, err
	}
	// The entries' directory is never created here: a root put creates it
	// with the master.
	unlockUID, err := u.s.usage.lockUID(ctx, u.uid, u.s.lockWait)
	if err != nil {
		return Version{}, err
	}
	defer unlockUID()
	u.prepareUsage(ctx) // the scope's figure, walked before the store lock
	if err := ctx.Err(); err != nil {
		return Version{}, err // done during the walk: no hold, nothing written
	}
	u = u.withGUID() // then the lookup, so its answer is fresh at the lock
	root, done, err := u.s.openLocked(ctx, false, true)
	if errors.Is(err, fs.ErrNotExist) {
		return Version{}, fmt.Errorf("%w: the keystore directory is missing; a root put creates the keystore", ErrMasterMissing)
	}
	if err != nil {
		return Version{}, err
	}
	defer done()
	defer func() { // before done: the refusal's line is appended under the lock
		if err != nil {
			g.refused(err)
		}
	}()
	if err := u.s.admit(u.uid, false); err != nil {
		return Version{}, err
	}
	grant := g.take
	k, err := u.masterForWrite()
	if err != nil {
		return Version{}, err
	}
	uk, entries, err := u.openScope(root, func() (keys, error) { return k, nil })
	roomJudged := false
	if errors.Is(err, errNoScopeKey) {
		// The mint appends the delivery record's floor line first. This one
		// check covers the name's line too, so none follows the mint's ok
		// audit line: a refusal after it would be audited after an ok.
		if err := u.s.floorGrantRoom(u.scope, []string{deliveriesFloorName, name}, entryWriteBytes(name, value)); err != nil {
			return Version{}, err
		}
		roomJudged = true
		uk, entries, err = u.mint(root, k.wrap, grant)
	}
	if err != nil {
		return Version{}, err
	}
	defer func() { _ = entries.Close() }() // writes are fsynced by writeFile
	if names := u.s.lostLines.names(u.scope); len(names) > 0 {
		u.catchUpLostIn(entries, uk, names)
	}
	if err := u.checkNewName(entries, name); err != nil {
		return Version{}, err
	}
	// Refuse, before the grant's first write, a put whose floor line would
	// be refused after its commit.
	if !roomJudged {
		if err := u.s.floorGrantRoom(u.scope, []string{name}, entryWriteBytes(name, value)); err != nil {
			return Version{}, err
		}
	}
	if err := u.checkUsageQuota(root, name, value); err != nil {
		return Version{}, err
	}
	// The ok line names the version the put writes and its fingerprint,
	// under the scope's keys, which a minting put opened only after its
	// line (mint), so its line names neither.
	if !roomJudged {
		g.version, g.fingerprint = 1, fingerprint(kind, value, uk.fingerprint)
	}
	if err := grant(); err != nil {
		return Version{}, err
	}
	// The figure is out of the table from the mkdir to its update, so a
	// failure or a panic in between leaves none (usageOp).
	op := u.s.usage.begin(u.uid)
	e, err := u.createUserEntry(entries, name)
	if err != nil {
		if errors.Is(err, ErrExists) {
			op.confirm(nil) // the mkdir found the entry: nothing written
		}
		return Version{}, err
	}
	defer e.close()
	v, err := u.s.writeEntry(e, uk, kind, value)
	if err != nil {
		return Version{}, err
	}
	u.usageAfterPut(op, entries, name)
	// The record, the pointer, then the floor line: a crash between the
	// last two leaves the floor one behind, which a read accepts.
	if err := u.s.userFloor.append(u.scope, name, e.generation, 1, false); err != nil {
		// The next operation on the scope catches the line up.
		u.s.lostLines.note(u.scope, name)
		return v, fmt.Errorf("%w, and its floor line was not written: %w", errCommitted, err)
	}
	return v, nil
}

// masterForWrite loads the master for a user-scope write, read-only: it
// never mints a master and never completes a master swap, both root's. A
// master.next or master.next.sha256 in the master directory is a Rewrap half
// done, ErrRewrapInProgress: a .user created now would refuse its resume, and
// a scope.key sealed now would be under a W the Rewrap is about to replace.
// The caller holds the exclusive store lock, which Rewrap takes too.
func (u *UserScope) masterForWrite() (keys, error) {
	root, err := u.s.openMasterDir(false)
	if errors.Is(err, fs.ErrNotExist) {
		return keys{}, ErrMasterMissing
	}
	if err != nil {
		return keys{}, fmt.Errorf("%w: %w", ErrMasterUntrusted, err)
	}
	for _, n := range []string{masterNextName, masterNextFingerprintName} {
		_, err := root.Lstat(n)
		if err == nil {
			_ = root.Close() // read-only
			return keys{}, fmt.Errorf("%w (%s is present)", ErrRewrapInProgress, n)
		}
		if !errors.Is(err, fs.ErrNotExist) {
			_ = root.Close() // read-only
			return keys{}, fmt.Errorf("check for %s: %w", n, err)
		}
	}
	_ = root.Close() // read-only
	return u.s.loadMaster()
}

// checkNewName refuses, before a grant's audit line, a name entries
// already holds: ErrExists for an entry, and damage (openUserEntry) for a
// directory without a current pointer. createUserEntry checks again under
// the same lock.
func (u *UserScope) checkNewName(entries *os.Root, name string) error {
	if _, err := entries.Lstat(name); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	e, err := openUserEntry(entries, name)
	if err != nil {
		return err
	}
	e.close()
	return ErrExists
}

// createUserEntry makes name's directory in entries with a fresh
// generation. An existing directory is never removed: one with a current
// pointer is ErrExists, and one without is damage (openUserEntry), since
// without the user-scope floor a crashed Put cannot be told from a committed
// entry whose pointer was unlinked.
func (u *UserScope) createUserEntry(entries *os.Root, name string) (*entry, error) {
	made, err := u.s.mkdirAt(entries, name)
	if errors.Is(err, fs.ErrExist) {
		e, oerr := openUserEntry(entries, name)
		if oerr != nil {
			return nil, oerr
		}
		e.close()
		return nil, ErrExists
	}
	if err != nil {
		return nil, fmt.Errorf("create the entry directory: %w", err)
	}
	return u.s.initEntry(entries, name, made)
}

// errUserNoPointer is a user entry directory with no current pointer.
var errUserNoPointer = fmt.Errorf("%w: the entry has no current pointer; an interrupted put cannot be told from a committed entry whose pointer was removed, so it is refused and kept, not removed", ErrCorrupt)

// openUserEntry opens name's directory in a user scope's entries/ and reads
// its generation. A missing directory is ErrNotFound; a directory with no
// current pointer, whatever else it holds, is errUserNoPointer (ErrCorrupt,
// never ErrNotFound).
func openUserEntry(entries *os.Root, name string) (*entry, error) {
	e, err := openEntryDirRaw(entries, name)
	if err != nil {
		return nil, err
	}
	if _, err := e.root.Lstat(currentName); err != nil {
		e.close()
		if errors.Is(err, fs.ErrNotExist) {
			return nil, errUserNoPointer
		}
		return nil, err
	}
	if e.generation, err = readGeneration(e.root); err != nil {
		e.close()
		return nil, err
	}
	return e, nil
}

// Current returns the version input's pointer names, with its value. It
// writes no audit line: it is this package's own read. The socket's read
// is ReadForExec, audited as exec-read.
func (u *UserScope) Current(ctx context.Context, input string) (Version, []byte, error) {
	var (
		v   Version
		val []byte
	)
	name, err := u.own("current", input)
	if err != nil {
		return Version{}, nil, err
	}
	if err := u.quarantineErr(); err != nil {
		return Version{}, nil, fail("current", err)
	}
	err = u.read(ctx, func(entries *os.Root, uk keys) error {
		e, err := openUserEntry(entries, name)
		if err != nil {
			return err
		}
		defer e.close()
		cur, err := u.flooredPointer(e, uk)
		if err != nil {
			return err
		}
		v, val, err = e.version(uk, cur)
		if err := rawOnly(v, err); err != nil {
			clear(val) // a refused typed envelope never lingers
			val = nil
			return err
		}
		return nil
	})
	if err != nil {
		return Version{}, nil, fail("current", err)
	}
	return v, val, nil
}

// List returns every entry of the scope, sorted by name, as FileStore.List
// does: an entry that cannot be opened carries Err. Each entry carries its
// current version and its version count, not every version
// (listUserEntry). A uid with no scope is ErrScopeAbsent. It is audited as
// list (auditedRead).
func (u *UserScope) List(ctx context.Context) ([]Entry, error) {
	if err := u.quarantineErr(); err != nil {
		u.auditBriefly(ctx, auditLine{op: "list"}, err)
		return nil, fail("list", err)
	}
	var out []Entry
	err := u.auditedRead(ctx, auditLine{op: "list"}, func(entries *os.Root, uk keys) error {
		names, err := readDirNames(entries, maxDirNames)
		if err != nil {
			return err
		}
		sort.Strings(names)
		for _, name := range names {
			if checkName(name) != nil {
				continue
			}
			e, err := openUserEntry(entries, name)
			if errors.Is(err, ErrNotFound) {
				continue
			}
			if err != nil {
				out = append(out, Entry{Name: name, Err: err})
				continue
			}
			if _, err := u.flooredPointer(e, uk); err != nil {
				out = append(out, Entry{Name: name, Err: err})
				e.close()
				continue
			}
			out = append(out, listUserEntry(e, uk))
			e.close()
		}
		return nil
	})
	if err != nil {
		return nil, fail("list", err)
	}
	return out, nil
}

// ReadForExec returns the value of input's current version, with the
// version: the socket's read-for-exec, the one way a user reaches its own
// value. It reads raw kinds only, as Current does, and is audited as
// exec-read (auditedRead): a read whose line cannot be written returns no
// value.
func (u *UserScope) ReadForExec(ctx context.Context, input string) (Version, []byte, error) {
	name, err := u.own("exec-read", input)
	if err != nil {
		u.auditBriefly(ctx, auditLine{op: "exec-read", name: auditPlaceholder}, err)
		return Version{}, nil, fail("exec-read", err)
	}
	if err := u.quarantineErr(); err != nil {
		u.auditBriefly(ctx, auditLine{op: "exec-read", name: name}, err)
		return Version{}, nil, fail("exec-read", err)
	}
	var (
		v   Version
		val []byte
	)
	err = u.auditedRead(ctx, auditLine{op: "exec-read", name: name}, func(entries *os.Root, uk keys) error {
		e, err := openUserEntry(entries, name)
		if err != nil {
			return err
		}
		defer e.close()
		cur, err := u.flooredPointer(e, uk)
		if err != nil {
			return err
		}
		v, val, err = e.version(uk, cur)
		return rawOnly(v, err)
	})
	if err != nil {
		clear(val) // a refused read never hands out its value
		return Version{}, nil, fail("exec-read", err)
	}
	return v, val, nil
}

// errReadAuditRefused is a read refused because its audit line could not
// be written: the fail-closed rule for reads, which no exception covers.
var errReadAuditRefused = errors.New("the audit line could not be written, so the read is refused")

// auditedRead runs fn as read does, under the shared lock, and appends l
// under that same hold, after the read and before the caller replies
// (docs/design/keystore.md § "The audit log": lock modes, audit before
// reply, fail closed). A uid past its share is refused first, with nothing
// read and no line written (errShareSpent): reads are charged to the share
// like any line and are not in the revocation class. A read whose line
// cannot be appended is refused (errReadAuditRefused), and so is a
// scope-absent one, which a list serves as empty; any other refused read's
// line is written best effort, with the refusal's result.
func (u *UserScope) auditedRead(ctx context.Context, l auditLine, fn func(*os.Root, keys) error) error {
	if err := u.s.checkConfig(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err // done before the lookup: none runs, no lock is taken
	}
	u = u.withGUID()
	root, done, err := u.s.openLocked(ctx, false, false)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: the keystore directory is missing", ErrScopeAbsent)
	}
	if err != nil {
		return err
	}
	defer done()
	if err := u.s.admit(u.uid, false); err != nil {
		return err
	}
	o, entries, err := u.openScopeFull(root, u.s.loadMaster)
	if err == nil {
		err = fn(entries, o.uk)
		_ = entries.Close() // read-only; nothing to flush
		o.close()
	}
	l.result = auditResult(err)
	// A scope-absent answer is served as an empty list (the socket's list),
	// so a read whose line failed is refused then too, never served with
	// no line.
	if aerr := u.audit(l); aerr != nil && (err == nil || errors.Is(err, ErrScopeAbsent)) {
		return fmt.Errorf("%w: %w", errReadAuditRefused, aerr)
	}
	return err
}

// read runs fn on the scope's entries' directory and keys under the shared
// lock. A read never mints: a missing keystore, scope or container is
// ErrScopeAbsent.
func (u *UserScope) read(ctx context.Context, fn func(*os.Root, keys) error) error {
	return u.readScope(ctx, func(entries *os.Root, o *openedScope) error { return fn(entries, o.uk) })
}

// readScope is read, giving fn the opened scope.
func (u *UserScope) readScope(ctx context.Context, fn func(*os.Root, *openedScope) error) error {
	if err := u.s.checkConfig(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err // done before the lookup: none runs, no lock is taken
	}
	u = u.withGUID()
	root, done, err := u.s.openLocked(ctx, false, false)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: the keystore directory is missing", ErrScopeAbsent)
	}
	if err != nil {
		return err
	}
	defer done()
	o, entries, err := u.openScopeFull(root, u.s.loadMaster)
	if err != nil {
		return err
	}
	defer o.close()
	defer func() { _ = entries.Close() }() // read-only; nothing to flush
	return fn(entries, o)
}

// openScope opens the scope under root, the entries' directory, and returns
// its derived keys and its open entries' directory. wrap supplies W; it is
// called only once scope.key is found, so a missing scope is ErrScopeAbsent
// whether or not the master opens. A missing .user, .user/<uid>/ or
// scope.key is errNoScopeKey; a missing entries/ beside a scope.key is
// ErrScopeAbsent too, never an empty scope, and never minted over.
func (u *UserScope) openScope(root *os.Root, wrap func() (keys, error)) (keys, *os.Root, error) {
	o, entries, err := u.openScopeFull(root, wrap)
	if err != nil {
		return keys{}, nil, err
	}
	uk := o.uk
	o.close()
	return uk, entries, nil
}

// openScopeFull is openScope, returning the opened scope: its directory,
// derived keys, delivery-record key and bound generation. A scope.key with
// no deliveries record beside it is ErrScopeAbsent, an incomplete scope and
// never an empty record, as a missing entries/ is.
func (u *UserScope) openScopeFull(root *os.Root, wrap func() (keys, error)) (*openedScope, *os.Root, error) {
	dir, err := u.openScopeDir(root, false)
	if err != nil {
		return nil, nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = dir.Close() // abandoned; read-only so far
		}
	}()
	ku, gen, err := u.readScopeKey(dir, wrap)
	if err != nil {
		return nil, nil, err
	}
	uk, err := deriveKeys(ku, u.scope)
	dk := deliveriesKey(ku, u.scope)
	clear(ku) // only the derived keys are kept
	if err != nil {
		return nil, nil, err
	}
	if _, err := dir.Lstat(deliveriesName); errors.Is(err, fs.ErrNotExist) {
		return nil, nil, fmt.Errorf("%w: the scope has a scope key and no %s record", ErrScopeAbsent, deliveriesName)
	} else if err != nil {
		return nil, nil, fmt.Errorf("check for %s: %w", deliveriesName, err)
	}
	entries, err := u.s.openSubdir(dir, scopeEntriesName, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, fmt.Errorf("%w: the scope has a scope key and no entries/ directory", ErrScopeAbsent)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s: %w", ErrCorrupt, scopeEntriesName, err)
	}
	ok = true
	return &openedScope{dir: dir, key: dk, gen: gen, uk: uk}, entries, nil
}

// openScopeDir opens .user/<uid>/ under root, each level with openSubdir,
// creating them with create set. A missing level without create is
// errNoScopeKey.
func (u *UserScope) openScopeDir(root *os.Root, create bool) (*os.Root, error) {
	users, err := u.s.openSubdir(root, userScopesName, create)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errNoScopeKey
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrCorrupt, userScopesName, err)
	}
	defer func() { _ = users.Close() }() // the scope directory is opened; .user is done with
	dir, err := u.s.openSubdir(users, strconv.FormatUint(uint64(u.uid), 10), create)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errNoScopeKey
	}
	if err != nil {
		return nil, fmt.Errorf("%w: the scope directory: %w", ErrCorrupt, err)
	}
	return dir, nil
}

// openScopeDirForRm is openScopeDir for rm-scope's judge only, never for
// a serving path: .user and .user/<uid>/ are each opened as openSubdir
// does (Lstat, OpenRoot, the same file on the descriptor) and must be the
// service user's, but their mode is not judged. The service user can set
// either directory's mode, and a judge that refused it would let the
// principal being revoked veto its revocation; the take then forces the
// scope directory to 0700. A missing level is errNoScopeKey; another owner
// is ErrCorrupt, as with openScopeDir.
func (u *UserScope) openScopeDirForRm(root *os.Root) (*os.Root, error) {
	users, err := u.s.openSubdirAnyMode(root, userScopesName)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errNoScopeKey
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrCorrupt, userScopesName, err)
	}
	defer func() { _ = users.Close() }() // the scope directory is opened; .user is done with
	dir, err := u.s.openSubdirAnyMode(users, strconv.FormatUint(uint64(u.uid), 10))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errNoScopeKey
	}
	if err != nil {
		return nil, fmt.Errorf("%w: the scope directory: %w", ErrCorrupt, err)
	}
	return dir, nil
}

// openSubdirAnyMode opens the existing directory name under parent as
// openSubdir does, checking on the descriptor that it is the directory
// Lstat named and that the service user owns it, whatever its mode.
func (s *FileStore) openSubdirAnyMode(parent *os.Root, name string) (*os.Root, error) {
	named, err := parent.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !named.IsDir() {
		return nil, fmt.Errorf("%s is not a directory (mode %s)", name, named.Mode())
	}
	root, err := parent.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	opened, err := root.Stat(".")
	if err == nil && !os.SameFile(named, opened) {
		err = errors.New("changed while it was opened")
	}
	if err == nil {
		err = s.checkOwned(opened, fs.ModePerm)
	}
	if err != nil {
		_ = root.Close() // the open is abandoned; its close has nothing to report
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return root, nil
}

// readScopeKey reads, checks and opens dir's scope.key and returns K_u, which
// the caller clears. The file must be a regular file reached without a
// symlink, owned by the service user, at most 0600, and of a scope key's
// size; the record must be kind 0xFE, named "scope", at the key epoch. The
// uid's live GeneratedUID is read (lookupGeneratedUID, failing closed) and
// must equal the record's generation, which the record authenticates under
// W: a real, different answer is ErrScopeOwnerChanged. It returns the
// record's generation beside K_u. A scope.key that does not open under W is
// opened once more under master.next's W when the master keys carry one:
// the reader's rule for a Rewrap that crashed after moving it.
func (u *UserScope) readScopeKey(dir *os.Root, wrap func() (keys, error)) ([]byte, [generationSize]byte, error) {
	var zero [generationSize]byte
	r, err := u.s.readScopeKeyRecord(dir)
	if err != nil {
		return nil, zero, err
	}
	live, err := u.liveGUID()
	if err != nil {
		return nil, zero, err
	}
	k, err := wrap()
	if err != nil {
		return nil, zero, err
	}
	ku, err := u.openScopeKey(r, k)
	if err != nil {
		return nil, zero, err
	}
	if r.generation != live {
		clear(ku)
		return nil, zero, fmt.Errorf("%w: uid %d", ErrScopeOwnerChanged, u.uid)
	}
	return ku, r.generation, nil
}

// openScopeKey opens the scope.key record r under k's W and, failing that,
// under master.next's W when k carries one, and returns K_u, which the
// caller clears. A K_u whose identity the removed-scopes record lists is
// refused (errScopeRemoved), and so is every K_u while that record does not
// read: every open of a scope key, for a read, a grant, the start step's
// catch-up or a rebuild, comes here.
func (u *UserScope) openScopeKey(r record, k keys) ([]byte, error) {
	ku, err := r.open(k.wrap, u.scope)
	if err != nil && errors.Is(err, ErrCorrupt) && k.next != nil && k.next.wrap != nil {
		ku, err = r.open(k.next.wrap, u.scope)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", scopeKeyName, err)
	}
	if len(ku) != scopeKeySize {
		clear(ku)
		return nil, fmt.Errorf("%w: %s holds %d bytes, want %d", ErrCorrupt, scopeKeyName, len(ku), scopeKeySize)
	}
	if !u.allowRemoved {
		if err := u.s.checkScopeNotRemoved(u.uid, scopeKeyID(u.scope, ku)); err != nil {
			clear(ku)
			return nil, fmt.Errorf("%s: %w", u.scope, err)
		}
	}
	return ku, nil
}

// errScopeKeyUntrusted marks an openScopeForRevoke whose scope directory
// opened but whose scope.key is present and untrusted (ErrCorrupt: a
// second link, a mode wider than 0600, content that does not parse or
// open), all of which the service user can cause. rm-scope treats it as a
// missing scope.key.
var errScopeKeyUntrusted = errors.New("the scope's scope.key cannot be trusted")

// openScopeForRevoke opens the scope for a revocation: a withdraw, which
// only ever adds a tombstone. It reads no live GeneratedUID: the bound
// generation is the one scope.key's record authenticates under W, so a
// directory service that is slow, down, or answering for a new owner of the
// uid never keeps a revoked credential delivered. It opens scope.key under
// the live W or master.next's, so it runs at every step of a Rewrap, and
// needs no entries/ directory. A scope.key that is present but ErrCorrupt
// is also errScopeKeyUntrusted.
func (u *UserScope) openScopeForRevoke(root *os.Root, k keys) (*openedScope, error) {
	dir, err := u.openScopeDir(root, false)
	if err != nil {
		return nil, err
	}
	return u.openRevokeIn(dir, k)
}

// openScopeForRm is rm-scope's judge: openScopeForRevoke over the scope
// directory openScopeDirForRm opens, so neither .user's nor the scope
// directory's mode refuses it. pin is the device and inode of the scope
// directory it opened, set whenever it opened one, also when its
// scope.key is then missing or untrusted, so rm-scope can require the
// directory its walk holds at the name to be the one judged.
func (u *UserScope) openScopeForRm(root *os.Root, k keys) (*openedScope, rmDirPin, error) {
	dir, err := u.openScopeDirForRm(root)
	if err != nil {
		return nil, rmDirPin{}, err
	}
	var pin rmDirPin
	if fi, serr := dir.Stat("."); serr == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			pin = rmDirPin{dev: uint64(st.Dev), ino: st.Ino, set: true}
		}
	}
	o, err := u.openRevokeIn(dir, k)
	return o, pin, err
}

// rmDirPin is the device and inode of the scope directory rm-scope's
// judge opened (set when it opened one).
type rmDirPin struct {
	dev, ino uint64
	set      bool
}

// openRevokeIn is openScopeForRevoke over the opened scope directory dir,
// which it closes on a failure.
func (u *UserScope) openRevokeIn(dir *os.Root, k keys) (*openedScope, error) {
	r, err := u.s.readScopeKeyRecord(dir)
	var ku []byte
	if err == nil {
		ku, err = u.openScopeKey(r, k)
	}
	if err != nil {
		_ = dir.Close() // read-only so far
		if errors.Is(err, ErrCorrupt) {
			err = fmt.Errorf("%w: %w", errScopeKeyUntrusted, err)
		}
		return nil, err
	}
	return u.openedFrom(dir, r, ku)
}

// openedFrom is the opened scope from dir and the K_u ku its scope.key
// record r opened to; it clears ku, and closes dir on a failure.
func (u *UserScope) openedFrom(dir *os.Root, r record, ku []byte) (*openedScope, error) {
	uk, err := deriveKeys(ku, u.scope)
	dk := deliveriesKey(ku, u.scope)
	id := scopeKeyID(u.scope, ku)
	clear(ku) // only the derived keys are kept
	if err != nil {
		clear(dk)
		_ = dir.Close() // read-only so far
		return nil, err
	}
	return &openedScope{dir: dir, key: dk, gen: r.generation, uk: uk, id: id}, nil
}

// errScopeKeyJudgeOnly is openScopeForRmLoose's refusal of a scope.key the
// judge refused for something other than its link count or mode.
var errScopeKeyJudgeOnly = errors.New("scope.key's link count and mode are as the judge wants, so its refusal was for another cause")

// openScopeForRmLoose is rm-scope's second open of a scope.key the judge
// refused (errScopeKeyUntrusted): a second link or a mode wider than 0600
// fails the judge, but any local user can cause either, and the content
// still authenticates under the master, so removing the scope unlisted
// would let a copy put back open. It reads scope.key by descriptor as
// readScopeKeyRecord does (O_NOFOLLOW, a regular file, bounded at a scope
// key record's size, owned by the service user) without the link-count and
// mode checks, and opens it under W as openScopeForRevoke does. why names
// what the judge refused (its link count, its mode); a scope.key whose
// link count and mode pass is errScopeKeyJudgeOnly, and one that does not
// parse or authenticate is ErrCorrupt: both leave the removal unlisted.
func (u *UserScope) openScopeForRmLoose(root *os.Root, k keys) (o *openedScope, why string, err error) {
	dir, err := u.openScopeDirForRm(root)
	if err != nil {
		return nil, "", err
	}
	ok := false
	defer func() {
		if !ok {
			_ = dir.Close() // read-only
		}
	}()
	b, fi, err := readFile(dir, scopeKeyName, int64(maxScopeKeyRecordSize))
	if err != nil {
		return nil, "", fmt.Errorf("%w: %s: %w", ErrCorrupt, scopeKeyName, err)
	}
	st, sok := fi.Sys().(*syscall.Stat_t)
	if !sok || st.Uid != u.s.uid {
		return nil, "", fmt.Errorf("%w: %s is not the service user's", ErrCorrupt, scopeKeyName)
	}
	var whys []string
	if st.Nlink != 1 {
		whys = append(whys, fmt.Sprintf("it had %d links, not 1", st.Nlink))
	}
	if perm := fi.Mode().Perm(); perm&^fileMode != 0 {
		whys = append(whys, fmt.Sprintf("its mode was %04o, wider than %04o", perm, fileMode))
	}
	if len(whys) == 0 {
		return nil, "", errScopeKeyJudgeOnly
	}
	r, err := parseScopeKey(b)
	if err != nil {
		return nil, "", err
	}
	ku, err := u.openScopeKey(r, k)
	if err != nil {
		return nil, "", err
	}
	ok = true
	o, err = u.openedFrom(dir, r, ku)
	if err != nil {
		return nil, "", err
	}
	return o, strings.Join(whys, " and "), nil
}

// readScopeKeyRecord reads and parses dir's scope.key, unopened. The file
// must be a regular file reached without a symlink, owned by the service
// user, at most 0600, with one link, and of a scope key's size and shape. A
// missing one is errNoScopeKey. Rewrap reads it this way too: it re-seals
// the record and never needs the owner's live GeneratedUID.
func (s *FileStore) readScopeKeyRecord(dir *os.Root) (record, error) {
	b, fi, err := readFile(dir, scopeKeyName, int64(maxScopeKeyRecordSize))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return record{}, errNoScopeKey
	case errors.Is(err, errBadFile):
		return record{}, fmt.Errorf("%w: %s: %w", ErrCorrupt, scopeKeyName, err)
	case err != nil:
		return record{}, fmt.Errorf("read %s: %w", scopeKeyName, err)
	}
	if err := s.checkOwned(fi, fileMode); err != nil {
		return record{}, fmt.Errorf("%w: %s: %w", ErrCorrupt, scopeKeyName, err)
	}
	// scope.key is only ever written by rename, so it has one link; a second
	// one keeps a copy the store does not know of, which a later re-seal of
	// the key would leave behind.
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || st.Nlink != 1 {
		return record{}, fmt.Errorf("%w: %s has more than one link", ErrCorrupt, scopeKeyName)
	}
	return parseScopeKey(b)
}

// parseScopeKey decodes a scope.key file: a record of kind 0xFE, named
// "scope", at the key epoch, with a ciphertext exactly a sealed 32-byte key.
// Anything else is ErrCorrupt.
func parseScopeKey(b []byte) (record, error) {
	r, err := parseRecordOf(b, func(kind byte) bool { return kind == kindScopeKey })
	if err != nil {
		return record{}, fmt.Errorf("%s: %w", scopeKeyName, err)
	}
	if r.name != scopeKeyRecordName || r.version != scopeKeyEpoch || len(r.ciphertext) != scopeKeySize+tagSize {
		return record{}, fmt.Errorf("%w: %s does not hold this scope's key record", ErrCorrupt, scopeKeyName)
	}
	return r, nil
}

// mint makes the scope: the uid's GeneratedUID is read first, so a lookup
// that fails creates nothing; then .user/<uid>/ and entries/ are made, then
// the empty deliveries record (sequence 1) and its floor line, and scope.key
// is written last, so a scope whose scope.key opens has its entries/
// directory and its delivery record. A fresh K_u is never minted over entries: an entries/
// directory that holds anything, without a scope.key, is a scope whose key
// was lost, and ErrScopeAbsent, as the master is never minted over entries.
// The caller holds the exclusive lock.
func (u *UserScope) mint(root *os.Root, wrap []byte, grant func() error) (keys, *os.Root, error) {
	if err := u.s.eligibleUID(u.uid); err != nil {
		return keys{}, nil, err
	}
	g, err := u.liveGUID()
	if err != nil {
		return keys{}, nil, err
	}
	// The floor is read, and the grant's audit line appended, before the
	// first mkdir, so a mint refused for either creates nothing.
	// A floor past the first sequence for this owner's generation means a
	// delivery record under the lost key committed writes: a new key would
	// reset its history under a floor that refuses the reset record.
	if fl, err := u.s.userFloor.floor(u.scope, deliveriesFloorName, g); err != nil {
		return keys{}, nil, err
	} else if fl > 1 {
		return keys{}, nil, fmt.Errorf("%w: the user-scope floor records %s writes under a scope key that is gone; restore scope.key", ErrScopeAbsent, deliveriesName)
	}
	// Its own refusals come before the grant line, which is appended only
	// for a mint that goes ahead, and still before its first write.
	if dir, err := u.openScopeDir(root, false); err == nil {
		err = u.checkMintable(dir)
		_ = dir.Close() // read-only
		if err != nil {
			return keys{}, nil, err
		}
	} else if !errors.Is(err, errNoScopeKey) {
		return keys{}, nil, err
	}
	if err := grant(); err != nil {
		return keys{}, nil, err
	}
	dir, err := u.openScopeDir(root, true)
	if err != nil {
		return keys{}, nil, err
	}
	defer func() { _ = dir.Close() }() // writes are fsynced by writeFile
	if _, err := dir.Lstat(scopeKeyName); !errors.Is(err, fs.ErrNotExist) {
		return keys{}, nil, fmt.Errorf("%w: %s appeared while the scope was minted: %v", ErrCorrupt, scopeKeyName, err)
	}
	entries, err := u.s.openSubdir(dir, scopeEntriesName, true)
	if err != nil {
		return keys{}, nil, fmt.Errorf("%w: %s: %w", ErrCorrupt, scopeEntriesName, err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = entries.Close() // abandoned
		}
	}()
	names, err := readDirNames(entries, maxDirNames)
	if err != nil {
		return keys{}, nil, err
	}
	if len(names) > 0 {
		return keys{}, nil, fmt.Errorf("%w: entries/ holds %d names and there is no scope key, so a new key would orphan them; restore scope.key", ErrScopeAbsent, len(names))
	}
	ku := make([]byte, scopeKeySize)
	defer clear(ku) // only the derived keys outlive the mint
	if err := u.s.readRandom(ku); err != nil {
		return keys{}, nil, fmt.Errorf("mint the scope key: %w", err)
	}
	// The empty delivery record, sequence 1, before scope.key: a scope whose
	// scope.key opens has its record.
	dk := deliveriesKey(ku, u.scope)
	err = u.writeDeliveries(dir, dk, g, nil, 1, false)
	clear(dk)
	if err != nil {
		return keys{}, nil, err
	}
	rec := record{kind: kindScopeKey, name: scopeKeyRecordName, version: scopeKeyEpoch, generation: g, created: u.s.now().Unix()}
	if err := rec.seal(wrap, u.scope, ku, u.s.rand); err != nil {
		return keys{}, nil, err
	}
	if err := u.s.writeFile(dir, scopeKeyName, rec.marshal()); err != nil {
		return keys{}, nil, err
	}
	uk, err := deriveKeys(ku, u.scope)
	if err != nil {
		return keys{}, nil, err
	}
	ok = true
	return uk, entries, nil
}

// checkMintable refuses a mint into the existing scope directory dir: a
// scope.key there (ErrCorrupt), or an entries/ that holds names and no
// scope.key, a scope whose key was lost (ErrScopeAbsent). It writes
// nothing; mint checks again once the directories are made.
func (u *UserScope) checkMintable(dir *os.Root) error {
	if _, err := dir.Lstat(scopeKeyName); !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %s appeared while the scope was minted: %v", ErrCorrupt, scopeKeyName, err)
	}
	entries, err := u.s.openSubdir(dir, scopeEntriesName, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrCorrupt, scopeEntriesName, err)
	}
	defer func() { _ = entries.Close() }() // read-only
	names, err := readDirNames(entries, maxDirNames)
	if err != nil {
		return err
	}
	if len(names) > 0 {
		return fmt.Errorf("%w: entries/ holds %d names and there is no scope key, so a new key would orphan them; restore scope.key", ErrScopeAbsent, len(names))
	}
	return nil
}
