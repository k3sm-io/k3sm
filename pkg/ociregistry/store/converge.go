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

package store

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// The limits of one pass.
const (
	// convergeMaxEntries is how many directory entries a scan reads. Past it the
	// pass works on what it saw, and a keeper whose names went unseen is refused
	// for an uncounted link.
	convergeMaxEntries = 250_000
	// convergeMaxMerges is how many names a pass replaces.
	convergeMaxMerges = 1024
	// convergeMaxHashBytes is how much a pass hashes, keepers and targets
	// together. The first digest it hashes is exempt: see hashAllowed.
	convergeMaxHashBytes = 16 << 30
	// convergeHashRate is how fast a pass hashes, in bytes a second.
	convergeHashRate = 256 << 20
	// convergeMaxNames is how many names one inode may have. A keeper at it takes
	// no more, and the copies stay.
	convergeMaxNames = 32_000
	// convergeNlinkPin is the value st_nlink stops at on darwin. A read of it
	// cannot tell 65,535 names from 70,000, so it refuses the keeper.
	convergeNlinkPin = 65_535
	// convergeMinPace is the shortest wait the hash rate is held with; a shorter
	// debt is carried to the next chunk.
	convergeMinPace = 10 * time.Millisecond
	// convergeMaxSyncFailures is how many digests in a row may fail a sync before
	// the pass stops: one bad inode costs its digest, a failing volume the pass.
	convergeMaxSyncFailures = 3
)

// SkipReason says why a pass left a copy or passed over a keeper.
type SkipReason string

// Reasons a pass leaves a copy in place. Each keeps the copy for a later pass.
const (
	// SkipKeeperRefused is a keeper candidate passed over: disqualified by its
	// mtime, owner or mode, gone, swapped, or with other names than the scan counted.
	// It counts candidates; every other reason counts names, except SkipSync,
	// which counts failed syncs.
	SkipKeeperRefused SkipReason = "keeper-refused"
	// SkipNoKeeper is a target left because no candidate could be its keeper.
	SkipNoKeeper SkipReason = "no-keeper"
	// SkipKeeperFull is a target of a keeper that takes no more links this pass:
	// it failed the link test after it was verified, whichever way its count
	// moved, or link(2) refused it with
	// EMLINK, EPERM or ENOTSUP. Such a target spends no budget, past the one that
	// found out.
	SkipKeeperFull SkipReason = "keeper-full"
	// SkipKeeperGone is a target whose keeper's name was gone or was another
	// inode at the link, with its link count unmoved.
	SkipKeeperGone SkipReason = "keeper-gone"
	// SkipNewer is a target newer than its keeper.
	SkipNewer SkipReason = "newer"
	// SkipOwnerOrMode is a target with a wrong owner or a mode other than 0600.
	SkipOwnerOrMode SkipReason = "owner-or-mode"
	// SkipNotReviewed is a target in a repository the GC marker does not name.
	SkipNotReviewed SkipReason = "not-reviewed"
	// SkipNoTag is a target in a repository with no tagged row.
	SkipNoTag SkipReason = "no-tag"
	// SkipSize is a target of another size than its verified keeper.
	SkipSize SkipReason = "size"
	// SkipHashBudget is a target the pass's hash budget could not cover.
	SkipHashBudget SkipReason = "hash-budget"
	// SkipTargetChanged is a target that no longer names the inode the scan saw,
	// or whose repository left the store.
	SkipTargetChanged SkipReason = "target-changed"
	// SkipLock is a target whose repository lock could not be taken.
	SkipLock SkipReason = "lock"
	// SkipCrossDevice is a link that failed with EXDEV. Grouping by device should
	// prevent it; a copy is what is already there, so there is no fallback.
	SkipCrossDevice SkipReason = "cross-device"
	// SkipNoSpace is a link or rename that failed with ENOSPC.
	SkipNoSpace SkipReason = "no-space"
	// SkipLinkFailed is a link or rename that failed any other way.
	SkipLinkFailed SkipReason = "link-failed"
	// SkipSync is a keeper or directory F_FULLFSYNC that failed. It costs the rest
	// of that digest for this pass; see Converge for when it ends the pass.
	SkipSync SkipReason = "sync"
)

// ConvergeOptions is what a pass needs from its caller.
type ConvergeOptions struct {
	// Reviewed says whether the GC marker, valid for this store's id, names a
	// repository. Only such a repository is a target. A nil Reviewed names none,
	// so the pass rewrites nothing.
	Reviewed func(ref.Name) bool
	// Log receives each merge and each corrupt file (slog.Default when nil).
	Log *slog.Logger
	// Rotation is what passes share so that no digest leads them all. The loop
	// driving the passes keeps one; nil leaves every pass in the fixed order.
	Rotation *ConvergeRotation

	// limits and seams are zero outside this package's tests.
	limits convergeLimits
	seams  convergeSeams
}

// convergeLimits overrides the pass's limits where a field is non-zero.
type convergeLimits struct {
	entries, merges int
	hashBytes, rate int64
	names           uint64
}

// convergeSeams are the calls a test replaces, each defaulting to the real one.
type convergeSeams struct {
	link, rename func(oldpath, newpath string) error
	sync         func(*os.File) error
	open         func(path string) (*os.File, error)
	nlink        func(os.FileInfo) uint64
	uid          func() uint32
	clock        func() time.Time
	pace         func(context.Context, time.Duration) error
	// scanned runs after the scan, and beforeMerge before each target's lock.
	scanned     func()
	beforeMerge func(ref.Name)
}

// ConvergeRotation keeps a digest that spent hash budget and still has copies
// from leading the next pass, which also keeps it from setting the schedule for
// every pass until its last copy merged. It holds only that order, in memory; a
// new one starts again at largest first, and costs nothing else. The zero value
// is ready to use.
type ConvergeRotation struct {
	mu sync.Mutex
	// pass counts the passes recorded, and served is the pass each unfinished
	// group last hashed in. Groups no longer in a pass's work leave it, so it is no
	// larger than the table.
	pass   uint64
	served map[convergeGroupKey]uint64
}

// order sorts groups, which are largest first, so that the longest since served
// comes first. A group never served comes before any that was, and size decides
// among equals.
func (r *ConvergeRotation) order(groups []*convergeGroup) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	slices.SortStableFunc(groups, func(a, b *convergeGroup) int {
		return cmp.Compare(r.served[a.key()], r.served[b.key()])
	})
}

// record notes one pass over groups.
func (r *ConvergeRotation) record(groups []*convergeGroup) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pass++
	next := make(map[convergeGroupKey]uint64)
	for _, g := range groups {
		switch at, ok := r.served[g.key()]; {
		case g.pending() <= 0:
		case g.hashed:
			next[g.key()] = r.pass
		case ok:
			next[g.key()] = at
		}
	}
	r.served = next
}

// ConvergeReport is what a pass did. It holds no digest or repository name, so a
// caller may publish it.
type ConvergeReport struct {
	// Merged is how many names now point at their keeper.
	Merged int
	// ReclaimedBytes counts only inodes whose last name went.
	ReclaimedBytes int64
	// Pending is how many names still hold a copy of a digest with another inode.
	Pending int
	// CorruptTargets is how many target inodes failed their hash or read.
	CorruptTargets int
	// CorruptReplaced is how many names of such inodes the pass replaced.
	CorruptReplaced int
	// CorruptKeepers is how many keeper candidates failed their hash or read.
	CorruptKeepers int
	// HashedBytes is how much the pass hashed.
	HashedBytes int64
	// ScanTruncated says the scan stopped at its entry limit. A later pass scans the
	// same entries, so this alone is no reason to run one.
	ScanTruncated bool
	// MergeLimited says the pass spent its merge limit.
	MergeLimited bool
	// Skipped counts what was left, by reason.
	Skipped map[SkipReason]int
}

// LeftWork reports whether the pass's own limits left copies that a later pass
// could merge: its hash budget, or its merge limit with copies pending. Every
// other reason a copy stays repeats until something changes, so it does not count.
func (r ConvergeReport) LeftWork() bool {
	return r.Skipped[SkipHashBudget] > 0 || (r.MergeLimited && r.Pending > 0)
}

// convergeStat is what the pass reads from one lstat or fstat.
type convergeStat struct {
	dev, ino uint64
	uid      uint32
	size     int64
	mtime    time.Time
	mode     fs.FileMode
}

func statOf(fi os.FileInfo) (convergeStat, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return convergeStat{}, false
	}
	return convergeStat{
		dev: uint64(st.Dev), ino: st.Ino, uid: st.Uid,
		size: fi.Size(), mtime: fi.ModTime(), mode: fi.Mode(),
	}, true
}

// inodeKey identifies an inode in the store.
type inodeKey struct{ dev, ino uint64 }

func (c convergeStat) key() inodeKey { return inodeKey{c.dev, c.ino} }

// convergeInode is one inode of a digest and the repositories naming it, in the
// lexical order of the scan.
type convergeInode struct {
	stat  convergeStat
	names []ref.Name
}

// convergeGroup is every inode of one digest on one device.
type convergeGroup struct {
	digest digest.Digest
	dev    uint64
	inodes map[uint64]*convergeInode
	// order is the inodes newest first, ties to the first repository.
	order []*convergeInode
	// keeper is the verified keeper, and merged how many names went to it.
	keeper *convergeInode
	merged int
	// hashed says this pass read bytes of the group.
	hashed bool
}

func (g *convergeGroup) key() convergeGroupKey { return convergeGroupKey{g.digest, g.dev} }

type convergeGroupKey struct {
	digest digest.Digest
	dev    uint64
}

// convergeTable is a scan's result: a hint every later step re-checks.
type convergeTable struct {
	groups map[convergeGroupKey]*convergeGroup
	// names counts the blobs/ names each inode has, under any digest.
	names map[inodeKey]uint64
}

func newConvergeTable() *convergeTable {
	return &convergeTable{groups: map[convergeGroupKey]*convergeGroup{}, names: map[inodeKey]uint64{}}
}

// add records that repository n names blob d with st. Files of size 0 are
// counted as names and take no further part.
func (t *convergeTable) add(n ref.Name, d digest.Digest, st convergeStat) {
	t.names[st.key()]++
	if st.size == 0 {
		return
	}
	k := convergeGroupKey{d, st.dev}
	g := t.groups[k]
	if g == nil {
		g = &convergeGroup{digest: d, dev: st.dev, inodes: map[uint64]*convergeInode{}}
		t.groups[k] = g
	}
	in := g.inodes[st.ino]
	if in == nil {
		in = &convergeInode{stat: st}
		g.inodes[st.ino] = in
	}
	in.names = append(in.names, n)
}

// work returns the groups with two or more inodes, largest first, each with its
// inodes ordered newest first.
func (t *convergeTable) work() []*convergeGroup {
	var out []*convergeGroup
	for _, g := range t.groups {
		if len(g.inodes) < 2 {
			continue
		}
		g.order = slices.SortedFunc(maps.Values(g.inodes), func(a, b *convergeInode) int {
			if c := b.stat.mtime.Compare(a.stat.mtime); c != 0 {
				return c
			}
			return strings.Compare(a.names[0].String(), b.names[0].String())
		})
		out = append(out, g)
	}
	slices.SortFunc(out, func(a, b *convergeGroup) int {
		return cmp.Or(
			cmp.Compare(b.size(), a.size()),
			strings.Compare(a.digest.String(), b.digest.String()),
			cmp.Compare(a.dev, b.dev),
		)
	})
	return out
}

// size is the largest size the group's inodes claim. The newest may lie, so this
// only orders the work.
func (g *convergeGroup) size() int64 {
	var size int64
	for _, in := range g.inodes {
		size = max(size, in.stat.size)
	}
	return size
}

// pending is how many names of the group do not share its keeper's inode: the
// verified keeper when there is one, otherwise the newest.
func (g *convergeGroup) pending() int {
	keeper := g.keeper
	if keeper == nil {
		keeper = g.order[0]
	}
	n := -g.merged
	for _, in := range g.inodes {
		if in != keeper {
			n += len(in.names)
		}
	}
	return n
}

// Converge is one pass of the background dedupe: for each digest held as two or
// more inodes on one device, it makes every repository it may rewrite name the
// inode with the newest mtime. Commits and mounts do none of this, so a push
// answers the same whatever other repositories hold, and copies already on disk
// converge by the same code. It keeps no state but the order o.Rotation holds; the
// table is rebuilt each pass.
//
// Link-or-keep holds throughout: every failure keeps the copy, and the one step
// that drops a name is an atomic rename with verified, durable bytes behind it.
//
//  1. Scan, no locks: lstat every blobs/<algorithm>/<hex> of every repository
//     and count the names each inode has.
//  2. Choose the keeper: newest mtime, ties to the first repository. A future
//     mtime, a wrong owner or a mode other than 0600 disqualifies it.
//  3. Verify, no locks: hash through a descriptor, then F_FULLFSYNC, because an
//     inode another writer of the layout left has no durability promise from us. A hash failure logs
//     ErrStoreCorrupt and the next-newest is tried. A link the scan did not count
//     (a crashed commit's session, a crashed merge's temp, a mount after the
//     scan), a counted name since removed or a pinned st_nlink refuses the keeper
//     the same way.
//  4. Hash each target, no locks, once per inode. A mismatch or read error logs
//     ErrStoreCorrupt and the merge goes ahead, since the replacement is the
//     repair: the hash is evidence and gates nothing.
//  5. Merge one target at a time, holding only that target's repository lock:
//     re-check it all, link the keeper's path to .temps/.tmp-<uuid>, check that it
//     is the descriptor's inode, rename it over the target, F_FULLFSYNC both
//     directories. Two repository locks are never held together, and the lock is
//     held for no hash.
//
// The keeper is at least as new as its target and target touches take the lock
// the merge holds, so a merge never makes a blob look older to GC, and the pass
// writes no mtime. A keeper's sync or a directory's after a rename, which cannot
// be undone and where either name is good, may fail. ENOTSUP or ENOTTY is how a
// volume without F_FULLFSYNC answers, so nothing on it can merge and the pass ends
// with the error. Any other failure is one inode's: the pass counts it, leaves
// the rest of that digest and goes on, and ends with the error only after
// convergeMaxSyncFailures digests in a row. The report is valid alongside any
// error.
func (s *Store) Converge(ctx context.Context, o ConvergeOptions) (ConvergeReport, error) {
	p := newConvergePass(s, o)
	table, err := p.scan(ctx)
	if err != nil {
		return p.rep, err
	}
	p.table = table
	if p.o.seams.scanned != nil {
		p.o.seams.scanned()
	}
	groups := table.work()
	p.o.Rotation.order(groups)
	defer func() { p.o.Rotation.record(groups) }()
	var runErr error
	for _, g := range groups {
		if runErr = ctx.Err(); runErr != nil || p.mergesLeft() == 0 {
			break
		}
		if runErr = p.afterGroup(p.converge(ctx, g)); runErr != nil {
			break
		}
	}
	for _, g := range groups {
		p.rep.Pending += g.pending()
	}
	p.rep.MergeLimited = p.mergesLeft() <= 0
	return p.rep, runErr
}

// convergePass is the state of one pass.
type convergePass struct {
	s     *Store
	o     ConvergeOptions
	log   *slog.Logger
	rep   ConvergeReport
	table *convergeTable
	lim   convergeLimits
	// first is true until the pass has finished with its first digest's first
	// target: see hashAllowed.
	first bool
	// hashStart is when the first byte was hashed, for the rate.
	hashStart time.Time
	// syncFailures is how many digests in a row have failed a sync.
	syncFailures int
	// tagged caches whether a repository has a tagged row. It only saves hashing
	// a target the lock's re-read would refuse.
	tagged map[string]bool
	euid   uint32
}

func newConvergePass(s *Store, o ConvergeOptions) *convergePass {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Reviewed == nil {
		o.Reviewed = func(ref.Name) bool { return false }
	}
	lim := o.limits
	lim.entries = cmp.Or(lim.entries, convergeMaxEntries)
	lim.merges = cmp.Or(lim.merges, convergeMaxMerges)
	lim.hashBytes = cmp.Or(lim.hashBytes, convergeMaxHashBytes)
	lim.rate = cmp.Or(lim.rate, convergeHashRate)
	lim.names = cmp.Or(lim.names, convergeMaxNames)
	sm := &o.seams
	if sm.link == nil {
		sm.link = os.Link
	}
	if sm.rename == nil {
		sm.rename = os.Rename
	}
	if sm.sync == nil {
		sm.sync = fullSync
	}
	if sm.open == nil {
		sm.open = func(p string) (*os.File, error) { return openRegular(p, os.O_RDONLY) }
	}
	if sm.nlink == nil {
		sm.nlink = nlink
	}
	if sm.uid == nil {
		sm.uid = func() uint32 { return uint32(os.Geteuid()) }
	}
	if sm.clock == nil {
		sm.clock = time.Now
	}
	if sm.pace == nil {
		sm.pace = paceWait
	}
	return &convergePass{
		s: s, o: o, log: o.Log, lim: lim, first: true, tagged: map[string]bool{}, euid: sm.uid(),
		rep: ConvergeReport{Skipped: map[SkipReason]int{}},
	}
}

// paceWait waits d, or until ctx is done.
func paceWait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (p *convergePass) mergesLeft() int { return p.lim.merges - p.rep.Merged }

func (p *convergePass) skip(r SkipReason, n int) { p.rep.Skipped[r] += n }

// afterGroup returns the error that ends the pass, given what one group returned.
func (p *convergePass) afterGroup(err error) error {
	if !errors.Is(err, errSyncFailed) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.ENOTTY) {
		return err
	}
	p.syncFailures++
	if p.syncFailures < convergeMaxSyncFailures {
		return nil
	}
	return fmt.Errorf("%d digests in a row: %w", p.syncFailures, err)
}

// scan is step 1. A repository or directory it cannot read is passed over: its
// names go uncounted, which at worst refuses a keeper.
func (p *convergePass) scan(ctx context.Context) (*convergeTable, error) {
	repos, err := p.s.Repositories()
	if err != nil {
		return nil, err
	}
	t := newConvergeTable()
	entries := 0
	for _, n := range repos {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		dir, err := p.s.path(n, blobsDir)
		if err != nil {
			p.log.Warn("dedupe scan passed over a repository", "repository", n.String(), "error", err)
			continue
		}
		algs, err := os.ReadDir(dir)
		if err != nil {
			continue // GC removed it meanwhile, or it reads next pass
		}
		for _, a := range algs {
			if !a.IsDir() || !isAlgorithm(a.Name()) {
				continue
			}
			ents, err := os.ReadDir(filepath.Join(dir, a.Name()))
			if err != nil {
				continue
			}
			for _, e := range ents {
				if entries >= p.lim.entries {
					p.rep.ScanTruncated = true
					p.log.Warn("dedupe scan stopped at its entry limit", "entries", entries)
					return t, nil
				}
				entries++
				if !e.Type().IsRegular() {
					continue
				}
				d, err := ref.ParseDigest(a.Name() + ":" + e.Name())
				if err != nil {
					continue // a temp, or nothing the store wrote
				}
				fi, err := e.Info()
				if err != nil {
					continue // removed meanwhile
				}
				if st, ok := statOf(fi); ok && fi.Mode().IsRegular() {
					t.add(n, d, st)
				}
			}
		}
	}
	return t, nil
}

// goodOwnerMode is the test a keeper and a target share.
func (p *convergePass) goodOwnerMode(st convergeStat) bool {
	return st.uid == p.euid && st.mode == fs.FileMode(fileMode)
}

// goodKeeper is step 2's test.
func (p *convergePass) goodKeeper(st convergeStat) bool {
	return p.goodOwnerMode(st) && !st.mtime.After(p.s.now())
}

// hasTag reports whether n has a tagged row, as a hint: it costs one read of its
// index.json a pass, and the merge reads it again under the lock.
func (p *convergePass) hasTag(n ref.Name) bool {
	if v, ok := p.tagged[n.String()]; ok {
		return v
	}
	idx, err := p.s.Index(n)
	v := err == nil && hasTaggedRow(idx)
	p.tagged[n.String()] = v
	return v
}

func hasTaggedRow(idx ispec.Index) bool {
	return slices.ContainsFunc(idx.Manifests, func(r ispec.Descriptor) bool {
		_, ok := r.Annotations[ispec.AnnotationRefName]
		return ok
	})
}

// anyTarget reports whether keeper has a name it could replace, counting nothing.
// A candidate without one is not worth hashing.
func (p *convergePass) anyTarget(g *convergeGroup, keeper *convergeInode) bool {
	for _, in := range g.order {
		if in == keeper || in.stat.mtime.After(keeper.stat.mtime) || !p.goodOwnerMode(in.stat) {
			continue
		}
		for _, n := range in.names {
			if p.o.Reviewed(n) && p.hasTag(n) {
				return true
			}
		}
	}
	return false
}

// converge runs steps 2 to 5 for one group.
func (p *convergePass) converge(ctx context.Context, g *convergeGroup) error {
	hashedBefore := p.rep.HashedBytes
	defer func() {
		// Whatever this digest cost, the exemption covers one digest.
		if p.rep.HashedBytes > 0 {
			p.first = false
		}
		g.hashed = p.rep.HashedBytes > hashedBefore
	}()
	k, err := p.chooseKeeper(ctx, g)
	if err != nil {
		return err
	}
	if k == nil {
		return nil
	}
	defer k.f.Close()
	g.keeper = k.inode
	if err := p.mergeInto(ctx, g, k); err != nil {
		return err
	}
	p.syncFailures = 0 // the keeper synced, and so did every directory it merged into
	return nil
}

// verifiedKeeper is a keeper that passed step 3, with the descriptor that
// proved it.
type verifiedKeeper struct {
	inode  *convergeInode
	f      *os.File
	name   ref.Name
	path   string
	size   int64
	merged uint64
	full   bool
}

// errNoBudget stops the search for a keeper when the hash budget cannot cover
// the next candidate.
var errNoBudget = errors.New("the pass's hash budget is spent")

// errSyncFailed marks an error as a failed keeper or directory sync, which costs
// its digest and need not end the pass: see afterGroup.
var errSyncFailed = errors.New("sync failed")

// chooseKeeper returns the newest inode that passes steps 2 and 3, or nil. An
// error ends this digest's work, and the pass as afterGroup says. A candidate with
// nothing it could merge is not hashed; neither is one that fails a cheaper test
// first.
func (p *convergePass) chooseKeeper(ctx context.Context, g *convergeGroup) (*verifiedKeeper, error) {
	tried := false
	for _, in := range g.order {
		if !p.goodKeeper(in.stat) {
			p.skip(SkipKeeperRefused, 1)
			tried = true
			continue
		}
		if !p.anyTarget(g, in) {
			continue
		}
		tried = true
		k, err := p.verifyKeeper(ctx, g, in)
		if errors.Is(err, errNoBudget) {
			p.skip(SkipHashBudget, g.pending())
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if k != nil {
			return k, nil
		}
	}
	if tried {
		p.skip(SkipNoKeeper, g.pending())
		return nil, nil
	}
	// No inode had work: say why, against the newest.
	for _, in := range g.order[1:] {
		p.classify(g, g.order[0], -1, in)
	}
	return nil, nil
}

// verifyKeeper is step 3 for one candidate: nil, nil when it is refused.
func (p *convergePass) verifyKeeper(ctx context.Context, g *convergeGroup, in *convergeInode) (*verifiedKeeper, error) {
	name := in.names[0]
	refuse := func(why string, args ...any) (*verifiedKeeper, error) {
		p.skip(SkipKeeperRefused, 1)
		p.log.Info("dedupe refused a keeper", append([]any{"reason", why, "repository", name.String(), "digest", g.digest.String()}, args...)...)
		return nil, nil
	}
	path, err := p.s.blobPath(name, g.digest)
	if err != nil {
		return refuse("path", "error", err)
	}
	f, err := p.o.seams.open(path)
	if err != nil {
		return refuse("open", "error", err)
	}
	keep := false
	defer func() {
		if !keep {
			f.Close()
		}
	}()
	fi, err := f.Stat()
	if err != nil {
		return refuse("stat", "error", err)
	}
	st, ok := statOf(fi)
	if !ok || st.key() != in.stat.key() {
		return refuse("swapped")
	}
	if !p.goodKeeper(st) {
		return refuse("owner, mode or mtime")
	}
	if !p.nlinkOK(fi, p.table.names[st.key()]) {
		return refuse("uncounted link or name limit", "links", p.o.seams.nlink(fi), "counted", p.table.names[st.key()])
	}
	if !p.hashAllowed(st.size) {
		return nil, errNoBudget
	}
	good, err := p.hash(ctx, f, g.digest)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if err != nil || !good {
		p.rep.CorruptKeepers++
		p.log.Error("dedupe found a corrupt blob", "error", ErrStoreCorrupt, "repository", name.String(), "digest", g.digest.String(), "cause", err)
		return nil, nil
	}
	if err := p.o.seams.sync(f); err != nil {
		p.skip(SkipSync, 1)
		p.log.Error("dedupe could not sync a keeper", "repository", name.String(), "digest", g.digest.String(), "cause", err)
		return nil, fmt.Errorf("%w: keeper %s in %s: %w", errSyncFailed, g.digest, name, err)
	}
	keep = true
	return &verifiedKeeper{inode: in, f: f, name: name, path: path, size: st.size}, nil
}

// nlinkOK is the keeper's link test: exactly the names counted, not the pin, and
// room for one more. A count below the scan's is a name removed since, and with
// more removed than appeared it would otherwise hide an uncounted link. Refusing
// only keeps the copy, and the next pass counts again. A removal and a link that
// cancel out read the same as neither, which no count can see. That leaves the
// merge's own checks: it links by path and compares the inode, and a session
// sharing an inode with another name refuses an append at its open.
func (p *convergePass) nlinkOK(fi os.FileInfo, counted uint64) bool {
	n := p.o.seams.nlink(fi)
	return n == counted && n < convergeNlinkPin && n < p.lim.names
}

// hashAllowed reports whether the budget covers a file of size bytes. The pass's
// first digest passes whatever its size, through its keeper and its first
// target: a merge needs both hashed, so a layer larger than the budget would
// otherwise hash its keeper every pass and never merge. It converges one target
// each time it leads. ConvergeRotation decides when that is, so one digest in many
// copies does not take the budget from every other until it is done.
func (p *convergePass) hashAllowed(size int64) bool {
	return p.first || p.rep.HashedBytes+size <= p.lim.hashBytes
}

// hash reads f from its start against d through the rate limit.
func (p *convergePass) hash(ctx context.Context, f *os.File, d digest.Digest) (bool, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	if p.hashStart.IsZero() {
		p.hashStart = p.o.seams.clock()
	}
	v := d.Verifier()
	buf := make([]byte, 1<<20)
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		n, err := f.Read(buf)
		if n > 0 {
			_, _ = v.Write(buf[:n]) // a digest's Write never fails
			p.rep.HashedBytes += int64(n)
			if werr := p.holdRate(ctx); werr != nil {
				return false, werr
			}
		}
		if errors.Is(err, io.EOF) {
			return v.Verified(), nil
		}
		if err != nil {
			return false, err
		}
	}
}

// holdRate waits until the bytes hashed so far fit the rate. float64 keeps a
// blob past 9 GiB from overflowing the nanoseconds.
func (p *convergePass) holdRate(ctx context.Context) error {
	want := time.Duration(float64(p.rep.HashedBytes) / float64(p.lim.rate) * float64(time.Second))
	debt := want - p.o.seams.clock().Sub(p.hashStart)
	if debt < convergeMinPace {
		return nil
	}
	return p.o.seams.pace(ctx, debt)
}

// mergeInto is steps 4 and 5 for every other inode of the group.
func (p *convergePass) mergeInto(ctx context.Context, g *convergeGroup, k *verifiedKeeper) error {
	for _, in := range g.order {
		if in == k.inode {
			continue
		}
		names := p.classify(g, k.inode, k.size, in)
		if len(names) == 0 {
			continue
		}
		if !k.full {
			fi, err := k.f.Stat()
			k.full = err != nil || !p.nlinkOK(fi, p.table.names[k.inode.stat.key()]+k.merged)
		}
		if k.full {
			p.skip(SkipKeeperFull, len(names))
			continue
		}
		if p.mergesLeft() == 0 {
			return nil
		}
		if !p.hashAllowed(in.stat.size) {
			p.skip(SkipHashBudget, len(names))
			continue
		}
		corrupt, ok, err := p.hashTarget(ctx, g, in, names)
		if err != nil {
			return err
		}
		if !ok {
			p.skip(SkipTargetChanged, len(names))
			continue
		}
		p.first = false
		for i, n := range names {
			if k.full {
				p.skip(SkipKeeperFull, len(names)-i)
				break
			}
			if p.mergesLeft() == 0 {
				return nil
			}
			if err := p.mergeOne(ctx, g, k, in, n, corrupt); err != nil {
				return err
			}
		}
	}
	return nil
}

// classify is the cheap half of steps 4 and 5: it counts every name of in that
// cannot be a target of keeper and returns the rest. A target's size is judged
// only against a verified keeper, so size is negative for any other.
func (p *convergePass) classify(g *convergeGroup, keeper *convergeInode, size int64, in *convergeInode) []ref.Name {
	switch {
	case in.stat.mtime.After(keeper.stat.mtime):
		p.skip(SkipNewer, len(in.names))
		return nil
	case !p.goodOwnerMode(in.stat):
		p.skip(SkipOwnerOrMode, len(in.names))
		return nil
	case size >= 0 && in.stat.size != size:
		p.skip(SkipSize, len(in.names))
		p.log.Warn("dedupe left a blob of the wrong size", "repository", in.names[0].String(), "digest", g.digest.String(), "size", in.stat.size, "want", size)
		return nil
	}
	var out []ref.Name
	for _, n := range in.names {
		switch {
		case !p.o.Reviewed(n):
			p.skip(SkipNotReviewed, 1)
		case !p.hasTag(n):
			p.skip(SkipNoTag, 1)
		default:
			out = append(out, n)
		}
	}
	return out
}

// hashTarget is step 4 for one inode, through the first of names that still
// names it. ok is false when none does. corrupt is the evidence, and gates
// nothing. An error is only ctx ending the pass.
func (p *convergePass) hashTarget(ctx context.Context, g *convergeGroup, in *convergeInode, names []ref.Name) (corrupt, ok bool, err error) {
	for _, n := range names {
		f := p.openInode(n, g.digest, in)
		if f == nil {
			continue
		}
		defer f.Close()
		good, herr := p.hash(ctx, f, g.digest)
		if cerr := ctx.Err(); cerr != nil {
			return false, false, cerr
		}
		if herr != nil || !good {
			p.rep.CorruptTargets++
			p.log.Error("dedupe found a corrupt blob", "error", ErrStoreCorrupt, "repository", n.String(), "digest", g.digest.String(), "cause", herr)
			return true, true, nil
		}
		return false, true, nil
	}
	return false, false, nil
}

// openInode opens n's blob d when it still names in, and returns nil otherwise.
func (p *convergePass) openInode(n ref.Name, d digest.Digest, in *convergeInode) *os.File {
	path, err := p.s.blobPath(n, d)
	if err != nil {
		return nil
	}
	f, err := p.o.seams.open(path)
	if err != nil {
		return nil
	}
	fi, err := f.Stat()
	if err == nil {
		if st, ok := statOf(fi); ok && st.key() == in.stat.key() {
			return f
		}
	}
	f.Close()
	return nil
}

// mergeOne is step 5 for one name. Only ctx ending or a directory sync failing
// return an error, and the latter ends only this digest's work unless afterGroup
// says otherwise; any other miss counts a reason and keeps the copy.
func (p *convergePass) mergeOne(ctx context.Context, g *convergeGroup, k *verifiedKeeper, in *convergeInode, n ref.Name, corrupt bool) error {
	if hook := p.o.seams.beforeMerge; hook != nil {
		hook(n)
	}
	if err := ctx.Err(); err != nil {
		return err // the pass stops between merges
	}
	var stop error
	err := p.s.WithLock(ctx, n, func(l *Locked) error {
		reason, reclaimed, err := p.relink(l, g, k, in, n)
		if reason != "" {
			p.skip(reason, 1)
			if reason == SkipSync {
				// The rename cannot be undone, and either name is good.
				p.log.Error("dedupe could not sync a directory after a merge", "repository", n.String(), "digest", g.digest.String(), "cause", err)
				stop = fmt.Errorf("%w: blobs of %s after merging %s: %w", errSyncFailed, n, g.digest, err)
			} else {
				if err != nil {
					p.log.Warn("dedupe kept a copy", "reason", string(reason), "repository", n.String(), "digest", g.digest.String(), "cause", err)
				}
				return nil
			}
		}
		p.rep.Merged++
		p.rep.ReclaimedBytes += reclaimed
		g.merged++
		k.merged++
		if corrupt {
			p.rep.CorruptReplaced++
		}
		p.log.Info("dedupe merged a blob", "repository", n.String(), "digest", g.digest.String(), "keeper", k.name.String(), "size", k.size, "reclaimed", reclaimed)
		return nil
	})
	switch {
	case stop != nil:
		return stop
	case err == nil:
		return nil
	case ctx.Err() != nil:
		return ctx.Err()
	case errors.Is(err, ErrRepositoryUnknown):
		p.skip(SkipTargetChanged, 1)
	default:
		p.skip(SkipLock, 1)
		p.log.Warn("dedupe kept a copy", "reason", string(SkipLock), "repository", n.String(), "digest", g.digest.String(), "cause", err)
	}
	return nil
}

// relink is the part of step 5 that runs under n's lock. A reason other than
// SkipSync means the copy stayed. An empty reason, or SkipSync, means the rename
// happened; reclaimed is the inode's size if that was its last name.
func (p *convergePass) relink(l *Locked, g *convergeGroup, k *verifiedKeeper, in *convergeInode, n ref.Name) (SkipReason, int64, error) {
	idx, err := l.Index()
	if err != nil {
		return SkipTargetChanged, 0, err
	}
	if !hasTaggedRow(idx) {
		return SkipNoTag, 0, nil
	}
	dst, err := p.s.blobPath(n, g.digest)
	if err != nil {
		return SkipTargetChanged, 0, err
	}
	tfi, err := os.Lstat(dst)
	if err != nil {
		return SkipTargetChanged, 0, err
	}
	tst, ok := statOf(tfi)
	if !ok || !tfi.Mode().IsRegular() || tst.key() != in.stat.key() || tst.size != k.size {
		return SkipTargetChanged, 0, nil
	}
	if !p.goodOwnerMode(tst) {
		return SkipOwnerOrMode, 0, nil
	}
	kfi, err := k.f.Stat()
	if err != nil {
		return SkipKeeperGone, 0, err
	}
	if os.SameFile(kfi, tfi) {
		return SkipTargetChanged, 0, nil
	}
	if kfi.ModTime().Before(tfi.ModTime()) {
		return SkipNewer, 0, nil
	}
	if !p.nlinkOK(kfi, p.table.names[k.inode.stat.key()]+k.merged) {
		k.full = true
		return SkipKeeperFull, 0, nil
	}

	tmp, err := p.s.tempName(l.dir)
	if err != nil {
		return renameFailure(err), 0, err
	}
	if err := p.o.seams.link(k.path, tmp); err != nil {
		reason := linkFailure(err)
		if reason == SkipKeeperFull {
			k.full = true
		}
		return reason, 0, err
	}
	// Gone after the rename. A rename onto the same inode is a no-op that leaves
	// the temp, so this runs whatever the rename said.
	defer os.Remove(tmp)
	lfi, err := os.Lstat(tmp)
	if err != nil {
		return SkipKeeperGone, 0, err
	}
	if !os.SameFile(lfi, kfi) {
		return SkipKeeperGone, 0, errors.New("the keeper's name is another inode")
	}
	if err := p.o.seams.rename(tmp, dst); err != nil {
		return renameFailure(err), 0, err
	}
	var reclaimed int64
	if nlink(tfi) == 1 {
		reclaimed = tst.size
	}
	// The rename left one directory and entered another, and either can reach the
	// medium first.
	if err := p.syncDir(filepath.Dir(dst)); err != nil {
		return SkipSync, reclaimed, err
	}
	if err := p.syncDir(filepath.Dir(tmp)); err != nil {
		return SkipSync, reclaimed, err
	}
	return "", reclaimed, nil
}

// syncDir flushes dir with F_FULLFSYNC, which the store's own syncDir leaves to
// the toolchain's os.File.Sync and its fsync fallback. There is no fallback here.
func (p *convergePass) syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return p.o.seams.sync(d)
}

// linkFailure names the reason a link(2) failed. EMLINK, EPERM and ENOTSUP are
// the keeper's fault, not the target's, so they mark it full.
func linkFailure(err error) SkipReason {
	switch {
	case errors.Is(err, unix.EMLINK), errors.Is(err, unix.EPERM), errors.Is(err, unix.ENOTSUP):
		return SkipKeeperFull
	case errors.Is(err, os.ErrNotExist):
		return SkipKeeperGone
	default:
		return renameFailure(err)
	}
}

func renameFailure(err error) SkipReason {
	switch {
	case errors.Is(err, unix.EXDEV):
		return SkipCrossDevice
	case errors.Is(err, unix.ENOSPC):
		return SkipNoSpace
	default:
		return SkipLinkFailed
	}
}
