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

package deliver

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"k3sm.io/k3sm/pkg/keystore"
)

// Revocation: a keys rm must not leave the deleted value readable in the
// cluster, so a sweep deletes the Secret it delivered for an entry that is
// gone. The recorded UID decides which Secret is ours, as for an update, and
// the delete carries it as a precondition. Because a delete cannot be undone,
// three guards stand between "the entry is absent" and a delete:
//
//   - the restore hold: the entries' directory's identity
//     (keystore.FileStore.Identity) must be the one the previous sweep saw. A
//     restore that moves keystore/ aside, or a keystore recreated by a Put,
//     gets a new identity. After a start, or a sweep that sees a new identity,
//     nothing is revoked until both that sweep has passed and revokeHold has
//     elapsed (logged at Warn with the time it ends), so the operator has that
//     long to put back an entry the restored keystore lacks. Absent's own
//     identity must match the sweep's too, so a swap in the middle of a sweep
//     deletes nothing;
//   - the floor (keystore-floor.json) is the durable witness of a delete:
//     Delete buries the name's live record (a tombstone), so Absent answers
//     ErrFloorRecordsEntry, not absent, for a name the floor records live
//     whose directory is missing, and absent for one it holds only burials
//     for. That is a restored or rolled-back keystore/, and
//     it holds that name's revocation for as long as it lasts, not for one
//     sweep. Where the floor proves nothing (removed and rebuilt by the
//     restore procedure, or full), the restore hold is what stands;
//   - the breaker: when more than revokeLimit of the delivered entries would
//     be revoked in one sweep, none is. It counts entries, not Secrets, so one
//     rm of an entry delivered into many namespaces is one revocation. It
//     holds until the absent set drops back to the limit: the entries are put
//     back, or the operator deletes the Secrets by hand.
//
// A delete is done only when its effect is seen: the Get after it answers
// NotFound or another UID. A Secret still there (a finalizer holds it
// terminating) is a stuck revocation, retried every sweep and kept out of the
// breaker. A held revocation (the floor, an unconfirmed absence, a keystore
// change mid-sweep, an unreadable Secret) Warns once per name when it is
// first held, and the held and the stuck repeat in one summary at most hourly.
//
// The guarantee is the delete from the API only: a copy a Pod already read,
// the datastore's history and its backups keep the value, so revoking a
// credential still means rotating it where it is accepted. Absent and the
// identity are read again just before each delete, but that read and the
// delete are not atomic: an entry put back between them loses its Secret, and
// the next sweep creates it again.

// stateRevoked is a target's state once its Secret was revoked.
const stateRevoked = "revoked"

// revocation is one Secret a sweep deletes once every target is seen.
type revocation struct {
	entry, namespace, secret string
	uid                      string
	terminating              bool
	// withdrawn is a target no longer declared, whose record is dropped once
	// its revocation is done; target is the declared target otherwise.
	withdrawn bool
	target    Target
}

// defaultRevokeLimit is the breaker: max(3, 25% of the delivered entries).
func defaultRevokeLimit(entries int) int { return max(3, entries/4) }

// defaultRevokeHold is how long the restore hold lasts after a start or an
// identity change.
const defaultRevokeHold = 10 * time.Minute

// observeKeystore reads the entries' directory's identity, holding this
// sweep's revocations when it cannot be read, when no sweep since start saw
// it, when it differs from the last sweep's (logged at Error), and until the
// restore hold that either began has run out.
func (r *Reconciler) observeKeystore(ctx context.Context, sw *sweep) {
	id, err := r.store.Identity(ctx)
	if err != nil {
		sw.hold = "the keystore's identity cannot be read"
		if sig := err.Error(); r.keystoreState != sig {
			r.keystoreState = sig
			r.logger.Warn("keystore delivery: cannot read the keystore's identity; no Secret of a deleted entry is deleted until it can be", "err", err)
		}
		return
	}
	r.keystoreState = ""
	sw.keystore = id
	switch {
	case r.keystore == "":
		sw.hold = "the first sweep since start has not seen the keystore before"
		r.startHold("the start")
	case r.keystore != id:
		sw.hold = "the keystore directory changed"
		r.logger.Error("keystore delivery: the keystore directory changed since the last sweep (a restore, or a keystore deleted and created again); "+
			"no Secret of a deleted entry is deleted until the restore hold ends",
			"was", r.keystore, "now", id)
		r.startHold("a keystore directory change")
	case r.now().Before(r.holdUntil):
		sw.hold = "the restore hold lasts until " + r.holdUntil.Format(time.RFC3339)
	}
	r.keystore = id
}

// startHold starts the restore hold, ending revokeHold from now, and logs
// when it ends.
func (r *Reconciler) startHold(after string) {
	r.holdUntil = r.now().Add(r.revokeHold)
	r.logger.Warn("keystore delivery: revocation is held after "+after+": no Secret of a deleted entry is deleted before the hold ends; "+
		"put back any entry that should still be delivered before then",
		"until", r.holdUntil.Format(time.RFC3339))
}

// heldRevocation is a revocation held for a reason that names it: its name
// for the logs, why, and since when.
type heldRevocation struct {
	name, reason string
	since        time.Time
}

// holdNote records that the revocation keyed by key, shown as name, is held
// this sweep for reason, logging msg at Warn when it is first held or its
// reason changes. Once held it repeats only in reportStuck's summary;
// reportStuck forgets a key this sweep did not hold, so a name held again
// later Warns again.
func (r *Reconciler) holdNote(sw *sweep, key, name, reason, msg string, attrs ...any) {
	sw.held[key] = true
	cur := r.held[key]
	switch {
	case cur == nil:
		r.startSummary()
		r.held[key] = &heldRevocation{name: name, reason: reason, since: r.now()}
	case cur.reason != reason:
		cur.reason = reason
	default:
		return
	}
	r.logger.Warn("keystore delivery: "+msg, attrs...)
}

// holdSecret is holdNote for the Secret namespace/secret of entry.
func (r *Reconciler) holdSecret(sw *sweep, entry, namespace, secret, reason, msg string, attrs ...any) {
	k := stateKey(namespace, secret)
	r.holdNote(sw, "secret/"+k, k, reason, msg, append([]any{"entry", entry, "namespace", namespace, "secret", secret}, attrs...)...)
}

// The reasons a revocation is held, as the summary names them.
const (
	heldFloor        = "the keystore floor still records the entry"
	heldUnconfirmed  = "the entry's absence cannot be confirmed"
	heldFoundAgain   = "the entry was found again"
	heldKeystoreSwap = "the keystore directory changed during the sweep"
	heldUnreadable   = "its Secret cannot be read"
)

// floorHolds reports whether err is Absent's ErrFloorRecordsEntry: the
// floor still records name live and its directory is missing, a restored or
// rolled-back keystore/ rather than an rm, so its Secrets are kept (held by
// entry, so one entry delivered into many namespaces is one name).
func (r *Reconciler) floorHolds(sw *sweep, name string, err error) bool {
	if !errors.Is(err, keystore.ErrFloorRecordsEntry) {
		return false
	}
	r.holdNote(sw, "entry/"+name, EntryPrefix+name, heldFloor,
		"the keystore floor still records this entry but its directory is missing, "+
			"which a restored or rolled-back keystore/ leaves and an rm does not; its delivered Secrets are kept",
		"entry", EntryPrefix+name)
	return true
}

// revokeRefused is a refused target's revocation: Get its Secret and, when it
// is ours and the entry is gone, gather it. It reads no value and writes
// nothing but the delete.
func (r *Reconciler) revokeRefused(ctx context.Context, sw *sweep, t Target) {
	cur, err := r.client.CoreV1().Secrets(t.Namespace).Get(ctx, t.Secret(), metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		return
	case err != nil:
		// Unreadable: a Secret this server recorded may be one whose entry is
		// gone, so its revocation is pending until it can be read.
		if sw.state.UID(t.Namespace, t.Secret()) != "" {
			r.holdSecret(sw, t.Entry, t.Namespace, t.Secret(), heldUnreadable,
				"cannot read a refused target's Secret, so its pending revocation, if its entry is gone, cannot be checked; will retry", "err", err)
		}
		return
	case r.notOurs(sw, t, cur) != "":
		// Foreign: nothing to revoke. A refused target logs its refusal only.
		return
	}
	r.collect(ctx, sw, t, cur, true)
}

// collect gathers cur, the Secret this server created for declared target t
// (its UID is the recorded one), when the store confirms t's entry is gone
// under this sweep's keystore identity. quiet logs nothing for a live entry.
func (r *Reconciler) collect(ctx context.Context, sw *sweep, t Target, cur *corev1.Secret, quiet bool) {
	absent, id, err := r.store.Absent(ctx, t.Name())
	held := true
	switch {
	case r.floorHolds(sw, t.Name(), err):
	case err != nil:
		r.holdSecret(sw, t.Entry, t.Namespace, t.Secret(), heldUnconfirmed,
			"the entry is not found but its absence cannot be confirmed, so the Secret is kept; will retry", "err", err)
	case !absent:
		if !quiet {
			r.holdSecret(sw, t.Entry, t.Namespace, t.Secret(), heldFoundAgain,
				"the entry was not found and then found again, so the Secret is kept; will retry")
		}
	case id != sw.keystore:
		r.holdSecret(sw, t.Entry, t.Namespace, t.Secret(), heldKeystoreSwap,
			"the entry is gone but the keystore directory changed during the sweep, so the Secret is kept; will retry")
	default:
		held = false
	}
	if held {
		// The target's next outcome (delivered again, or revoked) logs.
		r.targetState[targetKey(t)] = "held"
		return
	}
	sw.revokes = append(sw.revokes, revocation{
		entry: t.Entry, namespace: t.Namespace, secret: t.Secret(), uid: string(cur.UID),
		terminating: cur.DeletionTimestamp != nil, target: t,
	})
	if reason := unmarked(t, cur); reason != "" {
		r.logger.Warn("keystore delivery: the Secret of a deleted entry lacks the marks a delivery sets; it carries the recorded UID, so it is deleted anyway",
			"entry", t.Entry, "namespace", t.Namespace, "secret", t.Secret(), "reason", reason)
	}
}

// withdrawn handles the record of namespace/name, a Secret this server
// created for a target no longer declared: when the Secret still carries the
// recorded UID and the entry the record names is gone, it is gathered for
// revocation and its record kept until that is done; when the entry is live,
// or the Secret is gone or another, the record is dropped and the Secret
// left alone. A transient failure keeps the record for the next sweep.
func (r *Reconciler) withdrawn(ctx context.Context, sw *sweep, namespace, name string) {
	k := stateKey(namespace, name)
	ctx, cancel := context.WithTimeout(ctx, r.targetTimeout)
	defer cancel()
	cur, err := r.client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		return
	case err != nil:
		sw.keep[k] = true
		r.logger.Warn("keystore delivery: cannot read a withdrawn target's Secret to check its entry; will retry",
			"namespace", namespace, "secret", name, "err", err)
		return
	case string(cur.UID) != sw.state.UID(namespace, name):
		return // recreated by someone else: not ours
	case cur.Type != corev1.SecretTypeOpaque:
		// As for a declared target: this server creates Opaque Secrets only.
		r.recordNote(k, "type:"+string(cur.Type), "keystore delivery: a withdrawn target's Secret is not Opaque, so it is left alone",
			"namespace", namespace, "secret", name, "type", string(cur.Type))
		return
	}
	// The entry is the record's, written when the Secret was delivered. The
	// label is on an object any namespace writer can edit: relabelled to a
	// live entry it would keep a deleted entry's value readable, and to
	// another deleted entry it would get the Secret deleted early. So the
	// label decides nothing here. Only a record an older build wrote, with no
	// entry, falls back to it, with a Warn: the upgrade window, since a
	// declared target's record gets its entry on the first sweep that sees
	// it, and every record written since names one.
	label := cur.Labels[LabelKey]
	entry := sw.state.Entry(namespace, name)
	if entry == "" {
		if label == "" {
			r.recordNote(k, "no-entry:no-label", "keystore delivery: a withdrawn target's record names no entry and its Secret has no "+LabelKey+" label, so its entry is unknown and it is left alone",
				"namespace", namespace, "secret", name)
			return
		}
		entry = EntryPrefix + label
		r.recordNote(k, "no-entry:label:"+label, "keystore delivery: a withdrawn target's record names no entry (an older build wrote it), so the "+LabelKey+" label on its Secret names it",
			"entry", entry, "namespace", namespace, "secret", name)
	}
	t := Target{Entry: entry, Namespace: namespace, SecretName: name}
	if t.Check() != nil {
		r.recordNote(k, "bad-entry:"+entry, "keystore delivery: a withdrawn target's entry is not a deliverable entry name, so its Secret is left alone",
			"namespace", namespace, "secret", name)
		return
	}
	if label != t.Name() {
		// Kept whatever the entry's state, so a relabel never silently
		// drops the target: the record is checked again every sweep.
		sw.keep[k] = true
		r.recordNote(k, "relabelled:"+label, "keystore delivery: a withdrawn target's Secret has a "+LabelKey+" label that is not the entry recorded when it was delivered; the record decides, and is kept",
			"entry", t.Entry, "label", label, "namespace", namespace, "secret", name)
	}
	absent, id, err := r.store.Absent(ctx, t.Name())
	switch {
	case r.floorHolds(sw, t.Name(), err):
		sw.keep[k] = true
		return
	case err != nil:
		sw.keep[k] = true
		r.holdSecret(sw, t.Entry, namespace, name, heldUnconfirmed,
			"cannot confirm whether a withdrawn target's entry is gone, so its Secret is kept; will retry", "err", err)
		return
	case !absent:
		return // undeliver of a live entry: the Secret stays
	case id != sw.keystore:
		sw.keep[k] = true
		r.holdSecret(sw, t.Entry, namespace, name, heldKeystoreSwap,
			"a withdrawn target's entry is gone but the keystore directory changed during the sweep, so its Secret is kept; will retry")
		return
	}
	sw.keep[k] = true
	sw.revokes = append(sw.revokes, revocation{
		entry: t.Entry, namespace: namespace, secret: name, uid: string(cur.UID),
		terminating: cur.DeletionTimestamp != nil, withdrawn: true,
	})
}

// dropRecord drops namespace/name's record, written at the end of the sweep.
func (r *Reconciler) dropRecord(sw *sweep, namespace, name string) {
	if _, ok := sw.state.owned[stateKey(namespace, name)]; ok {
		delete(sw.state.owned, stateKey(namespace, name))
		sw.dirty = true
	}
}

// recordNote logs msg at Warn for the withdrawn record k once per state.
func (r *Reconciler) recordNote(k, state, msg string, attrs ...any) {
	if r.recordState[k] == state {
		return
	}
	r.recordState[k] = state
	r.logger.Warn(msg, attrs...)
}

// revokeAll deletes the gathered Secrets, unless this sweep holds them (the
// keystore's identity is new or unread, or the restore hold lasts) or the
// breaker trips. The breaker counts distinct entries: one entry delivered into
// many namespaces is one revocation. A stuck revocation (its Secret
// terminating, or its Delete failing or unconfirmed) does not count toward
// it, so a few that never finish cannot hold every later rm back; they are
// logged instead (see markStuck).
func (r *Reconciler) revokeAll(ctx context.Context, sw *sweep) {
	defer r.reportStuck(sw)
	n := len(sw.revokes)
	if n == 0 {
		r.heldState = ""
		return
	}
	fresh := map[string]bool{}
	for _, rv := range sw.revokes {
		switch {
		case rv.terminating:
			r.markStuck(rv, stuckTerminating, nil)
		case r.retrying(rv):
			// Stuck on an earlier sweep: retried, not counted.
		default:
			fresh[rv.entry] = true
		}
	}
	if sw.hold != "" {
		if r.heldLog("hold:" + sw.hold + ":" + strconv.Itoa(n)) {
			r.logger.Warn(fmt.Sprintf("keystore delivery: %d Secrets of deleted entries are kept this sweep: %s; will retry", n, sw.hold))
		}
		return
	}
	if limit := r.revokeLimit(sw.deliveredEntries); len(fresh) > limit {
		if r.heldLog("breaker:" + strconv.Itoa(len(fresh))) {
			r.logger.Error(fmt.Sprintf("keystore delivery: %d of %d delivered entries are gone at once, more than the %d one sweep revokes, so none of their Secrets is deleted; "+
				"put the entries back if this was not meant, or delete those Secrets with kubectl", len(fresh), sw.deliveredEntries, limit))
		}
		return
	}
	r.heldState = ""
	for _, rv := range sw.revokes {
		r.revokeOne(ctx, sw, rv)
	}
}

// heldLog reports whether a held or tripped sweep with signature sig logs:
// when sig differs from the last one logged, or heldRepeatEvery has passed
// since, so a hold that lasts stays in the log.
func (r *Reconciler) heldLog(sig string) bool {
	if r.heldState == sig && r.now().Sub(r.heldAt) < heldRepeatEvery {
		return false
	}
	r.heldState, r.heldAt = sig, r.now()
	return true
}

// heldRepeatEvery is how often a hold or a tripped breaker logs again while
// it lasts.
const heldRepeatEvery = time.Hour

// The states of a stuck revocation.
const (
	stuckTerminating       = "terminating"
	stuckDeleteFailing     = "delete failing"
	stuckDeleteUnconfirmed = "still there after its delete"
)

// stuckRevocation is one revocation that has not finished: its state, since
// when it is stuck, and its names for the logs.
type stuckRevocation struct {
	entry, namespace, secret string
	state                    string
	since                    time.Time
}

// retrying reports whether rv got stuck on an earlier sweep.
func (r *Reconciler) retrying(rv revocation) bool {
	return r.stuck[stateKey(rv.namespace, rv.secret)] != nil
}

// stuckSummaryEvery is how often the summary of stuck and held revocations
// repeats while any is stuck or held.
const stuckSummaryEvery = time.Hour

// startSummary starts the summary's clock when the first revocation gets
// stuck or held, so the first summary comes stuckSummaryEvery later.
func (r *Reconciler) startSummary() {
	if len(r.stuck) == 0 && len(r.held) == 0 {
		r.stuckSummary = r.now()
	}
}

// markStuck records rv as stuck in state, logging a Warn when it first gets
// stuck and again each time its state changes.
func (r *Reconciler) markStuck(rv revocation, state string, err error) {
	k := stateKey(rv.namespace, rv.secret)
	attrs := []any{"entry", rv.entry, "namespace", rv.namespace, "secret", rv.secret, "state", state}
	if err != nil {
		attrs = append(attrs, "err", err)
	}
	cur := r.stuck[k]
	switch {
	case cur == nil:
		r.startSummary()
		r.stuck[k] = &stuckRevocation{entry: rv.entry, namespace: rv.namespace, secret: rv.secret, state: state, since: r.now()}
		r.logger.Warn("keystore delivery: the revocation of a deleted entry's Secret is stuck; it does not count toward the delivery breaker, and is retried every sweep", attrs...)
	case cur.state != state:
		cur.state = state
		r.logger.Warn("keystore delivery: a stuck revocation changed state; it is still stuck", append(attrs, "stuckFor", r.now().Sub(cur.since).Round(time.Second).String())...)
	}
}

// reportStuck forgets the stuck revocations this sweep did not gather (the
// entry is back, or the record is gone) or finished, and the held ones it did
// not hold, and, while any is still stuck or held, logs a summary Warn at
// most every stuckSummaryEvery naming each, why, and for how long.
func (r *Reconciler) reportStuck(sw *sweep) {
	gathered := make(map[string]bool, len(sw.revokes))
	for _, rv := range sw.revokes {
		gathered[stateKey(rv.namespace, rv.secret)] = true
	}
	for k := range r.stuck {
		if !gathered[k] || sw.unstuck[k] {
			delete(r.stuck, k)
		}
	}
	for k := range r.held {
		if !sw.held[k] {
			delete(r.held, k)
		}
	}
	if len(r.stuck)+len(r.held) == 0 || r.now().Sub(r.stuckSummary) < stuckSummaryEvery {
		return
	}
	r.stuckSummary = r.now()
	r.reportHeld()
	if len(r.stuck) == 0 {
		return
	}
	keys := make([]string, 0, len(r.stuck))
	for k := range r.stuck {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		st := r.stuck[k]
		parts = append(parts, fmt.Sprintf("%s (%s, stuck for %s)", k, st.state, r.now().Sub(st.since).Round(time.Second)))
	}
	r.logger.Warn(fmt.Sprintf("keystore delivery: %d revocations of deleted entries' Secrets are still stuck: %s", len(keys), strings.Join(parts, ", ")))
}

// reportHeld logs the summary of the held revocations, if any: how many, and
// each one's name, reason and how long it has been held.
func (r *Reconciler) reportHeld() {
	if len(r.held) == 0 {
		return
	}
	keys := make([]string, 0, len(r.held))
	for k := range r.held {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		h := r.held[k]
		parts = append(parts, fmt.Sprintf("%s (%s, held for %s)", h.name, h.reason, r.now().Sub(h.since).Round(time.Second)))
	}
	r.logger.Warn(fmt.Sprintf("keystore delivery: %d revocations of deleted entries' Secrets are still held: %s", len(keys), strings.Join(parts, ", ")))
}

// revokeOne deletes one gathered Secret under a precondition on its recorded
// UID, logging the names, never a value.
func (r *Reconciler) revokeOne(ctx context.Context, sw *sweep, rv revocation) {
	ctx, cancel := context.WithTimeout(ctx, r.targetTimeout)
	defer cancel()
	attrs := []any{"entry", rv.entry, "namespace", rv.namespace, "secret", rv.secret}
	if rv.terminating {
		// Logged by markStuck, at Warn, when it first gets stuck.
		r.logger.Debug("keystore delivery: the Secret of a deleted entry is being deleted; waiting", attrs...)
		return
	}
	// Gather and delete are a whole sweep apart: the entry may be back, or
	// the keystore swapped, since. So both are asked again just before the
	// delete; the window left is this read to the delete.
	name := Target{Entry: rv.entry}.Name()
	absent, id, err := r.store.Absent(ctx, name)
	switch {
	case r.floorHolds(sw, name, err):
		return
	case err != nil:
		r.holdSecret(sw, rv.entry, rv.namespace, rv.secret, heldUnconfirmed,
			"the entry's absence cannot be confirmed again before the delete, so the Secret is kept; will retry", "err", err)
		return
	case !absent:
		r.logger.Info("keystore delivery: the entry was put back before its Secret was deleted, so the Secret is kept", attrs...)
		return
	case id != sw.keystore:
		r.holdSecret(sw, rv.entry, rv.namespace, rv.secret, heldKeystoreSwap,
			"the keystore directory changed before the delete, so the Secret is kept; will retry")
		return
	}
	uid := types.UID(rv.uid)
	err = r.client.CoreV1().Secrets(rv.namespace).Delete(ctx, rv.secret, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
	done := true
	switch {
	case apierrors.IsNotFound(err):
		r.logger.Info("keystore delivery: the entry is gone and so is its Secret", attrs...)
	case apierrors.IsConflict(err):
		r.logger.Warn("keystore delivery: the entry is gone but the Secret was replaced before it could be deleted, so it is left alone", append(attrs, "err", err)...)
	case err != nil:
		done = false
		r.markStuck(rv, stuckDeleteFailing, err)
		r.logger.Debug("keystore delivery: cannot delete the Secret of a deleted entry; will retry", append(attrs, "err", err)...)
	default:
		// A Delete that succeeds may only mark the Secret for deletion (a
		// finalizer holds it), so it is done once a Get no longer finds it.
		if done = r.confirmDeleted(ctx, rv); done {
			r.logger.Info("keystore delivery: deleted the Secret; its keystore entry no longer exists", attrs...)
		}
	}
	if done {
		sw.unstuck[stateKey(rv.namespace, rv.secret)] = true
	}
	if rv.withdrawn {
		if done {
			delete(sw.keep, stateKey(rv.namespace, rv.secret))
		}
		return
	}
	if done {
		// The record goes with the Secret: its UID matches nothing now, and
		// a revoked record would count as a live delivery in the breaker's
		// base. A later create records the target again.
		r.targetState[targetKey(rv.target)] = stateRevoked
		r.dropRecord(sw, rv.namespace, rv.secret)
	}
}

// confirmDeleted reports whether rv's Secret is gone after its Delete: a Get
// answers NotFound, or finds another UID. Otherwise the revocation is stuck
// (terminating, or still there, or the Get failed), and retried next sweep.
func (r *Reconciler) confirmDeleted(ctx context.Context, rv revocation) bool {
	cur, err := r.client.CoreV1().Secrets(rv.namespace).Get(ctx, rv.secret, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		return true
	case err != nil:
		r.markStuck(rv, stuckDeleteUnconfirmed, fmt.Errorf("cannot read the Secret after its delete: %w", err))
	case string(cur.UID) != rv.uid:
		return true
	case cur.DeletionTimestamp != nil:
		r.markStuck(rv, stuckTerminating, nil)
	default:
		r.markStuck(rv, stuckDeleteUnconfirmed, errors.New("the Secret is still there after its delete"))
	}
	return false
}

// unmarked is why cur lacks the marks a delivery sets for t, or "" when it
// carries them all: the LabelKey label naming t's entry, and the version and
// fingerprint annotations. A missing mark is logged; the recorded UID alone
// decides the delete.
func unmarked(t Target, cur *corev1.Secret) string {
	switch {
	case cur.Labels[LabelKey] != t.Name():
		return "its " + LabelKey + " label does not name this entry"
	case cur.Annotations[VersionAnnotation] == "":
		return "it has no " + VersionAnnotation + " annotation"
	case cur.Annotations[FingerprintAnnotation] == "":
		return "it has no " + FingerprintAnnotation + " annotation"
	}
	return ""
}
