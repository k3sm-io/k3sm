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
	"log/slog"
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
// two guards stand between "the entry is absent" and a delete:
//
//   - the entries' directory's identity (keystore.FileStore.Identity) must be
//     the one the previous sweep saw. A restore that moves keystore/ aside, or
//     a keystore recreated by a Put, gets a new identity; the first sweep that
//     sees it, and the first sweep after a start, revoke nothing, so a restore
//     holds revocation for one sweep. Absent's own identity must match the
//     sweep's too, so a swap in the middle of a sweep deletes nothing;
//   - the floor (keystore-floor.json) is the durable witness of a delete:
//     Delete removes the name from it, so Absent answers
//     ErrFloorRecordsEntry, not absent, for a name the floor records whose
//     directory is missing. That is a restored or rolled-back keystore/, and
//     it holds that name's revocation for as long as it lasts (a Warn once
//     per name), not for one sweep. Where the floor proves nothing (removed
//     and rebuilt by the restore procedure, or full), the identity hold is
//     what stands;
//   - the breaker: when more than revokeLimit of the recorded Secrets would be
//     revoked in one sweep, none is. It holds until the absent set drops back
//     to the limit: the entries are put back, or the operator deletes the
//     Secrets by hand.
//
// The guarantee is the delete from the API only: a copy a Pod already read,
// the datastore's history and its backups keep the value, so revoking a
// credential still means rotating it where it is accepted. Absent and the
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

// defaultRevokeLimit is the breaker: max(3, 25% of the recorded Secrets).
func defaultRevokeLimit(recorded int) int { return max(3, recorded/4) }

// observeKeystore reads the entries' directory's identity, holding this
// sweep's revocations when it cannot be read, when no sweep since start saw
// it, or when it differs from the last sweep's (logged at Error).
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
	case r.keystore != id:
		sw.hold = "the keystore directory changed"
		r.logger.Error("keystore delivery: the keystore directory changed since the last sweep (a restore, or a keystore deleted and created again); "+
			"no Secret of a deleted entry is deleted this sweep, and revocation resumes on the next sweep that sees it unchanged",
			"was", r.keystore, "now", id)
	}
	r.keystore = id
}

// floorHolds reports whether err is Absent's ErrFloorRecordsEntry: the
// floor still records name and its directory is missing, a restored or
// rolled-back keystore/ rather than an rm, so its Secrets are kept. It logs
// a Warn once per name while that lasts (pruneFloorHolds forgets a name the
// sweep no longer saw held).
func (r *Reconciler) floorHolds(sw *sweep, name string, err error) bool {
	if !errors.Is(err, keystore.ErrFloorRecordsEntry) {
		return false
	}
	sw.floorHeld[name] = true
	if !r.floorHeld[name] {
		r.floorHeld[name] = true
		r.logger.Warn("keystore delivery: the keystore floor still records this entry but its directory is missing, "+
			"which a restored or rolled-back keystore/ leaves and an rm does not; its delivered Secrets are kept",
			"entry", EntryPrefix+name)
	}
	return true
}

// pruneFloorHolds forgets the names this sweep did not see held, so a name
// held again later logs again.
func (r *Reconciler) pruneFloorHolds(sw *sweep) {
	for n := range r.floorHeld {
		if !sw.floorHeld[n] {
			delete(r.floorHeld, n)
		}
	}
}

// revokeRefused is a refused target's revocation: Get its Secret and, when it
// is ours and the entry is gone, gather it. It reads no value and writes
// nothing but the delete.
func (r *Reconciler) revokeRefused(ctx context.Context, sw *sweep, t Target) {
	cur, err := r.client.CoreV1().Secrets(t.Namespace).Get(ctx, t.Secret(), metav1.GetOptions{})
	if err != nil || r.notOurs(sw, t, cur) != "" {
		// Absent, foreign or unreadable: nothing to revoke. A refused target
		// logs its refusal only, so this logs nothing.
		return
	}
	r.collect(ctx, sw, t, cur, true)
}

// collect gathers cur, the Secret this server created for declared target t
// (its UID is the recorded one), when the store confirms t's entry is gone
// under this sweep's keystore identity. quiet logs nothing for a live entry.
func (r *Reconciler) collect(ctx context.Context, sw *sweep, t Target, cur *corev1.Secret, quiet bool) {
	absent, id, err := r.store.Absent(ctx, t.Name())
	switch {
	case r.floorHolds(sw, t.Name(), err):
		return
	case err != nil:
		r.note(t, "error:absent:"+err.Error(), slog.LevelWarn,
			"the entry is not found but its absence cannot be confirmed, so the Secret is kept; will retry", "err", err)
		return
	case !absent:
		if !quiet {
			r.note(t, "error:absent:present", slog.LevelWarn,
				"the entry was not found and then found again, so the Secret is kept; will retry")
		}
		return
	case id != sw.keystore:
		r.note(t, "held:keystore-changed", slog.LevelWarn,
			"the entry is gone but the keystore directory changed during the sweep, so the Secret is kept; will retry")
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
	}
	// The entry is the record's, written when the Secret was delivered. The
	// label is on an object any namespace writer can edit: relabelled to a
	// live entry it would keep a deleted entry's value readable, and to
	// another deleted entry it would get the Secret deleted early. So the
	// label decides nothing here; a record an older build wrote, with no
	// entry, falls back to it, with a Warn.
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
		r.logger.Warn("keystore delivery: cannot confirm whether a withdrawn target's entry is gone; will retry",
			"entry", t.Entry, "namespace", namespace, "secret", name, "err", err)
		return
	case !absent:
		return // undeliver of a live entry: the Secret stays
	case id != sw.keystore:
		sw.keep[k] = true
		return
	}
	sw.keep[k] = true
	sw.revokes = append(sw.revokes, revocation{
		entry: t.Entry, namespace: namespace, secret: name, uid: string(cur.UID),
		terminating: cur.DeletionTimestamp != nil, withdrawn: true,
	})
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
// keystore's identity is new or unread) or the breaker trips. A stuck
// revocation (its Secret terminating, or its Delete failing and retrying)
// does not count toward the breaker, so a few that never finish cannot hold
// every later rm back; they are logged instead (see markStuck).
func (r *Reconciler) revokeAll(ctx context.Context, sw *sweep) {
	defer r.reportStuck(sw)
	n := len(sw.revokes)
	if n == 0 {
		r.heldState = ""
		return
	}
	fresh := 0
	for _, rv := range sw.revokes {
		switch {
		case rv.terminating:
			r.markStuck(rv, stuckTerminating, nil)
		case r.retrying(rv):
			// Its Delete failed on an earlier sweep: retried, not counted.
		default:
			fresh++
		}
	}
	if sw.hold != "" {
		if sig := "hold:" + sw.hold + ":" + strconv.Itoa(n); r.heldState != sig {
			r.heldState = sig
			r.logger.Warn(fmt.Sprintf("keystore delivery: %d Secrets of deleted entries are kept this sweep: %s; will retry", n, sw.hold))
		}
		return
	}
	if limit := r.revokeLimit(sw.recordedSecrets); fresh > limit {
		if sig := "breaker:" + strconv.Itoa(fresh); r.heldState != sig {
			r.heldState = sig
			r.logger.Error(fmt.Sprintf("keystore delivery: %d of %d delivered Secrets' entries are gone at once, more than the %d one sweep revokes, so none is deleted; "+
				"put the entries back if this was not meant, or delete those Secrets with kubectl", fresh, sw.recordedSecrets, limit))
		}
		return
	}
	r.heldState = ""
	for _, rv := range sw.revokes {
		r.revokeOne(ctx, sw, rv)
	}
}

// The states of a stuck revocation.
const (
	stuckTerminating   = "terminating"
	stuckDeleteFailing = "delete failing"
)

// stuckRevocation is one revocation that has not finished: its state, since
// when it is stuck, and its names for the logs.
type stuckRevocation struct {
	entry, namespace, secret string
	state                    string
	since                    time.Time
}

// retrying reports whether rv's Delete failed on an earlier sweep.
func (r *Reconciler) retrying(rv revocation) bool {
	st := r.stuck[stateKey(rv.namespace, rv.secret)]
	return st != nil && st.state == stuckDeleteFailing
}

// stuckSummaryEvery is how often the summary of stuck revocations repeats
// while any is stuck.
const stuckSummaryEvery = time.Hour

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
		if len(r.stuck) == 0 {
			r.stuckSummary = r.now()
		}
		r.stuck[k] = &stuckRevocation{entry: rv.entry, namespace: rv.namespace, secret: rv.secret, state: state, since: r.now()}
		r.logger.Warn("keystore delivery: the revocation of a deleted entry's Secret is stuck; it does not count toward the delivery breaker, and is retried every sweep", attrs...)
	case cur.state != state:
		cur.state = state
		r.logger.Warn("keystore delivery: a stuck revocation changed state; it is still stuck", append(attrs, "stuckFor", r.now().Sub(cur.since).Round(time.Second).String())...)
	}
}

// reportStuck forgets the stuck revocations this sweep did not gather (the
// entry is back, or the record is gone) or finished, and, while any is
// still stuck, logs a summary Warn at most every stuckSummaryEvery naming
// each and how long it has been stuck.
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
	if len(r.stuck) == 0 || r.now().Sub(r.stuckSummary) < stuckSummaryEvery {
		return
	}
	r.stuckSummary = r.now()
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
	uid := types.UID(rv.uid)
	err := r.client.CoreV1().Secrets(rv.namespace).Delete(ctx, rv.secret, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
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
		r.logger.Info("keystore delivery: deleted the Secret; its keystore entry no longer exists", attrs...)
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
		r.targetState[targetKey(rv.target)] = stateRevoked
	}
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
