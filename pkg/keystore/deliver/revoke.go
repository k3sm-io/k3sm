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
	"fmt"
	"log/slog"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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
// recorded UID and the entry its label names is gone, it is gathered for
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
	// The record holds no entry name; the label on our own object names it.
	// A namespace writer who changes it can only get our own Secret deleted,
	// which a delete of it would do as well.
	entry := cur.Labels[LabelKey]
	if entry == "" {
		r.logger.Warn("keystore delivery: a withdrawn target's Secret has no "+LabelKey+" label, so its entry is unknown and it is left alone",
			"namespace", namespace, "secret", name)
		return
	}
	t := Target{Entry: EntryPrefix + entry, Namespace: namespace, SecretName: name}
	if t.Check() != nil {
		r.logger.Warn("keystore delivery: a withdrawn target's Secret has a "+LabelKey+" label that names no entry, so it is left alone",
			"namespace", namespace, "secret", name)
		return
	}
	absent, id, err := r.store.Absent(ctx, t.Name())
	switch {
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

// revokeAll deletes the gathered Secrets, unless this sweep holds them (the
// keystore's identity is new or unread) or the breaker trips.
func (r *Reconciler) revokeAll(ctx context.Context, sw *sweep) {
	n := len(sw.revokes)
	if n == 0 {
		r.heldState = ""
		return
	}
	if sw.hold != "" {
		if sig := "hold:" + sw.hold + ":" + strconv.Itoa(n); r.heldState != sig {
			r.heldState = sig
			r.logger.Warn(fmt.Sprintf("keystore delivery: %d Secrets of deleted entries are kept this sweep: %s; will retry", n, sw.hold))
		}
		return
	}
	if limit := r.revokeLimit(sw.recordedSecrets); n > limit {
		if sig := "breaker:" + strconv.Itoa(n); r.heldState != sig {
			r.heldState = sig
			r.logger.Error(fmt.Sprintf("keystore delivery: %d of %d delivered Secrets' entries are gone at once, more than the %d one sweep revokes, so none is deleted; "+
				"put the entries back if this was not meant, or delete those Secrets with kubectl", n, sw.recordedSecrets, limit))
		}
		return
	}
	r.heldState = ""
	for _, rv := range sw.revokes {
		r.revokeOne(ctx, sw, rv)
	}
}

// revokeOne deletes one gathered Secret under a precondition on its recorded
// UID, logging the names, never a value.
func (r *Reconciler) revokeOne(ctx context.Context, sw *sweep, rv revocation) {
	ctx, cancel := context.WithTimeout(ctx, r.targetTimeout)
	defer cancel()
	attrs := []any{"entry", rv.entry, "namespace", rv.namespace, "secret", rv.secret}
	if rv.terminating {
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
		r.logger.Warn("keystore delivery: cannot delete the Secret of a deleted entry; will retry", append(attrs, "err", err)...)
	default:
		r.logger.Info("keystore delivery: deleted the Secret; its keystore entry no longer exists", attrs...)
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
