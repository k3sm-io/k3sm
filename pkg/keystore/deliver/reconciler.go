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
	"crypto/subtle"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"k3sm.io/k3sm/pkg/addons"
	"k3sm.io/k3sm/pkg/keystore"
)

// LabelKey is the ownership label on every Secret the reconciler creates; its
// value is the keystore entry name. It is distinct from k3sm.io/managed, so
// these Secrets are never mistaken for the embedded add-on set's objects.
const LabelKey = "k3sm.io/keystore-delivery"

// VersionAnnotation records the entry version a Secret holds. A sweep
// re-applies the Secret when it differs from Store.Current's.
const VersionAnnotation = "k3sm.io/keystore-version"

// FingerprintAnnotation records the fingerprint (keystore.Version.Fingerprint)
// of the value a Secret holds. The version alone does not identify a value:
// an entry deleted and put back starts at version 1 again with a new value.
// pkg/keystore exposes no generation, and the fingerprint is derived from the
// value itself, so a value change of any kind re-applies. It names no value:
// an Ed25519 fingerprint is a digest of the public key, an opaque one a keyed
// digest (see keystore.Version).
const FingerprintAnnotation = "k3sm.io/keystore-fingerprint"

// AllowPlaintextFlag is the `k3sm server` flag that lets delivery write
// Secrets while secrets encryption is off.
const AllowPlaintextFlag = "allow-plaintext-secrets-delivery"

// targetTimeout bounds one target's calls, so a hung apiserver call cannot
// stall the sweep for every target after it.
const targetTimeout = 10 * time.Second

// changeDebounce coalesces a burst of filesystem events (the CLI's
// write-rename, an editor's write-rename-chmod) into one sweep.
const changeDebounce = 500 * time.Millisecond

// ValueSource is the slice of keystore.Store the reconciler reads.
// MergePending is non-nil while a keystore restore is unfinished (its floor
// merge has not run): the restored floor then lacks the deletions since the
// backup, so a sweep delivers nothing until it is nil.
type ValueSource interface {
	Current(ctx context.Context, name string) (keystore.Version, []byte, error)
	MergePending() error
}

// Config is what New needs.
type Config struct {
	// Path is the declaration, <data root>/FileName.
	Path string
	// StatePath is the state file, <server work dir>/StateFileName, and
	// StateOwner the server's euid, which owns it.
	StatePath  string
	StateOwner uint32
	// StateDirOwners are further uids the state file's directory may be
	// owned by: the service user, for a root server (see StateDirCheck).
	StateDirOwners []uint32
	// Client is the server's admin client, the one the embedded add-on
	// reconciler uses. The reconciler only Gets, creates and updates Secrets
	// through it, and deletes an owned immutable one under a UID
	// precondition.
	Client kubernetes.Interface
	// Store supplies each entry's current version.
	Store ValueSource
	// EncryptionOn is the start-time verdict of executor.EncryptionAtStart:
	// true when the apiserver was started with an encryption provider.
	EncryptionOn bool
	// AllowPlaintext is --allow-plaintext-secrets-delivery, read at start.
	AllowPlaintext bool
	Logger         *slog.Logger
}

// Reconciler converges one labelled Opaque Secret per declared target. It
// never lists, deletes only an owned immutable Secret under a UID
// precondition, and never touches another kind (see doc.go).
//
// Sweep and Run never return an error: every failure is logged here, at the
// boundary that handles it, and the sweep moves on to the next target.
type Reconciler struct {
	path           string
	client         kubernetes.Interface
	store          ValueSource
	encryptionOn   bool
	allowPlaintext bool
	logger         *slog.Logger

	// statePath is the state file in the server's work dir (StateFileName).
	statePath string

	// Seams, fixed by New; tests replace them.
	open  Opener
	check FileCheck
	// stateCheck and stateDirCheck judge the state file and its directory
	// (production: StateFileCheck and StateDirCheck of Config.StateOwner);
	// chown hands a new state file to its owner (production: none, since the
	// server creates it as itself).
	stateCheck    FileCheck
	stateDirCheck FileCheck
	chown         func(f *os.File) error
	interval      time.Duration
	// targetTimeout bounds each target's apiserver and store calls.
	targetTimeout time.Duration
	// newTicker returns the periodic sweep's channel and its stop.
	newTicker func(d time.Duration) (<-chan time.Time, func())
	// after is the debounce timer.
	after func(d time.Duration) <-chan time.Time
	// watch watches the declaration's directory; it returns the channel of
	// changes to the declaration and the watch's close.
	watch func(dir, name string) (<-chan struct{}, func(), error)

	// mu serializes sweeps and guards fileState and targetState: Run's
	// goroutine is the only production caller, but a test may call Sweep.
	mu sync.Mutex
	// fileState is the signature of the last logged declaration refusal or
	// absence, so an unchanged refused or absent file logs once;
	// stateFileState is the state file's.
	fileState      string
	stateFileState string
	// targetState maps a target to its last logged outcome, so each target
	// logs once per state change.
	targetState map[string]string
}

// New returns a reconciler for cfg.
func New(cfg Config) *Reconciler {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Reconciler{
		path:           cfg.Path,
		statePath:      cfg.StatePath,
		client:         cfg.Client,
		store:          cfg.Store,
		encryptionOn:   cfg.EncryptionOn,
		allowPlaintext: cfg.AllowPlaintext,
		logger:         logger,
		open:           OpenNoFollow,
		check:          RootCheck,
		stateCheck:     StateFileCheck(cfg.StateOwner),
		stateDirCheck:  StateDirCheck(cfg.StateOwner, cfg.StateDirOwners...),
		chown:          chownNone,
		interval:       addons.ManifestSweepInterval,
		targetTimeout:  targetTimeout,
		newTicker: func(d time.Duration) (<-chan time.Time, func()) {
			t := time.NewTicker(d)
			return t.C, t.Stop
		},
		after: time.After,
		watch: func(dir, name string) (<-chan struct{}, func(), error) {
			return watchFile(dir, name, logger)
		},
		targetState: map[string]string{},
	}
}

// Run sweeps once, then on every debounced change to the declaration and
// every interval (addons.ManifestSweepInterval), until ctx is done. Without a
// filesystem watch it sweeps on the interval alone.
func (r *Reconciler) Run(ctx context.Context) {
	r.Sweep(ctx)

	changes, closeWatch, err := r.watch(filepath.Dir(r.path), filepath.Base(r.path))
	if err != nil {
		r.logger.Warn("keystore delivery: no filesystem watch; changes are picked up by the periodic sweep only",
			"interval", r.interval, "err", err)
	} else {
		defer closeWatch()
	}
	ticks, stopTicker := r.newTicker(r.interval)
	defer stopTicker()
	var debounce <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			r.Sweep(ctx)
		case _, ok := <-changes:
			if !ok {
				changes = nil
				continue
			}
			debounce = r.after(changeDebounce)
		case <-debounce:
			debounce = nil
			r.Sweep(ctx)
		}
	}
}

// watchFile watches dir with fsnotify and forwards an event that names name.
// The declaration is replaced by rename, so the directory is watched, not the
// file. The forwarding goroutine ends when the returned close is called.
func watchFile(dir, name string, logger *slog.Logger) (<-chan struct{}, func(), error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, nil, err
	}
	if err := w.Add(dir); err != nil {
		_ = w.Close() // never started; nothing to report
		return nil, nil, err
	}
	out := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		forwardEvents(w.Events, w.Errors, name, out, logger)
	}()
	return out, func() {
		_ = w.Close() // closes Events and Errors, which ends the goroutine
		<-done
	}, nil
}

// forwardEvents sends on out (without blocking) for each event naming name,
// until events or errs is closed.
func forwardEvents(events <-chan fsnotify.Event, errs <-chan error, name string, out chan<- struct{}, logger *slog.Logger) {
	defer close(out)
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				return
			}
			if filepath.Base(ev.Name) != name {
				continue
			}
			select {
			case out <- struct{}{}:
			default: // a change is already pending; the debounce coalesces it
			}
		case err, ok := <-errs:
			if !ok {
				return
			}
			// The periodic sweep still runs; a lost event only delays a change.
			logger.Warn("keystore delivery: filesystem watch error; a change may wait for the periodic sweep", "err", err)
		}
	}
}

// Sweep reads the declaration once and converges every target in it.
func (r *Reconciler) Sweep(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.store.MergePending(); err != nil {
		// A restored keystore whose floor merge has not run may hold a key
		// deleted since the backup to revoke it: nothing is published until
		// the merge has run. The next sweep tries again.
		r.logger.Error("keystore delivery: a keystore restore is unfinished; nothing delivered until sudo k3sm keys floor merge has run, retried on the next sweep", "reason", err.Error())
		return
	}

	d, fi, exists, err := Read(r.path, r.open, r.check)
	if err != nil {
		sig := "err:" + err.Error()
		if fi != nil {
			sig = statSignature(fi) + "/" + err.Error()
		}
		if r.fileState != sig {
			r.fileState = sig
			r.logger.Warn("keystore delivery: declaration refused; nothing delivered", "file", r.path, "reason", err.Error())
		}
		return
	}
	if !exists {
		// An absent declaration (file or data root) is not a withdrawal:
		// nothing is created or updated, and the ownership records are kept,
		// so a declaration that comes back still reaches its Secrets. Only a
		// declaration that exists and parses without a target withdraws it.
		r.missingDeclaration()
		return
	}
	r.fileState = ""
	// Ownership rests on the state file, so one that cannot be trusted
	// delivers nothing: without it, no Secret is known to be ours.
	st, err := ReadState(r.statePath, r.open, r.stateDirCheck, r.stateCheck)
	if err != nil {
		if sig := err.Error(); r.stateFileState != sig {
			r.stateFileState = sig
			r.logger.Warn("keystore delivery: state file refused; nothing delivered", "file", r.statePath, "reason", sig)
		}
		return
	}
	r.stateFileState = ""
	sw := &sweep{state: st}
	seen := make(map[string]bool, len(d.Targets))
	declared := make(map[string]bool, len(d.Targets))
	for _, t := range d.Targets {
		if ctx.Err() != nil {
			return
		}
		k := targetKey(t)
		seen[k] = true
		declared[stateKey(t.Namespace, t.Secret())] = true
		r.converge(ctx, sw, t)
	}
	// Forget a withdrawn target, so declaring it again logs again. Its Secret
	// stays: withdrawing a target never deletes anything, but it is no longer
	// recorded as ours, so declaring it again leaves it alone.
	for k := range r.targetState {
		if !seen[k] {
			delete(r.targetState, k)
		}
	}
	if sw.state.Retain(func(ns, name string) bool { return declared[stateKey(ns, name)] }) {
		if err := WriteState(r.statePath, sw.state, r.stateDirCheck, r.chown); err != nil {
			r.logger.Warn("keystore delivery: cannot drop withdrawn targets from the state file; will retry", "file", r.statePath, "err", err)
		}
	}
}

// missingDeclaration logs an absent declaration: at Warn, once per state,
// when the state file records delivered Secrets that rotations no longer
// reach, else at Debug. It reads the state file to count the records and
// never writes it; the count is all it logs.
func (r *Reconciler) missingDeclaration() {
	st, err := ReadState(r.statePath, r.open, r.stateDirCheck, r.stateCheck)
	if err != nil || len(st.owned) == 0 {
		r.fileState = ""
		r.logger.Debug("keystore delivery: no declaration; nothing to deliver, records kept", "file", r.path)
		return
	}
	n := len(st.owned)
	if sig := "absent:" + strconv.Itoa(n); r.fileState != sig {
		r.fileState = sig
		r.logger.Warn(fmt.Sprintf("keystore delivery: the declaration is missing; %d delivered Secrets are not being updated", n),
			"file", r.path, "state", r.statePath)
	}
}

// sweep is one Sweep's working state: the ownership record, and whether it
// was written this sweep (so the first create or delete proves it can be).
type sweep struct {
	state    State
	recorded bool
}

// targetKey identifies a target for the once-per-state log.
func targetKey(t Target) string {
	return t.Entry + "\x00" + t.Namespace + "\x00" + t.Secret() + "\x00" + t.Key()
}

// note logs msg at level for t once per distinct state.
func (r *Reconciler) note(t Target, state string, level slog.Level, msg string, attrs ...any) {
	k := targetKey(t)
	if r.targetState[k] == state {
		return
	}
	r.targetState[k] = state
	attrs = append([]any{"entry", t.Entry, "namespace", t.Namespace, "secret", t.Secret()}, attrs...)
	r.logger.Log(context.Background(), level, "keystore delivery: "+msg, attrs...)
}

// converge delivers one target: refuse it while encryption is off without
// the override, else Get its Secret and create it (absent), update it
// (present, with the UID this server recorded when it created it, at another
// value; only its metadata when the value is current), or leave it alone
// (any other Secret, labelled or not).
func (r *Reconciler) converge(ctx context.Context, sw *sweep, t Target) {
	ctx, cancel := context.WithTimeout(ctx, r.targetTimeout)
	defer cancel()
	if !delivers(r.encryptionOn, r.allowPlaintext) {
		r.note(t, "refused:encryption-off", slog.LevelWarn,
			"target refused; start the server with --"+AllowPlaintextFlag+" to deliver anyway",
			"reason", keystore.ErrEncryptionOff.Error())
		return
	}
	secrets := r.client.CoreV1().Secrets(t.Namespace)
	cur, err := secrets.Get(ctx, t.Secret(), metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		cur = nil
	case err != nil:
		r.note(t, "error:get:"+err.Error(), slog.LevelWarn, "cannot read the Secret; will retry", "err", err)
		return
	default:
		if reason := r.notOurs(sw, t, cur); reason != "" {
			r.note(t, "skipped:foreign:"+reason, slog.LevelWarn,
				"Secret left alone, not created by this server; delete it or pick another --secret", "reason", reason)
			return
		}
		if cur.Type != corev1.SecretTypeOpaque {
			r.note(t, "skipped:type:"+string(cur.Type), slog.LevelWarn, "Secret left alone: it is labelled for this entry but is not Opaque", "type", string(cur.Type))
			return
		}
	}

	ver, value, err := r.store.Current(ctx, t.Name())
	defer clear(value)
	if err != nil {
		r.note(t, "error:store:"+err.Error(), slog.LevelWarn, "cannot read the entry; will retry", "err", err)
		return
	}
	want := strconv.FormatUint(ver.Version, 10)

	if cur == nil {
		r.create(ctx, sw, t, ver, want, value)
		return
	}
	stamped, current := upToDate(cur, want, ver.Fingerprint, t.Key(), value)
	labelled := cur.Labels[LabelKey] == t.Name()
	if current && stamped && labelled {
		r.note(t, "ok:"+want, slog.LevelInfo, "delivered", "version", ver.Version, "plaintext", !r.encryptionOn)
		return
	}
	if current {
		// The value is in place and only the label or the annotations
		// differ: put them back without touching data. An immutable Secret
		// allows a metadata update, so this never deletes.
		r.updateMetadata(ctx, t, cur, ver, want)
		return
	}
	if cur.Immutable != nil && *cur.Immutable {
		if cur.DeletionTimestamp != nil {
			r.note(t, "waiting:terminating", slog.LevelInfo, "the Secret is being deleted; waiting")
			return
		}
		r.recreateImmutable(ctx, sw, t, cur, ver, want, value)
		return
	}
	if stamped {
		// Its stamps say current and its content does not: someone edited
		// it. Logged every time, since each edit is its own event; the value
		// is never logged.
		r.logger.Warn("keystore delivery: Secret drifted from the stored value; re-applying",
			"entry", t.Entry, "namespace", t.Namespace, "secret", t.Secret(), "version", ver.Version)
	}
	next := cur.DeepCopy()
	if next.Annotations == nil {
		next.Annotations = map[string]string{}
	}
	if next.Labels == nil {
		next.Labels = map[string]string{}
	}
	next.Labels[LabelKey] = t.Name()
	next.Annotations[VersionAnnotation] = want
	next.Annotations[FingerprintAnnotation] = ver.Fingerprint
	next.Type = corev1.SecretTypeOpaque
	next.Data = map[string][]byte{t.Key(): value}
	next.StringData = nil
	next.Immutable = nil
	if _, err := secrets.Update(ctx, next, metav1.UpdateOptions{}); err != nil {
		r.note(t, "error:update:"+err.Error(), slog.LevelWarn, "cannot update the Secret; will retry", "err", err)
		return
	}
	r.note(t, "ok:"+want, slog.LevelInfo, "re-delivered", "version", ver.Version, "plaintext", !r.encryptionOn)
}

// updateMetadata puts back the label and the version and fingerprint
// annotations on a Secret this server owns whose data is already current,
// with a plain Update that leaves data, type and immutability as they are.
func (r *Reconciler) updateMetadata(ctx context.Context, t Target, cur *corev1.Secret, ver keystore.Version, want string) {
	next := cur.DeepCopy()
	if next.Labels == nil {
		next.Labels = map[string]string{}
	}
	if next.Annotations == nil {
		next.Annotations = map[string]string{}
	}
	next.Labels[LabelKey] = t.Name()
	next.Annotations[VersionAnnotation] = want
	next.Annotations[FingerprintAnnotation] = ver.Fingerprint
	if _, err := r.client.CoreV1().Secrets(t.Namespace).Update(ctx, next, metav1.UpdateOptions{}); err != nil {
		r.note(t, "error:update:"+err.Error(), slog.LevelWarn, "cannot update the Secret's label and annotations; will retry", "err", err)
		return
	}
	r.note(t, "ok:"+want, slog.LevelInfo, "delivered; restored the Secret's label and annotations", "version", ver.Version, "plaintext", !r.encryptionOn)
}

// recreateImmutable re-delivers an immutable Secret this server owns, which
// cannot be updated: it deletes it under a precondition on the recorded UID,
// so only that object can go, then creates it again and records the new UID.
// It is the only delete the reconciler makes. The state file is proven
// writable first, so the Secret created after the delete can be recorded; a
// state file that cannot be written deletes nothing. A refused delete (the
// precondition failed, or any error) creates nothing.
func (r *Reconciler) recreateImmutable(ctx context.Context, sw *sweep, t Target, cur *corev1.Secret, ver keystore.Version, want string, value []byte) {
	if !r.proveState(sw, t, "cannot write the state file, so the immutable Secret is not deleted to re-deliver it; will retry") {
		return
	}
	uid := cur.UID
	err := r.client.CoreV1().Secrets(t.Namespace).Delete(ctx, t.Secret(), metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
	if err != nil && !apierrors.IsNotFound(err) {
		r.note(t, "error:delete:"+err.Error(), slog.LevelWarn, "cannot delete the immutable Secret to re-deliver it; will retry", "err", err)
		return
	}
	r.note(t, "deleted:immutable:"+want, slog.LevelInfo, "deleted an immutable Secret this server created, to re-create it at the current version",
		"version", ver.Version)
	if r.create(ctx, sw, t, ver, want, value) {
		r.logger.Info("keystore delivery: re-created the immutable Secret",
			"entry", t.Entry, "namespace", t.Namespace, "secret", t.Secret(), "version", ver.Version)
	}
}

// notOurs is why cur is not a Secret this server created for t, or "" when it
// is: it carries the UID recorded when this server created it. The UID alone
// decides. The label proves nothing either way: a namespace writer can set it
// on their own Secret, or remove or change it on ours; an owned Secret whose
// label is missing or names another entry (a tenant's edit, or root
// re-pointing the Secret at another entry) is updated and relabelled.
func (r *Reconciler) notOurs(sw *sweep, t Target, cur *corev1.Secret) string {
	uid := sw.state.UID(t.Namespace, t.Secret())
	if uid != "" && uid == string(cur.UID) {
		return ""
	}
	owner, ok := cur.Labels[LabelKey]
	switch {
	case !ok:
		return "it has no " + LabelKey + " label and no recorded UID matches it"
	case owner != t.Name():
		return "its " + LabelKey + " label names another entry and no recorded UID matches it"
	case uid == "":
		return "no UID is recorded for it, so it was created by someone else"
	default:
		return "its UID is not the one recorded when this server created it, so it was recreated by someone else"
	}
}

// create creates t's Secret and records its UID. The state file is written
// before the first create of a sweep, so a Secret is never created that
// could not then be recorded, and again after the create with the new UID.
func (r *Reconciler) create(ctx context.Context, sw *sweep, t Target, ver keystore.Version, want string, value []byte) bool {
	if !r.proveState(sw, t, "cannot write the state file, so the Secret is not created; will retry") {
		return false
	}
	secrets := r.client.CoreV1().Secrets(t.Namespace)
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        t.Secret(),
			Namespace:   t.Namespace,
			Labels:      map[string]string{LabelKey: t.Name()},
			Annotations: map[string]string{VersionAnnotation: want, FingerprintAnnotation: ver.Fingerprint},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{t.Key(): value},
	}
	created, err := secrets.Create(ctx, s, metav1.CreateOptions{})
	if err != nil {
		r.note(t, "error:create:"+err.Error(), slog.LevelWarn, "cannot create the Secret; will retry", "err", err)
		return false
	}
	if created.UID == "" {
		r.note(t, "error:uid", slog.LevelError, "the created Secret has no UID, so it cannot be recorded and is left alone; delete it")
		return false
	}
	sw.state.Set(t.Namespace, t.Secret(), string(created.UID))
	if err := WriteState(r.statePath, sw.state, r.stateDirCheck, r.chown); err != nil {
		r.note(t, "error:record:"+err.Error(), slog.LevelError, "created the Secret but cannot record it, so later sweeps leave it alone; delete it to have it created again", "file", r.statePath, "err", err)
		return false
	}
	r.note(t, "ok:"+want, slog.LevelInfo, "delivered", "version", ver.Version, "plaintext", !r.encryptionOn)
	return true
}

// proveState writes the state file once per sweep, before the first create
// or delete, so no Secret is created that could not then be recorded. On
// failure it logs msg once per state for t and reports false.
func (r *Reconciler) proveState(sw *sweep, t Target, msg string) bool {
	if sw.recorded {
		return true
	}
	if err := WriteState(r.statePath, sw.state, r.stateDirCheck, r.chown); err != nil {
		r.note(t, "error:state:"+err.Error(), slog.LevelWarn, msg, "file", r.statePath, "err", err)
		return false
	}
	sw.recorded = true
	return true
}

// upToDate reports whether a Secret this server owns holds the current
// value: stamped when its version and fingerprint annotations match, and
// current when data holds exactly the declared key and no other (so a
// changed --data-key re-applies and drops the stale key) and that key's
// bytes are the stored value, whatever the annotations say. The bytes are
// compared in constant time; the annotations alone would leave a hand edit
// of data in place.
func upToDate(cur *corev1.Secret, version, fingerprint, key string, value []byte) (stamped, current bool) {
	stamped = cur.Annotations[VersionAnnotation] == version && cur.Annotations[FingerprintAnnotation] == fingerprint
	got, ok := cur.Data[key]
	if !ok || len(cur.Data) != 1 || len(cur.StringData) != 0 {
		return stamped, false
	}
	return stamped, subtle.ConstantTimeCompare(got, value) == 1
}

// statSignature is the identity of a declaration state that was refused: a
// chown, a chmod or a rewrite changes it, so the file is judged and logged
// again.
func statSignature(fi fs.FileInfo) string {
	uid, gid := -1, -1
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st != nil {
		uid, gid = int(st.Uid), int(st.Gid)
	}
	return fmt.Sprintf("%d/%d/%o/%d/%d", uid, gid, fi.Mode(), fi.Size(), fi.ModTime().UnixNano())
}

// Delivers reports whether a reconciler built from c delivers at all: secrets
// encryption is on, or the plaintext override is set. Otherwise every target
// is refused.
func (c Config) Delivers() bool { return delivers(c.EncryptionOn, c.AllowPlaintext) }

func delivers(encryptionOn, allowPlaintext bool) bool { return encryptionOn || allowPlaintext }

// Validate refuses a Config New cannot run with.
func (c Config) Validate() error {
	switch {
	case c.Path == "" || !filepath.IsAbs(c.Path):
		return errors.New("keystore delivery: the declaration path is not absolute")
	case c.StatePath == "" || !filepath.IsAbs(c.StatePath):
		return errors.New("keystore delivery: the state file path is not absolute")
	case c.Client == nil:
		return errors.New("keystore delivery: no client")
	case c.Store == nil:
		return errors.New("keystore delivery: no store")
	}
	return nil
}
