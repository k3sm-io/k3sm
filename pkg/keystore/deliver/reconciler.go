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
	"io/fs"
	"log/slog"
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

// changeDebounce coalesces a burst of filesystem events (the CLI's
// write-rename, an editor's write-rename-chmod) into one sweep.
const changeDebounce = 500 * time.Millisecond

// ValueSource is the slice of keystore.Store the reconciler reads.
type ValueSource interface {
	Current(ctx context.Context, name string) (keystore.Version, []byte, error)
}

// Config is what New needs.
type Config struct {
	// Path is the declaration, <data root>/FileName.
	Path string
	// Client is the server's admin client, the one the embedded add-on
	// reconciler uses. The reconciler only Gets, creates and updates Secrets
	// through it.
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
// never lists, never deletes and never touches another kind (see doc.go).
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

	// Seams, fixed by New; tests replace them.
	open     Opener
	check    FileCheck
	interval time.Duration
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
	// fileState is the signature of the last logged declaration refusal, so an
	// unchanged refused file logs once.
	fileState string
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
		client:         cfg.Client,
		store:          cfg.Store,
		encryptionOn:   cfg.EncryptionOn,
		allowPlaintext: cfg.AllowPlaintext,
		logger:         logger,
		open:           OpenNoFollow,
		check:          RootCheck,
		interval:       addons.ManifestSweepInterval,
		newTicker: func(d time.Duration) (<-chan time.Time, func()) {
			t := time.NewTicker(d)
			return t.C, t.Stop
		},
		after:       time.After,
		watch:       watchFile,
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
func watchFile(dir, name string) (<-chan struct{}, func(), error) {
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
		defer close(out)
		for {
			select {
			case ev, ok := <-w.Events:
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
			case _, ok := <-w.Errors:
				if !ok {
					return
				}
			}
		}
	}()
	return out, func() {
		_ = w.Close() // closes Events and Errors, which ends the goroutine
		<-done
	}, nil
}

// Sweep reads the declaration once and converges every target in it.
func (r *Reconciler) Sweep(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()

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
	r.fileState = ""
	if !exists {
		r.logger.Debug("keystore delivery: no declaration; nothing to deliver", "file", r.path)
	}
	seen := make(map[string]bool, len(d.Targets))
	for _, t := range d.Targets {
		if ctx.Err() != nil {
			return
		}
		k := targetKey(t)
		seen[k] = true
		r.converge(ctx, t)
	}
	// Forget a withdrawn target, so declaring it again logs again. Its Secret
	// stays: withdrawing a target never deletes anything.
	for k := range r.targetState {
		if !seen[k] {
			delete(r.targetState, k)
		}
	}
}

// targetKey identifies a target for the once-per-state log.
func targetKey(t Target) string {
	return t.Name + "\x00" + t.Namespace + "\x00" + t.Secret() + "\x00" + t.Key()
}

// note logs msg at level for t once per distinct state.
func (r *Reconciler) note(t Target, state string, level slog.Level, msg string, attrs ...any) {
	k := targetKey(t)
	if r.targetState[k] == state {
		return
	}
	r.targetState[k] = state
	attrs = append([]any{"entry", "system/" + t.Name, "namespace", t.Namespace, "secret", t.Secret()}, attrs...)
	r.logger.Log(context.Background(), level, "keystore delivery: "+msg, attrs...)
}

// converge delivers one target: refuse it while encryption is off without
// the override, else Get its Secret and create it (absent), update it
// (labelled for this entry, at another version), or leave it alone (present
// without the label, or labelled for another entry).
func (r *Reconciler) converge(ctx context.Context, t Target) {
	if !r.encryptionOn && !r.allowPlaintext {
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
		if owner, ok := cur.Labels[LabelKey]; !ok || owner != t.Name {
			reason := "it has no " + LabelKey + " label, so k3sm did not create it"
			if ok {
				reason = "its " + LabelKey + " label names another entry"
			}
			r.note(t, "skipped:foreign:"+owner, slog.LevelWarn, "Secret left alone; delete it or pick another --secret-name", "reason", reason)
			return
		}
		if cur.Type != corev1.SecretTypeOpaque {
			r.note(t, "skipped:type:"+string(cur.Type), slog.LevelWarn, "Secret left alone: it is labelled for this entry but is not Opaque", "type", string(cur.Type))
			return
		}
	}

	ver, value, err := r.store.Current(ctx, t.Name)
	defer clear(value)
	if err != nil {
		r.note(t, "error:store:"+err.Error(), slog.LevelWarn, "cannot read the entry; will retry", "err", err)
		return
	}
	want := strconv.FormatUint(ver.Version, 10)

	if cur == nil {
		s := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:        t.Secret(),
				Namespace:   t.Namespace,
				Labels:      map[string]string{LabelKey: t.Name},
				Annotations: map[string]string{VersionAnnotation: want, FingerprintAnnotation: ver.Fingerprint},
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{t.Key(): value},
		}
		if _, err := secrets.Create(ctx, s, metav1.CreateOptions{}); err != nil {
			r.note(t, "error:create:"+err.Error(), slog.LevelWarn, "cannot create the Secret; will retry", "err", err)
			return
		}
		r.note(t, "ok:"+want, slog.LevelInfo, "delivered", "version", ver.Version, "plaintext", !r.encryptionOn)
		return
	}
	if upToDate(cur, want, ver.Fingerprint, t.Key()) {
		r.note(t, "ok:"+want, slog.LevelInfo, "delivered", "version", ver.Version, "plaintext", !r.encryptionOn)
		return
	}
	next := cur.DeepCopy()
	if next.Annotations == nil {
		next.Annotations = map[string]string{}
	}
	next.Annotations[VersionAnnotation] = want
	next.Annotations[FingerprintAnnotation] = ver.Fingerprint
	next.Data = map[string][]byte{t.Key(): value}
	next.StringData = nil
	if _, err := secrets.Update(ctx, next, metav1.UpdateOptions{}); err != nil {
		r.note(t, "error:update:"+err.Error(), slog.LevelWarn, "cannot update the Secret; will retry", "err", err)
		return
	}
	r.note(t, "ok:"+want, slog.LevelInfo, "re-delivered", "version", ver.Version, "plaintext", !r.encryptionOn)
}

// upToDate reports whether a Secret labelled for the entry already holds the
// current value under exactly the declared data key: its version and
// fingerprint annotations match, and data has that one key and no other, so
// a changed --data-key re-applies and drops the stale key.
func upToDate(cur *corev1.Secret, version, fingerprint, key string) bool {
	if cur.Annotations[VersionAnnotation] != version || cur.Annotations[FingerprintAnnotation] != fingerprint {
		return false
	}
	_, ok := cur.Data[key]
	return ok && len(cur.Data) == 1 && len(cur.StringData) == 0
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

// Validate refuses a Config New cannot run with.
func (c Config) Validate() error {
	switch {
	case c.Path == "" || !filepath.IsAbs(c.Path):
		return errors.New("keystore delivery: the declaration path is not absolute")
	case c.Client == nil:
		return errors.New("keystore delivery: no client")
	case c.Store == nil:
		return errors.New("keystore delivery: no store")
	}
	return nil
}
