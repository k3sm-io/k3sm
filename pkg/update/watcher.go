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

package update

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	updatesv1alpha1 "k3sm.io/apis/updates/v1alpha1"
	"k3sm.io/darwin-net/pkg/netd/wire"

	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/version"
)

// FieldManager is the field manager of every Node write this package makes.
const FieldManager = "k3sm-update"

// The names inside an attempt directory.
const (
	attemptPrefix = "attempt-"
	archiveName   = "release.tar.gz"
	setDirName    = "set"
)

// ownNodeResync is the own-node informer's resync period: a lost event is
// reconsidered at most this late.
const ownNodeResync = 5 * time.Minute

// readyRetry is how often Run re-checks a node that runs the requested
// release but is not yet fully up, so its Done is written soon after it is.
const readyRetry = 5 * time.Second

// Netd is the root helper's ApplyUpdate verb (darwin-net's *wire.Client).
type Netd interface {
	ApplyUpdate(ctx context.Context, args wire.ApplyUpdateArgs, progress func(wire.UpdatePhase)) (wire.UpdateResult, error)
}

// Config configures a Watcher. Every field but Log is required.
type Config struct {
	// Node is this node's name.
	Node string
	// Client reads this node's own Node and patches its phase annotation.
	Client kubernetes.Interface
	// Running is the running build's version provenance.
	Running version.Info
	// Root is the directory, under the data root and owned by the service
	// user, the attempt directories are made in. It is created (0700) when
	// absent.
	Root string
	// Fetcher downloads the release archive.
	Fetcher Fetcher
	// Netd installs the build set.
	Netd Netd
	// ClusterCA is the cluster CA the update signer must chain to: the node
	// credential's CA on an agent, the server's own cluster CA on a server.
	// Required: without it no payload can be authorised.
	ClusterCA *x509.CertPool
	// Now is the clock the signer's validity is judged at; nil is time.Now.
	Now func() time.Time
	// ReleaseBase is the node's recorded --update-release-base, nil for
	// GitHub's index: the HostPin admits its host for the archive URL.
	ReleaseBase *url.URL
	// Ready reports whether this daemon is fully up (its pod runtime
	// answering). Done is written only once it returns true, because the
	// controller counts a node complete on Done, its kubeletVersion and a
	// Ready condition that holds. nil means always ready.
	Ready func(ctx context.Context) bool
	// Log is the logger; nil uses slog.Default.
	Log *slog.Logger
}

// Watcher applies the release the update controller asks this node for. See
// the package doc for the sequence.
type Watcher struct {
	cfg Config
	log *slog.Logger
	// tried records the handovers (tag and payload) this process started, so
	// a Downloading or Verifying phase is resumed only when an earlier process
	// left it. Sync is not called concurrently, so it needs no lock.
	tried map[string]bool
	// donePending is set by Sync when the node runs the requested release but
	// Ready said no, so Run re-syncs on readyRetry until Done is written.
	donePending bool
}

// New checks cfg and returns a Watcher.
func New(cfg Config) (*Watcher, error) {
	switch {
	case cfg.Node == "":
		return nil, errors.New("update: the node name is required")
	case cfg.Client == nil:
		return nil, errors.New("update: the API client is required")
	case cfg.ClusterCA == nil:
		return nil, errors.New("update: the cluster CA is required: it is what authorises an update")
	case cfg.Fetcher == nil || cfg.Netd == nil:
		return nil, errors.New("update: the fetcher and the root helper client are required")
	case !filepath.IsAbs(cfg.Root) || filepath.Clean(cfg.Root) != cfg.Root:
		return nil, fmt.Errorf("update: the update root %q is not a clean absolute path", cfg.Root)
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	return &Watcher{cfg: cfg, log: log.With("node", cfg.Node), tried: map[string]bool{}}, nil
}

// Run removes the attempt directories an earlier process left, then watches
// this node's own Node (a single-object informer, which the Node authorizer
// allows) and runs Sync after every change, until ctx ends.
func (w *Watcher) Run(ctx context.Context) {
	w.prune()
	f := informers.NewSharedInformerFactoryWithOptions(w.cfg.Client, ownNodeResync,
		informers.WithTweakListOptions(func(o *metav1.ListOptions) {
			o.FieldSelector = fields.OneTermEqualSelector("metadata.name", w.cfg.Node).String()
		}))
	inf := f.Core().V1().Nodes().Informer()
	changed := make(chan struct{}, 1)
	signal := func() {
		select {
		case changed <- struct{}{}:
		default:
		}
	}
	_, _ = inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { signal() },
		UpdateFunc: func(_, _ any) { signal() },
	})
	go inf.Run(ctx.Done())
	retry := time.NewTimer(readyRetry)
	defer retry.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-changed:
		case <-retry.C:
			retry.Reset(readyRetry)
			if !w.donePending {
				continue
			}
		}
		if err := w.Sync(ctx); err != nil && ctx.Err() == nil {
			w.log.Warn("update: reconciling this node's update failed", "err", err)
		}
	}
}

// Sync reads this node's Node from the apiserver (never a cache, so a phase
// this process just wrote is seen) and acts on its update annotations:
//
//   - no update-version: nothing;
//   - the running build is the tag: once Ready says the daemon is fully up,
//     write Done unless it is already written;
//   - phase empty (a fresh handover), or Downloading/Verifying left by an
//     earlier process: run the attempt;
//   - any other phase: nothing. Installing and Restarting belong to an
//     installer the root helper may still be running, which restarts this
//     daemon; Failed and Done are the controller's to act on.
func (w *Watcher) Sync(ctx context.Context) error {
	n, err := w.cfg.Client.CoreV1().Nodes().Get(ctx, w.cfg.Node, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get node %s: %w", w.cfg.Node, err)
	}
	tag := n.Annotations[updatesv1alpha1.AnnotationUpdateVersion]
	if tag == "" {
		return nil
	}
	phase, _ := ParsePhase(n.Annotations[updatesv1alpha1.AnnotationUpdatePhase])
	w.donePending = false
	if w.onTarget(tag) {
		if phase == updatesv1alpha1.UpdateNodePhaseDone {
			return nil
		}
		if w.cfg.Ready != nil && !w.cfg.Ready(ctx) {
			w.donePending = true
			return nil
		}
		w.log.Info("update: this node runs the requested release", "version", tag)
		return w.setPhase(ctx, updatesv1alpha1.UpdateNodePhaseDone, "")
	}
	key := tag + "\n" + n.Annotations[AnnotationUpdatePayload] + "\n" + n.Annotations[AnnotationUpdatePayloadSig]
	switch phase {
	case "":
	case updatesv1alpha1.UpdateNodePhaseDownloading, updatesv1alpha1.UpdateNodePhaseVerifying:
		if w.tried[key] {
			return nil
		}
		w.log.Info("update: resuming an update an earlier daemon left unfinished", "version", tag, "phase", phase)
	default:
		return nil
	}
	w.tried[key] = true
	return w.attempt(ctx, tag, n.Annotations)
}

// onTarget reports whether the running build is tag, by the measure the
// controller applies to the Node: the k3sm part of the kubeletVersion this
// build reports equals the one a build of tag would report.
func (w *Watcher) onTarget(tag string) bool {
	want := version.Info{KubeVersion: w.cfg.Running.KubeVersion, Version: tag}
	return w.cfg.Running.NodeVersion() == want.NodeVersion()
}

// attempt runs one update of this node to tag. The signature is checked
// before anything else, so a payload the server did not sign is never even
// downloaded. A refusal or a failure writes Failed; a stop of this daemon (ctx
// ending) writes nothing, because the restarted daemon judges the outcome.
func (w *Watcher) attempt(ctx context.Context, tag string, ann map[string]string) error {
	log := w.log.With("version", tag)
	signed, err := VerifySignedPayload(w.cfg.ClusterCA, []byte(ann[AnnotationUpdatePayload]), ann[AnnotationUpdatePayloadSig], ann[AnnotationUpdateSigner], w.now())
	if err != nil {
		return w.fail(ctx, log, err, "")
	}
	p := signed.Payload
	if p.Version != tag {
		return w.fail(ctx, log, fmt.Errorf("%w: the signed payload installs %s, the Node asks for %s", ErrRefused, p.Version, tag), "")
	}
	if err := (HostPin{Base: w.cfg.ReleaseBase}).CheckRaw(p.URL); err != nil {
		return w.fail(ctx, log, err, "")
	}
	if cmp, ok := install.CompareReleaseVersions(tag, w.cfg.Running.Version); ok && cmp < 0 && !p.AllowDowngrade {
		return w.fail(ctx, log, fmt.Errorf("%w: %s is older than the running %s and the update does not allow a downgrade", ErrRefused, tag, w.cfg.Running.Version), "")
	}
	dir, err := w.newAttemptDir()
	if err != nil {
		return w.fail(ctx, log, err, "")
	}
	log = log.With("dir", dir)

	if err := w.setPhase(ctx, updatesv1alpha1.UpdateNodePhaseDownloading, ""); err != nil {
		return err
	}
	archive := filepath.Join(dir, archiveName)
	sum, err := w.download(ctx, p.URL, archive)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return w.fail(ctx, log, err, "")
	}

	// The root helper re-checks the digest on its own copy; checking it here
	// too fails a bad download without a root round trip.
	if err := w.setPhase(ctx, updatesv1alpha1.UpdateNodePhaseVerifying, ""); err != nil {
		return err
	}
	if sum != p.SHA256 {
		return w.fail(ctx, log, fmt.Errorf("%w: the archive's sha256 is %s, the signed payload says %s", ErrRefused, sum, p.SHA256), "")
	}

	if err := w.setPhase(ctx, updatesv1alpha1.UpdateNodePhaseInstalling, ""); err != nil {
		return err
	}
	log.Info("update: handing the signed payload and the archive to the root helper")
	m := newPhaseMirror(updatesv1alpha1.UpdateNodePhaseInstalling)
	res, err := w.cfg.Netd.ApplyUpdate(ctx, wire.ApplyUpdateArgs{
		ArchivePath: archive,
		Payload:     signed.Raw,
		Signature:   signed.Signature,
		SignerCert:  signed.SignerPEM,
	}, func(ph wire.UpdatePhase) {
		if next, ok := m.advance(ph); ok {
			if err := w.setPhase(ctx, next, ""); err != nil {
				log.Warn("update: writing the phase failed", "phase", next, "err", err)
			}
		}
	})
	if err != nil {
		if ctx.Err() != nil {
			log.Info("update: this daemon is stopping while the root helper installs; the restarted daemon reports the outcome")
			return nil
		}
		return w.fail(ctx, log, err, res.Log)
	}
	if next, ok := m.advance(res.Phase); ok {
		return w.setPhase(ctx, next, "")
	}
	return nil
}

func (w *Watcher) now() time.Time {
	if w.cfg.Now != nil {
		return w.cfg.Now()
	}
	return time.Now()
}

// phaseMirror maps the root helper's streamed phases onto the node phase,
// writing each step forward once. Verifying and Installing are already
// written by the node before the verb runs. Done means the installer exited
// 0; the node reports Restarting for it, because Done is the claim of the
// restarted daemon running the new build. Failed is reported from the verb's
// error, with its message.
type phaseMirror struct {
	last updatesv1alpha1.UpdateNodePhase
}

func newPhaseMirror(start updatesv1alpha1.UpdateNodePhase) *phaseMirror {
	return &phaseMirror{last: start}
}

func (m *phaseMirror) advance(ph wire.UpdatePhase) (updatesv1alpha1.UpdateNodePhase, bool) {
	switch ph {
	case wire.UpdatePhaseRestarting, wire.UpdatePhaseDone:
		if m.last == updatesv1alpha1.UpdateNodePhaseRestarting {
			return "", false
		}
		m.last = updatesv1alpha1.UpdateNodePhaseRestarting
		return m.last, true
	}
	return "", false
}

// fail writes Failed with err's message and, when the installer's log tail is
// known, its last line.
func (w *Watcher) fail(ctx context.Context, log *slog.Logger, err error, tail string) error {
	msg := err.Error()
	if last := lastLine(tail); last != "" {
		msg += " (installer: " + last + ")"
	}
	log.Error("update: this node's update failed", "err", err, "installer-log", tail)
	return w.setPhase(ctx, updatesv1alpha1.UpdateNodePhaseFailed, msg)
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// setPhase merge-patches the phase annotation on this node's own Node, and
// nothing else: the controller's own update-* annotations (the cordon and
// timing records) are never written or removed here, and the controller
// clears the update keys itself when the node finishes.
func (w *Watcher) setPhase(ctx context.Context, phase updatesv1alpha1.UpdateNodePhase, msg string) error {
	patch, err := json.Marshal(map[string]any{"metadata": map[string]any{"annotations": map[string]any{
		updatesv1alpha1.AnnotationUpdatePhase: FormatPhase(phase, msg),
	}}})
	if err != nil {
		return fmt.Errorf("encode the phase patch: %w", err)
	}
	if _, err := w.cfg.Client.CoreV1().Nodes().Patch(ctx, w.cfg.Node, types.MergePatchType, patch, metav1.PatchOptions{FieldManager: FieldManager}); err != nil {
		return fmt.Errorf("write phase %s on node %s: %w", phase, w.cfg.Node, err)
	}
	return nil
}

// download fetches rawURL into the new file at dst, at most MaxArchiveBytes and
// within DownloadTimeout, and returns the sha256 of the bytes written.
func (w *Watcher) download(ctx context.Context, rawURL, dst string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, DownloadTimeout)
	defer cancel()
	if err := (HostPin{Base: w.cfg.ReleaseBase}).CheckRaw(rawURL); err != nil {
		return "", err
	}
	body, err := w.cfg.Fetcher.Fetch(ctx, rawURL)
	if err != nil {
		return "", err
	}
	defer body.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", dst, err)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(body, MaxArchiveBytes+1))
	if err == nil && n > MaxArchiveBytes {
		err = fmt.Errorf("%w: the archive is larger than %d bytes", ErrRefused, MaxArchiveBytes)
	}
	if cerr := out.Close(); err == nil && cerr != nil {
		err = cerr
	}
	if err != nil {
		return "", fmt.Errorf("download the archive: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// newAttemptDir prepares Root, removes every earlier attempt directory and
// makes a fresh one, mode 0700.
func (w *Watcher) newAttemptDir() (string, error) {
	if err := w.ensureRoot(); err != nil {
		return "", err
	}
	w.prune()
	dir, err := os.MkdirTemp(w.cfg.Root, attemptPrefix)
	if err != nil {
		return "", fmt.Errorf("create an update directory in %s: %w", w.cfg.Root, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", fmt.Errorf("chmod %s: %w", dir, err)
	}
	return dir, nil
}

// ensureRoot creates Root (0700) when it is absent and otherwise requires a
// real directory owned by this process's uid, which it sets to mode 0700.
func (w *Watcher) ensureRoot() error {
	root := w.cfg.Root
	if err := os.Mkdir(root, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("create the update root %s: %w", root, err)
	}
	fi, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("inspect the update root %s: %w", root, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%w: the update root %s is not a directory owned by this daemon's user", ErrRefused, root)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return fmt.Errorf("chmod %s: %w", root, err)
	}
	return nil
}

// prune removes the attempt directories in Root. Only real directories with
// the attempt prefix are touched.
func (w *Watcher) prune() {
	entries, err := os.ReadDir(w.cfg.Root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), attemptPrefix) || e.Type()&fs.ModeType != fs.ModeDir {
			continue
		}
		p := filepath.Join(w.cfg.Root, e.Name())
		if err := os.RemoveAll(p); err != nil {
			w.log.Warn("update: removing an earlier update directory failed", "dir", p, "err", err)
		}
	}
}
