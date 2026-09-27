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

package addons

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"k3sm.io/k3sm/pkg/policy"
)

// ManifestFieldManager is the server-side-apply field manager of every object the
// manifest-directory reconciler applies. It is distinct from FieldManager (the
// embedded set) so the two appliers never take each other's fields.
const ManifestFieldManager = "k3sm-manifest-dir"

// ManifestChecksumAnnotation is stamped on every object the manifest-directory
// reconciler applies: the sha256 of the file the object came from. It is content
// derived, so re-applying an unchanged file writes nothing new to the datastore.
const ManifestChecksumAnnotation = "manifests.k3sm.io/sha256"

// DarwinSchedulingEventReason is the reason of the Warning Event recorded on an
// applied object whose Pod template lacks the Darwin scheduling fields.
const DarwinSchedulingEventReason = "ManifestNeedsDarwinScheduling"

// ConflictEventReason is the reason of the Warning Event recorded on an object
// whose apply was refused because another field manager owns fields the manifest
// sets. The reconciler never forces, so the file is parked until it changes.
const ConflictEventReason = "ManifestFieldConflict"

// ManifestSweepInterval is how often the reconciler re-reads the directory even
// when no filesystem event arrived: the backstop for a missed event and for a
// directory created after start.
const ManifestSweepInterval = 60 * time.Second

// Bounds on what one sweep reads. A file over maxManifestBytes is refused, and a
// directory holding more than maxManifestFiles candidates is applied up to the
// bound (in name order) with the rest refused, so a runaway directory cannot turn
// one sweep into an unbounded read.
const (
	maxManifestBytes = 4 << 20
	maxManifestFiles = 256
)

// changeDebounce coalesces a burst of filesystem events (an editor's
// write-rename-chmod) into one sweep.
const changeDebounce = 500 * time.Millisecond

// refusedCoreKinds are the core kinds the reconciler never applies. A Secret or
// a ServiceAccount is provisioned by kubectl or by k3sm's Go paths: a manifest
// that could create a kubernetes.io/service-account-token Secret would mint the
// token of any existing ServiceAccount, which escalation prevention does not
// cover. Also a recorded divergence from k3s.
var refusedCoreKinds = map[string]bool{
	"Secret":         true,
	"ServiceAccount": true,
}

// refusedGroups are the API groups the reconciler never applies, whatever the
// identity it applies with could do: a manifest must not grant authority or
// change what admission enforces. This is a recorded divergence from k3s, whose
// manifest directory applies anything.
var refusedGroups = map[string]bool{
	"rbac.authorization.k8s.io":    true,
	"admissionregistration.k8s.io": true,
}

// fileCheck decides whether an opened file (or the directory itself) may be read.
// Production binds rootOwnedNotShared; tests bind a variant that accepts the test
// user as the owner, since a unit test cannot create a root-owned file.
type fileCheck func(fi fs.FileInfo) error

// rootOwnedNotShared refuses anything not owned by root, or writable by its group
// or by others.
func rootOwnedNotShared(fi fs.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return errors.New("owner unknown")
	}
	if st.Uid != 0 {
		return fmt.Errorf("owned by uid %d, not root", st.Uid)
	}
	return notShared(fi)
}

// notShared refuses a group- or other-writable mode.
func notShared(fi fs.FileInfo) error {
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("mode %04o is group- or other-writable", fi.Mode().Perm())
	}
	return nil
}

// ManifestDir applies the operator's manifests from a root-owned directory: the
// k3s server/manifests analog, apply-only (see doc.go § The manifest directory).
//
// Sweep and Run never return an error. Every failure is logged here, at the
// boundary that handles it, and the reconciler carries on; nothing it does can
// reach the control plane's tear-down path.
type ManifestDir struct {
	dir      string
	dyn      dynamic.Interface
	mapper   meta.RESTMapper
	events   kubernetes.Interface
	logger   *slog.Logger
	check    fileCheck
	interval time.Duration
	now      func() time.Time

	// mu guards settled and serializes sweeps: Run's goroutine is the only
	// production caller, but a test may call Sweep directly.
	mu sync.Mutex
	// settled maps a file name to the signature of its last settled outcome:
	// "sha:<hex>" once its content was applied (or deterministically refused),
	// "stat:<…>" once the file itself was refused. A file whose signature is
	// unchanged is skipped silently.
	settled map[string]string
}

// NewManifestDir returns a reconciler for dir that applies through dyn (mapping
// kinds with mapper) and records Events through events. All three must carry the
// bounded manifest identity, never the admin one.
func NewManifestDir(dir string, dyn dynamic.Interface, mapper meta.RESTMapper, events kubernetes.Interface, logger *slog.Logger) *ManifestDir {
	if logger == nil {
		logger = slog.Default()
	}
	return &ManifestDir{
		dir:      dir,
		dyn:      dyn,
		mapper:   mapper,
		events:   events,
		logger:   logger,
		check:    rootOwnedNotShared,
		interval: ManifestSweepInterval,
		now:      time.Now,
		settled:  map[string]string{},
	}
}

// Run sweeps once, then again on every change to the directory (fsnotify) and
// every ManifestSweepInterval, until ctx is done. A directory that does not exist
// yet is watched once it appears (the periodic sweep re-arms the watch).
func (m *ManifestDir) Run(ctx context.Context) {
	m.Sweep(ctx)

	var (
		events   <-chan fsnotify.Event
		errs     <-chan error
		watching bool
	)
	w, err := fsnotify.NewWatcher()
	if err != nil {
		m.logger.Warn("manifest dir: no filesystem watch; changes are picked up by the periodic sweep only",
			"dir", m.dir, "interval", m.interval, "err", err)
	} else {
		defer func() { _ = w.Close() }() // closing a watcher at shutdown has nothing to report
		events, errs = w.Events, w.Errors
	}
	arm := func() {
		if w == nil || watching {
			return
		}
		if err := w.Add(m.dir); err == nil {
			watching = true
		}
	}
	arm()

	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	debounce := time.NewTimer(changeDebounce)
	debounce.Stop()
	defer debounce.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			arm()
			m.Sweep(ctx)
		case ev, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			if filepath.Clean(ev.Name) == filepath.Clean(m.dir) && ev.Has(fsnotify.Remove|fsnotify.Rename) {
				watching = false // the directory itself went away; re-armed by the next tick
			}
			debounce.Reset(changeDebounce)
		case err, ok := <-errs:
			if !ok {
				errs = nil
				continue
			}
			m.logger.Debug("manifest dir: watch error", "dir", m.dir, "err", err)
		case <-debounce.C:
			m.Sweep(ctx)
		}
	}
}

// Sweep reads the directory once and applies every candidate file whose content
// changed since it was last settled. A missing directory is not an error.
func (m *ManifestDir) Sweep(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()

	di, err := os.Lstat(m.dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		m.logger.Debug("manifest dir: absent; nothing to apply", "dir", m.dir)
		clear(m.settled)
		return
	case err != nil:
		m.logger.Warn("manifest dir: cannot stat; nothing applied", "dir", m.dir, "err", err)
		return
	case di.Mode()&fs.ModeSymlink != 0 || !di.IsDir():
		m.logger.Warn("manifest dir: not a real directory; nothing applied", "dir", m.dir, "mode", di.Mode().String())
		return
	}
	if err := m.check(di); err != nil {
		m.logger.Warn("manifest dir: refused; nothing applied", "dir", m.dir, "reason", err.Error())
		return
	}
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		m.logger.Warn("manifest dir: cannot list; nothing applied", "dir", m.dir, "err", err)
		return
	}

	var names []string
	for _, e := range entries {
		if isDirManifest(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	seen := make(map[string]bool, len(names))
	for i, name := range names {
		seen[name] = true
		if i >= maxManifestFiles {
			m.logger.Warn("manifest dir: too many manifest files; skipped", "file", filepath.Join(m.dir, name), "limit", maxManifestFiles)
			continue
		}
		m.sweepFile(ctx, name)
	}
	// Forget a removed file, so putting it back applies it again. Its objects stay
	// in the cluster: removing a file never deletes anything.
	for name := range m.settled {
		if !seen[name] {
			delete(m.settled, name)
		}
	}
}

// isDirManifest reports whether a directory entry name is a manifest the
// reconciler reads: .yaml, .yml or .json, and not hidden or parked (a leading "."
// or "_", the k3s convention for a file the operator wants ignored).
func isDirManifest(name string) bool {
	if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
		return false
	}
	switch filepath.Ext(name) {
	case ".yaml", ".yml", ".json":
		return true
	default:
		return false
	}
}

// sweepFile applies one file if its settled signature changed. Called with mu held.
func (m *ManifestDir) sweepFile(ctx context.Context, name string) {
	path := filepath.Join(m.dir, name)
	li, err := os.Lstat(path)
	if err != nil {
		m.logger.Warn("manifest dir: cannot stat file; skipped", "file", path, "err", err)
		return
	}
	if li.Mode()&fs.ModeSymlink != 0 {
		m.refuse(name, path, li, "a symlink")
		return
	}
	if !li.Mode().IsRegular() {
		m.refuse(name, path, li, "not a regular file")
		return
	}
	// O_NOFOLLOW refuses a symlink swapped in after the Lstat; O_NONBLOCK keeps a
	// FIFO swapped in from wedging the sweep. The ownership check runs on the
	// OPENED file, so it judges exactly the bytes that are read.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		m.logger.Warn("manifest dir: cannot open file; skipped", "file", path, "err", err)
		return
	}
	defer func() { _ = f.Close() }() // read-only: nothing to flush, nothing to report
	fi, err := f.Stat()
	if err != nil {
		m.logger.Warn("manifest dir: cannot stat opened file; skipped", "file", path, "err", err)
		return
	}
	if !fi.Mode().IsRegular() {
		m.refuse(name, path, fi, "not a regular file")
		return
	}
	if err := m.check(fi); err != nil {
		m.refuse(name, path, fi, err.Error())
		return
	}
	if fi.Size() > maxManifestBytes {
		m.refuse(name, path, fi, fmt.Sprintf("larger than %d bytes", maxManifestBytes))
		return
	}
	data, err := io.ReadAll(io.LimitReader(f, maxManifestBytes+1))
	if err != nil {
		m.logger.Warn("manifest dir: cannot read file; skipped", "file", path, "err", err)
		return
	}
	if len(data) > maxManifestBytes {
		m.refuse(name, path, fi, fmt.Sprintf("larger than %d bytes", maxManifestBytes))
		return
	}
	sum := sha256.Sum256(data)
	hexSum := hex.EncodeToString(sum[:])
	sig := "sha:" + hexSum
	if m.settled[name] == sig {
		return // unchanged since it was last settled
	}
	if m.applyFile(ctx, path, hexSum, data) {
		m.settled[name] = sig
	} else {
		delete(m.settled, name) // a transient failure: the next sweep retries
	}
}

// refuse logs a refused file once per distinct file state and remembers it, so an
// unchanged refused file does not log on every sweep. Called with mu held.
func (m *ManifestDir) refuse(name, path string, fi fs.FileInfo, reason string) {
	sig := "stat:" + statSignature(fi)
	if m.settled[name] == sig {
		return
	}
	m.settled[name] = sig
	m.logger.Warn("manifest dir: file refused; skipped", "file", path, "reason", reason)
}

// statSignature is the identity of a file state the reconciler refused: a chown,
// a chmod or a rewrite changes it, so the file is judged again.
func statSignature(fi fs.FileInfo) string {
	uid, gid := -1, -1
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st != nil {
		uid, gid = int(st.Uid), int(st.Gid)
	}
	return fmt.Sprintf("%d/%d/%o/%s/%d/%d", uid, gid, fi.Mode(), fi.Mode().Type(), fi.Size(), fi.ModTime().UnixNano())
}

// applyFile decodes and applies every object in one file. It reports whether the
// outcome is settled: true when every object applied or failed for a reason the
// same bytes would fail for again (a decode error, a refused kind, a field
// conflict), false when a retry could succeed (an apiserver error, an unmapped
// kind whose CRD may not be established yet).
func (m *ManifestDir) applyFile(ctx context.Context, path, sum string, data []byte) bool {
	settled := true
	reader := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
	for i := 0; ; i++ {
		raw, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			m.logger.Warn("manifest dir: unreadable document; rest of file skipped", "file", path, "document", i, "err", err)
			break
		}
		objs, errs := expandDocument(raw)
		for _, err := range errs {
			m.logger.Warn("manifest dir: invalid document; skipped", "file", path, "document", i, "err", err)
		}
		for _, obj := range objs {
			if !m.applyObject(ctx, path, sum, obj) {
				settled = false
			}
		}
	}
	return settled
}

// expandDocument decodes one YAML or JSON document into the objects it carries.
// A v1 List and a top-level JSON (or YAML) array are flattened into their items,
// which is how kubectl reads them; the List's own metadata is ignored. Any other
// document is one object. An item that fails the authoring contract is reported
// and skipped; its siblings are still returned. An empty or comment-only document
// yields nothing.
func expandDocument(raw []byte) ([]*unstructured.Unstructured, []error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}
	jsonBytes, err := utilyaml.ToJSON(raw)
	if err != nil {
		return nil, []error{fmt.Errorf("convert yaml to json: %w", err)}
	}
	trimmed := bytes.TrimSpace(jsonBytes)
	var items []json.RawMessage
	switch {
	case bytes.Equal(trimmed, []byte("null")):
		return nil, nil
	case len(trimmed) > 0 && trimmed[0] == '[':
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return nil, []error{fmt.Errorf("unmarshal array: %w", err)}
		}
	default:
		var head struct {
			APIVersion string            `json:"apiVersion"`
			Kind       string            `json:"kind"`
			Items      []json.RawMessage `json:"items"`
		}
		if err := json.Unmarshal(trimmed, &head); err != nil {
			return nil, []error{fmt.Errorf("unmarshal object: %w", err)}
		}
		if head.APIVersion != "v1" || head.Kind != "List" {
			obj, err := decodeDocument(trimmed)
			if err != nil {
				return nil, []error{err}
			}
			if obj == nil {
				return nil, nil
			}
			return []*unstructured.Unstructured{obj}, nil
		}
		items = head.Items
	}
	var (
		objs []*unstructured.Unstructured
		errs []error
	)
	for j, item := range items {
		obj, err := decodeDocument(item)
		if err != nil {
			errs = append(errs, fmt.Errorf("item %d: %w", j, err))
			continue
		}
		if obj != nil {
			objs = append(objs, obj)
		}
	}
	return objs, errs
}

// applyObject applies one object and reports whether its outcome is settled (see
// applyFile).
func (m *ManifestDir) applyObject(ctx context.Context, path, sum string, obj *unstructured.Unstructured) bool {
	gvk := obj.GroupVersionKind()
	if refusedGroups[gvk.Group] {
		m.logger.Warn("manifest dir: refused kind; an RBAC or admission object is never applied from the manifest directory (provision it in Go)",
			"file", path, "kind", gvk.String(), "object", describe(obj))
		return true
	}
	if gvk.Group == "" && refusedCoreKinds[gvk.Kind] {
		m.logger.Warn("manifest dir: refused kind; a Secret or ServiceAccount is never applied from the manifest directory (create it with kubectl or provision it in Go)",
			"file", path, "kind", gvk.String(), "object", describe(obj))
		return true
	}
	mapping, err := m.mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		if meta.IsNoMatchError(err) {
			if r, ok := m.mapper.(meta.ResettableRESTMapper); ok {
				r.Reset() // a CRD established since the last discovery is found next time
			}
		}
		m.logger.Warn("manifest dir: unknown kind; will retry", "file", path, "kind", gvk.String(), "object", describe(obj), "err", err)
		return false
	}
	var ri dynamic.ResourceInterface
	if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
		if obj.GetNamespace() == "" {
			m.logger.Warn("manifest dir: namespaced object declares no metadata.namespace; skipped", "file", path, "kind", gvk.String(), "object", describe(obj))
			return true
		}
		ri = m.dyn.Resource(mapping.Resource).Namespace(obj.GetNamespace())
	} else {
		if obj.GetNamespace() != "" {
			m.logger.Warn("manifest dir: cluster-scoped object declares a metadata.namespace; skipped", "file", path, "kind", gvk.String(), "object", describe(obj))
			return true
		}
		ri = m.dyn.Resource(mapping.Resource)
	}

	ann := obj.GetAnnotations()
	if ann == nil {
		ann = map[string]string{}
	}
	ann[ManifestChecksumAnnotation] = sum
	obj.SetAnnotations(ann)

	// Force is false: server-side apply only ever conflicts with ANOTHER manager,
	// so an unforced apply takes over nothing an operator or a controller set by
	// hand. A conflict is reported and left for the operator.
	applied, err := ri.Apply(ctx, obj.GetName(), obj, metav1.ApplyOptions{FieldManager: ManifestFieldManager})
	if err != nil {
		if apierrors.IsConflict(err) {
			// Parked: the same bytes would conflict again, so the file waits for a
			// change. The Event makes the conflict visible to kubectl, not only in
			// the server log.
			managers := conflictManagers(err)
			m.logger.Warn("manifest dir: field conflict with another manager; not forced, parked until the file changes",
				"file", path, "kind", gvk.String(), "object", describe(obj), "managers", strings.Join(managers, ", "), "err", err)
			m.recordEvent(ctx, path, sum, "conflict", ConflictEventReason, obj, nil,
				fmt.Sprintf("not applied from %s: fields are owned by %s; the manifest directory never forces, so change the file or remove that manager's fields",
					filepath.Base(path), strings.Join(managers, ", ")))
			return true
		}
		m.logger.Warn("manifest dir: apply failed; will retry", "file", path, "kind", gvk.String(), "object", describe(obj), "err", err)
		return false
	}
	m.logger.Info("manifest dir: applied", "file", path, "kind", gvk.String(), "object", describe(obj))
	if missing := missingDarwinScheduling(obj); len(missing) > 0 {
		m.recordEvent(ctx, path, sum, "darwin", DarwinSchedulingEventReason, obj, applied,
			fmt.Sprintf("applied from %s, but its pod template lacks %s; its pods will not run on a k3sm node until the manifest carries them",
				filepath.Base(path), strings.Join(missing, " and ")))
	}
	return true
}

// podSpecPaths is where each Pod-template kind keeps its PodSpec.
var podSpecPaths = map[string][]string{
	"Pod":         {"spec"},
	"Deployment":  {"spec", "template", "spec"},
	"DaemonSet":   {"spec", "template", "spec"},
	"StatefulSet": {"spec", "template", "spec"},
	"Job":         {"spec", "template", "spec"},
	"CronJob":     {"spec", "jobTemplate", "spec", "template", "spec"},
}

// missingDarwinScheduling names the Darwin scheduling fields a Pod-template
// object lacks: the kubernetes.io/os=darwin nodeSelector and the k3sm.io/provider
// toleration. A stock manifest carries neither, so its workload object applies
// cleanly while every Pod it spawns is rejected by admission or left
// Unschedulable. An object with no PodSpec, or one it cannot decode, yields none.
func missingDarwinScheduling(obj *unstructured.Unstructured) []string {
	fields, ok := podSpecPaths[obj.GetKind()]
	if !ok {
		return nil
	}
	if g := obj.GroupVersionKind().Group; g != "" && g != "apps" && g != "batch" {
		return nil
	}
	raw, found, err := unstructured.NestedMap(obj.Object, fields...)
	if err != nil || !found {
		return nil
	}
	var spec corev1.PodSpec
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(raw, &spec); err != nil {
		return nil
	}
	var missing []string
	if spec.NodeSelector["kubernetes.io/os"] != "darwin" {
		missing = append(missing, "nodeSelector kubernetes.io/os=darwin")
	}
	tolerated := false
	for _, tol := range spec.Tolerations {
		if toleratesProviderTaint(tol) {
			tolerated = true
			break
		}
	}
	if !tolerated {
		missing = append(missing, "toleration "+policy.ProviderTaintKey+" (operator: Exists, effect: NoSchedule)")
	}
	return missing
}

// toleratesProviderTaint reports whether tol tolerates the provider taint
// (policy.ProviderTaintKey, empty value, NoSchedule). It is the same match
// Toleration.ToleratesTaint makes, and the same one pkg/policy's CEL transcribes:
// the effect matches or is empty, the key matches or is empty, and the operator is
// Exists or the (empty) value matches.
func toleratesProviderTaint(tol corev1.Toleration) bool {
	if tol.Effect != "" && tol.Effect != corev1.TaintEffectNoSchedule {
		return false
	}
	if tol.Key != "" && tol.Key != policy.ProviderTaintKey {
		return false
	}
	switch tol.Operator {
	case corev1.TolerationOpExists:
		return true
	case "", corev1.TolerationOpEqual:
		return tol.Value == ""
	default:
		return false
	}
}

// recordEvent records a Warning Event with reason on the object obj names. Its
// name is derived from the object, the file checksum and tag, so the same outcome
// for the same file bytes (a restart re-applying it) finds the Event already there
// instead of writing a new one. applied, when non-nil, supplies the UID and
// resourceVersion the apiserver returned.
func (m *ManifestDir) recordEvent(ctx context.Context, path, sum, tag, reason string, obj, applied *unstructured.Unstructured, message string) {
	ref := applied
	if ref == nil {
		ref = obj
	}
	ns := obj.GetNamespace()
	if ns == "" {
		ns = metav1.NamespaceDefault
	}
	name := obj.GetName()
	if len(name) > 200 {
		name = name[:200]
	}
	now := metav1.NewTime(m.now())
	ev := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: fmt.Sprintf("%s.%s.%s", name, sum[:16], tag)},
		InvolvedObject: corev1.ObjectReference{
			APIVersion:      obj.GetAPIVersion(),
			Kind:            obj.GetKind(),
			Namespace:       obj.GetNamespace(),
			Name:            obj.GetName(),
			UID:             ref.GetUID(),
			ResourceVersion: ref.GetResourceVersion(),
		},
		Reason:              reason,
		Message:             message,
		Type:                corev1.EventTypeWarning,
		Source:              corev1.EventSource{Component: ManifestFieldManager},
		ReportingController: "k3sm.io/" + ManifestFieldManager,
		FirstTimestamp:      now,
		LastTimestamp:       now,
		Count:               1,
	}
	if _, err := m.events.CoreV1().Events(ns).Create(ctx, ev, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		m.logger.Warn("manifest dir: could not record an event", "reason", reason, "file", path, "object", describe(obj), "err", err)
		return
	}
	if reason == DarwinSchedulingEventReason {
		m.logger.Warn("manifest dir: applied object lacks Darwin scheduling fields", "file", path, "kind", obj.GetKind(), "object", describe(obj), "message", message)
	}
}

// conflictManagers extracts the field managers a server-side apply conflict
// names. The apiserver reports each conflicting field as a FieldManagerConflict
// cause whose message reads `conflict with "<manager>" …`. A conflict without
// such causes yields "another field manager".
func conflictManagers(err error) []string {
	var status apierrors.APIStatus
	seen := map[string]bool{}
	var out []string
	if errors.As(err, &status) {
		if d := status.Status().Details; d != nil {
			for _, c := range d.Causes {
				if c.Type != metav1.CauseTypeFieldManagerConflict {
					continue
				}
				const marker = `conflict with "`
				k := strings.Index(c.Message, marker)
				if k < 0 {
					continue
				}
				rest := c.Message[k+len(marker):]
				end := strings.Index(rest, `"`)
				if end <= 0 {
					continue
				}
				if mgr := rest[:end]; !seen[mgr] {
					seen[mgr] = true
					out = append(out, mgr)
				}
			}
		}
	}
	if len(out) == 0 {
		return []string{"another field manager"}
	}
	sort.Strings(out)
	return out
}
