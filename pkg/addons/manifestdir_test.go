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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
)

// syncBuffer is a goroutine-safe log sink: Run logs from its own goroutine while
// the test reads.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// manifestMapper maps the kinds the manifest-dir fixtures use. The refused RBAC,
// Secret and ServiceAccount kinds are registered too, so their refusal is proven
// to happen BEFORE mapping rather than by an unmapped kind failing.
func manifestMapper() meta.RESTMapper {
	m := meta.NewDefaultRESTMapper([]schema.GroupVersion{{Version: "v1"}, {Group: "apps", Version: "v1"}, {Group: "batch", Version: "v1"}})
	m.Add(configMapGVK, meta.RESTScopeNamespace)
	m.Add(schema.GroupVersionKind{Version: "v1", Kind: "Secret"}, meta.RESTScopeNamespace)
	m.Add(schema.GroupVersionKind{Version: "v1", Kind: "ServiceAccount"}, meta.RESTScopeNamespace)
	for _, gvk := range []schema.GroupVersionKind{
		{Group: "apps", Version: "v1", Kind: "Deployment"},
		{Group: "apps", Version: "v1", Kind: "DaemonSet"},
		{Group: "apps", Version: "v1", Kind: "StatefulSet"},
		{Group: "batch", Version: "v1", Kind: "Job"},
		{Group: "batch", Version: "v1", Kind: "CronJob"},
	} {
		m.Add(gvk, meta.RESTScopeNamespace)
	}
	m.Add(schema.GroupVersionKind{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "ClusterRole"}, meta.RESTScopeRoot)
	return m
}

// manifestHarness is one reconciler over a temp dir, with the fakes it talks to.
type manifestHarness struct {
	dir     string
	dyn     *dynamicfake.FakeDynamicClient
	events  *fake.Clientset
	logs    *syncBuffer
	m       *ManifestDir
	foreign map[string]bool
}

// newManifestHarness builds the harness. The ownership seam accepts the test
// user in place of root (a unit test cannot create a root-owned file) but keeps
// the real group/other-writable check, and refuses any file named in foreign as
// a stand-in for a file owned by someone other than root.
func newManifestHarness(t *testing.T) *manifestHarness {
	t.Helper()
	h := &manifestHarness{
		dir:     filepath.Join(t.TempDir(), "manifests"),
		dyn:     newFakeDynamic(t),
		events:  fake.NewClientset(),
		logs:    &syncBuffer{},
		foreign: map[string]bool{},
	}
	if err := os.Mkdir(h.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h.m = NewManifestDir(h.dir, h.dyn, manifestMapper(), h.events, logger)
	h.m.check = func(fi fs.FileInfo) error {
		if h.foreign[fi.Name()] {
			return errors.New("owned by uid 501, not root")
		}
		return notShared(fi)
	}
	return h
}

func (h *manifestHarness) write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(h.dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	// WriteFile honors the umask; pin the mode the reconciler judges.
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// applies returns the apply patches issued since the last reset, failing on any
// verb other than an apply patch under the manifest field manager, unforced.
func (h *manifestHarness) applies(t *testing.T) []k8stesting.PatchActionImpl {
	t.Helper()
	var out []k8stesting.PatchActionImpl
	for i, a := range h.dyn.Actions() {
		pa, ok := a.(k8stesting.PatchActionImpl)
		if !ok || a.GetVerb() != "patch" {
			t.Errorf("action %d: verb %q; the manifest reconciler issues apply patches only (never a list or a delete)", i, a.GetVerb())
			continue
		}
		if pa.GetPatchType() != types.ApplyPatchType {
			t.Errorf("action %d: patch type %q, want server-side apply", i, pa.GetPatchType())
		}
		if got := pa.PatchOptions.FieldManager; got != ManifestFieldManager {
			t.Errorf("action %d: field manager %q, want %q", i, got, ManifestFieldManager)
		}
		if pa.PatchOptions.Force != nil && *pa.PatchOptions.Force {
			t.Errorf("action %d: apply is forced; it must never take fields from another manager", i)
		}
		out = append(out, pa)
	}
	h.dyn.ClearActions()
	return out
}

func appliedNames(as []k8stesting.PatchActionImpl) []string {
	var out []string
	for _, a := range as {
		out = append(out, a.GetName())
	}
	return out
}

func annotationOf(t *testing.T, pa k8stesting.PatchActionImpl) string {
	t.Helper()
	obj := &unstructured.Unstructured{}
	if err := obj.UnmarshalJSON(pa.GetPatch()); err != nil {
		t.Fatalf("decode apply patch: %v", err)
	}
	return obj.GetAnnotations()[ManifestChecksumAnnotation]
}

func sumOf(body string) string {
	s := sha256.Sum256([]byte(body))
	return hex.EncodeToString(s[:])
}

const manifestCM = `apiVersion: v1
kind: ConfigMap
metadata:
  name: op-config
  namespace: default
data:
  k: v1
`

const manifestCMChanged = `apiVersion: v1
kind: ConfigMap
metadata:
  name: op-config
  namespace: default
data:
  k: v2
`

const manifestRBAC = `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: grab-everything
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: beside-rbac
  namespace: default
`

const manifestLinuxDeploy = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: stock-addon
  namespace: kube-system
spec:
  selector:
    matchLabels: {app: stock-addon}
  template:
    metadata:
      labels: {app: stock-addon}
    spec:
      containers:
      - name: c
        image: example/stock-addon:1
`

// manifestLinuxWorkloads is one stock (Linux-authored) object of every other
// Pod-template kind. The CronJob carries the darwin nodeSelector at the end of its
// five-level template path (and no toleration), so its Event proves that path is
// the one read.
const manifestLinuxWorkloads = `apiVersion: apps/v1
kind: DaemonSet
metadata: {name: stock-ds, namespace: kube-system}
spec:
  selector: {matchLabels: {app: ds}}
  template:
    metadata: {labels: {app: ds}}
    spec: {containers: [{name: c, image: example/ds:1}]}
---
apiVersion: apps/v1
kind: StatefulSet
metadata: {name: stock-sts, namespace: kube-system}
spec:
  serviceName: sts
  selector: {matchLabels: {app: sts}}
  template:
    metadata: {labels: {app: sts}}
    spec: {containers: [{name: c, image: example/sts:1}]}
---
apiVersion: batch/v1
kind: Job
metadata: {name: stock-job, namespace: kube-system}
spec:
  template:
    spec: {restartPolicy: Never, containers: [{name: c, image: example/job:1}]}
---
apiVersion: batch/v1
kind: CronJob
metadata: {name: stock-cron, namespace: kube-system}
spec:
  schedule: "*/5 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
          nodeSelector: {kubernetes.io/os: darwin}
          containers: [{name: c, image: example/cron:1}]
`

const manifestDarwinDeploy = `{"apiVersion": "apps/v1", "kind": "Deployment",
 "metadata": {"name": "darwin-addon", "namespace": "kube-system"},
 "spec": {"selector": {"matchLabels": {"app": "darwin-addon"}},
  "template": {"metadata": {"labels": {"app": "darwin-addon"}},
   "spec": {"nodeSelector": {"kubernetes.io/os": "darwin"},
    "tolerations": [{"key": "k3sm.io/provider", "operator": "Exists", "effect": "NoSchedule"}],
    "containers": [{"name": "c", "image": "example/darwin-addon:1"}]}}}}
`

// TestManifestDirReconcile is the B94 gate: the root-owned auto-deploy manifest
// directory is applied (server-side apply, field manager k3sm-manifest-dir,
// never forced) on start and on change, unchanged files are skipped by checksum,
// hidden/parked files and symlinks are ignored, RBAC, admission, Secret and
// ServiceAccount objects are refused with a log, a Pod template without the Darwin scheduling fields gets a
// Warning Event, a missing directory is not an error, no failure propagates, and
// the apply authenticates as the bounded ServiceAccount, never the admin.
func TestManifestDirReconcile(t *testing.T) {
	ctx := context.Background()

	t.Run("applies on start under the manifest field manager with the checksum annotation", func(t *testing.T) {
		h := newManifestHarness(t)
		h.write(t, "config.yaml", manifestCM)
		h.m.Sweep(ctx)
		as := h.applies(t)
		if got := appliedNames(as); len(got) != 1 || got[0] != "op-config" {
			t.Fatalf("applied %v, want [op-config]", got)
		}
		if got, want := annotationOf(t, as[0]), sumOf(manifestCM); got != want {
			t.Errorf("%s = %q, want the file's sha256 %q", ManifestChecksumAnnotation, got, want)
		}
		if _, err := h.dyn.Tracker().Get(configMapGVR, "default", "op-config"); err != nil {
			t.Errorf("the ConfigMap is not in the cluster: %v", err)
		}
	})

	t.Run("an unchanged file is skipped by checksum and a changed one re-applied", func(t *testing.T) {
		h := newManifestHarness(t)
		h.write(t, "config.yaml", manifestCM)
		h.m.Sweep(ctx)
		h.applies(t)
		h.m.Sweep(ctx)
		if got := h.applies(t); len(got) != 0 {
			t.Errorf("an unchanged file was re-applied: %v", appliedNames(got))
		}
		h.write(t, "config.yaml", manifestCMChanged)
		h.m.Sweep(ctx)
		as := h.applies(t)
		if len(as) != 1 {
			t.Fatalf("a changed file applied %d objects, want 1", len(as))
		}
		if got, want := annotationOf(t, as[0]), sumOf(manifestCMChanged); got != want {
			t.Errorf("re-applied %s = %q, want the new sha256 %q", ManifestChecksumAnnotation, got, want)
		}
	})

	t.Run("hidden and parked files, other extensions and symlinks are ignored", func(t *testing.T) {
		h := newManifestHarness(t)
		h.write(t, ".hidden.yaml", strings.ReplaceAll(manifestCM, "op-config", "hidden"))
		h.write(t, "_parked.yaml", strings.ReplaceAll(manifestCM, "op-config", "parked"))
		h.write(t, "notes.txt", strings.ReplaceAll(manifestCM, "op-config", "notes"))
		outside := filepath.Join(t.TempDir(), "target.yaml")
		if err := os.WriteFile(outside, []byte(strings.ReplaceAll(manifestCM, "op-config", "via-link")), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(h.dir, "link.yaml")); err != nil {
			t.Fatal(err)
		}
		h.write(t, "real.json", `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"from-json","namespace":"default"}}`)
		h.m.Sweep(ctx)
		if got := appliedNames(h.applies(t)); len(got) != 1 || got[0] != "from-json" {
			t.Errorf("applied %v, want only [from-json]", got)
		}
		if !strings.Contains(h.logs.String(), "a symlink") {
			t.Errorf("the symlink was not logged as refused:\n%s", h.logs.String())
		}
	})

	t.Run("RBAC, admission, Secret and ServiceAccount objects are refused with a log; their siblings apply", func(t *testing.T) {
		h := newManifestHarness(t)
		path := h.write(t, "rbac.yaml", manifestRBAC)
		h.write(t, "webhook.yaml", `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: intercept-everything
`)
		h.write(t, "creds.yaml", `apiVersion: v1
kind: Secret
metadata:
  name: mint-admin-token
  namespace: kube-system
  annotations:
    kubernetes.io/service-account.name: admin
type: kubernetes.io/service-account-token
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: planted-account
  namespace: default
`)
		h.m.Sweep(ctx)
		if got := appliedNames(h.applies(t)); len(got) != 1 || got[0] != "beside-rbac" {
			t.Errorf("applied %v, want only [beside-rbac]", got)
		}
		logs := h.logs.String()
		for _, want := range []string{"refused kind", path, "grab-everything", "intercept-everything", "mint-admin-token", "planted-account"} {
			if !strings.Contains(logs, want) {
				t.Errorf("the refusal log lacks %q:\n%s", want, logs)
			}
		}
	})

	t.Run("a pod template without the Darwin scheduling fields gets a Warning Event", func(t *testing.T) {
		h := newManifestHarness(t)
		h.write(t, "stock.yaml", manifestLinuxDeploy)
		h.write(t, "darwin.json", manifestDarwinDeploy)
		h.write(t, "workloads.yaml", manifestLinuxWorkloads)
		h.m.Sweep(ctx)
		if got := appliedNames(h.applies(t)); len(got) != 6 {
			t.Fatalf("applied %v, want all six workloads (the trap is warned about, never refused)", got)
		}
		evs, err := h.events.CoreV1().Events("kube-system").List(ctx, metav1.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]string{
			"Deployment": "stock-addon", "DaemonSet": "stock-ds", "StatefulSet": "stock-sts",
			"Job": "stock-job", "CronJob": "stock-cron",
		}
		got := map[string]string{}
		for _, ev := range evs.Items {
			if ev.Reason != DarwinSchedulingEventReason || ev.Type != "Warning" {
				t.Errorf("event %s %s, want Warning %s", ev.Type, ev.Reason, DarwinSchedulingEventReason)
			}
			if !strings.Contains(ev.Message, "k3sm.io/provider") {
				t.Errorf("event on %s does not name the provider toleration: %s", ev.InvolvedObject.Name, ev.Message)
			}
			// stock-cron sets the nodeSelector five levels down, so its Event must
			// name only the toleration: proof the CronJob path is actually read.
			wantSelector := ev.InvolvedObject.Name != "stock-cron"
			if strings.Contains(ev.Message, "kubernetes.io/os=darwin") != wantSelector {
				t.Errorf("event on %s names the nodeSelector = %v, want %v: %s", ev.InvolvedObject.Name, !wantSelector, wantSelector, ev.Message)
			}
			got[ev.InvolvedObject.Kind] = ev.InvolvedObject.Name
		}
		if len(got) != len(want) || len(evs.Items) != len(want) {
			t.Errorf("events on %v, want exactly one on each of %v (none on darwin-addon)", got, want)
		}
		for kind, name := range want {
			if got[kind] != name {
				t.Errorf("no Darwin event on %s/%s (got %q)", kind, name, got[kind])
			}
		}
	})

	t.Run("a field conflict is parked with a Warning Event until the file changes", func(t *testing.T) {
		h := newManifestHarness(t)
		body := strings.ReplaceAll(manifestCM, "op-config", "contested")
		changed := strings.ReplaceAll(manifestCMChanged, "op-config", "contested")
		h.write(t, "contested.yaml", body)
		conflictSum := sumOf(body)
		h.dyn.PrependReactor("patch", "configmaps", func(action k8stesting.Action) (bool, runtime.Object, error) {
			pa, ok := action.(k8stesting.PatchActionImpl)
			if !ok || pa.GetName() != "contested" || !strings.Contains(string(pa.GetPatch()), conflictSum) {
				return false, nil, nil
			}
			return true, nil, apierrors.NewApplyConflict([]metav1.StatusCause{{
				Type:    metav1.CauseTypeFieldManagerConflict,
				Message: `conflict with "kubectl-edit" using v1`,
				Field:   ".data.k",
			}}, `Apply failed with 1 conflict: conflict with "kubectl-edit" using v1: .data.k`)
		})

		h.m.Sweep(ctx)
		if got := h.applies(t); len(got) != 1 {
			t.Fatalf("first sweep attempted %d applies, want 1", len(got))
		}
		h.m.Sweep(ctx)
		h.m.Sweep(ctx)
		if got := h.applies(t); len(got) != 0 {
			t.Errorf("a conflicted file was retried with unchanged bytes: %v", appliedNames(got))
		}
		if n := strings.Count(h.logs.String(), "field conflict"); n != 1 {
			t.Errorf("the conflict was logged %d times, want once:\n%s", n, h.logs.String())
		}
		evs, err := h.events.CoreV1().Events("default").List(ctx, metav1.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(evs.Items) != 1 {
			t.Fatalf("events = %d, want exactly one conflict event", len(evs.Items))
		}
		ev := evs.Items[0]
		if ev.Reason != ConflictEventReason || ev.Type != "Warning" || ev.InvolvedObject.Name != "contested" {
			t.Errorf("event = %s %s on %s, want Warning %s on contested", ev.Type, ev.Reason, ev.InvolvedObject.Name, ConflictEventReason)
		}
		for _, want := range []string{"contested.yaml", "kubectl-edit"} {
			if !strings.Contains(ev.Message, want) {
				t.Errorf("conflict event does not name %q: %s", want, ev.Message)
			}
		}

		// The operator changes the file (here, the new bytes no longer conflict):
		// it is applied again.
		h.write(t, "contested.yaml", changed)
		h.m.Sweep(ctx)
		if got := appliedNames(h.applies(t)); len(got) != 1 || got[0] != "contested" {
			t.Fatalf("after the file changed applied %v, want [contested]", got)
		}
		if _, err := h.dyn.Tracker().Get(configMapGVR, "default", "contested"); err != nil {
			t.Errorf("the object is not in the cluster after the conflict cleared: %v", err)
		}
	})

	t.Run("a v1 List and a top-level array are applied item by item", func(t *testing.T) {
		h := newManifestHarness(t)
		h.write(t, "list.yaml", `apiVersion: v1
kind: List
metadata:
  name: ignored-list-name
items:
- apiVersion: v1
  kind: ConfigMap
  metadata: {name: list-a, namespace: default}
- apiVersion: v1
  kind: ConfigMap
  metadata: {name: list-b, namespace: default}
`)
		h.write(t, "array.json", `[
 {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "array-a", "namespace": "default"}},
 {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "array-b", "namespace": "default"}}
]`)
		h.m.Sweep(ctx)
		got := strings.Join(appliedNames(h.applies(t)), ",")
		for _, want := range []string{"list-a", "list-b", "array-a", "array-b"} {
			if !strings.Contains(got, want) {
				t.Errorf("applied [%s], missing %s", got, want)
			}
		}
		if strings.Contains(got, "ignored-list-name") || strings.Contains(h.logs.String(), "unknown kind") {
			t.Errorf("the List itself was treated as an object: applied [%s]\n%s", got, h.logs.String())
		}
		// Settled: a second sweep applies nothing.
		h.m.Sweep(ctx)
		if again := h.applies(t); len(again) != 0 {
			t.Errorf("an unchanged List file was re-applied: %v", appliedNames(again))
		}
	})

	t.Run("a missing directory is not an error", func(t *testing.T) {
		h := newManifestHarness(t)
		if err := os.Remove(h.dir); err != nil {
			t.Fatal(err)
		}
		h.m.Sweep(ctx)
		if got := h.applies(t); len(got) != 0 {
			t.Errorf("a missing directory applied %v", appliedNames(got))
		}
		if strings.Contains(h.logs.String(), "level=WARN") || strings.Contains(h.logs.String(), "level=ERROR") {
			t.Errorf("a missing directory was reported as a problem:\n%s", h.logs.String())
		}
	})

	t.Run("errors are logged and never propagate; unsafe files are refused", func(t *testing.T) {
		h := newManifestHarness(t)
		h.write(t, "a-broken.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata: [unterminated\n")
		h.write(t, "b-fails.yaml", strings.ReplaceAll(manifestCM, "op-config", "rejected"))
		h.write(t, "c-foreign.yaml", strings.ReplaceAll(manifestCM, "op-config", "foreign"))
		h.foreign["c-foreign.yaml"] = true
		shared := h.write(t, "d-shared.yaml", strings.ReplaceAll(manifestCM, "op-config", "shared"))
		if err := os.Chmod(shared, 0o666); err != nil {
			t.Fatal(err)
		}
		h.write(t, "e-good.yaml", manifestCM)
		failApplyOf(h.dyn, "rejected", "apiserver unavailable")

		// Sweep has no error to return: the only observable outcome of a failure is
		// the log, and every good file still applies.
		h.m.Sweep(ctx)
		as := h.applies(t)
		names := strings.Join(appliedNames(as), ",")
		if !strings.Contains(names, "op-config") || strings.Contains(names, "foreign") || strings.Contains(names, "shared") {
			t.Errorf("applied [%s], want op-config applied and the foreign/shared files refused", names)
		}
		logs := h.logs.String()
		for _, want := range []string{"a-broken.yaml", "apiserver unavailable", "not root", "group- or other-writable"} {
			if !strings.Contains(logs, want) {
				t.Errorf("the log lacks %q:\n%s", want, logs)
			}
		}
		// The transient failure is retried on the next sweep; the settled files are not.
		h.m.Sweep(ctx)
		if got := appliedNames(h.applies(t)); len(got) != 1 || got[0] != "rejected" {
			t.Errorf("second sweep applied %v, want only the retry of [rejected]", got)
		}
	})

	t.Run("Run applies on start and on change, and stops with its context", func(t *testing.T) {
		h := newManifestHarness(t)
		h.m.interval = 50 * time.Millisecond
		h.write(t, "config.yaml", manifestCM)
		runCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { h.m.Run(runCtx); close(done) }()

		waitFor := func(what string, cond func() bool) {
			t.Helper()
			deadline := time.Now().Add(5 * time.Second)
			for !cond() {
				if time.Now().After(deadline) {
					t.Fatalf("timed out waiting for %s", what)
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		annotation := func() string {
			o, err := h.dyn.Tracker().Get(configMapGVR, "default", "op-config")
			if err != nil {
				return ""
			}
			u, ok := o.(*unstructured.Unstructured)
			if !ok {
				return ""
			}
			return u.GetAnnotations()[ManifestChecksumAnnotation]
		}
		waitFor("the start apply", func() bool { return annotation() == sumOf(manifestCM) })
		h.write(t, "config.yaml", manifestCMChanged)
		waitFor("the re-apply on change", func() bool { return annotation() == sumOf(manifestCMChanged) })

		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Run did not return after its context was cancelled")
		}
	})

	t.Run("the apply authenticates as the ServiceAccount, never the admin", func(t *testing.T) {
		var (
			mu    sync.Mutex
			auths []string
		)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			auths = append(auths, r.Header.Get("Authorization"))
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"op-config","namespace":"default"}}`))
		}))
		defer srv.Close()

		admin := fake.NewClientset()
		var tokenFor string
		admin.PrependReactor("create", "serviceaccounts", func(a k8stesting.Action) (bool, runtime.Object, error) {
			ca, ok := a.(k8stesting.CreateActionImpl)
			if !ok || ca.GetSubresource() != "token" {
				return false, nil, nil
			}
			tokenFor = ca.GetNamespace() + "/" + ca.Name
			return true, &authenticationv1.TokenRequest{Status: authenticationv1.TokenRequestStatus{
				Token:               "sa-token",
				ExpirationTimestamp: metav1.NewTime(time.Now().Add(time.Hour)),
			}}, nil
		})
		adminCfg := &rest.Config{Host: srv.URL, BearerToken: "admin-token", Username: "admin", Password: "admin"}
		cfg := manifestRESTConfig(adminCfg, &saTokenSource{admin: admin, namespace: "kube-system", name: "k3sm-manifests", now: time.Now})
		dyn, err := dynamic.NewForConfig(cfg)
		if err != nil {
			t.Fatal(err)
		}
		obj := unstructuredObj("v1", "ConfigMap", "default", "op-config")
		if _, err := dyn.Resource(configMapGVR).Namespace("default").Apply(ctx, "op-config", obj, metav1.ApplyOptions{FieldManager: ManifestFieldManager}); err != nil {
			t.Fatalf("apply through the manifest identity: %v", err)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(auths) == 0 {
			t.Fatal("no request reached the apiserver")
		}
		for _, a := range auths {
			if a != "Bearer sa-token" {
				t.Errorf("request authenticated as %q, want the ServiceAccount token", a)
			}
		}
		if tokenFor != "kube-system/k3sm-manifests" {
			t.Errorf("TokenRequest was for %q, want kube-system/k3sm-manifests", tokenFor)
		}
	})
}
