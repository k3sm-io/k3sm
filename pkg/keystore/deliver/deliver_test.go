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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"k3sm.io/k3sm/pkg/addons"
	"k3sm.io/k3sm/pkg/keystore"
)

// syncBuffer is a log sink safe for Run's goroutine and the test to share.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// fakeStore is a ValueSource over a map; it counts Current calls.
type fakeStore struct {
	mu      sync.Mutex
	entries map[string]fakeEntry
	reads   int
}

type fakeEntry struct {
	version uint64
	value   []byte
}

func (s *fakeStore) Current(_ context.Context, name string) (keystore.Version, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	e, ok := s.entries[name]
	if !ok {
		return keystore.Version{}, nil, keystore.ErrNotFound
	}
	// The reconciler clears the value it is given, as the real store's
	// caller owns it, so each call returns a fresh copy.
	// The fingerprint stands for the real store's: derived from the value.
	sum := sha256.Sum256(e.value)
	return keystore.Version{Name: name, Version: e.version, Kind: keystore.KindOpaque, Fingerprint: hex.EncodeToString(sum[:8])}, bytes.Clone(e.value), nil
}

func (s *fakeStore) set(name string, version uint64, value []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[name] = fakeEntry{version, value}
}

// harness is one reconciler over a temp data root, a fake clientset that
// records every call, and a fake store. Its check accepts the test user as the
// owner in place of root (a unit test cannot make a root-owned file), keeping
// the real mode check; TestDeclarationRootOwned also runs the real check.
type harness struct {
	dir    string
	path   string
	client *fake.Clientset
	store  *fakeStore
	logs   *syncBuffer
	r      *Reconciler
}

func newHarness(t *testing.T, encryptionOn, allowPlaintext bool, objs ...runtime.Object) *harness {
	t.Helper()
	h := &harness{
		dir:    t.TempDir(),
		client: fake.NewClientset(objs...),
		store:  &fakeStore{entries: map[string]fakeEntry{}},
		logs:   &syncBuffer{},
	}
	h.path = filepath.Join(h.dir, FileName)
	// The apiserver assigns a UID on create; the fake does not, so this
	// reactor stands in for it and lets the tracker store the object.
	var uids int
	h.client.PrependReactor("create", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if s, ok := a.(k8stesting.CreateAction).GetObject().(*corev1.Secret); ok && s.UID == "" {
			uids++
			s.UID = types.UID(fmt.Sprintf("uid-%d", uids))
		}
		return false, nil, nil
	})
	h.r = h.reconciler(encryptionOn, allowPlaintext)
	return h
}

// reconciler builds another reconciler over the harness's file, client and
// store, as a server restart would.
func (h *harness) reconciler(encryptionOn, allowPlaintext bool) *Reconciler {
	r := New(Config{
		Path:           h.path,
		Client:         h.client,
		Store:          h.store,
		EncryptionOn:   encryptionOn,
		AllowPlaintext: allowPlaintext,
		Logger:         slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	r.check = testCheck
	// Non-root, a test cannot hand the state file to root.
	r.chown = func(*os.File) error { return nil }
	return r
}

// own records obj as created by the reconciler, as a create would have.
func (h *harness) own(t *testing.T, objs ...*corev1.Secret) {
	t.Helper()
	st, err := ReadState(filepath.Join(h.dir, StateFileName), OpenNoFollow, testCheck)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range objs {
		st.Set(o.Namespace, o.Name, string(o.UID))
	}
	if err := WriteState(filepath.Join(h.dir, StateFileName), st, func(*os.File) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

// testCheck stands the test user in for root.
func testCheck(fi fs.FileInfo) error {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) == os.Geteuid() {
		return addons.NotShared(fi)
	}
	return addons.RootOwnedNotShared(fi)
}

func (h *harness) declare(t *testing.T, targets ...Target) {
	t.Helper()
	h.writeRaw(t, mustMarshal(t, Declaration{Version: SchemaVersion, Targets: targets}), FileMode)
}

func mustMarshal(t *testing.T, d Declaration) []byte {
	t.Helper()
	b, err := d.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (h *harness) writeRaw(t *testing.T, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(h.path, data, mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile honours the umask; pin the mode the reconciler judges.
	if err := os.Chmod(h.path, mode); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) secret(t *testing.T, ns, name string) *corev1.Secret {
	t.Helper()
	s, err := h.client.CoreV1().Secrets(ns).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get %s/%s: %v", ns, name, err)
	}
	return s
}

// verbs is every recorded call as verb/resource, after the harness's own
// reads are dropped.
func (h *harness) verbs() []string {
	var out []string
	for _, a := range h.client.Actions() {
		out = append(out, a.GetVerb()+"/"+a.GetResource().Resource)
	}
	return out
}

// assertOnlyGetCreateUpdateSecrets fails on any recorded call that is not a
// get, create or update of a Secret: no list, no watch, no delete, no other
// kind.
func (h *harness) assertOnlyGetCreateUpdateSecrets(t *testing.T) {
	t.Helper()
	for _, a := range h.client.Actions() {
		switch {
		case a.GetResource().Resource != "secrets":
			t.Errorf("touched another kind: %s %s", a.GetVerb(), a.GetResource().Resource)
		case a.GetVerb() != "get" && a.GetVerb() != "create" && a.GetVerb() != "update":
			t.Errorf("made a %s call on secrets; only get, create and update are allowed", a.GetVerb())
		}
	}
}

func secretObj(ns, name string, labels map[string]string, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: labels},
		Type:       corev1.SecretTypeOpaque,
		Data:       data,
	}
}

// TestDeliveryRefusedWhileEncryptionOff: with encryption off and no override,
// every target is refused before any apiserver call or store read, and the
// refusal is logged at Warn once per target however many sweeps run (G18).
func TestDeliveryRefusedWhileEncryptionOff(t *testing.T) {
	h := newHarness(t, false, false)
	h.store.set("api-token", 1, []byte("tok"))
	h.store.set("signer", 1, []byte("sig"))
	h.declare(t, Target{Name: "api-token", Namespace: "payments"}, Target{Name: "signer", Namespace: "payments"})
	ctx := context.Background()
	for range 3 {
		h.r.Sweep(ctx)
	}
	if got := h.client.Actions(); len(got) != 0 {
		t.Fatalf("encryption off: the apiserver saw %v, want no call", h.verbs())
	}
	if h.store.reads != 0 {
		t.Fatalf("encryption off: the store was read %d times, want 0", h.store.reads)
	}
	logs := h.logs.String()
	if n := strings.Count(logs, "level=WARN msg=\"keystore delivery: target refused"); n != 2 {
		t.Fatalf("got %d Warn refusals over 3 sweeps of 2 targets, want 2 (once per target)\n%s", n, logs)
	}
	if !strings.Contains(logs, "--"+AllowPlaintextFlag) {
		t.Errorf("the refusal does not name the override flag\n%s", logs)
	}
}

// TestDeliveryOverrideAllowsPlaintext: with encryption off, the override flag
// set at start lets delivery create the Secret (G18).
func TestDeliveryOverrideAllowsPlaintext(t *testing.T) {
	h := newHarness(t, false, true)
	h.store.set("api-token", 2, []byte("tok"))
	h.declare(t, Target{Name: "api-token", Namespace: "payments"})
	h.r.Sweep(context.Background())
	s := h.secret(t, "payments", "api-token")
	if got := string(s.Data[DefaultDataKey]); got != "tok" {
		t.Fatalf("data[%s] = %q, want %q", DefaultDataKey, got, "tok")
	}
	if s.Annotations[VersionAnnotation] != "2" {
		t.Fatalf("annotation %s = %q, want 2", VersionAnnotation, s.Annotations[VersionAnnotation])
	}
}

// TestDeliveredTargetStaysWhenOverrideRemoved: a target delivered under the
// override is left as it is by a server restarted without it: no update, no
// delete, the Secret still there (G18).
func TestDeliveredTargetStaysWhenOverrideRemoved(t *testing.T) {
	h := newHarness(t, false, true)
	h.store.set("api-token", 1, []byte("tok"))
	h.declare(t, Target{Name: "api-token", Namespace: "payments"})
	ctx := context.Background()
	h.r.Sweep(ctx)
	h.client.ClearActions()

	h.store.set("api-token", 2, []byte("tok2"))
	restarted := h.reconciler(false, false)
	restarted.Sweep(ctx)
	if got := h.client.Actions(); len(got) != 0 {
		t.Fatalf("after the override was removed the apiserver saw %v, want no call", h.verbs())
	}
	if got := string(h.secret(t, "payments", "api-token").Data[DefaultDataKey]); got != "tok" {
		t.Fatalf("the delivered Secret changed to %q", got)
	}
}

// TestDeclarationRootOwned: a declaration that is not root-owned, is group-
// or other-writable, is a symlink, is not a regular file, is oversized, or
// does not parse strictly (unknown field, wrong version, trailing data, too
// many targets) is refused whole: nothing reaches the apiserver, and the
// refusal is logged once per file state (G19).
func TestDeclarationRootOwned(t *testing.T) {
	valid := `{"version":1,"targets":[{"name":"api-token","namespace":"payments"}]}`
	many := func() string {
		var b strings.Builder
		b.WriteString(`{"version":1,"targets":[`)
		for i := range MaxTargets + 1 {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `{"name":"e%d","namespace":"payments"}`, i)
		}
		b.WriteString("]}")
		return b.String()
	}()
	cases := []struct {
		name  string
		setup func(t *testing.T, h *harness)
		// realCheck runs the production check, the manifest directory's.
		realCheck bool
		reason    string
	}{
		{"not owned by root", func(t *testing.T, h *harness) {
			h.writeRaw(t, []byte(valid), 0o644)
			if os.Geteuid() == 0 { // as root, hand the file to another owner
				if err := os.Chown(h.path, 1, 1); err != nil {
					t.Fatal(err)
				}
			}
		}, true, "not root"},
		{"group-writable", func(t *testing.T, h *harness) { h.writeRaw(t, []byte(valid), 0o664) }, false, "group- or other-writable"},
		{"other-writable", func(t *testing.T, h *harness) { h.writeRaw(t, []byte(valid), 0o646) }, false, "group- or other-writable"},
		{"symlink", func(t *testing.T, h *harness) {
			target := filepath.Join(h.dir, "real.json")
			if err := os.WriteFile(target, []byte(valid), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, h.path); err != nil {
				t.Fatal(err)
			}
		}, false, "a symlink"},
		{"directory", func(t *testing.T, h *harness) {
			if err := os.Mkdir(h.path, 0o755); err != nil {
				t.Fatal(err)
			}
		}, false, "not a regular file"},
		{"fifo", func(t *testing.T, h *harness) {
			if err := syscall.Mkfifo(h.path, 0o644); err != nil {
				t.Fatal(err)
			}
		}, false, "not a regular file"},
		{"oversize", func(t *testing.T, h *harness) {
			pad := strings.Repeat(" ", MaxFileBytes)
			h.writeRaw(t, []byte(valid+pad), 0o644)
		}, false, "larger than"},
		{"unknown field", func(t *testing.T, h *harness) {
			h.writeRaw(t, []byte(`{"version":1,"targets":[{"name":"api-token","namespace":"payments","kind":"Role"}]}`), 0o644)
		}, false, "unknown field"},
		{"unknown top-level field", func(t *testing.T, h *harness) {
			h.writeRaw(t, []byte(`{"version":1,"targets":[],"extra":true}`), 0o644)
		}, false, "unknown field"},
		{"wrong version", func(t *testing.T, h *harness) {
			h.writeRaw(t, []byte(`{"version":2,"targets":[{"name":"api-token","namespace":"payments"}]}`), 0o644)
		}, false, "version 2"},
		{"trailing data", func(t *testing.T, h *harness) { h.writeRaw(t, []byte(valid+valid), 0o644) }, false, "trailing data"},
		{"too many targets", func(t *testing.T, h *harness) { h.writeRaw(t, []byte(many), 0o644) }, false, "the limit is"},
		{"invalid namespace", func(t *testing.T, h *harness) {
			h.writeRaw(t, []byte(`{"version":1,"targets":[{"name":"api-token","namespace":"Bad_NS"}]}`), 0o644)
		}, false, "namespace is not a valid"},
		{"duplicate Secret", func(t *testing.T, h *harness) {
			h.writeRaw(t, []byte(`{"version":1,"targets":[{"name":"a","namespace":"p","secretName":"s"},{"name":"b","namespace":"p","secretName":"s"}]}`), 0o644)
		}, false, "the same Secret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, true, false)
			h.store.set("api-token", 1, []byte("tok"))
			if tc.realCheck {
				h.r.check = RootCheck
			}
			tc.setup(t, h)
			ctx := context.Background()
			h.r.Sweep(ctx)
			h.r.Sweep(ctx)
			if got := h.client.Actions(); len(got) != 0 {
				t.Fatalf("a refused declaration reached the apiserver: %v", h.verbs())
			}
			logs := h.logs.String()
			if n := strings.Count(logs, `msg="keystore delivery: declaration refused`); n != 1 {
				t.Fatalf("logged %d refusals over two sweeps, want 1\n%s", n, logs)
			}
			if !strings.Contains(logs, tc.reason) {
				t.Fatalf("the refusal does not say %q\n%s", tc.reason, logs)
			}
		})
	}
}

// TestDeclarationOpenedWithNoFollow: the production opener refuses a symlink
// itself (O_NOFOLLOW), and the check judges the descriptor the opener
// returned, not the path (G19).
func TestDeclarationOpenedWithNoFollow(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.json")
	if err := os.WriteFile(real, []byte(`{"version":1,"targets":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, FileName)
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenNoFollow(link); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("OpenNoFollow on a symlink: %v, want ELOOP", err)
	}
	// An opener that hands back another file than the path names: the check
	// sees that file's mode, so the group-writable file it opened is refused.
	shared := filepath.Join(dir, "shared.json")
	if err := os.WriteFile(shared, []byte(`{"version":1,"targets":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o664); err != nil {
		t.Fatal(err)
	}
	open := func(string) (*os.File, error) { return os.Open(shared) }
	if _, _, _, err := Read(real, open, testCheck); !errors.Is(err, ErrRefused) {
		t.Fatalf("Read judged the path, not the opened file: %v", err)
	}
}

// TestReconcilerTouchesOnlyLabelledSecrets: an unlabelled Secret and one
// labelled for another entry are left byte for byte as they were; a Secret
// labelled for this entry is updated, an absent one created; and the
// recorded calls are only gets, creates and updates of Secrets: no list, no
// delete, no other kind (G20).
func TestReconcilerTouchesOnlyLabelledSecrets(t *testing.T) {
	plain := secretObj("payments", "plain", nil, map[string][]byte{"value": []byte("operator's")})
	foreign := secretObj("payments", "foreign", map[string]string{LabelKey: "someone-else"}, map[string][]byte{"value": []byte("theirs")})
	ours := secretObj("payments", "ours", map[string]string{LabelKey: "api-token"}, map[string][]byte{"value": []byte("old")})
	ours.Annotations = map[string]string{VersionAnnotation: "1"}
	ours.UID = "ours-1"
	h := newHarness(t, true, false, plain, foreign, ours)
	h.own(t, ours)
	h.store.set("api-token", 2, []byte("new"))
	h.declare(t,
		Target{Name: "api-token", Namespace: "payments", SecretName: "plain"},
		Target{Name: "api-token", Namespace: "payments", SecretName: "foreign"},
		Target{Name: "api-token", Namespace: "payments", SecretName: "ours"},
		Target{Name: "api-token", Namespace: "payments", SecretName: "fresh", DataKey: "token"},
	)
	ctx := context.Background()
	h.r.Sweep(ctx)

	if got := h.secret(t, "payments", "plain"); string(got.Data["value"]) != "operator's" || len(got.Labels) != 0 || len(got.Annotations) != 0 {
		t.Errorf("the unlabelled Secret was changed: %+v", got)
	}
	if got := h.secret(t, "payments", "foreign"); string(got.Data["value"]) != "theirs" || got.Labels[LabelKey] != "someone-else" || len(got.Annotations) != 0 {
		t.Errorf("the foreign Secret was changed: %+v", got)
	}
	if got := h.secret(t, "payments", "ours"); string(got.Data["value"]) != "new" || got.Annotations[VersionAnnotation] != "2" {
		t.Errorf("the labelled Secret was not re-delivered: %+v", got)
	}
	fresh := h.secret(t, "payments", "fresh")
	if fresh.Type != corev1.SecretTypeOpaque || fresh.Labels[LabelKey] != "api-token" ||
		fresh.Annotations[VersionAnnotation] != "2" || string(fresh.Data["token"]) != "new" || len(fresh.Data) != 1 {
		t.Errorf("the created Secret is not the labelled Opaque one: %+v", fresh)
	}
	h.assertOnlyGetCreateUpdateSecrets(t)
	var creates, updates int
	for _, v := range h.verbs() {
		switch v {
		case "create/secrets":
			creates++
		case "update/secrets":
			updates++
		}
	}
	if creates != 1 || updates != 1 {
		t.Errorf("got %d creates and %d updates, want 1 and 1: %v", creates, updates, h.verbs())
	}
	logs := h.logs.String()
	for _, want := range []string{"secret=plain", "has no " + LabelKey + " label", "secret=foreign", "names another entry"} {
		if !strings.Contains(logs, want) {
			t.Errorf("the skip is not logged with %q\n%s", want, logs)
		}
	}

	// A second sweep at the same version only reads.
	h.client.ClearActions()
	h.r.Sweep(ctx)
	for _, v := range h.verbs() {
		if v != "get/secrets" {
			t.Errorf("an unchanged sweep made %s", v)
		}
	}
}

// TestReconcilerRedeliversOnRotation: a new current version re-applies the
// labelled Secret's data and bumps its annotation (G20).
func TestReconcilerRedeliversOnRotation(t *testing.T) {
	h := newHarness(t, true, false)
	h.store.set("api-token", 1, []byte("one"))
	h.declare(t, Target{Name: "api-token", Namespace: "payments"})
	ctx := context.Background()
	h.r.Sweep(ctx)
	h.store.set("api-token", 2, []byte("two"))
	h.r.Sweep(ctx)
	s := h.secret(t, "payments", "api-token")
	if string(s.Data[DefaultDataKey]) != "two" || s.Annotations[VersionAnnotation] != "2" {
		t.Fatalf("not re-delivered after a rotation: %+v", s)
	}
	h.assertOnlyGetCreateUpdateSecrets(t)
}

// TestReconcilerSkipsLabelledNonOpaque: a Secret labelled for the entry but
// of another type is left alone, since a Secret's type cannot change (G20).
func TestReconcilerSkipsLabelledNonOpaque(t *testing.T) {
	tls := secretObj("payments", "api-token", map[string]string{LabelKey: "api-token"}, map[string][]byte{"tls.crt": []byte("c"), "tls.key": []byte("k")})
	tls.Type = corev1.SecretTypeTLS
	tls.UID = "tls-1"
	h := newHarness(t, true, false, tls)
	h.own(t, tls)
	h.store.set("api-token", 1, []byte("one"))
	h.declare(t, Target{Name: "api-token", Namespace: "payments"})
	h.r.Sweep(context.Background())
	for _, v := range h.verbs() {
		if v != "get/secrets" {
			t.Errorf("a labelled non-Opaque Secret drew %s", v)
		}
	}
}

// TestReconcilerContinuesAfterTargetFailure: a target whose Get fails, and one
// whose entry is missing, are logged, and the next target is still delivered.
func TestReconcilerContinuesAfterTargetFailure(t *testing.T) {
	h := newHarness(t, true, false)
	h.client.PrependReactor("get", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetNamespace() == "broken" {
			return true, nil, apierrors.NewInternalError(errors.New("boom"))
		}
		return false, nil, nil
	})
	h.store.set("api-token", 1, []byte("tok"))
	h.declare(t,
		Target{Name: "api-token", Namespace: "broken"},
		Target{Name: "missing", Namespace: "payments"},
		Target{Name: "api-token", Namespace: "payments"},
	)
	h.r.Sweep(context.Background())
	if got := string(h.secret(t, "payments", "api-token").Data[DefaultDataKey]); got != "tok" {
		t.Fatalf("the healthy target was not delivered after a failing one: %q", got)
	}
	logs := h.logs.String()
	if !strings.Contains(logs, "cannot read the Secret") || !strings.Contains(logs, "cannot read the entry") {
		t.Fatalf("a per-target failure is not logged\n%s", logs)
	}
}

// TestReconcilerEd25519RawBytes: an Ed25519 entry is delivered as its stored
// seed bytes exactly, with no PEM wrapping.
func TestReconcilerEd25519RawBytes(t *testing.T) {
	h := newHarness(t, true, false)
	seed := bytes.Repeat([]byte{0x42}, 32)
	h.store.set("signer", 1, seed)
	h.declare(t, Target{Name: "signer", Namespace: "payments", DataKey: "private.key"})
	h.r.Sweep(context.Background())
	if got := h.secret(t, "payments", "signer").Data["private.key"]; !bytes.Equal(got, seed) {
		t.Fatalf("data = %x, want the 32 stored bytes %x", got, seed)
	}
}

// TestRunSweepsOnStartChangeAndInterval: Run sweeps once at start, once after
// a change once the debounce fires, and once per interval tick, and returns
// when ctx is done. The clock is the injected ticker and debounce channels.
func TestRunSweepsOnStartChangeAndInterval(t *testing.T) {
	h := newHarness(t, true, false)
	h.store.set("api-token", 1, []byte("tok"))
	h.declare(t, Target{Name: "api-token", Namespace: "payments"})
	ticks := make(chan time.Time)
	changes := make(chan struct{})
	debounce := make(chan time.Time)
	var debounced []time.Duration
	h.r.newTicker = func(d time.Duration) (<-chan time.Time, func()) {
		if d != addons.ManifestSweepInterval {
			t.Errorf("interval %v, want addons.ManifestSweepInterval", d)
		}
		return ticks, func() {}
	}
	h.r.after = func(d time.Duration) <-chan time.Time { debounced = append(debounced, d); return debounce }
	closed := false
	h.r.watch = func(dir, name string) (<-chan struct{}, func(), error) {
		if dir != h.dir || name != FileName {
			t.Errorf("watch(%q, %q), want the declaration's directory and name", dir, name)
		}
		return changes, func() { closed = true }, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); h.r.Run(ctx) }()

	// Each send on an unbuffered channel completes only once Run is back in
	// its select, so the sweep the previous send caused has finished.
	changes <- struct{}{}
	debounce <- time.Time{}
	ticks <- time.Time{}
	ticks <- time.Time{}
	// This change only arms the debounce; its send completing means the
	// second tick's sweep has finished.
	changes <- struct{}{}
	cancel()
	<-done

	var gets int
	for _, v := range h.verbs() {
		if v == "get/secrets" {
			gets++
		}
	}
	if gets != 4 {
		t.Fatalf("got %d sweeps (one Get each), want 4: start, debounced change, two ticks", gets)
	}
	if len(debounced) != 2 || debounced[0] != changeDebounce {
		t.Fatalf("debounce armed %v, want twice for %v", debounced, changeDebounce)
	}
	if !closed {
		t.Fatal("the watch was not closed when Run returned")
	}
}

// TestRunWithoutWatchUsesInterval: a watch that cannot start leaves the
// interval sweep.
func TestRunWithoutWatchUsesInterval(t *testing.T) {
	h := newHarness(t, true, false)
	h.store.set("api-token", 1, []byte("tok"))
	h.declare(t, Target{Name: "api-token", Namespace: "payments"})
	ticks := make(chan time.Time)
	h.r.newTicker = func(time.Duration) (<-chan time.Time, func()) { return ticks, func() {} }
	h.r.watch = func(string, string) (<-chan struct{}, func(), error) { return nil, nil, errors.New("no kqueue") }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); h.r.Run(ctx) }()
	ticks <- time.Time{}
	ticks <- time.Time{} // completes once the first tick's sweep has finished
	cancel()
	<-done
	if n := len(h.verbs()); n < 2 {
		t.Fatalf("got %d calls, want the start sweep and the tick's", n)
	}
	if !strings.Contains(h.logs.String(), "no filesystem watch") {
		t.Fatalf("the missing watch is not logged\n%s", h.logs.String())
	}
}

// TestDeclarationParseDefaults: a target without secretName or dataKey gets
// the entry name and "value"; a valid declaration round-trips through
// Marshal; Upsert replaces by Secret and Remove withdraws by entry and
// namespace.
func TestDeclarationParseDefaults(t *testing.T) {
	d, err := Parse([]byte(`{"version":1,"targets":[{"name":"signer-key","namespace":"payments"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Targets[0]; got.Secret() != "signer-key" || got.Key() != "value" {
		t.Fatalf("defaults: secret %q key %q", got.Secret(), got.Key())
	}
	if d.Upsert(Target{Name: "other", Namespace: "payments", SecretName: "signer-key"}) != true {
		t.Fatal("Upsert did not replace the target naming the same Secret")
	}
	d.Upsert(Target{Name: "signer-key", Namespace: "ops"})
	b, err := d.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(b)
	if err != nil {
		t.Fatalf("Marshal's output does not parse: %v\n%s", err, b)
	}
	if n := back.Remove("signer-key", "ops"); n != 1 || len(back.Targets) != 1 {
		t.Fatalf("Remove removed %d, left %d", n, len(back.Targets))
	}
	if _, err := Parse([]byte(`{"version":1,"targets":[{"name":"` + strings.Repeat("a", 64) + `","namespace":"p"}]}`)); err == nil {
		t.Fatal("an entry name too long for a label value parsed")
	}
}

// TestWriteAtomic: Write leaves exactly the declaration at FileMode, passes
// the temp file to chown before it is renamed, and leaves no temp file
// behind on success or failure.
func TestWriteAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	var chowned string
	d := Declaration{Version: SchemaVersion, Targets: []Target{{Name: "a", Namespace: "p"}}}
	if err := Write(path, d, func(f *os.File) error { chowned = f.Name(); return nil }); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode() != FileMode {
		t.Fatalf("mode %v, want %v", fi.Mode(), FileMode)
	}
	if filepath.Dir(chowned) != dir || chowned == path {
		t.Fatalf("chown saw %q, want a temp file beside the declaration", chowned)
	}
	if err := Write(path, d, func(*os.File) error { return errors.New("EPERM") }); err == nil {
		t.Fatal("a failed chown did not fail the write")
	}
	names, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0].Name() != FileName {
		t.Fatalf("directory holds %v, want only %s", names, FileName)
	}
}

// TestReconcilerRedeliversAfterRmPut: an entry deleted and put back holds a
// new value at version 1 again; the version alone cannot tell, so the Secret
// must still be re-delivered (G20).
func TestReconcilerRedeliversAfterRmPut(t *testing.T) {
	h := newHarness(t, true, false)
	h.store.set("api-token", 1, []byte("one"))
	h.declare(t, Target{Name: "api-token", Namespace: "payments"})
	ctx := context.Background()
	h.r.Sweep(ctx)
	h.store.set("api-token", 1, []byte("replaced"))
	h.r.Sweep(ctx)
	if got := string(h.secret(t, "payments", "api-token").Data[DefaultDataKey]); got != "replaced" {
		t.Fatalf("after rm and put at version 1 the Secret still holds %q", got)
	}
	h.assertOnlyGetCreateUpdateSecrets(t)
}

// TestReconcilerReappliesChangedDataKey: a target whose dataKey changes is
// re-applied at the same version, and the stale key leaves data (G20).
func TestReconcilerReappliesChangedDataKey(t *testing.T) {
	h := newHarness(t, true, false)
	h.store.set("api-token", 1, []byte("tok"))
	h.declare(t, Target{Name: "api-token", Namespace: "payments", DataKey: "old"})
	ctx := context.Background()
	h.r.Sweep(ctx)
	h.declare(t, Target{Name: "api-token", Namespace: "payments", DataKey: "new"})
	h.r.Sweep(ctx)
	got := h.secret(t, "payments", "api-token").Data
	if len(got) != 1 || string(got["new"]) != "tok" {
		t.Fatalf("data after a dataKey change = %q, want only new=tok", got)
	}
	h.assertOnlyGetCreateUpdateSecrets(t)
}

// TestLockRefusesUntrustedFile: the writers' lock is refused when it is a
// symlink, not a regular file, or shared-writable, judged on its descriptor.
func TestLockRefusesUntrustedFile(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, path string)
	}{
		{"symlink", func(t *testing.T, path string) {
			target := filepath.Join(filepath.Dir(path), "elsewhere")
			if err := os.WriteFile(target, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}},
		{"directory", func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"group-writable", func(t *testing.T, path string) {
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o620); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), LockName)
			tc.setup(t, path)
			if unlock, err := Lock(context.Background(), path, testCheck, nil); !errors.Is(err, ErrRefused) {
				if unlock != nil {
					unlock()
				}
				t.Fatalf("Lock: %v, want ErrRefused", err)
			}
		})
	}
}

// TestLockBoundedWait: a lock another writer holds is retried a bounded
// number of times, then refused with ErrLockBusy; once released it is taken.
func TestLockBoundedWait(t *testing.T) {
	path := filepath.Join(t.TempDir(), LockName)
	unlock, err := Lock(context.Background(), path, testCheck, nil)
	if err != nil {
		t.Fatal(err)
	}
	waits := 0
	ready := make(chan time.Time)
	close(ready)
	busy := func() <-chan time.Time { waits++; return ready }
	if _, err := Lock(context.Background(), path, testCheck, busy); !errors.Is(err, ErrLockBusy) {
		t.Fatalf("second Lock while held: %v, want ErrLockBusy", err)
	}
	if waits != lockAttempts {
		t.Fatalf("waited %d times, want %d", waits, lockAttempts)
	}
	unlock()
	again, err := Lock(context.Background(), path, testCheck, busy)
	if err != nil {
		t.Fatalf("Lock after release: %v", err)
	}
	again()
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode() != lockMode {
		t.Fatalf("lock file mode %v (%v), want %v", fi.Mode(), err, lockMode)
	}
}

// updates counts the recorded updates of Secrets.
func (h *harness) updates() int {
	n := 0
	for _, v := range h.verbs() {
		if v == "update/secrets" {
			n++
		}
	}
	return n
}

// TestReconcilerNeverWritesTenantPrecreated: a namespace writer who creates
// the target Secret first, with the ownership label, does not get the value
// written into it: the label is forgeable, and no UID was recorded for it
// (G20).
func TestReconcilerNeverWritesTenantPrecreated(t *testing.T) {
	planted := secretObj("payments", "api-token", map[string]string{LabelKey: "api-token"}, map[string][]byte{"value": []byte("tenant's")})
	planted.UID = "tenant-1"
	h := newHarness(t, true, false, planted)
	h.store.set("api-token", 1, []byte("the-stored-value"))
	h.declare(t, Target{Name: "api-token", Namespace: "payments"})
	ctx := context.Background()
	h.r.Sweep(ctx)
	h.r.Sweep(ctx)
	if n := h.updates(); n != 0 {
		t.Fatalf("the tenant's pre-created Secret drew %d updates: %v", n, h.verbs())
	}
	if got := h.secret(t, "payments", "api-token"); string(got.Data["value"]) != "tenant's" {
		t.Fatalf("the tenant's Secret now holds %q", got.Data["value"])
	}
	logs := h.logs.String()
	if !strings.Contains(logs, "not created by this server") || strings.Count(logs, "not created by this server") != 1 {
		t.Fatalf("the skip is not logged once with its reason\n%s", logs)
	}
}

// TestReconcilerDoesNotAdoptRecreated: a Secret the reconciler created, then
// deleted and recreated by someone else under the same name and label, has a
// new UID and is not adopted (G20).
func TestReconcilerDoesNotAdoptRecreated(t *testing.T) {
	h := newHarness(t, true, false)
	h.store.set("api-token", 1, []byte("one"))
	h.declare(t, Target{Name: "api-token", Namespace: "payments"})
	ctx := context.Background()
	h.r.Sweep(ctx)
	if err := h.client.CoreV1().Secrets("payments").Delete(ctx, "api-token", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	again := secretObj("payments", "api-token", map[string]string{LabelKey: "api-token"}, map[string][]byte{"value": []byte("tenant's")})
	again.UID = "tenant-2"
	if _, err := h.client.CoreV1().Secrets("payments").Create(ctx, again, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	h.client.ClearActions()
	h.store.set("api-token", 2, []byte("two"))
	h.r.Sweep(ctx)
	if n := h.updates(); n != 0 {
		t.Fatalf("the recreated Secret drew %d updates: %v", n, h.verbs())
	}
	if got := h.secret(t, "payments", "api-token"); string(got.Data["value"]) != "tenant's" {
		t.Fatalf("the recreated Secret now holds %q", got.Data["value"])
	}
	if !strings.Contains(h.logs.String(), "not created by this server") {
		t.Fatalf("the skip is not logged\n%s", h.logs.String())
	}
}

// TestReconcilerRecordsCreatedUID: a create records the Secret's UID in the
// state file beside the declaration, 0600, and the entry is dropped once the
// target leaves the declaration (G20).
func TestReconcilerRecordsCreatedUID(t *testing.T) {
	h := newHarness(t, true, false)
	h.store.set("api-token", 1, []byte("one"))
	h.declare(t, Target{Name: "api-token", Namespace: "payments"})
	ctx := context.Background()
	h.r.Sweep(ctx)
	statePath := filepath.Join(h.dir, "keystore-delivery-state.json")
	fi, err := os.Lstat(statePath)
	if err != nil {
		t.Fatalf("no state file after a create: %v", err)
	}
	if fi.Mode() != 0o600 {
		t.Fatalf("state file mode %v, want 0600", fi.Mode())
	}
	b, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	uid := string(h.secret(t, "payments", "api-token").UID)
	if uid == "" || !strings.Contains(string(b), `"uid": "`+uid+`"`) {
		t.Fatalf("the state file does not record the created UID %q:\n%s", uid, b)
	}
	h.declare(t)
	h.r.Sweep(ctx)
	if b, err = os.ReadFile(statePath); err != nil || strings.Contains(string(b), uid) {
		t.Fatalf("the withdrawn target's UID is still recorded (%v):\n%s", err, b)
	}
}

// TestReconcilerReappliesDrift: a Secret whose data was edited with the
// annotations left as they were is re-applied, and the drift is logged
// without the value (G20).
func TestReconcilerReappliesDrift(t *testing.T) {
	h := newHarness(t, true, false)
	h.store.set("api-token", 1, []byte("the-stored-value"))
	h.declare(t, Target{Name: "api-token", Namespace: "payments"})
	ctx := context.Background()
	h.r.Sweep(ctx)
	edited := h.secret(t, "payments", "api-token")
	edited.Data[DefaultDataKey] = []byte("edited-by-hand")
	if _, err := h.client.CoreV1().Secrets("payments").Update(ctx, edited, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	h.r.Sweep(ctx)
	if got := string(h.secret(t, "payments", "api-token").Data[DefaultDataKey]); got != "the-stored-value" {
		t.Fatalf("drifted data was not re-applied: %q", got)
	}
	logs := h.logs.String()
	if !strings.Contains(logs, "drift") {
		t.Fatalf("the drift is not logged\n%s", logs)
	}
	for _, v := range []string{"the-stored-value", "edited-by-hand"} {
		if strings.Contains(logs, v) {
			t.Fatalf("the log carries a value %q\n%s", v, logs)
		}
	}
}

// TestReconcilerImmutableOwned: an immutable Secret the reconciler owns
// cannot be updated, so it is not, and the reason is logged at Warn once per
// state change, telling the operator to delete it (G20).
func TestReconcilerImmutableOwned(t *testing.T) {
	h := newHarness(t, true, false)
	h.store.set("api-token", 1, []byte("one"))
	h.declare(t, Target{Name: "api-token", Namespace: "payments"})
	ctx := context.Background()
	h.r.Sweep(ctx)
	s := h.secret(t, "payments", "api-token")
	yes := true
	s.Immutable = &yes
	if _, err := h.client.CoreV1().Secrets("payments").Update(ctx, s, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	h.client.ClearActions()
	h.store.set("api-token", 2, []byte("two"))
	h.r.Sweep(ctx)
	h.r.Sweep(ctx)
	if n := h.updates(); n != 0 {
		t.Fatalf("an immutable Secret drew %d updates: %v", n, h.verbs())
	}
	logs := h.logs.String()
	if n := strings.Count(logs, `level=WARN msg="keystore delivery: Secret is immutable`); n != 1 {
		t.Fatalf("logged the immutable Secret %d times over two sweeps, want once at Warn\n%s", n, logs)
	}
	if !strings.Contains(logs, "delete it") {
		t.Fatalf("the warning does not tell the operator to delete it\n%s", logs)
	}
}

// TestNewDefaultsBindRoot: New's own seams, untouched, refuse what
// production must: a declaration the test user owns is refused before any
// apiserver call, a symlink is not followed, and a new state file is handed
// to root or the hand-over fails (G19).
func TestNewDefaultsBindRoot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	if err := os.WriteFile(path, []byte(`{"version":1,"targets":[{"name":"api-token","namespace":"payments"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(path, 1, 1); err != nil {
			t.Fatal(err)
		}
	}
	client := fake.NewClientset()
	logs := &syncBuffer{}
	store := &fakeStore{entries: map[string]fakeEntry{}}
	store.set("api-token", 1, []byte("tok"))
	r := New(Config{Path: path, Client: client, Store: store, EncryptionOn: true,
		Logger: slog.New(slog.NewTextHandler(logs, nil))})
	r.Sweep(context.Background())
	if n := len(client.Actions()); n != 0 {
		t.Fatalf("New's default check let a non-root declaration through: %d apiserver calls", n)
	}
	if !strings.Contains(logs.String(), "not root") {
		t.Fatalf("the refusal does not say the file is not root's\n%s", logs.String())
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if f, err := r.open(link); !errors.Is(err, syscall.ELOOP) {
		if f != nil {
			_ = f.Close() // opened by mistake; read-only
		}
		t.Fatalf("New's default opener followed a symlink: %v", err)
	}

	f, err := os.CreateTemp(dir, "state")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }() // nothing written
	cerr := r.chown(f)
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || (cerr == nil && st.Uid != 0) {
		t.Fatalf("New's default chown succeeded without making the file root's (%v)", cerr)
	}
}
