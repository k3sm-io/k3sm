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
	"encoding/base64"
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

	"github.com/fsnotify/fsnotify"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
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

// fakeStore is a ValueSource over a map; it counts Current calls. absentErr,
// when set, is Absent's answer, standing in for a store that cannot confirm
// an absence (a missing entries' directory); identity is the entries'
// directory's identity Identity and Absent answer.
type fakeStore struct {
	mu        sync.Mutex
	entries   map[string]fakeEntry
	reads     int
	absentErr error
	identity  string
	// beforeAbsent, when set, runs before Absent answers, with the name and
	// how many times Absent was asked for it (1 for the first).
	beforeAbsent func(name string, call int)
	absentCalls  map[string]int
	// pending is what MergePending returns: set, a restore is unfinished.
	pending error
}

func (s *fakeStore) MergePending() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pending
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

func (s *fakeStore) Absent(_ context.Context, name string) (bool, string, error) {
	s.mu.Lock()
	if s.absentCalls == nil {
		s.absentCalls = map[string]int{}
	}
	s.absentCalls[name]++
	call, hook := s.absentCalls[name], s.beforeAbsent
	s.mu.Unlock()
	if hook != nil {
		hook(name, call)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.absentErr != nil {
		return false, "", s.absentErr
	}
	_, ok := s.entries[name]
	return !ok, s.identity, nil
}

func (s *fakeStore) Identity(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.identity, nil
}

// rm deletes name, as keys rm does.
func (s *fakeStore) rm(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, name)
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
		store:  &fakeStore{entries: map[string]fakeEntry{}, identity: "1:1"},
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
		StatePath:      filepath.Join(h.dir, StateFileName),
		StateOwner:     uint32(os.Geteuid()),
		Client:         h.client,
		Store:          h.store,
		EncryptionOn:   encryptionOn,
		AllowPlaintext: allowPlaintext,
		Logger:         slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	// The declaration stands the test user in for root; the state file's
	// checks are production's, since the server's euid owns it.
	r.check = testCheck
	// The restore hold's duration is tested on its own
	// (TestRestoreHoldLastsTenMinutes); elsewhere only its first sweep holds.
	r.revokeHold = 0
	return r
}

// own records obj as created by the reconciler, as a create would have.
func (h *harness) own(t *testing.T, objs ...*corev1.Secret) {
	t.Helper()
	euid := uint32(os.Geteuid())
	st, err := ReadState(filepath.Join(h.dir, StateFileName), OpenNoFollow, StateDirCheck(euid), StateFileCheck(euid))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range objs {
		st.Set(o.Namespace, o.Name, string(o.UID))
	}
	if err := WriteState(filepath.Join(h.dir, StateFileName), st, StateDirCheck(euid), chownNone); err != nil {
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
// get, create or update of a Secret, or a delete under a UID precondition
// (an owned immutable Secret's, or one whose entry is gone): no list, no
// watch, no other delete, no other kind.
func (h *harness) assertOnlyGetCreateUpdateSecrets(t *testing.T) {
	t.Helper()
	for _, a := range h.client.Actions() {
		switch {
		case a.GetResource().Resource != "secrets":
			t.Errorf("touched another kind: %s %s", a.GetVerb(), a.GetResource().Resource)
		case a.GetVerb() == "delete":
			// The one delete shape allowed: an owned Secret, under a
			// precondition on its UID.
			d, ok := a.(k8stesting.DeleteAction)
			if !ok || d.GetDeleteOptions().Preconditions == nil || d.GetDeleteOptions().Preconditions.UID == nil || *d.GetDeleteOptions().Preconditions.UID == "" {
				t.Errorf("made a delete without a UID precondition")
			}
		case a.GetVerb() != "get" && a.GetVerb() != "create" && a.GetVerb() != "update":
			t.Errorf("made a %s call on secrets; only get, create, update and a UID-preconditioned delete are allowed", a.GetVerb())
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
// every target is refused: no create, no update and no read of a value; the
// only calls are the Gets a revocation needs. The refusal is logged at Warn
// once per target however many sweeps run (G18).
func TestDeliveryRefusedWhileEncryptionOff(t *testing.T) {
	h := newHarness(t, false, false)
	h.store.set("api-token", 1, []byte("tok"))
	h.store.set("signer", 1, []byte("sig"))
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"}, Target{Entry: "system/signer", Namespace: "payments"})
	ctx := context.Background()
	for range 3 {
		h.r.Sweep(ctx)
	}
	for _, v := range h.verbs() {
		if v != "get/secrets" {
			t.Fatalf("encryption off: the apiserver saw %v, want Gets only", h.verbs())
		}
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

// TestDeliveryRefusedWhileMergePending (U192): while a restore is unfinished
// (the store's MergePending is set), a sweep delivers nothing: no apiserver
// call and no store read, logged at Error. Once the merge has run, the next
// sweep delivers.
func TestDeliveryRefusedWhileMergePending(t *testing.T) {
	h := newHarness(t, true, false)
	h.store.set("api-token", 1, []byte("tok"))
	h.store.pending = errors.New("a restore is unfinished")
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"})
	ctx := context.Background()
	h.r.Sweep(ctx)
	if got := h.client.Actions(); len(got) != 0 {
		t.Fatalf("merge pending: the apiserver saw %v, want no call", h.verbs())
	}
	if h.store.reads != 0 {
		t.Fatalf("merge pending: the store was read %d times, want 0", h.store.reads)
	}
	if logs := h.logs.String(); !strings.Contains(logs, "level=ERROR") || !strings.Contains(logs, "keys floor merge") {
		t.Fatalf("merge pending: logs %s; want an Error naming keys floor merge", logs)
	}
	h.store.mu.Lock()
	h.store.pending = nil
	h.store.mu.Unlock()
	h.r.Sweep(ctx)
	if s := h.secret(t, "payments", "api-token"); string(s.Data[DefaultDataKey]) != "tok" {
		t.Fatalf("after the merge: data = %q, want tok", s.Data[DefaultDataKey])
	}
}

// TestDeliveryOverrideAllowsPlaintext: with encryption off, the override flag
// set at start lets delivery create the Secret (G18).
func TestDeliveryOverrideAllowsPlaintext(t *testing.T) {
	h := newHarness(t, false, true)
	h.store.set("api-token", 2, []byte("tok"))
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"})
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
// override, whose entry is live, is left as it is by a server restarted
// without it: no update, no delete, the Secret still there (G18).
func TestDeliveredTargetStaysWhenOverrideRemoved(t *testing.T) {
	h := newHarness(t, false, true)
	h.store.set("api-token", 1, []byte("tok"))
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"})
	ctx := context.Background()
	h.r.Sweep(ctx)
	h.client.ClearActions()

	h.store.set("api-token", 2, []byte("tok2"))
	restarted := h.reconciler(false, false)
	restarted.Sweep(ctx)
	restarted.Sweep(ctx)
	for _, v := range h.verbs() {
		if v != "get/secrets" {
			t.Fatalf("after the override was removed the apiserver saw %v, want Gets only", h.verbs())
		}
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
	valid := `{"version":1,"targets":[{"entry":"system/api-token","namespace":"payments"}]}`
	many := func() string {
		var b strings.Builder
		b.WriteString(`{"version":1,"targets":[`)
		for i := range MaxTargets + 1 {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `{"entry":"system/e%d","namespace":"payments"}`, i)
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
			h.writeRaw(t, []byte(`{"version":1,"targets":[{"entry":"system/api-token","namespace":"payments","kind":"Role"}]}`), 0o644)
		}, false, "unknown field"},
		{"unknown top-level field", func(t *testing.T, h *harness) {
			h.writeRaw(t, []byte(`{"version":1,"targets":[],"extra":true}`), 0o644)
		}, false, "unknown field"},
		{"wrong version", func(t *testing.T, h *harness) {
			h.writeRaw(t, []byte(`{"version":2,"targets":[{"entry":"system/api-token","namespace":"payments"}]}`), 0o644)
		}, false, "version 2"},
		{"trailing data", func(t *testing.T, h *harness) { h.writeRaw(t, []byte(valid+valid), 0o644) }, false, "trailing data"},
		{"too many targets", func(t *testing.T, h *harness) { h.writeRaw(t, []byte(many), 0o644) }, false, "the limit is"},
		{"invalid namespace", func(t *testing.T, h *harness) {
			h.writeRaw(t, []byte(`{"version":1,"targets":[{"entry":"system/api-token","namespace":"Bad_NS"}]}`), 0o644)
		}, false, "namespace is not a valid"},
		{"duplicate Secret", func(t *testing.T, h *harness) {
			h.writeRaw(t, []byte(`{"version":1,"targets":[{"entry":"system/a","namespace":"p","secretName":"s"},{"entry":"system/b","namespace":"p","secretName":"s"}]}`), 0o644)
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
		Target{Entry: "system/api-token", Namespace: "payments", SecretName: "plain"},
		Target{Entry: "system/api-token", Namespace: "payments", SecretName: "foreign"},
		Target{Entry: "system/api-token", Namespace: "payments", SecretName: "ours"},
		Target{Entry: "system/api-token", Namespace: "payments", SecretName: "fresh", DataKey: "token"},
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
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"})
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
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"})
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
		Target{Entry: "system/api-token", Namespace: "broken"},
		Target{Entry: "system/missing", Namespace: "payments"},
		Target{Entry: "system/api-token", Namespace: "payments"},
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
	h.declare(t, Target{Entry: "system/signer", Namespace: "payments", DataKey: "private.key"})
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
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"})
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
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"})
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
	d, err := Parse([]byte(`{"version":1,"targets":[{"entry":"system/signer-key","namespace":"payments"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Targets[0]; got.Secret() != "signer-key" || got.Key() != "value" {
		t.Fatalf("defaults: secret %q key %q", got.Secret(), got.Key())
	}
	if d.Upsert(Target{Entry: "system/other", Namespace: "payments", SecretName: "signer-key"}) != true {
		t.Fatal("Upsert did not replace the target naming the same Secret")
	}
	d.Upsert(Target{Entry: "system/signer-key", Namespace: "ops"})
	b, err := d.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(b)
	if err != nil {
		t.Fatalf("Marshal's output does not parse: %v\n%s", err, b)
	}
	if n := back.Remove("system/signer-key", "ops", ""); n != 1 || len(back.Targets) != 1 {
		t.Fatalf("Remove removed %d, left %d", n, len(back.Targets))
	}
	if _, err := Parse([]byte(`{"version":1,"targets":[{"entry":"system/` + strings.Repeat("a", 64) + `","namespace":"p"}]}`)); err == nil {
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
	d := Declaration{Version: SchemaVersion, Targets: []Target{{Entry: "system/a", Namespace: "p"}}}
	if err := Write(path, d, testCheck, func(f *os.File) error { chowned = f.Name(); return nil }); err != nil {
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
	if err := Write(path, d, testCheck, func(*os.File) error { return errors.New("EPERM") }); err == nil {
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
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"})
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
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments", DataKey: "old"})
	ctx := context.Background()
	h.r.Sweep(ctx)
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments", DataKey: "new"})
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
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"})
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
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"})
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
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"})
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
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"})
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

// TestReconcilerImmutableOwned: an immutable Secret the server owns cannot
// be updated, so a rotation deletes it under a UID precondition (the only
// delete the reconciler makes), creates it again with the new value, and
// records the new UID; both steps are logged without the value (G20).
func TestReconcilerImmutableOwned(t *testing.T) {
	h := newHarness(t, true, false)
	h.store.set("api-token", 1, []byte("immutable-one"))
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"})
	ctx := context.Background()
	h.r.Sweep(ctx)
	s := h.secret(t, "payments", "api-token")
	oldUID := s.UID
	yes := true
	s.Immutable = &yes
	if _, err := h.client.CoreV1().Secrets("payments").Update(ctx, s, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	h.client.ClearActions()
	h.store.set("api-token", 2, []byte("immutable-two"))
	h.r.Sweep(ctx)
	got := h.secret(t, "payments", "api-token")
	if string(got.Data[DefaultDataKey]) != "immutable-two" || got.UID == oldUID || got.UID == "" {
		t.Fatalf("the rotation did not land on a recreated Secret: %q, uid %q (was %q)", got.Data[DefaultDataKey], got.UID, oldUID)
	}
	if n := h.updates(); n != 0 {
		t.Fatalf("an immutable Secret drew %d updates", n)
	}
	var deletes int
	for _, a := range h.client.Actions() {
		if d, ok := a.(k8stesting.DeleteAction); ok {
			deletes++
			pre := d.GetDeleteOptions().Preconditions
			if pre == nil || pre.UID == nil || *pre.UID != oldUID {
				t.Fatalf("the delete carries no precondition on the owned UID %q: %+v", oldUID, pre)
			}
		}
	}
	if deletes != 1 {
		t.Fatalf("got %d deletes, want 1: %v", deletes, h.verbs())
	}
	h.assertOnlyGetCreateUpdateSecrets(t)
	st, err := ReadState(filepath.Join(h.dir, StateFileName), OpenNoFollow, StateDirCheck(uint32(os.Geteuid())), StateFileCheck(uint32(os.Geteuid())))
	if err != nil || st.UID("payments", "api-token") != string(got.UID) {
		t.Fatalf("the new UID is not recorded (%q, %v), want %q", st.UID("payments", "api-token"), err, got.UID)
	}
	logs := h.logs.String()
	if !strings.Contains(logs, "immutable") || !strings.Contains(logs, "re-created") {
		t.Fatalf("the delete and the create are not both logged\n%s", logs)
	}
	if strings.Contains(logs, "immutable-one") || strings.Contains(logs, "immutable-two") {
		t.Fatalf("the log carries a value\n%s", logs)
	}
}

// TestReconcilerImmutableDeleteConflict: when the UID precondition fails (the
// object is not the one recorded), the delete is refused and nothing is
// created (G20).
func TestReconcilerImmutableDeleteConflict(t *testing.T) {
	h := newHarness(t, true, false)
	h.store.set("api-token", 1, []byte("one"))
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"})
	ctx := context.Background()
	h.r.Sweep(ctx)
	s := h.secret(t, "payments", "api-token")
	yes := true
	s.Immutable = &yes
	if _, err := h.client.CoreV1().Secrets("payments").Update(ctx, s, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	h.client.PrependReactor("delete", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewConflict(corev1.Resource("secrets"), "api-token", errors.New("Precondition failed: UID in precondition"))
	})
	h.client.ClearActions()
	h.store.set("api-token", 2, []byte("two"))
	h.r.Sweep(ctx)
	for _, v := range h.verbs() {
		if v == "create/secrets" || v == "update/secrets" {
			t.Fatalf("a refused delete was followed by %s: %v", v, h.verbs())
		}
	}
	if got := string(h.secret(t, "payments", "api-token").Data[DefaultDataKey]); got != "one" {
		t.Fatalf("the Secret changed: %q", got)
	}
}

// TestNewDefaultsBindRoot: New's own seams, untouched, refuse what
// production must: a declaration the test user owns is refused before any
// apiserver call, and a symlink is not followed (G19).
func TestNewDefaultsBindRoot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	if err := os.WriteFile(path, []byte(`{"version":1,"targets":[{"entry":"system/api-token","namespace":"payments"}]}`), 0o644); err != nil {
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

}

// TestReconcilerLogsNoValue: across a full sweep history (create, update on
// rotation, drift, and failing get, create and update calls) no stored value appears in the log, raw, base64 or hex (G20).
func TestReconcilerLogsNoValue(t *testing.T) {
	h := newHarness(t, true, false)
	values := [][]byte{[]byte("first-stored-value"), []byte("second-stored-value"), []byte("drifted-hand-value"), []byte("third-stored-value")}
	h.store.set("api-token", 1, values[0])
	h.store.set("other", 1, values[0])
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"}, Target{Entry: "system/other", Namespace: "failing"})
	failing := true
	for _, verb := range []string{"get", "create", "update"} {
		h.client.PrependReactor(verb, "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
			if failing && a.GetNamespace() == "failing" {
				return true, nil, apierrors.NewInternalError(errors.New(a.GetVerb() + " refused"))
			}
			return false, nil, nil
		})
	}
	ctx := context.Background()
	h.r.Sweep(ctx) // create; the failing target's get fails
	failing = false
	h.client.PrependReactor("create", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetNamespace() == "failing" {
			return true, nil, apierrors.NewInternalError(errors.New("create refused"))
		}
		return false, nil, nil
	})
	h.r.Sweep(ctx) // the failing target's create fails
	h.store.set("api-token", 2, values[1])
	h.r.Sweep(ctx) // update on rotation
	s := h.secret(t, "payments", "api-token")
	s.Data[DefaultDataKey] = values[2]
	if _, err := h.client.CoreV1().Secrets("payments").Update(ctx, s, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	h.r.Sweep(ctx) // drift
	h.client.PrependReactor("update", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewInternalError(errors.New("update refused"))
	})
	h.store.set("api-token", 3, values[3])
	h.r.Sweep(ctx) // the update fails
	logs := h.logs.String()
	for _, want := range []string{"delivered", "re-delivered", "drifted", "cannot read the Secret", "cannot create the Secret", "cannot update the Secret"} {
		if !strings.Contains(logs, want) {
			t.Errorf("the sweep history did not reach %q\n%s", want, logs)
		}
	}
	for _, v := range values {
		for _, form := range []string{string(v), hex.EncodeToString(v), base64.StdEncoding.EncodeToString(v), fmt.Sprint(v)} {
			if strings.Contains(logs, form) {
				t.Fatalf("the log carries a stored value (%q)\n%s", form, logs)
			}
		}
	}
}

// hangingClient is a clientset whose Secret Gets in namespace hung block
// until their context is done, as a wedged apiserver call would.
type hangingClient struct {
	kubernetes.Interface
	hung string
}

func (c hangingClient) CoreV1() typedcorev1.CoreV1Interface {
	return hangingCore{c.Interface.CoreV1(), c.hung}
}

type hangingCore struct {
	typedcorev1.CoreV1Interface
	hung string
}

func (c hangingCore) Secrets(ns string) typedcorev1.SecretInterface {
	return hangingSecrets{c.CoreV1Interface.Secrets(ns), ns == c.hung}
}

type hangingSecrets struct {
	typedcorev1.SecretInterface
	hang bool
}

func (s hangingSecrets) Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.Secret, error) {
	if s.hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return s.SecretInterface.Get(ctx, name, opts)
}

// TestReconcilerTargetTimeout: a target whose apiserver call hangs is given
// up at its own deadline, and the next target is still delivered in the same
// sweep (G20).
func TestReconcilerTargetTimeout(t *testing.T) {
	h := newHarness(t, true, false)
	h.store.set("api-token", 1, []byte("tok"))
	h.declare(t, Target{Entry: "system/api-token", Namespace: "hung"}, Target{Entry: "system/api-token", Namespace: "payments"})
	h.r.client = hangingClient{h.client, "hung"}
	h.r.targetTimeout = time.Millisecond
	h.r.Sweep(context.Background())
	if got := string(h.secret(t, "payments", "api-token").Data[DefaultDataKey]); got != "tok" {
		t.Fatalf("the target after a hung one was not delivered: %q", got)
	}
	if !strings.Contains(h.logs.String(), "cannot read the Secret") || !strings.Contains(h.logs.String(), "deadline exceeded") {
		t.Fatalf("the hung call is not logged as timed out\n%s", h.logs.String())
	}
}

// TestNewTargetTimeout: production gives each target ten seconds.
func TestNewTargetTimeout(t *testing.T) {
	if got := New(Config{}).targetTimeout; got != 10*time.Second {
		t.Fatalf("target timeout %v, want 10s", got)
	}
}

// TestWatchLogsErrors: an fsnotify error is logged at Warn, and events for
// the declaration still go through.
func TestWatchLogsErrors(t *testing.T) {
	events := make(chan fsnotify.Event)
	errs := make(chan error)
	out := make(chan struct{}, 1)
	logs := &syncBuffer{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		forwardEvents(events, errs, FileName, out, slog.New(slog.NewTextHandler(logs, nil)))
	}()
	errs <- errors.New("queue overflow")
	events <- fsnotify.Event{Name: filepath.Join("/x", FileName)}
	<-out
	close(events)
	<-done
	if !strings.Contains(logs.String(), `level=WARN`) || !strings.Contains(logs.String(), "queue overflow") {
		t.Fatalf("the watch error is not logged at Warn\n%s", logs.String())
	}
}

// TestDataRootDirectoryChecked: Read, Write and Lock refuse a data root that
// is group- or other-writable, not root's (the production check), or a
// symlink, judged on the directory's own descriptor (G19).
func TestDataRootDirectoryChecked(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T) (dir string, check FileCheck)
	}{
		{"group-writable", func(t *testing.T) (string, FileCheck) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o775); err != nil {
				t.Fatal(err)
			}
			return dir, testCheck
		}},
		{"other-writable", func(t *testing.T) (string, FileCheck) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o757); err != nil {
				t.Fatal(err)
			}
			return dir, testCheck
		}},
		{"not root's", func(t *testing.T) (string, FileCheck) {
			dir := t.TempDir()
			if os.Geteuid() == 0 {
				if err := os.Chown(dir, 1, 1); err != nil {
					t.Fatal(err)
				}
			}
			return dir, RootCheck
		}},
		{"symlink", func(t *testing.T) (string, FileCheck) {
			parent := t.TempDir()
			real := filepath.Join(parent, "real")
			if err := os.Mkdir(real, 0o755); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(parent, "link")
			if err := os.Symlink(real, link); err != nil {
				t.Fatal(err)
			}
			return link, testCheck
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, check := tc.setup(t)
			path := filepath.Join(dir, FileName)
			// A declaration the file check itself accepts, so only the
			// directory can be what is refused.
			if err := os.WriteFile(path, []byte(`{"version":1,"targets":[]}`), 0o644); err != nil {
				t.Fatal(err)
			}
			fileCheck := func(fs.FileInfo) error { return nil }
			if _, _, _, err := Read(path, OpenNoFollow, dirOnly(check, fileCheck)); !errors.Is(err, ErrRefused) {
				t.Errorf("Read: %v, want ErrRefused", err)
			}
			if _, err := ReadState(filepath.Join(dir, StateFileName), OpenNoFollow, check, fileCheck); !errors.Is(err, ErrRefused) {
				t.Errorf("ReadState: %v, want ErrRefused", err)
			}
			noChown := func(*os.File) error { return nil }
			if err := Write(path, Declaration{Version: SchemaVersion}, check, noChown); !errors.Is(err, ErrRefused) {
				t.Errorf("Write: %v, want ErrRefused", err)
			}
			if err := WriteState(filepath.Join(dir, StateFileName), State{}, check, noChown); !errors.Is(err, ErrRefused) {
				t.Errorf("WriteState: %v, want ErrRefused", err)
			}
			if unlock, err := Lock(context.Background(), filepath.Join(dir, LockName), check, nil); !errors.Is(err, ErrRefused) {
				if unlock != nil {
					unlock()
				}
				t.Errorf("Lock: %v, want ErrRefused", err)
			}
		})
	}
}

// dirOnly applies dir to a directory and file to anything else, so a test
// can refuse the directory while accepting the file in it.
func dirOnly(dir, file FileCheck) FileCheck {
	return func(fi fs.FileInfo) error {
		if fi.IsDir() {
			return dir(fi)
		}
		return file(fi)
	}
}

// TestStateStockInstallShape: on an install the server runs as a non-root
// uid that owns its work dir; delivery there creates the Secret and records
// its UID in <work dir>/keystore-delivery-state.json, owned by that uid,
// 0600, through New's own state checks (G20).
func TestStateStockInstallShape(t *testing.T) {
	euid := os.Geteuid()
	if euid == 0 {
		t.Skip("the stock install's server is not root")
	}
	dataRoot := t.TempDir()
	work := filepath.Join(dataRoot, "server")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dataRoot, FileName)
	if err := os.WriteFile(path, []byte(`{"version":1,"targets":[{"entry":"system/api-token","namespace":"payments"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, true, false)
	h.store.set("api-token", 1, []byte("tok"))
	statePath := filepath.Join(work, StateFileName)
	r := New(Config{Path: path, StatePath: statePath, StateOwner: uint32(euid), Client: h.client, Store: h.store, EncryptionOn: true,
		Logger: slog.New(slog.NewTextHandler(h.logs, nil))})
	r.check = testCheck // the declaration is root's on an install; a test cannot make it so
	r.Sweep(context.Background())
	s := h.secret(t, "payments", "api-token")
	fi, err := os.Lstat(statePath)
	if err != nil {
		t.Fatalf("no state file in the work dir: %v\n%s", err, h.logs.String())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != euid || fi.Mode() != StateFileMode {
		t.Fatalf("state file %v uid %d, want %v owned by the server's uid %d", fi.Mode(), st.Uid, StateFileMode, euid)
	}
	got, err := ReadState(statePath, OpenNoFollow, StateDirCheck(uint32(euid)), StateFileCheck(uint32(euid)))
	if err != nil || got.UID("payments", "api-token") != string(s.UID) || s.UID == "" {
		t.Fatalf("recorded UID %q (%v), want the created Secret's %q", got.UID("payments", "api-token"), err, s.UID)
	}
}

// TestStateFileOtherOwnerRefused: a state file, or the directory holding it,
// owned by a uid other than the server's (and, for the directory, not root)
// is refused, and the sweep delivers nothing (G19).
func TestStateFileOtherOwnerRefused(t *testing.T) {
	h := newHarness(t, true, false)
	h.store.set("api-token", 1, []byte("tok"))
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"})
	h.own(t) // an empty state file, owned by the test user
	other := uint32(os.Geteuid() + 1)
	h.r.stateCheck = StateFileCheck(other)
	h.r.Sweep(context.Background())
	if n := len(h.client.Actions()); n != 0 {
		t.Fatalf("a state file the server's uid does not own let the sweep through: %d calls", n)
	}
	if !strings.Contains(h.logs.String(), "state file refused") || !strings.Contains(h.logs.String(), "not the server's uid") {
		t.Fatalf("the refusal is not logged with its reason\n%s", h.logs.String())
	}
	path := filepath.Join(h.dir, StateFileName)
	if _, err := ReadState(path, OpenNoFollow, StateDirCheck(other), StateFileCheck(uint32(os.Geteuid()))); !errors.Is(err, ErrRefused) {
		t.Fatalf("a directory owned by neither the server's uid nor root: %v, want ErrRefused", err)
	}
	if err := os.Chmod(path, 0o620); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadState(path, OpenNoFollow, StateDirCheck(uint32(os.Geteuid())), StateFileCheck(uint32(os.Geteuid()))); !errors.Is(err, ErrRefused) {
		t.Fatalf("a group-writable state file: %v, want ErrRefused", err)
	}
}

// TestStateDirServiceUserOwner: a root server also accepts a state-file
// directory the service user owns, and the sweep delivers through it; the
// file must still be the server's, and without the service user named the
// same directory is refused (G19).
func TestStateDirServiceUserOwner(t *testing.T) {
	h := newHarness(t, true, false)
	h.store.set("api-token", 1, []byte("tok"))
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"})
	euid := uint32(os.Geteuid())
	// The test user stands in for the service user owning the work dir;
	// another uid stands in for the server's euid.
	server := euid + 1
	r := New(Config{Path: h.path, StatePath: filepath.Join(h.dir, StateFileName), StateOwner: server, StateDirOwners: []uint32{euid},
		Client: h.client, Store: h.store, EncryptionOn: true, Logger: slog.New(slog.NewTextHandler(h.logs, nil))})
	r.check = testCheck
	r.stateCheck = StateFileCheck(euid) // the file this test creates is the test user's
	r.Sweep(context.Background())
	if got := string(h.secret(t, "payments", "api-token").Data[DefaultDataKey]); got != "tok" {
		t.Fatalf("a service-user-owned work dir refused delivery: %q\n%s", got, h.logs.String())
	}
	if err := StateDirCheck(server)(mustStat(t, h.dir)); err == nil {
		t.Fatal("without the service user, a directory owned by neither the euid nor root was accepted")
	}
	if err := StateDirCheck(server, euid)(mustStat(t, h.dir)); err != nil {
		t.Fatalf("with the service user, its directory was refused: %v", err)
	}
	if err := StateFileCheck(server)(mustStat(t, filepath.Join(h.dir, StateFileName))); err == nil {
		t.Fatal("a state file the service user owns was accepted for a root server")
	}
}

func mustStat(t *testing.T, path string) fs.FileInfo {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi
}

// TestDeclarationEntryField: a target names its entry scope-qualified, as
// "entry": "system/<name>". A file in the old "name" shape is refused as an
// unknown field, a user/ entry or an unqualified one is refused (a user entry
// is a KeyDelivery's), the name after the prefix gets the keystore's name
// check, and the file keeps the key order entry, namespace, secretName,
// dataKey (G19).
func TestDeclarationEntryField(t *testing.T) {
	for _, tc := range []struct {
		name, doc, reason string
	}{
		{"old name field", `{"version":1,"targets":[{"name":"api-token","namespace":"payments"}]}`, "unknown field"},
		{"user entry", `{"version":1,"targets":[{"entry":"user/501/api-token","namespace":"payments"}]}`, "not a system/<name> entry"},
		{"unqualified", `{"version":1,"targets":[{"entry":"api-token","namespace":"payments"}]}`, "not a system/<name> entry"},
		{"bad name", `{"version":1,"targets":[{"entry":"system/Bad_Name","namespace":"payments"}]}`, "not a valid keystore entry name"},
		{"nested", `{"version":1,"targets":[{"entry":"system/a/b","namespace":"payments"}]}`, "not a valid keystore entry name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, true, false)
			h.store.set("api-token", 1, []byte("tok"))
			h.writeRaw(t, []byte(tc.doc), FileMode)
			h.r.Sweep(context.Background())
			if n := len(h.client.Actions()); n != 0 {
				t.Fatalf("a refused declaration reached the apiserver: %v", h.verbs())
			}
			if !strings.Contains(h.logs.String(), tc.reason) {
				t.Fatalf("the refusal does not say %q\n%s", tc.reason, h.logs.String())
			}
		})
	}
	b, err := Declaration{Version: SchemaVersion, Targets: []Target{{Entry: "system/signer-key", Namespace: "payments", SecretName: "signer", DataKey: "private.key"}}}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	order := []string{`"entry": "system/signer-key"`, `"namespace"`, `"secretName"`, `"dataKey"`}
	last := -1
	for _, k := range order {
		i := strings.Index(got, k)
		if i <= last {
			t.Fatalf("key %s out of order (want entry, namespace, secretName, dataKey):\n%s", k, got)
		}
		last = i
	}
	if tg := (Target{Entry: "system/signer-key"}); tg.Secret() != "signer-key" || tg.Key() != DefaultDataKey {
		t.Fatalf("defaults: secret %q key %q, want the name without system/ and %q", tg.Secret(), tg.Key(), DefaultDataKey)
	}
}

// TestMissingDeclarationKeepsRecords: a declaration that is absent, as a
// file or with its whole directory, withdraws nothing: the ownership records
// survive and nothing is created or updated, and once the declaration is back
// the next rotation still reaches the Secret. Only a declaration that exists
// and parses without the target withdraws it (G20).
func TestMissingDeclarationKeepsRecords(t *testing.T) {
	for _, removeDir := range []bool{false, true} {
		t.Run(fmt.Sprintf("removeDir=%v", removeDir), func(t *testing.T) {
			h := newHarness(t, true, false)
			declDir := filepath.Join(h.dir, "decl")
			if err := os.Mkdir(declDir, 0o755); err != nil {
				t.Fatal(err)
			}
			h.path = filepath.Join(declDir, FileName)
			h.r = h.reconciler(true, false)
			h.store.set("api-token", 1, []byte("one"))
			target := Target{Entry: "system/api-token", Namespace: "payments"}
			h.declare(t, target)
			ctx := context.Background()
			h.r.Sweep(ctx)
			uid := string(h.secret(t, "payments", "api-token").UID)

			if removeDir {
				if err := os.RemoveAll(declDir); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Remove(h.path); err != nil {
				t.Fatal(err)
			}
			h.client.ClearActions()
			h.store.set("api-token", 2, []byte("two"))
			h.r.Sweep(ctx)
			for _, v := range h.verbs() {
				if v != "get/secrets" {
					t.Fatalf("an absent declaration drew %s", v)
				}
			}
			st, err := ReadState(filepath.Join(h.dir, StateFileName), OpenNoFollow, StateDirCheck(uint32(os.Geteuid())), StateFileCheck(uint32(os.Geteuid())))
			if err != nil || st.UID("payments", "api-token") != uid {
				t.Fatalf("an absent declaration dropped the record (%q, %v), want %q", st.UID("payments", "api-token"), err, uid)
			}

			if err := os.MkdirAll(declDir, 0o755); err != nil {
				t.Fatal(err)
			}
			h.declare(t, target)
			h.r.Sweep(ctx)
			if got := string(h.secret(t, "payments", "api-token").Data[DefaultDataKey]); got != "two" {
				t.Fatalf("after the declaration came back the rotation did not land: %q", got)
			}
		})
	}
}

// TestReconcilerRepointsOwnedSecret: root re-points ns/S from system/A to
// system/B with deliver; the Secret the server created keeps its UID, so it
// is updated to B's value and relabelled for B (G20).
func TestReconcilerRepointsOwnedSecret(t *testing.T) {
	h := newHarness(t, true, false)
	h.store.set("alpha", 1, []byte("alpha-value"))
	h.store.set("beta", 1, []byte("beta-value"))
	h.declare(t, Target{Entry: "system/alpha", Namespace: "payments", SecretName: "shared"})
	ctx := context.Background()
	h.r.Sweep(ctx)
	h.declare(t, Target{Entry: "system/beta", Namespace: "payments", SecretName: "shared"})
	h.r.Sweep(ctx)
	s := h.secret(t, "payments", "shared")
	if string(s.Data[DefaultDataKey]) != "beta-value" || s.Labels[LabelKey] != "beta" {
		t.Fatalf("re-pointed Secret holds %q labelled %q, want beta's value and label", s.Data[DefaultDataKey], s.Labels[LabelKey])
	}
}

// TestReconcilerRelabelledOwnedSecret: a tenant removes or changes the label
// on a Secret the server created; its UID still matches, so the label is put
// back and the next rotation lands (G20).
func TestReconcilerRelabelledOwnedSecret(t *testing.T) {
	for _, labels := range []map[string]string{nil, {LabelKey: "someone-else"}} {
		h := newHarness(t, true, false)
		h.store.set("api-token", 1, []byte("one"))
		h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"})
		ctx := context.Background()
		h.r.Sweep(ctx)
		s := h.secret(t, "payments", "api-token")
		s.Labels = labels
		if _, err := h.client.CoreV1().Secrets("payments").Update(ctx, s, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		h.r.Sweep(ctx)
		if got := h.secret(t, "payments", "api-token").Labels[LabelKey]; got != "api-token" {
			t.Fatalf("labels %v: the label was not put back: %q", labels, got)
		}
		h.store.set("api-token", 2, []byte("two"))
		h.r.Sweep(ctx)
		if got := string(h.secret(t, "payments", "api-token").Data[DefaultDataKey]); got != "two" {
			t.Fatalf("labels %v: the rotation did not land: %q", labels, got)
		}
	}
}

// TestStateWriteFailureCreatesNothing: when the state file cannot be written
// before the first create (here its directory is not writable), nothing is
// created, so no Secret exists that could not be recorded (G20).
func TestStateWriteFailureCreatesNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a read-only directory")
	}
	h := newHarness(t, true, false)
	stateDir := filepath.Join(h.dir, "state")
	if err := os.Mkdir(stateDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(stateDir, 0o700) }) // let TempDir's cleanup remove it
	h.r.statePath = filepath.Join(stateDir, StateFileName)
	h.store.set("api-token", 1, []byte("tok"))
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"})
	h.r.Sweep(context.Background())
	for _, v := range h.verbs() {
		if v == "create/secrets" {
			t.Fatalf("a Secret was created though the state file could not be written: %v", h.verbs())
		}
	}
	if !strings.Contains(h.logs.String(), "cannot write the state file") {
		t.Fatalf("the refusal is not logged\n%s", h.logs.String())
	}
}

// TestStateFileMalformedDeliversNothing: a state file owned and moded as it
// must be but not parsing strictly (unknown field, wrong version, trailing
// data, too many records, an empty UID, a repeated record, a namespace
// holding the key's "/" separator) delivers nothing (G19).
func TestStateFileMalformedDeliversNothing(t *testing.T) {
	rec := func(i int) string { return fmt.Sprintf(`{"namespace":"p","secretName":"s%d","uid":"u%d"}`, i, i) }
	many := `{"version":1,"secrets":[`
	for i := range MaxTargets + 1 {
		if i > 0 {
			many += ","
		}
		many += rec(i)
	}
	many += "]}"
	for _, tc := range []struct{ name, doc string }{
		{"unknown field", `{"version":1,"secrets":[],"extra":1}`},
		{"unknown record field", `{"version":1,"secrets":[{"namespace":"p","secretName":"s","uid":"u","kind":"x"}]}`},
		{"wrong version", `{"version":2,"secrets":[]}`},
		{"trailing data", `{"version":1,"secrets":[]}{}`},
		{"too many records", many},
		{"empty uid", `{"version":1,"secrets":[{"namespace":"p","secretName":"s","uid":""}]}`},
		{"duplicate record", `{"version":1,"secrets":[` + rec(1) + `,` + rec(1) + `]}`},
		{"namespace with a slash", `{"version":1,"secrets":[{"namespace":"p/q","secretName":"s","uid":"u"}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, true, false)
			h.store.set("api-token", 1, []byte("tok"))
			h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"})
			path := filepath.Join(h.dir, StateFileName)
			if err := os.WriteFile(path, []byte(tc.doc), StateFileMode); err != nil {
				t.Fatal(err)
			}
			h.r.Sweep(context.Background())
			if n := len(h.client.Actions()); n != 0 {
				t.Fatalf("a malformed state file let the sweep through: %v", h.verbs())
			}
			if !strings.Contains(h.logs.String(), "state file refused") {
				t.Fatalf("the refusal is not logged\n%s", h.logs.String())
			}
		})
	}
}

// TestReconcilerUpdateCarriesUIDAndResourceVersion: the object sent to
// Update carries the uid and resourceVersion the Get returned, so the
// apiserver refuses the write if the Secret was replaced or changed in
// between (G20).
func TestReconcilerUpdateCarriesUIDAndResourceVersion(t *testing.T) {
	ours := secretObj("payments", "api-token", map[string]string{LabelKey: "api-token"}, map[string][]byte{"value": []byte("old")})
	ours.UID = "ours-1"
	ours.ResourceVersion = "42"
	h := newHarness(t, true, false, ours)
	h.own(t, ours)
	h.store.set("api-token", 2, []byte("new"))
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"})
	var sent *corev1.Secret
	h.client.PrependReactor("update", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
		sent = a.(k8stesting.UpdateAction).GetObject().(*corev1.Secret).DeepCopy()
		return false, nil, nil
	})
	h.r.Sweep(context.Background())
	if sent == nil {
		t.Fatalf("no update was sent: %v", h.verbs())
	}
	if sent.UID != "ours-1" || sent.ResourceVersion != "42" {
		t.Fatalf("update sent uid %q resourceVersion %q, want the Get's ours-1 and 42", sent.UID, sent.ResourceVersion)
	}
}

// staleImmutableOwned is an immutable Secret the server created at version 1
// with value "one", for a store that now holds a later version.
func staleImmutableOwned() *corev1.Secret {
	s := secretObj("payments", "api-token", map[string]string{LabelKey: "api-token"}, map[string][]byte{DefaultDataKey: []byte("one")})
	s.UID = "ours-1"
	sum := sha256.Sum256([]byte("one"))
	s.Annotations = map[string]string{VersionAnnotation: "1", FingerprintAnnotation: hex.EncodeToString(sum[:8])}
	yes := true
	s.Immutable = &yes
	return s
}

// deletes counts the recorded deletes of Secrets.
func (h *harness) deletes() int {
	n := 0
	for _, v := range h.verbs() {
		if v == "delete/secrets" {
			n++
		}
	}
	return n
}

// TestStateWriteFailureDeletesNothing: an owned immutable Secret that needs a
// rotation is not deleted when the state file cannot be written, since the
// Secret created after the delete could not be recorded (G20).
func TestStateWriteFailureDeletesNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a read-only directory")
	}
	ours := staleImmutableOwned()
	h := newHarness(t, true, false, ours)
	stateDir := filepath.Join(h.dir, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	h.r.statePath = filepath.Join(stateDir, StateFileName)
	var st State
	st.Set(ours.Namespace, ours.Name, string(ours.UID))
	if err := WriteState(h.r.statePath, st, StateDirCheck(uint32(os.Geteuid())), chownNone); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stateDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(stateDir, 0o700) }) // let TempDir's cleanup remove it
	h.store.set("api-token", 2, []byte("two"))
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"})
	h.r.Sweep(context.Background())
	if n := h.deletes(); n != 0 {
		t.Fatalf("the immutable Secret was deleted though the state file could not be written: %v", h.verbs())
	}
	if got := h.secret(t, "payments", "api-token"); got.UID != "ours-1" || string(got.Data[DefaultDataKey]) != "one" {
		t.Fatalf("the Secret changed: uid %q, data %q", got.UID, got.Data[DefaultDataKey])
	}
	if !strings.Contains(h.logs.String(), "cannot write the state file") {
		t.Fatalf("the refusal is not logged\n%s", h.logs.String())
	}
}

// TestReconcilerImmutableMetadataOnly: an owned immutable Secret whose data
// is current but whose label or annotations differ (a tenant's relabel, or a
// new version of the same value) gets a metadata update that leaves data as
// it is, and is never deleted (G20).
func TestReconcilerImmutableMetadataOnly(t *testing.T) {
	for _, tc := range []struct {
		name    string
		labels  map[string]string
		version uint64
	}{
		{"wrong label", map[string]string{LabelKey: "someone-else"}, 1},
		{"no label", nil, 1},
		{"stale version annotation", map[string]string{LabelKey: "api-token"}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ours := staleImmutableOwned()
			ours.Labels = tc.labels
			h := newHarness(t, true, false, ours)
			h.own(t, ours)
			h.store.set("api-token", tc.version, []byte("one"))
			h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"})
			var sent *corev1.Secret
			h.client.PrependReactor("update", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
				sent = a.(k8stesting.UpdateAction).GetObject().(*corev1.Secret).DeepCopy()
				return false, nil, nil
			})
			ctx := context.Background()
			h.r.Sweep(ctx)
			h.r.Sweep(ctx)
			if n := h.deletes(); n != 0 {
				t.Fatalf("a metadata difference drew a delete: %v", h.verbs())
			}
			if n := h.updates(); n != 1 || sent == nil {
				t.Fatalf("got %d updates, want 1 metadata update: %v", n, h.verbs())
			}
			if string(sent.Data[DefaultDataKey]) != "one" || len(sent.Data) != 1 || sent.Immutable == nil || !*sent.Immutable {
				t.Fatalf("the update touched data or immutability: data %q, immutable %v", sent.Data, sent.Immutable)
			}
			got := h.secret(t, "payments", "api-token")
			want := fmt.Sprint(tc.version)
			if got.UID != "ours-1" || got.Labels[LabelKey] != "api-token" || got.Annotations[VersionAnnotation] != want {
				t.Fatalf("uid %q label %q version %q, want ours-1, api-token, %s", got.UID, got.Labels[LabelKey], got.Annotations[VersionAnnotation], want)
			}
			h.assertOnlyGetCreateUpdateSecrets(t)
		})
	}
}

// TestReconcilerTerminatingNotDeleted: an owned immutable Secret that needs a
// rotation but is already being deleted is neither deleted nor re-created
// while it terminates, and the wait is logged once (G20).
func TestReconcilerTerminatingNotDeleted(t *testing.T) {
	ours := staleImmutableOwned()
	now := metav1.Now()
	ours.DeletionTimestamp = &now
	ours.Finalizers = []string{"example.com/hold"}
	h := newHarness(t, true, false, ours)
	h.own(t, ours)
	h.store.set("api-token", 2, []byte("two"))
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"})
	ctx := context.Background()
	h.r.Sweep(ctx)
	h.r.Sweep(ctx)
	for _, v := range h.verbs() {
		if v == "delete/secrets" || v == "create/secrets" {
			t.Fatalf("a terminating Secret drew %s: %v", v, h.verbs())
		}
	}
	if got := h.secret(t, "payments", "api-token"); got.UID != "ours-1" {
		t.Fatalf("the Secret was replaced: uid %q", got.UID)
	}
	if n := strings.Count(h.logs.String(), "the Secret is being deleted; waiting"); n != 1 {
		t.Fatalf("the wait is logged %d times, want 1\n%s", n, h.logs.String())
	}
}

// TestMissingDeclarationWarnsOnce: an absent declaration while the state
// file holds records warns once per state, with the record count and no
// value, and leaves the state file unwritten; with no records it does not
// warn (G20).
func TestMissingDeclarationWarnsOnce(t *testing.T) {
	const msg = "the declaration is missing; 1 delivered Secrets are not being updated"
	h := newHarness(t, true, false)
	h.r.Sweep(context.Background())
	if strings.Contains(h.logs.String(), "the declaration is missing") {
		t.Fatalf("an absent declaration with no records warned\n%s", h.logs.String())
	}
	h.store.set("api-token", 1, []byte("the-stored-value"))
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"})
	ctx := context.Background()
	h.r.Sweep(ctx)
	if err := os.Remove(h.path); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(h.dir, StateFileName)
	before := mustStat(t, statePath)
	h.r.Sweep(ctx)
	h.r.Sweep(ctx)
	logs := h.logs.String()
	if n := strings.Count(logs, msg); n != 1 {
		t.Fatalf("the missing declaration is warned %d times, want 1\n%s", n, logs)
	}
	if !strings.Contains(logs, "level=WARN msg=\"keystore delivery: "+msg) {
		t.Fatalf("the missing declaration is not a Warn\n%s", logs)
	}
	if strings.Contains(logs, "the-stored-value") {
		t.Fatalf("the log carries the value\n%s", logs)
	}
	if after := mustStat(t, statePath); !after.ModTime().Equal(before.ModTime()) || after.Size() != before.Size() {
		t.Fatalf("an absent declaration rewrote the state file")
	}
	// Back, then gone again: a new state, so it warns again.
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"})
	h.r.Sweep(ctx)
	if err := os.Remove(h.path); err != nil {
		t.Fatal(err)
	}
	h.r.Sweep(ctx)
	if n := strings.Count(h.logs.String(), msg); n != 2 {
		t.Fatalf("a second absence is warned %d times in all, want 2\n%s", n, h.logs.String())
	}
}

// TestReconcilerImmutableDeleteNotFound: a Delete that finds the owned
// immutable Secret already gone goes on to create it; when a foreign Secret
// took the name in between, the create is refused and the foreign Secret is
// not overwritten (G20).
func TestReconcilerImmutableDeleteNotFound(t *testing.T) {
	ours := staleImmutableOwned()
	h := newHarness(t, true, false, ours)
	h.own(t, ours)
	h.store.set("api-token", 2, []byte("two"))
	h.declare(t, Target{Entry: "system/api-token", Namespace: "payments"})
	foreign := secretObj("payments", "api-token", map[string]string{LabelKey: "api-token"}, map[string][]byte{DefaultDataKey: []byte("tenant's")})
	foreign.UID = "tenant-1"
	gvr := corev1.SchemeGroupVersion.WithResource("secrets")
	h.client.PrependReactor("delete", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		// Ours went away and someone else's took its name before the delete.
		if err := h.client.Tracker().Delete(gvr, "payments", "api-token"); err != nil {
			return true, nil, err
		}
		if err := h.client.Tracker().Add(foreign); err != nil {
			return true, nil, err
		}
		return true, nil, apierrors.NewNotFound(corev1.Resource("secrets"), "api-token")
	})
	h.r.Sweep(context.Background())
	var creates int
	for _, v := range h.verbs() {
		switch v {
		case "create/secrets":
			creates++
		case "update/secrets":
			t.Fatalf("the foreign Secret drew an update: %v", h.verbs())
		}
	}
	if creates != 1 {
		t.Fatalf("a NotFound delete drew %d creates, want 1: %v", creates, h.verbs())
	}
	if got := h.secret(t, "payments", "api-token"); got.UID != "tenant-1" || string(got.Data[DefaultDataKey]) != "tenant's" {
		t.Fatalf("the foreign Secret was overwritten: uid %q data %q", got.UID, got.Data[DefaultDataKey])
	}
	st, err := ReadState(filepath.Join(h.dir, StateFileName), OpenNoFollow, StateDirCheck(uint32(os.Geteuid())), StateFileCheck(uint32(os.Geteuid())))
	if err != nil || st.UID("payments", "api-token") == "tenant-1" {
		t.Fatalf("the foreign UID was recorded (%q, %v)", st.UID("payments", "api-token"), err)
	}
}
