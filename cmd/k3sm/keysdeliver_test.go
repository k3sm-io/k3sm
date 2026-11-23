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

package main

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/addons"
	"k3sm.io/k3sm/pkg/keystore"
	keydeliver "k3sm.io/k3sm/pkg/keystore/deliver"
)

// keysTestDeliveryCheck is the declaration check with the test user standing
// in for root, as a non-root test cannot make a root-owned file; the mode
// check is the real one.
func keysTestDeliveryCheck(fi fs.FileInfo) error {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) == os.Geteuid() {
		return addons.NotShared(fi)
	}
	return addons.RootOwnedNotShared(fi)
}

// declarationPath is the declaration in the harness's data root.
func (h *keysHarness) declarationPath() string {
	return filepath.Join(filepath.Dir(h.work), keydeliver.FileName)
}

func (h *keysHarness) declaration() keydeliver.Declaration {
	h.t.Helper()
	b, err := os.ReadFile(h.declarationPath())
	if err != nil {
		h.t.Fatal(err)
	}
	d, err := keydeliver.Parse(b)
	if err != nil {
		h.t.Fatalf("the CLI wrote a declaration the reconciler refuses: %v\n%s", err, b)
	}
	return d
}

// TestKeysDeliverWritesDeclaration: deliver writes the declaration at 0644
// with the defaults stated, adds a second target beside the first, and
// replaces a target naming the same Secret.
func TestKeysDeliverWritesDeclaration(t *testing.T) {
	h := newKeysHarness(t)
	h.put("system/signer-key", []byte("v1"))
	h.mustRun(keysOK, "deliver", "system/signer-key", "--namespace", "payments")
	if !strings.Contains(h.stdout.String(), "declared delivery of system/signer-key as Secret payments/signer-key (data key value)") {
		t.Fatalf("stdout: %s", h.stdout.String())
	}
	fi, err := os.Lstat(h.declarationPath())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode() != keydeliver.FileMode {
		t.Fatalf("declaration mode %v, want %v", fi.Mode(), keydeliver.FileMode)
	}
	want := []keydeliver.Target{{Entry: "system/signer-key", Namespace: "payments", SecretName: "signer-key", DataKey: "value"}}
	if got := h.declaration().Targets; !slices.Equal(got, want) {
		t.Fatalf("targets %+v, want %+v", got, want)
	}

	h.mustRun(keysOK, "deliver", "system/signer-key", "--namespace", "ops", "--secret", "signer", "--data-key", "private.key")
	h.mustRun(keysOK, "deliver", "system/signer-key", "--namespace", "payments", "--data-key", "key")
	if !strings.Contains(h.stdout.String(), "replaced the declaration for") {
		t.Fatalf("a second deliver to the same Secret did not say it replaced: %s", h.stdout.String())
	}
	want = []keydeliver.Target{
		{Entry: "system/signer-key", Namespace: "payments", SecretName: "signer-key", DataKey: "key"},
		{Entry: "system/signer-key", Namespace: "ops", SecretName: "signer", DataKey: "private.key"},
	}
	if got := h.declaration().Targets; !slices.Equal(got, want) {
		t.Fatalf("targets %+v, want %+v", got, want)
	}
}

// TestKeysDeliverEncryptionOffNote: on a data root where encryption is off,
// deliver still declares the target and prints the refusal the server will
// make, "unless the server was started with the override"; with encryption
// on it prints none.
func TestKeysDeliverEncryptionOffNote(t *testing.T) {
	h := newKeysHarness(t)
	h.put("system/api-token", []byte("tok"))
	h.mustRun(keysOK, "deliver", "system/api-token", "--namespace", "payments")
	if strings.Contains(h.stderr.String(), "encryption is off") {
		t.Fatalf("encryption on, but deliver warned: %s", h.stderr.String())
	}
	h.encryptionOff = true
	h.mustRun(keysOK, "deliver", "system/api-token", "--namespace", "ops")
	for _, want := range []string{"unless the server was started with the override", "--allow-plaintext-secrets-delivery"} {
		if !strings.Contains(h.stderr.String(), want) {
			t.Errorf("deliver with encryption off does not say %q: %s", want, h.stderr.String())
		}
	}
	if n := len(h.declaration().Targets); n != 2 {
		t.Fatalf("the declaration holds %d targets, want 2: the note does not stop the declaration", n)
	}
}

// TestKeysUndeliver: undeliver removes only the targets of that entry in that
// namespace, prints that the Secret stays, and refuses a target that is not
// declared.
func TestKeysUndeliver(t *testing.T) {
	h := newKeysHarness(t)
	h.put("system/api-token", []byte("tok"))
	h.mustRun(keysOK, "deliver", "system/api-token", "--namespace", "payments")
	h.mustRun(keysOK, "deliver", "system/api-token", "--namespace", "ops")
	h.mustRun(keysOK, "undeliver", "system/api-token", "--namespace", "payments")
	if !strings.Contains(h.stdout.String(), keysUndeliverHint) {
		t.Fatalf("undeliver does not print %q: %s", keysUndeliverHint, h.stdout.String())
	}
	want := []keydeliver.Target{{Entry: "system/api-token", Namespace: "ops", SecretName: "api-token", DataKey: "value"}}
	if got := h.declaration().Targets; !slices.Equal(got, want) {
		t.Fatalf("targets %+v, want %+v", got, want)
	}
	h.mustRun(keysRefused, "undeliver", "system/api-token", "--namespace", "payments")
	if !strings.Contains(h.stderr.String(), "no delivery of system/api-token is declared") {
		t.Fatalf("stderr: %s", h.stderr.String())
	}
}

// TestKeysDeliverRefusals: both verbs require root; deliver requires
// --namespace and an existing entry; a bad flag value is refused without
// being echoed; a declaration the reconciler would refuse is refused and
// left as it is, with its path scrubbed.
func TestKeysDeliverRefusals(t *testing.T) {
	h := newKeysHarness(t)
	h.put("system/api-token", []byte("tok"))
	cases := []struct {
		name   string
		euid   int
		args   []string
		want   int
		stderr string
	}{
		{"deliver not root", 501, []string{"deliver", "system/api-token", "--namespace", "p"}, keysRefused, "run as root"},
		{"undeliver not root", 501, []string{"undeliver", "system/api-token", "--namespace", "p"}, keysRefused, "run as root"},
		{"no namespace", 0, []string{"deliver", "system/api-token"}, keysBadUsage, "--namespace is required"},
		{"undeliver no namespace", 0, []string{"undeliver", "system/api-token"}, keysBadUsage, "--namespace is required"},
		{"bad namespace", 0, []string{"deliver", "system/api-token", "--namespace", "SECRET_VALUE"}, keysBadUsage, "namespace is not a valid"},
		{"bad secret name", 0, []string{"deliver", "system/api-token", "--namespace", "p", "--secret", "SECRET_VALUE"}, keysBadUsage, "secretName is not a valid"},
		{"bad data key", 0, []string{"deliver", "system/api-token", "--namespace", "p", "--data-key", "SECRET/VALUE"}, keysBadUsage, "dataKey is not a valid"},
		{"missing entry", 0, []string{"deliver", "system/absent", "--namespace", "p"}, keysRefused, "deliver only an existing entry"},
		{"user scope", 0, []string{"deliver", "user/x", "--namespace", "p"}, keysRefused, "user scopes are not supported"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h.euid = tc.euid
			h.mustRun(tc.want, tc.args...)
			got := h.stderr.String()
			if !strings.Contains(got, tc.stderr) {
				t.Fatalf("stderr %q does not say %q", got, tc.stderr)
			}
			if strings.Contains(got, "SECRET") {
				t.Fatalf("stderr echoes a flag value: %q", got)
			}
			if _, err := os.Lstat(h.declarationPath()); err == nil {
				t.Fatal("a refused verb wrote the declaration")
			}
		})
	}

	t.Run("refused declaration", func(t *testing.T) {
		h.euid = 0
		raw := []byte(`{"version":1,"targets":[]}`)
		if err := os.WriteFile(h.declarationPath(), raw, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(h.declarationPath(), 0o666); err != nil {
			t.Fatal(err)
		}
		for _, verb := range []string{"deliver", "undeliver"} {
			h.mustRun(keysRefused, verb, "system/api-token", "--namespace", "p")
			got := h.stderr.String()
			if !strings.Contains(got, "group- or other-writable") || strings.Contains(got, filepath.Dir(h.work)) {
				t.Fatalf("%s: stderr %q: want the refusal with the data root scrubbed", verb, got)
			}
			if b, err := os.ReadFile(h.declarationPath()); err != nil || string(b) != string(raw) {
				t.Fatalf("%s rewrote a refused declaration: %q, %v", verb, b, err)
			}
		}
	})
}

// TestKeysDeliverWritersSerialize: two deliver runs at once both land. The
// first is parked between its read and its write of the declaration; the
// second is let go as soon as it either reads (no lock: it reads the stale
// file, and one target is lost) or finds the lock held; once the first has
// written, the second retries, reads both, and writes both (G19).
func TestKeysDeliverWritersSerialize(t *testing.T) {
	h := newKeysHarness(t)
	h.put("system/api-token", []byte("tok"))
	h.euid = 0
	uid, gid := keysServiceIDs(t)
	floorUID, floorGID := keysFloorIDs()
	env := func(stdout, stderr *bytes.Buffer, read func(), busy func() <-chan time.Time) keysEnv {
		return keysEnv{
			euid:       func() int { return 0 },
			serviceIDs: func() (uint32, uint32, error) { return uid, gid, nil },
			open: func(cfg keystore.Config) keysStore {
				cfg.FloorUID, cfg.FloorGID = floorUID, floorGID
				return keystore.New(cfg)
			},
			stdin:            strings.NewReader(""),
			stdinTTY:         func() bool { return false },
			stdoutTTY:        func() bool { return false },
			deliveryCheck:    keysTestDeliveryCheck,
			deliveryChown:    func(*os.File) error { return nil },
			encryptionOn:     func(string) bool { return true },
			deliveryLockBusy: busy,
			deliveryRead:     read,
			stdout:           stdout,
			stderr:           stderr,
		}
	}
	var (
		readA, goA, doneA = make(chan struct{}), make(chan struct{}), make(chan struct{})
		bReady            = make(chan struct{})
		aWritten          = make(chan time.Time) // closed with doneA, as a lock retry's wait
		bOnce             sync.Once
		codeA, codeB      int
		outA, errA        bytes.Buffer
		outB, errB        bytes.Buffer
	)
	signalB := func() { bOnce.Do(func() { close(bReady) }) }
	envA := env(&outA, &errA, func() { close(readA); <-goA }, nil)
	envB := env(&outB, &errB, signalB, func() <-chan time.Time { signalB(); return aWritten })
	go func() {
		defer close(doneA)
		defer close(aWritten)
		codeA = runKeysWith(context.Background(), []string{"deliver", "system/api-token", "--namespace", "payments", "--work-dir", h.work}, envA)
	}()
	<-readA
	doneB := make(chan struct{})
	go func() {
		defer close(doneB)
		codeB = runKeysWith(context.Background(), []string{"deliver", "system/api-token", "--namespace", "ops", "--work-dir", h.work}, envB)
	}()
	<-bReady
	close(goA)
	<-doneA
	<-doneB
	if codeA != keysOK || codeB != keysOK {
		t.Fatalf("exit %d and %d\nA: %s\nB: %s", codeA, codeB, errA.String(), errB.String())
	}
	var got []string
	for _, tg := range h.declaration().Targets {
		got = append(got, tg.Namespace)
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"ops", "payments"}) {
		t.Fatalf("declared namespaces %v, want both writers' (ops, payments)", got)
	}
}

// TestKeysRmWarnsDeclared: rm of an entry still declared for delivery warns
// once per declared target, naming the namespace and Secret and what happens,
// and prints no path and no value; an undeclared entry draws no warning.
func TestKeysRmWarnsDeclared(t *testing.T) {
	h := newKeysHarness(t)
	value := []byte("rm-warn-secret-value")
	h.put("system/api-token", value)
	h.put("system/other", []byte("other-secret-value"))
	h.mustRun(keysOK, "deliver", "system/api-token", "--namespace", "payments")
	h.mustRun(keysOK, "deliver", "system/api-token", "--namespace", "ops", "--secret", "tok")
	h.mustRun(keysOK, "deliver", "system/other", "--namespace", "payments")
	h.mustRun(keysOK, "rm", "system/api-token", "--yes")
	errOut := h.stderr.String()
	for _, want := range []string{
		"system/api-token is still declared for delivery to payments/api-token; the server deletes that Secret on its next sweep, unless the delivery breaker or a restore hold stops it; the server log says so; running `k3sm keys undeliver` does not change that",
		"still declared for delivery to ops/tok",
	} {
		if !strings.Contains(errOut, want) {
			t.Errorf("rm does not warn %q\n%s", want, errOut)
		}
	}
	if strings.Contains(errOut, "payments/other") {
		t.Errorf("rm warned about another entry's target\n%s", errOut)
	}
	out := h.stdout.String() + errOut
	for _, leak := range []string{string(value), filepath.Dir(h.work), keydeliver.FileName} {
		if strings.Contains(out, leak) {
			t.Fatalf("rm printed %q\n%s", leak, out)
		}
	}
	h.put("system/fresh", []byte("x"))
	h.mustRun(keysOK, "rm", "system/fresh", "--yes")
	if h.stderr.Len() != 0 {
		t.Fatalf("rm of an undeclared entry warned: %s", h.stderr.String())
	}
}

// TestKeysDeliveryPrintsNoValue: the delivery verbs, and rm of a declared
// entry, print no stored value on stdout or stderr, with encryption on or
// off.
func TestKeysDeliveryPrintsNoValue(t *testing.T) {
	h := newKeysHarness(t)
	value := []byte("delivery-cli-secret-value")
	h.put("system/api-token", value)
	var out strings.Builder
	runs := [][]string{
		{"deliver", "system/api-token", "--namespace", "payments"},
		{"deliver", "system/api-token", "--namespace", "payments", "--data-key", "token"},
		{"undeliver", "system/api-token", "--namespace", "payments"},
		{"undeliver", "system/api-token", "--namespace", "payments"},
		{"deliver", "system/api-token", "--namespace", "Bad_NS"},
		{"deliver", "system/api-token", "--namespace", "ops"},
		{"rm", "system/api-token", "--yes"},
	}
	for i, args := range runs {
		h.encryptionOff = i%2 == 1
		h.run(args...)
		out.WriteString(h.stdout.String())
		out.WriteString(h.stderr.String())
	}
	if !strings.Contains(out.String(), "still declared for delivery") {
		t.Fatalf("the runs did not reach rm's warning:\n%s", out.String())
	}
	if strings.Contains(out.String(), string(value)) {
		t.Fatalf("a delivery verb printed the value:\n%s", out.String())
	}
}

// TestKeysUndeliverSecret: undeliver --secret withdraws only the delivery
// into that Secret, and the old --secret-name flag is gone.
func TestKeysUndeliverSecret(t *testing.T) {
	h := newKeysHarness(t)
	h.put("system/api-token", []byte("tok"))
	h.mustRun(keysOK, "deliver", "system/api-token", "--namespace", "payments")
	h.mustRun(keysOK, "deliver", "system/api-token", "--namespace", "payments", "--secret", "tok")
	h.mustRun(keysOK, "undeliver", "system/api-token", "--namespace", "payments", "--secret", "tok")
	want := []keydeliver.Target{{Entry: "system/api-token", Namespace: "payments", SecretName: "api-token", DataKey: "value"}}
	if got := h.declaration().Targets; !slices.Equal(got, want) {
		t.Fatalf("targets %+v, want %+v", got, want)
	}
	h.mustRun(keysRefused, "undeliver", "system/api-token", "--namespace", "payments", "--secret", "tok")
	h.mustRun(keysBadUsage, "deliver", "system/api-token", "--namespace", "payments", "--secret-name", "x")
}
