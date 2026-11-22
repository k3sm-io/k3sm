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
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"testing/iotest"

	"k3sm.io/k3sm/pkg/keystore"
)

// keysRecorder passes every call to the store it wraps, the real
// *keystore.FileStore, and records the method's name, so a test can check
// which calls a verb made and in what order.
type keysRecorder struct {
	keysStore
	calls *[]string
}

func (r keysRecorder) note(m string) { *r.calls = append(*r.calls, m) }

func (r keysRecorder) Put(ctx context.Context, name string, kind keystore.Kind, value []byte) (keystore.Version, error) {
	r.note("Put")
	return r.keysStore.Put(ctx, name, kind, value)
}

func (r keysRecorder) Current(ctx context.Context, name string) (keystore.Version, []byte, error) {
	r.note("Current")
	return r.keysStore.Current(ctx, name)
}

func (r keysRecorder) Get(ctx context.Context, name string, n uint64) (keystore.Version, []byte, error) {
	r.note("Get")
	return r.keysStore.Get(ctx, name, n)
}

func (r keysRecorder) List(ctx context.Context) ([]keystore.Entry, error) {
	r.note("List")
	return r.keysStore.List(ctx)
}

func (r keysRecorder) Rotate(ctx context.Context, name string, value []byte) (keystore.Version, error) {
	r.note("Rotate")
	return r.keysStore.Rotate(ctx, name, value)
}

func (r keysRecorder) Delete(ctx context.Context, name string) error {
	r.note("Delete")
	return r.keysStore.Delete(ctx, name)
}

func (r keysRecorder) Rewrap(ctx context.Context, newMaster []byte) error {
	r.note("Rewrap")
	return r.keysStore.Rewrap(ctx, newMaster)
}

func (r keysRecorder) RaiseFloor(ctx context.Context) error {
	r.note("RaiseFloor")
	return r.keysStore.RaiseFloor(ctx)
}

// keysHarness runs the keys verbs against the real *keystore.FileStore over
// a t.TempDir() data root, laid out as pkg/keystore's tests lay it out: the
// data root and the floor owned by keysFloorIDs, the server work dir inside
// it handed to the service user (keysServiceIDs).
type keysHarness struct {
	t    *testing.T
	work string
	// cfg is the Config the verb built from the install layout; storeCfg is
	// the one the store was opened with, cfg with the test's floor owner.
	cfg, storeCfg keystore.Config
	// wrap, when set, replaces the store the verbs get; nil is the real
	// store. Each test that sets it says why the real store will not do.
	wrap      func(keysStore) keysStore
	calls     []string
	euid      int
	stdin     io.Reader
	stdinTTY  bool
	stdoutTTY bool
	rand      io.Reader
	// keyOutStep, when set, is the verb's keyOutStep seam.
	keyOutStep func(string) error
	// encryptionOff is what the verbs' encryptionOn seam answers, negated.
	encryptionOff bool
	stdout        bytes.Buffer
	stderr        bytes.Buffer
}

func newKeysHarness(t *testing.T) *keysHarness {
	t.Helper()
	keysServiceIDs(t) // a root run without a service user skips here
	work := filepath.Join(t.TempDir(), "server")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	keysGiveToService(t, work)
	return &keysHarness{
		t:     t,
		work:  work,
		stdin: strings.NewReader(""),
		rand:  bytes.NewReader(bytes.Repeat([]byte{0xA5}, 64)),
	}
}

// run runs `k3sm keys <args> --work-dir <work>` and returns the exit code;
// args that name --work-dir themselves keep theirs. The buffers hold that
// run's output only.
func (h *keysHarness) run(args ...string) int {
	h.t.Helper()
	h.stdout.Reset()
	h.stderr.Reset()
	uid, gid := keysServiceIDs(h.t)
	env := keysEnv{
		euid:       func() int { return h.euid },
		serviceIDs: func() (uint32, uint32, error) { return uid, gid, nil },
		open: func(cfg keystore.Config) keysStore {
			h.cfg = cfg
			// Non-root, a test cannot create a root-owned file, so the test
			// user stands in for root as the floor's owner.
			h.storeCfg = cfg
			h.storeCfg.FloorUID, h.storeCfg.FloorGID = keysFloorIDs()
			var s keysStore = keystore.New(h.storeCfg)
			if h.wrap != nil {
				s = h.wrap(s)
			}
			return keysRecorder{keysStore: s, calls: &h.calls}
		},
		stdin:      h.stdin,
		stdinTTY:   func() bool { return h.stdinTTY },
		stdoutTTY:  func() bool { return h.stdoutTTY },
		rand:       h.rand,
		keyOutStep: h.keyOutStep,
		// Non-root, the test user stands in for root as the declaration's
		// owner, and the declaration cannot be handed to root.
		deliveryCheck: keysTestDeliveryCheck,
		deliveryChown: func(*os.File) error { return nil },
		encryptionOn:  func(string) bool { return !h.encryptionOff },
		stdout:        &h.stdout,
		stderr:        &h.stderr,
	}
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") && args[0] != "help" && !slices.Contains(args, "--work-dir") {
		args = append(slices.Clone(args), "--work-dir", h.work)
	}
	return runKeysWith(context.Background(), args, env)
}

func (h *keysHarness) mustRun(want int, args ...string) {
	h.t.Helper()
	if got := h.run(args...); got != want {
		h.t.Fatalf("keys %v: exit %d, want %d\nstdout:\n%s\nstderr:\n%s", args, got, want, h.stdout.String(), h.stderr.String())
	}
}

func (h *keysHarness) put(name string, value []byte) {
	h.t.Helper()
	h.stdin = bytes.NewReader(value)
	h.mustRun(0, "put", name, "--in", "-")
}

// keystoreDir is the entries' directory the verbs use.
func (h *keysHarness) keystoreDir() string { return filepath.Join(h.work, "keystore") }

// value reads version n of name back through a second real store over the
// same files, not through the verbs.
func (h *keysHarness) value(name string, n uint64) []byte {
	h.t.Helper()
	if h.storeCfg.Dir == "" {
		h.t.Fatal("no verb has opened the store yet")
	}
	_, v, err := keystore.New(h.storeCfg).Get(context.Background(), name, n)
	if err != nil {
		h.t.Fatalf("read %s v%d from the store: %v", name, n, err)
	}
	return v
}

// masterFile returns the master key file's bytes.
func (h *keysHarness) masterFile() []byte {
	h.t.Helper()
	b, err := os.ReadFile(filepath.Join(h.work, "cred", "keystore-master", "master"))
	if err != nil {
		h.t.Fatal(err)
	}
	return b
}

// damageRecord flips the last byte of one record file of an entry, as a disk
// error or an edit would, keeping its owner and mode.
func (h *keysHarness) damageRecord(name, file string) {
	h.t.Helper()
	p := filepath.Join(h.keystoreDir(), name, file)
	b, err := os.ReadFile(p)
	if err != nil {
		h.t.Fatal(err)
	}
	if len(b) == 0 {
		h.t.Fatalf("%s is empty", p)
	}
	b[len(b)-1] ^= 0xff
	f, err := os.OpenFile(p, os.O_WRONLY, 0)
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := f.WriteAt(b, 0); err != nil {
		h.t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		h.t.Fatal(err)
	}
}

// failReader fails the test if anything reads it: a verb that must not read
// stdin is given one.
type failReader struct{ t *testing.T }

func (r failReader) Read([]byte) (int, error) {
	r.t.Error("stdin was read")
	return 0, io.EOF
}

func TestKeysRotateFromVersionNoValueOut(t *testing.T) {
	h := newKeysHarness(t)
	v1 := []byte("alpha-secret-value\n")
	v2 := []byte("beta-secret-value")
	h.put("system/signer", v1)
	h.stdin = bytes.NewReader(v2)
	h.mustRun(0, "rotate", "system/signer", "--in", "-")

	h.stdin = failReader{t}
	h.mustRun(0, "rotate", "system/signer", "--from-version", "1")
	if got := h.value("signer", 3); !bytes.Equal(got, v1) {
		t.Fatalf("version 3 = %q, want version 1's bytes %q", got, v1)
	}
	if got := h.value("signer", 2); !bytes.Equal(got, v2) {
		t.Fatalf("version 2 = %q, want %q", got, v2)
	}
	out := h.stdout.String() + h.stderr.String()
	for _, secret := range [][]byte{v1, bytes.TrimSpace(v1), v2} {
		if strings.Contains(out, string(secret)) {
			t.Fatalf("rotate --from-version printed a value: %q", out)
		}
	}
	if !strings.Contains(h.stdout.String(), "version 3") {
		t.Errorf("rotate --from-version output %q does not name the new version", h.stdout.String())
	}
	h.mustRun(0, "list", "-o", "json")
	var doc struct {
		Entries []struct {
			Version  uint64 `json:"version"`
			Versions int    `json:"versions"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(h.stdout.Bytes(), &doc); err != nil {
		t.Fatalf("list -o json: %v\n%s", err, h.stdout.String())
	}
	if len(doc.Entries) != 1 || doc.Entries[0].Version != 3 || doc.Entries[0].Versions != 3 {
		t.Fatalf("list after rotate --from-version = %+v, want version 3 of 3", doc.Entries)
	}

	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"absent version", []string{"rotate", "system/signer", "--from-version", "9"}, 1},
		{"version zero", []string{"rotate", "system/signer", "--from-version", "0"}, 2},
		{"with --in", []string{"rotate", "system/signer", "--from-version", "1", "--in", "-"}, 2},
		{"absent entry", []string{"rotate", "system/nope", "--from-version", "1"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h.stdin = failReader{t}
			h.mustRun(tc.want, tc.args...)
		})
	}
}

// rfc3339UTC matches the created column: second precision, in UTC.
var rfc3339UTC = regexp.MustCompile(`\b\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\b`)

func TestKeysListCorruptExitsOne(t *testing.T) {
	h := newKeysHarness(t)
	h.put("system/alpha", []byte("a"))
	h.put("system/beta", []byte("b"))
	h.mustRun(0, "list")
	if !strings.Contains(h.stdout.String(), "system/alpha") || !rfc3339UTC.MatchString(h.stdout.String()) {
		t.Fatalf("list output lacks the name or the UTC created time:\n%s", h.stdout.String())
	}

	h.damageRecord("beta", "v1")
	h.calls = nil
	h.mustRun(1, "list")
	if i, j := slices.Index(h.calls, "RaiseFloor"), slices.Index(h.calls, "List"); i < 0 || i > j {
		t.Errorf("list calls %v: RaiseFloor must come before List", h.calls)
	}
	var alpha, beta string
	for _, l := range strings.Split(h.stdout.String(), "\n") {
		switch {
		case strings.HasPrefix(l, "system/alpha"):
			alpha = l
		case strings.HasPrefix(l, "system/beta"):
			beta = l
		}
	}
	if !strings.Contains(alpha, " ok") {
		t.Errorf("healthy entry line %q is not ok", alpha)
	}
	_, _, storeErr := keystore.New(h.storeCfg).Current(context.Background(), "beta")
	if !errors.Is(storeErr, keystore.ErrCorrupt) {
		t.Fatalf("the damaged entry opens: %v, want ErrCorrupt", storeErr)
	}
	if !strings.Contains(beta, "corrupt: ") || !strings.Contains(beta, "version 1: ") || !strings.Contains(beta, "does not authenticate") {
		t.Errorf("damaged entry line %q lacks corrupt and the store's message naming the record", beta)
	}

	h.mustRun(1, "list", "-o", "json")
	var doc struct {
		Entries []struct {
			Name    string `json:"name"`
			Version uint64 `json:"version"`
			Created string `json:"created"`
			Status  string `json:"status"`
			Error   string `json:"error"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(h.stdout.Bytes(), &doc); err != nil {
		t.Fatalf("list -o json: %v\n%s", err, h.stdout.String())
	}
	if len(doc.Entries) != 2 || doc.Entries[0].Status != "ok" || doc.Entries[0].Version != 1 || !rfc3339UTC.MatchString(doc.Entries[0].Created) ||
		doc.Entries[1].Name != "system/beta" || doc.Entries[1].Status != "corrupt" || !strings.Contains(doc.Entries[1].Error, "does not authenticate") {
		t.Fatalf("list -o json = %+v", doc.Entries)
	}
	h.mustRun(2, "list", "-o", "yaml")
}

// keysFloorEntries returns the names the floor records, read from the file.
func (h *keysHarness) keysFloorEntries() map[string]json.RawMessage {
	h.t.Helper()
	b, err := os.ReadFile(filepath.Join(filepath.Dir(h.work), "keystore-floor.json"))
	if err != nil {
		h.t.Fatal(err)
	}
	var doc struct {
		Entries map[string]json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		h.t.Fatalf("the floor: %v\n%s", err, b)
	}
	return doc.Entries
}

// TestKeysRmCorruptEntry is G16's rm half through the CLI: an entry list
// reports corrupt is removed by rm, with its floor entry, and the healthy
// entry beside it is untouched.
func TestKeysRmCorruptEntry(t *testing.T) {
	h := newKeysHarness(t)
	h.put("system/alpha", []byte("a"))
	h.put("system/beta", []byte("b"))
	if _, ok := h.keysFloorEntries()["beta"]; !ok {
		t.Fatalf("the floor does not record beta: %v", h.keysFloorEntries())
	}
	h.damageRecord("beta", "current")
	h.mustRun(1, "list")
	if !strings.Contains(h.stdout.String(), "system/beta") || !strings.Contains(h.stdout.String(), "corrupt: ") {
		t.Fatalf("list does not report beta corrupt:\n%s", h.stdout.String())
	}
	h.mustRun(0, "rm", "system/beta", "--yes")
	if _, err := os.Lstat(filepath.Join(h.keystoreDir(), "beta")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the corrupt entry's directory after rm: %v", err)
	}
	floor := h.keysFloorEntries()
	if _, ok := floor["beta"]; ok {
		t.Fatalf("the floor still records beta after rm: %v", floor)
	}
	if _, ok := floor["alpha"]; !ok {
		t.Fatalf("rm took alpha's floor entry: %v", floor)
	}
	h.mustRun(0, "list")
	if strings.Contains(h.stdout.String(), "system/beta") || !strings.Contains(h.stdout.String(), "system/alpha") {
		t.Fatalf("list after rm:\n%s", h.stdout.String())
	}
	if got := h.value("alpha", 1); string(got) != "a" {
		t.Fatalf("alpha = %q", got)
	}
}

func TestKeysShowRevealByteExact(t *testing.T) {
	seed := bytes.Repeat([]byte{0x00, 0x0a, 0xff, 0x20}, 8)
	for _, tc := range []struct {
		name  string
		kind  string
		value []byte
		next  []byte
	}{
		{"opaque with trailing newline", "opaque", []byte("token\n"), []byte("other")},
		{"opaque binary", "opaque", []byte{0x00, 0x01, '\r', '\n', 0xfe}, []byte("other")},
		{"ed25519 seed 32 bytes", "ed25519", seed, bytes.Repeat([]byte{0x7e}, ed25519.SeedSize)},
		{"ed25519 expanded 64 bytes", "ed25519", ed25519.NewKeyFromSeed(seed), ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x7e}, ed25519.SeedSize))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newKeysHarness(t)
			h.stdin = bytes.NewReader(tc.value)
			h.mustRun(0, "put", "system/k", "--kind", tc.kind, "--in", "-")
			rec, err := os.ReadFile(filepath.Join(h.keystoreDir(), "k", "v1"))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(rec, tc.value) {
				t.Fatalf("the record on disk holds the value in the clear: %x", rec)
			}
			h.calls = nil
			h.mustRun(0, "show", "system/k", "--reveal")
			if !bytes.Equal(h.stdout.Bytes(), tc.value) {
				t.Fatalf("show --reveal wrote %q, want exactly %q", h.stdout.Bytes(), tc.value)
			}
			if i, j := slices.Index(h.calls, "RaiseFloor"), slices.Index(h.calls, "Current"); i < 0 || i > j {
				t.Errorf("show calls %v: RaiseFloor must come before Current", h.calls)
			}
			h.stdin = bytes.NewReader(tc.next)
			h.mustRun(0, "rotate", "system/k", "--in", "-")
			h.mustRun(0, "show", "system/k", "--version", "1", "--reveal")
			if !bytes.Equal(h.stdout.Bytes(), tc.value) {
				t.Fatalf("show --version 1 --reveal wrote %q, want exactly %q", h.stdout.Bytes(), tc.value)
			}
			h.mustRun(0, "show", "system/k")
			if bytes.Contains(h.stdout.Bytes(), tc.value) || bytes.Contains(h.stdout.Bytes(), tc.next) {
				t.Fatalf("show without --reveal printed the value:\n%s", h.stdout.String())
			}
			if !strings.Contains(h.stdout.String(), "system/k") || !strings.Contains(h.stdout.String(), "version:     2") ||
				!strings.Contains(h.stdout.String(), "kind:        "+tc.kind) {
				t.Fatalf("show metadata lacks the name, version or kind:\n%s", h.stdout.String())
			}
		})
	}
}

// TestKeysShowMetadataOnly: show without --reveal never asks the store for a
// value (no Current, no Get: the metadata comes from List) and prints no
// size, for the current version and for an older one.
func TestKeysShowMetadataOnly(t *testing.T) {
	h := newKeysHarness(t)
	h.put("system/k", []byte("first-value"))
	h.stdin = bytes.NewReader([]byte("second-value-longer"))
	h.mustRun(0, "rotate", "system/k", "--in", "-")
	for _, tc := range []struct {
		args    []string
		version string
	}{
		{[]string{"show", "system/k"}, "version:     2"},
		{[]string{"show", "system/k", "--version", "1"}, "version:     1"},
	} {
		h.calls = nil
		h.mustRun(0, tc.args...)
		if slices.Contains(h.calls, "Current") || slices.Contains(h.calls, "Get") {
			t.Errorf("%v calls %v: it fetched the value", tc.args, h.calls)
		}
		if i, j := slices.Index(h.calls, "RaiseFloor"), slices.Index(h.calls, "List"); i < 0 || i > j {
			t.Errorf("%v calls %v: RaiseFloor must come before List", tc.args, h.calls)
		}
		out := h.stdout.String()
		if strings.Contains(out, "size") || strings.Contains(out, "bytes") {
			t.Errorf("%v printed the value's size:\n%s", tc.args, out)
		}
		if !strings.Contains(out, tc.version) || !strings.Contains(out, "fingerprint: ") {
			t.Errorf("%v metadata lacks %q or the fingerprint:\n%s", tc.args, tc.version, out)
		}
	}
	h.mustRun(1, "show", "system/k", "--version", "3")
	h.mustRun(1, "show", "system/absent")
	h.damageRecord("k", "v1")
	h.mustRun(1, "show", "system/k", "--version", "2")
	if !strings.Contains(h.stderr.String(), "does not authenticate") {
		t.Errorf("show of a corrupt entry: stderr %q lacks the store's reason", h.stderr.String())
	}
}

// copyTree copies the directories and regular files under src to dst,
// keeping each one's owner and mode, as `ditto` does in the restore recipe
// (docs/user/keys.md). Anything else under src fails the test.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("%s: no owner", p)
		}
		to := filepath.Join(dst, rel)
		switch {
		case fi.IsDir():
			if err := os.Mkdir(to, 0o700); err != nil {
				return err
			}
		case fi.Mode().IsRegular():
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if err := os.WriteFile(to, b, 0o600); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s is %v, not a directory or a regular file", p, fi.Mode().Type())
		}
		if err := os.Chmod(to, fi.Mode().Perm()); err != nil {
			return err
		}
		return os.Lchown(to, int(st.Uid), int(st.Gid))
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestKeysRollbackRoundTrip is G21's CLI test: the rollback recipes in
// docs/user/keys.md run as written. A restore of a saved keystore/, with the
// floor saved beside it, brings a deleted entry back, and without the floor it
// is refused; and `show --version N --reveal` piped into `rotate --in -`
// stores a version whose value equals version N's byte for byte
// (bytes.Equal, the comparison cmp makes), for an opaque and an Ed25519 entry.
func TestKeysRollbackRoundTrip(t *testing.T) {
	// saveRmRestore saves keystore/ and the floor, rm's the entry, then
	// restores keystore/ as the recipe does, with the saved floor when
	// withFloor is set, and returns the entry's value and the moved-aside copy.
	saveRmRestore := func(t *testing.T, h *keysHarness, withFloor bool) ([]byte, string) {
		t.Helper()
		value := []byte("rollback\x00value\n")
		h.put("system/rb", value)
		backup := filepath.Join(t.TempDir(), "keystore")
		copyTree(t, h.keystoreDir(), backup)
		floor := filepath.Join(filepath.Dir(h.work), "keystore-floor.json")
		savedFloor, err := os.ReadFile(floor)
		if err != nil {
			t.Fatal(err)
		}
		h.mustRun(0, "rm", "system/rb", "--yes")
		h.mustRun(1, "show", "system/rb", "--reveal")
		// The recipe moves the live copy aside, never deletes it first.
		aside := h.keystoreDir() + ".pre-restore"
		if err := os.Rename(h.keystoreDir(), aside); err != nil {
			t.Fatal(err)
		}
		copyTree(t, backup, h.keystoreDir())
		if withFloor {
			// The floor saved with the backup goes back too, as root.
			tmp := floor + ".restore"
			if err := os.WriteFile(tmp, savedFloor, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(tmp, floor); err != nil {
				t.Fatal(err)
			}
		}
		return value, aside
	}
	t.Run("save rm restore", func(t *testing.T) {
		h := newKeysHarness(t)
		value, aside := saveRmRestore(t, h, true)
		h.mustRun(0, "list")
		h.mustRun(0, "show", "system/rb", "--reveal")
		if !bytes.Equal(h.stdout.Bytes(), value) {
			t.Fatalf("restored value = %q, want %q", h.stdout.Bytes(), value)
		}
		if err := os.RemoveAll(aside); err != nil {
			t.Fatal(err)
		}
	})
	// Without its floor, the restored entry is the deleted one put back, and
	// the floor's tombstone refuses it.
	t.Run("save rm restore without the floor is refused", func(t *testing.T) {
		h := newKeysHarness(t)
		saveRmRestore(t, h, false)
		h.mustRun(1, "list")
		h.mustRun(1, "show", "system/rb", "--reveal")
		if h.stdout.Len() != 0 {
			t.Fatalf("show printed %q for a refused entry", h.stdout.Bytes())
		}
		if msg := h.stderr.String(); !strings.Contains(msg, "the floor records as deleted") {
			t.Fatalf("show of an entry restored without its floor: %q, want the floor's refusal", msg)
		}
	})
	seed := bytes.Repeat([]byte{0x00, 0x0a, 0xff, 0x20}, 8)
	for _, tc := range []struct {
		kind          string
		first, second []byte
	}{
		{"opaque", []byte("first\n"), []byte("second")},
		{"ed25519", ed25519.NewKeyFromSeed(seed), bytes.Repeat([]byte{0x7e}, ed25519.SeedSize)},
	} {
		t.Run("show reveal piped into rotate, "+tc.kind, func(t *testing.T) {
			h := newKeysHarness(t)
			h.stdin = bytes.NewReader(tc.first)
			h.mustRun(0, "put", "system/rb", "--kind", tc.kind, "--in", "-")
			h.stdin = bytes.NewReader(tc.second)
			h.mustRun(0, "rotate", "system/rb", "--in", "-")
			h.mustRun(0, "show", "system/rb", "--version", "1", "--reveal")
			h.stdin = bytes.NewReader(slices.Clone(h.stdout.Bytes()))
			h.mustRun(0, "rotate", "system/rb", "--in", "-")
			v1, v3 := h.value("rb", 1), h.value("rb", 3)
			if !bytes.Equal(v3, v1) || !bytes.Equal(v1, tc.first) {
				t.Fatalf("version 3 = %x, version 1 = %x, want both exactly %x", v3, v1, tc.first)
			}
		})
	}
}

// TestKeysReadVerbsRaiseFloor is G7's CLI half: list, show and show --reveal
// raise the floor before they read. With root's record removed, as the
// restore procedure removes it, each one writes it again, and calls
// RaiseFloor before the read.
func TestKeysReadVerbsRaiseFloor(t *testing.T) {
	for _, tc := range []struct {
		args []string
		read string
	}{
		{[]string{"list"}, "List"},
		{[]string{"show", "system/f"}, "List"},
		{[]string{"show", "system/f", "--reveal"}, "Current"},
		{[]string{"show", "system/f", "--version", "1", "--reveal"}, "Get"},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			h := newKeysHarness(t)
			h.put("system/f", []byte("floor-value"))
			floor := filepath.Join(filepath.Dir(h.work), "keystore-floor.json")
			if err := os.Remove(floor); err != nil {
				t.Fatalf("put left no floor to remove: %v", err)
			}
			h.calls = nil
			h.mustRun(0, tc.args...)
			if _, err := os.Lstat(floor); err != nil {
				t.Fatalf("%v did not write the floor again: %v", tc.args, err)
			}
			if i, j := slices.Index(h.calls, "RaiseFloor"), slices.Index(h.calls, tc.read); i < 0 || j < 0 || i > j {
				t.Errorf("%v calls %v: RaiseFloor must come before %s", tc.args, h.calls, tc.read)
			}
		})
	}
}

func TestKeysRefusals(t *testing.T) {
	for _, tc := range []struct {
		name      string
		args      []string
		euid      int
		stdin     string
		stdinTTY  bool
		stdoutTTY bool
		want      int
		say       string
		never     string
		// reaches is set for a row refused by the store itself.
		reaches bool
	}{
		{name: "put not root", args: []string{"put", "system/a", "--in", "-"}, euid: 501, stdin: "v", want: 1, say: "sudo"},
		{name: "list not root", args: []string{"list"}, euid: 501, want: 1, say: "sudo"},
		{name: "show not root", args: []string{"show", "system/a"}, euid: 501, want: 1, say: "sudo"},
		{name: "rotate not root", args: []string{"rotate", "system/a", "--in", "-"}, euid: 501, stdin: "v", want: 1, say: "sudo"},
		{name: "rm not root", args: []string{"rm", "system/a", "--yes"}, euid: 501, want: 1, say: "sudo"},
		{name: "rewrap not root", args: []string{"rewrap", "--key-out", "k"}, euid: 501, want: 1, say: "sudo"},
		{name: "bare name", args: []string{"put", "signer-hunter2", "--in", "-"}, stdin: "v", want: 2, say: "system/<name>", never: "hunter2"},
		{name: "unknown scope not echoed", args: []string{"show", "team/hunter2"}, want: 2, say: "system/<name>", never: "hunter2"},
		{name: "nested name not echoed", args: []string{"show", "system/a/hunter2"}, want: 2, say: "system/<name>", never: "hunter2"},
		{name: "malformed name not echoed", args: []string{"show", "system/Hunter2+x="}, want: 2, say: "the entry name is not valid (DNS-1123 subdomain); it is not echoed", never: "Hunter2"},
		{name: "kind value not echoed", args: []string{"put", "system/a", "--kind", "Hunter2"}, stdin: "v", want: 2, say: "--kind", never: "Hunter2"},
		{name: "output value not echoed", args: []string{"list", "-o", "Hunter2"}, want: 2, say: "-o", never: "Hunter2"},
		{name: "flag package value not echoed", args: []string{"show", "system/a", "--version", "Hunter2"}, want: 2, say: "--version", never: "Hunter2"},
		{name: "unknown flag not echoed", args: []string{"show", "system/a", "--Hunter2"}, want: 2, say: "not defined", never: "Hunter2"},
		{name: "user scope", args: []string{"show", "user/501/signer"}, want: 1, say: "user scopes are not supported by this build"},
		{name: "unknown scope", args: []string{"show", "team/signer"}, want: 2, say: "system/<name>"},
		{name: "empty system name", args: []string{"show", "system/"}, want: 2, say: "system/<name>"},
		{name: "argv value on put", args: []string{"put", "system/a", "hunter2-secret"}, want: 2, say: "--in", never: "hunter2-secret"},
		{name: "argv value on rotate", args: []string{"rotate", "system/a", "hunter2-secret"}, want: 2, say: "--in", never: "hunter2-secret"},
		{name: "tty stdin on put", args: []string{"put", "system/a", "--in", "-"}, stdinTTY: true, want: 1, say: "terminal"},
		{name: "tty stdin on put default in", args: []string{"put", "system/a"}, stdinTTY: true, want: 1, say: "terminal"},
		{name: "value over the cap", args: []string{"put", "system/a", "--in", "-"}, stdin: strings.Repeat("x", keystore.MaxValueSize+1), want: 1, say: "limit"},
		{name: "reveal to a tty", args: []string{"show", "system/held", "--reveal"}, stdoutTTY: true, want: 1, say: "--yes"},
		{name: "rm without yes", args: []string{"rm", "system/held"}, want: 2, say: "--yes"},
		{name: "unknown verb", args: []string{"frob"}, want: 2, say: "unknown"},
		{name: "in path not echoed", args: []string{"put", "system/x", "--in", "Hunter2"}, want: 1, say: "open --in: no such file or directory (the path is not echoed)", never: "Hunter2"},
		{name: "key-in path not echoed", args: []string{"rewrap", "--key-in", "/tmp/Hunter2"}, want: 1, say: "open --key-in: no such file or directory (the path is not echoed)", never: "Hunter2"},
		{name: "key-out path not echoed", args: []string{"rewrap", "--key-out", "/nonexistent/Hunter2"}, want: 1, say: "--key-out: no such file or directory (the path is not echoed)", never: "Hunter2"},
		{name: "work dir in a list store error", args: []string{"list", "--work-dir", "/Hunter2/server"}, want: 1, say: "<data-root>", never: "Hunter2", reaches: true},
		{name: "work dir in a put store error", args: []string{"put", "system/x", "--work-dir", "/Hunter2/server"}, stdin: "v", want: 1, say: "<data-root>", never: "Hunter2", reaches: true},
		{name: "work dir beside a refused key-out", args: []string{"rewrap", "--key-out", "/tmp/k", "--work-dir", "/Hunter2/server"}, want: 1, say: "--key-out", never: "Hunter2"},
		{name: "unknown verb not echoed", args: []string{"Hunter2"}, want: 2, say: "unknown subcommand (not echoed); see k3sm keys --help", never: "Hunter2"},
		{name: "relative work dir not echoed", args: []string{"list", "--work-dir", "Hunter2"}, want: 1, say: "--work-dir", never: "Hunter2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newKeysHarness(t)
			h.put("system/held", []byte("held-secret"))
			h.calls = nil
			h.euid = tc.euid
			h.stdin = strings.NewReader(tc.stdin)
			h.stdinTTY, h.stdoutTTY = tc.stdinTTY, tc.stdoutTTY
			h.mustRun(tc.want, tc.args...)
			if !strings.Contains(h.stderr.String(), tc.say) {
				t.Errorf("stderr %q does not say %q", h.stderr.String(), tc.say)
			}
			out := h.stdout.String() + h.stderr.String()
			if tc.never != "" && strings.Contains(out, tc.never) {
				t.Errorf("output echoes %q: %q", tc.never, out)
			}
			if strings.Contains(out, "held-secret") {
				t.Errorf("output carries a stored value: %q", out)
			}
			for _, c := range h.calls {
				if !tc.reaches && c != "RaiseFloor" && c != "Current" && c != "Get" {
					t.Errorf("refused verb reached the store: %v", h.calls)
					break
				}
			}
		})
	}
	t.Run("work dir in a rewrap store error", func(t *testing.T) {
		h := newKeysHarness(t)
		p := filepath.Join(t.TempDir(), "k")
		h.mustRun(1, "rewrap", "--key-out", p, "--work-dir", "/Hunter2/server")
		if !slices.Contains(h.calls, "Rewrap") {
			t.Fatalf("rewrap did not reach the store: %v", h.calls)
		}
		if out := h.stdout.String() + h.stderr.String(); strings.Contains(out, "Hunter2") || !strings.Contains(out, "<") {
			t.Errorf("output echoes the work dir, or names no scrubbed root: %q", out)
		}
	})
	t.Run("absent entry names the validated name only", func(t *testing.T) {
		h := newKeysHarness(t)
		h.put("system/held", []byte("held-secret"))
		h.mustRun(1, "show", "system/absent")
		if want := "k3sm keys show: system/absent: keystore entry not found\n"; h.stderr.String() != want {
			t.Fatalf("stderr %q, want %q", h.stderr.String(), want)
		}
	})
	t.Run("reveal to a tty with yes", func(t *testing.T) {
		h := newKeysHarness(t)
		h.put("system/held", []byte("held-secret"))
		h.stdoutTTY = true
		h.mustRun(0, "show", "system/held", "--reveal", "--yes")
		if h.stdout.String() != "held-secret" {
			t.Fatalf("stdout = %q", h.stdout.String())
		}
	})
	t.Run("put from a file", func(t *testing.T) {
		h := newKeysHarness(t)
		p := filepath.Join(t.TempDir(), "value")
		if err := os.WriteFile(p, []byte("from-file\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		h.stdin, h.stdinTTY = failReader{t}, true
		h.mustRun(0, "put", "system/f", "--in", p)
		if got := h.value("f", 1); string(got) != "from-file\n" {
			t.Fatalf("stored %q", got)
		}
	})
	t.Run("help needs no root", func(t *testing.T) {
		h := newKeysHarness(t)
		h.euid = 501
		h.mustRun(0, "--help")
		for _, verb := range []string{"put", "list", "show", "rotate", "rm", "rewrap", "--from-version", "--key-out", "--key-in", "system/<name>"} {
			if !strings.Contains(h.stdout.String(), verb) {
				t.Errorf("usage lacks %q", verb)
			}
		}
	})
}

// TestKeysScrubPaths: scrubPaths replaces each root, its /private form and
// its resolved form with the root's token, a path inside another root with
// its own, only at a path boundary, and never "/".
func TestKeysScrubPaths(t *testing.T) {
	work := "/Hunter2/server"
	master := work + "/cred/keystore-master"
	data := "/Hunter2"
	err := fmt.Errorf("open %s/master: x; open %s/keystore/a: y; open /private%s/keystore-floor.json: z; open /etc/hosts", master, work, data)
	got := scrubPaths(err, work, master, data)
	want := "open <master-dir>/master: x; open <work-dir>/keystore/a: y; open <data-root>/keystore-floor.json: z; open /etc/hosts"
	if got != want {
		t.Fatalf("scrubPaths = %q, want %q", got, want)
	}
	for in, want := range map[string]string{
		"open /var/lib/k3sm/server2/x":      "open /var/lib/k3sm/server2/x",
		"open /var/lib/k3sm/server/x":       "open <work-dir>/x",
		"open /var/lib/k3sm/server: denied": "open <work-dir>: denied",
		"stat /var/lib/k3sm/server":         "stat <work-dir>",
		`"/var/lib/k3sm/server"`:            `"<work-dir>"`,
		"open /var/lib/k3sm/server.old/x":   "open /var/lib/k3sm/server.old/x",
	} {
		// The work dir alone: a sibling that shares its prefix is another path.
		if got := scrubPaths(errors.New(in), "/var/lib/k3sm/server"); got != want {
			t.Errorf("scrubPaths(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		// The data root is a real parent of the sibling, so it is replaced.
		"open /var/lib/k3sm/server2/x":        "open <data-root>/server2/x",
		"open /var/lib/k3sm/keystore-floor.x": "open <data-root>/keystore-floor.x",
		"open /var/lib/k3sm2/x":               "open /var/lib/k3sm2/x",
	} {
		if got := scrubPaths(errors.New(in), "/var/lib/k3sm/server", "/var/lib/k3sm/server/cred/keystore-master", "/var/lib/k3sm"); got != want {
			t.Errorf("scrubPaths(%q) = %q, want %q", in, got, want)
		}
	}
	if got := scrubPaths(errors.New("open /a/b"), "/a", "/a/m", "/"); got != "open <work-dir>/b" {
		t.Fatalf("scrubPaths with a / data root = %q", got)
	}
	dir := t.TempDir()
	real, rerr := filepath.EvalSymlinks(dir)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if got := scrubPaths(fmt.Errorf("open %s/x", real), dir); got != "open <work-dir>/x" {
		t.Fatalf("scrubPaths of the resolved path = %q", got)
	}
}

// TestKeysEntryStatusScrubs: a list row is scrubbed of the store's roots
// where it is built.
func TestKeysEntryStatusScrubs(t *testing.T) {
	work := "/Hunter2/server"
	e := keystore.Entry{Name: "a", Err: fmt.Errorf("open %s/keystore/a/v1: %w", work, keystore.ErrCorrupt)}
	r := keysEntryStatus(e, work, work+"/cred/keystore-master", "/Hunter2")
	if r.Status != "corrupt" || strings.Contains(r.Error, "Hunter2") || !strings.Contains(r.Error, "<work-dir>/keystore/a/v1") {
		t.Fatalf("keysEntryStatus = %+v, want a corrupt row with the work dir scrubbed", r)
	}
}

// TestKeysReadValueOneBuffer: readValue reads into one buffer of the cap plus
// one byte, allocated before the read, so the value it returns is that buffer
// and clearing it clears every copy; a reader that returns a byte at a time
// is read in full, and one over the cap is refused.
func TestKeysReadValueOneBuffer(t *testing.T) {
	read := func(r io.Reader) ([]byte, error) {
		var stderr bytes.Buffer
		env := keysEnv{stdin: r, stdinTTY: func() bool { return false }, stderr: &stderr}
		return newKeysVerb("put", env).readValue("-")
	}
	want := bytes.Repeat([]byte("v"), 3000)
	b, err := read(iotest.OneByteReader(bytes.NewReader(want)))
	if err != nil || !bytes.Equal(b, want) {
		t.Fatalf("readValue = %d bytes, %v; want the %d bytes", len(b), err, len(want))
	}
	if cap(b) != keystore.MaxValueSize+1 {
		t.Fatalf("the value's buffer has cap %d, want the one preallocated buffer of %d", cap(b), keystore.MaxValueSize+1)
	}
	over := bytes.Repeat([]byte("v"), keystore.MaxValueSize+1)
	if b, err := read(bytes.NewReader(over)); err == nil || b != nil {
		t.Fatalf("readValue over the cap = %d bytes, %v; want a refusal", len(b), err)
	}
	if _, err := read(iotest.ErrReader(errors.New("boom"))); err == nil {
		t.Fatal("readValue hid a read error")
	}
}

// TestKeysReadValueErrorNotEchoed: a read error from --in is reported as
// the flag and the errno class, never the path a wrapped fs.PathError
// carries.
func TestKeysReadValueErrorNotEchoed(t *testing.T) {
	var stderr bytes.Buffer
	env := keysEnv{
		stdin:    iotest.ErrReader(&fs.PathError{Op: "read", Path: "/Hunter2/value", Err: syscall.EIO}),
		stdinTTY: func() bool { return false },
		stderr:   &stderr,
	}
	_, err := newKeysVerb("put", env).readValue("-")
	if err == nil || strings.Contains(err.Error(), "Hunter2") || !strings.Contains(err.Error(), "read --in: input/output error (the path is not echoed)") {
		t.Fatalf("readValue = %v, want the flag and the errno class without the path", err)
	}
}

// TestKeysInFileChecks: --in FILE reads only a regular file, reached without
// following a symlink and without blocking on a FIFO, and warns when group or
// others can read or write it, or another user than root owns it.
func TestKeysInFileChecks(t *testing.T) {
	for name, mk := range map[string]func(t *testing.T, p string){
		"directory": func(t *testing.T, p string) {
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"fifo": func(t *testing.T, p string) {
			if err := syscall.Mkfifo(p, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(t *testing.T, p string) {
			target := p + ".target"
			if err := os.WriteFile(target, []byte("v"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, p); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run("refuses a "+name, func(t *testing.T) {
			h := newKeysHarness(t)
			p := filepath.Join(t.TempDir(), "value")
			mk(t, p)
			h.calls = nil
			h.mustRun(1, "put", "system/a", "--in", p)
			if slices.Contains(h.calls, "Put") {
				t.Fatal("put ran")
			}
		})
	}
	t.Run("warns on a group-readable file", func(t *testing.T) {
		h := newKeysHarness(t)
		p := filepath.Join(t.TempDir(), "value")
		if err := os.WriteFile(p, []byte("v"), 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o640); err != nil {
			t.Fatal(err)
		}
		h.mustRun(0, "put", "system/a", "--in", p)
		if !strings.Contains(h.stderr.String(), "group or others") {
			t.Errorf("stderr %q does not warn", h.stderr.String())
		}
	})
	for _, mode := range []fs.FileMode{0o620, 0o602} {
		t.Run(fmt.Sprintf("warns on a file at %04o", mode), func(t *testing.T) {
			h := newKeysHarness(t)
			p := filepath.Join(t.TempDir(), "value")
			if err := os.WriteFile(p, []byte("v"), mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(p, mode); err != nil {
				t.Fatal(err)
			}
			h.mustRun(0, "put", "system/a", "--in", p)
			if !strings.Contains(h.stderr.String(), "writable by group or others") {
				t.Errorf("stderr %q does not warn", h.stderr.String())
			}
		})
	}
	t.Run("warns on a file another user owns", func(t *testing.T) {
		// Only root can make a file another user owns; the root run of this
		// binary covers it.
		if !keysAsRoot() {
			t.Skip("needs root to give the file to another user")
		}
		h := newKeysHarness(t)
		p := filepath.Join(t.TempDir(), "value")
		if err := os.WriteFile(p, []byte("v"), 0o600); err != nil {
			t.Fatal(err)
		}
		keysGiveToService(t, p)
		h.mustRun(0, "put", "system/a", "--in", p)
		if !strings.Contains(h.stderr.String(), "not owned by root") {
			t.Errorf("stderr %q does not warn", h.stderr.String())
		}
	})
	t.Run("no warning on a root-only file", func(t *testing.T) {
		h := newKeysHarness(t)
		p := filepath.Join(t.TempDir(), "value")
		if err := os.WriteFile(p, []byte("v"), 0o600); err != nil {
			t.Fatal(err)
		}
		h.mustRun(0, "put", "system/a", "--in", p)
		if h.stderr.Len() != 0 {
			t.Errorf("stderr %q, want nothing", h.stderr.String())
		}
	})
}

func TestKeysStoreConfigFromLayout(t *testing.T) {
	h := newKeysHarness(t)
	h.mustRun(0, "list")
	uid, gid := keysServiceIDs(t)
	// The install layout's config leaves the floor's owner at root, 0:0.
	want := keystore.Config{
		Dir:       filepath.Join(h.work, "keystore"),
		MasterDir: filepath.Join(h.work, "cred", "keystore-master"),
		UID:       uid,
		GID:       gid,
		DataRoot:  filepath.Dir(h.work),
	}
	if h.cfg != want {
		t.Fatalf("store config = %+v, want %+v", h.cfg, want)
	}
	if h.cfg.FloorUID != 0 || h.cfg.FloorGID != 0 {
		t.Fatalf("store config names the floor owner %d:%d, want 0:0 (root)", h.cfg.FloorUID, h.cfg.FloorGID)
	}
}

// keysResumedStore forces ErrRewrapResumed from Rewrap and records the key it
// was given; every other call goes to the real store. The real store returns
// ErrRewrapResumed only after an earlier rewrap crashed with some record live
// under its key, a crash no seam outside pkg/keystore can stage.
type keysResumedStore struct {
	keysStore
	key []byte
}

func (s *keysResumedStore) Rewrap(_ context.Context, newMaster []byte) error {
	s.key = slices.Clone(newMaster)
	// As the store's own: a resume of another key sealed nothing under this
	// one (pkg/keystore's TestRewrapNotStarted).
	return fmt.Errorf("rewrap: %w (%w)", keystore.ErrRewrapResumed, keystore.ErrRewrapNotStarted)
}

func TestKeysRewrap(t *testing.T) {
	key := bytes.Repeat([]byte{0xA5}, 32)
	t.Run("key-out written 0600 before rewrap", func(t *testing.T) {
		h := newKeysHarness(t)
		h.put("system/a", []byte("a-value"))
		before := h.masterFile()
		p := filepath.Join(t.TempDir(), "new-master")
		h.mustRun(0, "rewrap", "--key-out", p)
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, key) || !bytes.Equal(h.masterFile(), key) || bytes.Equal(before, key) {
			t.Fatalf("key file %x, master now %x (was %x), want both %x", got, h.masterFile(), before, key)
		}
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode() != 0o600 {
			t.Fatalf("key file mode %v, want 0600", fi.Mode())
		}
		out := h.stdout.String() + h.stderr.String()
		if strings.Contains(out, fmt.Sprintf("%x", key)) || strings.Contains(out, string(key)) {
			t.Fatalf("rewrap printed the key: %q", out)
		}
		if !strings.Contains(out, "Now delete the --key-out file") || strings.Contains(out, p) {
			t.Errorf("rewrap output %q does not tell the operator to delete the --key-out file, or names its path", out)
		}
		if got := h.value("a", 1); string(got) != "a-value" {
			t.Fatalf("after rewrap the entry holds %q", got)
		}
	})
	for _, tc := range []struct {
		name string
		make func(t *testing.T, p string)
	}{
		{"existing file", func(t *testing.T, p string) {
			if err := os.WriteFile(p, []byte("keep"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"dangling symlink", func(t *testing.T, p string) {
			if err := os.Symlink(filepath.Join(filepath.Dir(p), "target"), p); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run("key-out refuses "+tc.name, func(t *testing.T) {
			h := newKeysHarness(t)
			h.put("system/a", []byte("a-value"))
			before := h.masterFile()
			p := filepath.Join(t.TempDir(), "new-master")
			tc.make(t, p)
			h.mustRun(1, "rewrap", "--key-out", p)
			if slices.Contains(h.calls, "Rewrap") || !bytes.Equal(h.masterFile(), before) {
				t.Fatal("rewrap ran over an existing key file")
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(p), "target")); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("the symlink's target was created: %v", err)
			}
		})
	}
	t.Run("resumed", func(t *testing.T) {
		h := newKeysHarness(t)
		h.put("system/a", []byte("a-value"))
		// The one forced store error: see keysResumedStore.
		resumed := &keysResumedStore{}
		h.wrap = func(s keysStore) keysStore { resumed.keysStore = s; return resumed }
		p := filepath.Join(t.TempDir(), "new-master")
		h.mustRun(3, "rewrap", "--key-out", p)
		if !bytes.Equal(resumed.key, key) {
			t.Fatalf("rewrap key %x, want %x", resumed.key, key)
		}
		if !strings.Contains(h.stderr.String(), "new key") || !strings.Contains(h.stderr.String(), "deleted") {
			t.Errorf("stderr %q does not say to run again with a new key and that the unused one was deleted", h.stderr.String())
		}
		// No rewrap is recorded under the key this run drew, so no resume
		// can use it.
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("the unused key file is kept after a resumed rewrap: %v", err)
		}
	})
	for _, tc := range []struct {
		name   string
		damage func(t *testing.T, h *keysHarness)
		want   error
		say    string
	}{
		{"a user-scope directory that is not one", func(t *testing.T, h *keysHarness) {
			if err := os.WriteFile(filepath.Join(h.keystoreDir(), ".user"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}, keystore.ErrCorrupt, "keystore/.user"},
		{"an entry that does not open", func(t *testing.T, h *keysHarness) { h.damageRecord("a", "v1") }, keystore.ErrCorrupt, "rm"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newKeysHarness(t)
			h.put("system/a", []byte("a-value"))
			before := h.masterFile()
			tc.damage(t, h)
			if err := keystore.New(h.storeCfg).Rewrap(context.Background(), bytes.Repeat([]byte{1}, 32)); !errors.Is(err, tc.want) {
				t.Fatalf("the store's own Rewrap: %v, want %v", err, tc.want)
			}
			p := filepath.Join(t.TempDir(), "new-master")
			h.mustRun(1, "rewrap", "--key-out", p)
			if !strings.Contains(h.stderr.String(), tc.say) {
				t.Errorf("stderr %q does not say %q", h.stderr.String(), tc.say)
			}
			if !strings.Contains(h.stderr.String(), "nothing was changed") || strings.Contains(h.stderr.String(), "--key-in") {
				t.Errorf("stderr %q does not say nothing was changed, or offers --key-in", h.stderr.String())
			}
			if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("the key file is kept after a rewrap that recorded nothing under it: %v", err)
			}
			if !bytes.Equal(h.masterFile(), before) {
				t.Error("a refused rewrap swapped the master")
			}
		})
	}
	for _, tc := range []struct {
		name  string
		value []byte
		mode  fs.FileMode
	}{
		{"short", bytes.Repeat([]byte{1}, 31), 0o600},
		{"long", bytes.Repeat([]byte{1}, 33), 0o600},
		{"group readable", bytes.Repeat([]byte{1}, 32), 0o640},
	} {
		t.Run("key-in refuses "+tc.name, func(t *testing.T) {
			h := newKeysHarness(t)
			p := filepath.Join(t.TempDir(), "saved")
			if err := os.WriteFile(p, tc.value, tc.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(p, tc.mode); err != nil {
				t.Fatal(err)
			}
			h.mustRun(1, "rewrap", "--key-in", p)
			if slices.Contains(h.calls, "Rewrap") {
				t.Fatal("rewrap ran with a refused key file")
			}
		})
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"neither key flag", []string{"rewrap"}},
		{"both key flags", []string{"rewrap", "--key-out", "a", "--key-in", "b"}},
		{"positional", []string{"rewrap", "--key-out", "a", "extra"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newKeysHarness(t)
			h.mustRun(2, tc.args...)
		})
	}
}

// keysCrashedRewrapStore stands in for a Rewrap that crashed after it
// recorded its key: Rewrap leaves the master directory as that crash does
// (stageInterruptedRewrap) and fails. The store's own crash points are
// pkg/keystore's step seam, which no test outside that package reaches.
type keysCrashedRewrapStore struct {
	keysStore
	h *keysHarness
}

func (s keysCrashedRewrapStore) Rewrap(_ context.Context, newMaster []byte) error {
	s.h.stageInterruptedRewrap(newMaster)
	return errors.New("rewrap: injected crash after master.next.sha256")
}

// TestKeysRewrapKeyOutFile: --key-out writes the new key only into a
// directory owned by root (the running user) and closed to group and others
// for writing; a write, sync or chmod that fails removes the partial file;
// and after a failed rewrap the file is kept only while the store records an
// interrupted rewrap under that key, which is when --key-in can finish it.
func TestKeysRewrapKeyOutFile(t *testing.T) {
	for _, mode := range []fs.FileMode{0o770, 0o707, 0o730} {
		t.Run(fmt.Sprintf("refuses a parent dir at %04o", mode), func(t *testing.T) {
			h := newKeysHarness(t)
			h.put("system/a", []byte("a-value"))
			before := h.masterFile()
			dir := t.TempDir()
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(dir, "new-master")
			h.calls = nil
			h.mustRun(1, "rewrap", "--key-out", p)
			if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("the key file was written into a shared directory: %v", err)
			}
			if slices.Contains(h.calls, "Rewrap") || !bytes.Equal(h.masterFile(), before) {
				t.Fatal("rewrap ran")
			}
			if !strings.Contains(h.stderr.String(), "group or others") {
				t.Errorf("stderr %q does not name the directory's mode", h.stderr.String())
			}
		})
	}
	t.Run("refuses a parent dir another user owns", func(t *testing.T) {
		h := newKeysHarness(t)
		h.put("system/a", []byte("a-value"))
		// Non-root, / is root's, not the running user's; as root, a
		// directory handed to the service user stands in.
		dir := "/"
		if keysAsRoot() {
			dir = t.TempDir()
			keysGiveToService(t, dir)
		}
		p := filepath.Join(dir, "k3sm-keys-test-new-master")
		h.calls = nil
		h.mustRun(1, "rewrap", "--key-out", p)
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("the key file was written: %v", err)
		}
		if slices.Contains(h.calls, "Rewrap") {
			t.Fatal("rewrap ran")
		}
		if !strings.Contains(h.stderr.String(), "owned by") {
			t.Errorf("stderr %q does not name the owner", h.stderr.String())
		}
	})
	for _, step := range []string{"chmod", "write", "sync"} {
		t.Run("removes the partial file when "+step+" fails", func(t *testing.T) {
			h := newKeysHarness(t)
			h.put("system/a", []byte("a-value"))
			before := h.masterFile()
			h.keyOutStep = func(s string) error {
				if s == step {
					return fmt.Errorf("injected %s failure", s)
				}
				return nil
			}
			p := filepath.Join(t.TempDir(), "new-master")
			h.calls = nil
			h.mustRun(1, "rewrap", "--key-out", p)
			if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("the partial key file is left: %v", err)
			}
			if slices.Contains(h.calls, "Rewrap") || !bytes.Equal(h.masterFile(), before) {
				t.Fatal("rewrap ran")
			}
			if !strings.Contains(h.stderr.String(), "nothing was changed") {
				t.Errorf("stderr %q does not say nothing was changed", h.stderr.String())
			}
		})
	}
	t.Run("keeps the file when a resume is possible", func(t *testing.T) {
		h := newKeysHarness(t)
		h.put("system/a", []byte("a-value"))
		h.wrap = func(s keysStore) keysStore { return keysCrashedRewrapStore{keysStore: s, h: h} }
		p := filepath.Join(t.TempDir(), "new-master")
		h.mustRun(1, "rewrap", "--key-out", p)
		got, err := os.ReadFile(p)
		if err != nil || len(got) != 32 {
			t.Fatalf("the key file after a crash that recorded its key: %x, %v", got, err)
		}
		if !strings.Contains(h.stderr.String(), "keep the --key-out file") || !strings.Contains(h.stderr.String(), "rewrap --key-in <that file>") ||
			strings.Contains(h.stderr.String(), p) || strings.Contains(h.stderr.String(), "nothing was changed") {
			t.Errorf("stderr %q does not say to keep the --key-out file and finish with --key-in, or names its path", h.stderr.String())
		}
		// And that file finishes it.
		h.wrap = nil
		h.mustRun(0, "rewrap", "--key-in", p)
		if !bytes.Equal(h.masterFile(), got) {
			t.Fatalf("master %x, want the saved key %x", h.masterFile(), got)
		}
	})
}

// keysResumeFailedStore forces keystore.ErrRewrapResumeFailed from Rewrap:
// the real store returns it only when a resume of an earlier rewrap fails
// partway, a crash no seam outside pkg/keystore can stage (pkg/keystore's
// TestRewrapResumeFailed covers the store's side).
type keysResumeFailedStore struct{ keysStore }

func (keysResumeFailedStore) Rewrap(context.Context, []byte) error {
	return fmt.Errorf("rewrap: injected crash at rename a/current (%w)", keystore.ErrRewrapResumeFailed)
}

// TestKeysRewrapResumeFailedKeepsKeyFile: a rewrap that fails while it
// completes an earlier interrupted rewrap keeps this run's --key-out file,
// sends the operator to the earlier rewrap's key file, and never says
// nothing was changed.
func TestKeysRewrapResumeFailedKeepsKeyFile(t *testing.T) {
	h := newKeysHarness(t)
	h.put("system/a", []byte("a-value"))
	h.wrap = func(s keysStore) keysStore { return keysResumeFailedStore{s} }
	p := filepath.Join(t.TempDir(), "new-master")
	h.mustRun(1, "rewrap", "--key-out", p)
	want := "an earlier interrupted rewrap was advanced and did not finish; keep the earlier rewrap's key file; finish with: sudo k3sm keys rewrap --key-in <that earlier file>"
	if !strings.Contains(h.stderr.String(), want) {
		t.Errorf("stderr %q does not say %q", h.stderr.String(), want)
	}
	if strings.Contains(h.stderr.String(), "nothing was changed") {
		t.Errorf("stderr %q says nothing was changed", h.stderr.String())
	}
	if got, err := os.ReadFile(p); err != nil || len(got) != 32 {
		t.Fatalf("this run's key file after a failed resume: %x, %v; want it kept", got, err)
	}
}

// keysSwapDirStore stands in for a directory swapped under a running
// rewrap: its Rewrap moves the --key-out file's directory aside, puts a new
// directory holding a decoy at the old path, and fails as the store does
// before it seals anything, so the verb deletes its key file.
type keysSwapDirStore struct {
	keysStore
	dir string
}

func (s keysSwapDirStore) Rewrap(context.Context, []byte) error {
	if err := os.Rename(s.dir, s.dir+".moved"); err != nil {
		return err
	}
	if err := os.Mkdir(s.dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(s.dir, "new-master"), []byte("decoy"), 0o600); err != nil {
		return err
	}
	return fmt.Errorf("rewrap: injected refusal (%w)", keystore.ErrRewrapNotStarted)
}

// TestKeysRewrapKeyOutDeletesThroughCheckedDir: after a rewrap that sealed
// nothing, the --key-out file is deleted through the directory handle that
// was checked when it was written, so a directory swapped in at its path
// loses nothing; and a relative --key-out is refused before anything is
// written.
func TestKeysRewrapKeyOutDeletesThroughCheckedDir(t *testing.T) {
	t.Run("deletes through the checked directory", func(t *testing.T) {
		h := newKeysHarness(t)
		h.put("system/a", []byte("a-value"))
		dir := filepath.Join(t.TempDir(), "keys")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		h.wrap = func(s keysStore) keysStore { return keysSwapDirStore{keysStore: s, dir: dir} }
		h.mustRun(1, "rewrap", "--key-out", filepath.Join(dir, "new-master"))
		if got, err := os.ReadFile(filepath.Join(dir, "new-master")); err != nil || string(got) != "decoy" {
			t.Fatalf("the file swapped in at the key file's path: %q, %v; want it untouched", got, err)
		}
		if _, err := os.Lstat(filepath.Join(dir+".moved", "new-master")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("the key file written in the checked directory was not deleted: %v", err)
		}
		if !strings.Contains(h.stderr.String(), "was deleted") {
			t.Errorf("stderr %q does not say the key file was deleted", h.stderr.String())
		}
	})
	t.Run("refuses a relative path", func(t *testing.T) {
		h := newKeysHarness(t)
		h.put("system/a", []byte("a-value"))
		before := h.masterFile()
		h.calls = nil
		h.mustRun(1, "rewrap", "--key-out", "new-master")
		if !strings.Contains(h.stderr.String(), "give an absolute path") {
			t.Errorf("stderr %q does not say to give an absolute path", h.stderr.String())
		}
		if slices.Contains(h.calls, "Rewrap") || !bytes.Equal(h.masterFile(), before) {
			t.Fatal("rewrap ran")
		}
		if _, err := os.Lstat("new-master"); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("a key file was written in the working directory: %v", err)
		}
	})
}

// keysSwapUnsyncedStore forces a resume failure after the earlier rewrap's
// master swap went through, in the shape the store returns it (err);
// pkg/keystore's TestRewrapResumeFailed stages the real ones.
type keysSwapUnsyncedStore struct {
	keysStore
	err error
}

func (s keysSwapUnsyncedStore) Rewrap(context.Context, []byte) error { return s.err }

// TestKeysRewrapSwapUnsynced: when the failed resume is the earlier
// rewrap's master swap, renamed through but not synced, whether finishSwap
// (a swap half done before this run) or the resumed plan's own swapMaster
// failed, rewrap says to run a new rewrap, not to finish with --key-in, and
// deletes its unused file.
func TestKeysRewrapSwapUnsynced(t *testing.T) {
	for name, err := range map[string]error{
		"finishSwap": fmt.Errorf("rewrap: injected sync failure (%w) (%w)", keystore.ErrRewrapSwapUnsynced, keystore.ErrRewrapResumeFailed),
		"swapMaster on a resumed plan": fmt.Errorf("rewrap: injected crash at rename master.next.sha256 (%w) (%w)",
			keystore.ErrRewrapSwapUnsynced, keystore.ErrRewrapResumeFailed),
	} {
		t.Run(name, func(t *testing.T) {
			h := newKeysHarness(t)
			h.put("system/a", []byte("a-value"))
			h.wrap = func(s keysStore) keysStore { return keysSwapUnsyncedStore{keysStore: s, err: err} }
			p := filepath.Join(t.TempDir(), "new-master")
			h.mustRun(1, "rewrap", "--key-out", p)
			want := "the earlier rewrap's master swap completed but did not sync; run sudo k3sm keys rewrap --key-out FILE again; the earlier rewrap's key file is now a copy of the live master; delete it after this rewrap succeeds"
			if !strings.Contains(h.stderr.String(), want) || strings.Contains(h.stderr.String(), "--key-in") {
				t.Errorf("stderr %q does not say %q, or offers --key-in", h.stderr.String(), want)
			}
			if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("the unused key file is kept: %v", err)
			}
		})
	}
}

// TestKeysRewrapOwnSwapUnsynced: when this run's own master swap went
// through but did not sync, the --key-out file holds the live master, so
// rewrap keeps it and says so, with no --key-in hint.
func TestKeysRewrapOwnSwapUnsynced(t *testing.T) {
	h := newKeysHarness(t)
	h.put("system/a", []byte("a-value"))
	err := fmt.Errorf("rewrap: injected crash at rename master.next.sha256 (%w)", keystore.ErrRewrapSwapUnsynced)
	h.wrap = func(s keysStore) keysStore { return keysSwapUnsyncedStore{keysStore: s, err: err} }
	p := filepath.Join(t.TempDir(), "new-master")
	h.mustRun(1, "rewrap", "--key-out", p)
	want := "the master swap completed but did not sync; this run's key file is now a copy of the live master: keep it until a later rewrap succeeds, then delete it."
	if !strings.Contains(h.stderr.String(), want) || strings.Contains(h.stderr.String(), "--key-in") {
		t.Errorf("stderr %q does not say %q, or offers --key-in", h.stderr.String(), want)
	}
	// No line speaks of an earlier rewrap, which this run's own swap is not.
	if strings.Contains(h.stderr.String(), "earlier") {
		t.Errorf("stderr %q names an earlier rewrap", h.stderr.String())
	}
	if got, rerr := os.ReadFile(p); rerr != nil || len(got) != 32 {
		t.Fatalf("the key file after this run's own swap: %x, %v; want it kept", got, rerr)
	}
}

// TestKeysDocsSayWhatTheVerbsDo: docs/user/keys.md carries the resume
// message rewrap prints, word for word, and the three cautions the verbs
// cannot enforce: raw bytes from show --reveal, no sudoers delegation, and
// the --key-out file after a successful rewrap.
func TestKeysDocsSayWhatTheVerbsDo(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "user", "keys.md"))
	if err != nil {
		t.Fatal(err)
	}
	// The doc wraps prose, so it is compared with whitespace collapsed.
	doc := strings.Join(strings.Fields(string(b)), " ")
	for _, want := range []string{
		keysResumeFailed,
		keysSwapUnsynced,
		keysUndeliverHint,
		"unless the server was started with the override (`--allow-plaintext-secrets-delivery`)",
		"It writes the raw bytes, so a value holding terminal escape sequences is interpreted by the terminal.",
		"Never delegate the `keys` verbs through `sudoers`: `put --in` and `show --reveal` read any file root can read",
		"After a successful rewrap, `FILE` is a second copy of the live master key: delete it, or move it to offline storage, and never keep it beside a backup of the entries.",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("docs/user/keys.md does not say %q", want)
		}
	}
}

// TestKeysWriteKeyOutFailureReturnsNoHandle: every failure of writeKeyOut
// returns no keyOutFile, so no caller can delete through a closed root.
func TestKeysWriteKeyOutFailureReturnsNoHandle(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	for _, step := range []string{"chmod", "write", "sync"} {
		p := filepath.Join(t.TempDir(), "new-master")
		out, err := writeKeyOut(p, key, func(s string) error {
			if s == step {
				return fmt.Errorf("injected %s failure", s)
			}
			return nil
		})
		if err == nil || out != nil {
			t.Fatalf("writeKeyOut failing at %s = %v, %v; want an error and no handle", step, out, err)
		}
	}
	for _, p := range []string{"relative", "/nonexistent/new-master"} {
		if out, err := writeKeyOut(p, key, nil); err == nil || out != nil {
			t.Fatalf("writeKeyOut(%q) = %v, %v; want an error and no handle", p, out, err)
		}
	}
}

// keysHalfRewrapStore stands in for a rewrap interrupted after it renamed
// some records in, whose master.next was then replaced or removed, the
// scenario of pkg/keystore's TestRewrapRecoversReplacedNext. Its Rewrap runs
// the real Rewrap to the end, then puts back the old master pair and the
// pre-rewrap files of entry b, so entry a is sealed under the new key, b
// under the old, and the master directory holds no master.next unless
// replace plants another key's agreeing pair. It then fails with a
// mid-run error, as the store's does. The crash points are pkg/keystore's
// step seam, which no test outside that package reaches.
type keysHalfRewrapStore struct {
	keysStore
	h       *keysHarness
	replace []byte
}

func (s keysHalfRewrapStore) Rewrap(ctx context.Context, newMaster []byte) error {
	h := s.h
	mdir := filepath.Join(h.work, "cred", "keystore-master")
	old := map[string][]byte{}
	for _, n := range []string{"master", "master.sha256"} {
		b, err := os.ReadFile(filepath.Join(mdir, n))
		if err != nil {
			h.t.Fatal(err)
		}
		old[n] = b
	}
	b := filepath.Join(h.t.TempDir(), "b")
	copyTree(h.t, filepath.Join(h.keystoreDir(), "b"), b)
	if err := s.keysStore.Rewrap(ctx, newMaster); err != nil {
		h.t.Fatalf("the real rewrap: %v", err)
	}
	for n, v := range old {
		if err := os.WriteFile(filepath.Join(mdir, n), v, 0o600); err != nil {
			h.t.Fatal(err)
		}
	}
	if err := os.RemoveAll(filepath.Join(h.keystoreDir(), "b")); err != nil {
		h.t.Fatal(err)
	}
	copyTree(h.t, b, filepath.Join(h.keystoreDir(), "b"))
	if s.replace != nil {
		h.stageInterruptedRewrap(s.replace)
	}
	return fmt.Errorf("rewrap: %w: master.next changed during the rewrap", keystore.ErrMasterUntrusted)
}

// TestKeysRewrapKeyInRecoversReplacedNext: a --key-out rewrap interrupted
// after some records moved under its key, with master.next then removed or
// replaced by another key's agreeing pair, keeps its key file ("a resume
// may need this file"), and --key-in with that file finishes it through the
// CLI, although master.next.sha256 no longer names the key. Another key is
// still refused, with nothing changed.
func TestKeysRewrapKeyInRecoversReplacedNext(t *testing.T) {
	for name, replace := range map[string][]byte{
		"master.next removed":  nil,
		"master.next replaced": bytes.Repeat([]byte{0x99}, 32),
	} {
		t.Run(name, func(t *testing.T) {
			h := newKeysHarness(t)
			h.put("system/a", []byte("a-value"))
			h.put("system/b", []byte("b-value"))
			before := h.masterFile()
			h.wrap = func(s keysStore) keysStore { return keysHalfRewrapStore{keysStore: s, h: h, replace: replace} }
			p := filepath.Join(t.TempDir(), "new-master")
			h.mustRun(1, "rewrap", "--key-out", p)
			saved, err := os.ReadFile(p)
			if err != nil || len(saved) != 32 {
				t.Fatalf("the key file after a mid-run failure: %x, %v", saved, err)
			}
			if !strings.Contains(h.stderr.String(), "a resume may need this file") {
				t.Errorf("stderr %q does not say a resume may need the file", h.stderr.String())
			}
			if !bytes.Equal(h.masterFile(), before) {
				t.Fatal("the staging did not restore the old master")
			}
			h.wrap = nil
			h.calls = nil
			h.mustRun(1, "rewrap", "--key-in", writeKeyFile(t, bytes.Repeat([]byte{0x4d}, 32)))
			if slices.Contains(h.calls, "Rewrap") || !strings.Contains(h.stderr.String(), "nothing was changed") {
				t.Fatalf("another key was not refused with nothing changed: calls %v, stderr %q", h.calls, h.stderr.String())
			}
			h.mustRun(0, "rewrap", "--key-in", p)
			if !bytes.Equal(h.masterFile(), saved) {
				t.Fatalf("master %x, want the saved key %x", h.masterFile(), saved)
			}
			if got := h.value("a", 1); string(got) != "a-value" {
				t.Fatalf("a = %q", got)
			}
			if got := h.value("b", 1); string(got) != "b-value" {
				t.Fatalf("b = %q", got)
			}
		})
	}
}

// stageInterruptedRewrap leaves the master directory as a rewrap to key
// crashed right after writing master.next and its fingerprint leaves it: the
// pair the store's own Rewrap writes, owned by the service user, mode 0600.
func (h *keysHarness) stageInterruptedRewrap(key []byte) {
	h.t.Helper()
	dir := filepath.Join(h.work, "cred", "keystore-master")
	sum := sha256.Sum256(key)
	for name, b := range map[string][]byte{
		"master.next":        key,
		"master.next.sha256": []byte(hex.EncodeToString(sum[:]) + "\n"),
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			h.t.Fatal(err)
		}
		keysGiveToService(h.t, p)
	}
}

// writeKeyFile writes key to a new 0600 file, as an earlier --key-out did.
func writeKeyFile(t *testing.T, key []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "saved")
	if err := os.WriteFile(p, key, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestKeysRewrapKeyInRecoveryOnly: --key-in only finishes an interrupted
// rewrap, with the key whose SHA-256 that rewrap recorded. On a keystore
// with no rewrap pending it refuses any key, the live master's included, and
// the master stays byte-identical; with one pending it refuses another key
// and completes with the recorded one.
func TestKeysRewrapKeyInRecoveryOnly(t *testing.T) {
	recorded := bytes.Repeat([]byte{0x3c}, 32)
	other := bytes.Repeat([]byte{0x4d}, 32)
	for name, key := range map[string]func(h *keysHarness) []byte{
		"an operator-made key": func(*keysHarness) []byte { return other },
		"the live master":      func(h *keysHarness) []byte { return h.masterFile() },
	} {
		t.Run("clean keystore refuses "+name, func(t *testing.T) {
			h := newKeysHarness(t)
			h.put("system/a", []byte("a-value"))
			before := h.masterFile()
			h.calls = nil
			h.rand = failReaderRand{t}
			h.mustRun(1, "rewrap", "--key-in", writeKeyFile(t, key(h)))
			if slices.Contains(h.calls, "Rewrap") {
				t.Fatal("rewrap ran with a key no interrupted rewrap recorded")
			}
			if !bytes.Equal(h.masterFile(), before) {
				t.Fatal("the master changed")
			}
			if !strings.Contains(h.stderr.String(), "--key-out") {
				t.Errorf("stderr %q does not point at --key-out", h.stderr.String())
			}
		})
	}
	t.Run("interrupted rewrap refuses another key", func(t *testing.T) {
		h := newKeysHarness(t)
		h.put("system/a", []byte("a-value"))
		before := h.masterFile()
		h.stageInterruptedRewrap(recorded)
		h.calls = nil
		h.mustRun(1, "rewrap", "--key-in", writeKeyFile(t, other))
		if slices.Contains(h.calls, "Rewrap") {
			t.Fatal("rewrap ran with a key the interrupted rewrap did not record")
		}
		if !bytes.Equal(h.masterFile(), before) {
			t.Fatal("the master changed")
		}
		next, err := os.ReadFile(filepath.Join(h.work, "cred", "keystore-master", "master.next"))
		if err != nil || !bytes.Equal(next, recorded) {
			t.Fatalf("master.next = %x, %v; want the recorded key left in place", next, err)
		}
	})
	t.Run("interrupted rewrap completes with the recorded key", func(t *testing.T) {
		h := newKeysHarness(t)
		h.put("system/a", []byte("a-value"))
		h.stageInterruptedRewrap(recorded)
		h.rand = failReaderRand{t}
		h.mustRun(0, "rewrap", "--key-in", writeKeyFile(t, recorded))
		if !bytes.Equal(h.masterFile(), recorded) {
			t.Fatalf("master %x, want the recorded %x", h.masterFile(), recorded)
		}
		if got := h.value("a", 1); string(got) != "a-value" {
			t.Fatalf("after rewrap the entry holds %q", got)
		}
	})
}

// TestKeysReadKeyInRefusals: --key-in reads only a regular file of this
// user's (root's), reached without following a symlink and without waiting
// on a FIFO; each refusal says why, and the verb never reaches Rewrap.
func TestKeysReadKeyInRefusals(t *testing.T) {
	key := bytes.Repeat([]byte{0x3c}, 32)
	for name, tc := range map[string]struct {
		make func(t *testing.T, p string)
		say  string
	}{
		"symlink": {func(t *testing.T, p string) {
			if err := os.Symlink(writeKeyFile(t, key), p); err != nil {
				t.Fatal(err)
			}
		}, "open --key-in: too many levels of symbolic links"},
		"fifo": {func(t *testing.T, p string) {
			if err := syscall.Mkfifo(p, 0o600); err != nil {
				t.Fatal(err)
			}
		}, "not a regular file"},
		"directory": {func(t *testing.T, p string) {
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
		}, "not a regular file"},
		"file another user owns": {func(t *testing.T, p string) {
			// Only root can make a file another user owns; the root run of
			// this binary covers it.
			if !keysAsRoot() {
				t.Skip("needs root to give the file to another user")
			}
			if err := os.WriteFile(p, key, 0o600); err != nil {
				t.Fatal(err)
			}
			keysGiveToService(t, p)
		}, "not owned by this user"},
	} {
		t.Run("refuses a "+name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "saved")
			tc.make(t, p)
			// readKeyIn opens non-blocking, so a FIFO with no writer is refused
			// at once; were that to regress, the open would block until go
			// test's own timeout.
			b, err := readKeyIn(p)
			clear(b)
			if err == nil || !strings.Contains(err.Error(), tc.say) {
				t.Fatalf("readKeyIn = %v, want a refusal saying %q", err, tc.say)
			}
			h := newKeysHarness(t)
			h.put("system/a", []byte("a-value"))
			h.calls = nil
			h.mustRun(1, "rewrap", "--key-in", p)
			if slices.Contains(h.calls, "Rewrap") {
				t.Fatal("rewrap ran with a refused key file")
			}
		})
	}
}

// failReaderRand fails the test if the verb draws randomness.
type failReaderRand struct{ t *testing.T }

func (r failReaderRand) Read([]byte) (int, error) {
	r.t.Error("rand was read")
	return 0, io.EOF
}

// U101: rewrap prints the user-scope warning while keystore/.user exists,
// before it starts and again when it finishes: Rewrap re-seals each
// scope.key but does not re-key K_u. With no .user it prints none.
func TestRewrapWarnsWhenUserScopesExist(t *testing.T) {
	for _, users := range []bool{false, true} {
		t.Run(fmt.Sprintf("user scopes %v", users), func(t *testing.T) {
			h := newKeysHarness(t)
			h.put("system/a", []byte("a-value"))
			if users {
				p := filepath.Join(h.keystoreDir(), ".user")
				if err := os.Mkdir(p, 0o700); err != nil {
					t.Fatal(err)
				}
				keysGiveToService(t, p)
			}
			h.mustRun(0, "rewrap", "--key-out", filepath.Join(t.TempDir(), "new-master"))
			got := strings.Count(h.stderr.String(), keystore.UserScopeRewrapWarning)
			want := 0
			if users {
				want = 2
			}
			if got != want {
				t.Fatalf("rewrap printed the user-scope warning %d times, want %d:\n%s", got, want, h.stderr.String())
			}
			if users && !strings.Contains(keystore.UserScopeRewrapWarning, "re-put") {
				t.Fatalf("the warning does not name the procedure: %q", keystore.UserScopeRewrapWarning)
			}
		})
	}
	// A .user that appears during the run, after the opening check, still
	// gets the closing warning: the check is made again once Rewrap returns.
	t.Run("user scopes appear during the run", func(t *testing.T) {
		h := newKeysHarness(t)
		h.put("system/a", []byte("a-value"))
		made := false
		h.keyOutStep = func(string) error {
			if !made {
				made = true
				p := filepath.Join(h.keystoreDir(), ".user")
				if err := os.Mkdir(p, 0o700); err != nil {
					return err
				}
				keysGiveToService(t, p)
			}
			return nil
		}
		h.mustRun(0, "rewrap", "--key-out", filepath.Join(t.TempDir(), "new-master"))
		if got := strings.Count(h.stderr.String(), keystore.UserScopeRewrapWarning); got != 1 {
			t.Fatalf("rewrap printed the user-scope warning %d times, want the closing one:\n%s", got, h.stderr.String())
		}
	})
}
