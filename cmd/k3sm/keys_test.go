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
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"testing/iotest"
	"time"

	"k3sm.io/k3sm/pkg/keystore"
	"k3sm.io/k3sm/pkg/keystore/typed"
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
	// logFlags, when set, is the store's flag source (keystore.Config.LogFlags):
	// a non-root test cannot set SF_APPEND.
	logFlags func(*os.File) (uint32, error)
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
	// attrs is the maintenance verbs' file-attribute writer; nil leaves
	// fileAttrSeam, which panics in a unit test.
	attrs  keystore.FileAttrWriter
	stdout bytes.Buffer
	stderr bytes.Buffer
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
			h.storeCfg.LogFlags = h.logFlags
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
		attrs:         h.attrs,
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

// recipeBackup is one backup as the save recipe in docs/user/keys.md leaves
// it: keystore/ under a directory named after the backup, and the floor
// saved under the same name in a root-only directory, with its SHA-256 in a
// file beside it, in the format shasum writes.
type recipeBackup struct {
	keystore, floor, sum string
}

// saveRecipeBackup saves h's keystore/ and floor as the backup named name,
// its floor under floorRoot (the recipe's /var/root/keystore-floor-backup).
func saveRecipeBackup(t *testing.T, h *keysHarness, floorRoot, name string) recipeBackup {
	t.Helper()
	b := recipeBackup{keystore: filepath.Join(t.TempDir(), name, "keystore")}
	if err := os.MkdirAll(filepath.Dir(b.keystore), 0o700); err != nil {
		t.Fatal(err)
	}
	copyTree(t, h.keystoreDir(), b.keystore)
	// install -d -m 0700, then install -m 0644, under the backup's name.
	dir := filepath.Join(floorRoot, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	b.floor = filepath.Join(dir, "keystore-floor.json")
	raw, err := os.ReadFile(recipeFloor(h))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b.floor, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	// shasum -a 256 FILE | tee FILE.sha256
	sum := sha256.Sum256(raw)
	b.sum = b.floor + ".sha256"
	if err := os.WriteFile(b.sum, fmt.Appendf(nil, "%x  %s\n", sum, b.floor), 0o644); err != nil {
		t.Fatal(err)
	}
	return b
}

// recipeFloor is h's live floor file.
func recipeFloor(h *keysHarness) string {
	return filepath.Join(filepath.Dir(h.work), "keystore-floor.json")
}

// checkRecipeSum is shasum -a 256 -c on b's recorded SHA-256: shasum itself
// when the host has it, and the same comparison in Go otherwise.
func checkRecipeSum(b recipeBackup) error {
	if shasum, err := exec.LookPath("shasum"); err == nil {
		out, err := exec.Command(shasum, "-a", "256", "-c", b.sum).CombinedOutput()
		if err != nil || !bytes.HasSuffix(bytes.TrimSpace(out), []byte(": OK")) {
			return fmt.Errorf("shasum -c: %s, %v", out, err)
		}
		return nil
	}
	line, err := os.ReadFile(b.sum)
	if err != nil {
		return err
	}
	f := strings.Fields(string(line))
	if len(f) != 2 {
		return fmt.Errorf("%s: malformed", b.sum)
	}
	raw, err := os.ReadFile(f[1])
	if err != nil {
		return err
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != f[0] {
		return fmt.Errorf("%s: FAILED", f[1])
	}
	return nil
}

// recipePreRestore is h's pre-restore.d in the data root (a parent only
// root can write), the root-only directory the recipe moves the live
// keystore/ into.
func recipePreRestore(h *keysHarness) string {
	return filepath.Join(filepath.Dir(recipeFloor(h)), "pre-restore.d")
}

// restoreRecipeBackup restores b over h as the recipe does, with the saved
// floor when withFloor is set, and returns the moved-aside keystore/. Before
// anything moves, it refuses (an error, nothing changed) when pre-restore.d
// or the floor's .pre-restore copy is still set aside (the ls -d check) or,
// with the floor, when the saved floor no longer matches its SHA-256
// (shasum -c). The live keystore/ is moved, its files untouched, into a new
// 0700 pre-restore.d (mkdir, which fails on an existing name), and the live
// floor aside after its test ! -e guard: neither is overwritten.
func restoreRecipeBackup(t *testing.T, h *keysHarness, b recipeBackup, withFloor bool) (string, error) {
	t.Helper()
	floor := recipeFloor(h)
	aside := filepath.Join(recipePreRestore(h), "keystore")
	for _, p := range []string{recipePreRestore(h), floor + ".pre-restore"} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("%s is still set aside from an earlier restore (%v)", p, err)
		}
	}
	if withFloor {
		if err := checkRecipeSum(b); err != nil {
			return "", err
		}
	}
	if err := os.Mkdir(recipePreRestore(h), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(h.keystoreDir(), aside); err != nil {
		t.Fatal(err)
	}
	// test ! -e, then the root ditto into the staging directory; the merge
	// moves it into place.
	staged := filepath.Join(recipePreRestore(h), "restored")
	if !withFloor {
		// A restore without the floor never merges: the copy goes
		// straight into place, where the floor refuses it.
		staged = h.keystoreDir()
	}
	if _, err := os.Lstat(staged); !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("%s exists (%v)", staged, err)
	}
	copyTree(t, b.keystore, staged)
	if withFloor {
		if err := os.Rename(floor, floor+".pre-restore"); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(b.floor)
		if err != nil {
			t.Fatal(err)
		}
		// install -o root -g wheel -m 0644: the owner is this test's floor
		// owner, and the mode is set whatever the umask.
		if err := os.WriteFile(floor, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(floor, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return aside, nil
}

// stageKeystore stages h's live keystore/ as the restore recipe leaves the
// restored one, in a root-only pre-restore.d as restored, for a test that
// sets the guard file up by hand: the merge moves it back into place.
func stageKeystore(t *testing.T, h *keysHarness) {
	t.Helper()
	if err := os.Mkdir(recipePreRestore(h), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(h.keystoreDir(), filepath.Join(recipePreRestore(h), "restored")); err != nil {
		t.Fatal(err)
	}
}

// refusedDeleted fails t unless show of name is refused as a deleted entry
// put back, printing no value.
func refusedDeleted(t *testing.T, h *keysHarness, name string) {
	t.Helper()
	if code := h.run("show", name, "--reveal"); code == 0 || h.stdout.Len() != 0 || !strings.Contains(h.stderr.String(), "records as deleted") {
		t.Fatalf("show of the copy of %s put back: exit %d, stdout %q, stderr %q; want it refused as deleted", name, code, h.stdout.String(), h.stderr.String())
	}
}

// recipeDeletedNames is plutil -extract tombstones raw on the moved-aside
// floor: the names it records as deleted, sorted. It runs plutil itself
// when the host has it, and reads the same field in Go otherwise. Only
// plutil's exact "No value at that key path" means no deletions; any other
// failure (an unreadable or malformed file) stops the test.
func recipeDeletedNames(t *testing.T, h *keysHarness) []string {
	t.Helper()
	p := recipeFloor(h) + ".pre-restore"
	if plutil, err := exec.LookPath("plutil"); err == nil {
		var stderr bytes.Buffer
		cmd := exec.Command(plutil, "-extract", "tombstones", "raw", "-o", "-", p)
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			if strings.Contains(stderr.String()+string(out), "No value at that key path") {
				return nil // no tombstones: nothing deleted
			}
			t.Fatalf("plutil on the moved-aside floor: %v: %s%s", err, out, stderr.String())
		}
		names := strings.Fields(string(out))
		slices.Sort(names)
		return names
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Tombstones map[string]json.RawMessage `json:"tombstones"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	var names []string
	for n := range f.Tombstones {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

// recipeLines is each line inside a fenced code block of a Markdown doc,
// keyed by its 1-based line number.
func recipeLines(doc string) map[int]string {
	out := map[int]string{}
	fenced := false
	for i, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			fenced = !fenced
			continue
		}
		if fenced {
			out[i+1] = line
		}
	}
	return out
}

// recursiveChange reports whether line runs chown, chgrp, chmod or chflags
// with a short-option cluster holding -R.
func recursiveChange(line string) bool {
	fields := strings.Fields(line)
	for i, f := range fields {
		switch filepath.Base(f) {
		case "chown", "chgrp", "chmod", "chflags":
		default:
			continue
		}
		for _, opt := range fields[i+1:] {
			if !strings.HasPrefix(opt, "-") || strings.HasPrefix(opt, "--") {
				break
			}
			if strings.Contains(opt, "R") {
				return true
			}
		}
	}
	return false
}

// TestKeysRollbackRoundTrip is G21's CLI test: the rollback recipes in
// docs/user/keys.md run as written. A restore of a saved keystore/, with the
// floor saved at the same moment, under the backup's name, into a directory
// only its owner can open, brings a deleted entry back, and without the
// floor it is refused. The restore refuses before it moves anything when a
// .pre-restore copy is still set aside or the saved floor no longer matches
// the SHA-256 recorded for it; an older backup keeps its own floor; the
// names the moved-aside floor records as deleted are listed, and a revoked
// one deleted again before start stays deleted. The undo steps, the restored
// copies renamed first, put the live state back; and `show --version N
// --reveal` piped into `rotate --in -` stores a version whose value equals
// version N's byte for byte (bytes.Equal, the comparison cmp makes), for an
// opaque and an Ed25519 entry.
// mergedFloors is the one renamed merge input beside floor,
// keystore-floor.json.merged-<unix>, its retired record not counted.
func mergedFloors(t *testing.T, floor string) []string {
	t.Helper()
	all, err := filepath.Glob(floor + ".merged-*")
	if err != nil {
		t.Fatal(err)
	}
	var merged []string
	for _, p := range all {
		if !strings.HasSuffix(p, ".retired") {
			merged = append(merged, p)
		}
	}
	if len(merged) != 1 {
		t.Fatalf("the merged floor: %v; want one", merged)
	}
	return merged
}

func TestKeysRollbackRoundTrip(t *testing.T) {
	// saveRmRestore saves keystore/ and the floor, rm's the entry, then
	// restores keystore/ as the recipe does, with the saved floor when
	// withFloor is set (the live floor moved aside first, never overwritten),
	// and returns the entry's value and the moved-aside copy.
	saveRmRestore := func(t *testing.T, h *keysHarness, withFloor bool) ([]byte, string) {
		t.Helper()
		value := []byte("rollback\x00value\n")
		h.put("system/rb", value)
		b := saveRecipeBackup(t, h, filepath.Join(t.TempDir(), "keystore-floor-backup"), "2026-11-22")
		h.mustRun(0, "rm", "system/rb", "--yes")
		h.mustRun(1, "show", "system/rb", "--reveal")
		aside, err := restoreRecipeBackup(t, h, b, withFloor)
		if err != nil {
			t.Fatalf("restore: %v", err)
		}
		return value, aside
	}
	t.Run("the recipe in docs/user/keys.md has these steps", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "user", "keys.md"))
		if err != nil {
			t.Fatal(err)
		}
		doc := strings.Join(strings.Fields(string(raw)), " ")
		steps := []string{
			"sudo install -d -o root -g wheel -m 0755 /path/to/backup",
			"sudo install -d -o root -g wheel -m 0700 /path/to/backup/$B",
			"sudo ditto /var/lib/k3sm/server/keystore /path/to/backup/$B/keystore",
			"sudo install -o root -g wheel -m 0644 /var/lib/k3sm/keystore-floor.json /var/root/keystore-floor-backup/$B/keystore-floor.json",
			"sudo shasum -a 256 /var/root/keystore-floor-backup/$B/keystore-floor.json | sudo tee /var/root/keystore-floor-backup/$B/keystore-floor.json.sha256",
			"Never keep the saved floor on a volume that ignores ownership",
			"sudo k3sm stop",
			"sudo ls -d /var/lib/k3sm/pre-restore.d /var/lib/k3sm/keystore-floor.json.pre-restore",
			"sudo shasum -a 256 -c /var/root/keystore-floor-backup/$B/keystore-floor.json.sha256",
			// Before anything moves: the service is down, the backups'
			// directory is root's with no group or other write, and the
			// backup's own directory root's at mode 0700.
			"! pgrep -u _k3sm || exit 1",
			`test "$(sudo find /path/to/backup -maxdepth 0 -user root \! -perm +022 | grep -c .)" -eq 1 || exit 1`,
			`test "$(sudo find /path/to/backup/$B -maxdepth 0 -user root -perm 0700 | grep -c .)" -eq 1 || exit 1`,
			"sudo mkdir -m 0700 /var/lib/k3sm/pre-restore.d || exit 1",
			"sudo mv /var/lib/k3sm/server/keystore /var/lib/k3sm/pre-restore.d/keystore || exit 1",
			"sudo test ! -e /var/lib/k3sm/keystore-floor.json.pre-restore || exit 1",
			"sudo mv /var/lib/k3sm/keystore-floor.json /var/lib/k3sm/keystore-floor.json.pre-restore || exit 1",
			"sudo test ! -e /var/lib/k3sm/pre-restore.d/restored || exit 1",
			"sudo test ! -L /path/to/backup/$B/keystore || exit 1",
			"sudo ditto /path/to/backup/$B/keystore /var/lib/k3sm/pre-restore.d/restored || exit 1",
			"sudo install -o root -g wheel -m 0644 /var/root/keystore-floor-backup/$B/keystore-floor.json /var/lib/k3sm/keystore-floor.json || exit 1",
			"sudo k3sm keys floor merge",
			"sudo k3sm keys rm system/<name> --yes",
			"sudo k3sm start",
			// The undo: the floors moved back, then the reverse merge, the
			// restored floor as the input, so a deletion made after the
			// restore survives the undo.
			"sudo k3sm stop",
			"! pgrep -u _k3sm || exit 1",
			"sudo test ! -e /var/lib/k3sm/pre-restore.d/restored || exit 1",
			"sudo mv /var/lib/k3sm/pre-restore.d/keystore /var/lib/k3sm/pre-restore.d/restored || exit 1",
			"sudo mv /var/lib/k3sm/server/keystore /var/lib/k3sm/pre-restore.d/keystore || exit 1",
			"sudo mv /var/lib/k3sm/keystore-floor.json.pre-restore /var/lib/k3sm/keystore-floor.json.undo || exit 1",
			"sudo mv /var/lib/k3sm/keystore-floor.json /var/lib/k3sm/keystore-floor.json.pre-restore || exit 1",
			"sudo mv /var/lib/k3sm/keystore-floor.json.undo /var/lib/k3sm/keystore-floor.json || exit 1",
			"sudo k3sm keys floor merge --undo --dry-run",
			"sudo k3sm keys floor merge --undo",
			"sudo rm -rf /var/lib/k3sm/pre-restore.d",
			"sudo k3sm start",
		}
		at := 0
		for _, step := range steps {
			i := strings.Index(doc[at:], step)
			if i < 0 {
				t.Fatalf("docs/user/keys.md does not say %q after the step before it", step)
			}
			at += i + len(step)
		}
	})
	// A recursive ownership, mode or flag change run as root over a tree the
	// service user wrote follows a hard link it planted there to any inode
	// on the volume, so no recipe line in the user docs makes one.
	t.Run("no recipe line changes owner, mode or flags recursively", func(t *testing.T) {
		docs, err := filepath.Glob(filepath.Join("..", "..", "docs", "user", "*.md"))
		if err != nil || len(docs) == 0 {
			t.Fatalf("docs/user/*.md: %v, %d files", err, len(docs))
		}
		for _, doc := range docs {
			raw, err := os.ReadFile(doc)
			if err != nil {
				t.Fatal(err)
			}
			for n, line := range recipeLines(string(raw)) {
				if recursiveChange(line) {
					t.Errorf("%s: recipe line %d %q changes owner, mode or flags recursively", filepath.Base(doc), n, line)
				}
			}
		}
	})
	t.Run("save rm restore", func(t *testing.T) {
		h := newKeysHarness(t)
		value, aside := saveRmRestore(t, h, true)
		floor := recipeFloor(h)
		// The moved-aside floor is the live one, tombstone and all.
		if b, err := os.ReadFile(floor + ".pre-restore"); err != nil || !strings.Contains(string(b), `"tombstones":{"rb":`) {
			t.Fatalf("moved-aside floor = %s, %v; want the live floor with rb's tombstone", b, err)
		}
		if got := recipeDeletedNames(t, h); !slices.Equal(got, []string{"rb"}) {
			t.Fatalf("names the moved-aside floor records as deleted = %q, want rb", got)
		}
		if fi, err := os.Stat(recipePreRestore(h)); err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("pre-restore.d = %v, %v; want mode 0700", fi, err)
		}
		if _, err := os.Lstat(h.keystoreDir()); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("keystore/ before the merge: %v, want it absent, the restored tree staged", err)
		}
		h.mustRun(keysCommitted, "floor", "merge", "--keep", "system/rb")
		h.mustRun(0, "list")
		h.mustRun(0, "show", "system/rb", "--reveal")
		if !bytes.Equal(h.stdout.Bytes(), value) {
			t.Fatalf("restored value = %q, want %q", h.stdout.Bytes(), value)
		}
		if filepath.Dir(aside) != recipePreRestore(h) {
			t.Fatalf("moved-aside keystore/ = %s, want it inside pre-restore.d", aside)
		}
		if fi, err := os.Stat(recipePreRestore(h)); err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("pre-restore.d = %v, %v; want mode 0700", fi, err)
		}
		for _, p := range []string{recipePreRestore(h), floor + ".pre-restore"} {
			if err := os.RemoveAll(p); err != nil {
				t.Fatal(err)
			}
		}
	})
	// A key deleted to revoke it since the backup is deleted again by the
	// merge, which buries the restored generation, reports it as buried
	// live and removes its restored directory, so no rm is needed and it
	// stays deleted.
	t.Run("save rm restore, the revoked key buried by the merge", func(t *testing.T) {
		h := newKeysHarness(t)
		saveRmRestore(t, h, true)
		h.mustRun(0, "floor", "merge")
		if got := h.stdout.String(); !strings.Contains(got, "merged 1\nalready present 0\nburied live 1\nkept 0\nretired 0\ndropped 0\n") || !strings.Contains(got, "buried live system/rb:") {
			t.Fatalf("floor merge printed %q, want rb buried live", got)
		}
		if _, err := os.Lstat(filepath.Join(h.keystoreDir(), "rb")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("rb's directory after the merge: %v, want it removed", err)
		}
		h.mustRun(1, "show", "system/rb", "--reveal")
		if h.stdout.Len() != 0 {
			t.Fatalf("show printed %q for the key buried by the merge", h.stdout.Bytes())
		}
		if _, err := os.Lstat(filepath.Join(h.keystoreDir(), "rb")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("rb's directory after rm: %v, want it removed", err)
		}
	})
	// --keep keeps the restored generation of an entry deleted since the
	// backup live: the entry restored on purpose.
	t.Run("save rm restore, the key kept with --keep", func(t *testing.T) {
		h := newKeysHarness(t)
		value, _ := saveRmRestore(t, h, true)
		h.mustRun(2, "floor", "merge", "--keep", "rb")
		// A --keep name that matches nothing refuses the merge, nothing
		// written, and the input stays for the merge run again.
		before, err := os.ReadFile(recipeFloor(h))
		if err != nil {
			t.Fatal(err)
		}
		if code := h.run("floor", "merge", "--keep", "system/rb", "--keep", "system/typo"); code != keysRefused || !strings.Contains(h.stderr.String(), "typo") {
			t.Fatalf("floor merge with an unmatched --keep: exit %d, stderr %q; want %d naming typo", code, h.stderr.String(), keysRefused)
		}
		if after, err := os.ReadFile(recipeFloor(h)); err != nil || !bytes.Equal(after, before) {
			t.Fatalf("live floor after the refused merge = %s, %v; want it unchanged", after, err)
		}
		h.mustRun(keysCommitted, "floor", "merge", "--keep", "system/rb")
		if got := h.stdout.String(); !strings.Contains(got, "merged 0\nalready present 0\nburied live 0\nkept 1\nretired 0\ndropped 0\n") || !strings.Contains(got, "kept system/rb:") {
			t.Fatalf("floor merge --keep printed %q, want rb kept", got)
		}
		if got := h.stderr.String(); !strings.Contains(got, "warning: system/rb is kept live") {
			t.Fatalf("floor merge --keep stderr %q, want the kept name warned about", got)
		}
		h.mustRun(0, "show", "system/rb", "--reveal")
		if !bytes.Equal(h.stdout.Bytes(), value) {
			t.Fatalf("kept value = %q, want %q", h.stdout.Bytes(), value)
		}
	})
	// A key created after the backup and revoked before the restore is in
	// neither the backup nor the restored floor; the merge carries its
	// tombstone over, so its copy put back is refused.
	t.Run("a key created and revoked after the backup stays refused", func(t *testing.T) {
		h := newKeysHarness(t)
		h.put("system/base", []byte("base"))
		b := saveRecipeBackup(t, h, filepath.Join(t.TempDir(), "keystore-floor-backup"), "2026-11-22")
		h.put("system/late", []byte("late"))
		late := filepath.Join(t.TempDir(), "late")
		copyTree(t, filepath.Join(h.keystoreDir(), "late"), late)
		h.mustRun(0, "rm", "system/late", "--yes")
		if _, err := restoreRecipeBackup(t, h, b, true); err != nil {
			t.Fatalf("restore: %v", err)
		}
		h.mustRun(0, "floor", "merge")
		if got := h.stdout.String(); !strings.HasPrefix(got, "merged 1\nalready present 0\nburied live 0\nkept 0\nretired 0\ndropped 0\n") {
			t.Fatalf("floor merge printed %q, want late's burial merged", got)
		}
		copyTree(t, late, filepath.Join(h.keystoreDir(), "late"))
		refusedDeleted(t, h, "system/late")
		h.mustRun(0, "show", "system/base", "--reveal")
	})
	// N is live as G1 at the backup, deleted, then put again as G2. The
	// restore puts G1 back, which the merge buries; G2, live in the floor
	// moved aside, is buried too, since choosing the backup retired it, so
	// G2's directory put back is refused.
	t.Run("a generation put after the backup is retired by the merge", func(t *testing.T) {
		h := newKeysHarness(t)
		h.put("system/n", []byte("g1"))
		b := saveRecipeBackup(t, h, filepath.Join(t.TempDir(), "keystore-floor-backup"), "2026-11-22")
		h.mustRun(0, "rm", "system/n", "--yes")
		h.put("system/n", []byte("g2"))
		g2 := filepath.Join(t.TempDir(), "n")
		copyTree(t, filepath.Join(h.keystoreDir(), "n"), g2)
		if _, err := restoreRecipeBackup(t, h, b, true); err != nil {
			t.Fatalf("restore: %v", err)
		}
		h.mustRun(0, "floor", "merge")
		merged := h.stdout.String()
		// The merge buried G1 live and removed its restored directory.
		if _, err := os.Lstat(filepath.Join(h.keystoreDir(), "n")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("n's directory after the merge: %v, want it removed", err)
		}
		copyTree(t, g2, filepath.Join(h.keystoreDir(), "n"))
		refusedDeleted(t, h, "system/n")
		if !strings.Contains(merged, "retired 1\n") || !strings.Contains(merged, "\nretired system/n:") {
			t.Fatalf("floor merge printed %q, want G2 retired and named", merged)
		}
	})
	// --keep keeps only the restored generation: with N live as G1 at the
	// backup, deleted and put again as G2, a merge keeping N keeps G1 live
	// and still retires G2, so after rm N a copy of G2 put back is refused.
	t.Run("--keep keeps only the restored generation", func(t *testing.T) {
		h := newKeysHarness(t)
		h.put("system/n", []byte("g1"))
		b := saveRecipeBackup(t, h, filepath.Join(t.TempDir(), "keystore-floor-backup"), "2026-11-22")
		h.mustRun(0, "rm", "system/n", "--yes")
		h.put("system/n", []byte("g2"))
		g2 := filepath.Join(t.TempDir(), "n")
		copyTree(t, filepath.Join(h.keystoreDir(), "n"), g2)
		if _, err := restoreRecipeBackup(t, h, b, true); err != nil {
			t.Fatalf("restore: %v", err)
		}
		h.mustRun(keysCommitted, "floor", "merge", "--keep", "system/n")
		if got := h.stdout.String(); !strings.Contains(got, "kept 1\nretired 1\n") || !strings.Contains(got, "\nretired system/n:") {
			t.Fatalf("floor merge --keep printed %q, want n kept and G2 retired", got)
		}
		h.mustRun(0, "show", "system/n", "--reveal")
		if got := h.stdout.String(); got != "g1" {
			t.Fatalf("kept n = %q, want g1", got)
		}
		h.mustRun(0, "rm", "system/n", "--yes")
		copyTree(t, g2, filepath.Join(h.keystoreDir(), "n"))
		refusedDeleted(t, h, "system/n")
	})
	// A name with two generations buried after the backup keeps both
	// burials through the merge: a copy of either is refused.
	t.Run("two generations buried after the backup stay refused", func(t *testing.T) {
		h := newKeysHarness(t)
		h.put("system/base", []byte("base"))
		b := saveRecipeBackup(t, h, filepath.Join(t.TempDir(), "keystore-floor-backup"), "2026-11-22")
		var copies []string
		for i := range 2 {
			h.put("system/twice", []byte(fmt.Sprintf("gen %d", i)))
			c := filepath.Join(t.TempDir(), "twice")
			copyTree(t, filepath.Join(h.keystoreDir(), "twice"), c)
			copies = append(copies, c)
			h.mustRun(0, "rm", "system/twice", "--yes")
		}
		if _, err := restoreRecipeBackup(t, h, b, true); err != nil {
			t.Fatalf("restore: %v", err)
		}
		h.mustRun(0, "floor", "merge")
		if got := h.stdout.String(); !strings.HasPrefix(got, "merged 2\n") {
			t.Fatalf("floor merge printed %q, want both burials merged", got)
		}
		for _, c := range copies {
			copyTree(t, c, filepath.Join(h.keystoreDir(), "twice"))
			refusedDeleted(t, h, "system/twice")
			if err := os.RemoveAll(filepath.Join(h.keystoreDir(), "twice")); err != nil {
				t.Fatal(err)
			}
		}
	})
	// A .pre-restore copy left by an earlier restore is never replaced:
	// the check refuses before anything moves.
	t.Run("a pre-restore copy still set aside refuses", func(t *testing.T) {
		for _, which := range []string{"keystore", "floor"} {
			t.Run(which, func(t *testing.T) {
				h := newKeysHarness(t)
				h.put("system/rb", []byte("v"))
				b := saveRecipeBackup(t, h, filepath.Join(t.TempDir(), "keystore-floor-backup"), "2026-11-22")
				left := recipeFloor(h) + ".pre-restore"
				if which == "keystore" {
					left = recipePreRestore(h)
				}
				if err := os.WriteFile(left, []byte("earlier\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				live, err := os.ReadFile(recipeFloor(h))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := restoreRecipeBackup(t, h, b, true); err == nil {
					t.Fatal("restore with a .pre-restore copy set aside went on")
				}
				if got, err := os.ReadFile(left); err != nil || string(got) != "earlier\n" {
					t.Fatalf("the earlier .pre-restore copy = %q, %v; want it untouched", got, err)
				}
				if got, err := os.ReadFile(recipeFloor(h)); err != nil || !bytes.Equal(got, live) {
					t.Fatalf("the live floor = %s, %v; want it untouched", got, err)
				}
				h.mustRun(0, "show", "system/rb", "--reveal")
			})
		}
	})
	// A saved floor changed since the save fails its SHA-256 check, and the
	// restore stops before anything moves.
	t.Run("a saved floor changed since the save refuses", func(t *testing.T) {
		h := newKeysHarness(t)
		h.put("system/rb", []byte("v"))
		b := saveRecipeBackup(t, h, filepath.Join(t.TempDir(), "keystore-floor-backup"), "2026-11-22")
		h.mustRun(0, "rm", "system/rb", "--yes")
		raw, err := os.ReadFile(b.floor)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(b.floor, append(raw, ' '), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := restoreRecipeBackup(t, h, b, true); err == nil {
			t.Fatal("restore with a changed saved floor went on")
		}
		if _, err := os.Lstat(recipePreRestore(h)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("keystore/ was moved aside before the check: %v", err)
		}
		h.mustRun(1, "show", "system/rb", "--reveal")
	})
	// Each backup keeps the floor saved under its name, so an older backup
	// restores with its own floor after a newer one is saved.
	t.Run("an older backup keeps its own floor", func(t *testing.T) {
		h := newKeysHarness(t)
		floorRoot := filepath.Join(t.TempDir(), "keystore-floor-backup")
		h.put("system/rb", []byte("old"))
		older := saveRecipeBackup(t, h, floorRoot, "2026-11-01")
		h.mustRun(0, "rm", "system/rb", "--yes")
		h.put("system/other", []byte("new"))
		newer := saveRecipeBackup(t, h, floorRoot, "2026-11-22")
		if older.floor == newer.floor {
			t.Fatalf("both backups saved their floor to %s", older.floor)
		}
		if _, err := restoreRecipeBackup(t, h, older, true); err != nil {
			t.Fatalf("restore of the older backup: %v", err)
		}
		h.mustRun(keysCommitted, "floor", "merge", "--keep", "system/rb")
		h.mustRun(0, "list")
		h.mustRun(0, "show", "system/rb", "--reveal")
		if got := h.stdout.String(); got != "old" {
			t.Fatalf("restored rb = %q, want old", got)
		}
	})
	// The undo steps: the restored keystore/ is renamed out of the way
	// first, since mv onto a directory that exists moves the source inside
	// it, then the moved-aside copy goes back; the floors swap places, the
	// restored one becoming the guard file, and the merge runs in reverse.
	// The live state, rb deleted, is what the CLI sees, and other, deleted
	// after the restore, stays deleted.
	t.Run("save rm restore, then undo", func(t *testing.T) {
		h := newKeysHarness(t)
		h.put("system/other", []byte("o"))
		_, aside := saveRmRestore(t, h, true)
		h.mustRun(keysCommitted, "floor", "merge", "--keep", "system/rb")
		h.mustRun(0, "rm", "system/other", "--yes")
		floor := recipeFloor(h)
		merged := mergedFloors(t, floor)
		staged := filepath.Join(recipePreRestore(h), "restored")
		if _, err := os.Lstat(staged); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("test ! -e %s: %v", staged, err)
		}
		for _, mv := range [][2]string{
			{aside, staged},
			{h.keystoreDir(), aside},
			{merged[0], floor + ".undo"},
			{floor, floor + ".pre-restore"},
			{floor + ".undo", floor},
		} {
			if err := os.Rename(mv[0], mv[1]); err != nil {
				t.Fatal(err)
			}
		}
		h.mustRun(0, "floor", "merge", "--undo", "--dry-run")
		if out := h.stdout.String(); !strings.Contains(out, "buried live system/other: deleted since the restore") {
			t.Fatalf("the reverse merge --dry-run printed %q, want other buried live, deleted since the restore", out)
		}
		h.mustRun(0, "floor", "merge", "--undo")
		if _, err := os.Lstat(filepath.Join(h.keystoreDir(), "other")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("other's directory after the reverse merge: %v, want it removed", err)
		}
		h.mustRun(1, "show", "system/other", "--reveal")
		// The merge moved the staged tree into place; the restored tree is
		// left in pre-restore.d as keystore, and rm -rf removes it.
		if _, err := os.Lstat(staged); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("staged tree after the reverse merge: %v, want it moved", err)
		}
		if err := os.RemoveAll(recipePreRestore(h)); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(filepath.Join(h.keystoreDir(), "keystore")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("undo nested a keystore/ inside the live one: %v", err)
		}
		h.mustRun(0, "list")
		h.mustRun(1, "show", "system/rb", "--reveal")
		if b, err := os.ReadFile(floor); err != nil || !strings.Contains(string(b), `"rb":[{"generation"`) || !strings.Contains(string(b), `"other":[{"generation"`) {
			t.Fatalf("floor after the undo = %s, %v; want the live floor with rb's tombstone and other's from after the restore", b, err)
		}
	})
	// The reverse merge with --undo reads the retired record the restore's
	// merge left: late, put after the backup and retired by the restore, is
	// reported apart from other, deleted since the restore; --keep brings
	// late back and is refused on other; and with no record --undo refuses.
	t.Run("undo reports what the restore retired apart from later deletions", func(t *testing.T) {
		h := newKeysHarness(t)
		h.put("system/other", []byte("o"))
		b := saveRecipeBackup(t, h, filepath.Join(t.TempDir(), "keystore-floor-backup"), "2026-11-22")
		h.put("system/late", []byte("l"))
		aside, err := restoreRecipeBackup(t, h, b, true)
		if err != nil {
			t.Fatalf("restore: %v", err)
		}
		h.mustRun(0, "floor", "merge")
		if out := h.stdout.String(); !strings.Contains(out, "retired system/late:") {
			t.Fatalf("the restore's merge printed %q, want late retired", out)
		}
		h.mustRun(0, "rm", "system/other", "--yes")
		floor := recipeFloor(h)
		merged := mergedFloors(t, floor)
		staged := filepath.Join(recipePreRestore(h), "restored")
		for _, mv := range [][2]string{
			{aside, staged},
			{h.keystoreDir(), aside},
			{merged[0], floor + ".undo"},
			{floor, floor + ".pre-restore"},
			{floor + ".undo", floor},
		} {
			if err := os.Rename(mv[0], mv[1]); err != nil {
				t.Fatal(err)
			}
		}
		record := merged[0] + ".retired"
		if err := os.Rename(record, record+".aside"); err != nil {
			t.Fatal(err)
		}
		h.mustRun(keysRefused, "floor", "merge", "--undo", "--dry-run")
		if !strings.Contains(h.stderr.String(), "there is none") {
			t.Fatalf("--undo with no retired record: stderr %q, want it refused for the missing record", h.stderr.String())
		}
		if err := os.Rename(record+".aside", record); err != nil {
			t.Fatal(err)
		}
		h.mustRun(0, "floor", "merge", "--undo", "--dry-run")
		out := h.stdout.String()
		if !strings.Contains(out, "buried live system/late: retired by the restore: pass --keep system/late") || !strings.Contains(out, "buried live system/other: deleted since the restore: stays deleted") {
			t.Fatalf("the reverse merge --dry-run printed %q, want late retired by the restore and other deleted since, apart", out)
		}
		h.mustRun(keysRefused, "floor", "merge", "--undo", "--keep", "system/other")
		if !strings.Contains(h.stderr.String(), "deleted since the restore") {
			t.Fatalf("--keep on other: stderr %q, want it refused as deleted since the restore", h.stderr.String())
		}
		h.mustRun(keysCommitted, "floor", "merge", "--undo", "--keep", "system/late")
		h.mustRun(0, "show", "system/late", "--reveal")
		if got := h.stdout.String(); got != "l" {
			t.Fatalf("late after the undo = %q, want l", got)
		}
		if _, err := os.Lstat(filepath.Join(h.keystoreDir(), "other")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("other's directory after the reverse merge: %v, want it removed", err)
		}
		h.mustRun(1, "show", "system/other", "--reveal")
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
	got := h.cfg
	if got.LogFlags != nil {
		t.Fatal("the install layout's config sets a flag source; production reads st_flags")
	}
	got.LogFlags = nil
	if !reflect.DeepEqual(got, want) {
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

// TestKeysAdopt is G9's CLI half: keys adopt is root-only, prints the
// current version and the orphan above it, and adopts only with --yes or a
// confirmation typed at a terminal. The orphan here is a newer version
// behind a copied-back pointer with the floor lagging, which leaves the
// same files a crashed rotation does.
func TestKeysAdopt(t *testing.T) {
	h := newKeysHarness(t)
	h.put("system/alpha", []byte("one"))
	cur := filepath.Join(h.keystoreDir(), "alpha", "current")
	saved, err := os.ReadFile(cur)
	if err != nil {
		t.Fatal(err)
	}
	h.stdin = strings.NewReader("two")
	h.mustRun(0, "rotate", "system/alpha", "--in", "-")
	if err := os.WriteFile(cur, saved, 0o600); err != nil {
		t.Fatal(err)
	}
	floorPath := filepath.Join(filepath.Dir(h.work), "keystore-floor.json")
	b, err := os.ReadFile(floorPath)
	if err != nil {
		t.Fatal(err)
	}
	lagged := strings.Replace(string(b), `"seq":2`, `"seq":1`, 1)
	if lagged == string(b) {
		t.Fatalf("the floor does not record sequence 2: %s", b)
	}
	if err := os.WriteFile(floorPath, []byte(lagged), 0o600); err != nil {
		t.Fatal(err)
	}

	h.euid = 501
	h.mustRun(1, "adopt", "system/alpha", "--yes")
	if !strings.Contains(h.stderr.String(), "run as root") {
		t.Fatalf("adopt as non-root: %s", h.stderr.String())
	}
	h.euid = 0

	// Neither --yes nor a terminal: both sides printed, nothing changed.
	info, err := keystore.New(h.storeCfg).Orphan(context.Background(), "alpha")
	if err != nil {
		t.Fatal(err)
	}
	h.mustRun(2, "adopt", "system/alpha")
	for _, want := range []string{
		"current:  version 1, opaque",
		adoptSide(info.Current, time.Time{}),
		"orphan:   version 2, opaque",
		adoptSide(info.Orphan, time.Time{}),
		"pass --yes",
	} {
		if !strings.Contains(h.stdout.String()+h.stderr.String(), want) {
			t.Fatalf("adopt without --yes does not print %q:\nstdout:\n%s\nstderr:\n%s", want, h.stdout.String(), h.stderr.String())
		}
	}
	if strings.Contains(h.stdout.String(), "issuedAt") {
		t.Fatalf("adopt printed an issuedAt for an opaque entry:\n%s", h.stdout.String())
	}
	// A terminal answering no changes nothing either.
	h.stdinTTY = true
	h.stdin = strings.NewReader("n\n")
	h.mustRun(1, "adopt", "system/alpha")
	// A read refuses the orphan (ErrOrphanVersion), so the pointer file is
	// what shows nothing changed.
	if got, err := os.ReadFile(cur); err != nil || !bytes.Equal(got, saved) {
		t.Fatalf("the declined adopt changed the current pointer (%v)", err)
	}
	h.stdin = strings.NewReader("yes\n")
	h.mustRun(0, "adopt", "system/alpha")
	if !strings.Contains(h.stdout.String(), "adopted system/alpha version 2") {
		t.Fatalf("adopt output:\n%s", h.stdout.String())
	}
	h.stdinTTY = false
	h.mustRun(0, "show", "system/alpha", "--reveal", "--yes")
	if h.stdout.String() != "two" {
		t.Fatalf("current after adopt = %q, want two", h.stdout.String())
	}
	h.mustRun(1, "adopt", "system/alpha", "--yes")
	if !strings.Contains(h.stderr.String(), "no sealed version lies above") {
		t.Fatalf("adopt with nothing to adopt: %s", h.stderr.String())
	}
	if strings.Contains(h.stdout.String()+h.stderr.String(), "two") {
		t.Fatal("adopt printed a value")
	}

	t.Run("typed", func(t *testing.T) { keysAdoptTyped(t) })
}

// adoptSide is the block `keys adopt` prints under one side's heading: the
// fingerprint, the record digest, the sealed issuedAt when issued is set,
// and the unauthenticated created time.
func adoptSide(v keystore.Version, issued time.Time) string {
	b := fmt.Sprintf("  fingerprint:    %s\n  record digest:  %s\n", v.Fingerprint, v.RecordDigest())
	if !issued.IsZero() {
		b += fmt.Sprintf("  issuedAt:       %s (sealed)\n", issued.UTC().Format(time.RFC3339))
	}
	return b + fmt.Sprintf("  created:        %s (unauthenticated)\n", v.Created.UTC().Format(time.RFC3339))
}

// keysAdoptTyped is TestKeysAdopt for a token entry: each side also shows
// the issuedAt sealed in its envelope, and no output carries the token.
func keysAdoptTyped(t *testing.T) {
	ctx := context.Background()
	h := newKeysHarness(t)
	h.put("system/seed", []byte("s")) // opens the store config
	st := keystore.New(h.storeCfg)
	marker1, marker2 := "MARKER-adopt-first-9c41e7", "MARKER-adopt-orphan-5d2b08"
	token := func(v string) typed.Envelope {
		return typed.Envelope{Credential: typed.Credential{Value: []byte(v), ExpiresAt: time.Now().Add(time.Hour)}}
	}
	if _, err := st.PutCredential(ctx, "tok", keystore.KindToken, token(marker1)); err != nil {
		t.Fatal(err)
	}
	_, c1, err := st.CurrentCredential(ctx, "tok")
	if err != nil {
		t.Fatal(err)
	}
	cur := filepath.Join(h.keystoreDir(), "tok", "current")
	saved, err := os.ReadFile(cur)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.RotateCredential(ctx, "tok", keystore.KindToken, token(marker2)); err != nil {
		t.Fatal(err)
	}
	_, c2, err := st.CurrentCredential(ctx, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cur, saved, 0o600); err != nil {
		t.Fatal(err)
	}
	floorPath := filepath.Join(filepath.Dir(h.work), "keystore-floor.json")
	b, err := os.ReadFile(floorPath)
	if err != nil {
		t.Fatal(err)
	}
	lagged := strings.Replace(string(b), `"seq":2`, `"seq":1`, 1)
	if lagged == string(b) {
		t.Fatalf("the floor does not record sequence 2: %s", b)
	}
	if err := os.WriteFile(floorPath, []byte(lagged), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := st.Orphan(ctx, "tok")
	if err != nil {
		t.Fatal(err)
	}

	h.mustRun(2, "adopt", "system/tok")
	out := h.stdout.String() + h.stderr.String()
	for _, want := range []string{
		"current:  version 1, token",
		adoptSide(info.Current, c1.IssuedAt),
		"orphan:   version 2, token",
		adoptSide(info.Orphan, c2.IssuedAt),
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("adopt does not print %q:\n%s", want, out)
		}
	}
	h.mustRun(0, "adopt", "system/tok", "--yes")
	out += h.stdout.String() + h.stderr.String()
	for _, m := range []string{marker1, marker2} {
		if strings.Contains(out, m) {
			t.Fatalf("adopt printed the token value %q:\n%s", m, out)
		}
	}
}

// committedStore reports every write it makes as committed with a failed
// step after the commit point, which the real store reaches only through a
// failing fsync or floor write a test cannot cause from outside.
type committedStore struct{ keysStore }

func (c committedStore) Put(ctx context.Context, name string, kind keystore.Kind, value []byte) (keystore.Version, error) {
	v, err := c.keysStore.Put(ctx, name, kind, value)
	if err != nil {
		return v, err
	}
	return v, fmt.Errorf("%w: injected failure after the commit point", keystore.ErrCommitted)
}

func (c committedStore) Rotate(ctx context.Context, name string, value []byte) (keystore.Version, error) {
	v, err := c.keysStore.Rotate(ctx, name, value)
	if err != nil {
		return v, err
	}
	return v, fmt.Errorf("%w: injected failure after the commit point", keystore.ErrCommitted)
}

func (c committedStore) Adopt(ctx context.Context, name string, orphan keystore.Version) (keystore.Version, error) {
	v, err := c.keysStore.Adopt(ctx, name, orphan)
	if err != nil {
		return v, err
	}
	return v, fmt.Errorf("%w: injected failure after the commit point", keystore.ErrCommitted)
}

// TestKeysCommittedExitCode is review round 4, item 6: put, rotate and adopt
// exit keysCommitted, not keysRefused, when the write committed and a step
// after it failed, and the usage text names the code.
func TestKeysCommittedExitCode(t *testing.T) {
	h := newKeysHarness(t)
	h.wrap = func(s keysStore) keysStore { return committedStore{s} }
	h.stdin = strings.NewReader("one")
	h.mustRun(keysCommitted, "put", "system/alpha", "--in", "-")
	cur := filepath.Join(h.keystoreDir(), "alpha", "current")
	saved, err := os.ReadFile(cur)
	if err != nil {
		t.Fatal(err)
	}
	h.stdin = strings.NewReader("two")
	h.mustRun(keysCommitted, "rotate", "system/alpha", "--in", "-")
	if got := h.value("alpha", 2); string(got) != "two" {
		t.Fatalf("alpha v2 = %q after the committed rotate", got)
	}
	// A copied-back pointer behind a lagging floor leaves version 2 to adopt.
	if err := os.WriteFile(cur, saved, 0o600); err != nil {
		t.Fatal(err)
	}
	floorPath := filepath.Join(filepath.Dir(h.work), "keystore-floor.json")
	b, err := os.ReadFile(floorPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(floorPath, []byte(strings.Replace(string(b), `"seq":2`, `"seq":1`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	h.mustRun(keysCommitted, "adopt", "system/alpha", "--yes")
	if !strings.Contains(h.stdout.String(), "adopted system/alpha version 2") {
		t.Fatalf("committed adopt output:\n%s", h.stdout.String())
	}
	if keysCommitted == keysRefused || keysCommitted == keysBadUsage || keysCommitted == keysResumed {
		t.Fatalf("keysCommitted %d is not distinct", keysCommitted)
	}
	if !strings.Contains(keysUsage, fmt.Sprintf("%d the change was made", keysCommitted)) {
		t.Fatalf("usage does not name exit code %d:\n%s", keysCommitted, keysUsage)
	}
}

// plantBurials sets name's tombstones in the floor file at p to n
// generations numbered from start, at delete sequences numbered from start,
// keeping the file's mode.
func plantBurials(t *testing.T, p, name string, start, n int) {
	t.Helper()
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	// The floor's own encoding, field for field, which parses only in the
	// form a keys verb writes.
	type burial struct {
		Generation string `json:"generation"`
		Deleted    int    `json:"deleted"`
	}
	var f struct {
		Version    int                        `json:"version"`
		Scope      string                     `json:"scope"`
		Entries    map[string]json.RawMessage `json:"entries"`
		Tombstones map[string][]burial        `json:"tombstones,omitempty"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Tombstones == nil {
		f.Tombstones = map[string][]burial{}
	}
	var bs []burial
	for i := range n {
		bs = append(bs, burial{fmt.Sprintf("%032x", start+i), start + i})
	}
	f.Tombstones[name] = bs
	out, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

// keysPerNameCap is the floor's cap of buried generations a name
// (pkg/keystore's maxBuriedPerName).
const keysPerNameCap = 64

// TestKeysEvictionExitsCommitted: rm whose floor write evicts a tombstone,
// here at the per-name cap, deletes the entry and exits 4, the change made;
// floor merge whose write drops a burial prints its report and exits 4 too.
func TestKeysEvictionExitsCommitted(t *testing.T) {
	t.Run("rm", func(t *testing.T) {
		h := newKeysHarness(t)
		h.put("system/k", []byte("v"))
		plantBurials(t, recipeFloor(h), "k", 1000, keysPerNameCap)
		if code := h.run("rm", "system/k", "--yes"); code != keysCommitted {
			t.Fatalf("rm at the per-name cap: exit %d, stderr %q; want %d", code, h.stderr.String(), keysCommitted)
		}
		if !strings.Contains(h.stdout.String(), "deleted system/k") || !strings.Contains(h.stderr.String(), "1 tombstone(s) evicted") {
			t.Fatalf("rm at the per-name cap printed %q, %q; want deleted and the eviction named", h.stdout.String(), h.stderr.String())
		}
		h.mustRun(1, "show", "system/k")
	})
	// rm whose burial evicts one and whose tree removal then fails (.lock
	// replaced by a directory) deleted the entry: exit 4, not 1.
	t.Run("rm with its tree left behind", func(t *testing.T) {
		h := newKeysHarness(t)
		h.put("system/k", []byte("v"))
		plantBurials(t, recipeFloor(h), "k", 1000, keysPerNameCap)
		lock := filepath.Join(h.keystoreDir(), ".lock")
		if err := os.Remove(lock); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(lock, 0o700); err != nil {
			t.Fatal(err)
		}
		if code := h.run("rm", "system/k", "--yes"); code != keysCommitted {
			t.Fatalf("rm at the cap with its tree left behind: exit %d, stderr %q; want %d", code, h.stderr.String(), keysCommitted)
		}
		if !strings.Contains(h.stderr.String(), "already deleted") || !strings.Contains(h.stdout.String(), "deleted system/k") {
			t.Fatalf("rm printed %q, %q; want deleted, and the tree left behind named", h.stdout.String(), h.stderr.String())
		}
	})
	// put over a live record of another generation (a Delete interrupted
	// before its floor write) at the per-name cap buries it and evicts the
	// oldest: the entry is created, exit 4.
	t.Run("put", func(t *testing.T) {
		h := newKeysHarness(t)
		h.put("system/k", []byte("v"))
		plantBurials(t, recipeFloor(h), "k", 1000, keysPerNameCap)
		if err := os.RemoveAll(filepath.Join(h.keystoreDir(), "k")); err != nil {
			t.Fatal(err)
		}
		h.stdin = strings.NewReader("w")
		if code := h.run("put", "system/k", "--in", "-"); code != keysCommitted {
			t.Fatalf("put at the cap: exit %d, stderr %q; want %d", code, h.stderr.String(), keysCommitted)
		}
		if !strings.Contains(h.stdout.String(), "created system/k") || !strings.Contains(h.stderr.String(), "tombstone(s) evicted") {
			t.Fatalf("put printed %q, %q; want created and the eviction named", h.stdout.String(), h.stderr.String())
		}
		h.mustRun(0, "show", "system/k", "--reveal")
	})
	t.Run("floor merge", func(t *testing.T) {
		h := newKeysHarness(t)
		h.put("system/k", []byte("v"))
		h.mustRun(0, "rm", "system/k", "--yes")
		aside := recipeFloor(h) + ".pre-restore"
		raw, err := os.ReadFile(recipeFloor(h))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(aside, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		plantBurials(t, aside, "k", 1000, keysPerNameCap)
		stageKeystore(t, h)
		// Any drop refuses without --accept-drops, the restored floor's
		// own burial included.
		if code := h.run("floor", "merge"); code != keysRefused {
			t.Fatalf("floor merge that drops a burial: exit %d, stderr %q; want %d", code, h.stderr.String(), keysRefused)
		}
		if code := h.run("floor", "merge", "--accept-drops"); code != keysCommitted {
			t.Fatalf("floor merge --accept-drops that drops a burial: exit %d, stderr %q; want %d", code, h.stderr.String(), keysCommitted)
		}
		if got := h.stdout.String(); !strings.Contains(got, "dropped 1\n") || !strings.Contains(got, "dropped system/k:") {
			t.Fatalf("floor merge printed %q, want the drop reported", got)
		}
	})
}

// TestKeysPendingMergeGuard (U192): while the restore's
// keystore-floor.json.pre-restore is in the data root, put and rotate
// refuse, naming keys floor merge, and list, show and rm still run, with a
// warning on stderr (show finds nothing: the restored tree is staged until
// the merge moves it into place); floor merge renames it to
// keystore-floor.json.merged-<unix>, and the verbs work again.
func TestKeysPendingMergeGuard(t *testing.T) {
	h := newKeysHarness(t)
	h.put("system/k", []byte("v"))
	h.put("system/j", []byte("j"))
	b := saveRecipeBackup(t, h, filepath.Join(t.TempDir(), "keystore-floor-backup"), "2026-11-22")
	h.mustRun(0, "rm", "system/k", "--yes")
	if _, err := restoreRecipeBackup(t, h, b, true); err != nil {
		t.Fatalf("restore: %v", err)
	}
	for _, args := range [][]string{
		{"put", "system/n", "--in", "-"},
		{"rotate", "system/k", "--in", "-"},
	} {
		h.stdin = strings.NewReader("value")
		if code := h.run(args...); code != keysRefused || !strings.Contains(h.stderr.String(), "keys floor merge") {
			t.Fatalf("%s with a merge pending: exit %d, stderr %q; want %d naming keys floor merge", args[0], code, h.stderr.String(), keysRefused)
		}
	}
	h.mustRun(0, "list")
	if !strings.Contains(h.stderr.String(), "warning: a restore is unfinished") {
		t.Fatalf("list with a merge pending: stderr %q; want the warning", h.stderr.String())
	}
	// The restored tree is staged until the merge moves it into place, so
	// show finds no entry yet, with the same warning.
	h.mustRun(1, "show", "system/k")
	if !strings.Contains(h.stderr.String(), "warning: a restore is unfinished") {
		t.Fatalf("show with a merge pending: stderr %q; want the warning", h.stderr.String())
	}
	h.mustRun(0, "rm", "system/j", "--yes")
	if !strings.Contains(h.stderr.String(), "warning: a restore is unfinished") {
		t.Fatalf("rm with a merge pending: stderr %q; want the warning", h.stderr.String())
	}
	h.mustRun(keysCommitted, "floor", "merge", "--keep", "system/k")
	merged := mergedFloors(t, recipeFloor(h))
	if _, err := os.Lstat(merged[0] + ".retired"); err != nil {
		t.Fatalf("the merge's retired record: %v, want it beside the renamed input", err)
	}
	if _, err := os.Lstat(recipeFloor(h) + ".pre-restore"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("keystore-floor.json.pre-restore after the merge: %v, want it renamed", err)
	}
	h.put("system/n", []byte("n"))
	h.mustRun(0, "rm", "system/k", "--yes")
}

// TestKeysFloorMergeCommittedRerun (U192): a merge whose floor write landed
// but whose rename failed (every keystore-floor.json.merged-<unix> name the
// clock can reach during the run is taken) prints its full report and exits
// keysNotRenamed (5), not keysCommitted, which means a burial was dropped;
// the guard stays, and a rerun of the same input, with the
// names freed, prints "already merged", renames the input and clears it.
func TestKeysFloorMergeCommittedRerun(t *testing.T) {
	h := newKeysHarness(t)
	h.put("system/k", []byte("v"))
	b := saveRecipeBackup(t, h, filepath.Join(t.TempDir(), "keystore-floor-backup"), "2026-11-22")
	h.mustRun(0, "rm", "system/k", "--yes")
	if _, err := restoreRecipeBackup(t, h, b, true); err != nil {
		t.Fatalf("restore: %v", err)
	}
	now := time.Now().Unix()
	var taken []string
	for at := now - 2; at <= now+60; at++ {
		p := fmt.Sprintf("%s.merged-%d", recipeFloor(h), at)
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		taken = append(taken, p)
	}
	aside := recipeFloor(h) + ".pre-restore"
	if code := h.run("floor", "merge"); code != 5 {
		t.Fatalf("merge with the rename failing: exit %d, stdout %q, stderr %q; want 5", code, h.stdout.String(), h.stderr.String())
	}
	if out := h.stdout.String(); !strings.Contains(out, "buried live 1\n") || !strings.Contains(out, "buried live system/k:") {
		t.Fatalf("merge with the rename failing printed %q; want the full report", out)
	}
	if !strings.Contains(h.stderr.String(), "run the same merge again") {
		t.Fatalf("merge with the rename failing: stderr %q; want it to say the rerun renames it", h.stderr.String())
	}
	h.stdin = strings.NewReader("value")
	if code := h.run("put", "system/n", "--in", "-"); code != keysRefused {
		t.Fatalf("put after the failed rename: exit %d, want the guard still set", code)
	}
	for _, p := range taken {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	h.mustRun(0, "floor", "merge")
	if !strings.Contains(h.stdout.String(), "already merged\n") {
		t.Fatalf("the rerun printed %q; want already merged", h.stdout.String())
	}
	if _, err := os.Lstat(aside); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the input after the rerun: %v, want it renamed", err)
	}
	h.put("system/n", []byte("n"))
}

// TestKeysFloorMergeMovesPlantedAside (U192): a symlink planted at the
// keystore directory while the restored tree is staged is reported on
// stdout and stderr; --dry-run names where it would go and moves nothing,
// and the merge moves it into pre-restore.d and exits 4, dry run too, so the
// report is read.
func TestKeysFloorMergeMovesPlantedAside(t *testing.T) {
	h := newKeysHarness(t)
	h.put("system/k", []byte("v"))
	b := saveRecipeBackup(t, h, filepath.Join(t.TempDir(), "keystore-floor-backup"), "2026-11-22")
	h.mustRun(0, "rm", "system/k", "--yes")
	if _, err := restoreRecipeBackup(t, h, b, true); err != nil {
		t.Fatalf("restore: %v", err)
	}
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, h.keystoreDir()); err != nil {
		t.Fatal(err)
	}
	h.mustRun(keysCommitted, "floor", "merge", "--dry-run")
	if out, errOut := h.stdout.String(), h.stderr.String(); !strings.Contains(out, "would move aside symlink "+h.keystoreDir()+" to ") || !strings.Contains(errOut, "warning: ") {
		t.Fatalf("dry run printed %q, %q; want the move aside reported", out, errOut)
	}
	if fi, err := os.Lstat(h.keystoreDir()); err != nil || fi.Mode().Type() != fs.ModeSymlink {
		t.Fatalf("keystore dir after the dry run: %v, %v; want the symlink left", fi, err)
	}
	h.mustRun(keysCommitted, "floor", "merge")
	if out, errOut := h.stdout.String(), h.stderr.String(); !strings.Contains(out, "moved aside symlink "+h.keystoreDir()+" to "+recipePreRestore(h)+"/planted-") || !strings.Contains(errOut, "warning: ") {
		t.Fatalf("merge printed %q, %q; want the move aside reported", out, errOut)
	}
	if names, err := os.ReadDir(elsewhere); err != nil || len(names) != 0 {
		t.Fatalf("symlink target after the merge holds %v, %v; want nothing written through it", names, err)
	}
}

// TestKeysFloorMergeCommittedRerunRefused (U192): a rerun after exit 5
// finds the floor already written, so a staged tree it refuses, dry run
// included, exits 5 with committed wording, never "Nothing is written".
func TestKeysFloorMergeCommittedRerunRefused(t *testing.T) {
	h := newKeysHarness(t)
	h.put("system/k", []byte("v"))
	b := saveRecipeBackup(t, h, filepath.Join(t.TempDir(), "keystore-floor-backup"), "2026-11-22")
	h.mustRun(0, "rm", "system/k", "--yes")
	if _, err := restoreRecipeBackup(t, h, b, true); err != nil {
		t.Fatalf("restore: %v", err)
	}
	now := time.Now().Unix()
	for at := now - 2; at <= now+60; at++ {
		p := fmt.Sprintf("%s.merged-%d", recipeFloor(h), at)
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(p) })
	}
	if code := h.run("floor", "merge"); code != keysNotRenamed {
		t.Fatalf("merge with the rename failing: exit %d, stderr %q; want %d", code, h.stderr.String(), keysNotRenamed)
	}
	// A tree staged again, holding a file where an entry's directory goes.
	restored := filepath.Join(recipePreRestore(h), "restored")
	if err := os.Mkdir(restored, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(restored, "bogus"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"floor", "merge", "--dry-run"}, {"floor", "merge"}} {
		code := h.run(args...)
		if errOut := h.stderr.String(); code != keysNotRenamed || !strings.Contains(errOut, "the merge is written") || strings.Contains(strings.ToLower(errOut), "nothing is written") {
			t.Fatalf("%v after exit 5 with a misshaped staged tree: exit %d, stderr %q; want %d with committed wording", args, code, errOut, keysNotRenamed)
		}
	}
}

// keysEvictingRaiseStore's RaiseFloor reports a floor raise whose write
// evicted a tombstone, as the store does after making it.
type keysEvictingRaiseStore struct{ keysStore }

func (s keysEvictingRaiseStore) RaiseFloor(ctx context.Context) error {
	if err := s.keysStore.RaiseFloor(ctx); err != nil {
		return err
	}
	return fmt.Errorf("raise the floor: %w: 1 tombstone(s) evicted", keystore.ErrTombstoneEvicted)
}

// TestKeysReadVerbsWarnEviction: list and show change nothing the operator
// asked for, so a floor raise before them whose write evicted a tombstone
// is a warning on stderr, and they exit 0.
func TestKeysReadVerbsWarnEviction(t *testing.T) {
	for _, verb := range [][]string{{"list"}, {"show", "system/k"}} {
		t.Run(verb[0], func(t *testing.T) {
			h := newKeysHarness(t)
			h.put("system/k", []byte("v"))
			h.wrap = func(s keysStore) keysStore { return keysEvictingRaiseStore{s} }
			h.mustRun(0, verb...)
			if got := h.stderr.String(); !strings.Contains(got, "warning") || !strings.Contains(got, "tombstone(s) evicted") {
				t.Fatalf("%s after an evicting raise: stderr %q, want the eviction as a warning", verb[0], got)
			}
			if !strings.Contains(h.stdout.String(), "system/k") && verb[0] == "list" {
				t.Fatalf("list printed %q, want the entry", h.stdout.String())
			}
		})
	}
}

// TestKeysFloorMergeTakesNoFile (U192): floor merge reads only the data
// root's keystore-floor.json.pre-restore, so naming any file, the backup's
// saved floor or the guard file itself, is a usage error that changes
// nothing, the guard left in place.
func TestKeysFloorMergeTakesNoFile(t *testing.T) {
	h := newKeysHarness(t)
	h.put("system/k", []byte("v"))
	b := saveRecipeBackup(t, h, filepath.Join(t.TempDir(), "keystore-floor-backup"), "2026-11-22")
	h.mustRun(0, "rm", "system/k", "--yes")
	if _, err := restoreRecipeBackup(t, h, b, true); err != nil {
		t.Fatalf("restore: %v", err)
	}
	before, err := os.ReadFile(recipeFloor(h))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{b.floor, recipeFloor(h) + ".pre-restore"} {
		if code := h.run("floor", "merge", p); code != keysBadUsage || !strings.Contains(h.stderr.String(), "takes no file") {
			t.Fatalf("floor merge %s: exit %d, stderr %q; want %d saying it takes no file", p, code, h.stderr.String(), keysBadUsage)
		}
	}
	if after, _ := os.ReadFile(recipeFloor(h)); string(after) != string(before) {
		t.Fatalf("floor after the refused merges changed: %s", after)
	}
	if _, err := os.Lstat(recipeFloor(h) + ".pre-restore"); err != nil {
		t.Fatalf("the guard file after the refused merges: %v, want it in place", err)
	}
	h.mustRun(0, "floor", "merge")
}

// TestKeysFloorMergeAcceptDrops (U192): a merge that would drop a deletion
// since the backup because the per-name cap binds is refused (exit 1),
// naming the cap and --accept-drops; an rm under the guard is kept, and
// --accept-drops writes the merge, prints each burial dropped, exits 4 and
// clears the guard. --dry-run exits as the real run would: 1, and 4 with
// --accept-drops.
func TestKeysFloorMergeAcceptDrops(t *testing.T) {
	h := newKeysHarness(t)
	h.put("system/k", []byte("v"))
	h.put("system/other", []byte("v"))
	aside := recipeFloor(h) + ".pre-restore"
	raw, err := os.ReadFile(recipeFloor(h))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(aside, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	plantBurials(t, aside, "k", 1000, keysPerNameCap)
	h.mustRun(0, "rm", "system/k", "--yes")
	stageKeystore(t, h)
	if code := h.run("floor", "merge"); code != keysRefused || !strings.Contains(h.stderr.String(), "per-name cap") || !strings.Contains(h.stderr.String(), "--accept-drops") {
		t.Fatalf("floor merge at the per-name cap: exit %d, stderr %q; want %d naming the cap and --accept-drops", code, h.stderr.String(), keysRefused)
	}
	// A dry run exits with the code the real run would.
	if code := h.run("floor", "merge", "--dry-run"); code != keysRefused || !strings.Contains(h.stdout.String(), "dropped system/k:") {
		t.Fatalf("floor merge --dry-run at the per-name cap: exit %d, stdout %q; want %d with the drop reported", code, h.stdout.String(), keysRefused)
	}
	if code := h.run("floor", "merge", "--dry-run", "--accept-drops"); code != keysCommitted || !strings.Contains(h.stdout.String(), "dropped system/k:") {
		t.Fatalf("floor merge --dry-run --accept-drops: exit %d, stdout %q, stderr %q; want %d, as the real run", code, h.stdout.String(), h.stderr.String(), keysCommitted)
	}
	if code := h.run("floor", "merge", "--accept-drops"); code != keysCommitted {
		t.Fatalf("floor merge --accept-drops: exit %d, stderr %q; want %d", code, h.stderr.String(), keysCommitted)
	}
	if got := h.stdout.String(); !strings.Contains(got, "dropped 1\n") || !strings.Contains(got, "dropped system/k:") {
		t.Fatalf("floor merge --accept-drops printed %q, want the drop reported", got)
	}
	if _, err := os.Lstat(aside); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the guard file after --accept-drops: %v, want it renamed", err)
	}
	h.mustRun(1, "show", "system/k")
}

// TestKeysFloorMergeDryRun (U192): floor merge --dry-run prints the full
// report the merge would make, writes nothing and renames nothing, so the
// guard stays; the merge run after it writes that report.
func TestKeysFloorMergeDryRun(t *testing.T) {
	h := newKeysHarness(t)
	h.put("system/k", []byte("v"))
	b := saveRecipeBackup(t, h, filepath.Join(t.TempDir(), "keystore-floor-backup"), "2026-11-22")
	h.mustRun(0, "rm", "system/k", "--yes")
	if _, err := restoreRecipeBackup(t, h, b, true); err != nil {
		t.Fatalf("restore: %v", err)
	}
	before, err := os.ReadFile(recipeFloor(h))
	if err != nil {
		t.Fatal(err)
	}
	h.mustRun(0, "floor", "merge", "--dry-run")
	if out := h.stdout.String(); !strings.Contains(out, "dry run: nothing written\n") || !strings.Contains(out, "buried live 1\n") || !strings.Contains(out, "buried live system/k:") {
		t.Fatalf("floor merge --dry-run printed %q, want the full report", out)
	}
	if after, _ := os.ReadFile(recipeFloor(h)); string(after) != string(before) {
		t.Fatalf("floor after --dry-run changed: %s", after)
	}
	if _, err := os.Lstat(recipeFloor(h) + ".pre-restore"); err != nil {
		t.Fatalf("the guard file after --dry-run: %v, want it in place", err)
	}
	h.mustRun(0, "floor", "merge")
	if out := h.stdout.String(); !strings.Contains(out, "buried live system/k:") {
		t.Fatalf("floor merge after --dry-run printed %q, want k buried live", out)
	}
}

// TestKeysFloorMergeReportCodes (U192): floor merge exits 4 when it keeps an
// entry with --keep or leaves one unverified (a restored pointer, or a
// moved-aside one, that does not authenticate), as for a drop, and its dry run
// exits as it would. A kept entry the moved-aside floor records as deleted
// is reported "revoked, kept live" and warned of on stderr; one the restored
// floor does not record is reported as the moved-aside version recorded,
// with no warning. A buried-live line names --keep for an undo. A staged
// tree holding user-scope entries exits 4 too, saying they were carried
// over without a floor check.
func TestKeysFloorMergeReportCodes(t *testing.T) {
	restore := func(t *testing.T, h *keysHarness, b recipeBackup) {
		t.Helper()
		if _, err := restoreRecipeBackup(t, h, b, true); err != nil {
			t.Fatalf("restore: %v", err)
		}
	}
	backup := func(t *testing.T, h *keysHarness) recipeBackup {
		return saveRecipeBackup(t, h, filepath.Join(t.TempDir(), "keystore-floor-backup"), "2026-11-22")
	}
	t.Run("revoked kept", func(t *testing.T) {
		h := newKeysHarness(t)
		h.put("system/rb", []byte("v"))
		b := backup(t, h)
		h.mustRun(0, "rm", "system/rb", "--yes")
		restore(t, h, b)
		for _, args := range [][]string{{"floor", "merge", "--keep", "system/rb", "--dry-run"}, {"floor", "merge", "--keep", "system/rb"}} {
			if code := h.run(args...); code != keysCommitted {
				t.Fatalf("%v: exit %d, stderr %q; want %d", args, code, h.stderr.String(), keysCommitted)
			}
			if !strings.Contains(h.stdout.String(), "kept system/rb: revoked, kept live") || !strings.Contains(h.stderr.String(), "warning: system/rb is kept live") {
				t.Fatalf("%v printed %q, %q; want rb reported revoked and kept live, and warned of", args, h.stdout.String(), h.stderr.String())
			}
		}
	})
	t.Run("recorded", func(t *testing.T) {
		h := newKeysHarness(t)
		h.put("system/base", []byte("base"))
		b := backup(t, h)
		h.put("system/late", []byte("late"))
		restore(t, h, b)
		if code := h.run("floor", "merge", "--keep", "system/late"); code != keysCommitted {
			t.Fatalf("merge --keep of a name the backup lacks: exit %d, stderr %q; want %d", code, h.stderr.String(), keysCommitted)
		}
		if !strings.Contains(h.stdout.String(), "kept system/late: recorded the moved-aside version") || strings.Contains(h.stdout.String(), "revoked, kept live") || strings.Contains(h.stderr.String(), "warning: system/late") {
			t.Fatalf("merge --keep printed %q, %q; want late reported as recorded, not revoked, and no warning", h.stdout.String(), h.stderr.String())
		}
	})
	t.Run("unverified", func(t *testing.T) {
		h := newKeysHarness(t)
		h.put("system/k", []byte("v"))
		b := backup(t, h)
		h.put("system/x", []byte("x"))
		h.mustRun(0, "rm", "system/x", "--yes")
		restore(t, h, b)
		master := filepath.Join(h.work, "cred", "keystore-master", "master")
		if err := os.Rename(master, master+".aside"); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{{"floor", "merge", "--dry-run"}, {"floor", "merge"}} {
			if code := h.run(args...); code != keysCommitted {
				t.Fatalf("%v with no master: exit %d, stderr %q; want %d", args, code, h.stderr.String(), keysCommitted)
			}
			if out := h.stdout.String(); !strings.Contains(out, "unverified system/k:") || !strings.Contains(out, "refused until a rotate numbers past the fence") {
				t.Fatalf("%v printed %q; want k unverified, saying what is refused", args, out)
			}
		}
	})
	t.Run("aside unverified", func(t *testing.T) {
		h := newKeysHarness(t)
		h.put("system/k", []byte("v"))
		b := backup(t, h)
		h.put("system/late", []byte("late"))
		restore(t, h, b)
		p := filepath.Join(recipePreRestore(h), "keystore", "k", "current")
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		raw[len(raw)-1] ^= 0xff
		if err := os.WriteFile(p, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{{"floor", "merge", "--dry-run"}, {"floor", "merge"}} {
			if code := h.run(args...); code != keysCommitted {
				t.Fatalf("%v with the moved-aside pointer refused: exit %d, stderr %q; want %d", args, code, h.stderr.String(), keysCommitted)
			}
			if out := h.stdout.String(); !strings.Contains(out, "unverified system/k: the moved-aside pointer") {
				t.Fatalf("%v printed %q; want k's moved-aside pointer unverified", args, out)
			}
		}
	})
	t.Run("buried live", func(t *testing.T) {
		h := newKeysHarness(t)
		h.put("system/rb", []byte("v"))
		b := backup(t, h)
		h.mustRun(0, "rm", "system/rb", "--yes")
		restore(t, h, b)
		h.mustRun(0, "floor", "merge")
		if out := h.stdout.String(); !strings.Contains(out, "buried live system/rb: ") || !strings.Contains(out, "removes its restored files") || strings.Contains(out, "keys rm") {
			t.Fatalf("merge printed %q; want the buried-live line to say its files are removed, naming no rm", out)
		}
		if _, err := os.Lstat(filepath.Join(h.work, "keystore", "rb")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("rb's directory after the merge: %v, want it removed", err)
		}
	})
	t.Run("user scoped", func(t *testing.T) {
		h := newKeysHarness(t)
		h.put("system/rb", []byte("v"))
		b := backup(t, h)
		h.mustRun(0, "rm", "system/rb", "--yes")
		restore(t, h, b)
		// The restored keystore holds a user scope: the merge carries it
		// over with no floor check of its deletions.
		if err := os.MkdirAll(filepath.Join(recipePreRestore(h), "restored", ".user", "501"), 0o700); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{{"floor", "merge", "--dry-run"}, {"floor", "merge"}} {
			if code := h.run(args...); code != keysCommitted {
				t.Fatalf("%v with user-scope entries staged: exit %d, stderr %q; want %d", args, code, h.stderr.String(), keysCommitted)
			}
			if !strings.Contains(h.stdout.String(), "user scope: ") || !strings.Contains(h.stderr.String(), "user-scope entries without a floor check") {
				t.Fatalf("%v printed %q, %q; want the user-scope report line and the exit-4 reason", args, h.stdout.String(), h.stderr.String())
			}
		}
	})
}

// deleteCapture keeps the error the store's Delete returned.
type deleteCapture struct {
	keysStore
	err *error
}

func (d deleteCapture) Delete(ctx context.Context, name string) error {
	*d.err = d.keysStore.Delete(ctx, name)
	return *d.err
}

// internalCommitted finds, in err's tree, the store's own committed marker:
// a leaf keystore.Committed reports, which is neither keystore.ErrCommitted
// nor keystore.ErrTombstoneEvicted.
func internalCommitted(err error) error {
	switch u := err.(type) {
	case interface{ Unwrap() []error }:
		for _, e := range u.Unwrap() {
			if c := internalCommitted(e); c != nil {
				return c
			}
		}
		return nil
	case interface{ Unwrap() error }:
		return internalCommitted(u.Unwrap())
	}
	if err != nil && keystore.Committed(err) && !errors.Is(err, keystore.ErrCommitted) && !errors.Is(err, keystore.ErrTombstoneEvicted) {
		return err
	}
	return nil
}

// wrappedCommittedStore reports every Put as committed through the store's
// own committed marker, wrapped, with no ErrCommitted in the chain.
type wrappedCommittedStore struct {
	keysStore
	marker error
}

func (w wrappedCommittedStore) Put(ctx context.Context, name string, kind keystore.Kind, value []byte) (keystore.Version, error) {
	v, err := w.keysStore.Put(ctx, name, kind, value)
	if err != nil {
		return v, err
	}
	return v, fmt.Errorf("put %s: %w: injected failure after the commit point", name, w.marker)
}

// TestKeysWrappedInternalCommittedExits4: the CLI tests a committed change
// with keystore.Committed, so a wrapped committed error that is not
// keystore.ErrCommitted (the store's own marker, taken here from a real rm
// whose floor write evicted a tombstone) exits 4, not 1.
func TestKeysWrappedInternalCommittedExits4(t *testing.T) {
	h := newKeysHarness(t)
	h.put("system/k", []byte("v"))
	plantBurials(t, recipeFloor(h), "k", 1000, keysPerNameCap)
	var rmErr error
	h.wrap = func(s keysStore) keysStore { return deleteCapture{s, &rmErr} }
	h.mustRun(keysCommitted, "rm", "system/k", "--yes")
	marker := internalCommitted(rmErr)
	if marker == nil {
		t.Fatalf("no committed marker in the rm's error %v", rmErr)
	}

	h = newKeysHarness(t)
	h.wrap = func(s keysStore) keysStore { return wrappedCommittedStore{s, marker} }
	h.stdin = strings.NewReader("one")
	h.mustRun(keysCommitted, "put", "system/alpha", "--in", "-")
	if got := h.value("alpha", 1); string(got) != "one" {
		t.Fatalf("alpha v1 = %q after the committed put", got)
	}
}
