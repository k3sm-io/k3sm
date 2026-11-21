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
	stdout    bytes.Buffer
	stderr    bytes.Buffer
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

// run runs `k3sm keys <args> --work-dir <work>` and returns the exit code.
// The buffers hold that run's output only.
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
		stdin:     h.stdin,
		stdinTTY:  func() bool { return h.stdinTTY },
		stdoutTTY: func() bool { return h.stdoutTTY },
		rand:      h.rand,
		stdout:    &h.stdout,
		stderr:    &h.stderr,
	}
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") && args[0] != "help" {
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

func TestKeysRollbackRoundTrip(t *testing.T) {
	t.Run("save rm restore", func(t *testing.T) {
		h := newKeysHarness(t)
		value := []byte("rollback\x00value\n")
		h.put("system/rb", value)
		backup := filepath.Join(t.TempDir(), "keystore")
		copyTree(t, h.keystoreDir(), backup)
		h.mustRun(0, "rm", "system/rb", "--yes")
		h.mustRun(1, "show", "system/rb", "--reveal")
		if err := os.RemoveAll(h.keystoreDir()); err != nil {
			t.Fatal(err)
		}
		copyTree(t, backup, h.keystoreDir())
		h.mustRun(0, "list")
		h.mustRun(0, "show", "system/rb", "--reveal")
		if !bytes.Equal(h.stdout.Bytes(), value) {
			t.Fatalf("restored value = %q, want %q", h.stdout.Bytes(), value)
		}
	})
	t.Run("show reveal piped into rotate", func(t *testing.T) {
		h := newKeysHarness(t)
		v1 := []byte("first\n")
		h.put("system/rb", v1)
		h.stdin = bytes.NewReader([]byte("second"))
		h.mustRun(0, "rotate", "system/rb", "--in", "-")
		h.mustRun(0, "show", "system/rb", "--version", "1", "--reveal")
		h.stdin = bytes.NewReader(slices.Clone(h.stdout.Bytes()))
		h.mustRun(0, "rotate", "system/rb", "--in", "-")
		if got := h.value("rb", 3); !bytes.Equal(got, v1) {
			t.Fatalf("version 3 = %q, want %q", got, v1)
		}
	})
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
	}{
		{name: "put not root", args: []string{"put", "system/a", "--in", "-"}, euid: 501, stdin: "v", want: 1, say: "sudo"},
		{name: "list not root", args: []string{"list"}, euid: 501, want: 1, say: "sudo"},
		{name: "show not root", args: []string{"show", "system/a"}, euid: 501, want: 1, say: "sudo"},
		{name: "rotate not root", args: []string{"rotate", "system/a", "--in", "-"}, euid: 501, stdin: "v", want: 1, say: "sudo"},
		{name: "rm not root", args: []string{"rm", "system/a", "--yes"}, euid: 501, want: 1, say: "sudo"},
		{name: "rewrap not root", args: []string{"rewrap", "--key-out", "k"}, euid: 501, want: 1, say: "sudo"},
		{name: "bare name", args: []string{"put", "signer", "--in", "-"}, stdin: "v", want: 2, say: "system/signer"},
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
				if c != "RaiseFloor" && c != "Current" && c != "Get" {
					t.Errorf("refused verb reached the store: %v", h.calls)
					break
				}
			}
		})
	}
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
	return fmt.Errorf("rewrap: %w", keystore.ErrRewrapResumed)
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
		if !strings.Contains(out, "delete") || !strings.Contains(out, p) {
			t.Errorf("rewrap output %q does not tell the operator to delete %s", out, p)
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
		if !strings.Contains(h.stderr.String(), "new key") {
			t.Errorf("stderr %q does not say %q", h.stderr.String(), "new key")
		}
		if _, err := os.Stat(p); err != nil {
			t.Errorf("the key file is gone after a resumed rewrap: %v", err)
		}
	})
	for _, tc := range []struct {
		name   string
		damage func(t *testing.T, h *keysHarness)
		want   error
		say    string
	}{
		{"scope unsupported", func(t *testing.T, h *keysHarness) {
			if err := os.Mkdir(filepath.Join(h.keystoreDir(), ".user"), 0o700); err != nil {
				t.Fatal(err)
			}
		}, keystore.ErrScopeUnsupported, "keystore/.user"},
		{"an entry that does not open", func(t *testing.T, h *keysHarness) { h.damageRecord("a", "v1") }, keystore.ErrCorrupt, "--key-in"},
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
			if _, err := os.Stat(p); err != nil {
				t.Errorf("the key file is gone after a failed rewrap: %v", err)
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

// failReaderRand fails the test if the verb draws randomness.
type failReaderRand struct{ t *testing.T }

func (r failReaderRand) Read([]byte) (int, error) {
	r.t.Error("rand was read")
	return 0, io.EOF
}
