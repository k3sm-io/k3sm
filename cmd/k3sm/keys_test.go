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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/keystore"
)

// fakeKeys is a keysStore kept as plain files under one directory, so a test
// can copy and restore the tree the way an operator backs up keystore/. It
// stores values in the clear: it stands in for the store's API, not its
// sealing, which pkg/keystore tests.
type fakeKeys struct {
	root      string
	calls     []string
	rewrapErr error
	rewrapKey []byte
}

var _ keysStore = (*fakeKeys)(nil)

var fakeCreated = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

func (f *fakeKeys) entry(name string) string { return filepath.Join(f.root, name) }

func (f *fakeKeys) checkName(name string) error {
	if name == "" || strings.ContainsRune(name, '/') || name != strings.ToLower(name) || strings.HasPrefix(name, ".") {
		return keystore.ErrInvalidName
	}
	return nil
}

func (f *fakeKeys) write(name string, n uint64, kind keystore.Kind, value []byte) error {
	d := f.entry(name)
	if err := os.WriteFile(filepath.Join(d, "v"+strconv.FormatUint(n, 10)), value, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(d, "kind"), []byte(strconv.Itoa(int(kind))), 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(d, "current"), []byte(strconv.FormatUint(n, 10)), 0o600)
}

func (f *fakeKeys) Put(_ context.Context, name string, kind keystore.Kind, value []byte) (keystore.Version, error) {
	f.calls = append(f.calls, "Put")
	if err := f.checkName(name); err != nil {
		return keystore.Version{}, err
	}
	if err := os.MkdirAll(f.root, 0o700); err != nil {
		return keystore.Version{}, err
	}
	if err := os.Mkdir(f.entry(name), 0o700); errors.Is(err, fs.ErrExist) {
		return keystore.Version{}, keystore.ErrExists
	} else if err != nil {
		return keystore.Version{}, err
	}
	if err := f.write(name, 1, kind, value); err != nil {
		return keystore.Version{}, err
	}
	return f.version(name, 1, kind, value), nil
}

func (f *fakeKeys) version(name string, n uint64, kind keystore.Kind, value []byte) keystore.Version {
	return keystore.Version{Name: name, Version: n, Kind: kind, Created: fakeCreated, Fingerprint: fmt.Sprintf("fp%d-%d", n, len(value))}
}

func (f *fakeKeys) current(name string) (uint64, keystore.Kind, error) {
	d := f.entry(name)
	if _, err := os.Stat(d); errors.Is(err, fs.ErrNotExist) {
		return 0, 0, keystore.ErrNotFound
	}
	if _, err := os.Stat(filepath.Join(d, "damaged")); err == nil {
		return 0, 0, fmt.Errorf("%w: test damage", keystore.ErrCorrupt)
	}
	b, err := os.ReadFile(filepath.Join(d, "current"))
	if err != nil {
		return 0, 0, err
	}
	n, err := strconv.ParseUint(string(b), 10, 64)
	if err != nil {
		return 0, 0, err
	}
	k, err := os.ReadFile(filepath.Join(d, "kind"))
	if err != nil {
		return 0, 0, err
	}
	kind, err := strconv.Atoi(string(k))
	return n, keystore.Kind(kind), err
}

func (f *fakeKeys) Current(ctx context.Context, name string) (keystore.Version, []byte, error) {
	f.calls = append(f.calls, "Current")
	n, _, err := f.current(name)
	if err != nil {
		return keystore.Version{}, nil, err
	}
	return f.get(name, n)
}

func (f *fakeKeys) get(name string, n uint64) (keystore.Version, []byte, error) {
	cur, kind, err := f.current(name)
	if err != nil {
		return keystore.Version{}, nil, err
	}
	if n == 0 || n > cur {
		return keystore.Version{}, nil, keystore.ErrVersionNotFound
	}
	v, err := os.ReadFile(filepath.Join(f.entry(name), "v"+strconv.FormatUint(n, 10)))
	if err != nil {
		return keystore.Version{}, nil, err
	}
	return f.version(name, n, kind, v), v, nil
}

func (f *fakeKeys) Get(_ context.Context, name string, n uint64) (keystore.Version, []byte, error) {
	f.calls = append(f.calls, "Get")
	return f.get(name, n)
}

func (f *fakeKeys) List(context.Context) ([]keystore.Entry, error) {
	f.calls = append(f.calls, "List")
	des, err := os.ReadDir(f.root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []keystore.Entry
	for _, de := range des {
		cur, _, err := f.current(de.Name())
		if err != nil {
			out = append(out, keystore.Entry{Name: de.Name(), Err: err})
			continue
		}
		e := keystore.Entry{Name: de.Name()}
		for n := uint64(1); n <= cur; n++ {
			v, _, err := f.get(de.Name(), n)
			if err != nil {
				return nil, err
			}
			e.Versions = append(e.Versions, v)
		}
		e.Current = e.Versions[len(e.Versions)-1]
		out = append(out, e)
	}
	return out, nil
}

func (f *fakeKeys) Rotate(_ context.Context, name string, value []byte) (keystore.Version, error) {
	f.calls = append(f.calls, "Rotate")
	cur, kind, err := f.current(name)
	if err != nil {
		return keystore.Version{}, err
	}
	if err := f.write(name, cur+1, kind, value); err != nil {
		return keystore.Version{}, err
	}
	return f.version(name, cur+1, kind, value), nil
}

func (f *fakeKeys) Delete(_ context.Context, name string) error {
	f.calls = append(f.calls, "Delete")
	if _, err := os.Stat(f.entry(name)); errors.Is(err, fs.ErrNotExist) {
		return keystore.ErrNotFound
	}
	return os.RemoveAll(f.entry(name))
}

func (f *fakeKeys) Rewrap(_ context.Context, newMaster []byte) error {
	f.calls = append(f.calls, "Rewrap")
	f.rewrapKey = slices.Clone(newMaster)
	return f.rewrapErr
}

func (f *fakeKeys) RaiseFloor(context.Context) error {
	f.calls = append(f.calls, "RaiseFloor")
	return nil
}

// keysHarness runs the keys verbs against a fakeKeys under a temp work dir.
type keysHarness struct {
	t         *testing.T
	work      string
	store     *fakeKeys
	cfg       keystore.Config
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
	work := filepath.Join(t.TempDir(), "server")
	return &keysHarness{
		t:     t,
		work:  work,
		store: &fakeKeys{root: filepath.Join(work, "keystore")},
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
	env := keysEnv{
		euid:       func() int { return h.euid },
		serviceIDs: func() (uint32, uint32, error) { return uint32(os.Getuid()), uint32(os.Getgid()), nil },
		open: func(cfg keystore.Config) keysStore {
			h.cfg = cfg
			return h.store
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

func (h *keysHarness) value(name string, n uint64) []byte {
	h.t.Helper()
	_, v, err := h.store.get(name, n)
	if err != nil {
		h.t.Fatalf("read %s v%d from the fake store: %v", name, n, err)
	}
	return v
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
	out := h.stdout.String() + h.stderr.String()
	for _, secret := range [][]byte{v1, bytes.TrimSpace(v1), v2} {
		if strings.Contains(out, string(secret)) {
			t.Fatalf("rotate --from-version printed a value: %q", out)
		}
	}
	if !strings.Contains(h.stdout.String(), "version 3") {
		t.Errorf("rotate --from-version output %q does not name the new version", h.stdout.String())
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

func TestKeysListCorruptExitsOne(t *testing.T) {
	h := newKeysHarness(t)
	h.put("system/alpha", []byte("a"))
	h.put("system/beta", []byte("b"))
	h.mustRun(0, "list")
	if !strings.Contains(h.stdout.String(), "system/alpha") || !strings.Contains(h.stdout.String(), "2026-03-04T05:06:07Z") {
		t.Fatalf("list output lacks the name or the UTC created time:\n%s", h.stdout.String())
	}

	if err := os.WriteFile(filepath.Join(h.store.entry("beta"), "damaged"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	h.store.calls = nil
	h.mustRun(1, "list")
	if i, j := slices.Index(h.store.calls, "RaiseFloor"), slices.Index(h.store.calls, "List"); i < 0 || i > j {
		t.Errorf("list calls %v: RaiseFloor must come before List", h.store.calls)
	}
	lines := strings.Split(h.stdout.String(), "\n")
	var alpha, beta string
	for _, l := range lines {
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
	if !strings.Contains(beta, "corrupt") || !strings.Contains(beta, "test damage") {
		t.Errorf("damaged entry line %q lacks corrupt and the store's message", beta)
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
	if len(doc.Entries) != 2 || doc.Entries[0].Status != "ok" || doc.Entries[0].Version != 1 || doc.Entries[0].Created != "2026-03-04T05:06:07Z" ||
		doc.Entries[1].Status != "corrupt" || !strings.Contains(doc.Entries[1].Error, "test damage") {
		t.Fatalf("list -o json = %+v", doc.Entries)
	}
	h.mustRun(2, "list", "-o", "yaml")
}

func TestKeysShowRevealByteExact(t *testing.T) {
	seed := bytes.Repeat([]byte{0x00, 0x0a, 0xff, 0x20}, 8)
	for _, tc := range []struct {
		name  string
		value []byte
	}{
		{"opaque with trailing newline", []byte("token\n")},
		{"opaque binary", []byte{0x00, 0x01, '\r', '\n', 0xfe}},
		{"ed25519 seed 32 bytes", seed},
		{"ed25519 expanded 64 bytes", append(slices.Clone(seed), seed...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newKeysHarness(t)
			h.put("system/k", tc.value)
			h.store.calls = nil
			h.mustRun(0, "show", "system/k", "--reveal")
			if !bytes.Equal(h.stdout.Bytes(), tc.value) {
				t.Fatalf("show --reveal wrote %q, want exactly %q", h.stdout.Bytes(), tc.value)
			}
			if i, j := slices.Index(h.store.calls, "RaiseFloor"), slices.Index(h.store.calls, "Current"); i < 0 || i > j {
				t.Errorf("show calls %v: RaiseFloor must come before Current", h.store.calls)
			}
			h.stdin = bytes.NewReader([]byte("other"))
			h.mustRun(0, "rotate", "system/k", "--in", "-")
			h.mustRun(0, "show", "system/k", "--version", "1", "--reveal")
			if !bytes.Equal(h.stdout.Bytes(), tc.value) {
				t.Fatalf("show --version 1 --reveal wrote %q, want exactly %q", h.stdout.Bytes(), tc.value)
			}
			h.mustRun(0, "show", "system/k")
			if bytes.Contains(h.stdout.Bytes(), tc.value) || bytes.Contains(h.stdout.Bytes(), []byte("other")) {
				t.Fatalf("show without --reveal printed the value:\n%s", h.stdout.String())
			}
			if !strings.Contains(h.stdout.String(), "system/k") || !strings.Contains(h.stdout.String(), "2") {
				t.Fatalf("show metadata lacks the name or version:\n%s", h.stdout.String())
			}
		})
	}
}

// copyTree copies the regular files and directories under src to dst.
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
		to := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(to, 0o700)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(to, b, 0o600)
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
		copyTree(t, h.store.root, backup)
		h.mustRun(0, "rm", "system/rb", "--yes")
		h.mustRun(1, "show", "system/rb", "--reveal")
		if err := os.RemoveAll(h.store.root); err != nil {
			t.Fatal(err)
		}
		copyTree(t, backup, h.store.root)
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
			h.store.calls = nil
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
			for _, c := range h.store.calls {
				if c != "RaiseFloor" && c != "Current" && c != "Get" {
					t.Errorf("refused verb reached the store: %v", h.store.calls)
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
	want := keystore.Config{
		Dir:       filepath.Join(h.work, "keystore"),
		MasterDir: filepath.Join(h.work, "cred", "keystore-master"),
		UID:       uint32(os.Getuid()),
		GID:       uint32(os.Getgid()),
		DataRoot:  filepath.Dir(h.work),
	}
	if h.cfg != want {
		t.Fatalf("store config = %+v, want %+v", h.cfg, want)
	}
}

func TestKeysRewrap(t *testing.T) {
	key := bytes.Repeat([]byte{0xA5}, 32)
	t.Run("key-out written 0600 before rewrap", func(t *testing.T) {
		h := newKeysHarness(t)
		p := filepath.Join(t.TempDir(), "new-master")
		h.mustRun(0, "rewrap", "--key-out", p)
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, key) || !bytes.Equal(h.store.rewrapKey, key) {
			t.Fatalf("key file %x, rewrap key %x, want both %x", got, h.store.rewrapKey, key)
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
			p := filepath.Join(t.TempDir(), "new-master")
			tc.make(t, p)
			h.mustRun(1, "rewrap", "--key-out", p)
			if slices.Contains(h.store.calls, "Rewrap") {
				t.Fatal("rewrap ran over an existing key file")
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(p), "target")); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("the symlink's target was created: %v", err)
			}
		})
	}
	for _, tc := range []struct {
		name string
		err  error
		want int
		say  string
	}{
		{"resumed", fmt.Errorf("rewrap: %w", keystore.ErrRewrapResumed), 3, "new key"},
		{"scope unsupported", fmt.Errorf("rewrap: %w", keystore.ErrScopeUnsupported), 1, "keystore/.user"},
		{"other failure", errors.New("disk on fire"), 1, "--key-in"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newKeysHarness(t)
			h.store.rewrapErr = tc.err
			p := filepath.Join(t.TempDir(), "new-master")
			h.mustRun(tc.want, "rewrap", "--key-out", p)
			if !strings.Contains(h.stderr.String(), tc.say) {
				t.Errorf("stderr %q does not say %q", h.stderr.String(), tc.say)
			}
			if _, err := os.Stat(p); err != nil {
				t.Errorf("the key file is gone after a failed rewrap: %v", err)
			}
		})
	}
	t.Run("key-in reuses a saved key", func(t *testing.T) {
		h := newKeysHarness(t)
		saved := bytes.Repeat([]byte{0x3c}, 32)
		p := filepath.Join(t.TempDir(), "saved")
		if err := os.WriteFile(p, saved, 0o600); err != nil {
			t.Fatal(err)
		}
		h.rand = failReaderRand{t}
		h.mustRun(0, "rewrap", "--key-in", p)
		if !bytes.Equal(h.store.rewrapKey, saved) {
			t.Fatalf("rewrap key %x, want the saved %x", h.store.rewrapKey, saved)
		}
	})
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
			if slices.Contains(h.store.calls, "Rewrap") {
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

// failReaderRand fails the test if the verb draws randomness.
type failReaderRand struct{ t *testing.T }

func (r failReaderRand) Read([]byte) (int, error) {
	r.t.Error("rand was read")
	return 0, io.EOF
}
