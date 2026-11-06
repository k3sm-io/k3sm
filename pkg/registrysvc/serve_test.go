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

package registrysvc

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/ociregistry/auth"
)

const (
	testPushSecret = "push-secret-for-the-serve-tests"
	testGateSecret = "gate-secret-for-the-serve-tests"
)

// writeTestServeConfig writes a valid serve config for a fresh work dir, after
// edit, and returns the work dir.
func writeTestServeConfig(t *testing.T, edit func(*ServeConfig)) string {
	t.Helper()
	work := t.TempDir()
	cfg := ServeConfig{
		Principals: []auth.Principal{
			{User: auth.UserPush, SecretSHA256: auth.HashSecret(testPushSecret)},
			{User: auth.UserGate, SecretSHA256: auth.HashSecret(testGateSecret)},
		},
		Listen: "127.0.0.1:6450",
	}
	if edit != nil {
		edit(&cfg)
	}
	b, err := marshalServeConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeServeConfig(work, b); err != nil {
		t.Fatal(err)
	}
	return work
}

// plentyFree keeps the tests off the 2 GiB low-space refusal on a full disk.
func plentyFree() (uint64, error) { return 1 << 40, nil }

// testServeDeps serves on ln, as this test process's own user.
func testServeDeps(ln net.Listener) serveDeps {
	return serveDeps{
		ident:       osIdentity(),
		getppid:     os.Getppid,
		listen:      func(string) (net.Listener, error) { return ln, nil },
		freeSpace:   plentyFree,
		gcGrace:     time.Hour,
		gcInterval:  time.Hour,
		statusEvery: 10 * time.Millisecond,
	}
}

// runTestServe runs serve for work in the background. The returned channel gets
// its result, and a test that has not read it has the server stopped at cleanup,
// which must be clean.
func runTestServe(t *testing.T, work string, d serveDeps) (<-chan error, context.CancelFunc) {
	t.Helper()
	ready := make(chan struct{})
	d.addr = func(net.Addr) { close(ready) }
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- serve(ctx, ServeConfigPath(work), d) }()
	t.Cleanup(cancel)
	select {
	case <-ready:
	case err := <-result:
		t.Fatalf("serve returned before serving: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("serve did not come up")
	}
	return result, cancel
}

// memClient is an HTTP client whose connections are the listener's.
func memClient(t *testing.T, l *memListener) *http.Client {
	t.Helper()
	tr := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) { return l.dial() }}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}

// do makes one request and returns the response with its body closed.
func do(t *testing.T, c *http.Client, method, url, user, secret string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if user != "" {
		req.SetBasicAuth(user, secret)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp
}

// eventually polls cond for up to 30 seconds.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// fakeIdentity models a process credential: a root process drops once, and after
// that cannot go back unless returnsToRoot says it can.
type fakeIdentity struct {
	euid, ruid, egid int
	calls            []string
	failSetuid       error
	ignoreSetuid     bool
	returnsToRoot    bool
}

func (f *fakeIdentity) identity() identity {
	return identity{
		geteuid: func() int { return f.euid },
		getuid:  func() int { return f.ruid },
		getegid: func() int { return f.egid },
		setgroups: func(g []int) error {
			f.calls = append(f.calls, "setgroups")
			return nil
		},
		setgid: func(g int) error {
			f.calls = append(f.calls, "setgid")
			f.egid = g
			return nil
		},
		setuid: func(u int) error {
			f.calls = append(f.calls, "setuid")
			if f.failSetuid != nil {
				return f.failSetuid
			}
			if u == 0 && f.euid != 0 && !f.returnsToRoot {
				return unix.EPERM
			}
			if !f.ignoreSetuid {
				f.euid, f.ruid = u, u
			}
			return nil
		},
	}
}

// TestApplyServeCredential pins the refuse-root and credential rules: root with a
// credential drops groups, then gid, then uid, and proves it cannot go back; root
// without one refuses; anyone else must already hold what the config names.
func TestApplyServeCredential(t *testing.T) {
	cases := []struct {
		name      string
		id        fakeIdentity
		uid, gid  int
		want      error
		wantCalls string
	}{
		{name: "root with no credential refuses", id: fakeIdentity{}, want: ErrServeAsRoot},
		{name: "a setuid root process with no credential refuses", id: fakeIdentity{euid: 501, egid: 20}, want: ErrServeAsRoot},
		{name: "root drops", id: fakeIdentity{}, uid: 499, gid: 498, wantCalls: "setgroups setgid setuid setuid"},
		{name: "root whose setuid fails refuses", id: fakeIdentity{failSetuid: unix.EPERM}, uid: 499, gid: 498, want: ErrServeAsRoot, wantCalls: "setgroups setgid setuid"},
		{name: "root whose setuid does not take refuses", id: fakeIdentity{ignoreSetuid: true}, uid: 499, gid: 498, want: ErrServeAsRoot, wantCalls: "setgroups setgid setuid"},
		{name: "root that can return to root refuses", id: fakeIdentity{returnsToRoot: true}, uid: 499, gid: 498, want: ErrServeAsRoot, wantCalls: "setgroups setgid setuid setuid"},
		{name: "the service user with its credential runs", id: fakeIdentity{euid: 499, ruid: 499, egid: 498}, uid: 499, gid: 498},
		{name: "an unprivileged user with no credential named runs", id: fakeIdentity{euid: 501, ruid: 501, egid: 20}},
		{name: "another user refuses", id: fakeIdentity{euid: 501, ruid: 501, egid: 498}, uid: 499, gid: 498, want: ErrServeCredential},
		{name: "another group refuses", id: fakeIdentity{euid: 499, ruid: 499, egid: 20}, uid: 499, gid: 498, want: ErrServeCredential},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := tc.id
			err := applyServeCredential(ServeConfig{UID: tc.uid, GID: tc.gid}, id.identity())
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if got := strings.Join(id.calls, " "); got != tc.wantCalls {
				t.Errorf("calls %q, want %q", got, tc.wantCalls)
			}
		})
	}
}

// TestServeRefusesBeforeTheStoreOpens pins that every startup refusal comes
// before store.Open, which would create the store root.
func TestServeRefusesBeforeTheStoreOpens(t *testing.T) {
	cases := []struct {
		name string
		edit func(*ServeConfig)
		deps func(*serveDeps)
		want error
	}{
		{
			name: "root whose drop fails",
			edit: func(c *ServeConfig) { c.UID, c.GID = os.Getuid(), os.Getgid() },
			deps: func(d *serveDeps) { d.ident = (&fakeIdentity{failSetuid: unix.EPERM}).identity() },
			want: ErrServeAsRoot,
		},
		{
			name: "another user than the config names",
			edit: func(c *ServeConfig) { c.UID, c.GID = os.Getuid()+1, os.Getgid() },
			want: ErrServeCredential,
		},
		{
			name: "a data volume on another device",
			edit: func(c *ServeConfig) { c.DataVolume = "/dev" },
			want: ErrOffDataVolume,
		},
		{
			name: "a data volume that is not mounted",
			edit: func(c *ServeConfig) { c.DataVolume = filepath.Dir(t.TempDir()) },
			want: ErrOffDataVolume,
		},
		{
			name: "a parent already gone",
			deps: func(d *serveDeps) { d.getppid = func() int { return 1 } },
			want: ErrParentExited,
		},
		{
			name: "a non-loopback listener",
			edit: func(c *ServeConfig) { c.Listen = "192.0.2.1:6450" },
			want: ErrNonLoopbackBind,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			work := writeTestServeConfig(t, tc.edit)
			d := testServeDeps(newMemListener())
			if tc.deps != nil {
				tc.deps(&d)
			}
			err := serve(context.Background(), ServeConfigPath(work), d)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if _, err := os.Stat(StateDir(work)); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("the store root exists after the refusal: %v", err)
			}
		})
	}
	t.Run("a config not at its work dir's path", func(t *testing.T) {
		work := writeTestServeConfig(t, nil)
		moved := filepath.Join(work, "elsewhere.json")
		if err := os.Rename(ServeConfigPath(work), moved); err != nil {
			t.Fatal(err)
		}
		if err := serve(context.Background(), moved, testServeDeps(newMemListener())); err == nil {
			t.Fatal("serve accepted a config at another path")
		}
	})
}

// TestServeDropsRootBeforeTheStoreOpens pins the order on the success path: the
// store root is created only after the last credential call.
func TestServeDropsRootBeforeTheStoreOpens(t *testing.T) {
	work := writeTestServeConfig(t, func(c *ServeConfig) { c.UID, c.GID = os.Getuid(), os.Getgid() })
	fake := fakeIdentity{}
	id := fake.identity()
	inner := id.setuid
	var absentAtDrop bool
	id.setuid = func(u int) error {
		_, err := os.Stat(StateDir(work))
		absentAtDrop = errors.Is(err, fs.ErrNotExist)
		return inner(u)
	}
	l := newMemListener()
	d := testServeDeps(l)
	d.ident = id
	result, cancel := runTestServe(t, work, d)
	if !absentAtDrop {
		t.Error("the store root existed when the credential was applied")
	}
	if got, want := strings.Join(fake.calls, " "), "setgroups setgid setuid setuid"; got != want {
		t.Errorf("calls %q, want %q", got, want)
	}
	if _, err := os.Stat(StateDir(work)); err != nil {
		t.Errorf("the store root after the start: %v", err)
	}
	cancel()
	if err := <-result; err != nil {
		t.Errorf("serve: %v", err)
	}
}

// TestServeAuthorizesAndReports serves over an in-memory listener and checks the
// permission matrix through the served stack, the slog records in registry.log,
// and the fields the server adds to the state record.
func TestServeAuthorizesAndReports(t *testing.T) {
	work := writeTestServeConfig(t, nil)
	// The daemon's record, which the server must add to and not replace.
	if err := WriteState(work, State{State: StateServing, Port: 6450, Addr: "127.0.0.1:6450"}); err != nil {
		t.Fatal(err)
	}
	l := newMemListener()
	d := testServeDeps(l)
	d.gcGrace, d.gcInterval = 20*time.Millisecond, 20*time.Millisecond
	result, cancel := runTestServe(t, work, d)
	c := memClient(t, l)
	const base = "http://registry.test/v2/"

	if resp := do(t, c, http.MethodGet, base, "", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("anonymous /v2/: %d, want 200", resp.StatusCode)
	}
	resp := do(t, c, http.MethodPost, base+"demo/blobs/uploads/", "", "")
	if resp.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Basic ") {
		t.Errorf("anonymous upload: %d %q, want 401 with a Basic challenge", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	if resp := do(t, c, http.MethodPost, base+"demo/blobs/uploads/", auth.UserGate, "wrong"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a wrong secret: %d, want 401", resp.StatusCode)
	}
	resp = do(t, c, http.MethodPost, base+"demo/blobs/uploads/", auth.UserGate, testGateSecret)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("gate upload: %d, want 202", resp.StatusCode)
	}
	session := "http://registry.test" + resp.Header.Get("Location")
	if resp := do(t, c, http.MethodDelete, session, auth.UserGate, testGateSecret); resp.StatusCode != http.StatusForbidden {
		t.Errorf("gate upload cancel: %d, want 403", resp.StatusCode)
	}
	if resp := do(t, c, http.MethodPost, base+"demo/blobs/uploads/", auth.UserPush, testPushSecret); resp.StatusCode != http.StatusAccepted {
		t.Errorf("k3sm upload: %d, want 202", resp.StatusCode)
	}

	var seen State
	eventually(t, "the sweep and the sessions in the state record", func() bool {
		st, err := os.ReadFile(StatePath(work))
		if err != nil {
			t.Fatal(err)
		}
		if seen, err = ParseState(st); err != nil {
			t.Fatal(err)
		}
		return seen.GC != nil && seen.UploadSessions >= 2
	})
	if seen.State != StateServing || seen.Addr != "127.0.0.1:6450" {
		t.Errorf("the server changed the daemon's fields: %+v", seen)
	}
	if !seen.GC.ReportOnly || seen.GC.LastSweep.IsZero() {
		t.Errorf("the first sweep: %+v, want a dated report-only sweep", seen.GC)
	}

	cancel()
	if err := <-result; err != nil {
		t.Fatalf("serve: %v", err)
	}
	st, err := os.ReadFile(StatePath(work))
	if err != nil {
		t.Fatal(err)
	}
	final, err := ParseState(st)
	if err != nil {
		t.Fatal(err)
	}
	if final.UploadSessions != 0 {
		t.Errorf("a stopped server reports %d upload sessions", final.UploadSessions)
	}

	raw, err := os.ReadFile(LogPath(work))
	if err != nil {
		t.Fatal(err)
	}
	log := string(raw)
	for _, want := range []string{
		`"reason":"anonymous"`,        // a refusal
		`"reason":"bad credential"`,   // an authentication failure
		`"reason":"denied"`,           // a principal without the permission
		`registry gc: sweep finished`, // a sweep
		`"msg":"registry server serving"`,
		`"msg":"registry server stopped"`,
	} {
		if !strings.Contains(log, want) {
			t.Errorf("registry.log has no %s:\n%s", want, log)
		}
	}
	for _, secret := range []string{testPushSecret, testGateSecret} {
		if strings.Contains(log, secret) {
			t.Errorf("registry.log carries a secret")
		}
	}
	fi, err := os.Stat(LogPath(work))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("registry.log mode %#o, want 0600", fi.Mode().Perm())
	}
}

// TestServeLogsAPush pins the push record of the log through the served stack.
func TestServeLogsAPush(t *testing.T) {
	work := writeTestServeConfig(t, nil)
	l := newMemListener()
	result, cancel := runTestServe(t, work, testServeDeps(l))
	c := memClient(t, l)
	resp := do(t, c, http.MethodPost, "http://registry.test/v2/demo/blobs/uploads/", auth.UserGate, testGateSecret)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("upload: %d", resp.StatusCode)
	}
	// The digest of the empty body.
	const empty = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	resp = do(t, c, http.MethodPut, "http://registry.test"+resp.Header.Get("Location")+"?digest="+empty, auth.UserGate, testGateSecret)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("commit: %d", resp.StatusCode)
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(LogPath(work))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"msg":"registry blob pushed"`) {
		t.Errorf("registry.log has no push record:\n%s", raw)
	}
}

// TestServeExitsWhenItsParentDies runs the watch against a real process, standing
// in for the daemon.
func TestServeExitsWhenItsParentDies(t *testing.T) {
	parent := exec.Command("/bin/sleep", "60")
	if err := parent.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = parent.Process.Kill()
		_ = parent.Wait()
	})
	work := writeTestServeConfig(t, nil)
	d := testServeDeps(newMemListener())
	d.getppid = func() int { return parent.Process.Pid }
	result, _ := runTestServe(t, work, d)
	select {
	case err := <-result:
		t.Fatalf("serve returned with its parent alive: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := parent.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, ErrParentExited) {
			t.Fatalf("got %v, want ErrParentExited", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("serve outlived its parent")
	}
}

// TestWatchParent covers the watch's two other ends: a pid already gone and a
// stop with the pid alive.
func TestWatchParent(t *testing.T) {
	t.Run("a pid already gone", func(t *testing.T) {
		gone := exec.Command("/usr/bin/true")
		if err := gone.Run(); err != nil {
			t.Fatal(err)
		}
		if _, _, err := watchParent(gone.Process.Pid); !errors.Is(err, ErrParentExited) {
			t.Fatalf("got %v, want ErrParentExited", err)
		}
	})
	t.Run("a stop leaves the channel open", func(t *testing.T) {
		goneCh, stop, err := watchParent(os.Getpid())
		if err != nil {
			t.Fatal(err)
		}
		stop()
		stop()
		select {
		case <-goneCh:
			t.Fatal("the watch reported an exit on a stop")
		default:
		}
	})
}

// TestCloseInheritedDescriptors plants a descriptor without FD_CLOEXEC, which is
// what a leak through an exec looks like, beside one with it.
func TestCloseInheritedDescriptors(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	leaked, err := unix.Dup(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if flags, err := unix.FcntlInt(uintptr(leaked), unix.F_GETFD, 0); err != nil || flags&unix.FD_CLOEXEC != 0 {
		t.Fatalf("the planted descriptor: flags %d, err %v", flags, err)
	}
	if err := closeInheritedDescriptors(); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(leaked), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		_ = unix.Close(leaked)
		t.Errorf("the inherited descriptor survived: %v", err)
	}
	if _, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0); err != nil {
		t.Errorf("a close-on-exec descriptor was closed: %v", err)
	}
	for fd := range 3 {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
			t.Errorf("stdio descriptor %d was closed: %v", fd, err)
		}
	}
}

// TestCheckDataVolume checks the st_dev comparison against real devices.
func TestCheckDataVolume(t *testing.T) {
	// /dev is the one mount every Mac has that a test can name: it is a device of
	// its own, and a path under it stands in for a store on the volume.
	tmp := t.TempDir()
	cases := []struct {
		name         string
		volume, root string
		want         error
	}{
		{name: "no data volume", root: tmp},
		{name: "the store on the mounted volume", volume: "/dev", root: "/dev"},
		{name: "a store root not created yet, judged by its ancestor", volume: "/dev", root: "/dev/k3sm-work/registry"},
		{name: "the store on another device", volume: "/dev", root: tmp, want: ErrOffDataVolume},
		{name: "a mount point nothing is mounted on", volume: tmp, root: filepath.Join(tmp, "registry"), want: ErrOffDataVolume},
		{name: "a mount point that is not there", volume: filepath.Join(tmp, "missing"), root: tmp, want: ErrOffDataVolume},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkDataVolume(tc.volume, tc.root); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// TestServeConfigServerFields round-trips the server's fields through the atomic
// write and the reader, and pins what validateForServing and root's read refuse.
func TestServeConfigServerFields(t *testing.T) {
	work := writeTestServeConfig(t, func(c *ServeConfig) {
		c.DataVolume, c.UID, c.GID = "/var/lib/k3sm", 499, 498
	})
	cfg, err := ReadServeConfig(ServeConfigPath(work))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:6450" || cfg.DataVolume != "/var/lib/k3sm" || cfg.UID != 499 || cfg.GID != 498 {
		t.Errorf("round trip: %+v", cfg)
	}
	if err := cfg.validateForServing(); err != nil {
		t.Errorf("validateForServing: %v", err)
	}
	refused := map[string]ServeConfig{
		"no listener":       {},
		"no port":           {Listen: "127.0.0.1"},
		"a named port":      {Listen: "127.0.0.1:http"},
		"port out of range": {Listen: "127.0.0.1:70000"},
		"off loopback":      {Listen: "0.0.0.0:6450"},
		"a negative uid":    {Listen: "127.0.0.1:6450", UID: -1},
		"a negative gid":    {Listen: "127.0.0.1:6450", UID: 499, GID: -1},
		"a gid with no uid": {Listen: "127.0.0.1:6450", GID: 498},
		"a relative volume": {Listen: "127.0.0.1:6450", DataVolume: "var/lib/k3sm"},
		"an unclean volume": {Listen: "127.0.0.1:6450", DataVolume: "/var/lib/../k3sm"},
	}
	for name, c := range refused {
		if err := c.validateForServing(); err == nil {
			t.Errorf("validateForServing accepted %s", name)
		}
	}
	t.Run("root reads a config its service user owns", func(t *testing.T) {
		w := writeTestServeConfig(t, func(c *ServeConfig) { c.UID, c.GID = os.Getuid(), os.Getgid() })
		if _, err := readServeConfigAs(ServeConfigPath(w), 0); err != nil {
			t.Error(err)
		}
	})
	t.Run("root refuses a config owned by a user it does not name", func(t *testing.T) {
		w := writeTestServeConfig(t, func(c *ServeConfig) { c.UID, c.GID = os.Getuid()+1, os.Getgid() })
		if _, err := readServeConfigAs(ServeConfigPath(w), 0); err == nil {
			t.Error("readServeConfigAs accepted it")
		}
	})
	t.Run("another user refuses it", func(t *testing.T) {
		if _, err := readServeConfigAs(ServeConfigPath(work), os.Geteuid()+1); err == nil {
			t.Error("readServeConfigAs accepted it")
		}
	})
}

// TestServeGCCadenceMatchesTheChild pins that the server collects on the cadence
// the child it replaces is configured with.
func TestServeGCCadenceMatchesTheChild(t *testing.T) {
	for _, tc := range []struct {
		spelled string
		value   time.Duration
	}{{gcDelay, serveGCGrace}, {gcInterval, serveGCInterval}} {
		d, err := time.ParseDuration(tc.spelled)
		if err != nil {
			t.Fatal(err)
		}
		if d != tc.value {
			t.Errorf("%s != %s", tc.spelled, tc.value)
		}
	}
}

// TestStateUpdatesDoNotLoseWrites hammers the record through the lock from many
// goroutines, each holding its own descriptor as a second process would.
func TestStateUpdatesDoNotLoseWrites(t *testing.T) {
	work := t.TempDir()
	if err := WriteState(work, State{State: StateServing}); err != nil {
		t.Fatal(err)
	}
	const n = 32
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			if err := updateState(work, func(st *State) bool {
				st.UploadSessions++
				return true
			}); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	b, err := os.ReadFile(StatePath(work))
	if err != nil {
		t.Fatal(err)
	}
	st, err := ParseState(b)
	if err != nil {
		t.Fatal(err)
	}
	if st.UploadSessions != n {
		t.Errorf("%d updates landed, want %d", st.UploadSessions, n)
	}
}
