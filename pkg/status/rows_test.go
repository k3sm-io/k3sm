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

package status

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/executor"
)

// fakeToken is the credential shape the secret tests hunt for. It is NOT a real
// token and never was; it exists so a test can prove a redaction fired.
const fakeToken = "k3sm-DEADBEEFfake0token0for0tests0only"

// ---- fakes ----------------------------------------------------------------

// fakeLaunchd answers Print from a canned map, so a test can describe a
// crash-looping daemon without one.
type fakeLaunchd struct {
	out      map[string][]byte
	err      map[string]error
	disabled []byte
}

func (f fakeLaunchd) Print(label string) ([]byte, error) {
	if err := f.err[label]; err != nil {
		return f.out[label], err
	}
	return f.out[label], nil
}

func (f fakeLaunchd) PrintDisabled() ([]byte, error) { return f.disabled, nil }

// fakeFileInfo is the minimum fs.FileInfo the rows read: a mode and a Sys()
// payload carrying the owning uid.
type fakeFileInfo struct {
	name string
	mode fs.FileMode
	uid  uint32
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return &syscall.Stat_t{Uid: f.uid} }

// fakeFS is the report's filesystem seam.
type fakeFS struct {
	present  map[string]bool
	denied   map[string]bool
	links    map[string]string
	tail     map[string][]string
	tailErr  map[string]error
	fileMode fs.FileMode
	// contents / unreadable back ReadFile (the crash-loop record).
	contents   map[string][]byte
	unreadable map[string]bool
}

func (f fakeFS) Stat(path string) (fs.FileInfo, error) {
	if f.denied[path] {
		return nil, &fs.PathError{Op: "stat", Path: path, Err: fs.ErrPermission}
	}
	if !f.present[path] {
		return nil, &fs.PathError{Op: "stat", Path: path, Err: fs.ErrNotExist}
	}
	return fakeFileInfo{name: filepath.Base(path), mode: f.fileMode}, nil
}

func (f fakeFS) ReadTail(path string, _ int) ([]string, error) {
	if err := f.tailErr[path]; err != nil {
		return nil, err
	}
	return f.tail[path], nil
}

// ReadFile serves the fake's files map like Stat does; an absent path is
// os.ErrNotExist so the crash-loop row reads "no record", and a path the fake
// marks unreadable is EACCES — the plain-user posture against a 0700 work dir.
func (f fakeFS) ReadFile(path string) ([]byte, error) {
	if f.unreadable != nil && f.unreadable[path] {
		return nil, os.ErrPermission
	}
	b, ok := f.contents[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return b, nil
}

func (f fakeFS) Readlink(path string) (string, error) {
	if target, ok := f.links[path]; ok {
		return target, nil
	}
	return "", &fs.PathError{Op: "readlink", Path: path, Err: fs.ErrNotExist}
}

// fakeKube answers the apiserver reads from canned values.
type fakeKube struct {
	raw    map[string][]byte
	rawErr map[string]error
	nodes  []corev1.Node
	pods   []corev1.Pod
	server string
	tls    string
}

func (f fakeKube) RawGet(_ context.Context, path string) ([]byte, error) {
	if err := f.rawErr[path]; err != nil {
		return nil, err
	}
	return f.raw[path], nil
}
func (f fakeKube) Nodes(context.Context) ([]corev1.Node, error) { return f.nodes, nil }
func (f fakeKube) Pods(context.Context) ([]corev1.Pod, error)   { return f.pods, nil }
func (f fakeKube) Server() string                               { return f.server }
func (f fakeKube) TLSPosture() string                           { return f.tls }

// fakeProcs answers the process-table seam.
type fakeProcs struct {
	live    Liveness
	vmHosts int
}

func (f fakeProcs) Liveness(int) Liveness    { return f.live }
func (f fakeProcs) VMHosts(int) (int, error) { return f.vmHosts, nil }

// fatalRuntimed fails the test if it is ever called. It is how the unprivileged
// case proves the owner-only socket was not touched, rather than proving only
// that the row happened to say "unknown".
type fatalRuntimed struct{ t *testing.T }

func (f fatalRuntimed) Info(context.Context) (*runtimev1.GetRuntimeInfoResponse, error) {
	f.t.Fatal("the runtimed control socket was dialled by a uid that may not open it")
	return nil, nil
}

// fakeDataRootFS describes a data-root posture no unprivileged test could create
// on a real disk — most importantly the shadow (declared in /etc/fstab, nothing
// mounted).
type fakeDataRootFS struct {
	fstab   string
	dir     string
	mode    fs.FileMode
	uid     uint32
	missing bool
	mounted bool
	entries []string
}

func (f fakeDataRootFS) Stat(path string) (fs.FileInfo, error) {
	if f.missing || path != f.dir {
		return nil, &fs.PathError{Op: "stat", Path: path, Err: fs.ErrNotExist}
	}
	return fakeFileInfo{name: filepath.Base(path), mode: f.mode | fs.ModeDir, uid: f.uid}, nil
}

func (f fakeDataRootFS) Statfs(path string, st *unix.Statfs_t) error {
	if !f.mounted || path != f.dir {
		copy(st.Mntonname[:], "/\x00")
		return nil
	}
	copy(st.Mntonname[:], f.dir+"\x00")
	copy(st.Fstypename[:], "apfs\x00")
	copy(st.Mntfromname[:], "/dev/disk3s7\x00")
	return nil
}

func (f fakeDataRootFS) ReadFile(path string) ([]byte, error) {
	if f.fstab == "" {
		return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
	}
	return []byte(f.fstab), nil
}

func (f fakeDataRootFS) ReadDir(string) ([]fs.DirEntry, error) {
	out := make([]fs.DirEntry, 0, len(f.entries))
	for _, name := range f.entries {
		out = append(out, fs.FileInfoToDirEntry(fakeFileInfo{name: name, mode: fs.ModeDir}))
	}
	return out, nil
}

// ---- fixtures -------------------------------------------------------------

// testPaths is an install laid out exactly like a real one, so the row details
// read like the ones an operator sees.
func testPaths(workDir string) Paths {
	return Paths{
		Binary:          "/Library/k3sm/k3sm",
		Link:            "/usr/local/bin/k3sm",
		LaunchDaemonDir: "/Library/LaunchDaemons",
		NetdLabel:       "io.k3sm.netd",
		ServerLabel:     "io.k3sm.server",
		DataRoot:        "/var/lib/k3sm",
		WorkDir:         workDir,
		NetdSocket:      "/var/lib/k3sm/run/netd.sock",
		NetdLog:         "/var/log/k3sm/netd.log",
		ServerLog:       "/var/log/k3sm/server.log",
	}
}

// installedFS is a complete, healthy install on disk.
func installedFS(p Paths) fakeFS {
	return fakeFS{
		present: map[string]bool{
			p.Binary:     true,
			p.NetdSocket: true,
			filepath.Join(p.LaunchDaemonDir, p.NetdLabel+".plist"):   true,
			filepath.Join(p.LaunchDaemonDir, p.ServerLabel+".plist"): true,
		},
		links: map[string]string{p.Link: p.Binary},
		tail:  map[string][]string{},
	}
}

// readyNode is a Ready darwin node.
func readyNode(name string) corev1.Node {
	n := corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}}
	n.Status.NodeInfo.KubeletVersion = "v1.36.2"
	n.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}
	return n
}

// healthyKube is an apiserver that is serving one Ready node and three pods.
func healthyKube() fakeKube {
	return fakeKube{
		raw:    map[string][]byte{"/readyz": []byte("ok"), "/readyz?verbose": []byte("[+]ping ok\nreadyz check passed")},
		nodes:  []corev1.Node{readyNode("my-mac")},
		pods:   []corev1.Pod{podIn(corev1.PodRunning), podIn(corev1.PodRunning), podIn(corev1.PodRunning)},
		server: "https://127.0.0.1:6444",
		tls:    "ca pinned",
	}
}

func podIn(phase corev1.PodPhase) corev1.Pod {
	p := corev1.Pod{}
	p.Status.Phase = phase
	return p
}

// walDB writes a WAL-mode state.db header into a work dir so the datastore row
// has something real, and read-only, to parse.
func walDB(t *testing.T) string {
	t.Helper()
	workDir := t.TempDir()
	path := executor.StateDBPath(workDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeFakeSQLiteHeader(t, path, 2, 1)
	return workDir
}

// ---- tests ----------------------------------------------------------------

// TestCollectorHealthyCluster proves the whole assembly: a Mac where everything
// is up produces a running verdict, and every row says why.
func TestCollectorHealthyCluster(t *testing.T) {
	t.Parallel()
	p := testPaths(walDB(t))
	c := Collector{
		Launchd: fakeLaunchd{out: map[string][]byte{
			p.NetdLabel:   fixture(t, "launchctl_netd_running.txt"),
			p.ServerLabel: fixture(t, "launchctl_netd_running.txt"),
		}},
		FS:         installedFS(p),
		Kube:       healthyKube(),
		KubeSource: "~/.kube/config context \"k3sm\"",
		Procs:      fakeProcs{live: LivenessRunning, vmHosts: 2},
		DataRoot:   fakeDataRootFS{dir: p.DataRoot, mode: 0o750, uid: 250, mounted: true},
		Paths:      p,
		EUID:       501,
		ServiceUID: 250,
		Now:        func() time.Time { return goldenTime },
		Version:    goldenVersion,
		Host:       goldenHost,
	}
	rep := c.Collect(context.Background())
	if rep.Verdict != VerdictRunning {
		t.Fatalf("verdict = %v (%s), want running\n%s", rep.Verdict, rep.Summary, Render(rep, Style{}))
	}
	want := map[string]RowState{
		RowInstall:   StateOK,
		RowNetd:      StateRunning,
		RowServer:    StateRunning,
		RowAPIServer: StateReady,
		RowNode:      StateReady,
		RowWorkloads: StateOK,
		RowDataRoot:  StateOK,
		RowDatastore: StateOK,
	}
	for name, state := range want {
		got, ok := rep.Row(name)
		if !ok {
			t.Errorf("row %q missing", name)
			continue
		}
		if got.State != state {
			t.Errorf("row %q state = %q, want %q (%s)", name, got.State, state, got.Detail)
		}
	}
	if w, _ := rep.Row(RowWorkloads); !strings.Contains(w.Detail, "2 vm") {
		t.Errorf("workloads row did not count the vm hosts: %q", w.Detail)
	}
	if a, _ := rep.Row(RowAPIServer); a.Wide["tls"] != "ca pinned" {
		t.Errorf("apiserver row did not record the TLS posture: %#v", a.Wide)
	}
	if rep.Timestamp != goldenTime {
		t.Errorf("timestamp = %v, want the injected clock", rep.Timestamp)
	}
}

// TestCollectorCrashLoopingServer is the failure this command exists for: a Mac
// that rebooted into a control plane that will not start.
func TestCollectorCrashLoopingServer(t *testing.T) {
	t.Parallel()
	p := testPaths(t.TempDir())
	fsys := installedFS(p)
	fsys.tail = map[string][]string{p.ServerLog: {
		`time=2026-09-05T09:29:58Z level=INFO msg="starting control plane"`,
		`time=2026-09-05T09:29:59Z level=ERROR msg="control plane exited" err="bind: address already in use"`,
		`time=2026-09-05T09:30:00Z level=ERROR msg="control plane exited" err="bind: address already in use"`,
	}}
	c := Collector{
		Launchd: fakeLaunchd{out: map[string][]byte{
			p.NetdLabel:   fixture(t, "launchctl_netd_running.txt"),
			p.ServerLabel: fixture(t, "launchctl_server_crashloop.txt"),
		}},
		FS:         fsys,
		KubeErr:    errors.New("connection refused"),
		Procs:      fakeProcs{live: LivenessRunning},
		DataRoot:   fakeDataRootFS{dir: p.DataRoot, mode: 0o750, uid: 250, mounted: true},
		Paths:      p,
		EUID:       501,
		ServiceUID: 250,
		Version:    goldenVersion,
	}
	rep := c.Collect(context.Background())
	if rep.Verdict != VerdictStopped {
		t.Fatalf("verdict = %v, want stopped\n%s", rep.Verdict, Render(rep, Style{}))
	}
	server, _ := rep.Row(RowServer)
	if server.State != StateCrashLoop {
		t.Fatalf("server state = %q, want crash-loop", server.State)
	}
	if server.Detail != "497 runs, last exit 1" {
		t.Errorf("server detail = %q", server.Detail)
	}
	if got := server.Wide["log"]; got != `level=ERROR msg="control plane exited" err="bind: address already in use"` {
		t.Errorf("quoted log line = %q — the timestamp should be stripped", got)
	}
	if server.Wide["log-repeats"] != "2" {
		t.Errorf("log-repeats = %q, want 2 (the identical run at the tail)", server.Wide["log-repeats"])
	}
	if !strings.Contains(rep.Summary, "io.k3sm.server is crash-looping") {
		t.Errorf("summary does not name the cause: %q", rep.Summary)
	}
}

// TestCollectorShadowedDataRoot pins the posture that looks like an empty
// cluster and is not: /var/lib/k3sm is declared in /etc/fstab and nothing is
// mounted there, so everything written lands on the boot disk.
func TestCollectorShadowedDataRoot(t *testing.T) {
	t.Parallel()
	p := testPaths(t.TempDir())
	c := Collector{
		Launchd: fakeLaunchd{out: map[string][]byte{
			p.NetdLabel:   fixture(t, "launchctl_netd_running.txt"),
			p.ServerLabel: fixture(t, "launchctl_netd_running.txt"),
		}},
		FS:    installedFS(p),
		Kube:  healthyKube(),
		Procs: fakeProcs{live: LivenessRunning},
		DataRoot: fakeDataRootFS{
			fstab:   "UUID=1234-ABCD /var/lib/k3sm apfs rw 0 0\n",
			dir:     p.DataRoot,
			mode:    0o750,
			uid:     0,
			mounted: false,
			entries: []string{"run"},
		},
		Paths:      p,
		EUID:       501,
		ServiceUID: 250,
		Version:    goldenVersion,
	}
	rep := c.Collect(context.Background())
	root, _ := rep.Row(RowDataRoot)
	if root.State != StateNotMounted || root.Severity != SeverityFail {
		t.Fatalf("data-root row = %q/%v, want not-mounted/fail (%s)", root.State, root.Severity, root.Detail)
	}
	for _, must := range []string{"declared in /etc/fstab", "shadow directory (uid 0)", "holds run"} {
		if !strings.Contains(root.Detail, must) {
			t.Errorf("data-root detail missing %q: %q", must, root.Detail)
		}
	}
	if !strings.Contains(root.Remedy, "diskutil mount -mountPoint /var/lib/k3sm") {
		t.Errorf("data-root remedy does not name the mount: %q", root.Remedy)
	}
	if rep.Verdict != VerdictDegraded {
		t.Errorf("verdict = %v, want degraded (the apiserver is still serving)", rep.Verdict)
	}
}

// TestCollectorWrongOwnerDataRoot pins the other data-root failure: the root
// exists and is mounted, but the service user cannot write it.
func TestCollectorWrongOwnerDataRoot(t *testing.T) {
	t.Parallel()
	p := testPaths(t.TempDir())
	c := Collector{
		Launchd:    fakeLaunchd{out: map[string][]byte{p.NetdLabel: fixture(t, "launchctl_netd_running.txt")}},
		FS:         installedFS(p),
		Procs:      fakeProcs{live: LivenessRunning},
		DataRoot:   fakeDataRootFS{dir: p.DataRoot, mode: 0o750, uid: 0, mounted: true},
		Paths:      p,
		EUID:       501,
		ServiceUID: 250,
		Version:    goldenVersion,
	}
	root, _ := c.Collect(context.Background()).Row(RowDataRoot)
	if root.State != StateWrongOwner {
		t.Fatalf("data-root state = %q, want wrong-owner (%s)", root.State, root.Detail)
	}
	if !strings.Contains(root.Detail, "owned by uid 0") || !strings.Contains(root.Detail, "_k3sm") {
		t.Errorf("data-root detail does not name the uid and the service user: %q", root.Detail)
	}
}

// TestCollectorUnreadableAsOrdinaryUser is the honest-unknown case: an account
// that can see the install but not the daemons' private state gets unknown rows
// and the unknown verdict, never a healthy-looking one.
func TestCollectorUnreadableAsOrdinaryUser(t *testing.T) {
	t.Parallel()
	p := testPaths("/var/lib/k3sm/server") // unreadable in the test process too
	fsys := installedFS(p)
	fsys.denied = map[string]bool{p.NetdSocket: true}
	c := Collector{
		Launchd: fakeLaunchd{out: map[string][]byte{
			p.NetdLabel:   fixture(t, "launchctl_format_drift.txt"),
			p.ServerLabel: fixture(t, "launchctl_format_drift.txt"),
		}},
		FS:         fsys,
		KubeErr:    errors.New("no k3sm context in ~/.kube/config"),
		DataRoot:   fakeDataRootFS{dir: p.DataRoot, mode: 0o750, uid: 250, mounted: true},
		Paths:      p,
		EUID:       501,
		ServiceUID: 250,
		Version:    goldenVersion,
	}
	rep := c.Collect(context.Background())
	if rep.Verdict != VerdictUnknown {
		t.Fatalf("verdict = %v, want unknown\n%s", rep.Verdict, Render(rep, Style{}))
	}
	if rep.Verdict.ExitCode() == 1 {
		t.Fatal("unknown must not share the internal-error exit code")
	}
	if !strings.Contains(rep.Summary, "re-run with sudo") {
		t.Errorf("summary does not say how to get an answer: %q", rep.Summary)
	}
}

// TestCollectorSkipsRuntimedUnprivileged proves the owner-only runtimed socket is
// not dialled by a uid that may not open it — the seam's Info fails the test if
// it is ever reached — and that the resulting row says so honestly.
func TestCollectorSkipsRuntimedUnprivileged(t *testing.T) {
	t.Parallel()
	p := testPaths(t.TempDir())
	c := Collector{
		Launchd:    fakeLaunchd{out: map[string][]byte{}},
		FS:         installedFS(p),
		Runtimed:   fatalRuntimed{t: t},
		DataRoot:   fakeDataRootFS{dir: p.DataRoot, mode: 0o750, uid: 250, mounted: true},
		Paths:      p,
		EUID:       501,
		ServiceUID: 250,
		Version:    goldenVersion,
	}
	rt, ok := c.Collect(context.Background()).Row(RowRuntimed)
	if !ok {
		t.Fatal("no runtimed row")
	}
	if rt.State != StateUnknown || rt.Detail != "needs sudo (socket is owner-only)" {
		t.Fatalf("runtimed row = %q/%q", rt.State, rt.Detail)
	}
}

// TestRuntimedReachable is the uid predicate both the adapter and the collector
// consult. It fails CLOSED on an unresolved service user, because dialling an
// owner-only socket on a guess is how a status command turns into a permission
// error dressed up as a fault.
func TestRuntimedReachable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		euid, serviceUID int
		want             bool
	}{
		{"root", 0, 250, true},
		{"the service user itself", 250, 250, true},
		{"an ordinary account", 501, 250, false},
		{"an unresolved service user", 501, RuntimeReachableUnknownUID, false},
		{"root with an unresolved service user", 0, RuntimeReachableUnknownUID, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := RuntimedReachable(tc.euid, tc.serviceUID); got != tc.want {
				t.Fatalf("RuntimedReachable(%d, %d) = %v, want %v", tc.euid, tc.serviceUID, got, tc.want)
			}
		})
	}
}

// TestReportNeverContainsSecrets is the disclosure gate. `launchctl print` echoes
// a job's whole argv, and the k3sm server's argv carries the cluster join token;
// the server's own log can echo it too. Neither the JSON nor the rendered screen
// may carry it, in any view.
func TestReportNeverContainsSecrets(t *testing.T) {
	t.Parallel()
	p := testPaths(t.TempDir())
	fsys := installedFS(p)
	fsys.tail = map[string][]string{p.ServerLog: {
		`time=2026-09-05T09:30:00Z level=ERROR msg="join failed" argv="--token ` + fakeToken + `"`,
		`time=2026-09-05T09:30:01Z level=ERROR msg="join failed" token=` + fakeToken,
	}}
	c := Collector{
		Launchd: fakeLaunchd{out: map[string][]byte{
			p.NetdLabel:   fixture(t, "launchctl_stopped_clean.txt"),
			p.ServerLabel: fixture(t, "launchctl_server_crashloop.txt"),
		}},
		FS:         fsys,
		KubeErr:    errors.New("apiserver refused the token " + fakeToken),
		DataRoot:   fakeDataRootFS{dir: p.DataRoot, mode: 0o750, uid: 250, mounted: true},
		Paths:      p,
		EUID:       501,
		ServiceUID: 250,
		Version:    goldenVersion,
	}
	rep := c.Collect(context.Background())

	// The fixtures must actually carry the secret, or this test proves nothing.
	if !strings.Contains(string(fixture(t, "launchctl_server_crashloop.txt")), fakeToken) {
		t.Fatal("the launchctl fixture no longer carries a token — this test is vacuous")
	}

	encoded, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	surfaces := map[string]string{
		"json":     string(encoded),
		"overview": Render(rep, Style{}),
		"wide":     Render(rep, Style{Wide: true}),
		"daemons":  RenderDaemons(rep, Style{}),
		"cluster":  RenderCluster(rep, Style{}),
	}
	for name, text := range surfaces {
		for _, forbidden := range []string{fakeToken, "--token k3sm-", "DEADBEEF"} {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s surface leaked %q:\n%s", name, forbidden, text)
			}
		}
		if !strings.Contains(text, "<redacted>") && name != "overview" && name != "wide" {
			continue // not every view quotes a redacted field
		}
	}
	if got := mustRow(t, rep, RowServer).Wide["log"]; !strings.Contains(got, "<redacted>") {
		t.Errorf("the quoted log line was not redacted: %q", got)
	}
}

// TestRedact is the table behind the disclosure gate: the shapes k3sm mints are
// removed, and ordinary text that merely starts with "k3sm-" is not mangled.
func TestRedact(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, in, want string
	}{
		{"a token flag takes its value with it", "server --token " + fakeToken + " --data-dir /var/lib/k3sm", "server --token <redacted> --data-dir /var/lib/k3sm"},
		{"an equals-joined token flag", "--token=" + fakeToken, "--token <redacted>"},
		{"a bare token anywhere", "refused token " + fakeToken, "refused token <redacted>"},
		{"a CA-pinned bootstrap token", "K10" + strings.Repeat("ab", 32) + "::server:secret", "<redacted>"},
		{"a short k3sm- identifier is not a token", "k3sm-vmhost exited", "k3sm-vmhost exited"},
		{"the runtime name survives", "k3sm-runtimed healthy", "k3sm-runtimed healthy"},
		{"ordinary text is untouched", "io.k3sm.server is not loaded", "io.k3sm.server is not loaded"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := Redact(tc.in); got != tc.want {
				t.Fatalf("Redact(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestStatusJSONRoundTrip pins the machine interface: a report survives a
// marshal/unmarshal round trip unchanged, and the verdict and severity words on
// the wire are the lowercase tokens a script matches on.
func TestStatusJSONRoundTrip(t *testing.T) {
	t.Parallel()
	for name, rep := range goldenReports() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			encoded, err := json.MarshalIndent(rep, "", "  ")
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var back Report
			if err := json.Unmarshal(encoded, &back); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if back.Verdict != rep.Verdict || back.Summary != rep.Summary || len(back.Rows) != len(rep.Rows) {
				t.Fatalf("round trip changed the report:\n%s", encoded)
			}
			for i := range rep.Rows {
				if back.Rows[i].Name != rep.Rows[i].Name || back.Rows[i].State != rep.Rows[i].State ||
					back.Rows[i].Severity != rep.Rows[i].Severity || back.Rows[i].Detail != rep.Rows[i].Detail {
					t.Fatalf("row %d changed: %+v vs %+v", i, back.Rows[i], rep.Rows[i])
				}
			}
			if !strings.Contains(string(encoded), `"verdict": "`+rep.Verdict.String()+`"`) {
				t.Errorf("verdict is not the lowercase word on the wire:\n%s", encoded)
			}
		})
	}

	t.Run("an unknown verdict word is an error, not a silent default", func(t *testing.T) {
		t.Parallel()
		var v Verdict
		if err := v.UnmarshalText([]byte("mostly-fine")); err == nil {
			t.Fatal("an unrecognised verdict word was accepted")
		}
	})
}

// mustRow fetches a row or fails.
func mustRow(t *testing.T, rep Report, name string) Row {
	t.Helper()
	r, ok := rep.Row(name)
	if !ok {
		t.Fatalf("row %q missing", name)
	}
	return r
}
