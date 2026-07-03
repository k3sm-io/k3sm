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

package provider

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	utilexec "k8s.io/utils/exec"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/provider/vkadapter"
)

// M2.5 — provider-served exec/attach/port-forward. These prove the provider wires
// the VK AttachIO / byte stream to the runtime/v1 Exec/Attach/PortForward bidi
// RPCs (against the frozen apis contract) using a fake runtime stream — no real
// confinement (that is e2e). The fake echoes input back and reports a scripted
// exit, so the stream plumbing and exit-status mapping are observable.

// fakeStreamRuntime is a runtimev1.RuntimeServer that tracks created pods (so the
// provider's lookup resolves them) and serves Exec/Attach/PortForward by echoing
// input and reporting a scripted exit.
type fakeStreamRuntime struct {
	runtimev1.UnimplementedRuntimeServer

	exitCode int32             // exit code Exec/Attach report
	execErr  *rpcstatus.Status // optional structured exec failure

	mu      sync.Mutex
	execCmd []string // command the last Exec received
	stdin   []byte   // stdin bytes Exec/Attach collected
	pfData  []byte   // bytes PortForward proxied pod-ward
}

func (f *fakeStreamRuntime) CreatePod(_ context.Context, req *runtimev1.CreatePodRequest) (*runtimev1.CreatePodResponse, error) {
	return &runtimev1.CreatePodResponse{Status: &runtimev1.PodStatus{PodId: req.GetPod().GetPodId(), Phase: runtimev1.PodPhase_POD_PHASE_RUNNING}}, nil
}

func (f *fakeStreamRuntime) GetPodStatus(_ context.Context, req *runtimev1.GetPodStatusRequest) (*runtimev1.GetPodStatusResponse, error) {
	return &runtimev1.GetPodStatusResponse{Status: &runtimev1.PodStatus{PodId: req.GetPodId(), Phase: runtimev1.PodPhase_POD_PHASE_RUNNING}}, nil
}

// Exec echoes the command then each stdin chunk to stdout, then sends the scripted
// terminal result.
func (f *fakeStreamRuntime) Exec(s grpc.BidiStreamingServer[runtimev1.ExecRequest, runtimev1.ExecResponse]) error {
	first, err := s.Recv()
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.execCmd = first.GetCommand()
	f.mu.Unlock()
	if err := s.Send(&runtimev1.ExecResponse{Stdout: []byte("ran:" + strings.Join(first.GetCommand(), " "))}); err != nil {
		return err
	}
	for {
		req, rerr := s.Recv()
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return rerr
		}
		if d := req.GetStdinData(); len(d) > 0 {
			f.mu.Lock()
			f.stdin = append(f.stdin, d...)
			f.mu.Unlock()
			if err := s.Send(&runtimev1.ExecResponse{Stdout: d}); err != nil {
				return err
			}
		}
	}
	return s.Send(&runtimev1.ExecResponse{Exit: &runtimev1.ExecResult{ExitCode: f.exitCode, Error: f.execErr}})
}

// Attach echoes stdin to stdout (no command), then a clean exit.
func (f *fakeStreamRuntime) Attach(s grpc.BidiStreamingServer[runtimev1.AttachRequest, runtimev1.AttachResponse]) error {
	if _, err := s.Recv(); err != nil { // initial params
		return err
	}
	if err := s.Send(&runtimev1.AttachResponse{Stdout: []byte("attached")}); err != nil {
		return err
	}
	for {
		req, rerr := s.Recv()
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return rerr
		}
		if d := req.GetStdinData(); len(d) > 0 {
			f.mu.Lock()
			f.stdin = append(f.stdin, d...)
			f.mu.Unlock()
			if err := s.Send(&runtimev1.AttachResponse{Stdout: d}); err != nil {
				return err
			}
		}
	}
	return s.Send(&runtimev1.AttachResponse{Exit: &runtimev1.ExecResult{ExitCode: f.exitCode}})
}

// PortForward echoes proxied bytes back to the client (proving both directions),
// recording what it received, and returns on the client's close/EOF.
func (f *fakeStreamRuntime) PortForward(s grpc.BidiStreamingServer[runtimev1.PortForwardRequest, runtimev1.PortForwardResponse]) error {
	for {
		req, err := s.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if req.GetClose() {
			return nil
		}
		if d := req.GetData(); len(d) > 0 {
			f.mu.Lock()
			f.pfData = append(f.pfData, d...)
			f.mu.Unlock()
			if err := s.Send(&runtimev1.PortForwardResponse{ConnectionId: req.GetConnectionId(), Data: d}); err != nil {
				return err
			}
		}
	}
}

// syncBuffer is a mutex-guarded byte sink implementing io.WriteCloser for the fake
// AttachIO stdout/stderr (Send may run on the RPC goroutine; -race safe).
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) Close() error { return nil }

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Bytes returns a copy of the accumulated bytes (byte-exact, for binary payloads).
func (b *syncBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf.Bytes()...)
}

// fakeAttachIO is a VK api.AttachIO over in-memory streams for the exec/attach
// tests.
type fakeAttachIO struct {
	stdin  io.Reader
	stdout *syncBuffer
	stderr *syncBuffer
	tty    bool
	resize chan vkadapter.TermSize
}

func (f *fakeAttachIO) Stdin() io.Reader                  { return f.stdin }
func (f *fakeAttachIO) Stdout() io.WriteCloser            { return f.stdout }
func (f *fakeAttachIO) Stderr() io.WriteCloser            { return f.stderr }
func (f *fakeAttachIO) TTY() bool                         { return f.tty }
func (f *fakeAttachIO) Resize() <-chan vkadapter.TermSize { return f.resize }

// newStreamProvider builds a runtimedRuntime over f with one tracked pod ("web"
// in "default") so the streaming verbs resolve it.
func newStreamProvider(t *testing.T, f runtimev1.RuntimeServer) *runtimedRuntime {
	t.Helper()
	r := newRuntimedWith(f, RuntimedConfig{NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir()}, nil, nil)
	if err := r.CreatePod(context.Background(), runtimedPod("default", "web")); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	return r
}

// TestM2_Exec is the M2.5-a1 proof for `kubectl exec`: RunInContainer streams
// stdin to the runtime Exec RPC, returns its stdout, and maps the exit code (zero
// ⇒ nil; non-zero ⇒ a CodeExitError carrying the code).
func TestM2_Exec(t *testing.T) {
	tests := []struct {
		name     string
		exit     int32
		wantCode int // -1 ⇒ expect nil error
	}{
		{"clean exit returns nil", 0, -1},
		{"non-zero exit surfaces the code", 3, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeStreamRuntime{exitCode: tt.exit}
			r := newStreamProvider(t, f)

			stdout := &syncBuffer{}
			attach := &fakeAttachIO{stdin: strings.NewReader("hello"), stdout: stdout, stderr: &syncBuffer{}}
			err := r.RunInContainer(context.Background(), "default", "web", "c0", []string{"sh", "-c", "echo hi"}, attach)

			if tt.wantCode < 0 {
				if err != nil {
					t.Fatalf("RunInContainer: %v", err)
				}
			} else {
				var ec utilexec.CodeExitError
				if !errors.As(err, &ec) || ec.Code != tt.wantCode {
					t.Fatalf("err = %v, want CodeExitError code %d", err, tt.wantCode)
				}
			}

			out := stdout.String()
			if !strings.Contains(out, "ran:sh -c echo hi") {
				t.Errorf("stdout missing command echo: %q", out)
			}
			if !strings.Contains(out, "hello") {
				t.Errorf("stdout missing stdin echo: %q", out)
			}
			f.mu.Lock()
			gotStdin, gotCmd := string(f.stdin), f.execCmd
			f.mu.Unlock()
			if gotStdin != "hello" {
				t.Errorf("runtime received stdin %q, want hello", gotStdin)
			}
			if len(gotCmd) != 3 {
				t.Errorf("runtime received command %v, want 3 args", gotCmd)
			}
		})
	}
}

// TestM2_ExecErrorSurfaces confirms a structured runtime exec failure surfaces as
// an error (not a panic) — the error path the acceptance calls out.
func TestM2_ExecErrorSurfaces(t *testing.T) {
	f := &fakeStreamRuntime{execErr: &rpcstatus.Status{Code: int32(codes.FailedPrecondition), Message: "container not running"}}
	r := newStreamProvider(t, f)

	attach := &fakeAttachIO{stdout: &syncBuffer{}, stderr: &syncBuffer{}}
	err := r.RunInContainer(context.Background(), "default", "web", "c0", []string{"true"}, attach)
	if err == nil {
		t.Fatal("want an error for a failed exec")
	}
	if !strings.Contains(err.Error(), "container not running") {
		t.Errorf("exec error = %v, want the runtime message surfaced", err)
	}
}

// TestM2_ExecPodNotFound confirms exec against an unknown pod is NotFound, not a
// panic.
func TestM2_ExecPodNotFound(t *testing.T) {
	r := newStreamProvider(t, &fakeStreamRuntime{})
	attach := &fakeAttachIO{stdout: &syncBuffer{}, stderr: &syncBuffer{}}
	if err := r.RunInContainer(context.Background(), "default", "ghost", "c0", []string{"true"}, attach); err == nil {
		t.Fatal("want NotFound for an unknown pod")
	}
}

// TestM2_Attach is the M2.5-a1 proof for `kubectl attach`: AttachToContainer
// streams a container's stdio over the runtime Attach RPC.
func TestM2_Attach(t *testing.T) {
	f := &fakeStreamRuntime{}
	r := newStreamProvider(t, f)

	stdout := &syncBuffer{}
	attach := &fakeAttachIO{stdin: strings.NewReader("input"), stdout: stdout, stderr: &syncBuffer{}}
	if err := r.AttachToContainer(context.Background(), "default", "web", "c0", attach); err != nil {
		t.Fatalf("AttachToContainer: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "attached") || !strings.Contains(out, "input") {
		t.Errorf("attach stdout = %q, want the attach banner + echoed stdin", out)
	}
}

// TestM2_PortForward is the M2.5-a1 proof for `kubectl port-forward`: PortForward
// proxies bytes both ways between the VK stream and the runtime PortForward RPC.
func TestM2_PortForward(t *testing.T) {
	f := &fakeStreamRuntime{}
	r := newStreamProvider(t, f)

	provConn, testConn := net.Pipe()
	errCh := make(chan error, 1)
	go func() { errCh <- r.PortForward(context.Background(), "default", "web", 8080, provConn) }()

	// Write client-ward bytes (net.Pipe Write blocks until read) and read the
	// echoed bytes back — proving both directions.
	go func() { _, _ = testConn.Write([]byte("ping")) }()
	buf := make([]byte, 4)
	_ = testConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(testConn, buf); err != nil {
		t.Fatalf("read echoed bytes: %v", err)
	}
	if string(buf) != "ping" {
		t.Errorf("port-forward echo = %q, want ping", buf)
	}

	_ = testConn.Close() // EOF the client side ⇒ provider closes the forward
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("PortForward: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("PortForward did not return after the client closed")
	}
	f.mu.Lock()
	got := string(f.pfData)
	f.mu.Unlock()
	if got != "ping" {
		t.Errorf("runtime received %q pod-ward, want ping", got)
	}
}

// TestM2_PortForwardPodNotFound confirms port-forward against an unknown pod is
// NotFound, not a panic.
func TestM2_PortForwardPodNotFound(t *testing.T) {
	r := newStreamProvider(t, &fakeStreamRuntime{})
	provConn, _ := net.Pipe()
	defer provConn.Close()
	if err := r.PortForward(context.Background(), "default", "ghost", 8080, provConn); err == nil {
		t.Fatal("want NotFound for an unknown pod")
	}
}

// B78 — kubectl cp is exec-of-tar: `kubectl cp local pod:dst` runs `exec -- tar xf
// -` with the tar on STDIN, and `kubectl cp pod:src local` runs `exec -- tar cf -`
// with the tar on STDOUT. The exec-stream bridge (RunInContainer → streamAttachIO →
// pumpClientStreams → streamPipe → Exec) must round-trip a binary tar byte-for-byte,
// across the 32KB stdin-frame boundary and the cap-16 reqs backpressure, with stderr
// kept off the stdout tar stream. These tests prove that at the public RunInContainer
// seam with a PURE-ECHO / PURE-PRODUCE fake (no banner, no added bytes).

// echoRuntime is a runtimev1.RuntimeServer whose Exec is a pure `cat` (or a pure tar
// producer), used to prove the exec bridge does not mutate a binary stream. Unlike
// fakeStreamRuntime it prepends NO banner: bytes in == bytes out.
type echoRuntime struct {
	runtimev1.UnimplementedRuntimeServer

	exitCode    int32  // terminal exit code
	produce     []byte // cp-out: stream this on stdout then exit (stdin ignored)
	produceStep int    // chunk size for produce (0 ⇒ whole in one frame)
	stderrData  []byte // if set, emitted on stderr once before exit

	mu      sync.Mutex
	rxStdin []byte // bytes the server received on stdin (cp-in), byte-exact
}

func (e *echoRuntime) CreatePod(_ context.Context, req *runtimev1.CreatePodRequest) (*runtimev1.CreatePodResponse, error) {
	return &runtimev1.CreatePodResponse{Status: &runtimev1.PodStatus{PodId: req.GetPod().GetPodId(), Phase: runtimev1.PodPhase_POD_PHASE_RUNNING}}, nil
}

func (e *echoRuntime) GetPodStatus(_ context.Context, req *runtimev1.GetPodStatusRequest) (*runtimev1.GetPodStatusResponse, error) {
	return &runtimev1.GetPodStatusResponse{Status: &runtimev1.PodStatus{PodId: req.GetPodId(), Phase: runtimev1.PodPhase_POD_PHASE_RUNNING}}, nil
}

// Exec is either a pure `cat` (echo each StdinData chunk straight back on stdout,
// recording it) or, when produce is set, a pure `tar cf -` (stream produce on stdout,
// ignore stdin). Either way it emits an optional stderr byte then the terminal exit —
// it adds NO bytes of its own to stdout beyond the echoed/produced payload.
func (e *echoRuntime) Exec(s grpc.BidiStreamingServer[runtimev1.ExecRequest, runtimev1.ExecResponse]) error {
	if _, err := s.Recv(); err != nil { // initial params
		return err
	}
	if e.produce != nil {
		step := e.produceStep
		if step <= 0 {
			step = len(e.produce)
		}
		for off := 0; off < len(e.produce); off += step {
			end := off + step
			if end > len(e.produce) {
				end = len(e.produce)
			}
			if err := s.Send(&runtimev1.ExecResponse{Stdout: e.produce[off:end]}); err != nil {
				return err
			}
		}
	} else {
		for {
			req, rerr := s.Recv()
			if errors.Is(rerr, io.EOF) {
				break
			}
			if rerr != nil {
				return rerr
			}
			if d := req.GetStdinData(); len(d) > 0 {
				e.mu.Lock()
				e.rxStdin = append(e.rxStdin, d...)
				e.mu.Unlock()
				if err := s.Send(&runtimev1.ExecResponse{Stdout: append([]byte(nil), d...)}); err != nil {
					return err
				}
			}
		}
	}
	if len(e.stderrData) > 0 {
		if err := s.Send(&runtimev1.ExecResponse{Stderr: append([]byte(nil), e.stderrData...)}); err != nil {
			return err
		}
	}
	return s.Send(&runtimev1.ExecResponse{Exit: &runtimev1.ExecResult{ExitCode: e.exitCode}})
}

func (e *echoRuntime) received() []byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]byte(nil), e.rxStdin...)
}

// cpAttachIO is a VK api.AttachIO whose stdout/stderr are arbitrary io.WriteClosers
// (an io.Pipe writer here) — unlike fakeAttachIO's unbounded syncBuffer sink, a pipe
// backpressures if not drained, so the bridge must not deadlock under a bounded sink
// (see runExecWithDrain's concurrent drain). tty is always false: kubectl cp never
// sets a TTY (a TTY merges stderr into stdout and would corrupt the tar).
type cpAttachIO struct {
	stdin  io.Reader
	stdout io.WriteCloser
	stderr io.WriteCloser
}

func (f *cpAttachIO) Stdin() io.Reader            { return f.stdin }
func (f *cpAttachIO) Stdout() io.WriteCloser      { return f.stdout }
func (f *cpAttachIO) Stderr() io.WriteCloser      { return f.stderr }
func (f *cpAttachIO) TTY() bool                   { return false }
func (f *cpAttachIO) Resize() <-chan api.TermSize { return nil }

// buildCpTarFixture builds a REAL archive/tar stream (>512KB) of a small tree whose
// binary member is filled with a deterministic full-byte-range payload (containing NUL
// and 0xFF), returning the tar bytes and the name→content map. Crossing 512KB forces
// the stream past both the 32KB stdin frame size and the cap-16 (=512KB) reqs buffer;
// the NUL/0xFF bytes catch any UTF-8/text mangling. seed makes each direction's
// payload deterministic yet independent.
func buildCpTarFixture(t *testing.T, seed uint32) ([]byte, map[string][]byte) {
	t.Helper()
	big := make([]byte, 600<<10)
	x := seed*2654435761 + 1
	for i := range big {
		x = x*1664525 + 1013904223
		big[i] = byte(x >> 24) // cycles the full 0x00..0xFF range
	}
	big[0], big[len(big)-1] = 0x00, 0xFF // guarantee NUL and 0xFF are present
	files := map[string][]byte{
		"cp/data.bin":     big,
		"cp/readme.txt":   []byte("hello k3sm cp\n"),
		"cp/nested/x.bin": {0x00, 0x01, 0xff, 0xfe, 0x7f, 0x80},
	}
	names := []string{"cp/data.bin", "cp/nested/x.bin", "cp/readme.txt"} // stable ⇒ deterministic tar
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, name := range names {
		content := files[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatalf("tar header %s: %v", name, err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatalf("tar write %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	tarBytes := buf.Bytes()
	if len(tarBytes) <= 512<<10 {
		t.Fatalf("fixture tar is %d bytes, want >512KB (vacuous otherwise)", len(tarBytes))
	}
	if bytes.IndexByte(big, 0x00) < 0 || bytes.IndexByte(big, 0xFF) < 0 {
		t.Fatal("fixture payload missing NUL or 0xFF byte (vacuous otherwise)")
	}
	return tarBytes, files
}

// untarAndCompare reads data as a tar archive and asserts its members' names and
// contents match want byte-for-byte.
func untarAndCompare(t *testing.T, data []byte, want map[string][]byte) {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(data))
	seen := map[string]bool{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		content, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("tar read %s: %v", h.Name, err)
		}
		w, ok := want[h.Name]
		if !ok {
			t.Errorf("unexpected tar member %q", h.Name)
			continue
		}
		if int64(len(w)) != h.Size {
			t.Errorf("member %q header size %d, want %d", h.Name, h.Size, len(w))
		}
		if !bytes.Equal(content, w) {
			t.Errorf("member %q content mismatch (%d bytes untarred vs %d expected)", h.Name, len(content), len(w))
		}
		seen[h.Name] = true
	}
	if len(seen) != len(want) {
		t.Errorf("untarred %d members, want %d", len(seen), len(want))
	}
}

// runExecWithDrain runs RunInContainer feeding stdin from stdin and draining stdout
// through an io.Pipe on a SEPARATE goroutine, concurrently with the stdin feed. This
// concurrency is load-bearing: streamPipe.Send writes to attach.Stdout() inline on the
// exec goroutine, so a non-draining sink backpressures through the cap-16 reqs buffer
// and, for a >512KB stream, feeding all of stdin before reading stdout would deadlock.
// The concurrent drain keeps the sink moving; the whole call is bounded by a timeout
// that fails the test rather than hanging. On a real deadlock the timeout branches
// t.Fatal (Goexit) and intentionally ABANDON the run/drain goroutines — do NOT replace
// this with a WaitGroup join, which would itself hang forever on the deadlock it guards.
func runExecWithDrain(t *testing.T, r *runtimedRuntime, stdin io.Reader, cmd []string, timeout time.Duration) (stdout, stderr []byte, err error) {
	t.Helper()
	pr, pw := io.Pipe()
	stderrBuf := &syncBuffer{}
	attach := &cpAttachIO{stdin: stdin, stdout: pw, stderr: stderrBuf}

	var stdoutBuf bytes.Buffer
	drained := make(chan error, 1)
	go func() { _, cerr := io.Copy(&stdoutBuf, pr); drained <- cerr }() // concurrent stdout drain

	runErr := make(chan error, 1)
	go func() {
		e := r.RunInContainer(context.Background(), "default", "web", "c0", cmd, attach)
		_ = pw.Close() // EOF the drain once all stdout is flushed
		runErr <- e
	}()

	select {
	case err = <-runErr:
	case <-time.After(timeout):
		t.Fatal("deadlock/timeout: RunInContainer did not return")
	}
	select {
	case derr := <-drained:
		if derr != nil {
			t.Fatalf("drain stdout: %v", derr)
		}
	case <-time.After(timeout):
		t.Fatal("deadlock/timeout: stdout drain did not finish")
	}
	return stdoutBuf.Bytes(), stderrBuf.Bytes(), err
}

// TestKubectlCpTarStreamRoundTrip proves the exec bridge round-trips a binary tar
// stream byte-for-byte in both `kubectl cp` directions, maps a non-zero tar exit, and
// keeps stderr out of the stdout tar stream.
func TestKubectlCpTarStreamRoundTrip(t *testing.T) {
	const timeout = 10 * time.Second

	// cp-in: `kubectl cp local pod:dst` ⇒ `exec -- tar xf -` (tar on STDIN). Assert
	// the server received the tar byte-exact, and it untars back to the source tree.
	t.Run("cp-in stdin tar xf -", func(t *testing.T) {
		tarIn, files := buildCpTarFixture(t, 1)
		f := &echoRuntime{}
		r := newStreamProvider(t, f)

		stdout, _, err := runExecWithDrain(t, r, bytes.NewReader(tarIn), []string{"tar", "xf", "-"}, timeout)
		if err != nil {
			t.Fatalf("RunInContainer: %v", err)
		}
		got := f.received()
		if !bytes.Equal(got, tarIn) {
			t.Fatalf("server received %d stdin bytes, want the %d-byte tar byte-exact", len(got), len(tarIn))
		}
		untarAndCompare(t, got, files)
		// The pure-cat echo also proves stdout is byte-exact end to end.
		if !bytes.Equal(stdout, tarIn) {
			t.Errorf("echoed stdout %d bytes != %d-byte input tar", len(stdout), len(tarIn))
		}
	})

	// cp-out: `kubectl cp pod:src local` ⇒ `exec -- tar cf -` (tar on STDOUT). Assert
	// the captured stdout is the produced tar byte-exact, and it untars to the tree.
	t.Run("cp-out stdout tar cf -", func(t *testing.T) {
		tarOut, files := buildCpTarFixture(t, 7) // independent payload from cp-in
		f := &echoRuntime{produce: tarOut, produceStep: 48 << 10}
		r := newStreamProvider(t, f)

		stdout, _, err := runExecWithDrain(t, r, nil, []string{"tar", "cf", "-"}, timeout)
		if err != nil {
			t.Fatalf("RunInContainer: %v", err)
		}
		if !bytes.Equal(stdout, tarOut) {
			t.Fatalf("captured stdout %d bytes, want the %d-byte tar byte-exact", len(stdout), len(tarOut))
		}
		untarAndCompare(t, stdout, files)
	})

	// A non-zero `tar` exit must surface as a CodeExitError carrying the code.
	t.Run("non-zero tar exit maps to CodeExitError", func(t *testing.T) {
		tarIn, _ := buildCpTarFixture(t, 3)
		f := &echoRuntime{exitCode: 2}
		r := newStreamProvider(t, f)

		_, _, err := runExecWithDrain(t, r, bytes.NewReader(tarIn), []string{"tar", "xf", "-"}, timeout)
		var ec utilexec.CodeExitError
		if !errors.As(err, &ec) || ec.Code != 2 {
			t.Fatalf("err = %v, want CodeExitError code 2", err)
		}
	})

	// stderr must reach attach.Stderr() and must NOT pollute the stdout tar stream.
	t.Run("stderr does not pollute the stdout tar", func(t *testing.T) {
		tarOut, _ := buildCpTarFixture(t, 5)
		warn := []byte("tar: removing leading '/' from member names\n")
		f := &echoRuntime{produce: tarOut, produceStep: 48 << 10, stderrData: warn}
		r := newStreamProvider(t, f)

		stdout, stderr, err := runExecWithDrain(t, r, nil, []string{"tar", "cf", "-"}, timeout)
		if err != nil {
			t.Fatalf("RunInContainer: %v", err)
		}
		if !bytes.Equal(stderr, warn) {
			t.Errorf("stderr = %q, want the scripted warning", stderr)
		}
		if bytes.Contains(stdout, warn) {
			t.Error("stderr bytes leaked into the stdout tar stream")
		}
		if !bytes.Equal(stdout, tarOut) {
			t.Errorf("stdout tar not byte-exact with stderr present (%d vs %d bytes)", len(stdout), len(tarOut))
		}
	})
}
