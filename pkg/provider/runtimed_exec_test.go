package provider

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/virtual-kubelet/virtual-kubelet/node/api"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	utilexec "k8s.io/utils/exec"

	runtimev1 "k3sm.io/apis/runtime/v1"
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

// fakeAttachIO is a VK api.AttachIO over in-memory streams for the exec/attach
// tests.
type fakeAttachIO struct {
	stdin  io.Reader
	stdout *syncBuffer
	stderr *syncBuffer
	tty    bool
	resize chan api.TermSize
}

func (f *fakeAttachIO) Stdin() io.Reader            { return f.stdin }
func (f *fakeAttachIO) Stdout() io.WriteCloser      { return f.stdout }
func (f *fakeAttachIO) Stderr() io.WriteCloser      { return f.stderr }
func (f *fakeAttachIO) TTY() bool                   { return f.tty }
func (f *fakeAttachIO) Resize() <-chan api.TermSize { return f.resize }

// newStreamProvider builds a runtimedRuntime over f with one tracked pod ("web"
// in "default") so the streaming verbs resolve it.
func newStreamProvider(t *testing.T, f *fakeStreamRuntime) *runtimedRuntime {
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
