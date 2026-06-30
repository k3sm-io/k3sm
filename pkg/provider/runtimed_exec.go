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
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/virtual-kubelet/virtual-kubelet/errdefs"
	"github.com/virtual-kubelet/virtual-kubelet/node/api"
	"google.golang.org/grpc"
	utilexec "k8s.io/utils/exec"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// M2.5 — provider-served exec/attach/port-forward. The Virtual Kubelet provider
// replaces the kubelet, so it must serve `kubectl exec`/`attach`/`port-forward`
// itself by driving the runtime/v1 Exec/Attach/PortForward bidi RPCs. These are a
// provider-implementation gap against a FROZEN apis contract (no apis change):
// runtimedRuntime wires the VK AttachIO (and the port-forward byte stream) to the
// runtime stream in-process, mirroring the watchStream/logSink adapters so the M2
// daemon split swaps the transport, not the logic.

// Compile-time check that runtimedRuntime serves the streaming verbs (M2.5).
var _ StreamingRuntime = (*runtimedRuntime)(nil)

// streamPipe is an in-process grpc.BidiStreamingServer[Req, Resp]: the runtime
// server consumes it (Recv pulls client→server frames, Send pushes server→client
// frames) while the provider drives the client side. It mirrors the in-process
// watchStream/logSink/execStream adapters so the M2 daemon split swaps it for a
// real gRPC client stream rather than a redesign.
//
// reqs carries the client frames the provider feeds (initial params, stdin,
// resize); closeSend is closed once by the stdin pump to signal CloseSend (Recv
// then returns io.EOF after reqs drains); send handles each server frame inline.
// reqs is intentionally never closed — it has multiple producers (stdin + resize)
// and termination is by ctx cancellation, avoiding any close-on-multiple-senders
// hazard.
type streamPipe[Req, Resp any] struct {
	grpc.ServerStream
	ctx       context.Context
	reqs      chan *Req
	closeSend chan struct{}
	send      func(*Resp) error
}

// Context returns the stream context (honored by the RPC for cancellation).
func (s *streamPipe[Req, Resp]) Context() context.Context { return s.ctx }

// Send delivers a server→client frame to the inline handler.
func (s *streamPipe[Req, Resp]) Send(resp *Resp) error { return s.send(resp) }

// Recv yields the next client frame, preferring a buffered frame over CloseSend so
// no frame is dropped when both are ready, then io.EOF after CloseSend, or the
// context error on cancellation.
func (s *streamPipe[Req, Resp]) Recv() (*Req, error) {
	select {
	case r := <-s.reqs:
		return r, nil
	case <-s.closeSend:
		select {
		case r := <-s.reqs:
			return r, nil
		default:
			return nil, io.EOF
		}
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}

// feed sends a client frame, reporting false if the context ended first (the RPC
// finished, so the frame is irrelevant and must not block the producer).
func (s *streamPipe[Req, Resp]) feed(r *Req) bool {
	select {
	case s.reqs <- r:
		return true
	case <-s.ctx.Done():
		return false
	}
}

// RunInContainer implements `kubectl exec` for the runtimed runtime: it resolves
// the pod, then streams the VK AttachIO over the runtime Exec RPC, returning the
// command's exit status (StreamingRuntime).
func (r *runtimedRuntime) RunInContainer(ctx context.Context, namespace, podName, container string, cmd []string, attach api.AttachIO) error {
	id, _, _, ok := r.lookup(namespace, podName)
	if !ok {
		return errdefs.NotFoundf("pod %q not found", namespace+"/"+podName)
	}
	tty := attach.TTY()
	initial := &runtimev1.ExecRequest{
		PodId:     id,
		Container: container,
		Command:   cmd,
		Tty:       tty,
		Stdin:     attach.Stdin() != nil,
		Stdout:    true,
		Stderr:    !tty, // a tty multiplexes stderr into stdout (kubelet parity)
	}
	return streamAttachIO(ctx, attach, initial,
		func(b []byte) *runtimev1.ExecRequest { return &runtimev1.ExecRequest{StdinData: b} },
		func(w, h uint32) *runtimev1.ExecRequest {
			return &runtimev1.ExecRequest{Resize: &runtimev1.TerminalSize{Width: w, Height: h}}
		},
		func(resp *runtimev1.ExecResponse) ([]byte, []byte, *runtimev1.ExecResult) {
			return resp.GetStdout(), resp.GetStderr(), resp.GetExit()
		},
		r.rt.Exec,
	)
}

// AttachToContainer implements `kubectl attach` for the runtimed runtime: it
// streams the VK AttachIO over the runtime Attach RPC (a running container's
// stdio, no command), returning the exit status (StreamingRuntime).
func (r *runtimedRuntime) AttachToContainer(ctx context.Context, namespace, podName, container string, attach api.AttachIO) error {
	id, _, _, ok := r.lookup(namespace, podName)
	if !ok {
		return errdefs.NotFoundf("pod %q not found", namespace+"/"+podName)
	}
	tty := attach.TTY()
	initial := &runtimev1.AttachRequest{
		PodId:     id,
		Container: container,
		Stdin:     attach.Stdin() != nil,
		Stdout:    true,
		Stderr:    !tty,
		Tty:       tty,
	}
	return streamAttachIO(ctx, attach, initial,
		func(b []byte) *runtimev1.AttachRequest { return &runtimev1.AttachRequest{StdinData: b} },
		func(w, h uint32) *runtimev1.AttachRequest {
			return &runtimev1.AttachRequest{Resize: &runtimev1.TerminalSize{Width: w, Height: h}}
		},
		func(resp *runtimev1.AttachResponse) ([]byte, []byte, *runtimev1.ExecResult) {
			return resp.GetStdout(), resp.GetStderr(), resp.GetExit()
		},
		r.rt.Attach,
	)
}

// PortForward implements `kubectl port-forward` for the runtimed runtime: it
// proxies the VK byte stream to a pod TCP port over the runtime PortForward RPC.
// VK invokes PortForward once per forwarded connection, so a single logical
// connection (connection_id 1) is used; an establishing frame is sent first so
// the runtime can dial the pod port before the client speaks (StreamingRuntime).
func (r *runtimedRuntime) PortForward(ctx context.Context, namespace, podName string, port int32, stream io.ReadWriteCloser) error {
	id, _, _, ok := r.lookup(namespace, podName)
	if !ok {
		return errdefs.NotFoundf("pod %q not found", namespace+"/"+podName)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	const connID = 1
	var (
		mu        sync.Mutex
		streamErr error
	)
	pipe := &streamPipe[runtimev1.PortForwardRequest, runtimev1.PortForwardResponse]{
		ctx:       ctx,
		reqs:      make(chan *runtimev1.PortForwardRequest, 16),
		closeSend: make(chan struct{}),
	}
	pipe.send = func(resp *runtimev1.PortForwardResponse) error {
		if d := resp.GetData(); len(d) > 0 {
			if _, err := stream.Write(d); err != nil {
				return err
			}
		}
		if st := resp.GetError(); st != nil && st.GetCode() != 0 {
			mu.Lock()
			streamErr = fmt.Errorf("port-forward to port %d: %s", port, st.GetMessage())
			mu.Unlock()
		}
		return nil
	}
	// Establish the connection before reading client bytes so the runtime can
	// start relaying pod→client immediately (buffered send, non-blocking).
	pipe.reqs <- &runtimev1.PortForwardRequest{PodId: id, Port: port, ConnectionId: connID}

	// Pump the client byte stream → forward frames; signal close on EOF.
	go func() {
		defer close(pipe.closeSend)
		buf := make([]byte, 32<<10)
		for {
			n, rerr := stream.Read(buf)
			if n > 0 {
				if !pipe.feed(&runtimev1.PortForwardRequest{PodId: id, Port: port, ConnectionId: connID, Data: append([]byte(nil), buf[:n]...)}) {
					return
				}
			}
			if rerr != nil {
				pipe.feed(&runtimev1.PortForwardRequest{PodId: id, Port: port, ConnectionId: connID, Close: true})
				return
			}
		}
	}()

	err := r.rt.PortForward(pipe)
	cancel() // stop the read pump
	mu.Lock()
	se := streamErr
	mu.Unlock()
	if err != nil {
		return fmt.Errorf("runtimed port-forward %s/%s:%d: %w", namespace, podName, port, err)
	}
	return se
}

// streamAttachIO wires a VK AttachIO to an in-process runtime streaming RPC (Exec
// or Attach) and runs it to completion, returning the command's exit status.
// initial is the first client frame (the exec/attach parameters); mkStdin wraps a
// stdin chunk and mkResize wraps a tty resize into the request type; outOf
// extracts stdout/stderr bytes and the terminal ExecResult from a response; invoke
// runs the RPC with the assembled stream (rt.Exec / rt.Attach).
func streamAttachIO[Req, Resp any](
	ctx context.Context,
	attach api.AttachIO,
	initial *Req,
	mkStdin func([]byte) *Req,
	mkResize func(width, height uint32) *Req,
	outOf func(*Resp) (stdout, stderr []byte, exit *runtimev1.ExecResult),
	invoke func(grpc.BidiStreamingServer[Req, Resp]) error,
) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		mu   sync.Mutex
		exit *runtimev1.ExecResult
	)
	pipe := &streamPipe[Req, Resp]{
		ctx:       ctx,
		reqs:      make(chan *Req, 16),
		closeSend: make(chan struct{}),
		send: func(resp *Resp) error {
			stdout, stderr, ex := outOf(resp)
			if len(stdout) > 0 {
				if _, err := attach.Stdout().Write(stdout); err != nil {
					return err
				}
			}
			if len(stderr) > 0 && attach.Stderr() != nil {
				if _, err := attach.Stderr().Write(stderr); err != nil {
					return err
				}
			}
			if ex != nil {
				mu.Lock()
				exit = ex
				mu.Unlock()
			}
			return nil
		},
	}
	pipe.reqs <- initial // first frame: the exec/attach parameters (buffered, non-blocking)

	go pumpClientStreams(ctx, attach, pipe, mkStdin, mkResize)

	err := invoke(pipe)
	cancel() // stop the client pump

	mu.Lock()
	ex := exit
	mu.Unlock()
	return execOutcome(ex, err)
}

// pumpClientStreams feeds a streamPipe's client side from a VK AttachIO: stdin
// chunks and tty resize events become request frames, and stdin EOF closes
// closeSend (CloseSend). It returns when stdin is exhausted, resize closes, or ctx
// is cancelled (the RPC finished). stdin's blocking Read runs in a sub-goroutine
// so it can be multiplexed with the resize channel; frames are sent under a
// ctx-guarded select so a finished RPC never blocks the pump.
func pumpClientStreams[Req, Resp any](ctx context.Context, attach api.AttachIO, pipe *streamPipe[Req, Resp], mkStdin func([]byte) *Req, mkResize func(width, height uint32) *Req) {
	stdinFrames := make(chan *Req)
	go func() {
		defer close(stdinFrames)
		stdin := attach.Stdin()
		if stdin == nil {
			return
		}
		buf := make([]byte, 32<<10)
		for {
			n, rerr := stdin.Read(buf)
			if n > 0 {
				select {
				case stdinFrames <- mkStdin(append([]byte(nil), buf[:n]...)):
				case <-ctx.Done():
					return
				}
			}
			if rerr != nil {
				return // EOF or error: no more stdin
			}
		}
	}()

	resize := attach.Resize()
	for {
		select {
		case f, ok := <-stdinFrames:
			if !ok {
				close(pipe.closeSend) // stdin exhausted ⇒ CloseSend
				return
			}
			if !pipe.feed(f) {
				return
			}
		case ts, ok := <-resize:
			if !ok {
				resize = nil // resize channel closed; stop selecting it
				continue
			}
			if mkResize != nil && !pipe.feed(mkResize(uint32(ts.Width), uint32(ts.Height))) {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

// execOutcome turns a captured ExecResult into the error the exec/attach verbs
// return: nil on a clean exit, a utilexec.CodeExitError carrying a non-zero code
// (so kubectl reports "command terminated with exit code N"), the runtime's
// structured error when the command could not run, or the stream error.
func execOutcome(exit *runtimev1.ExecResult, streamErr error) error {
	if streamErr != nil {
		return streamErr
	}
	if exit == nil {
		return errors.New("exec ended with no exit status")
	}
	if st := exit.GetError(); st != nil && st.GetCode() != 0 {
		return fmt.Errorf("exec failed: %s", st.GetMessage())
	}
	if code := exit.GetExitCode(); code != 0 {
		return utilexec.CodeExitError{Err: fmt.Errorf("command terminated with exit code %d", code), Code: int(code)}
	}
	return nil
}
