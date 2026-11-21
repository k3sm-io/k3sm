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
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/rand/v2"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/execsession"
)

// Large tar streams through `kubectl exec`. Cluster builds return their artifacts
// as `kubectl exec <pod> -- tar -cf - <dir>` piped to a local tar, and ship inputs
// the other way as `tar -xf -` on stdin. TestKubectlCpTarStreamRoundTrip proves the
// shape at 600 KiB; these tests prove the size: a 200 MiB pseudo-random tar crosses
// the provider's exec bridge (RunInContainer → streamAttachIO → streamPipe) intact in
// both directions, tail included, with exit code 0.
//
// The payload is generated on the fly from a fixed ChaCha8 seed and hashed as it
// passes, so no 200 MiB buffer or fixture exists anywhere: each side holds a frame or
// two. The expected digest is recomputed from the same seed, so "byte-identical" is a
// sha256 and length comparison against an independent generation.
//
// Two runtime doubles serve the Exec RPC. The in-process double is a pure `tar xf -`
// sink and a pure `tar cf -` producer on the runtime stream. The process double runs a
// real child process (this test binary, re-executed as a helper) through runtimed's
// execsession.Run, the stream path a native pod's exec takes, so the bytes cross real
// pipes and the child exits right after its last write: the case where a lost final
// buffered chunk would truncate the archive.

const (
	// largeStreamSize is the artifact member's size; the tar adds headers and the
	// end-of-archive trailer on top.
	largeStreamSize = 200 << 20
	// largeStreamTimeout bounds each transfer. A healthy one takes about a second
	// (a few under -race); a hang fails at the deadline instead of stalling the run.
	largeStreamTimeout = 3 * time.Minute
	// largeStreamHelperEnv selects the helper process's mode (see
	// TestExecStreamHelperProcess); unset, the helper test skips.
	largeStreamHelperEnv = "K3SM_EXEC_LARGE_STREAM_HELPER"
	// largeStreamProduceSeed is the seed the produce helper streams.
	largeStreamProduceSeed = 4
)

// writeLargeTar writes a deterministic tar to w: a size-byte ChaCha8 member seeded by
// seed, then a short tail member, then the end-of-archive trailer. Truncating any
// suffix of the stream changes its digest and length.
func writeLargeTar(w io.Writer, seed byte, size int64) error {
	var key [32]byte
	key[0] = seed
	rng := rand.NewChaCha8(key)
	tw := tar.NewWriter(w)
	if err := tw.WriteHeader(&tar.Header{Name: "build/artifact.bin", Mode: 0o644, Size: size, Typeflag: tar.TypeReg}); err != nil {
		return fmt.Errorf("artifact header: %w", err)
	}
	if _, err := io.CopyN(tw, rng, size); err != nil {
		return fmt.Errorf("artifact body: %w", err)
	}
	tail := []byte("end of artifact stream\n")
	if err := tw.WriteHeader(&tar.Header{Name: "build/TAIL", Mode: 0o644, Size: int64(len(tail)), Typeflag: tar.TypeReg}); err != nil {
		return fmt.Errorf("tail header: %w", err)
	}
	if _, err := tw.Write(tail); err != nil {
		return fmt.Errorf("tail body: %w", err)
	}
	return tw.Close()
}

// streamDigest is an io.WriteCloser that keeps only the sha256 and length of what is
// written to it. Writes may arrive on the exec goroutine, so it is mutex-guarded.
type streamDigest struct {
	mu sync.Mutex
	h  hash.Hash
	n  int64
}

func newStreamDigest() *streamDigest { return &streamDigest{h: sha256.New()} }

func (d *streamDigest) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.n += int64(len(p))
	return d.h.Write(p)
}

func (d *streamDigest) Close() error { return nil }

// result returns the hex sha256 and byte count written so far.
func (d *streamDigest) result() (string, int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return fmt.Sprintf("%x", d.h.Sum(nil)), d.n
}

// largeTarDigest is the expected hex sha256 and length of writeLargeTar(seed).
func largeTarDigest(t *testing.T, seed byte) (string, int64) {
	t.Helper()
	d := newStreamDigest()
	if err := writeLargeTar(d, seed, largeStreamSize); err != nil {
		t.Fatalf("generate expected tar: %v", err)
	}
	return d.result()
}

// largeTarReader streams writeLargeTar(seed) through a pipe, the client's stdin for
// the cp-in direction. The pipe is closed with an error when the test ends so an
// abandoned generator cannot leak.
func largeTarReader(t *testing.T, seed byte) io.Reader {
	t.Helper()
	pr, pw := io.Pipe()
	go func() { _ = pw.CloseWithError(writeLargeTar(pw, seed, largeStreamSize)) }()
	t.Cleanup(func() { _ = pr.CloseWithError(errors.New("test ended")) })
	return pr
}

// checkDigest fails the test unless the received stream matches the expected one,
// naming a short read explicitly.
func checkDigest(t *testing.T, what, gotSum string, gotN int64, wantSum string, wantN int64) {
	t.Helper()
	if gotN != wantN {
		t.Fatalf("%s: %d bytes, want %d (short by %d): the stream was truncated", what, gotN, wantN, wantN-gotN)
	}
	if gotSum != wantSum {
		t.Fatalf("%s: sha256 %s, want %s (length matches, content differs)", what, gotSum, wantSum)
	}
}

// execFuncRuntime is a runtimev1.RuntimeServer that resolves the tracked pod (via the
// embedded echoRuntime) and serves Exec with exec.
type execFuncRuntime struct {
	echoRuntime
	exec func(grpc.BidiStreamingServer[runtimev1.ExecRequest, runtimev1.ExecResponse]) error
}

func (e *execFuncRuntime) Exec(s grpc.BidiStreamingServer[runtimev1.ExecRequest, runtimev1.ExecResponse]) error {
	return e.exec(s)
}

// frameWriter turns each Write into one stdout ExecResponse frame, as a runtime's
// output pump does with each read.
type frameWriter struct {
	s grpc.BidiStreamingServer[runtimev1.ExecRequest, runtimev1.ExecResponse]
}

func (w frameWriter) Write(p []byte) (int, error) {
	if err := w.s.Send(&runtimev1.ExecResponse{Stdout: append([]byte(nil), p...)}); err != nil {
		return 0, err
	}
	return len(p), nil
}

// sinkExec is an in-process `tar xf -`: it hashes every stdin frame into rx until
// CloseSend, then exits 0 without writing stdout.
func sinkExec(rx *streamDigest) func(grpc.BidiStreamingServer[runtimev1.ExecRequest, runtimev1.ExecResponse]) error {
	return func(s grpc.BidiStreamingServer[runtimev1.ExecRequest, runtimev1.ExecResponse]) error {
		if _, err := s.Recv(); err != nil { // initial params
			return err
		}
		for {
			req, err := s.Recv()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return err
			}
			if _, err := rx.Write(req.GetStdinData()); err != nil {
				return err
			}
		}
		return s.Send(&runtimev1.ExecResponse{Exit: &runtimev1.ExecResult{ExitCode: 0}})
	}
}

// produceExec is an in-process `tar cf -`: it streams writeLargeTar(seed) as stdout
// frames, then the exit frame straight after the last one.
func produceExec(seed byte) func(grpc.BidiStreamingServer[runtimev1.ExecRequest, runtimev1.ExecResponse]) error {
	return func(s grpc.BidiStreamingServer[runtimev1.ExecRequest, runtimev1.ExecResponse]) error {
		if _, err := s.Recv(); err != nil { // initial params
			return err
		}
		if err := writeLargeTar(frameWriter{s}, seed, largeStreamSize); err != nil {
			return err
		}
		return s.Send(&runtimev1.ExecResponse{Exit: &runtimev1.ExecResult{ExitCode: 0}})
	}
}

// processExec runs the helper process in mode through runtimed's execsession.Run.
func processExec(t *testing.T, mode string) func(grpc.BidiStreamingServer[runtimev1.ExecRequest, runtimev1.ExecResponse]) error {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locate the test binary: %v", err)
	}
	return func(s grpc.BidiStreamingServer[runtimev1.ExecRequest, runtimev1.ExecResponse]) error {
		first, err := s.Recv()
		if err != nil {
			return err
		}
		cmd := exec.CommandContext(s.Context(), self, "-test.run=^TestExecStreamHelperProcess$")
		cmd.Env = append(os.Environ(), largeStreamHelperEnv+"="+mode)
		return execsession.Run(s, cmd, first.GetTty(), first.GetStdin(), nil)
	}
}

// runLargeExec runs RunInContainer with the given stdin and stdout under
// largeStreamTimeout, returning the captured stderr and its error.
func runLargeExec(t *testing.T, r *runtimedRuntime, stdin io.Reader, stdout io.WriteCloser, cmd []string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), largeStreamTimeout)
	defer cancel()
	stderr := &syncBuffer{}
	attach := &cpAttachIO{stdin: stdin, stdout: stdout, stderr: stderr}
	done := make(chan error, 1)
	go func() { done <- r.RunInContainer(ctx, "default", "web", "c0", cmd, attach) }()
	select {
	case err := <-done:
		return stderr.String(), err
	case <-ctx.Done():
		t.Fatalf("timeout: RunInContainer(%v) did not return within %v", cmd, largeStreamTimeout)
		return "", nil
	}
}

// TestExecLargeStream is the B1860 gate: a 200 MiB pseudo-random tar crosses
// `kubectl exec` byte-identical (sha256 and length) in through stdin and back out
// through stdout, tail at stream close included, and the exec exits 0. A short read
// in either direction fails it.
func TestExecLargeStream(t *testing.T) {
	cases := []struct {
		name string
		cmd  []string
		// in is the seed streamed on stdin (0: no stdin); the runtime must receive it.
		in byte
		// out is the seed the runtime streams on stdout (0: none); the client must
		// receive it.
		out byte
		// runtime builds the Exec double; rx collects what an in-process sink receives.
		runtime func(t *testing.T, rx *streamDigest) func(grpc.BidiStreamingServer[runtimev1.ExecRequest, runtimev1.ExecResponse]) error
		// process marks a child-process double, which reports the stdin it received
		// on stdout as "<sha256> <length>" instead of through rx.
		process bool
	}{
		{
			name: "stdin tar xf - into the runtime stream",
			cmd:  []string{"tar", "-xf", "-"},
			in:   1,
			runtime: func(_ *testing.T, rx *streamDigest) func(grpc.BidiStreamingServer[runtimev1.ExecRequest, runtimev1.ExecResponse]) error {
				return sinkExec(rx)
			},
		},
		{
			name: "stdout tar cf - from the runtime stream",
			cmd:  []string{"tar", "-cf", "-", "build"},
			out:  2,
			runtime: func(_ *testing.T, _ *streamDigest) func(grpc.BidiStreamingServer[runtimev1.ExecRequest, runtimev1.ExecResponse]) error {
				return produceExec(2)
			},
		},
		{
			name: "stdin tar xf - into a process via execsession",
			cmd:  []string{"tar", "-xf", "-"},
			in:   3,
			runtime: func(t *testing.T, _ *streamDigest) func(grpc.BidiStreamingServer[runtimev1.ExecRequest, runtimev1.ExecResponse]) error {
				return processExec(t, "sink")
			},
			process: true,
		},
		{
			name: "stdout tar cf - from a process via execsession",
			cmd:  []string{"tar", "-cf", "-", "build"},
			out:  largeStreamProduceSeed,
			runtime: func(t *testing.T, _ *streamDigest) func(grpc.BidiStreamingServer[runtimev1.ExecRequest, runtimev1.ExecResponse]) error {
				return processExec(t, "produce")
			},
			process: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rx := newStreamDigest()
			r := newStreamProvider(t, &execFuncRuntime{exec: tc.runtime(t, rx)})

			var stdin io.Reader
			if tc.in != 0 {
				stdin = largeTarReader(t, tc.in)
			}
			stdoutDigest := newStreamDigest()
			var report syncBuffer // a sink process's "<sha256> <length>" line
			var stdout io.WriteCloser = stdoutDigest
			if tc.process && tc.in != 0 {
				stdout = &report
			}

			stderr, err := runLargeExec(t, r, stdin, stdout, tc.cmd)
			if err != nil {
				t.Fatalf("RunInContainer: %v (want exit 0; stderr %q)", err, stderr)
			}
			if stderr != "" {
				t.Errorf("stderr = %q, want none", stderr)
			}

			if tc.in != 0 {
				wantSum, wantN := largeTarDigest(t, tc.in)
				gotSum, gotN := rx.result()
				if tc.process {
					if _, serr := fmt.Sscanf(report.String(), "%s %d", &gotSum, &gotN); serr != nil {
						t.Fatalf("sink process report %q: %v", report.String(), serr)
					}
				}
				checkDigest(t, "runtime received on stdin", gotSum, gotN, wantSum, wantN)
			}
			if tc.out != 0 {
				wantSum, wantN := largeTarDigest(t, tc.out)
				gotSum, gotN := stdoutDigest.result()
				checkDigest(t, "client received on stdout", gotSum, gotN, wantSum, wantN)
			}
		})
	}
}

// TestExecStreamHelperProcess is the child process TestExecLargeStream's process
// double runs; it skips unless largeStreamHelperEnv names a mode. "sink" reads stdin
// to EOF and prints "<sha256> <length>"; "produce" writes the largeStreamProduceSeed
// tar to stdout and exits at once after the last byte.
func TestExecStreamHelperProcess(t *testing.T) {
	mode := os.Getenv(largeStreamHelperEnv)
	if mode == "" {
		t.Skip("helper process for TestExecLargeStream")
	}
	switch mode {
	case "sink":
		d := newStreamDigest()
		if _, err := io.Copy(d, os.Stdin); err != nil {
			fmt.Fprintf(os.Stderr, "read stdin: %v\n", err)
			os.Exit(3)
		}
		sum, n := d.result()
		fmt.Fprintf(os.Stdout, "%s %d\n", sum, n)
	case "produce":
		if err := writeLargeTar(os.Stdout, largeStreamProduceSeed, largeStreamSize); err != nil {
			fmt.Fprintf(os.Stderr, "write stdout: %v\n", err)
			os.Exit(3)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown helper mode %q\n", mode)
		os.Exit(2)
	}
	os.Exit(0)
}
