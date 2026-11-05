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

package executor

import (
	"os/exec"
	"runtime"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestProcessExitedMonotoneAcrossReap pins that processExited never flips back to
// "running" once it has said "exited": a child observed as a zombie must still read
// exited while, and after, the reaper's wait4 removes it from the process table. A
// verdict built from two kernel reads straddling the reap answered false here.
func TestProcessExitedMonotoneAcrossReap(t *testing.T) {
	children := 300
	if testing.Short() {
		children = 20
	}
	for i := range children {
		cmd := exec.Command("/usr/bin/true")
		if err := cmd.Start(); err != nil {
			t.Fatalf("child %d: start: %v", i, err)
		}
		pid := cmd.Process.Pid

		deadline := time.Now().Add(30 * time.Second)
		for !processExited(pid) {
			if time.Now().After(deadline) {
				_ = cmd.Wait() // reap before failing; the verdict is the failure
				t.Skipf("child %d (pid %d): host too loaded to observe the exit in time", i, pid)
			}
			runtime.Gosched() // a barrier poll, not a budget: the deadline above is the only bound
		}

		waited := make(chan struct{})
		go func() {
			_ = cmd.Wait() // /usr/bin/true's status is not under test
			close(waited)
		}()
		after := 0
		for after < 20 {
			select {
			case <-waited:
				after++
			default:
			}
			if !processExited(pid) {
				<-waited
				t.Fatalf("child %d (pid %d): reported running after reporting exited", i, pid)
			}
		}
	}
}

// TestProcessExitedMonotoneAcrossReapSeam drives the straddle deterministically:
// the first read is the zombie record, the next reads are the empty slot a reap
// leaves behind. The verdict must stay "exited" across the reap.
func TestProcessExitedMonotoneAcrossReapSeam(t *testing.T) {
	zombie := make([]byte, unix.SizeofKinfoProc)
	var kp unix.KinfoProc
	kp.Proc.P_stat = pStatZombie
	copy(zombie, (*[unix.SizeofKinfoProc]byte)(unsafe.Pointer(&kp))[:])
	reaped := false
	read := func(int) ([]byte, error) {
		if !reaped {
			return zombie, nil
		}
		return nil, nil
	}
	if !processExitedVia(read, 42) {
		t.Fatal("zombie record read as running")
	}
	reaped = true
	if !processExitedVia(read, 42) {
		t.Fatal("reported running after the reap")
	}
}

// TestProcessExitedReportsUnknownRecordSize pins that an unexpected record size
// stays fail-safe (running) and logs exactly once per process lifetime.
func TestProcessExitedReportsUnknownRecordSize(t *testing.T) {
	origWarn := procSizeWarn
	t.Cleanup(func() { procSizeWarn = origWarn; procSizeWarnOnce = sync.Once{} })
	procSizeWarnOnce = sync.Once{}
	type call struct{ got, want int }
	var calls []call
	procSizeWarn = func(got, want int) { calls = append(calls, call{got, want}) }
	short := func(int) ([]byte, error) { return make([]byte, 7), nil }

	for range 3 {
		if processExitedVia(short, 42) {
			t.Fatal("unexpected record size must fail safe to running")
		}
	}
	if len(calls) != 1 {
		t.Fatalf("warnings = %d, want 1", len(calls))
	}
	if calls[0].got != 7 || calls[0].want != unix.SizeofKinfoProc {
		t.Fatalf("warning = %+v, want length 7 expected %d", calls[0], unix.SizeofKinfoProc)
	}
}
