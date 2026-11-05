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
	"testing"
	"time"
)

// TestProcessExitedMonotoneAcrossReap pins that processExited never flips back to
// "running" once it has said "exited": a child observed as a zombie must still read
// exited while, and after, the reaper's wait4 removes it from the process table. A
// verdict built from two kernel reads straddling the reap answered false here.
func TestProcessExitedMonotoneAcrossReap(t *testing.T) {
	const children = 300
	for i := range children {
		cmd := exec.Command("/usr/bin/true")
		if err := cmd.Start(); err != nil {
			t.Fatalf("child %d: start: %v", i, err)
		}
		pid := cmd.Process.Pid

		deadline := time.Now().Add(5 * time.Second)
		for !processExited(pid) {
			if time.Now().After(deadline) {
				_ = cmd.Wait() // reap before failing; the verdict is the failure
				t.Fatalf("child %d (pid %d): never reported exited", i, pid)
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
