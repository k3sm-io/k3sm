//go:build darwin

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

package builder

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// lockedBuffer is a bytes.Buffer safe for a concurrent copy and reads.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// TestRunBuildxPTYDrawsOnATerminalOfTheUsersSize stands a second
// pseudo-terminal in for the user's terminal. buildx (a script) must see a
// terminal on stderr, of that terminal's size, and again of its new size after
// a resize and SIGWINCH; what it prints must reach the terminal and the log.
func TestRunBuildxPTYDrawsOnATerminalOfTheUsersSize(t *testing.T) {
	userMaster, userTerm, err := openPTY()
	if err != nil {
		t.Skipf("no pseudo-terminal on this host: %v", err)
	}
	defer userMaster.Close()
	defer userTerm.Close()
	var screen lockedBuffer
	go func() { _, _ = io.Copy(&screen, userMaster) }()
	if err := unix.IoctlSetWinsize(int(userTerm.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: 33, Col: 101}); err != nil {
		t.Fatal(err)
	}

	script := filepath.Join(t.TempDir(), "fake-buildx")
	body := "#!/bin/sh\n[ -t 2 ] && echo tty >&2 || echo notty >&2\n" +
		"i=0; while [ $i -lt 60 ]; do stty -f /dev/fd/2 size >&2; i=$((i+1)); sleep 0.05; done\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	var log lockedBuffer
	done := make(chan error, 1)
	go func() { done <- RunBuildxPTY(t.Context(), script, nil, nil, io.Discard, userTerm, &log) }()

	waitFor := func(want string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !strings.Contains(log.String(), want) {
			if time.Now().After(deadline) {
				t.Fatalf("log never showed %q:\n%q", want, log.String())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitFor("33 101")
	if err := unix.IoctlSetWinsize(int(userTerm.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: 40, Col: 120}); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGWINCH); err != nil {
		t.Fatal(err)
	}
	waitFor("40 120")
	if err := <-done; err != nil {
		t.Fatalf("RunBuildxPTY: %v", err)
	}
	if !strings.HasPrefix(log.String(), "tty\r\n") {
		t.Errorf("buildx did not see a terminal on stderr: %q", log.String()[:min(20, len(log.String()))])
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(screen.String(), "40 120") {
		if time.Now().After(deadline) {
			t.Fatalf("the user's terminal did not get buildx's output: %q", screen.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
