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
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ptyDrainTimeout bounds how long RunBuildxPTY waits, after buildx exits, for
// the last of its output to come off the pseudo-terminal.
const ptyDrainTimeout = 5 * time.Second

// IsTerminal reports whether f is a terminal.
func IsTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TIOCGETA)
	return err == nil
}

// RunBuildxPTY runs buildx with its stderr on a pseudo-terminal, so buildx
// draws the same interactive progress view it draws on term, and copies what it
// draws to term unchanged and to log. The pseudo-terminal takes term's size, and
// again on every SIGWINCH: buildx reads the size on each redraw, so a resized
// window redraws to fit. stdout is buildx's stdout. When no pseudo-terminal can
// be opened, buildx runs with a plain copy to term and log instead, and the
// reason is logged.
func RunBuildxPTY(ctx context.Context, bin string, args, env []string, stdout io.Writer, term *os.File, log io.Writer) error {
	sink := &bestEffortWriter{ws: []io.Writer{term, log}}
	master, slave, err := openPTY()
	if err != nil {
		slog.Warn("no pseudo-terminal for buildx; its progress prints plain", "err", err)
		return RunBuildxTo(ctx, bin, args, env, stdout, sink)
	}
	defer master.Close()

	// The raw descriptors are read once, here: the resize goroutine must not
	// call Fd() while a Close runs, and it is stopped (and waited for) before
	// either file is closed.
	termFD, masterFD := int(term.Fd()), int(master.Fd())
	resize := func() {
		if ws, err := unix.IoctlGetWinsize(termFD, unix.TIOCGWINSZ); err == nil {
			_ = unix.IoctlSetWinsize(masterFD, unix.TIOCSWINSZ, ws)
		}
	}
	resize()
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	stopResize := make(chan struct{})
	var resizing sync.WaitGroup
	resizing.Add(1)
	go func() {
		defer resizing.Done()
		for {
			select {
			case <-winch:
				resize()
			case <-stopResize:
				return
			}
		}
	}()
	defer func() {
		signal.Stop(winch)
		close(stopResize)
		resizing.Wait()
	}()

	cmd := buildxCommand(ctx, bin, args, env)
	cmd.Stdout, cmd.Stderr = stdout, slave
	copied := make(chan struct{})
	go func() {
		defer close(copied)
		_, _ = io.Copy(sink, master) // ends with EIO once no process holds the slave
	}()
	err = cmd.Start()
	// The child holds its own copy; ours must go, or the copy never sees the end.
	_ = slave.Close()
	if err == nil {
		err = cmd.Wait()
	}
	select {
	case <-copied:
	case <-time.After(ptyDrainTimeout):
	}
	return buildxRunErr(ctx, err)
}

// openPTY opens a pseudo-terminal pair with the darwin ioctls posix_openpt,
// grantpt, unlockpt and ptsname are built on, through x/sys/unix's libSystem
// wrappers.
func openPTY() (master, slave *os.File, err error) {
	mfd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open /dev/ptmx: %w", err)
	}
	m := os.NewFile(uintptr(mfd), "/dev/ptmx")
	fail := func(what string, err error) (*os.File, *os.File, error) {
		_ = m.Close()
		return nil, nil, fmt.Errorf("%s: %w", what, err)
	}
	if err := unix.IoctlSetInt(mfd, unix.TIOCPTYGRANT, 0); err != nil {
		return fail("grant the pseudo-terminal", err)
	}
	if err := unix.IoctlSetInt(mfd, unix.TIOCPTYUNLK, 0); err != nil {
		return fail("unlock the pseudo-terminal", err)
	}
	path, err := ptyName(mfd)
	if err != nil {
		return fail("name the pseudo-terminal", err)
	}
	sfd, err := unix.Open(path, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail("open "+path, err)
	}
	return m, os.NewFile(uintptr(sfd), path), nil
}

// ptyName is the slave path TIOCPTYGNAME reports, which fills a 128-byte
// buffer. x/sys/unix has no darwin wrapper for that request, and a raw
// syscall is not the supported path on darwin, so the request goes through
// the libSystem ioctl wrapper IoctlSetTermios uses: it passes only the
// pointer, and the buffer is 128 bytes and 8-byte aligned, so the kernel's
// write stays inside it whatever the size of Termios.
func ptyName(fd int) (string, error) {
	var buf [16]uint64
	if err := unix.IoctlSetTermios(fd, unix.TIOCPTYGNAME, (*unix.Termios)(unsafe.Pointer(&buf[0]))); err != nil {
		return "", err
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(&buf[0])), len(buf)*8)
	n := bytes.IndexByte(b, 0)
	if n <= 0 {
		return "", fmt.Errorf("TIOCPTYGNAME returned no name")
	}
	return string(b[:n]), nil
}

// bestEffortWriter writes every chunk to each of ws and reports success: a
// terminal that went away must not stop the copy, or buildx would block on a
// full pseudo-terminal.
type bestEffortWriter struct{ ws []io.Writer }

func (b *bestEffortWriter) Write(p []byte) (int, error) {
	for _, w := range b.ws {
		_, _ = w.Write(p)
	}
	return len(p), nil
}
