//go:build spike && darwin

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

// Command keystore-spike is the helper behind hack/acceptance/keystore-spike.sh.
// It is built only with the spike tag (so ./... never sees it), imports nothing
// beyond the standard library and golang.org/x/sys, and is never part of the
// shipped k3sm binary. Each subcommand prints one or more lines the script
// parses; it never decides a leg's verdict on its own.
//
//	attempt <name> <dir> <file>   one sappnd defeat attempt (run as the service user)
//	root-rename <dir> <file>      root renames a fresh file over the flagged target
//	root-clear <file>             root clears SF_APPEND, then reads the flags back
//	state <file>                  the file's inode, size, flags and mode
//	listen <sock> <max> <secs>    a unix listener that reports each peer's LOCAL_PEERCRED
//	dial <sock>                   a client that reports the server's LOCAL_PEERCRED
//	guid <uid> <warm-n>           mbr_uid_to_uuid, its first-call and warm latencies
package main

/*
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <membership.h>
#include <uuid/uuid.h>

static int spike_punchhole(int fd, long long off, long long len) {
	fpunchhole_t a = {0};
	a.fp_offset = off;
	a.fp_length = len;
	if (fcntl(fd, F_PUNCHHOLE, &a) == -1) {
		return errno;
	}
	return 0;
}

static int spike_uid_to_uuid(unsigned int uid, unsigned char *out) {
	uuid_t u;
	int rc = mbr_uid_to_uuid((uid_t)uid, u);
	if (rc == 0) {
		memcpy(out, u, sizeof(uuid_t));
	}
	return rc;
}
*/
import "C"

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	args := os.Args[2:]
	var err error
	switch os.Args[1] {
	case "attempt":
		need(args, 3)
		err = attempt(args[0], args[1], args[2])
	case "root-rename":
		need(args, 2)
		err = rootRename(args[0], args[1])
	case "root-clear":
		need(args, 1)
		err = rootClear(args[0])
	case "state":
		need(args, 1)
		var s fileState
		s, err = stateOf(args[0])
		if err == nil {
			fmt.Println("STATE " + s.String())
		}
	case "listen":
		need(args, 3)
		err = listen(args[0], atoi(args[1]), atoi(args[2]))
	case "dial":
		need(args, 1)
		err = dial(args[0])
	case "guid":
		need(args, 2)
		err = guid(atoi(args[0]), atoi(args[1]))
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "keystore-spike:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: keystore-spike attempt|root-rename|root-clear|state|listen|dial|guid ...")
	os.Exit(2)
}

func need(args []string, n int) {
	if len(args) != n {
		usage()
	}
}

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		usage()
	}
	return n
}

// res renders a syscall result as "ok" or the errno's name (EPERM, ENOENT, ...).
func res(err error) string {
	if err == nil {
		return "ok"
	}
	var en syscall.Errno
	if errors.As(err, &en) {
		if name := unix.ErrnoName(en); name != "" {
			return name
		}
		return "errno" + strconv.Itoa(int(en))
	}
	return strings.ReplaceAll(err.Error(), " ", "_")
}

// fileState is what the defeat check compares before and after an attempt.
type fileState struct {
	exists bool
	ino    uint64
	size   int64
	flags  uint32
	mode   uint32
	prefix [32]byte // sha256 of the first size bytes
}

func (s fileState) String() string {
	if !s.exists {
		return "absent"
	}
	return fmt.Sprintf("ino=%d,size=%d,flags=0x%x,sappnd=%t,mode=%04o", s.ino, s.size, s.flags, s.flags&unix.SF_APPEND != 0, s.mode&0o7777)
}

func stateOf(path string) (fileState, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return fileState{}, nil
		}
		return fileState{}, err
	}
	s := fileState{exists: true, ino: st.Ino, size: st.Size, flags: st.Flags, mode: uint32(st.Mode)}
	b, err := readPrefix(path, st.Size)
	if err != nil {
		return s, err
	}
	s.prefix = sha256.Sum256(b)
	return s, nil
}

func readPrefix(path string, n int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := make([]byte, n)
	if _, err := f.ReadAt(b, 0); err != nil && n > 0 {
		return nil, err
	}
	return b, nil
}

// intact reports whether after still is before's file, unwidened and unshortened:
// the same inode at the path, SF_APPEND still set, the mode unchanged, no byte of
// the original length changed. Growth past the original length is an append.
func intact(before, after fileState, path string) (bool, string) {
	switch {
	case !after.exists:
		return false, "path-gone"
	case after.ino != before.ino:
		return false, "inode-replaced"
	case after.flags&unix.SF_APPEND == 0:
		return false, "sappnd-cleared"
	case after.mode != before.mode:
		return false, fmt.Sprintf("mode-%04o-to-%04o", before.mode&0o7777, after.mode&0o7777)
	case after.size < before.size:
		return false, "shortened"
	}
	b, err := readPrefix(path, before.size)
	if err != nil {
		return false, "unreadable:" + res(err)
	}
	if sha256.Sum256(b) != before.prefix {
		return false, "prefix-changed"
	}
	return true, "intact"
}

// attempt runs one defeat attempt against file (in dir) and prints
//
//	ATTEMPT <name> <verdict> steps=<step=result;...> reason=<why> before=<state> after=<state>
//
// verdict is ok/failed for "append" (the one write that must work) and
// held/defeated for every other name: held when the file is still intact
// afterwards, whatever each syscall returned.
func attempt(name, dir, file string) error {
	before, err := stateOf(file)
	if err != nil || !before.exists {
		return fmt.Errorf("state before %s: %v (exists=%t)", file, err, before.exists)
	}
	var steps []string
	step := func(label string, err error) error {
		steps = append(steps, label+"="+res(err))
		return err
	}
	payload := []byte("spike-append\n")
	base := filepath.Base(file)
	dfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open dir: %w", err)
	}
	defer unix.Close(dfd)

	switch name {
	case "append":
		fd, err := unix.Open(file, unix.O_WRONLY|unix.O_APPEND, 0)
		if step("open(O_WRONLY|O_APPEND)", err) == nil {
			_, err = unix.Write(fd, payload)
			_ = step("write", err)
			unix.Close(fd)
		}
	case "truncate":
		_ = step("truncate(0)", unix.Truncate(file, 0))
	case "ftruncate":
		fd, err := unix.Open(file, unix.O_WRONLY|unix.O_APPEND, 0)
		if step("open(O_WRONLY|O_APPEND)", err) == nil {
			_ = step("ftruncate(0)", unix.Ftruncate(fd, 0))
			unix.Close(fd)
		}
	case "open-trunc":
		fd, err := unix.Open(file, unix.O_WRONLY|unix.O_TRUNC, 0)
		if step("open(O_WRONLY|O_TRUNC)", err) == nil {
			unix.Close(fd)
		}
		fd, err = unix.Open(file, unix.O_WRONLY|unix.O_APPEND|unix.O_TRUNC, 0)
		if step("open(O_WRONLY|O_APPEND|O_TRUNC)", err) == nil {
			unix.Close(fd)
		}
	case "pwrite":
		// A non-append descriptor first, then pwrite at offset 0 through an
		// append descriptor (the offset must not be honoured on the original bytes).
		fd, err := unix.Open(file, unix.O_RDWR, 0)
		if step("open(O_RDWR)", err) == nil {
			_, err = unix.Pwrite(fd, []byte("X"), 0)
			_ = step("pwrite(rdwr,off=0)", err)
			unix.Close(fd)
		}
		fd, err = unix.Open(file, unix.O_WRONLY|unix.O_APPEND, 0)
		if step("open(O_WRONLY|O_APPEND)", err) == nil {
			_, err = unix.Pwrite(fd, []byte("X"), 0)
			_ = step("pwrite(append,off=0)", err)
			unix.Close(fd)
		}
	case "punchhole":
		for _, flags := range []int{unix.O_RDWR, unix.O_WRONLY | unix.O_APPEND} {
			label := "open(O_RDWR)"
			if flags != unix.O_RDWR {
				label = "open(O_WRONLY|O_APPEND)"
			}
			fd, err := unix.Open(file, flags, 0)
			if step(label, err) != nil {
				continue
			}
			rc := C.spike_punchhole(C.int(fd), 0, 4096)
			var perr error
			if rc != 0 {
				perr = syscall.Errno(rc)
			}
			_ = step("fcntl(F_PUNCHHOLE,0,4096)", perr)
			unix.Close(fd)
		}
	case "link-unlink":
		link := base + ".link"
		if step("link(new-name)", unix.Linkat(dfd, base, dfd, link, 0)) == nil {
			_ = step("unlink(original)", unix.Unlinkat(dfd, base, 0))
		}
	case "clone-swap":
		clone := base + ".clone"
		fd, err := unix.Open(file, unix.O_RDONLY, 0)
		if step("open(O_RDONLY)", err) == nil {
			err = unix.Fclonefileat(fd, dfd, clone, unix.CLONE_NOFOLLOW)
			unix.Close(fd)
			if step("fclonefileat(new-name)", err) == nil {
				if cs, cerr := stateOf(filepath.Join(dir, clone)); cerr == nil {
					steps = append(steps, "clone-state="+strings.ReplaceAll(cs.String(), ",", "/"))
				}
				_ = step("rename(clone,over-original)", unix.Renameat(dfd, clone, dfd, base))
			}
		}
	case "rename-over":
		other := base + ".other"
		fd, err := unix.Openat(dfd, other, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0o600)
		if step("create(other)", err) == nil {
			unix.Close(fd)
			_ = step("rename(other,over-original)", unix.Renameat(dfd, other, dfd, base))
		}
	case "rename-away":
		_ = step("rename(original,new-name)", unix.Renameat(dfd, base, dfd, base+".moved"))
	case "unlink":
		_ = step("unlink(original)", unix.Unlinkat(dfd, base, 0))
	case "chflags-clear":
		_ = step("chflags(nosappnd)", unix.Chflags(file, int(before.flags&^unix.SF_APPEND)))
	case "chmod":
		_ = step("chmod(0644)", unix.Chmod(file, 0o644))
		_ = step("chmod(0666)", unix.Chmod(file, 0o666))
	default:
		return fmt.Errorf("unknown attempt %q", name)
	}

	after, err := stateOf(file)
	if err != nil {
		return fmt.Errorf("state after: %w", err)
	}
	ok, why := intact(before, after, file)
	verdict := "held"
	if name == "append" {
		verdict = "failed"
		if ok && after.size == before.size+int64(len(payload)) {
			verdict = "ok"
		}
	} else if !ok {
		verdict = "defeated"
	}
	fmt.Printf("ATTEMPT %s %s steps=%s reason=%s before=%s after=%s\n",
		name, verdict, strings.Join(steps, ";"), why, before, after)
	return nil
}

// rootRename creates a fresh file beside the flagged target and renames it over
// the target, as root, without clearing the flag first.
func rootRename(dir, file string) error {
	before, err := stateOf(file)
	if err != nil {
		return err
	}
	fresh := filepath.Join(dir, filepath.Base(file)+".new")
	if err := os.WriteFile(fresh, []byte("replacement\n"), 0o600); err != nil {
		return err
	}
	rerr := unix.Rename(fresh, file)
	after, err := stateOf(file)
	if err != nil {
		return err
	}
	replaced := after.exists && after.ino != before.ino
	fmt.Printf("ROOTRENAME rename=%s replaced=%t before=%s after=%s\n", res(rerr), replaced, before, after)
	return nil
}

// rootClear clears SF_APPEND as root and reads the flags back.
func rootClear(file string) error {
	before, err := stateOf(file)
	if err != nil {
		return err
	}
	cerr := unix.Chflags(file, int(before.flags&^unix.SF_APPEND))
	after, err := stateOf(file)
	if err != nil {
		return err
	}
	fmt.Printf("ROOTCLEAR chflags=%s cleared=%t before=%s after=%s\n", res(cerr), after.flags&unix.SF_APPEND == 0, before, after)
	return nil
}

// peer reads LOCAL_PEERCRED and LOCAL_PEERPID off a connected unix socket.
func peer(c *net.UnixConn) (uid uint32, groups []uint32, pid int, err error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return 0, nil, 0, err
	}
	var xerr, perr error
	cerr := rc.Control(func(fd uintptr) {
		var x *unix.Xucred
		x, xerr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if xerr == nil {
			uid = x.Uid
			groups = x.Groups[:x.Ngroups]
		}
		pid, perr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	})
	if cerr != nil {
		return 0, nil, 0, cerr
	}
	if xerr != nil {
		return 0, nil, 0, fmt.Errorf("LOCAL_PEERCRED: %w", xerr)
	}
	if perr != nil {
		pid = -1
	}
	return uid, groups, pid, nil
}

// listen serves sock until max connections were accepted (0: no limit) or secs
// elapse. Each peer gets one line back naming what the server saw; stdout gets
// one ACCEPT line per peer.
func listen(sock string, max, secs int) error {
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		return err
	}
	l.SetUnlinkOnClose(true)
	defer l.Close()
	if err := os.Chmod(sock, 0o666); err != nil {
		return err
	}
	if secs > 0 {
		_ = l.SetDeadline(time.Now().Add(time.Duration(secs) * time.Second))
	}
	fmt.Printf("LISTEN sock=%s uid=%d euid=%d pid=%d\n", sock, os.Getuid(), os.Geteuid(), os.Getpid())
	for n := 0; max == 0 || n < max; n++ {
		c, err := l.AcceptUnix()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				fmt.Println("LISTEN timeout")
				return nil
			}
			return err
		}
		uid, groups, pid, perr := peer(c)
		line := fmt.Sprintf("SERVER uid=%d pid=%d saw-euid=%d saw-pid=%d saw-groups=%v err=%s", os.Geteuid(), os.Getpid(), uid, pid, groups, res(perr))
		fmt.Println("ACCEPT " + line)
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = c.Write([]byte(line + "\n"))
		c.Close()
	}
	return nil
}

// dial connects to sock, reads the server's uid off the connected fd and the
// server's own report of what it saw.
func dial(sock string) error {
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		fmt.Printf("CLIENT uid=%d pid=%d connect=%s\n", os.Geteuid(), os.Getpid(), res(err))
		return nil
	}
	defer c.Close()
	uid, _, pid, perr := peer(c)
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	line, _ := bufio.NewReader(c).ReadString('\n')
	fmt.Printf("CLIENT uid=%d pid=%d connect=ok server-euid=%d server-pid=%d err=%s | %s\n",
		os.Geteuid(), os.Getpid(), uid, pid, res(perr), strings.TrimSpace(line))
	return nil
}

func uidToUUID(uid int) (string, error) {
	var out [16]byte
	if rc := C.spike_uid_to_uuid(C.uint(uid), (*C.uchar)(unsafe.Pointer(&out[0]))); rc != 0 {
		return "", syscall.Errno(rc)
	}
	b := out[:]
	return strings.ToUpper(fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])), nil
}

// guid resolves uid's GeneratedUID once (the process's first call, cold) and
// then warm more times, printing the value and the latencies in nanoseconds.
func guid(uid, warm int) error {
	t0 := time.Now()
	first, err := uidToUUID(uid)
	cold := time.Since(t0)
	if err != nil {
		fmt.Printf("GUID uid=%d err=%s cold_ns=%d\n", uid, res(err), cold.Nanoseconds())
		return nil
	}
	ds := make([]int64, 0, warm)
	stable := true
	for i := 0; i < warm; i++ {
		t := time.Now()
		u, err := uidToUUID(uid)
		ds = append(ds, time.Since(t).Nanoseconds())
		if err != nil || u != first {
			stable = false
		}
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	var lo, med, hi int64
	if len(ds) > 0 {
		lo, med, hi = ds[0], ds[len(ds)/2], ds[len(ds)-1]
	}
	fmt.Printf("GUID uid=%d uuid=%s stable=%t cold_ns=%d warm_n=%d warm_min_ns=%d warm_med_ns=%d warm_max_ns=%d\n",
		uid, first, stable, cold.Nanoseconds(), len(ds), lo, med, hi)
	return nil
}
