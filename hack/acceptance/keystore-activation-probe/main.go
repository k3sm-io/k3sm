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

// Command keystore-activation-probe measures whether the keystore's non-root
// socket listener can ship with launchd socket activation or must bind its own
// socket. It is the helper behind run.sh in this directory. Like keystore-spike
// it is built only with the spike tag (so ./... never sees it), imports nothing
// beyond the standard library and golang.org/x/sys, links only system
// frameworks (Security, CoreFoundation, libSystem, libbsm), and is never part
// of the shipped k3sm binary. Every subcommand prints JSON lines; none decides
// a verdict.
//
//	serve --activated <name> | --self-bind <path> [--n N] [--timeout S] [--child-grab before|after|both]
//	connect <path>
//	grab <name>
//
// Symbols used that no public SDK header declares, or that are deprecated:
//
//	sandbox_check_by_audit_token, sandbox_check  private; exported by
//	    /usr/lib/system/libsystem_sandbox.dylib (listed in the SDK's
//	    usr/lib/system/libsystem_sandbox.tbd), declared below by hand in the
//	    form Apple's own SPI headers use:
//	    int sandbox_check_by_audit_token(audit_token_t, const char *, enum sandbox_filter_type, ...);
//	    with operation NULL and SANDBOX_FILTER_NONE (0) the call asks only
//	    "is this process sandboxed": 1 yes, 0 no, -1 error (errno).
//	launch_activate_socket  public, <launch.h> (macOS 10.10+); the rest of
//	    launch.h is deprecated, this function is not.
//	LOCAL_PEERTOKEN  public, <sys/un.h> (0x006), read with getsockopt(SOL_LOCAL).
//	SecCodeCopyGuestWithAttributes + kSecGuestAttributeAudit,
//	SecCodeCopySigningInformation  public, <Security/SecCode.h>.
//	audit_token_to_{pid,euid,ruid,pidversion}  public, <bsm/libbsm.h> (-lbsm).
package main

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation -lbsm
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <launch.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <bsm/libbsm.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

// Private SPI from libsystem_sandbox (no SDK header). enum sandbox_filter_type
// is int-sized; SANDBOX_FILTER_NONE is 0.
extern int sandbox_check_by_audit_token(audit_token_t token, const char *operation, int type, ...);
extern int sandbox_check(pid_t pid, const char *operation, int type, ...);

static int probe_activate(const char *name, int **fds, size_t *cnt) {
	return launch_activate_socket(name, fds, cnt);
}

static int probe_fd_at(int *fds, size_t i) { return fds[i]; }

static int probe_peertoken(int fd, audit_token_t *tok) {
	socklen_t len = sizeof(*tok);
	if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, tok, &len) != 0) {
		return errno;
	}
	if (len != sizeof(*tok)) {
		return EINVAL;
	}
	return 0;
}

static void probe_token_fields(audit_token_t *tok, int *pid, int *euid, int *ruid, int *pidver) {
	*pid = (int)audit_token_to_pid(*tok);
	*euid = (int)audit_token_to_euid(*tok);
	*ruid = (int)audit_token_to_ruid(*tok);
	*pidver = audit_token_to_pidversion(*tok);
}

static int probe_sandbox_token(audit_token_t *tok, int *err) {
	errno = 0;
	int rc = sandbox_check_by_audit_token(*tok, NULL, 0);
	*err = errno;
	return rc;
}

static int probe_sandbox_pid(int pid, int *err) {
	errno = 0;
	int rc = sandbox_check((pid_t)pid, NULL, 0);
	*err = errno;
	return rc;
}

typedef struct {
	OSStatus guest;
	OSStatus info;
	int has_flags;
	uint32_t flags;
	int has_status;
	uint32_t status;
	char ident[512];
	char team[128];
	char cdhash[129];
	char path[1024];
} probe_code;

static void probe_cfstr(CFTypeRef v, char *buf, size_t n) {
	buf[0] = 0;
	if (v != NULL && CFGetTypeID(v) == CFStringGetTypeID()) {
		CFStringGetCString((CFStringRef)v, buf, (CFIndex)n, kCFStringEncodingUTF8);
	}
}

static int probe_cfu32(CFTypeRef v, uint32_t *out) {
	if (v != NULL && CFGetTypeID(v) == CFNumberGetTypeID()) {
		long long x = 0;
		if (CFNumberGetValue((CFNumberRef)v, kCFNumberLongLongType, &x)) {
			*out = (uint32_t)x;
			return 1;
		}
	}
	return 0;
}

static void probe_code_lookup(audit_token_t *tok, probe_code *out) {
	memset(out, 0, sizeof(*out));
	CFDataRef d = CFDataCreate(NULL, (const UInt8 *)tok, sizeof(*tok));
	const void *k[] = {kSecGuestAttributeAudit};
	const void *v[] = {d};
	CFDictionaryRef attrs = CFDictionaryCreate(NULL, k, v, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	SecCodeRef code = NULL;
	out->guest = SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, &code);
	CFRelease(attrs);
	CFRelease(d);
	if (out->guest != errSecSuccess || code == NULL) {
		return;
	}
	CFDictionaryRef info = NULL;
	out->info = SecCodeCopySigningInformation((SecStaticCodeRef)code,
		kSecCSSigningInformation | kSecCSDynamicInformation, &info);
	if (out->info == errSecSuccess && info != NULL) {
		probe_cfstr(CFDictionaryGetValue(info, kSecCodeInfoIdentifier), out->ident, sizeof(out->ident));
		probe_cfstr(CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier), out->team, sizeof(out->team));
		out->has_flags = probe_cfu32(CFDictionaryGetValue(info, kSecCodeInfoFlags), &out->flags);
		out->has_status = probe_cfu32(CFDictionaryGetValue(info, kSecCodeInfoStatus), &out->status);
		CFTypeRef u = CFDictionaryGetValue(info, kSecCodeInfoUnique);
		if (u != NULL && CFGetTypeID(u) == CFDataGetTypeID()) {
			CFIndex n = CFDataGetLength((CFDataRef)u);
			const UInt8 *p = CFDataGetBytePtr((CFDataRef)u);
			for (CFIndex i = 0; i < n && i < 64; i++) {
				snprintf(out->cdhash + 2 * i, 3, "%02x", p[i]);
			}
		}
		CFTypeRef m = CFDictionaryGetValue(info, kSecCodeInfoMainExecutable);
		if (m != NULL && CFGetTypeID(m) == CFURLGetTypeID()) {
			CFURLGetFileSystemRepresentation((CFURLRef)m, true, (UInt8 *)out->path, sizeof(out->path));
		}
	}
	if (info != NULL) {
		CFRelease(info);
	}
	CFRelease(code);
}

static void probe_osstatus_message(OSStatus st, char *buf, size_t n) {
	buf[0] = 0;
	CFStringRef s = SecCopyErrorMessageString(st, NULL);
	if (s != NULL) {
		CFStringGetCString(s, buf, (CFIndex)n, kCFStringEncodingUTF8);
		CFRelease(s);
	}
}
*/
import "C"

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
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
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "connect":
		if len(os.Args) != 3 {
			usage()
		}
		err = connect(os.Args[2])
	case "grab":
		if len(os.Args) != 3 {
			usage()
		}
		emit(grab(os.Args[2]))
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "keystore-activation-probe:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: keystore-activation-probe serve (--activated <name> | --self-bind <path>) [--n N] [--timeout S] [--child-grab before|after|both]")
	fmt.Fprintln(os.Stderr, "       keystore-activation-probe connect <path>")
	fmt.Fprintln(os.Stderr, "       keystore-activation-probe grab <name>")
	os.Exit(2)
}

// emit prints v as one JSON line.
func emit(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		b = []byte(fmt.Sprintf(`{"event":"marshal-error","err":%q}`, err.Error()))
	}
	fmt.Println(string(b))
}

// errName renders an error as "ok" or the errno's name (EPERM, ENOENT, ...).
func errName(err error) string {
	if err == nil {
		return "ok"
	}
	var en syscall.Errno
	if errors.As(err, &en) {
		return errnoName(int(en))
	}
	return err.Error()
}

func errnoName(n int) string {
	if n == 0 {
		return "ok"
	}
	if name := unix.ErrnoName(syscall.Errno(n)); name != "" {
		return name
	}
	return "errno" + strconv.Itoa(n)
}

type self struct {
	Euid int `json:"euid"`
	Uid  int `json:"uid"`
	Egid int `json:"egid"`
	Pid  int `json:"pid"`
	Ppid int `json:"ppid"`
}

func whoami() self {
	return self{Euid: os.Geteuid(), Uid: os.Getuid(), Egid: os.Getegid(), Pid: os.Getpid(), Ppid: os.Getppid()}
}

type statView struct {
	Err  string `json:"err"`
	Uid  int64  `json:"uid"`
	Gid  int64  `json:"gid"`
	Mode string `json:"mode,omitempty"`
	Type string `json:"type,omitempty"`
	Ino  uint64 `json:"ino,omitempty"`
}

func fileType(m uint16) string {
	switch m & unix.S_IFMT {
	case unix.S_IFSOCK:
		return "socket"
	case unix.S_IFREG:
		return "file"
	case unix.S_IFDIR:
		return "dir"
	case unix.S_IFLNK:
		return "symlink"
	case unix.S_IFIFO:
		return "fifo"
	case unix.S_IFCHR:
		return "char"
	}
	return fmt.Sprintf("0%o", m&unix.S_IFMT)
}

func viewStat(st *unix.Stat_t, err error) statView {
	if err != nil {
		return statView{Err: errName(err), Uid: -1, Gid: -1}
	}
	return statView{Err: "ok", Uid: int64(st.Uid), Gid: int64(st.Gid), Mode: fmt.Sprintf("%04o", st.Mode&0o7777), Type: fileType(st.Mode), Ino: st.Ino}
}

func fstatOf(fd int) statView {
	var st unix.Stat_t
	err := unix.Fstat(fd, &st)
	return viewStat(&st, err)
}

func lstatOf(path string) statView {
	var st unix.Stat_t
	err := unix.Lstat(path, &st)
	return viewStat(&st, err)
}

// sockPath returns the bound path of a unix socket descriptor.
func sockPath(fd int) (string, string) {
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return "", errName(err)
	}
	if u, ok := sa.(*unix.SockaddrUnix); ok {
		return u.Name, "ok"
	}
	return "", fmt.Sprintf("not-unix:%T", sa)
}

type tokenView struct {
	Read       bool   `json:"read"`
	Err        string `json:"err"`
	Pid        int    `json:"pid"`
	Euid       int    `json:"euid"`
	Ruid       int    `json:"ruid"`
	Pidversion int    `json:"pidversion,omitempty"`
}

type sandboxView struct {
	Symbol  string `json:"symbol"`
	RC      int    `json:"rc"`
	Errno   string `json:"errno"`
	Meaning string `json:"meaning"`
}

func sandboxMeaning(rc int) string {
	switch rc {
	case 0:
		return "not-sandboxed"
	case 1:
		return "sandboxed"
	}
	return "error"
}

type codeView struct {
	Symbol        string `json:"symbol"`
	GuestStatus   int32  `json:"guest_osstatus"`
	GuestMessage  string `json:"guest_message,omitempty"`
	InfoStatus    int32  `json:"info_osstatus,omitempty"`
	InfoMessage   string `json:"info_message,omitempty"`
	Identifier    string `json:"identifier,omitempty"`
	Team          string `json:"team,omitempty"`
	Flags         string `json:"flags,omitempty"`
	DynamicStatus string `json:"dynamic_status,omitempty"`
	Cdhash        string `json:"cdhash,omitempty"`
	Path          string `json:"path,omitempty"`
}

func osMessage(st C.OSStatus) string {
	var buf [512]C.char
	C.probe_osstatus_message(st, &buf[0], C.size_t(len(buf)))
	return C.GoString(&buf[0])
}

func codeOf(tok *C.audit_token_t) *codeView {
	var c C.probe_code
	C.probe_code_lookup(tok, &c)
	v := &codeView{
		Symbol:      "SecCodeCopyGuestWithAttributes(NULL,{kSecGuestAttributeAudit}) + SecCodeCopySigningInformation(kSecCSSigningInformation|kSecCSDynamicInformation)",
		GuestStatus: int32(c.guest),
	}
	if c.guest != 0 {
		v.GuestMessage = osMessage(c.guest)
		return v
	}
	v.InfoStatus = int32(c.info)
	if c.info != 0 {
		v.InfoMessage = osMessage(c.info)
		return v
	}
	v.Identifier = C.GoString(&c.ident[0])
	v.Team = C.GoString(&c.team[0])
	if c.has_flags != 0 {
		v.Flags = fmt.Sprintf("0x%x", uint32(c.flags))
		// kSecCodeSignatureAdhoc is 0x2.
		if v.Team == "" && uint32(c.flags)&0x2 != 0 {
			v.Team = "adhoc"
		}
	}
	if c.has_status != 0 {
		v.DynamicStatus = fmt.Sprintf("0x%x", uint32(c.status))
	}
	v.Cdhash = C.GoString(&c.cdhash[0])
	v.Path = C.GoString(&c.path[0])
	return v
}

// peerView is what one end of a connected unix socket learns about the other.
type peerView struct {
	CredErr      string       `json:"cred_err"`
	Euid         int64        `json:"euid"`
	Gid          int64        `json:"gid"`
	Groups       []uint32     `json:"groups,omitempty"`
	PidErr       string       `json:"pid_err"`
	Pid          int          `json:"pid"`
	Token        tokenView    `json:"token"`
	SandboxToken *sandboxView `json:"sandbox_token,omitempty"`
	SandboxPid   *sandboxView `json:"sandbox_pid,omitempty"`
	Code         *codeView    `json:"code,omitempty"`
}

func peerOf(fd int) peerView {
	p := peerView{Euid: -1, Gid: -1, Pid: -1}
	x, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	p.CredErr = errName(err)
	if err == nil {
		p.Euid = int64(x.Uid)
		if x.Ngroups > 0 {
			p.Gid = int64(x.Groups[0])
			p.Groups = append([]uint32(nil), x.Groups[:x.Ngroups]...)
		}
	}
	pid, err := unix.GetsockoptInt(fd, unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	p.PidErr = errName(err)
	if err == nil {
		p.Pid = pid
	}
	if p.Pid > 0 {
		var e C.int
		rc := int(C.probe_sandbox_pid(C.int(p.Pid), &e))
		p.SandboxPid = &sandboxView{Symbol: "sandbox_check(pid,NULL,SANDBOX_FILTER_NONE)", RC: rc, Errno: errnoName(int(e)), Meaning: sandboxMeaning(rc)}
	}
	var tok C.audit_token_t
	if rc := int(C.probe_peertoken(C.int(fd), &tok)); rc != 0 {
		p.Token = tokenView{Err: errnoName(rc), Pid: -1, Euid: -1, Ruid: -1}
		return p
	}
	var tpid, teuid, truid, tver C.int
	C.probe_token_fields(&tok, &tpid, &teuid, &truid, &tver)
	p.Token = tokenView{Read: true, Err: "ok", Pid: int(tpid), Euid: int(teuid), Ruid: int(truid), Pidversion: int(tver)}
	var e C.int
	rc := int(C.probe_sandbox_token(&tok, &e))
	p.SandboxToken = &sandboxView{Symbol: "sandbox_check_by_audit_token(token,NULL,SANDBOX_FILTER_NONE)", RC: rc, Errno: errnoName(int(e)), Meaning: sandboxMeaning(rc)}
	p.Code = codeOf(&tok)
	return p
}

func connFD(c *net.UnixConn) (int, func(), error) {
	f, err := c.File() // a dup; closed by the returned func
	if err != nil {
		return -1, func() {}, err
	}
	return int(f.Fd()), func() { f.Close() }, nil
}

// ---- grab ------------------------------------------------------------------

type grabView struct {
	Event  string     `json:"event"`
	Name   string     `json:"name"`
	Symbol string     `json:"symbol"`
	Self   self       `json:"self"`
	RC     int        `json:"rc"`
	Errno  string     `json:"errno"`
	Count  int        `json:"count"`
	FDs    []fdReport `json:"fds,omitempty"`
}

type fdReport struct {
	FD         int      `json:"fd"`
	CloexecWas bool     `json:"cloexec_was"`
	Fstat      statView `json:"fstat"`
	Path       string   `json:"path,omitempty"`
	PathErr    string   `json:"path_err"`
	Lstat      statView `json:"lstat"`
}

func describeFD(fd int) fdReport {
	r := fdReport{FD: fd}
	if fl, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil {
		r.CloexecWas = fl&unix.FD_CLOEXEC != 0
	}
	r.Fstat = fstatOf(fd)
	r.Path, r.PathErr = sockPath(fd)
	if r.Path != "" {
		r.Lstat = lstatOf(r.Path)
	}
	return r
}

// activate calls launch_activate_socket and returns the descriptors it got.
func activate(name string) (int, []int) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	var fds *C.int
	var cnt C.size_t
	rc := int(C.probe_activate(cname, &fds, &cnt))
	var out []int
	if rc == 0 && fds != nil {
		for i := 0; i < int(cnt); i++ {
			out = append(out, int(C.probe_fd_at(fds, C.size_t(i))))
		}
		C.free(unsafe.Pointer(fds))
	}
	return rc, out
}

func grab(name string) grabView {
	rc, fds := activate(name)
	g := grabView{Event: "grab", Name: name, Symbol: "launch_activate_socket", Self: whoami(), RC: rc, Errno: errnoName(rc), Count: len(fds)}
	for _, fd := range fds {
		g.FDs = append(g.FDs, describeFD(fd))
		unix.Close(fd)
	}
	return g
}

// ---- serve -----------------------------------------------------------------

type listenView struct {
	Event    string      `json:"event"`
	Form     string      `json:"form"`
	Name     string      `json:"name,omitempty"`
	Self     self        `json:"self"`
	Activate *grabView   `json:"activate,omitempty"`
	BindErr  string      `json:"bind_err,omitempty"`
	ChmodErr string      `json:"chmod_err,omitempty"`
	Listen   *fdReport   `json:"listen_fd,omitempty"`
	Cloexec  string      `json:"cloexec_set,omitempty"`
	Children []childView `json:"child_grab,omitempty"`
}

type childView struct {
	When   string          `json:"when"`
	Setsid bool            `json:"setsid"`
	Err    string          `json:"err"`
	Line   json.RawMessage `json:"line,omitempty"`
	Raw    string          `json:"raw,omitempty"`
}

// childGrab runs "grab <name>" as a child of this process (a descendant of the
// launchd job when serve runs under launchd), once in this session and once
// after setsid, and returns what each child got.
func childGrab(when, name string) []childView {
	exe, err := os.Executable()
	if err != nil {
		return []childView{{When: when, Err: errName(err)}}
	}
	var out []childView
	for _, setsid := range []bool{false, true} {
		cmd := exec.Command(exe, "grab", name)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: setsid}
		b, err := cmd.Output()
		v := childView{When: when, Setsid: setsid, Err: errName(err)}
		line := strings.TrimSpace(string(b))
		if json.Valid([]byte(line)) && line != "" {
			v.Line = json.RawMessage(line)
		} else {
			v.Raw = line
		}
		out = append(out, v)
	}
	return out
}

type acceptView struct {
	Event  string   `json:"event"`
	Form   string   `json:"form"`
	N      int      `json:"n"`
	Server self     `json:"server"`
	Peer   peerView `json:"peer"`
	FDErr  string   `json:"fd_err,omitempty"`
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	activated := fs.String("activated", "", "launchd Sockets entry name to take with launch_activate_socket")
	selfBind := fs.String("self-bind", "", "socket path to bind and listen on instead")
	n := fs.Int("n", 1, "connections to serve before exiting (0: until the timeout)")
	timeout := fs.Int("timeout", 300, "seconds to wait for connections before exiting")
	childGrabWhen := fs.String("child-grab", "", "run 'grab <name>' as a child: before, after or both (activated form only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if (*activated == "") == (*selfBind == "") || fs.NArg() != 0 || *n < 0 || *timeout <= 0 {
		usage()
	}
	switch *childGrabWhen {
	case "", "before", "after", "both":
	default:
		usage()
	}

	lv := listenView{Event: "listen", Self: whoami()}
	var lfd int
	if *activated != "" {
		lv.Form = "activated"
		lv.Name = *activated
		if *childGrabWhen == "before" || *childGrabWhen == "both" {
			lv.Children = append(lv.Children, childGrab("before", *activated)...)
		}
		rc, fds := activate(*activated)
		g := grabView{Event: "activate", Name: *activated, Symbol: "launch_activate_socket", Self: lv.Self, RC: rc, Errno: errnoName(rc), Count: len(fds)}
		for _, fd := range fds {
			g.FDs = append(g.FDs, describeFD(fd))
		}
		lv.Activate = &g
		if len(fds) == 0 {
			emit(lv)
			return fmt.Errorf("launch_activate_socket(%q): %s, %d descriptors", *activated, errnoName(rc), len(fds))
		}
		for _, fd := range fds {
			// Open requirement 3: the listener reaches no child.
			unix.CloseOnExec(fd)
		}
		lfd = fds[0]
		for _, fd := range fds[1:] {
			unix.Close(fd)
		}
		if fl, err := unix.FcntlInt(uintptr(lfd), unix.F_GETFD, 0); err != nil {
			lv.Cloexec = errName(err)
		} else {
			lv.Cloexec = strconv.FormatBool(fl&unix.FD_CLOEXEC != 0)
		}
		if *childGrabWhen == "after" || *childGrabWhen == "both" {
			lv.Children = append(lv.Children, childGrab("after", *activated)...)
		}
	} else {
		lv.Form = "self-bind"
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		if err != nil {
			return err
		}
		unix.CloseOnExec(fd)
		err = unix.Bind(fd, &unix.SockaddrUnix{Name: *selfBind})
		lv.BindErr = errName(err)
		if err == nil {
			err = unix.Listen(fd, 16)
			if err != nil {
				lv.BindErr = "listen:" + errName(err)
			}
		}
		if err != nil {
			emit(lv)
			unix.Close(fd)
			return fmt.Errorf("bind %s: %w", *selfBind, err)
		}
		defer os.Remove(*selfBind)
		lv.ChmodErr = errName(unix.Chmod(*selfBind, 0o666))
		lfd = fd
	}
	r := describeFD(lfd)
	lv.Listen = &r
	emit(lv)

	f := os.NewFile(uintptr(lfd), "listener")
	ln, err := net.FileListener(f) // dups lfd
	f.Close()
	if err != nil {
		return fmt.Errorf("FileListener: %w", err)
	}
	ul, ok := ln.(*net.UnixListener)
	if !ok {
		ln.Close()
		return fmt.Errorf("listener is %T, not unix", ln)
	}
	defer ul.Close()
	_ = ul.SetDeadline(time.Now().Add(time.Duration(*timeout) * time.Second))
	for i := 1; *n == 0 || i <= *n; i++ {
		c, err := ul.AcceptUnix()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				emit(map[string]any{"event": "timeout", "form": lv.Form, "served": i - 1})
				return nil
			}
			return err
		}
		av := acceptView{Event: "accept", Form: lv.Form, N: i, Server: whoami()}
		fd, done, ferr := connFD(c)
		if ferr != nil {
			av.FDErr = errName(ferr)
		} else {
			av.Peer = peerOf(fd)
		}
		done()
		b, _ := json.Marshal(av)
		fmt.Println(string(b))
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = c.Write(append(b, '\n'))
		c.Close()
	}
	emit(map[string]any{"event": "done", "form": lv.Form, "served": *n})
	return nil
}

// ---- connect ---------------------------------------------------------------

type connectView struct {
	Event     string          `json:"event"`
	Path      string          `json:"path"`
	Self      self            `json:"self"`
	Connect   string          `json:"connect"`
	FDErr     string          `json:"fd_err,omitempty"`
	Server    *peerView       `json:"server,omitempty"`
	ServerSaw json.RawMessage `json:"server_saw,omitempty"`
	ServerRaw string          `json:"server_raw,omitempty"`
	ReadErr   string          `json:"read_err,omitempty"`
	PathLstat statView        `json:"path_lstat"`
}

func connect(path string) error {
	v := connectView{Event: "connect", Path: path, Self: whoami(), PathLstat: lstatOf(path)}
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	v.Connect = errName(err)
	if err != nil {
		emit(v)
		return nil
	}
	defer c.Close()
	fd, done, ferr := connFD(c)
	if ferr != nil {
		v.FDErr = errName(ferr)
	} else {
		p := peerOf(fd)
		v.Server = &p
	}
	done()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	line, rerr := bufio.NewReader(c).ReadString('\n')
	line = strings.TrimSpace(line)
	if rerr != nil && line == "" {
		v.ReadErr = errName(rerr)
	}
	if line != "" && json.Valid([]byte(line)) {
		v.ServerSaw = json.RawMessage(line)
	} else if line != "" {
		v.ServerRaw = line
	}
	emit(v)
	return nil
}
