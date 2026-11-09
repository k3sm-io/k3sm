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

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"k3sm.io/darwin-net/pkg/podnet"

	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/netserve"
)

// lsofPath is the absolute path the exposure check runs lsof from, so a PATH
// entry cannot stand in for it under sudo.
const lsofPath = "/usr/sbin/lsof"

// Bounds on one lsof run: its time, and the output it may produce before the
// table is refused as too large to trust.
const (
	lsofTimeout  = 5 * time.Second
	lsofMaxLines = 4096
	lsofMaxBytes = 1 << 20
)

// errLsofTooLarge is the named failure of an lsof table over the caps.
var errLsofTooLarge = errors.New("lsof output exceeds the size cap")

// Command classes of a LAN-reachable socket in the JSON report.
const (
	lanClassK3sm  = "k3sm"
	lanClassOther = "other"
)

// commandMaxLen bounds a command name in the text report; errorMaxLen bounds
// the failure text of the check.
const (
	commandMaxLen = 32
	errorMaxLen   = 200
)

// lsofWaitDelay bounds how long lsof's output pipes may stay open after it
// exits or is killed.
const lsofWaitDelay = time.Second

// lanSocket is one row of this Mac's socket table: a TCP listening socket or
// a bound UDP socket, its owning process (and that process's parent) and its
// local address. A wildcard bind is the unspecified address.
type lanSocket struct {
	PID      int
	PPID     int
	Command  string
	Protocol string
	Local    netip.AddrPort
}

// lanListener is one LAN-reachable socket. PID and Command appear in the
// root text output only, never in JSON.
type lanListener struct {
	PID      int    `json:"-"`
	Command  string `json:"-"`
	Class    string `json:"class"`
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     uint16 `json:"port"`
}

// lanExposure is the exposure section of `k3sm network lan status`: every
// socket a LAN peer can reach, the node daemon's own (and its children's)
// apart from the rest. Exactly one of NeedsRoot, Error and the lists
// describes the outcome; empty lists are clean only when the other two are
// unset.
type lanExposure struct {
	NeedsRoot bool           `json:"needsRoot,omitempty"`
	Error     string         `json:"error,omitempty"`
	Listeners []lanListener  `json:"listeners"`
	Counts    map[string]int `json:"counts"`
}

// lanExposureFor builds the exposure section for role: as root it lists the
// socket table through env.SocketTable and keeps the sockets a LAN peer can
// reach, classed k3sm by pid (the node daemon, the root network helper netd,
// and their children), never by command name. netd's pid is best effort: a
// netd that is not running owns no socket, and one whose pid cannot be read
// has its sockets listed as other rather than hidden.
func lanExposureFor(ctx context.Context, env networkEnv, role install.Role) lanExposure {
	var e lanExposure
	if env.Geteuid() != 0 {
		e.NeedsRoot = true
		return e
	}
	fail := func(err error) lanExposure {
		e.Error = sanitizePrintable(err.Error(), errorMaxLen)
		return e
	}
	pid, err := env.Sys.LaunchctlServicePID(nodeLabel(role))
	if err != nil {
		return fail(fmt.Errorf("find the node daemon's pid: %w", err))
	}
	owned := []int{pid}
	if npid, err := env.Sys.LaunchctlServicePID(install.NetdLabel); err == nil {
		owned = append(owned, npid)
	}
	args, err := env.NodeArgs(role)
	if err != nil {
		return fail(fmt.Errorf("read the node daemon's arguments: %w", err))
	}
	excluded, err := lanInternalPrefixes(args)
	if err != nil {
		return fail(err)
	}
	socks, err := env.SocketTable(ctx)
	if err != nil {
		return fail(fmt.Errorf("list this Mac's listening sockets: %w", err))
	}
	e.Listeners = lanReachable(socks, owned, excluded)
	e.Counts = map[string]int{lanClassK3sm: 0, lanClassOther: 0}
	for _, l := range e.Listeners {
		e.Counts[l.Class]++
	}
	return e
}

// lanInternalPrefixes are the ranges no LAN peer routes to: the cluster pod
// range (which holds the node's mesh address and its pod-range address), the
// Service range from the node daemon's arguments (the default when absent)
// and the vm NAT segment.
func lanInternalPrefixes(args []string) ([]netip.Prefix, error) {
	svc := strings.TrimSpace(install.ServerArgValue(args, install.ServiceCIDRFlag))
	if svc == "" {
		svc = install.DefaultServiceCIDR
	}
	out := []netip.Prefix{podnet.ClusterPodCIDR}
	for _, s := range []string{svc, netserve.DefaultVMNetSubnet} {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("parse the range %q: %w", s, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// lanReachable keeps the sockets of socks that a LAN peer can reach: not on
// loopback and not inside excluded. A socket of a pid in owned (the k3sm
// daemons) or of a process whose parent is one is classed k3sm; every other
// one, whatever its command name, is other. Duplicates are listed once.
func lanReachable(socks []lanSocket, owned []int, excluded []netip.Prefix) []lanListener {
	isOwned := func(pid int) bool { return pid > 0 && slices.Contains(owned, pid) }
	out := []lanListener{}
	for _, s := range socks {
		a := s.Local.Addr().Unmap()
		if a.IsLoopback() {
			continue
		}
		if slices.ContainsFunc(excluded, func(p netip.Prefix) bool { return p.Contains(a) }) {
			continue
		}
		class := lanClassOther
		if isOwned(s.PID) || isOwned(s.PPID) {
			class = lanClassK3sm
		}
		addr := a.String()
		if a.IsUnspecified() {
			addr = "*"
			if a.Is6() {
				addr = "[::]"
			}
		} else if a.Is6() {
			addr = "[" + addr + "]"
		}
		l := lanListener{PID: s.PID, Command: s.Command, Class: class, Protocol: strings.ToLower(s.Protocol), Address: addr, Port: s.Local.Port()}
		if !slices.Contains(out, l) {
			out = append(out, l)
		}
	}
	return out
}

// sanitizeCommand makes a process-chosen command name safe to print.
func sanitizeCommand(c string) string { return sanitizePrintable(c, commandMaxLen) }

// sanitizePrintable makes text from outside this program safe to print:
// bytes outside printable ASCII become '?', and it is cut to max bytes.
func sanitizePrintable(c string, max int) string {
	b := []byte(c)
	if len(b) > max {
		b = b[:max]
	}
	for i, ch := range b {
		if ch < 0x20 || ch > 0x7e {
			b[i] = '?'
		}
	}
	return string(b)
}

// lines renders the exposure section for a person (root only sees pids and
// commands).
func (e lanExposure) lines() []string {
	switch {
	case e.NeedsRoot:
		return []string{"LAN listeners: unknown to this user (the check needs root: run 'sudo k3sm network lan status')."}
	case e.Error != "":
		return []string{fmt.Sprintf("LAN listeners: unknown, the check failed (%s).", sanitizePrintable(e.Error, errorMaxLen))}
	}
	var out []string
	for _, b := range []struct{ class, heading string }{
		{lanClassK3sm, "k3sm control-plane ports (not moved by LAN access):"},
		{lanClassOther, "Listening on a LAN-reachable address (not moved by LAN access):"},
	} {
		var rows []string
		for _, l := range e.Listeners {
			if l.Class == b.class {
				rows = append(rows, fmt.Sprintf("  pid %d %s %s %s:%d", l.PID, sanitizeCommand(l.Command), l.Protocol, l.Address, l.Port))
			}
		}
		if len(rows) == 0 {
			out = append(out, b.heading+" none.")
			continue
		}
		out = append(out, b.heading)
		out = append(out, rows...)
	}
	return out
}

// cappedBuffer collects at most max bytes and records that more was offered.
type cappedBuffer struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); len(p) > room {
		c.over = true
		if room > 0 {
			c.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return c.buf.Write(p)
}

// lsofExec runs lsof with args, writing its output to stdout and stderr: the
// seam under runLsof, so a test can stand in for the process.
type lsofExec func(ctx context.Context, stdout, stderr io.Writer, args ...string) error

// execLsof is the production lsofExec: lsof as root by absolute path, with an
// empty environment and a bound on how long its pipes outlive it.
func execLsof(ctx context.Context, stdout, stderr io.Writer, args ...string) error {
	cmd := exec.CommandContext(ctx, lsofPath, args...)
	cmd.Env = []string{}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = lsofWaitDelay
	return cmd.Run()
}

// runLsof is the one hardened lsof runner: execLsof under runLsofWith.
func runLsof(ctx context.Context, args ...string) ([]byte, error) {
	return runLsofWith(ctx, execLsof, args...)
}

// runLsofWith runs lsof through run with a time bound and an output cap and
// returns its stdout. lsof exiting 1 with no output and nothing on stderr
// means no sockets (nil, nil); any other failure, any stderr text with exit
// 1, or output over the cap is an error.
func runLsofWith(ctx context.Context, run lsofExec, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, lsofTimeout)
	defer cancel()
	stdout := &cappedBuffer{max: lsofMaxBytes}
	stderr := &cappedBuffer{max: 4096}
	err := run(ctx, stdout, stderr, args...)
	if stdout.over {
		return nil, fmt.Errorf("%w (%d bytes)", errLsofTooLarge, lsofMaxBytes)
	}
	return lsofOutput(stdout.buf.Bytes(), stderr.buf.Bytes(), err)
}

// lsofOutput judges one lsof run (its stdout, stderr and exit error). lsof
// exiting 1 with no output and nothing on stderr means no sockets (nil, nil);
// any other failure, or any stderr text with exit 1, is an error.
func lsofOutput(stdout, stderr []byte, err error) ([]byte, error) {
	if err != nil {
		var ee interface{ ExitCode() int }
		if errors.As(err, &ee) && ee.ExitCode() == 1 && len(stdout) == 0 && len(stderr) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("%s: %w: %s", lsofPath, err, strings.TrimSpace(string(stderr)))
	}
	return stdout, nil
}

// lsofSocketTable is the production socket table: every TCP listening socket
// and bound UDP socket on this Mac with its pid, parent pid, command and
// protocol, read through runLsof.
func lsofSocketTable(ctx context.Context) ([]lanSocket, error) {
	out, err := runLsof(ctx, "-nP", "-iTCP", "-sTCP:LISTEN", "-iUDP", "-F", "pRcPn")
	if err != nil || out == nil {
		return nil, err
	}
	return parseLsofSocketTable(out)
}

// parseLsofSocketTable parses lsof -F pRcPn output: a "p<pid>" line opens a
// process set, "R<ppid>" and "c<command>" describe it, and each file in it is
// an "f<fd>" line, a "P<protocol>" line and an "n<name>" line. A name is
// "<host>:<port>", "*" being the wildcard and an IPv6 host in brackets; a
// connected UDP socket's "->peer" is dropped. The protocol must be TCP or
// UDP and precede the name, and a UDP socket with no port
// yet ("*:*") is skipped. Any other line, or more than
// lsofMaxLines lines, is an error, so a format change never reads as a clean
// table.
func parseLsofSocketTable(out []byte) ([]lanSocket, error) {
	var socks []lanSocket
	var cur lanSocket
	proto := ""
	lines := 0
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if lines++; lines > lsofMaxLines {
			return nil, fmt.Errorf("%w (%d lines)", errLsofTooLarge, lsofMaxLines)
		}
		if line == "" {
			return nil, errors.New("lsof: unparseable empty line")
		}
		switch line[0] {
		case 'p':
			n, err := strconv.Atoi(line[1:])
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("lsof: unparseable pid line %q", line)
			}
			cur, proto = lanSocket{PID: n}, ""
		case 'R':
			n, err := strconv.Atoi(line[1:])
			if err != nil || n < 0 {
				return nil, fmt.Errorf("lsof: unparseable parent pid line %q", line)
			}
			cur.PPID = n
		case 'c':
			cur.Command = line[1:]
		case 'f':
			proto = ""
		case 'P':
			if proto = line[1:]; proto != "TCP" && proto != "UDP" {
				return nil, fmt.Errorf("lsof: unexpected protocol line %q", line)
			}
		case 'n':
			if cur.PID == 0 {
				return nil, fmt.Errorf("lsof: socket %q before any process", line[1:])
			}
			if proto == "" {
				return nil, fmt.Errorf("lsof: socket %q without a protocol", line[1:])
			}
			local, bound, err := parseLsofName(line[1:])
			if err != nil {
				return nil, err
			}
			if !bound {
				continue
			}
			s := cur
			s.Protocol, s.Local = proto, local
			socks = append(socks, s)
		default:
			return nil, fmt.Errorf("lsof: unparseable line %q", line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("lsof: read output: %w", err)
	}
	return socks, nil
}

// parseLsofName parses one lsof socket name into its local address; bound is
// false for a socket with no local port ("*:*").
func parseLsofName(name string) (local netip.AddrPort, bound bool, err error) {
	loc, _, _ := strings.Cut(name, "->")
	i := strings.LastIndex(loc, ":")
	if i < 0 {
		return netip.AddrPort{}, false, fmt.Errorf("lsof: unparseable socket name %q", name)
	}
	host, portStr := loc[:i], loc[i+1:]
	if portStr == "*" {
		return netip.AddrPort{}, false, nil
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return netip.AddrPort{}, false, fmt.Errorf("lsof: unparseable port in %q", name)
	}
	if host == "*" {
		return netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(port)), true, nil
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, false, fmt.Errorf("lsof: unparseable address in %q", name)
	}
	return netip.AddrPortFrom(addr, uint16(port)), true, nil
}
