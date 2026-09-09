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

package status

import (
	"context"
	"io/fs"
	"regexp"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/version"
)

// Launchd reads the two LaunchDaemons' state. Print returns `launchctl print
// system/<label>` output and its exit error; PrintDisabled returns `launchctl
// print-disabled system`, which is a separate command because a disabled job
// and an idle one are indistinguishable in print output alone.
type Launchd interface {
	Print(label string) ([]byte, error)
	PrintDisabled() ([]byte, error)
}

// FS is the read-only filesystem surface the rows need: existence and mode
// (Stat), the tail of a log file (ReadTail), and the target of the
// /usr/local/bin launcher symlink (Readlink).
type FS interface {
	Stat(path string) (fs.FileInfo, error)
	ReadTail(path string, n int) ([]string, error)
	Readlink(path string) (string, error)
	// ReadFile reads a whole small file (the crash-loop record). It exists as
	// its own method so a fake can refuse it the way a 0700 work dir refuses a
	// plain-user status run.
	ReadFile(path string) ([]byte, error)
}

// Kube is the apiserver read surface. It is five methods rather than the usual
// one-to-three because it is ONE external system's read surface, not three
// concerns: a fake that answers RawGet must also answer Server(), or the row it
// produces cannot name what it talked to. Server and TLSPosture are pure
// accessors on the resolved client config, not calls.
type Kube interface {
	RawGet(ctx context.Context, path string) ([]byte, error)
	Nodes(ctx context.Context) ([]corev1.Node, error)
	Pods(ctx context.Context) ([]corev1.Pod, error)
	Server() string
	TLSPosture() string
}

// Liveness is the tri-state answer to "is this pid there?".
//
// It mirrors dev.Liveness deliberately rather than importing it: pkg/dev pulls
// the whole dev-cluster stack (pkg/install, the executor, darwin-net) in behind
// a three-value enum, and pkg/status is a reporting leaf that should stay cheap
// to import. cmd/k3sm converts at the adapter.
//
// The three values exist because kill(pid, 0) has three answers, not two: ESRCH
// (gone), success (there, and signalable), and EPERM (there, owned by someone
// else). An unprivileged status probe of a root daemon gets EPERM, and calling
// that "dead" would report a healthy daemon as gone.
type Liveness int

const (
	// LivenessDead means the pid is not in the process table.
	LivenessDead Liveness = iota
	// LivenessRunning means the pid exists and this uid can signal it.
	LivenessRunning
	// LivenessUnknown means the pid exists but is not probeable from this uid.
	LivenessUnknown
)

// Exists reports whether a process is there at all — true for both Running and
// Unknown, because an unprobeable pid belongs to a process that demonstrably
// exists.
func (l Liveness) Exists() bool { return l != LivenessDead }

// Procs is the process-table surface: whether a recorded pid is alive, and how
// many vm hosts the control plane has spawned.
type Procs interface {
	Liveness(pid int) Liveness
	VMHosts(serverPID int) (int, error)
}

// Runtimed is the native runtime daemon's health surface. The control socket is
// owner-only, so this seam is wired ONLY for root and the service user; every
// other caller gets a nil Runtimed and an honest "needs sudo" row rather than a
// connection error dressed up as a fault.
type Runtimed interface {
	Info(ctx context.Context) (*runtimev1.GetRuntimeInfoResponse, error)
}

// RuntimeReachableUnknownUID is the ServiceUID a caller passes when the service
// user could not be looked up. It can never equal a real euid, so an unresolved
// service user fails CLOSED: the socket is not dialled.
const RuntimeReachableUnknownUID = -1

// RuntimedReachable reports whether a process running as euid may open the
// runtimed control socket, which is mode 0600 inside a 0700 directory owned by
// the service user.
//
// It is the ONE home of that decision: cmd/k3sm consults it to decide whether to
// build a Runtimed seam at all, and Collector consults it again before using
// one. Dialling anyway and reporting the connection error would be worse than
// useless — it would print "permission denied" as if the runtime were broken,
// when the only thing that happened is that a status command was run without
// sudo, which is the ordinary case.
func RuntimedReachable(euid, serviceUID int) bool {
	return euid == 0 || (serviceUID >= 0 && euid == serviceUID)
}

// Paths are the installed locations the rows check. They are passed in rather
// than read from pkg/install here so a test can describe an install anywhere.
type Paths struct {
	Binary          string
	Link            string
	LaunchDaemonDir string
	NetdLabel       string
	ServerLabel     string
	DataRoot        string
	WorkDir         string
	NetdSocket      string
	NetdLog         string
	ServerLog       string
}

// tokenFlags are the argv flags whose VALUE is a credential. A log line that
// echoes one is redacted flag-and-all.
var tokenFlags = regexp.MustCompile(`(--(?:token|agent-token|server-token|server-ca-hash))[= ]\S+`)

// tokenLiterals are the credential SHAPES k3sm mints: the join token
// (`k3sm-<opaque>`) and the CA-pinned bootstrap token (`K10<sha256>::…`). They
// are matched on shape, not on where they were found, because a secret that
// reaches a log line has already escaped the argv it came from.
var tokenLiterals = regexp.MustCompile(`(?:k3sm-[A-Za-z0-9._~+/=-]{12,}|K10[0-9a-fA-F]{16,}(?:::\S+)?)`)

// redacted is what replaces a matched secret. It is a fixed word, never a
// prefix-preserving mask: showing the first characters of a token is showing
// part of a token.
const redacted = "<redacted>"

// Redact removes credential material from text destined for a report field.
//
// It is applied to every log line the report carries. The report never carries
// raw launchctl output at all — that is a structural exclusion, not a redaction
// — but a crash-looping server's own log can echo the flags it was started
// with, and that log tail IS quoted into the row.
func Redact(s string) string {
	s = tokenFlags.ReplaceAllString(s, "$1 "+redacted)
	return tokenLiterals.ReplaceAllString(s, redacted)
}

// stripTimestamp removes a leading log timestamp token so the quoted line reads
// as the message rather than as a clock. Both shapes k3sm's daemons emit are
// handled: slog's `time=<rfc3339>` and a bare leading ISO timestamp.
func stripTimestamp(line string) string {
	line = strings.TrimSpace(line)
	if rest, ok := strings.CutPrefix(line, "time="); ok {
		if i := strings.IndexByte(rest, ' '); i >= 0 {
			return strings.TrimSpace(rest[i+1:])
		}
		return ""
	}
	if i := strings.IndexByte(line, ' '); i > 0 && isoTimestamp.MatchString(line[:i]) {
		return strings.TrimSpace(line[i+1:])
	}
	return line
}

// isoTimestamp matches a bare leading ISO-8601 timestamp token.
var isoTimestamp = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}[T ]?\d{2}:\d{2}:\d{2}\S*$`)

// Collector holds the seams and the facts one report is built from. A nil Kube
// means no kubeconfig was resolvable (KubeErr says why); a nil Runtimed means
// this user may not open the runtime socket. Both are ordinary, reportable
// postures, not errors.
type Collector struct {
	Launchd    Launchd
	FS         FS
	Kube       Kube
	KubeErr    error
	KubeSource string
	Procs      Procs
	Runtimed   Runtimed
	DataRoot   dataroot.FS
	Paths      Paths
	EUID       int
	ServiceUID int
	Now        func() time.Time
	Version    version.Info
	Host       string
	// Hostname is this Mac's host name, used to pick THIS node out of a
	// multi-node cluster's node list. Empty leaves the node row to its fallback.
	Hostname string
}
