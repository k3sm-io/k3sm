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

package podlogs

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Ported from k8s.io/cri-client@v1.36.2 pkg/logs/logs.go and tail.go
// (Apache-2.0). Every observable behaviour below — the P-segment concatenation,
// "tail counts file lines", the strict-Before since, the mid-line limitBytes cut,
// the one final drain after the container exits — is what `kubectl logs` means to
// a k8s user, so it is reproduced rather than reinvented.
//
// ONE deliberate omission: upstream tries a Docker-JSON parser after the CRI
// parser, because a kubelet may inherit files a dockershim wrote. Nothing on a
// k3sm node has ever written that format, so parseFuncs holds the CRI parser
// alone. The sticky per-file detection structure is kept as it is, so adding a
// second format later is a one-line change and not a rewrite.

const (
	// RFC3339NanoFixed is the fixed-width timestamp the reader EMITS with
	// --timestamps (upstream timeFormatOut).
	RFC3339NanoFixed = "2006-01-02T15:04:05.000000000Z07:00"
	// rfc3339NanoLenient is the variable-width form the reader PARSES (upstream
	// timeFormatIn) — the writer emits fixed width, but a lenient parse also
	// accepts a file written by any other CRI runtime.
	rfc3339NanoLenient = "2006-01-02T15:04:05.999999999Z07:00"

	// logForceCheckPeriod is how often a follow re-reads even with no fsnotify
	// event. It is the safety net under every filesystem-watch edge case (macOS
	// kqueue coalescing, a directory recreated under the watch), which is why
	// upstream keeps it at one second and so does k3sm.
	logForceCheckPeriod = 1 * time.Second

	// blockSize is the tail scan's block size (upstream blockSize).
	blockSize = 1024
)

// stream is the CRI log stream tag of one line.
type stream string

const (
	streamStdout stream = "stdout"
	streamStderr stream = "stderr"

	// tagPartial is the CRI `P` tag: this line is a fragment whose content
	// continues on the next line. tagFull (`F`) ends a logical line.
	tagPartial = "P"
	// tagDelimiter separates multiple tags in the tag field. The format reserves
	// room for more tags than `P`/`F`; only the first is interpreted.
	tagDelimiter = ":"
)

var (
	// eol is the end-of-line byte in a log file.
	eol = []byte{'\n'}
	// delimiter separates the timestamp, stream and tag fields of a CRI line.
	delimiter = []byte{' '}
)

// Options is the kubelet-typed option set for one log read. The pointer fields
// are pointers for the reason v1.PodLogOptions makes them pointers and the reason
// the whole read path in k3sm is typed this way end to end: UNSET and ZERO are
// different requests. TailLines nil means "every line"; TailLines pointing at 0
// means "no lines at all", which a plain int64 could not express.
type Options struct {
	// TailLines is the number of lines to show from the end of the file. nil
	// shows everything.
	TailLines *int64
	// LimitBytes caps the RENDERED bytes written out (after the optional
	// timestamp prefix). nil is unlimited. The cut is taken mid-line, and
	// therefore possibly mid-rune, exactly as upstream's is.
	LimitBytes *int64
	// Since drops every line whose timestamp is strictly BEFORE it. The strictness
	// is upstream's: a line stamped exactly at Since is kept.
	Since time.Time
	// Timestamps prefixes each emitted logical line with its RFC3339NanoFixed
	// timestamp and a space. Only the FIRST segment of a P-continued line is
	// prefixed.
	Timestamps bool
	// Follow keeps reading until the container exits (plus one final drain) or
	// the context is cancelled.
	Follow bool
}

// RunningFunc reports whether the container whose log is being followed is still
// running. It is the consumer-side seam for upstream's isContainerRunning: the
// provider answers it from runtimed's pod status, and a test answers it from a
// variable.
type RunningFunc func(context.Context) (bool, error)

// logMessage is one parsed CRI line.
type logMessage struct {
	timestamp time.Time
	stream    stream
	log       []byte
}

// reset clears the message for reuse.
func (l *logMessage) reset() {
	l.timestamp = time.Time{}
	l.stream = ""
	l.log = nil
}

// parseFunc parses one raw log line into msg. msg is never nil.
type parseFunc func([]byte, *logMessage) error

// parseFuncs is the ordered format table getParseFunc probes. See the file
// comment for why it holds one entry.
var parseFuncs = []parseFunc{parseCRILog}

// parseCRILog parses one line of the CRI log format:
//
//	2016-10-06T00:17:09.669794202Z stdout P log content 1
//	2016-10-06T00:17:09.669794203Z stderr F log content 2
func parseCRILog(log []byte, msg *logMessage) error {
	var err error
	idx := bytes.Index(log, delimiter)
	if idx < 0 {
		return errors.New("timestamp is not found")
	}
	msg.timestamp, err = time.Parse(rfc3339NanoLenient, string(log[:idx]))
	if err != nil {
		return fmt.Errorf("unexpected timestamp format %q: %v", rfc3339NanoLenient, err)
	}

	log = log[idx+1:]
	idx = bytes.Index(log, delimiter)
	if idx < 0 {
		return errors.New("stream type is not found")
	}
	msg.stream = stream(log[:idx])
	if msg.stream != streamStdout && msg.stream != streamStderr {
		return fmt.Errorf("unexpected stream type %q", msg.stream)
	}

	log = log[idx+1:]
	idx = bytes.Index(log, delimiter)
	if idx < 0 {
		return errors.New("log tag is not found")
	}
	// Forward compatible: the tag field may carry more tags later, and only the
	// first one is interpreted today.
	tags := bytes.Split(log[:idx], []byte(tagDelimiter))
	partial := string(tags[0]) == tagPartial
	// A partial segment's trailing newline is the FILE's line terminator, not the
	// container's output, so it is dropped — that is what makes the P segments
	// concatenate back into the original long line.
	if partial && len(log) > 0 && log[len(log)-1] == '\n' {
		log = log[:len(log)-1]
	}
	msg.log = log[idx+1:]
	return nil
}

// getParseFunc returns the parser for a file, chosen from its first line and then
// used for the whole read (upstream's sticky detection).
func getParseFunc(log []byte) (parseFunc, error) {
	for _, p := range parseFuncs {
		if err := p(log, &logMessage{}); err == nil {
			return p, nil
		}
	}
	return nil, fmt.Errorf("unsupported log format: %q", log)
}

// logWriter renders parsed messages onto the caller's stdout/stderr, applying
// the timestamp prefix and the byte limit.
type logWriter struct {
	stdout io.Writer
	stderr io.Writer
	opts   *Options
	remain int64
}

// errMaximumWrite ends a read because LimitBytes has been reached. It is not a
// failure: the client asked for exactly this many bytes and got them.
var errMaximumWrite = errors.New("maximum write")

// errShortWrite ends a read because the sink accepted only part of a line.
var errShortWrite = errors.New("short write")

// newLogWriter returns a writer for opts. An unset LimitBytes is an effectively
// infinite budget rather than a special case in the hot path.
func newLogWriter(stdout, stderr io.Writer, opts *Options) *logWriter {
	w := &logWriter{stdout: stdout, stderr: stderr, opts: opts, remain: math.MaxInt64}
	if opts.LimitBytes != nil {
		w.remain = *opts.LimitBytes
	}
	return w
}

// write emits one parsed message. addPrefix is false for the continuation
// segments of a P-split line, so a single logical line carries one timestamp.
func (w *logWriter) write(msg *logMessage, addPrefix bool) error {
	if msg.timestamp.Before(w.opts.Since) {
		return nil
	}
	line := msg.log
	if w.opts.Timestamps && addPrefix {
		prefix := append([]byte(msg.timestamp.Format(RFC3339NanoFixed)), delimiter[0])
		line = append(prefix, line...)
	}
	if int64(len(line)) > w.remain {
		line = line[:w.remain]
	}
	var out io.Writer
	switch msg.stream {
	case streamStdout:
		out = w.stdout
	case streamStderr:
		out = w.stderr
	default:
		return fmt.Errorf("unexpected stream type %q", msg.stream)
	}
	// A nil sink means the caller did not ask for that stream: neither write it
	// nor charge it against the byte budget.
	if out == nil {
		return nil
	}
	n, err := out.Write(line)
	w.remain -= int64(n)
	if err != nil {
		return err
	}
	if n < len(line) {
		return errShortWrite
	}
	if w.remain <= 0 {
		return errMaximumWrite
	}
	return nil
}

// ReadLogs reads the CRI log file at path and renders it onto stdout and stderr
// per opts. isRunning is consulted only on the follow path; it may be nil for a
// non-follow read.
//
// Rotation is NOT followed: after the rotator renames the current file away this
// read sees the new, empty one, which is upstream's behaviour and upstream's
// documented limitation. `kubectl logs` has never read a rotated file.
func ReadLogs(ctx context.Context, path string, opts *Options, isRunning RunningFunc, log *slog.Logger, stdout, stderr io.Writer) error {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	// Resolve symlinks up front: filesystem watchers differ on whether they
	// follow one, and the whole tree is written by this node, so there is no
	// second principal whose symlink could be followed into.
	evaluated, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("failed to try resolving symlinks in path %q: %v", path, err)
	}
	path = evaluated
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open log file %q: %v", path, err)
	}
	defer func() { _ = f.Close() }()

	var tail int64 = -1
	if opts.TailLines != nil {
		tail = *opts.TailLines
	}
	start, err := findTailLineStartIndex(f, tail)
	if err != nil {
		return fmt.Errorf("failed to tail %d lines of log file %q: %w", tail, path, err)
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek %d in log file %q: %w", start, path, err)
	}

	// limitedMode stops after exactly tail lines on a NON-follow read. With
	// --follow the tail only chooses the starting offset and the stream then
	// continues, which is why the two are combined rather than either alone.
	limitedMode := (opts.TailLines != nil) && (!opts.Follow)
	limitedNum := tail

	r := bufio.NewReader(f)
	var watcher *fsnotify.Watcher
	var parse parseFunc
	var stop bool
	isNewLine := true
	found := true
	writer := newLogWriter(stdout, stderr, opts)
	msg := &logMessage{}
	dir := filepath.Dir(path)

	for {
		if stop || (limitedMode && limitedNum == 0) {
			return nil
		}
		l, err := r.ReadBytes(eol[0])
		if err != nil {
			if err != io.EOF {
				return fmt.Errorf("failed to read log file %q: %v", path, err)
			}
			if opts.Follow {
				// found=false means the previous wait observed an exited
				// container. Reaching EOF once more after that is the ONE final
				// drain: everything the container wrote before it died has now
				// been emitted, so the stream ends.
				if !found {
					return nil
				}
				// Rewind over the partial line so it is re-read whole once its
				// terminator lands.
				if _, err := f.Seek(-int64(len(l)), io.SeekCurrent); err != nil {
					return fmt.Errorf("failed to reset seek in log file %q: %v", path, err)
				}
				if watcher == nil {
					if watcher, err = fsnotify.NewWatcher(); err != nil {
						return fmt.Errorf("failed to create fsnotify watcher: %v", err)
					}
					defer func() { _ = watcher.Close() }()
					// The DIRECTORY, not the file: a rotation replaces the file,
					// and a watch on the old inode would go deaf.
					if err := watcher.Add(dir); err != nil {
						return fmt.Errorf("failed to watch directory %q: %w", dir, err)
					}
					// Re-read immediately: anything written between the EOF above
					// and the watch being armed has no event to announce it.
					continue
				}
				var recreated bool
				found, recreated, err = waitLogs(ctx, filepath.Base(path), watcher, isRunning, log)
				if err != nil {
					return err
				}
				if recreated {
					newF, err := os.Open(path)
					if err != nil {
						if os.IsNotExist(err) {
							continue
						}
						return fmt.Errorf("failed to open log file %q: %v", path, err)
					}
					_ = f.Close()
					f = newF
					r = bufio.NewReader(f)
				}
				continue
			}
			stop = true
			if len(l) == 0 {
				continue
			}
			log.Debug("incomplete line in log file", "path", path)
		}
		if parse == nil {
			parse, err = getParseFunc(l)
			if err != nil {
				return fmt.Errorf("failed to get parse function: %v", err)
			}
		}
		msg.reset()
		if err := parse(l, msg); err != nil {
			log.Error("failed when parsing line in log file", "path", path, "err", err)
			continue
		}
		if err := writer.write(msg, isNewLine); err != nil {
			if errors.Is(err, errMaximumWrite) {
				return nil
			}
			return err
		}
		if limitedMode {
			limitedNum--
		}
		// The next segment carries a prefix only if this one ended a logical
		// line. A P segment had its newline stripped by parseCRILog, so this is
		// the test that suppresses the repeated timestamp.
		if len(msg.log) > 0 {
			isNewLine = msg.log[len(msg.log)-1] == eol[0]
		} else {
			isNewLine = true
		}
	}
}

// waitLogs blocks until there is more to read. It returns whether the container
// may still produce output, whether the log file was RECREATED (so the caller
// must reopen), and any error.
func waitLogs(ctx context.Context, logName string, w *fsnotify.Watcher, isRunning RunningFunc, log *slog.Logger) (bool, bool, error) {
	if running, err := containerRunning(ctx, isRunning); !running {
		return false, false, err
	}
	errRetry := 5
	for {
		select {
		case <-ctx.Done():
			return false, false, errors.New("context cancelled")
		case e := <-w.Events:
			switch e.Op {
			case fsnotify.Write, fsnotify.Rename, fsnotify.Remove, fsnotify.Chmod:
				return true, false, nil
			case fsnotify.Create:
				return true, filepath.Base(e.Name) == logName, nil
			default:
				log.Debug("unexpected fsnotify event, retrying", "event", e.String())
			}
		case err := <-w.Errors:
			if errRetry == 0 {
				return false, false, err
			}
			log.Warn("fsnotify watch error, retrying", "err", err, "retries", errRetry)
			errRetry--
		case <-time.After(logForceCheckPeriod):
			return true, false, nil
		}
	}
}

// containerRunning applies upstream's isContainerRunning rule to the seam: a
// runtime that answers Unavailable is ASSUMED to still be running, because a
// container does not stop merely because the thing that reports on it did. Any
// other error is the caller's to surface; a nil seam means "assume running",
// which is what a non-follow read wants.
func containerRunning(ctx context.Context, isRunning RunningFunc) (bool, error) {
	if isRunning == nil {
		return true, nil
	}
	running, err := isRunning(ctx)
	if err != nil {
		if status.Code(err) == codes.Unavailable {
			return true, nil
		}
		return false, err
	}
	return running, nil
}

// findTailLineStartIndex returns the offset of the start of the last n lines.
// n < 0 returns the beginning of the file. A trailing incomplete line (no
// terminator) is not counted as a line, so `--tail=1` on a file whose last write
// is still in flight shows the last COMPLETE line plus that fragment.
func findTailLineStartIndex(f io.ReadSeeker, n int64) (int64, error) {
	if n < 0 {
		return 0, nil
	}
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, err
	}
	var left, cnt int64
	buf := make([]byte, blockSize)
	for right := size; right > 0 && cnt <= n; right -= blockSize {
		left = right - blockSize
		if left < 0 {
			left = 0
			buf = make([]byte, right)
		}
		if _, err := f.Seek(left, io.SeekStart); err != nil {
			return 0, err
		}
		if _, err := f.Read(buf); err != nil {
			return 0, err
		}
		cnt += int64(bytes.Count(buf, eol))
	}
	for ; cnt > n; cnt-- {
		idx := bytes.Index(buf, eol) + 1
		buf = buf[idx:]
		left += int64(idx)
	}
	return left, nil
}
