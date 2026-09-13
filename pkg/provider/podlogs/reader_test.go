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
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ptr returns a pointer to v. The option types are pointer-typed precisely so
// unset and zero can be told apart, so the tests below have to construct them.
func ptr[T any](v T) *T { return &v }

// line renders one CRI log line the way runtimed's writer does.
func line(ts time.Time, stream, tag, content string) string {
	return ts.Format(RFC3339NanoFixed) + " " + stream + " " + tag + " " + content + "\n"
}

// writeLog writes body to a fresh log file and returns its path.
func writeLog(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "0.log")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	return path
}

// TestReadLogsMatchesUpstream is the ported table from k8s.io/cri-client
// pkg/logs/logs_test.go (TestReadLogs, TestParseLog, TestWriteLogs,
// TestWriteLogsWithBytesLimit), re-expressed over CRI-format files.
//
// The upstream table is stated in docker-JSON lines because a kubelet may
// inherit dockershim files; k3sm's writer emits CRI and nothing on the node has
// ever written the other format, so the same CASES are asserted over CRI input.
// Every expectation below is upstream's own, unchanged — these are the semantics
// `kubectl logs` means, and a divergence in any one of them is a divergence a
// user would notice.
func TestReadLogsMatchesUpstream(t *testing.T) {
	base := time.Date(2020, 9, 27, 11, 18, 1, 0, time.UTC)
	body := line(base, "stdout", "F", "line1") +
		line(base.Add(time.Second), "stdout", "F", "line2") +
		line(base.Add(2*time.Second), "stdout", "F", "line3")
	path := writeLog(t, body)

	tests := []struct {
		name string
		opts Options
		want string
	}{
		{
			name: "default options output all lines",
			opts: Options{},
			want: "line1\nline2\nline3\n",
		},
		{
			name: "TailLines 2 outputs the last 2 lines",
			opts: Options{TailLines: ptr[int64](2)},
			want: "line2\nline3\n",
		},
		{
			name: "TailLines 4 outputs all lines when the log has fewer",
			opts: Options{TailLines: ptr[int64](4)},
			want: "line1\nline2\nline3\n",
		},
		{
			name: "TailLines 0 outputs nothing",
			opts: Options{TailLines: ptr[int64](0)},
			want: "",
		},
		{
			name: "LimitBytes 9 outputs the first 9 bytes, cut mid-line",
			opts: Options{LimitBytes: ptr[int64](9)},
			want: "line1\nlin",
		},
		{
			name: "LimitBytes 100 outputs everything when the log is smaller",
			opts: Options{LimitBytes: ptr[int64](100)},
			want: "line1\nline2\nline3\n",
		},
		{
			name: "LimitBytes 0 outputs nothing",
			opts: Options{LimitBytes: ptr[int64](0)},
			want: "",
		},
		{
			name: "Since keeps the line stamped exactly at it (strictly Before is dropped)",
			opts: Options{Since: base.Add(time.Second)},
			want: "line2\nline3\n",
		},
		{
			name: "Since in the future outputs nothing",
			opts: Options{Since: base.Add(time.Hour)},
			want: "",
		},
		{
			name: "Timestamps prefixes every logical line",
			opts: Options{TailLines: ptr[int64](1), Timestamps: true},
			want: base.Add(2*time.Second).Format(RFC3339NanoFixed) + " line3\n",
		},
		{
			name: "follow on an exited container outputs all lines",
			opts: Options{Follow: true},
			want: "line1\nline2\nline3\n",
		},
		{
			name: "follow combined with TailLines 2 outputs the last 2 lines",
			opts: Options{Follow: true, TailLines: ptr[int64](2)},
			want: "line2\nline3\n",
		},
		{
			name: "follow combined with Since outputs lines at or after it",
			opts: Options{Follow: true, Since: base.Add(time.Second)},
			want: "line2\nline3\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			// Not running: on the follow cases this is what ends the stream, after
			// the one final drain. On the others it is never consulted.
			exited := func(context.Context) (bool, error) { return false, nil }
			if err := ReadLogs(context.Background(), path, &tt.opts, exited, nil, &stdout, &stderr); err != nil {
				t.Fatalf("ReadLogs: %v", err)
			}
			if stderr.Len() > 0 {
				t.Fatalf("stderr = %q, want empty (every line in the fixture is stdout)", stderr.String())
			}
			if got := stdout.String(); got != tt.want {
				t.Errorf("stdout = %q, want %q", got, tt.want)
			}
		})
	}

	// The P/F concatenation, which is what makes a line longer than the writer's
	// 16 KiB chunk read back as ONE line with ONE timestamp. A reader that
	// emitted each segment as its own line would look almost right and be wrong
	// in exactly the case that matters (a long stack trace).
	t.Run("P segments concatenate into one logical line with one timestamp", func(t *testing.T) {
		ts := base
		p := writeLog(t, line(ts, "stdout", "P", "aaa")+line(ts, "stdout", "P", "bbb")+line(ts, "stdout", "F", "ccc"))
		var stdout, stderr bytes.Buffer
		opts := Options{Timestamps: true}
		if err := ReadLogs(context.Background(), p, &opts, nil, nil, &stdout, &stderr); err != nil {
			t.Fatalf("ReadLogs: %v", err)
		}
		want := ts.Format(RFC3339NanoFixed) + " aaabbbccc\n"
		if got := stdout.String(); got != want {
			t.Errorf("stdout = %q, want %q", got, want)
		}
	})

	// Streams are routed separately, so a handler that wants them apart can have
	// them apart — and the kubectl path, which passes one writer for both, gets
	// them interleaved in write order.
	t.Run("stderr lines are routed to the stderr writer", func(t *testing.T) {
		p := writeLog(t, line(base, "stdout", "F", "out")+line(base.Add(time.Second), "stderr", "F", "err"))
		var stdout, stderr bytes.Buffer
		opts := Options{}
		if err := ReadLogs(context.Background(), p, &opts, nil, nil, &stdout, &stderr); err != nil {
			t.Fatalf("ReadLogs: %v", err)
		}
		if stdout.String() != "out\n" {
			t.Errorf("stdout = %q, want %q", stdout.String(), "out\n")
		}
		if stderr.String() != "err\n" {
			t.Errorf("stderr = %q, want %q", stderr.String(), "err\n")
		}
	})

	// LimitBytes counts the RENDERED bytes, so the timestamp prefix is charged
	// against the budget too — and the cut lands mid-rune when that is where the
	// budget ran out, which is upstream's behaviour and not an accident.
	t.Run("LimitBytes counts rendered bytes and cuts mid-rune", func(t *testing.T) {
		p := writeLog(t, line(base, "stdout", "F", "héllo"))
		var stdout, stderr bytes.Buffer
		// "h" plus the first byte of the two-byte é.
		opts := Options{LimitBytes: ptr[int64](2)}
		if err := ReadLogs(context.Background(), p, &opts, nil, nil, &stdout, &stderr); err != nil {
			t.Fatalf("ReadLogs: %v", err)
		}
		if got := stdout.String(); got != "h\xc3" {
			t.Errorf("stdout = %q, want the budget cut mid-rune at %q", got, "h\xc3")
		}
	})

	// A line the parser cannot read is SKIPPED, not fatal: one corrupt line in a
	// file must not cost the user the rest of the file. A file whose FIRST line
	// is unparseable is a different matter — the format is undetectable, and the
	// read fails saying so.
	t.Run("an unparseable first line fails the read", func(t *testing.T) {
		p := writeLog(t, "not a cri log line\n")
		var stdout, stderr bytes.Buffer
		opts := Options{}
		err := ReadLogs(context.Background(), p, &opts, nil, nil, &stdout, &stderr)
		if err == nil {
			t.Fatal("ReadLogs over an unparseable file returned no error")
		}
		if !strings.Contains(err.Error(), "unsupported log format") {
			t.Errorf("err = %v, want it to name the unsupported format", err)
		}
	})

	// The `P:TAG1:TAG2` shape: only the FIRST tag is interpreted, so a future
	// runtime adding tags does not make this reader mis-render every line.
	t.Run("extra log tags after the first are ignored", func(t *testing.T) {
		p := writeLog(t, line(base, "stdout", "P:TAG1:TAG2", "part")+line(base, "stdout", "F", "ial"))
		var stdout, stderr bytes.Buffer
		opts := Options{}
		if err := ReadLogs(context.Background(), p, &opts, nil, nil, &stdout, &stderr); err != nil {
			t.Fatalf("ReadLogs: %v", err)
		}
		if got := stdout.String(); got != "partial\n" {
			t.Errorf("stdout = %q, want %q", got, "partial\n")
		}
	})
}

// TestFindTailLineStartIndex is upstream's TestTail: the block-scanning tail
// offset, including that a trailing INCOMPLETE line is not counted as a line.
//
// That last property is what makes `--tail=1` useful on a live container: the
// partial line currently being written is not the one line you asked for.
func TestFindTailLineStartIndex(t *testing.T) {
	l := strings.Repeat("a", blockSize)
	testBytes := []byte(l + "\n" + l + "\n" + l + "\n" + l + "\n" + l[blockSize/2:])

	tests := []struct {
		name  string
		n     int64
		start int64
	}{
		{name: "negative n is the beginning of the file", n: -1, start: 0},
		{name: "zero n is the end of the last complete line", n: 0, start: int64(len(l)+1) * 4},
		{name: "one line back", n: 1, start: int64(len(l)+1) * 3},
		{name: "more lines than the file has is the beginning", n: 9999, start: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := findTailLineStartIndex(bytes.NewReader(testBytes), tt.n)
			if err != nil {
				t.Fatalf("findTailLineStartIndex: %v", err)
			}
			if got != tt.start {
				t.Errorf("start = %d, want %d", got, tt.start)
			}
		})
	}
}
