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
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestOpenNoFollow proves the derived-path opener reads a regular file and
// refuses a symlink (to a real log, so a following open would succeed), a FIFO
// (without blocking) and a directory, and that ReadLogsWith opens only through
// the opener it is given.
func TestOpenNoFollow(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "0.log")
	line := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano) + " stdout F hello\n"
	if err := os.WriteFile(logFile, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "1.log")
	if err := os.Symlink(logFile, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "2.log")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "3.log")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		path    string
		wantErr error
	}{
		{name: "regular file opens", path: logFile},
		{name: "symlink is refused", path: link, wantErr: ErrUnsafeLogFile},
		{name: "fifo is refused without blocking", path: fifo, wantErr: ErrUnsafeLogFile},
		{name: "directory is refused", path: sub, wantErr: ErrUnsafeLogFile},
		{name: "missing file is not-exist", path: filepath.Join(dir, "9.log"), wantErr: fs.ErrNotExist},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := OpenNoFollow(tt.path)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("OpenNoFollow: %v", err)
				}
				_ = f.Close()
				return
			}
			if err == nil {
				_ = f.Close()
				t.Fatalf("OpenNoFollow(%s) succeeded, want %v", tt.path, tt.wantErr)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}

	t.Run("ReadLogsWith reads through the opener", func(t *testing.T) {
		var out bytes.Buffer
		if err := ReadLogsWith(context.Background(), logFile, OpenNoFollow, &Options{}, nil, nil, &out, &out); err != nil {
			t.Fatalf("ReadLogsWith: %v", err)
		}
		if got := out.String(); got != "hello\n" {
			t.Errorf("output = %q, want %q", got, "hello\n")
		}
		err := ReadLogsWith(context.Background(), link, OpenNoFollow, &Options{}, nil, nil, &out, &out)
		if !errors.Is(err, ErrUnsafeLogFile) {
			t.Errorf("ReadLogsWith through a symlink: err = %v, want ErrUnsafeLogFile", err)
		}
	})
}
