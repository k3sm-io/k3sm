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

package boundedread

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const testMax = 64

type readResult struct {
	b   []byte
	err error
}

// readWithin runs read in a goroutine and fails the test if it does not return
// within a bound, so a reader that blocks on a FIFO fails instead of hanging.
func readWithin(t *testing.T, read func(string, int64) ([]byte, error), path string, max int64) ([]byte, error) {
	t.Helper()
	done := make(chan readResult, 1)
	go func() {
		b, err := read(path, max)
		done <- readResult{b, err}
	}()
	select {
	case r := <-done:
		return r.b, r.err
	case <-time.After(10 * time.Second):
		t.Fatalf("read %s did not return: it blocked", path)
		return nil, nil
	}
}

// TestReadFileBounded drives both readers over each kind of file a planter can
// leave: what each returns, and which error class a refusal carries.
func TestReadFileBounded(t *testing.T) {
	exact := bytes.Repeat([]byte("x"), testMax)
	cases := []struct {
		name string
		make func(t *testing.T, dir string) string
		// want is the content expected from ReadFileBounded; nil means an error.
		want []byte
		// wantErr is the class of ReadFileBounded's error.
		wantErr error
		// followWant / followErr are the same for ReadFileBoundedFollow.
		followWant []byte
		followErr  error
	}{
		{
			name: "regular file",
			make: func(t *testing.T, dir string) string {
				return writeFile(t, dir, "f", []byte("hello"))
			},
			want: []byte("hello"), followWant: []byte("hello"),
		},
		{
			name: "missing",
			make: func(_ *testing.T, dir string) string {
				return filepath.Join(dir, "absent")
			},
			wantErr: fs.ErrNotExist, followErr: fs.ErrNotExist,
		},
		{
			name: "symlink to a regular file",
			make: func(t *testing.T, dir string) string {
				target := writeFile(t, dir, "target", []byte("linked"))
				link := filepath.Join(dir, "link")
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
				return link
			},
			wantErr: ErrRefused, followWant: []byte("linked"),
		},
		{
			name: "symlink to a FIFO",
			make: func(t *testing.T, dir string) string {
				fifo := makeFIFO(t, dir, "fifo")
				link := filepath.Join(dir, "link")
				if err := os.Symlink(fifo, link); err != nil {
					t.Fatal(err)
				}
				return link
			},
			wantErr: ErrRefused, followErr: ErrRefused,
		},
		{
			name: "FIFO",
			make: func(t *testing.T, dir string) string {
				return makeFIFO(t, dir, "fifo")
			},
			wantErr: ErrRefused, followErr: ErrRefused,
		},
		{
			name: "directory",
			make: func(_ *testing.T, dir string) string {
				return dir
			},
			wantErr: ErrRefused, followErr: ErrRefused,
		},
		{
			name: "oversize by one byte",
			make: func(t *testing.T, dir string) string {
				return writeFile(t, dir, "big", bytes.Repeat([]byte("x"), testMax+1))
			},
			wantErr: ErrRefused, followErr: ErrRefused,
		},
		{
			name: "exactly max",
			make: func(t *testing.T, dir string) string {
				return writeFile(t, dir, "exact", exact)
			},
			want: exact, followWant: exact,
		},
	}
	readers := []struct {
		name string
		read func(string, int64) ([]byte, error)
	}{
		{"ReadFileBounded", ReadFileBounded},
		{"ReadFileBoundedFollow", ReadFileBoundedFollow},
	}
	for _, tc := range cases {
		for _, r := range readers {
			t.Run(tc.name+"/"+r.name, func(t *testing.T) {
				path := tc.make(t, t.TempDir())
				want, wantErr := tc.want, tc.wantErr
				if r.name == "ReadFileBoundedFollow" {
					want, wantErr = tc.followWant, tc.followErr
				}
				got, err := readWithin(t, r.read, path, testMax)
				if wantErr != nil {
					if !errors.Is(err, wantErr) {
						t.Fatalf("err = %v, want one matching %v", err, wantErr)
					}
					if got != nil {
						t.Errorf("bytes = %q on error, want nil", got)
					}
					return
				}
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
				if !bytes.Equal(got, want) {
					t.Errorf("bytes = %q, want %q", got, want)
				}
			})
		}
	}
}

// TestErrRefusedIsNeitherAbsentNorPermission pins the property every fallback
// caller relies on: a refusal is not mistaken for an absent or root-only file.
func TestErrRefusedIsNeitherAbsentNorPermission(t *testing.T) {
	_, err := ReadFileBounded(makeFIFO(t, t.TempDir(), "fifo"), testMax)
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("err = %v, want ErrRefused", err)
	}
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
		t.Errorf("refusal %v matches fs.ErrNotExist or fs.ErrPermission", err)
	}
}

func writeFile(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func makeFIFO(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := unix.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestReadOpenedRefusesAFileThatGrewPastTheBound presents a file whose fstat
// size was under max but whose content is over it, the race the one-byte-over
// read exists for.
func TestReadOpenedRefusesAFileThatGrewPastTheBound(t *testing.T) {
	path := writeFile(t, t.TempDir(), "grown", bytes.Repeat([]byte("x"), testMax+1))
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	got, err := readOpened(f, path, 1, testMax)
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("err = %v, want ErrRefused", err)
	}
	if got != nil {
		t.Errorf("bytes = %d on error, want nil", len(got))
	}
}

// TestReadOpenedReadsAFileExactlyAtTheBound pins the boundary: max bytes read.
func TestReadOpenedReadsAFileExactlyAtTheBound(t *testing.T) {
	want := bytes.Repeat([]byte("x"), testMax)
	path := writeFile(t, t.TempDir(), "exact", want)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	got, err := readOpened(f, path, 1, testMax)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("got %d bytes, err %v; want %d bytes", len(got), err, len(want))
	}
}
