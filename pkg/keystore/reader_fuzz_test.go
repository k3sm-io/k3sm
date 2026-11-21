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

package keystore

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The fuzz targets below drive the readers of the master pair and of the
// generation file through real files, because the bytes are parsed in the
// functions that read them: readMaster for master and master.sha256, and
// openEntry for generation. Each target writes into one directory per fuzz
// worker, created once, and rewrites the files on every input.

// fuzzMasterStore returns a store whose readMaster can be called on the
// returned root, and the directory the root is open on.
func fuzzMasterStore(f *testing.F) (*FileStore, string) {
	dir := f.TempDir()
	return &FileStore{uid: uint32(os.Getuid()), gid: uint32(os.Getgid())}, dir
}

// readMasterPair writes master and fp as the master pair in dir and reads
// them back with readMaster.
func readMasterPair(t *testing.T, s *FileStore, dir string, master, fp []byte) ([]byte, error) {
	t.Helper()
	for name, b := range map[string][]byte{masterName: master, masterFingerprintName: fp} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, fileMode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, fileMode); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	return s.readMaster(root)
}

// checkMasterRead holds readMaster to its contract for one input: it accepts
// exactly a 32-byte master whose fingerprint file is the lowercase hex
// SHA-256 and a newline, returns that master unchanged, and refuses anything
// else as ErrMasterUntrusted.
func checkMasterRead(t *testing.T, master, fp, got []byte, err error) {
	t.Helper()
	want := len(master) == masterSize && string(fp) == masterFingerprint(master)
	switch {
	case want && err != nil:
		t.Fatalf("readMaster refused a good pair: %v", err)
	case !want && err == nil:
		t.Fatalf("readMaster accepted master %x with fingerprint file %q", master, fp)
	case err != nil && !errors.Is(err, ErrMasterUntrusted):
		t.Fatalf("readMaster error %v is not ErrMasterUntrusted", err)
	case err == nil && !bytes.Equal(got, master):
		t.Fatalf("readMaster = %x, want %x", got, master)
	}
}

// FuzzReadMaster fuzzes the master file's bytes, with a fingerprint file that
// matches them, so every input reaches the master's own checks.
func FuzzReadMaster(f *testing.F) {
	f.Add(bytes.Repeat([]byte{7}, masterSize))
	f.Add(bytes.Repeat([]byte{7}, masterSize-1))
	f.Add(bytes.Repeat([]byte{7}, masterSize+1))
	f.Add([]byte{})
	s, dir := fuzzMasterStore(f)
	f.Fuzz(func(t *testing.T, master []byte) {
		fp := []byte(masterFingerprint(master))
		got, err := readMasterPair(t, s, dir, master, fp)
		checkMasterRead(t, master, fp, got, err)
	})
}

// FuzzReadMasterFingerprint fuzzes the fingerprint file's bytes beside a good
// master.
func FuzzReadMasterFingerprint(f *testing.F) {
	master := bytes.Repeat([]byte{7}, masterSize)
	good := masterFingerprint(master)
	f.Add([]byte(good))
	f.Add(bytes.ToUpper([]byte(good)))
	f.Add([]byte(good[:len(good)-1]))
	f.Add([]byte(good + "\n"))
	f.Add([]byte{})
	s, dir := fuzzMasterStore(f)
	f.Fuzz(func(t *testing.T, fp []byte) {
		got, err := readMasterPair(t, s, dir, master, fp)
		checkMasterRead(t, master, fp, got, err)
	})
}

// FuzzReadGeneration fuzzes an entry's generation file: openEntry accepts
// exactly 32 hex digits and a newline, decodes them as the generation, and
// refuses anything else as ErrCorrupt.
func FuzzReadGeneration(f *testing.F) {
	good := hex.EncodeToString(bytes.Repeat([]byte{0xA5}, generationSize)) + "\n"
	f.Add([]byte(good))
	f.Add([]byte(good[:len(good)-1]))
	f.Add([]byte(good[:len(good)-1] + " "))
	f.Add([]byte("not hex at all, but thirty-three"))
	f.Add([]byte{})
	dir := f.TempDir()
	entryDir := filepath.Join(dir, "a")
	if err := os.Mkdir(entryDir, dirMode); err != nil {
		f.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(entryDir, currentName), nil, fileMode); err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if err := os.WriteFile(filepath.Join(entryDir, generationName), b, fileMode); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		e, err := openEntry(root, "a")
		var want [generationSize]byte
		ok := len(b) == generationFileSize && b[len(b)-1] == '\n'
		if ok {
			_, herr := hex.Decode(want[:], b[:len(b)-1])
			ok = herr == nil
		}
		switch {
		case ok && err != nil:
			t.Fatalf("openEntry refused generation %q: %v", b, err)
		case !ok && err == nil:
			e.close()
			t.Fatalf("openEntry accepted generation %q", b)
		case err != nil && !errors.Is(err, ErrCorrupt):
			t.Fatalf("openEntry error %v is not ErrCorrupt", err)
		case err == nil:
			defer e.close()
			if e.generation != want {
				t.Fatalf("generation = %x, want %x", e.generation, want)
			}
		}
	})
}
