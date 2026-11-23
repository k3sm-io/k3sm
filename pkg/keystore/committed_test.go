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
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/keystore/typed"
)

// corruptAt fails the step named step with an error that matches ErrCorrupt,
// as a floor refusal does, so a committed error that let its cause through
// would match ErrCorrupt too.
func corruptAt(step string) func(string) error {
	return func(name string) error {
		if name == step {
			return fmt.Errorf("%w: injected at %s", ErrCorrupt, step)
		}
		return nil
	}
}

// TestCommitPointReported is U151: once a write's pointer rename has
// succeeded, every later failure (the directory fsync, the floor line, the
// oauth prune) returns the committed Version, and for GenerateSSH the
// public key, with an error that matches ErrCommitted and never ErrCorrupt,
// whatever its cause matched.
func TestCommitPointReported(t *testing.T) {
	ctx := context.Background()
	seed := bytes.Repeat([]byte{0x5a}, 32)
	wantLine, _ := typed.SSHAuthorizedKey(seed, "c")
	type op struct {
		name  string
		steps []string
		// run sets up s, then runs the write under test with the fault
		// installed by arm, and returns its result and the version it
		// should have committed.
		run func(t *testing.T, s *FileStore, arm func()) (Version, string, error, uint64)
	}
	syncFloor := []string{"sync current", "write " + floorName}
	ops := []op{
		{"Rotate", syncFloor, func(t *testing.T, s *FileStore, arm func()) (Version, string, error, uint64) {
			mustPut(t, s, "k", KindOpaque, []byte("one"))
			arm()
			v, err := s.Rotate(ctx, "k", []byte("two"))
			return v, "", err, 2
		}},
		{"Put", syncFloor, func(t *testing.T, s *FileStore, arm func()) (Version, string, error, uint64) {
			arm()
			v, err := s.Put(ctx, "k", KindOpaque, []byte("one"))
			return v, "", err, 1
		}},
		{"PutCredential", syncFloor, func(t *testing.T, s *FileStore, arm func()) (Version, string, error, uint64) {
			arm()
			v, err := s.PutCredential(ctx, "k", KindToken, tokenEnvelope("t1"))
			return v, "", err, 1
		}},
		{"RotateIf", append(syncFloor, "prune k"), func(t *testing.T, s *FileStore, arm func()) (Version, string, error, uint64) {
			mustPutCredential(t, s, "k", KindOAuth, oauthEnvelope("a1", "r1"))
			mustRotateCredential(t, s, "k", KindOAuth, oauthEnvelope("a2", "r2"))
			read, _ := mustCredential(t, s, "k")
			arm()
			v, err := s.RotateIf(ctx, "k", KindOAuth, read, oauthEnvelope("a3", "r3"))
			return v, "", err, 3
		}},
		{"GenerateSSH", syncFloor, func(t *testing.T, s *FileStore, arm func()) (Version, string, error, uint64) {
			s.rand = io.MultiReader(bytes.NewReader(seed), rand.Reader)
			arm()
			v, line, err := s.GenerateSSH(ctx, "k", "c")
			return v, line, err, 1
		}},
	}
	for _, o := range ops {
		for _, step := range o.steps {
			t.Run(o.name+" "+step, func(t *testing.T) {
				s, _ := newTypedStore(t)
				v, line, err, want := o.run(t, s, func() { s.step = corruptAt(step) })
				s.step = func(string) error { return nil }
				if !errors.Is(err, ErrCommitted) || v.Version != want || v.Name != "k" {
					t.Fatalf("%s failing at %s = %+v, %v; want version %d and ErrCommitted", o.name, step, v, err, want)
				}
				if errors.Is(err, ErrCorrupt) {
					t.Fatalf("%s failing at %s: %v also matches ErrCorrupt", o.name, step, err)
				}
				if o.name == "GenerateSSH" && line != wantLine {
					t.Fatalf("GenerateSSH failing at %s returned line %q, want %q", step, line, wantLine)
				}
				list, lerr := s.List(ctx)
				if lerr != nil || len(list) != 1 || list[0].Err != nil || list[0].Current != v {
					t.Fatalf("List after the committed failure = %+v, %v; want %+v current", list, lerr, v)
				}
			})
		}
	}
}

// TestFloorLagNeverDeletesCommittedVersion is U151's floor-lag case: a
// rotation whose floor write failed (ErrCommitted) leaves the floor one
// behind its pointer; an older pointer copied back in that window passes the
// floor check, and the next rotation must refuse, as ErrCorrupt, rather than
// unlink the newer committed version above it, which for oauth holds the
// only valid refresh token. Restoring the newer pointer and raising the
// floor reads it again.
func TestFloorLagNeverDeletesCommittedVersion(t *testing.T) {
	ctx := context.Background()
	type kind struct {
		name   string
		put    func(t *testing.T, s *FileStore)
		rotate func(s *FileStore, n string) (Version, error)
		check  func(t *testing.T, s *FileStore, n string)
	}
	kinds := []kind{
		{"oauth", func(t *testing.T, s *FileStore) {
			mustPutCredential(t, s, "k", KindOAuth, oauthEnvelope("a1", "r1"))
			mustRotateCredential(t, s, "k", KindOAuth, oauthEnvelope("a2", "r2"))
		}, func(s *FileStore, n string) (Version, error) {
			return s.RotateCredential(ctx, "k", KindOAuth, oauthEnvelope("a"+n, "r"+n))
		}, func(t *testing.T, s *FileStore, n string) {
			if _, c := mustCredential(t, s, "k"); string(c.AccessToken) != "a"+n {
				t.Fatalf("current access token %q, want a%s", c.AccessToken, n)
			}
		}},
		{"opaque", func(t *testing.T, s *FileStore) {
			mustPut(t, s, "k", KindOpaque, []byte("1"))
			mustRotate(t, s, "k", "2")
		}, func(s *FileStore, n string) (Version, error) {
			return s.Rotate(ctx, "k", []byte(n))
		}, func(t *testing.T, s *FileStore, n string) { mustCurrent(t, s, "k", n) }},
	}
	for _, kd := range kinds {
		t.Run(kd.name, func(t *testing.T) {
			s, server := newTypedStore(t)
			kd.put(t, s)
			older := readString(t, entryPath(server, "k", currentName))
			s.step = failAt("write " + floorName)
			if v, err := kd.rotate(s, "3"); !errors.Is(err, ErrCommitted) || v.Version != 3 {
				t.Fatalf("rotation with a failed floor = %+v, %v; want version 3 and ErrCommitted", v, err)
			}
			s.step = func(string) error { return nil }
			newer := readString(t, entryPath(server, "k", currentName))
			v3 := readString(t, entryPath(server, "k", versionName(3)))
			writeFile(t, entryPath(server, "k", currentName), older)

			v, err := kd.rotate(s, "4")
			if !errors.Is(err, ErrCorrupt) || errors.Is(err, ErrCommitted) || v != (Version{}) {
				t.Fatalf("rotation over a copied-back pointer = %+v, %v; want a refusal matching ErrCorrupt", v, err)
			}
			if !strings.Contains(err.Error(), "copied back") {
				t.Fatalf("refusal %q does not name the rollback", err)
			}
			if got := readString(t, entryPath(server, "k", versionName(3))); got != v3 {
				t.Fatal("the refused rotation changed or removed version 3")
			}
			if _, err := os.Lstat(entryPath(server, "k", versionName(4))); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the refused rotation wrote version 4: %v", err)
			}
			// The newer pointer restored and the floor rebuilt, version 3 reads.
			writeFile(t, entryPath(server, "k", currentName), newer)
			remove(t, floorPath(server))
			if err := s.RaiseFloor(ctx); err != nil {
				t.Fatal(err)
			}
			kd.check(t, s, "3")
			if f := floorOf(t, server)["k"]; f.Seq != 3 {
				t.Fatalf("rebuilt floor %+v, want sequence 3", f)
			}
		})
	}
}
