//go:build darwin

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

package install

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The launcher-link half of the production darwin System, exercised against a
// REAL filesystem — unprivileged, in a per-case t.TempDir(). Everything these
// two functions decide is a filesystem judgement (what is at the path, what the
// parent's mode says), so a fake would be asserting the test's own model rather
// than the behaviour; and none of it needs privilege.
//
// Deliberately NOT parallel: several cases read os.Geteuid()-conditional
// branches and manipulate directory modes, and t.TempDir() cleanup of a mode-
// stripped directory is easier to reason about serially.
//
// One branch this table cannot reach on a live filesystem: the uid-0 half of the
// directory-trust check ("owned by uid N, not root"). It is gated on
// os.Geteuid()==0 precisely because an unprivileged run cannot chown a temp dir
// to root. That arm — and the wording of every refusal, which an operator has to
// act on — is asserted against the pure linkDirVerdict in
// TestEnsureSymlinkNamesTheRemedyForAnUntrustedLinkDir instead; what this table
// still owns is that the real Lstat-driven wrapper reaches those verdicts from
// an actual directory.

func TestEnsureSymlink(t *testing.T) {
	sys := darwinSystem{}

	for _, tc := range []struct {
		name string
		// setup prepares the case's temp root and returns the link path to ask
		// for and the target it must end up pointing at.
		setup func(t *testing.T, root string) (link, target string)
		// wantErr, when non-empty, is a substring the error must contain.
		wantErr string
	}{
		{
			name: "absent parent is created 0755",
			setup: func(t *testing.T, root string) (string, string) {
				return filepath.Join(root, "bin", "k3sm"), filepath.Join(root, "Library", "k3sm")
			},
		},
		{
			name: "absent link is created pointing at the target",
			setup: func(t *testing.T, root string) (string, string) {
				mkdir(t, filepath.Join(root, "bin"), 0o755)
				return filepath.Join(root, "bin", "k3sm"), filepath.Join(root, "Library", "k3sm")
			},
		},
		{
			name: "already-correct link is a no-op",
			setup: func(t *testing.T, root string) (string, string) {
				mkdir(t, filepath.Join(root, "bin"), 0o755)
				link, target := filepath.Join(root, "bin", "k3sm"), filepath.Join(root, "Library", "k3sm")
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
				return link, target
			},
		},
		{
			name: "stale link pointing elsewhere is replaced",
			setup: func(t *testing.T, root string) (string, string) {
				mkdir(t, filepath.Join(root, "bin"), 0o755)
				link := filepath.Join(root, "bin", "k3sm")
				writeFile(t, filepath.Join(root, "other"))
				if err := os.Symlink(filepath.Join(root, "other"), link); err != nil {
					t.Fatal(err)
				}
				return link, filepath.Join(root, "Library", "k3sm")
			},
		},
		{
			name: "dangling link is replaced",
			setup: func(t *testing.T, root string) (string, string) {
				mkdir(t, filepath.Join(root, "bin"), 0o755)
				link := filepath.Join(root, "bin", "k3sm")
				if err := os.Symlink(filepath.Join(root, "gone"), link); err != nil {
					t.Fatal(err)
				}
				return link, filepath.Join(root, "Library", "k3sm")
			},
		},
		{
			name: "a regular file at the link path is never replaced",
			setup: func(t *testing.T, root string) (string, string) {
				mkdir(t, filepath.Join(root, "bin"), 0o755)
				link := filepath.Join(root, "bin", "k3sm")
				writeFile(t, link)
				return link, filepath.Join(root, "Library", "k3sm")
			},
			wantErr: "refusing to replace non-symlink",
		},
		{
			name: "a directory at the link path is never replaced",
			setup: func(t *testing.T, root string) (string, string) {
				mkdir(t, filepath.Join(root, "bin"), 0o755)
				link := filepath.Join(root, "bin", "k3sm")
				mkdir(t, link, 0o755)
				return link, filepath.Join(root, "Library", "k3sm")
			},
			wantErr: "refusing to replace non-symlink",
		},
		{
			name: "a group-writable link dir is refused",
			setup: func(t *testing.T, root string) (string, string) {
				mkdir(t, filepath.Join(root, "bin"), 0o775)
				return filepath.Join(root, "bin", "k3sm"), filepath.Join(root, "Library", "k3sm")
			},
			wantErr: "refusing to link the k3sm launcher into",
		},
		{
			name: "a world-writable link dir is refused",
			setup: func(t *testing.T, root string) (string, string) {
				mkdir(t, filepath.Join(root, "bin"), 0o757)
				return filepath.Join(root, "bin", "k3sm"), filepath.Join(root, "Library", "k3sm")
			},
			wantErr: "refusing to link the k3sm launcher into",
		},
		{
			name: "a link dir that is itself a symlink to a dir is refused",
			setup: func(t *testing.T, root string) (string, string) {
				mkdir(t, filepath.Join(root, "real"), 0o755)
				if err := os.Symlink(filepath.Join(root, "real"), filepath.Join(root, "bin")); err != nil {
					t.Fatal(err)
				}
				return filepath.Join(root, "bin", "k3sm"), filepath.Join(root, "Library", "k3sm")
			},
			wantErr: "refusing to link the k3sm launcher into",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			link, target := tc.setup(t, root)
			err := sys.EnsureSymlink(target, link)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("EnsureSymlink(%q, %q) = nil, want an error containing %q", target, link, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
				}
				// A refusal must leave no temp link behind.
				assertNoTemps(t, filepath.Dir(link))
				return
			}
			if err != nil {
				t.Fatalf("EnsureSymlink(%q, %q): %v", target, link, err)
			}
			got, err := os.Readlink(link)
			if err != nil {
				t.Fatalf("readlink %s: %v", link, err)
			}
			if got != target {
				t.Errorf("link points at %q, want %q", got, target)
			}
			// The parent must be a directory at 0755 (created here or pre-made),
			// and when we are actually root it must be root-owned — the property
			// the trust check will assert on the NEXT install.
			parent := filepath.Dir(link)
			fi, err := os.Lstat(parent)
			if err != nil {
				t.Fatalf("lstat %s: %v", parent, err)
			}
			if !fi.IsDir() {
				t.Fatalf("%s is not a directory", parent)
			}
			if perm := fi.Mode().Perm(); perm&linkDirMaxMode != 0 {
				t.Errorf("link dir mode = %04o, want no group/other write", perm)
			}
			if os.Geteuid() == 0 {
				if err := checkLinkDirTrust(parent, parent); err != nil {
					t.Errorf("link dir must satisfy the trust check after creation: %v", err)
				}
			}
			assertNoTemps(t, parent)
			// Idempotent: asking again for the same link is a no-op success.
			if err := sys.EnsureSymlink(target, link); err != nil {
				t.Errorf("second EnsureSymlink must be a no-op success, got %v", err)
			}
		})
	}
}

// TestEnsureDataRoot exercises the data-root ownership policy against a REAL
// temp directory, unprivileged — using the test process's own uid (it is a
// member of the staff group DataRootGID names, so the chown needs no
// privilege). It must NEVER call darwinSystem.EnsureServiceUser: that runs
// dscl against the live directory service, which is exactly the privileged
// operation this file's package comment says these tests avoid.
func TestEnsureDataRoot(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "data-root")
	uid := os.Getuid()

	if err := EnsureDataRoot(dir, uid); err != nil {
		t.Fatalf("EnsureDataRoot(%q, %d): %v", dir, uid, err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat %s: %v", dir, err)
	}
	if !fi.IsDir() {
		t.Fatalf("%s is not a directory", dir)
	}
	if perm := fi.Mode().Perm(); perm != DataRootMode {
		t.Errorf("mode = %04o, want %04o", perm, DataRootMode)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if int(st.Uid) != uid {
			t.Errorf("owner uid = %d, want %d", st.Uid, uid)
		}
		if int(st.Gid) != DataRootGID {
			t.Errorf("owner gid = %d, want %d", st.Gid, DataRootGID)
		}
	}
	// Idempotent: asking again for the same, already-correct dir is a no-op
	// success.
	if err := EnsureDataRoot(dir, uid); err != nil {
		t.Errorf("second EnsureDataRoot must be a no-op success, got %v", err)
	}
}

// TestLogDirIsNotWorldReadableOnDisk is the on-disk half of
// TestLogDirIsNotWorldReadable (install_test.go, which pins the constants): it
// runs the real ensureLogDir against a real directory, unprivileged, in a
// t.TempDir().
//
// It uses the test process's own uid for BOTH owners and its own gid for the
// group: chowning to _k3sm, to root, or to group admin needs privilege this
// file's package comment says these tests never take, and what is under test is
// the MODE and the repair of an existing tree, not whether this process may
// hand a file to another user.
func TestLogDirIsNotWorldReadableOnDisk(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "k3sm")
	// The state an earlier build leaves behind: a 0755 directory whose logs
	// were created by launchd at the spawning job's umask.
	mkdir(t, dir, 0o755)
	server := filepath.Join(dir, filepath.Base(ServerLogPath()))
	if err := os.WriteFile(server, []byte("an existing line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A file in the directory that is NOT one of the daemon logs. k3sm
	// does not own it and must not touch it.
	stranger := filepath.Join(dir, "someone-elses.log")
	if err := os.WriteFile(stranger, []byte("not ours\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	own := logOwnership{serviceUID: os.Getuid(), rootUID: os.Getuid(), gid: os.Getgid()}
	if err := ensureLogDir(dir, own); err != nil {
		t.Fatalf("ensureLogDir: %v", err)
	}

	assertMode(t, dir, LogDirMode)
	for _, f := range logFiles(dir, own) {
		assertMode(t, f.path, LogFileMode)
		fi, err := os.Stat(f.path)
		if err != nil {
			t.Fatalf("stat %s: %v", f.path, err)
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			if int(st.Uid) != f.uid {
				t.Errorf("%s owner uid = %d, want %d", f.path, st.Uid, f.uid)
			}
			if int(st.Gid) != own.gid {
				t.Errorf("%s owner gid = %d, want %d", f.path, st.Gid, own.gid)
			}
		}
	}

	// O_CREATE without O_TRUNC: repairing an install must not throw away the
	// log lines that are the reason someone is repairing it.
	if content, err := os.ReadFile(server); err != nil || string(content) != "an existing line\n" {
		t.Errorf("server.log content = %q (err %v), want it preserved", content, err)
	}
	assertMode(t, stranger, 0o644)

	// Idempotent: asking again for an already-correct tree is a no-op success.
	if err := ensureLogDir(dir, own); err != nil {
		t.Errorf("second ensureLogDir must be a no-op success, got %v", err)
	}
	assertMode(t, dir, LogDirMode)
}

func TestRemoveSymlink(t *testing.T) {
	sys := darwinSystem{}

	for _, tc := range []struct {
		name string
		// setup returns the link path to ask about and the target to judge it
		// against.
		setup       func(t *testing.T, root string) (link, target string)
		wantRemoved bool
		wantErr     string
		// wantGone asserts the path is absent afterwards; otherwise it must
		// still be there, untouched.
		wantGone bool
	}{
		{
			name: "a link pointing at our target is removed",
			setup: func(t *testing.T, root string) (string, string) {
				target := filepath.Join(root, "Library", "k3sm")
				link := filepath.Join(root, "k3sm")
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
				return link, target
			},
			wantRemoved: true,
			wantGone:    true,
		},
		{
			name: "a link pointing somewhere else is kept",
			setup: func(t *testing.T, root string) (string, string) {
				link := filepath.Join(root, "k3sm")
				if err := os.Symlink(filepath.Join(root, "somebody-else"), link); err != nil {
					t.Fatal(err)
				}
				return link, filepath.Join(root, "Library", "k3sm")
			},
		},
		{
			name: "a regular file is never removed",
			setup: func(t *testing.T, root string) (string, string) {
				link := filepath.Join(root, "k3sm")
				writeFile(t, link)
				return link, filepath.Join(root, "Library", "k3sm")
			},
		},
		{
			name: "an absent link is a quiet no-op",
			setup: func(t *testing.T, root string) (string, string) {
				return filepath.Join(root, "k3sm"), filepath.Join(root, "Library", "k3sm")
			},
			wantGone: true,
		},
		{
			name: "a relative link path is refused",
			setup: func(t *testing.T, root string) (string, string) {
				return "usr/local/bin/k3sm", filepath.Join(root, "Library", "k3sm")
			},
			wantErr: "non-absolute",
			// Nothing was ever created at a relative path.
			wantGone: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			link, target := tc.setup(t, root)
			removed, err := sys.RemoveSymlink(link, target)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("RemoveSymlink(%q, %q) error = %v, want it to contain %q", link, target, err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatalf("RemoveSymlink(%q, %q): %v", link, target, err)
			}
			if removed != tc.wantRemoved {
				t.Errorf("removed = %v, want %v", removed, tc.wantRemoved)
			}
			_, statErr := os.Lstat(link)
			if tc.wantGone && statErr == nil {
				t.Errorf("%s must be gone", link)
			}
			if !tc.wantGone && statErr != nil {
				t.Errorf("%s must be left in place, got %v", link, statErr)
			}
		})
	}
}

// mkdir creates dir with an explicit mode. MkdirAll applies the process umask, so
// the mode is re-applied with Chmod — the group-writable cases depend on the bits
// actually landing.
func mkdir(t *testing.T, dir string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(dir, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("not a symlink\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// assertNoTemps proves the atomic-replacement temp link never survives a run —
// a leaked `k3sm.k3sm-tmp-<pid>` in /usr/local/bin would be litter in a directory
// k3sm was trusted with.
func assertNoTemps(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return // the case never created the directory
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".k3sm-tmp-") {
			t.Errorf("leaked temp link %s in %s", e.Name(), dir)
		}
	}
}

// stagingSystem is the System seam with the three methods stageJoinToken drives
// backed by the REAL filesystem, at the test process's own identity.
//
// The rest of the seam comes from the package's fake, which is never reached
// here: staging reads a file, judges its mode, and writes a copy, and all three
// of those are filesystem judgements a fake could only assert its own model of.
// The owner is this process because chowning to _k3sm needs privilege these
// tests never take, and what is under test is the mode, the repair and the
// temp-and-rename rather than whether this process may give a file away.
type stagingSystem struct {
	*fakeSystem
	uid, gid int
}

func (s stagingSystem) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

func (s stagingSystem) FileMode(path string) (fs.FileMode, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return fi.Mode().Perm(), nil
}

func (s stagingSystem) WriteServiceUserFile(path string, contents []byte, _ uint32, mode, dirMode fs.FileMode) error {
	return writeServiceUserFile(path, contents, s.uid, s.gid, mode, dirMode)
}

// TestWriteServiceUserFileOnDisk is the on-disk half of the staged-token write.
//
// The fake records what the installer ASKED for; only this proves the darwin
// implementation does it. Everything it checks is a property a credential
// depends on: the directory and the file end up at the modes the caller named,
// a tree an earlier build left open is repaired rather than trusted, the
// temp-and-rename leaves nothing behind, and a parent that cannot be created is
// an error rather than a half-written token.
//
// Unprivileged, in a per-case t.TempDir(), with the process's own uid and gid —
// see stagingSystem for why the owner is not _k3sm.
func TestWriteServiceUserFileOnDisk(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	const token = "K10abc123::node:s3cr3t\n"

	assertOwner := func(t *testing.T, path string) {
		t.Helper()
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return
		}
		if int(st.Uid) != uid || int(st.Gid) != gid {
			t.Errorf("%s owner = %d:%d, want %d:%d", path, st.Uid, st.Gid, uid, gid)
		}
	}
	// noTempLeft asserts the directory holds exactly the names given. The
	// temp-and-rename creates a .k3sm-* file in the SAME directory (a rename
	// cannot cross a filesystem), so a leaked temp is a second copy of a
	// credential sitting beside the one that was wanted.
	noTempLeft := func(t *testing.T, dir string, want ...string) {
		t.Helper()
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		var got []string
		for _, e := range entries {
			got = append(got, e.Name())
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s holds %v, want exactly %v (a leaked temp file is a second copy of the token)", dir, got, want)
		}
	}

	t.Run("a fresh tree gets the directory and the file at the modes asked for", func(t *testing.T) {
		root := t.TempDir()
		dir := filepath.Join(root, agentWorkSubdir)
		path := filepath.Join(dir, agentTokenName)

		if err := writeServiceUserFile(path, []byte(token), uid, gid, AgentTokenFileMode, AgentTokenDirMode); err != nil {
			t.Fatalf("writeServiceUserFile: %v", err)
		}
		assertMode(t, dir, AgentTokenDirMode)
		assertMode(t, path, AgentTokenFileMode)
		assertOwner(t, dir)
		assertOwner(t, path)
		content, err := os.ReadFile(path)
		if err != nil || string(content) != token {
			t.Errorf("content = %q (err %v), want the token", content, err)
		}
		noTempLeft(t, dir, agentTokenName)
	})

	t.Run("an open tree from an earlier build is repaired, not trusted", func(t *testing.T) {
		root := t.TempDir()
		dir := filepath.Join(root, agentWorkSubdir)
		path := filepath.Join(dir, agentTokenName)
		// What a hand-run mkdir, or a build that wrote the token with the
		// prevailing umask, leaves behind: a directory every account can enter
		// and a credential every account can read.
		mkdir(t, dir, 0o755)
		if err := os.WriteFile(path, []byte("K10stale::node:old\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}

		if err := writeServiceUserFile(path, []byte(token), uid, gid, AgentTokenFileMode, AgentTokenDirMode); err != nil {
			t.Fatalf("writeServiceUserFile: %v", err)
		}
		assertMode(t, dir, AgentTokenDirMode)
		assertMode(t, path, AgentTokenFileMode)
		content, err := os.ReadFile(path)
		if err != nil || string(content) != token {
			t.Errorf("content = %q (err %v), want the new token to have replaced the stale one", content, err)
		}
		noTempLeft(t, dir, agentTokenName)
	})

	t.Run("a parent that cannot be created is an error and changes nothing", func(t *testing.T) {
		root := t.TempDir()
		// A regular file exactly where the directory has to go. MkdirAll cannot
		// proceed, and the one thing that must not happen is a partial write or
		// a mangled file in its place.
		blocker := filepath.Join(root, agentWorkSubdir)
		const notADir = "someone else's file\n"
		if err := os.WriteFile(blocker, []byte(notADir), 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(blocker, agentTokenName)

		if err := writeServiceUserFile(path, []byte(token), uid, gid, AgentTokenFileMode, AgentTokenDirMode); err == nil {
			t.Fatal("writeServiceUserFile succeeded with a regular file where the directory belongs")
		}
		content, err := os.ReadFile(blocker)
		if err != nil || string(content) != notADir {
			t.Errorf("the blocking file is now %q (err %v), want it untouched", content, err)
		}
		assertMode(t, blocker, 0o600)
	})

	t.Run("staging never modifies the operator's own file", func(t *testing.T) {
		root := t.TempDir()
		src := filepath.Join(root, "operator-token")
		if err := os.WriteFile(src, []byte(token), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(src, 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := Config{DataRoot: filepath.Join(root, "data"), TokenFile: src}.withDefaults()
		sys := stagingSystem{fakeSystem: &fakeSystem{}, uid: uid, gid: gid}

		// Read the way Install reads it — once, at the preflight — and stage those
		// bytes: the two halves are separate functions now, and this is the pair.
		tokenText, _, err := operatorJoinToken(sys, cfg)
		if err != nil {
			t.Fatalf("operatorJoinToken: %v", err)
		}
		if err := stageJoinToken(sys, cfg, uint32(uid), tokenText); err != nil {
			t.Fatalf("stageJoinToken: %v", err)
		}
		staged, err := os.ReadFile(cfg.agentTokenPath())
		if err != nil || strings.TrimSpace(string(staged)) != strings.TrimSpace(token) {
			t.Fatalf("staged copy = %q (err %v), want the token", staged, err)
		}
		assertMode(t, cfg.agentTokenPath(), AgentTokenFileMode)
		// The operator's file is theirs: same bytes, same mode, still there. The
		// installer reads it and nothing else — deleting it is the operator's
		// decision, after the node is Ready.
		content, err := os.ReadFile(src)
		if err != nil || string(content) != token {
			t.Errorf("the operator's file = %q (err %v), want it untouched", content, err)
		}
		assertMode(t, src, 0o600)
	})

	t.Run("staging refuses an operator file anyone can read", func(t *testing.T) {
		root := t.TempDir()
		src := filepath.Join(root, "operator-token")
		if err := os.WriteFile(src, []byte(token), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(src, 0o644); err != nil {
			t.Fatal(err)
		}
		cfg := Config{DataRoot: filepath.Join(root, "data"), TokenFile: src}.withDefaults()
		sys := stagingSystem{fakeSystem: &fakeSystem{}, uid: uid, gid: gid}

		// The mode refusal belongs to the ONE reader of the operator's file, which
		// runs at the preflight before anything is written; staging never sees the
		// bytes of a file that was refused there.
		_, _, err := operatorJoinToken(sys, cfg)
		if err == nil {
			t.Fatal("operatorJoinToken accepted a world-readable join token file")
		}
		if !strings.Contains(err.Error(), "chmod 600") {
			t.Errorf("error %q does not name the remedy", err)
		}
		if strings.Contains(err.Error(), strings.TrimSpace(token)) {
			t.Errorf("the refusal echoed the token: %q", err)
		}
		if _, statErr := os.Stat(cfg.agentTokenPath()); statErr == nil {
			t.Error("a refused token was staged anyway")
		}
	})
}

// TestWriteLaunchDaemonMode pins the plist writer's MODE half against a real
// filesystem: the mode asked for is the mode on disk, and a REWRITE tightens an
// existing wider mode rather than inheriting it.
//
// The rewrite case is the one that matters. os.WriteFile applies its mode only
// when it creates the file, so without the explicit chmod every Mac installed by
// an earlier build would have kept its 0644 server plist through the install
// that was supposed to tighten it, with nothing to show for the change.
//
// Ownership (root:wheel) is the one-line method above and is not exercised here:
// chowning a file to root needs privilege these tests never take.
func TestWriteLaunchDaemonMode(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()

	t.Run("a fresh plist is written at the mode asked for", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "daemons", ServerLabel+".plist")
		if err := writeLaunchDaemon(path, []byte("<plist/>"), ServerPlistMode, uid, gid); err != nil {
			t.Fatalf("writeLaunchDaemon: %v", err)
		}
		assertMode(t, path, ServerPlistMode)
	})

	t.Run("a rewrite over a world-readable plist tightens it", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ServerLabel+".plist")
		// The file an earlier build left: the admin token on the argv, 0644.
		if err := os.WriteFile(path, []byte("<plist>--token k3sm-old</plist>"), PlistMode); err != nil {
			t.Fatalf("seed the legacy plist: %v", err)
		}
		if err := writeLaunchDaemon(path, []byte("<plist/>"), ServerPlistMode, uid, gid); err != nil {
			t.Fatalf("writeLaunchDaemon: %v", err)
		}
		assertMode(t, path, ServerPlistMode)
		got, err := os.ReadFile(path)
		if err != nil || string(got) != "<plist/>" {
			t.Errorf("content = %q (err %v), want the rewritten plist", got, err)
		}
	})

	t.Run("every other daemon keeps the conventional mode", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), NetdLabel+".plist")
		if err := writeLaunchDaemon(path, []byte("<plist/>"), plistMode(NetdLabel), uid, gid); err != nil {
			t.Fatalf("writeLaunchDaemon: %v", err)
		}
		assertMode(t, path, PlistMode)
	})
}

// TestReadRegularFileOnDisk exercises the no-follow read against a REAL
// filesystem, because the one thing it has to do cannot be observed through a
// fake: whether the kernel refuses the open. A fake asserts the test's own model
// of O_NOFOLLOW; only a real symlink proves the flag is on the open call.
//
// Unprivileged and serial, like every other on-disk table here.
func TestReadRegularFileOnDisk(t *testing.T) {
	t.Run("a regular file reads back verbatim", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "node.key")
		if err := os.WriteFile(path, []byte("the key bytes"), 0o600); err != nil {
			t.Fatalf("seed: %v", err)
		}
		got, err := readRegularFile(path)
		if err != nil {
			t.Fatalf("readRegularFile: %v", err)
		}
		if string(got) != "the key bytes" {
			t.Errorf("read %q, want %q", got, "the key bytes")
		}
	})

	t.Run("a symlink is refused and its target never read", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "somebody-elses-secret")
		if err := os.WriteFile(target, []byte("not this node's key"), 0o600); err != nil {
			t.Fatalf("seed: %v", err)
		}
		path := filepath.Join(dir, "node.key")
		if err := os.Symlink(target, path); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		got, err := readRegularFile(path)
		if err == nil {
			t.Fatalf("readRegularFile followed the symlink and returned %q", got)
		}
		if !errors.Is(err, ErrNotRegularFile) {
			t.Errorf("error %v does not match ErrNotRegularFile (callers tell this apart from absence)", err)
		}
		if strings.Contains(string(got), "not this node's key") {
			t.Errorf("the target's bytes were returned: %q", got)
		}
	})

	t.Run("a directory is refused", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "node.key")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if _, err := readRegularFile(path); !errors.Is(err, ErrNotRegularFile) {
			t.Errorf("readRegularFile on a directory = %v, want ErrNotRegularFile", err)
		}
	})

	t.Run("a missing file keeps the fs.ErrNotExist posture", func(t *testing.T) {
		_, err := readRegularFile(filepath.Join(t.TempDir(), "node.key"))
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("readRegularFile on a missing path = %v, want an fs.ErrNotExist (absence is a posture, not a failure)", err)
		}
	})
}

// TestAdoptTreeWalksByDescriptorAndNeverFollowsASymlink exercises the REAL
// adoption walk against a REAL filesystem, unprivileged.
//
// It is the half of B327 a fake cannot assert. The fake in install_test.go
// models the policy — which entries are adopted, in which order — but it has no
// descriptors, so the property this walk exists for (the object acted on is the
// object that was classified, even though a pod running as the service user can
// rename and re-link underneath it) is only observable here.
//
// Privilege is avoided the way ensureContainerLogDir's tests avoid it: adoptTree
// takes the uid it takes FROM and the uid it gives TO explicitly, so this test
// hands the tree from the test process to the test process. Every syscall on the
// path — openat, fstatat, fchown, fchownat — runs exactly as it does at install
// time; only the numbers are the caller's own.
//
// The symlink property is asserted by COUNT rather than by ownership, because a
// chown to one's own uid is invisible: the link points at a directory holding a
// file that WOULD be adopted if the walk followed it, so a walk that followed
// reports one more adoption than a walk that did not.
func TestAdoptTreeWalksByDescriptorAndNeverFollowsASymlink(t *testing.T) {
	me, myGroup := os.Getuid(), os.Getgid()

	t.Run("a pod tree is adopted parent-first and a planted symlink is stepped over", func(t *testing.T) {
		base := t.TempDir()
		root := filepath.Join(base, "pods")
		// What a walk that followed the link would reach: a directory outside
		// the tree, holding a file that satisfies every adoption rule.
		outside := filepath.Join(base, "outside")
		mkdirAllT(t, filepath.Join(outside, "container"))
		writeFileT(t, filepath.Join(outside, "container", "0.log"), "not yours")

		podDir := filepath.Join(root, "default_web-0_9f1c")
		mkdirAllT(t, filepath.Join(podDir, "web"))
		writeFileT(t, filepath.Join(podDir, "web", "0.log"), "hello")
		// Plantable by any process running as the service user, which every
		// native pod is, for the whole of an install.
		if err := os.Symlink(outside, filepath.Join(podDir, "escape")); err != nil {
			t.Fatalf("plant the symlink: %v", err)
		}
		// Debris at the root: neither is the <ns>_<pod>_<uid> shape.
		writeFileT(t, filepath.Join(root, "rotation.state"), "x")
		mkdirAllT(t, filepath.Join(root, "not-a-pod-dir", "deep"))

		rep, err := adoptTree(root, me, me, myGroup, podLogWalkMaxDepth, AdoptPodDirs)
		if err != nil {
			t.Fatalf("adoptTree: %v", err)
		}
		// The pod dir, its container dir and the log file. Not the escape link,
		// not anything through it, not the debris at the root.
		if rep.Adopted != 3 {
			t.Errorf("adopted %d entries, want 3 (the pod dir, its container dir, its log file); skipped = %v", rep.Adopted, rep.Skipped)
		}
		for _, want := range []string{
			filepath.Join(podDir, "escape"),
			filepath.Join(root, "rotation.state"),
			filepath.Join(root, "not-a-pod-dir"),
		} {
			if !skipReported(rep, want) {
				t.Errorf("%s was not reported to the operator; skipped = %v", want, rep.Skipped)
			}
		}
		// The link is still a link, pointing where it did: the walk neither
		// followed it nor replaced it.
		if got, err := os.Readlink(filepath.Join(podDir, "escape")); err != nil || got != outside {
			t.Errorf("the escape link is now %q (err %v), want %q untouched", got, err, outside)
		}
		// And nothing inside the tree was removed — this step is not a deleter.
		if _, err := os.Stat(filepath.Join(podDir, "web", "0.log")); err != nil {
			t.Errorf("the log file is gone: %v", err)
		}
	})

	t.Run("a symlink at the root of the tree is refused by O_NOFOLLOW rather than followed", func(t *testing.T) {
		base := t.TempDir()
		real := filepath.Join(base, "real")
		mkdirAllT(t, filepath.Join(real, "default_web-0_9f1c"))
		root := filepath.Join(base, "pods")
		if err := os.Symlink(real, root); err != nil {
			t.Fatalf("link the root: %v", err)
		}
		if _, err := adoptTree(root, me, me, myGroup, podLogWalkMaxDepth, AdoptPodDirs); err == nil {
			t.Fatal("adoptTree walked a tree whose root is a symlink")
		}
	})

	t.Run("the link directory hands over the links themselves and nothing they point at", func(t *testing.T) {
		base := t.TempDir()
		dir := filepath.Join(base, "containers")
		mkdirAllT(t, dir)
		target := filepath.Join(base, "pods", "default_web-0_9f1c", "web")
		mkdirAllT(t, target)
		writeFileT(t, filepath.Join(target, "0.log"), "hello")
		if err := os.Symlink(filepath.Join(target, "0.log"), filepath.Join(dir, "web-0_default_web-abc123.log")); err != nil {
			t.Fatalf("link: %v", err)
		}
		// A directory has no business here and is not a log link.
		mkdirAllT(t, filepath.Join(dir, "stray"))

		rep, err := adoptTree(dir, me, me, myGroup, 1, AdoptLogLinks)
		if err != nil {
			t.Fatalf("adoptTree: %v", err)
		}
		if rep.Adopted != 1 {
			t.Errorf("adopted %d entries, want 1 (the link itself); skipped = %v", rep.Adopted, rep.Skipped)
		}
		if !skipReported(rep, filepath.Join(dir, "stray")) {
			t.Errorf("the stray directory was not reported; skipped = %v", rep.Skipped)
		}
		// The link still resolves, and its target still exists: an lchown moves
		// the link, and nothing here ever touched the file it names.
		if _, err := os.Stat(filepath.Join(target, "0.log")); err != nil {
			t.Errorf("the link's target is gone: %v", err)
		}
	})

	t.Run("an absent tree keeps the missing-entry contract", func(t *testing.T) {
		_, err := adoptTree(filepath.Join(t.TempDir(), "nope"), me, me, myGroup, podLogWalkMaxDepth, AdoptPodDirs)
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("adoptTree on a missing tree = %v, want an fs.ErrNotExist", err)
		}
	})

	t.Run("the depth bound stops a tree deeper than k3sm walks", func(t *testing.T) {
		base := t.TempDir()
		root := filepath.Join(base, "pods")
		deep := filepath.Join(root, "default_web-0_9f1c")
		for i := 0; i < 6; i++ {
			deep = filepath.Join(deep, "d")
		}
		mkdirAllT(t, deep)
		writeFileT(t, filepath.Join(deep, "0.log"), "hello")

		rep, err := adoptTree(root, me, me, myGroup, 3, AdoptPodDirs)
		if err != nil {
			t.Fatalf("adoptTree: %v", err)
		}
		// The pod dir and two levels below it, and then a report instead of a
		// descent.
		if rep.Adopted != 3 {
			t.Errorf("adopted %d entries, want 3 under a depth bound of 3; skipped = %v", rep.Adopted, rep.Skipped)
		}
		if len(rep.Skipped) != 1 || !strings.Contains(rep.Skipped[0].Reason, "deeper than") {
			t.Errorf("skipped = %v, want one entry reported as too deep", rep.Skipped)
		}
	})
}

// skipReported reports whether path is one of the entries the walk told the
// operator about.
func skipReported(rep TreeAdoption, path string) bool {
	for _, s := range rep.Skipped {
		if s.Path == path {
			return true
		}
	}
	return false
}

// mkdirAllT and writeFileT are the two-line fixtures these cases build trees
// from; they fail the test rather than returning an error, because a fixture
// that cannot be laid down is not a result.
func mkdirAllT(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
}

func writeFileT(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
