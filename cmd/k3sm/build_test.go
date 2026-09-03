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
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/oci"
)

// time0 is the fixed timestamp the builder writes to every tar header and to the
// image config.
func time0() time.Time { return time.Unix(0, 0).UTC() }

func timeAt(sec int64) time.Time { return time.Unix(sec, 0) }

// mkfifo creates a FIFO so the type-allowlist row exercises a real non-regular
// file rather than a fake. It needs no privilege.
func mkfifo(t *testing.T, path string) {
	t.Helper()
	if err := unix.Mkfifo(path, 0o644); err != nil {
		t.Fatalf("mkfifo %s: %v", path, err)
	}
}

// TestCopyOnlyDockerfileBuild is B118's acceptance gate. It proves, in one test:
//
//   - the Dockerfile subset parse table — every accepted verb, the RUN rejection
//     (whose message must name the vm-backed builder), the known-but-unsupported
//     verbs, unknown verbs, and the syntax classes a subset parser would
//     otherwise mis-read;
//   - build-context containment — no COPY may read outside the context, by any
//     of five routes;
//   - deterministic layer digests — the SAME LOGICAL context materialized twice
//     in different directories with different on-disk mtimes and modes yields
//     byte-identical layer and image digests;
//   - the entrypoint/env/workdir metadata round-trip through the emitted config.
func TestCopyOnlyDockerfileBuild(t *testing.T) {
	t.Parallel()

	t.Run("parse", testParseTable)
	t.Run("containment", testContainment)
	t.Run("determinism", testDeterminism)
	t.Run("config", testConfigRoundTrip)
	t.Run("output", testOutputSinks)
	t.Run("cli", testBuildCLI)
}

// ---------------------------------------------------------------- parse table

func testParseTable(t *testing.T) {
	t.Parallel()

	accepted := []struct {
		name string
		in   string
	}{
		{"from-scratch", "FROM scratch"},
		{"from-lowercase-verb", "from scratch"},
		{"from-as-named-single-stage", "FROM scratch AS build"},
		{"copy-single", "FROM scratch\nCOPY app /app"},
		{"copy-multi-source-dir-dest", "FROM scratch\nCOPY a b /dir/"},
		{"copy-json-array-form", "FROM scratch\nCOPY [\"app\", \"/app\"]"},
		{"add-local-file-alias-of-copy", "FROM scratch\nADD app /app"},
		{"env-equals-form", "FROM scratch\nENV K=V"},
		{"env-legacy-space-form", "FROM scratch\nENV K some value"},
		{"env-multi-pair-one-line", "FROM scratch\nENV A=1 B=2"},
		{"env-quoted-value-with-spaces", `FROM scratch` + "\n" + `ENV K="a b"`},
		{"entrypoint-json-exec-form", "FROM scratch\nENTRYPOINT [\"/app\", \"-f\"]"},
		{"entrypoint-shell-form", "FROM scratch\nENTRYPOINT /app -f"},
		{"cmd-json-exec-form", "FROM scratch\nCMD [\"-v\"]"},
		{"cmd-shell-form", "FROM scratch\nCMD /app"},
		{"workdir-absolute", "FROM scratch\nWORKDIR /srv"},
		{"workdir-relative-accumulates", "FROM scratch\nWORKDIR /srv\nWORKDIR app"},
		{"label-single", "FROM scratch\nLABEL a=b"},
		{"label-multi-pair", "FROM scratch\nLABEL a=b c=d"},
		{"expose-bare-port", "FROM scratch\nEXPOSE 8080"},
		{"expose-explicit-tcp", "FROM scratch\nEXPOSE 8080/tcp"},
		{"expose-udp", "FROM scratch\nEXPOSE 53/udp"},
		{"expose-multiple-ports", "FROM scratch\nEXPOSE 80 443"},
		{"comments-interleaved", "# hi\nFROM scratch\n# there\nCOPY app /app"},
		{"line-continuation", "FROM scratch\nCOPY \\\n  app /app"},
		{"crlf-line-endings", "FROM scratch\r\nCOPY app /app\r\n"},
		{"blank-lines-before-from", "\n\n\nFROM scratch"},
	}
	for _, tc := range accepted {
		t.Run("accept/"+tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := oci.Parse(strings.NewReader(tc.in)); err != nil {
				t.Fatalf("Parse(%q) = %v, want nil", tc.in, err)
			}
		})
	}

	rejected := []struct {
		name string
		in   string
		want error
	}{
		{"run", "FROM scratch\nRUN make", oci.ErrRunUnsupported},
		{"run-lowercase", "FROM scratch\nrun make", oci.ErrRunUnsupported},
		{"run-on-last-line", "FROM scratch\nCOPY app /app\nRUN make", oci.ErrRunUnsupported},
		{"user", "FROM scratch\nUSER nobody", oci.ErrUnsupportedInstruction},
		{"volume", "FROM scratch\nVOLUME /data", oci.ErrUnsupportedInstruction},
		{"healthcheck", "FROM scratch\nHEALTHCHECK CMD x", oci.ErrUnsupportedInstruction},
		{"shell", "FROM scratch\nSHELL [\"/bin/sh\"]", oci.ErrUnsupportedInstruction},
		{"stopsignal", "FROM scratch\nSTOPSIGNAL SIGTERM", oci.ErrUnsupportedInstruction},
		{"onbuild", "FROM scratch\nONBUILD COPY a b", oci.ErrUnsupportedInstruction},
		{"arg", "FROM scratch\nARG V=1", oci.ErrUnsupportedInstruction},
		{"maintainer", "FROM scratch\nMAINTAINER me", oci.ErrUnsupportedInstruction},
		{"unknown-verb", "FROM scratch\nFROBNICATE x", oci.ErrUnknownInstruction},
		// A malformed reference is still a PARSE rejection, reported with its line
		// before any output is opened. A WELL-FORMED one is no longer rejected here:
		// the parser accepts it and Build refuses it when no resolver is configured
		// (see reject-at-build/named-base-without-resolver below).
		{"from-malformed-ref", "FROM UPPER CASE:!!", oci.ErrBadInstruction},
		{"multi-stage-second-from", "FROM scratch\nFROM scratch", oci.ErrUnsupportedSyntax},
		{"heredoc", "FROM scratch\nCOPY <<EOF /f", oci.ErrUnsupportedSyntax},
		{"syntax-directive", "# syntax=docker/dockerfile:1\nFROM scratch", oci.ErrUnsupportedSyntax},
		{"escape-directive", "# escape=`\nFROM scratch", oci.ErrUnsupportedSyntax},
		{"copy-from-flag", "FROM scratch\nCOPY --from=build a b", oci.ErrUnsupportedSyntax},
		{"copy-chown-flag", "FROM scratch\nCOPY --chown=1:1 a b", oci.ErrUnsupportedSyntax},
		{"copy-chmod-flag", "FROM scratch\nCOPY --chmod=755 a b", oci.ErrUnsupportedSyntax},
		{"copy-variable-in-path", "FROM scratch\nCOPY $HOME/x /x", oci.ErrUnsupportedSyntax},
		{"workdir-variable", "FROM scratch\nWORKDIR $HOME", oci.ErrUnsupportedSyntax},
		{"add-remote-url", "FROM scratch\nADD https://example.com/x /x", oci.ErrRemoteSource},
		{"add-remote-url-plain-http", "FROM scratch\nADD http://example.com/x /x", oci.ErrRemoteSource},
		{"add-local-tar-autoextract", "FROM scratch\nADD bundle.tar.gz /", oci.ErrArchiveAutoExtract},
		{"add-local-tgz-autoextract", "FROM scratch\nADD bundle.tgz /", oci.ErrArchiveAutoExtract},
		{"empty-file", "", oci.ErrMissingFrom},
		{"comments-only", "# nothing here", oci.ErrMissingFrom},
		{"from-missing", "COPY a b", oci.ErrMissingFrom},
		{"from-not-first", "ENV A=1\nFROM scratch", oci.ErrMissingFrom},
		{"copy-zero-args", "FROM scratch\nCOPY", oci.ErrBadInstruction},
		{"copy-one-arg", "FROM scratch\nCOPY only", oci.ErrBadInstruction},
		{"env-no-value", "FROM scratch\nENV K", oci.ErrBadInstruction},
		{"label-not-key-value", "FROM scratch\nLABEL nope", oci.ErrBadInstruction},
		{"expose-not-a-port", "FROM scratch\nEXPOSE http", oci.ErrBadInstruction},
		{"expose-bad-protocol", "FROM scratch\nEXPOSE 80/sctp", oci.ErrBadInstruction},
		{"unterminated-continuation", "FROM scratch\nCOPY a \\", oci.ErrBadInstruction},
		{"unterminated-quote", "FROM scratch\nENV K=\"unclosed", oci.ErrBadInstruction},
		{"malformed-json-array", "FROM scratch\nCMD [\"a\",", oci.ErrBadInstruction},
	}
	for _, tc := range rejected {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := oci.Parse(strings.NewReader(tc.in))
			if !errors.Is(err, tc.want) {
				t.Fatalf("Parse(%q) = %v, want %v", tc.in, err, tc.want)
			}
		})
	}

	// The RUN rejection is the security boundary of this whole feature, so its
	// message must route the operator to the RUN-capable path rather than just
	// saying no. A bare non-nil error fails this row.
	t.Run("reject/run-message-names-vm-builder", func(t *testing.T) {
		t.Parallel()
		_, err := oci.Parse(strings.NewReader("FROM scratch\nRUN make"))
		if err == nil {
			t.Fatal("Parse accepted RUN")
		}
		msg := err.Error()
		for _, want := range []string{"RUN", "vm"} {
			if !strings.Contains(msg, want) {
				t.Errorf("RUN error %q does not mention %q", msg, want)
			}
		}
	})
}

// ----------------------------------------------------------------- containment

func testContainment(t *testing.T) {
	t.Parallel()

	// A file outside the context that must never appear in any image.
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.key")
	if err := os.WriteFile(secret, []byte("PRIVATE KEY"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		setup   func(t *testing.T, ctxDir string)
		docker  string
		want    error
		wantErr bool
		check   func(t *testing.T, entries []tarEntry)
	}{
		{
			name:    "relative-parent-escape",
			docker:  "FROM scratch\nCOPY ../secret.key /k",
			want:    oci.ErrContextEscape,
			wantErr: true,
		},
		{
			name:    "deep-parent-escape",
			docker:  "FROM scratch\nCOPY ../../../../etc/passwd /k",
			want:    oci.ErrContextEscape,
			wantErr: true,
		},
		{
			name: "symlink-escape",
			setup: func(t *testing.T, ctxDir string) {
				if err := os.Symlink(secret, filepath.Join(ctxDir, "link")); err != nil {
					t.Fatal(err)
				}
			},
			docker:  "FROM scratch\nCOPY link /k",
			want:    oci.ErrContextEscape,
			wantErr: true,
		},
		{
			name: "escaping-symlink-directory-component",
			setup: func(t *testing.T, ctxDir string) {
				if err := os.Symlink(outside, filepath.Join(ctxDir, "sub")); err != nil {
					t.Fatal(err)
				}
			},
			docker:  "FROM scratch\nCOPY sub/secret.key /k",
			want:    oci.ErrContextEscape,
			wantErr: true,
		},
		{
			name: "glob-expansion-selects-escaping-symlink",
			setup: func(t *testing.T, ctxDir string) {
				if err := os.Symlink(secret, filepath.Join(ctxDir, "a-link")); err != nil {
					t.Fatal(err)
				}
			},
			docker:  "FROM scratch\nCOPY a-* /d/",
			want:    oci.ErrContextEscape,
			wantErr: true,
		},
		{
			name: "fifo-is-refused-not-skipped",
			setup: func(t *testing.T, ctxDir string) {
				mkfifo(t, filepath.Join(ctxDir, "pipe"))
			},
			docker:  "FROM scratch\nCOPY pipe /p",
			want:    oci.ErrUnsupportedFileType,
			wantErr: true,
		},
		{
			name:    "missing-source",
			docker:  "FROM scratch\nCOPY nope /k",
			want:    oci.ErrSourceNotFound,
			wantErr: true,
		},
		{
			// Docker parity: an absolute source is context-root-relative. The
			// forbidden implementation reads the HOST /etc/passwd.
			name: "absolute-source-is-context-relative",
			setup: func(t *testing.T, ctxDir string) {
				if err := os.MkdirAll(filepath.Join(ctxDir, "etc"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(ctxDir, "etc", "passwd"), []byte("in-context"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			docker: "FROM scratch\nCOPY /etc/passwd /p",
			check: func(t *testing.T, entries []tarEntry) {
				// Asserting the BODY is what falsifies a host-reading
				// implementation: the host /etc/passwd contains neither the
				// marker string nor an unsafe name, so a name-only check passes
				// for the very bug this row exists to catch.
				var got string
				for _, e := range entries {
					if e.name == "p" {
						got = string(e.body)
					}
				}
				if got != "in-context" {
					t.Errorf("entry \"p\" body = %q, want %q (the host file was read)", got, "in-context")
				}
			},
		},
		{
			// Docker parity: "/.." is a no-op at the image root, so this is a
			// normalization case, not a rejection. The invariant that matters —
			// no emitted entry name escapes the image root — is asserted for
			// every case below, and directly in emitted-names-never-escape.
			name:   "destination-traversal-is-normalized",
			docker: "FROM scratch\nCOPY app /../../etc/passwd",
		},
		{
			name: "whiteout-source-name-is-refused",
			setup: func(t *testing.T, ctxDir string) {
				if err := os.WriteFile(filepath.Join(ctxDir, ".wh.evil"), []byte("x"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			docker:  "FROM scratch\nCOPY .wh.evil /d/.wh.evil",
			want:    oci.ErrBadEntryName,
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctxDir := t.TempDir()
			if err := os.WriteFile(filepath.Join(ctxDir, "app"), []byte("payload"), 0o755); err != nil {
				t.Fatal(err)
			}
			if tc.setup != nil {
				tc.setup(t, ctxDir)
			}
			img, err := buildFrom(t, tc.docker, ctxDir)
			if tc.wantErr {
				if !errors.Is(err, tc.want) {
					t.Fatalf("build = %v, want %v", err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("build = %v, want nil", err)
			}
			// The escape cases above must not merely error — no image k3sm
			// builds may ever contain the out-of-context bytes, and no emitted
			// entry name or symlink target may escape the image root.
			for _, e := range layerEntries(t, img) {
				if strings.Contains(string(e.body), "PRIVATE KEY") {
					t.Fatalf("entry %q carries out-of-context bytes", e.name)
				}
				assertSafeEntryName(t, e.name)
				assertSafeLinkname(t, e.name, e.hdr.Linkname)
			}
			if tc.check != nil {
				tc.check(t, layerEntries(t, img))
			}
		})
	}

	// A symlink can point upward through directories that EXIST inside the
	// context — so it resolves in-context and passes the source-side check —
	// while the entry it produces sits shallower in the image and escapes on
	// extraction. Paired with the parent dirs a later layer emits, that is a
	// write-through primitive against any unpacker that mkdir -p's a component
	// which is already a symlink.
	t.Run("symlink-target-escaping-image-root-is-refused", func(t *testing.T) {
		t.Parallel()
		ctxDir := t.TempDir()
		deep := filepath.Join(ctxDir, "a", "b", "c", "d", "e", "f")
		if err := os.MkdirAll(deep, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(ctxDir, "payload"), []byte("PAYLOAD"), 0o644); err != nil {
			t.Fatal(err)
		}
		// Resolves to <ctx>/payload — inside the context.
		if err := os.Symlink("../../../../../../payload", filepath.Join(deep, "esc")); err != nil {
			t.Fatal(err)
		}
		_, err := buildFrom(t, "FROM scratch\nCOPY a/b/c/d/e/f/esc /esc", ctxDir)
		if !errors.Is(err, oci.ErrBadEntryName) {
			t.Fatalf("build = %v, want ErrBadEntryName", err)
		}
	})

	// Colliding multi-source COPY: the dedup keeps the last of each equal-name
	// run, so the winner must be the last SOURCE. With an unstable sort the Go
	// runtime's pivot choice picks the winner instead, making the layer digest a
	// function of the toolchain. 12 names are used because the failure only
	// appears once pdqsort stops falling back to insertion sort.
	t.Run("colliding-multi-source-copy-last-source-wins", func(t *testing.T) {
		t.Parallel()
		ctxDir := t.TempDir()
		for _, sub := range []string{"sub1", "sub2"} {
			if err := os.MkdirAll(filepath.Join(ctxDir, sub), 0o755); err != nil {
				t.Fatal(err)
			}
			for i := range 12 {
				name := filepath.Join(ctxDir, sub, string(rune('a'+i)))
				if err := os.WriteFile(name, []byte(sub), 0o644); err != nil {
					t.Fatal(err)
				}
			}
		}
		img, err := buildFrom(t, "FROM scratch\nCOPY sub1 sub2 /dest/", ctxDir)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		n := 0
		for _, e := range layerEntries(t, img) {
			if e.hdr.Typeflag != tar.TypeReg {
				continue
			}
			n++
			if string(e.body) != "sub2" {
				t.Errorf("entry %q body = %q, want %q (last source must win)", e.name, e.body, "sub2")
			}
		}
		if n != 12 {
			t.Errorf("got %d regular entries, want 12", n)
		}
	})

	// A "."-terminated destination is a DIRECTORY, not a rename. Recognizing only
	// a trailing "/" silently writes the payload as a regular file at the
	// WORKDIR path.
	t.Run("dot-destination-is-a-directory", func(t *testing.T) {
		t.Parallel()
		ctxDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(ctxDir, "app"), []byte("payload"), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct{ name, docker, want string }{
			{"workdir-relative-dot", "FROM scratch\nWORKDIR /w\nCOPY app .", "w/app"},
			{"explicit-slash-dot", "FROM scratch\nCOPY app /w/.", "w/app"},
			{"root-dot", "FROM scratch\nCOPY app .", "app"},
		} {
			img, err := buildFrom(t, tc.docker, ctxDir)
			if err != nil {
				t.Fatalf("%s: build = %v", tc.name, err)
			}
			var names []string
			for _, e := range layerEntries(t, img) {
				if e.hdr.Typeflag == tar.TypeReg {
					names = append(names, e.name)
				}
			}
			if len(names) != 1 || names[0] != tc.want {
				t.Errorf("%s: regular entries = %v, want [%s]", tc.name, names, tc.want)
			}
		}
	})

	t.Run("in-image-relative-symlink-is-preserved", func(t *testing.T) {
		t.Parallel()
		ctxDir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(ctxDir, "d"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(ctxDir, "d", "real"), []byte("R"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("real", filepath.Join(ctxDir, "d", "link")); err != nil {
			t.Fatal(err)
		}
		img, err := buildFrom(t, "FROM scratch\nCOPY d /d/", ctxDir)
		if err != nil {
			t.Fatalf("build = %v, want nil (a legitimate relative link must survive)", err)
		}
		var found bool
		for _, e := range layerEntries(t, img) {
			if e.name == "d/link" {
				found = true
				if e.hdr.Linkname != "real" {
					t.Errorf("linkname = %q, want %q", e.hdr.Linkname, "real")
				}
			}
		}
		if !found {
			t.Error("the symlink entry was dropped")
		}
	})

	// The write-side invariant, stated once over a set of hostile destinations:
	// a pushed image is somebody else's untrusted input, so a builder that can
	// be made to emit a traversing entry or a whiteout is a tar-bomb factory.
	t.Run("emitted-names-never-escape", func(t *testing.T) {
		t.Parallel()
		ctxDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(ctxDir, "app"), []byte("payload"), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, df := range []string{
			"FROM scratch\nCOPY app /../../etc/passwd",
			"FROM scratch\nWORKDIR /../..\nCOPY app x",
			"FROM scratch\nWORKDIR /a/b\nWORKDIR ../../../..\nCOPY app x",
			"FROM scratch\nCOPY app /a/../../../b",
		} {
			img, err := buildFrom(t, df, ctxDir)
			if err != nil {
				t.Fatalf("build(%q) = %v", df, err)
			}
			for _, e := range layerEntries(t, img) {
				assertSafeEntryName(t, e.name)
			}
		}
	})
}

// assertSafeLinkname pins that no emitted symlink escapes the image root when
// resolved at its own depth.
func assertSafeLinkname(t *testing.T, name, link string) {
	t.Helper()
	if link == "" {
		return
	}
	if strings.HasPrefix(link, "/") {
		t.Errorf("entry %q targets the absolute path %q", name, link)
		return
	}
	resolved := path.Join(path.Dir(name), link)
	if resolved == ".." || strings.HasPrefix(resolved, "../") {
		t.Errorf("entry %q targets %q, which escapes the image root", name, link)
	}
}

// assertSafeEntryName pins the properties every emitted tar entry name must have.
func assertSafeEntryName(t *testing.T, name string) {
	t.Helper()
	if strings.HasPrefix(name, "/") {
		t.Errorf("entry %q is absolute", name)
	}
	if strings.Contains(name, `\`) || strings.ContainsRune(name, 0) {
		t.Errorf("entry %q contains a backslash or NUL", name)
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			t.Errorf("entry %q traverses upward", name)
		}
		if strings.HasPrefix(part, ".wh.") {
			t.Errorf("entry %q is an OCI whiteout marker", name)
		}
	}
}

// --------------------------------------------------------------- determinism

// testDeterminism proves the layer digest is a function of the CONTENT, not of
// the machine. Building twice in one process would pass even for a builder that
// reads os.Stat().ModTime() straight into the tar header, so the same logical
// context is materialized in two different directories with deliberately
// different on-disk mtimes and modes.
func testDeterminism(t *testing.T) {
	t.Parallel()

	const dockerfile = "FROM scratch\nCOPY bin/app /usr/local/bin/app\nCOPY etc /etc/\nENV A=1\nENTRYPOINT [\"/usr/local/bin/app\"]"

	a := goldenContext(t, contextSpec{mtime: 0, exec: 0o755, data: 0o644})
	b := goldenContext(t, contextSpec{mtime: 1_700_000_000, exec: 0o777, data: 0o600})

	imgA, err := buildFrom(t, dockerfile, a)
	if err != nil {
		t.Fatalf("build A: %v", err)
	}
	imgB, err := buildFrom(t, dockerfile, b)
	if err != nil {
		t.Fatalf("build B: %v", err)
	}

	digA, err := imgA.Digest()
	if err != nil {
		t.Fatal(err)
	}
	digB, err := imgB.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if digA != digB {
		t.Errorf("image digest differs across contexts: %s vs %s", digA, digB)
	}

	t.Run("layer-digests-equal", func(t *testing.T) {
		la, lb := layerDigests(t, imgA), layerDigests(t, imgB)
		if len(la) != len(lb) {
			t.Fatalf("layer count %d vs %d", len(la), len(lb))
		}
		for i := range la {
			if la[i] != lb[i] {
				t.Errorf("layer %d digest %s vs %s", i, la[i], lb[i])
			}
		}
	})

	t.Run("tar-headers-normalized", func(t *testing.T) {
		for _, e := range layerEntries(t, imgA) {
			if e.hdr.Uid != 0 || e.hdr.Gid != 0 {
				t.Errorf("%s: uid/gid = %d/%d, want 0/0", e.name, e.hdr.Uid, e.hdr.Gid)
			}
			if e.hdr.Uname != "" || e.hdr.Gname != "" {
				t.Errorf("%s: uname/gname = %q/%q, want empty", e.name, e.hdr.Uname, e.hdr.Gname)
			}
			if !e.hdr.ModTime.Equal(time0()) {
				t.Errorf("%s: mtime = %v, want epoch", e.name, e.hdr.ModTime)
			}
			switch e.hdr.Typeflag {
			case tar.TypeReg, tar.TypeDir, tar.TypeSymlink:
			default:
				t.Errorf("%s: typeflag %q outside the allowlist", e.name, string(e.hdr.Typeflag))
			}
			if len(e.hdr.Xattrs) != 0 { //nolint:staticcheck // asserting the field stays empty
				t.Errorf("%s: carries xattrs %v", e.name, e.hdr.Xattrs)
			}
		}
	})

	// Ordering is a PER-LAYER invariant: each COPY produces its own layer, and
	// layers follow instruction order, not name order.
	t.Run("tar-entry-order-is-sorted", func(t *testing.T) {
		for li, names := range layerEntryNames(t, imgA) {
			for i := 1; i < len(names); i++ {
				if names[i-1] > names[i] {
					t.Errorf("layer %d: entries out of order: %q before %q", li, names[i-1], names[i])
				}
			}
		}
	})

	t.Run("exec-bit-preserved-data-bit-normalized", func(t *testing.T) {
		for _, e := range layerEntries(t, imgA) {
			if e.hdr.Typeflag != tar.TypeReg {
				continue
			}
			want := int64(0o644)
			if strings.HasSuffix(e.name, "/app") {
				want = 0o755
			}
			if e.hdr.Mode != want {
				t.Errorf("%s: mode %o, want %o", e.name, e.hdr.Mode, want)
			}
		}
	})

	t.Run("config-created-is-epoch", func(t *testing.T) {
		cfg, err := imgA.ConfigFile()
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.Created.Time.Equal(time0()) {
			t.Errorf("config Created = %v, want epoch", cfg.Created.Time)
		}
		for i, h := range cfg.History {
			if !h.Created.Time.Equal(time0()) {
				t.Errorf("history[%d] Created = %v, want epoch", i, h.Created.Time)
			}
		}
	})
}

// ---------------------------------------------------------- config round-trip

func testConfigRoundTrip(t *testing.T) {
	t.Parallel()

	ctxDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(ctxDir, "app"), []byte("payload"), 0o755); err != nil {
		t.Fatal(err)
	}
	const dockerfile = `FROM scratch
COPY app /app
ENV A=1 B=2
ENV A=overridden
WORKDIR /srv
WORKDIR sub
LABEL org.example.a=1
LABEL org.example.a=2 org.example.b=3
EXPOSE 8080
EXPOSE 53/udp
ENTRYPOINT ["/app", "-f"]
CMD ["-v"]`

	img, err := buildFrom(t, dockerfile, ctxDir)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("platform-is-darwin-arm64-not-ggcr-default", func(t *testing.T) {
		if cfg.OS != "darwin" || cfg.Architecture != "arm64" {
			t.Fatalf("platform = %s/%s, want darwin/arm64", cfg.OS, cfg.Architecture)
		}
	})
	t.Run("env-override-replaces-in-place", func(t *testing.T) {
		want := []string{"A=overridden", "B=2"}
		if !equalSlice(cfg.Config.Env, want) {
			t.Errorf("Env = %v, want %v", cfg.Config.Env, want)
		}
	})
	t.Run("workdir-relative-accumulates", func(t *testing.T) {
		if cfg.Config.WorkingDir != "/srv/sub" {
			t.Errorf("WorkingDir = %q, want /srv/sub", cfg.Config.WorkingDir)
		}
	})
	t.Run("label-merge-last-wins", func(t *testing.T) {
		if got := cfg.Config.Labels["org.example.a"]; got != "2" {
			t.Errorf("label a = %q, want 2", got)
		}
		if got := cfg.Config.Labels["org.example.b"]; got != "3" {
			t.Errorf("label b = %q, want 3", got)
		}
	})
	t.Run("exposed-ports-map-shape", func(t *testing.T) {
		for _, want := range []string{"8080/tcp", "53/udp"} {
			if _, ok := cfg.Config.ExposedPorts[want]; !ok {
				t.Errorf("ExposedPorts missing %q (got %v)", want, cfg.Config.ExposedPorts)
			}
		}
	})
	t.Run("entrypoint-exec-form-verbatim", func(t *testing.T) {
		if !equalSlice(cfg.Config.Entrypoint, []string{"/app", "-f"}) {
			t.Errorf("Entrypoint = %v", cfg.Config.Entrypoint)
		}
	})
	t.Run("cmd-independent-of-entrypoint", func(t *testing.T) {
		if !equalSlice(cfg.Config.Cmd, []string{"-v"}) {
			t.Errorf("Cmd = %v", cfg.Config.Cmd)
		}
	})
	t.Run("shell-form-is-wrapped", func(t *testing.T) {
		img, err := buildFrom(t, "FROM scratch\nCOPY app /app\nENTRYPOINT /app -f", ctxDir)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := img.ConfigFile()
		if err != nil {
			t.Fatal(err)
		}
		if !equalSlice(cfg.Config.Entrypoint, []string{"/bin/sh", "-c", "/app -f"}) {
			t.Errorf("Entrypoint = %v", cfg.Config.Entrypoint)
		}
	})
	t.Run("one-diffid-per-copy", func(t *testing.T) {
		if len(cfg.RootFS.DiffIDs) != 1 {
			t.Errorf("DiffIDs = %d, want 1", len(cfg.RootFS.DiffIDs))
		}
	})
	t.Run("history-one-entry-per-instruction", func(t *testing.T) {
		// Every instruction but FROM contributes exactly one entry.
		if got, want := len(cfg.History), 11; got != want {
			t.Errorf("History = %d entries, want %d", got, want)
		}
		empties := 0
		for _, h := range cfg.History {
			if h.EmptyLayer {
				empties++
			}
		}
		if got, want := empties, 10; got != want {
			t.Errorf("EmptyLayer entries = %d, want %d", got, want)
		}
	})
	t.Run("build-never-signs", func(t *testing.T) {
		// The copied bytes must reach the layer verbatim: a codesign pass would
		// rewrite the Mach-O in place, changing both the entry and the operator's
		// source tree.
		for _, e := range layerEntries(t, img) {
			if e.name == "app" || strings.HasSuffix(e.name, "/app") {
				if string(e.body) != "payload" {
					t.Errorf("%s body = %q, want the source bytes verbatim", e.name, e.body)
				}
			}
		}
	})
	t.Run("platform-flag-rejects-foreign-target", func(t *testing.T) {
		df, err := oci.Parse(strings.NewReader("FROM scratch\nCOPY app /app"))
		if err != nil {
			t.Fatal(err)
		}
		bc, err := oci.NewContext(ctxDir)
		if err != nil {
			t.Fatal(err)
		}
		_, err = oci.Build(oci.Request{Dockerfile: df, Context: bc, Platform: "linux/amd64", TmpDir: t.TempDir()})
		if !errors.Is(err, oci.ErrUnsupportedPlatform) {
			t.Fatalf("Build(linux/amd64) = %v, want ErrUnsupportedPlatform", err)
		}
	})
}

// -------------------------------------------------------------------- sinks

func testOutputSinks(t *testing.T) {
	t.Parallel()

	ctxDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(ctxDir, "app"), []byte("payload"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ctxDir, "Dockerfile"), []byte("FROM scratch\nCOPY app /app\nENTRYPOINT [\"/app\"]"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("tarball-round-trips", func(t *testing.T) {
		t.Parallel()
		out := filepath.Join(t.TempDir(), "img.tar")
		if err := buildWith(t.Context(), buildOptions{
			dockerfile: filepath.Join(ctxDir, "Dockerfile"),
			tag:        "example.com/app:v1",
			output:     out,
			format:     "docker",
			contextDir: ctxDir,
		}, io.Discard, engineBuild, noStore, noPush); err != nil {
			t.Fatalf("build: %v", err)
		}
		img, err := tarball.ImageFromPath(out, nil)
		if err != nil {
			t.Fatalf("read back tarball: %v", err)
		}
		cfg, err := img.ConfigFile()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.OS != "darwin" || cfg.Architecture != "arm64" {
			t.Errorf("round-tripped platform = %s/%s", cfg.OS, cfg.Architecture)
		}
	})

	t.Run("oci-layout-round-trips", func(t *testing.T) {
		t.Parallel()
		out := filepath.Join(t.TempDir(), "layout")
		if err := buildWith(t.Context(), buildOptions{
			dockerfile: filepath.Join(ctxDir, "Dockerfile"),
			tag:        "example.com/app:v1",
			output:     out,
			format:     "oci",
			contextDir: ctxDir,
		}, io.Discard, engineBuild, noStore, noPush); err != nil {
			t.Fatalf("build: %v", err)
		}
		if _, err := os.Stat(filepath.Join(out, "index.json")); err != nil {
			t.Fatalf("no index.json in layout: %v", err)
		}
		if _, err := os.Stat(filepath.Join(out, "oci-layout")); err != nil {
			t.Fatalf("no oci-layout marker: %v", err)
		}
	})

	t.Run("malformed-dockerfile-writes-no-output", func(t *testing.T) {
		t.Parallel()
		// A Dockerfile that is not usable by ANY builder is still refused here,
		// natively and immediately — routing it to the engine would spend
		// minutes to re-derive the same syntax error. The artifact assertion is
		// the point: parsing completes before the output is opened.
		bad := filepath.Join(ctxDir, "Dockerfile.malformed")
		if err := os.WriteFile(bad, []byte("FROM scratch\nCOPY app"), 0o644); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(t.TempDir(), "img.tar")
		err := buildWith(t.Context(), buildOptions{
			dockerfile: bad, tag: "example.com/app:v1", output: out, format: "docker", contextDir: ctxDir,
		}, io.Discard, engineBuild, noStore, noPush)
		if !errors.Is(err, oci.ErrBadInstruction) {
			t.Fatalf("build = %v, want ErrBadInstruction", err)
		}
		if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a rejected build left an artifact at %s", out)
		}
	})
}

// ---------------------------------------------------------------------- CLI

func testBuildCLI(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"unknown-flag", []string{"--nope", "."}, "nope"},
		{"missing-tag", []string{"--output", "o.tar", "."}, "--tag"},
		{"missing-context", []string{"--tag", "a:v1", "--output", "o.tar"}, "context"},
		{"bad-format", []string{"--tag", "a:v1", "--output", "o", "--format", "zip", "."}, "format"},
		{"flag-after-context", []string{".", "--tag", "a:v1"}, "before the context"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// ContinueOnError is load-bearing: with the house ExitOnError idiom
			// this row would os.Exit(2) the whole test binary.
			_, err := parseBuildArgs(tc.args, io.Discard)
			if err == nil {
				t.Fatalf("parseBuildArgs(%v) = nil, want an error", tc.args)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}

	t.Run("defaults-dockerfile-to-context", func(t *testing.T) {
		t.Parallel()
		o, err := parseBuildArgs([]string{"--tag", "a:v1", "--output", "o.tar", "/ctx"}, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if want := filepath.Join("/ctx", "Dockerfile"); o.dockerfile != want {
			t.Errorf("dockerfile = %q, want %q", o.dockerfile, want)
		}
	})
}

// ------------------------------------------------------------------ helpers

type contextSpec struct {
	mtime int64
	exec  os.FileMode
	data  os.FileMode
}

// goldenContext materializes the same LOGICAL tree with caller-chosen on-disk
// metadata, so two instances differ in every field the normalization must erase.
func goldenContext(t *testing.T, spec contextSpec) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel string, body string, mode os.FileMode) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		if spec.mtime != 0 {
			ts := timeAt(spec.mtime)
			if err := os.Chtimes(p, ts, ts); err != nil {
				t.Fatal(err)
			}
		}
	}
	write("bin/app", "payload", spec.exec)
	write("etc/config.yaml", "k: v", spec.data)
	write("etc/nested/more.txt", "more", spec.data)
	return root
}

// buildFrom parses dockerfile and builds it against ctxDir.
func buildFrom(t *testing.T, dockerfile, ctxDir string) (ggcrv1.Image, error) {
	t.Helper()
	df, err := oci.Parse(strings.NewReader(dockerfile))
	if err != nil {
		return nil, err
	}
	bc, err := oci.NewContext(ctxDir)
	if err != nil {
		return nil, err
	}
	return oci.Build(oci.Request{Dockerfile: df, Context: bc, TmpDir: t.TempDir()})
}

type tarEntry struct {
	name string
	hdr  *tar.Header
	body []byte
}

func layerEntries(t *testing.T, img ggcrv1.Image) []tarEntry {
	t.Helper()
	layers, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}
	var out []tarEntry
	for _, l := range layers {
		rc, err := l.Uncompressed()
		if err != nil {
			t.Fatal(err)
		}
		tr := tar.NewReader(rc)
		for {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			if hdr.Typeflag == tar.TypeReg {
				if _, err := io.Copy(&buf, tr); err != nil {
					t.Fatal(err)
				}
			}
			out = append(out, tarEntry{name: strings.TrimSuffix(hdr.Name, "/"), hdr: hdr, body: buf.Bytes()})
		}
		rc.Close()
	}
	return out
}

// layerEntryNames returns the entry names of each layer, layer by layer.
func layerEntryNames(t *testing.T, img ggcrv1.Image) [][]string {
	t.Helper()
	layers, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}
	out := make([][]string, 0, len(layers))
	for _, l := range layers {
		rc, err := l.Uncompressed()
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		tr := tar.NewReader(rc)
		for {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			names = append(names, strings.TrimSuffix(hdr.Name, "/"))
		}
		rc.Close()
		out = append(out, names)
	}
	return out
}

func layerDigests(t *testing.T, img ggcrv1.Image) []string {
	t.Helper()
	layers, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(layers))
	for _, l := range layers {
		d, err := l.Digest()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, d.String())
	}
	return out
}

func equalSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
