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

package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/internal/binsign"
	"k3sm.io/k3sm/pkg/helmchart"
)

// signedSuffix is what the fake codesign appends to "sign" a file ad hoc; a file
// carries a valid ad-hoc signature when it ends with it. devIDSuffix marks a file
// with a valid signature that is NOT ad hoc (a Developer ID, say).
const (
	signedSuffix = "SIGNED"
	devIDSuffix  = "DEVID!"
)

// signCall is one fake codesign sign: the -i identifier and the path signed.
type signCall struct{ id, path string }

// fakeCodesign puts a fake `codesign` first on PATH and returns a func reporting
// the signs it performed, in order. The fake rewrites a file IN PLACE when it signs
// (an append, keeping the inode), exactly as the real tool does, so a sign at a
// live path is visible through any fd or mapping held on that file. It answers
// --verify (valid: either suffix) and -dv (Signature=adhoc only for the ad-hoc
// suffix). It runs the production signer (binsign.Codesign → exec "codesign"), so
// nothing between k3sm and the tool is faked, and no real codesign runs.
func fakeCodesign(t *testing.T) func() []signCall {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "codesign.log")
	script := `#!/bin/sh
for a in "$@"; do last=$a; done
tailOf() { /usr/bin/tail -c 6 "$1" 2>/dev/null; }
case "$1" in
--verify)
	case "$(tailOf "$last")" in ` + signedSuffix + `|` + devIDSuffix + `) exit 0 ;; esac
	exit 1
	;;
-dv)
	case "$(tailOf "$last")" in
	` + signedSuffix + `) echo "Signature=adhoc" >&2; exit 0 ;;
	` + devIDSuffix + `) echo "Authority=Developer ID Application: Someone" >&2; exit 0 ;;
	esac
	exit 1
	;;
-s)
	[ "$4" = "-i" ] || { echo "no -i identifier" >&2; exit 3; }
	printf 'sign %s %s\n' "$5" "$last" >> "` + log + `"
	[ "$(tailOf "$last")" = "` + signedSuffix + `" ] || printf ` + signedSuffix + ` >> "$last"
	exit 0
	;;
esac
exit 2
`
	if err := os.WriteFile(filepath.Join(dir, "codesign"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() []signCall {
		b, err := os.ReadFile(log)
		if err != nil {
			return nil
		}
		var calls []signCall
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if rest, ok := strings.CutPrefix(line, "sign "); ok {
				id, path, _ := strings.Cut(rest, " ")
				calls = append(calls, signCall{id, path})
			}
		}
		return calls
	}
}

// heldFile is an open fd and a shared read-only mapping of a binary as it was
// before an update: a running process's view of it.
type heldFile struct {
	path string
	ino  uint64
	want string
	f    *os.File
	mmap []byte
}

// hold opens and maps path. The update under test must not change what either
// one reads.
func hold(t *testing.T, path string) *heldFile {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	m, err := unix.Mmap(int(f.Fd()), 0, len(data), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	h := &heldFile{path: path, ino: inode(t, path), want: string(data), f: f, mmap: m}
	t.Cleanup(func() {
		_ = unix.Munmap(m)
		_ = f.Close()
	})
	return h
}

// assertReplaced checks the update put path on a NEW inode and left the old one,
// as seen through the held fd and mapping, byte-for-byte intact.
func (h *heldFile) assertReplaced(t *testing.T) {
	t.Helper()
	if got := inode(t, h.path); got == h.ino {
		t.Errorf("%s still has inode %d: it was rewritten in place", filepath.Base(h.path), got)
	}
	buf := make([]byte, len(h.want)+64)
	n, _ := h.f.ReadAt(buf, 0)
	if string(buf[:n]) != h.want {
		t.Errorf("the fd held on the old %s reads %q, want %q untouched", filepath.Base(h.path), buf[:n], h.want)
	}
	if string(h.mmap) != h.want {
		t.Errorf("the mapping of the old %s reads %q, want %q untouched", filepath.Base(h.path), h.mmap, h.want)
	}
}

// inode returns path's inode number.
func inode(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Ino
}

// tempTarget returns the final p is an atomicfile temp of: one of finals in the
// same directory, with p named ".<base>.tmp-<digits>".
func tempTarget(p string, finals ...string) (string, bool) {
	for _, final := range finals {
		if filepath.Dir(p) != filepath.Dir(final) {
			continue
		}
		rest, ok := strings.CutPrefix(filepath.Base(p), "."+filepath.Base(final)+".tmp-")
		if ok && rest != "" && strings.Trim(rest, "0123456789") == "" {
			return final, true
		}
	}
	return "", false
}

// assertSignedOnlyTemps fails on any sign of a path other than a temp beside one
// of finals (the signer must never touch a live name), and on any identifier other
// than that final's base name (the temp's own name must not become the code
// identifier).
func assertSignedOnlyTemps(t *testing.T, signed []signCall, finals ...string) {
	t.Helper()
	for _, c := range signed {
		final, ok := tempTarget(c.path, finals...)
		if !ok {
			t.Errorf("codesign signed %s: only a temp beside its target may be signed", c.path)
			continue
		}
		if c.id != filepath.Base(final) {
			t.Errorf("codesign signed %s as %q, want the final name %q as its identifier", c.path, c.id, filepath.Base(final))
		}
	}
}

// assertSignedAt fails unless path holds signed bytes: no unsigned file is visible
// at the final name once the update returns.
func assertSignedAt(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(b), signedSuffix) {
		t.Errorf("%s holds unsigned bytes %q", filepath.Base(path), b)
	}
}

// markHealed records names as healed at stamp in dir's binsign marker.
func markHealed(t *testing.T, dir, stamp string, names ...string) {
	t.Helper()
	var b strings.Builder
	for _, n := range names {
		b.WriteString(n + "\t" + stamp + "\n")
	}
	if err := os.WriteFile(filepath.Join(dir, binsign.HealMarkerName), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeBin(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestBinaryStagingNeverRewritesALiveInode is the B544 gate. macOS caches a Mach-O's
// code signature per vnode: rewriting a signed binary IN PLACE while any process has
// it mapped (an O_TRUNC write, a copy onto it, `codesign -f` on it) leaves the
// kernel holding the old signature, and every process mapping the file afterwards is
// SIGKILLed (Code Signature Invalid). So every way the executor stages or signs a
// binary must put changed bytes on a NEW inode and sign only a temp:
//
//   - seed: a versioned re-seed over an existing binary from the payload;
//   - boot re-sign: the per-boot signBinaries over the live work-dir set;
//   - fresh staging: a source-built child (stagedChild), the helm download, and a
//     control-plane download.
//
// For each it asserts the target's inode changes when its content or signature
// changes, an already-valid binary, ad hoc or not, is left untouched (same inode,
// no sign call), codesign only ever sees temp
// paths and always signs under the final name (-i), no unsigned bytes are left at
// a final name, and an fd and a mapping held on the old file still read the old
// bytes. The one-time heal replaces every staged binary once per version stamp.
func TestBinaryStagingNeverRewritesALiveInode(t *testing.T) {
	t.Run("seed: a versioned re-seed replaces each binary on a new inode", func(t *testing.T) {
		calls := fakeCodesign(t)
		payload, work := t.TempDir(), t.TempDir()
		bd := binDir(work)
		if err := os.MkdirAll(bd, 0o755); err != nil {
			t.Fatal(err)
		}
		var finals []string
		held := map[string]*heldFile{}
		for _, name := range cpBinaries {
			writeBin(t, filepath.Join(bd, name), "old-"+name+signedSuffix)
			// The payload copy is longer than the old one, so a mapping of the old
			// file is never read past an in-place rewrite's EOF (SIGBUS).
			content := "new-payload-" + name + "-bytes"
			if name == "kube-apiserver" {
				content += signedSuffix // arrives signed: kept as is
			}
			writeBin(t, filepath.Join(payload, name), content)
			finals = append(finals, filepath.Join(bd, name))
			held[name] = hold(t, filepath.Join(bd, name))
		}
		if err := writeKubeMarker(bd, "v1.0.0"); err != nil {
			t.Fatal(err)
		}
		if err := writeKubeMarker(payload, DefaultKubeVersion); err != nil {
			t.Fatal(err)
		}

		if err := seedBinDir(t.Context(), discardLogger(), work, payload, DefaultKineVersion, DefaultKubeVersion, false); err != nil {
			t.Fatal(err)
		}
		signed := calls()
		assertSignedOnlyTemps(t, signed, finals...)
		for _, name := range cpBinaries {
			held[name].assertReplaced(t)
			assertSignedAt(t, filepath.Join(bd, name))
			if got, _ := os.ReadFile(filepath.Join(bd, name)); !strings.HasPrefix(string(got), "new-payload-"+name) {
				t.Errorf("%s = %q, want the payload's bytes", name, got)
			}
		}
		if len(signed) != len(cpBinaries)-1 {
			t.Errorf("signed %d temps, want %d (the payload's signed apiserver kept as is)", len(signed), len(cpBinaries)-1)
		}
	})

	t.Run("boot re-sign: a validly signed binary is untouched, an unsigned one is replaced", func(t *testing.T) {
		calls := fakeCodesign(t)
		bd := t.TempDir()
		valid := filepath.Join(bd, "kube-scheduler")
		invalid := filepath.Join(bd, "kube-apiserver")
		devID := filepath.Join(bd, "kube-controller-manager")
		writeBin(t, valid, "scheduler"+signedSuffix)
		writeBin(t, invalid, "apiserver-unsigned")
		writeBin(t, devID, "controller-manager"+devIDSuffix)
		// Already healed once at this stamp, so only the signature check acts.
		markHealed(t, bd, healStamp(kubeMarkerPath(bd)), cpBinaries...)
		validIno, devIDIno := inode(t, valid), inode(t, devID)
		hInvalid := hold(t, invalid)

		if err := signBinaries(t.Context(), bd, healStamp(kubeMarkerPath(bd)), cpBinaries); err != nil {
			t.Fatal(err)
		}
		signed := calls()
		assertSignedOnlyTemps(t, signed, invalid)
		if len(signed) != 1 {
			t.Errorf("signed %v, want one temp copy of the unsigned binary", signed)
		}
		hInvalid.assertReplaced(t)
		assertSignedAt(t, invalid)
		// A valid non-ad-hoc signature (a Developer ID) is never replaced by an
		// ad-hoc one: that would strip its provenance (B480).
		if got := inode(t, devID); got != devIDIno {
			t.Errorf("the Developer ID-signed %s was replaced (inode %d -> %d)", filepath.Base(devID), devIDIno, got)
		}
		if got, _ := os.ReadFile(devID); string(got) != "controller-manager"+devIDSuffix {
			t.Errorf("the Developer ID-signed binary changed to %q", got)
		}
		if got := inode(t, valid); got != validIno {
			t.Errorf("the validly signed %s was replaced (inode %d -> %d)", filepath.Base(valid), validIno, got)
		}
		if got, _ := os.ReadFile(valid); string(got) != "scheduler"+signedSuffix {
			t.Errorf("the validly signed binary changed to %q", got)
		}
		if fi, err := os.Stat(invalid); err != nil || fi.Mode().Perm() != 0o755 {
			t.Errorf("re-signed binary mode = %v (%v), want 0755 kept", fi.Mode(), err)
		}
	})

	t.Run("heal: once per stamp, every staged binary on a new inode", func(t *testing.T) {
		calls := fakeCodesign(t)
		bd := t.TempDir()
		var finals []string
		for _, name := range cpBinaries {
			writeBin(t, filepath.Join(bd, name), name+signedSuffix) // all valid ad hoc
			finals = append(finals, filepath.Join(bd, name))
		}
		if err := writeKubeMarker(bd, "v1.0.0"); err != nil {
			t.Fatal(err)
		}
		inodes := func() map[string]uint64 {
			m := map[string]uint64{}
			for _, f := range finals {
				m[f] = inode(t, f)
			}
			return m
		}
		boot := func() []signCall {
			t.Helper()
			before := len(calls())
			if err := signBinaries(t.Context(), bd, healStamp(kubeMarkerPath(bd)), cpBinaries); err != nil {
				t.Fatal(err)
			}
			return calls()[before:]
		}

		held := hold(t, finals[0])
		first := inodes()
		signed := boot()
		assertSignedOnlyTemps(t, signed, finals...)
		if len(signed) != len(cpBinaries) {
			t.Errorf("first boot without the marker signed %d temps, want all %d", len(signed), len(cpBinaries))
		}
		held.assertReplaced(t)
		for f, ino := range inodes() {
			if ino == first[f] {
				t.Errorf("first boot left %s on its old inode", filepath.Base(f))
			}
		}
		if _, err := os.Stat(filepath.Join(bd, binsign.HealMarkerName)); err != nil {
			t.Errorf("no heal marker after the first boot: %v", err)
		}

		second := inodes()
		if signed := boot(); len(signed) != 0 {
			t.Errorf("second boot signed %v, want nothing", signed)
		}
		for f, ino := range inodes() {
			if ino != second[f] {
				t.Errorf("second boot replaced %s", filepath.Base(f))
			}
		}

		if err := writeKubeMarker(bd, "v1.1.0"); err != nil {
			t.Fatal(err)
		}
		if signed := boot(); len(signed) != len(cpBinaries) {
			t.Errorf("a changed version marker healed %d binaries, want all %d", len(signed), len(cpBinaries))
		}
	})

	t.Run("fresh staging: a source-built child is signed before it takes the name", func(t *testing.T) {
		calls := fakeCodesign(t)
		c, bd := kineChild(DefaultKineVersion), t.TempDir()
		writeBin(t, c.binPath(bd), "old-kine"+signedSuffix)
		if err := os.WriteFile(c.markerPath(bd), []byte("v0.0.1 "+c.variant+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		h := hold(t, c.binPath(bd))
		c.build = func(_ context.Context, scratch string) (string, error) {
			p := filepath.Join(scratch, c.name)
			return p, os.WriteFile(p, []byte("freshly-built-kine-binary"), 0o755)
		}
		if err := c.ensureInto(t.Context(), bd); err != nil {
			t.Fatal(err)
		}
		signed := calls()
		assertSignedOnlyTemps(t, signed, c.binPath(bd))
		if len(signed) != 1 {
			t.Errorf("signed %v, want the one staged temp", signed)
		}
		h.assertReplaced(t)
		assertSignedAt(t, c.binPath(bd))

		// The next boot heals the newly staged pin once (a new stamp), through a
		// temp; the boot after that leaves the valid binary alone.
		if err := c.ensureInto(t.Context(), bd); err != nil {
			t.Fatal(err)
		}
		signed = calls()
		assertSignedOnlyTemps(t, signed, c.binPath(bd))
		if len(signed) != 2 {
			t.Errorf("signed %v, want one heal after the stage", signed)
		}
		ino := inode(t, c.binPath(bd))
		if err := c.ensureInto(t.Context(), bd); err != nil {
			t.Fatal(err)
		}
		if signed := calls(); len(signed) != 2 {
			t.Errorf("a staged, healed, valid child was re-signed: %v", signed)
		}
		if got := inode(t, c.binPath(bd)); got != ino {
			t.Errorf("a staged, valid child was replaced (inode %d -> %d)", ino, got)
		}
	})

	t.Run("fresh staging: helm is extracted and signed on a temp", func(t *testing.T) {
		calls := fakeCodesign(t)
		fakeHelmRelease(t, helmTarball(t, map[string]string{
			helmchart.HelmTarballMember: "the-new-helm-binary-bytes",
		}), "")
		bd := t.TempDir()
		dst := helmchart.HelmPath(bd)
		writeBin(t, dst, "old-helm"+signedSuffix)
		h := hold(t, dst)
		if err := stageHelm(t.Context(), bd, true); err != nil {
			t.Fatal(err)
		}
		signed := calls()
		assertSignedOnlyTemps(t, signed, dst)
		if len(signed) != 1 {
			t.Errorf("signed %v, want the one extracted temp", signed)
		}
		h.assertReplaced(t)
		assertSignedAt(t, dst)
		if fi, err := os.Stat(dst); err != nil || fi.Mode().Perm() != 0o755 {
			t.Errorf("staged helm mode = %v (%v), want 0755", fi.Mode(), err)
		}
	})

	t.Run("fresh staging: a control-plane download is signed through temps", func(t *testing.T) {
		calls := fakeCodesign(t)
		fakeDownload(t, "downloaded")
		dir := t.TempDir()
		if err := downloadControlPlane(t.Context(), discardLogger(), dir, "v0.0.0-unpinned", false); err != nil {
			t.Fatal(err)
		}
		signed := calls()
		var finals []string
		for _, name := range cpBinaries {
			finals = append(finals, filepath.Join(dir, name))
			assertSignedAt(t, filepath.Join(dir, name))
		}
		assertSignedOnlyTemps(t, signed, finals...)
		if len(signed) != len(cpBinaries) {
			t.Errorf("signed %v, want one temp per downloaded binary", signed)
		}
	})
}

// TestReapStagingTemps pins the start-of-boot cleanup: the temps a killed install
// left for any staged binary (and for the heal marker) are removed, and nothing
// else in the bin dir is.
func TestReapStagingTemps(t *testing.T) {
	bd := t.TempDir()
	orphans := []string{".kube-apiserver.tmp-123", ".kine.tmp-9", "." + binsign.HealMarkerName + ".tmp-77"}
	keep := []string{"kube-apiserver", ".zot.tmp-5", ".kube-apiserver.tmp-x", KubeMarkerName}
	for _, n := range append(append([]string{}, orphans...), keep...) {
		writeBin(t, filepath.Join(bd, n), n)
	}
	if err := reapStagingTemps(bd); err != nil {
		t.Fatal(err)
	}
	for _, n := range orphans {
		if _, err := os.Lstat(filepath.Join(bd, n)); !os.IsNotExist(err) {
			t.Errorf("orphan temp %s survived (err %v)", n, err)
		}
	}
	for _, n := range keep {
		if _, err := os.Lstat(filepath.Join(bd, n)); err != nil {
			t.Errorf("%s was removed: %v", n, err)
		}
	}
	if err := reapStagingTemps(filepath.Join(bd, "absent")); err != nil {
		t.Errorf("an absent bin dir must not be an error: %v", err)
	}
}
