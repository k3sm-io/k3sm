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

package updatectl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"

	updatesv1alpha1 "k3sm.io/apis/updates/v1alpha1"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/update"
)

const otherSum = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

// testOwner is the uid the tests hold the pin to: the test process's own,
// since a test cannot create root-owned files.
func testOwner() uint32 { return uint32(os.Getuid()) }

// pinWorkDir is a work dir with a pin for version and sum written by the
// test's own uid.
func pinWorkDir(t *testing.T, version, sum string) string {
	t.Helper()
	wd := t.TempDir()
	if err := writeReleasePin(wd, ReleasePin{Version: version, SHA256: sum, At: rigStart}, testOwner()); err != nil {
		t.Fatal(err)
	}
	return wd
}

func pinned(r Resolver, wd string) PinnedResolver {
	return PinnedResolver{Resolver: r, WorkDir: wd, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), owner: testOwner()}
}

// TestPinnedResolverRefusesDigestMismatch is the release pin's gate: a pin for
// the target whose digest the release's checksums file does not carry ends
// the Update Failed with the reason ReleasePinMismatch before any node is
// cordoned, and a matching pin records the pinned digest with the reason
// ResolvedPinned, which then rides every node's CA-signed payload.
func TestPinnedResolverRefusesDigestMismatch(t *testing.T) {
	ctx := context.Background()
	t.Run("resolver", func(t *testing.T) {
		noEntry := fmt.Errorf("%w: checksums file has no entry for k3sm_0.2.0_darwin_arm64.tar.gz", ErrRelease)
		for _, tc := range []struct {
			name       string
			pin        *ReleasePin
			inner      error
			wantErr    error
			wantPinned bool
		}{
			{name: "no pin resolves unpinned"},
			{name: "a pin for another version is ignored", pin: &ReleasePin{Version: "v0.1.9", SHA256: otherSum}},
			{name: "a matching pin", pin: &ReleasePin{Version: target, SHA256: targetSum}, wantPinned: true},
			{name: "a mismatching pin", pin: &ReleasePin{Version: target, SHA256: otherSum}, wantErr: ErrReleasePinMismatch},
			{name: "no checksums entry under a pin", pin: &ReleasePin{Version: target, SHA256: targetSum}, inner: noEntry, wantErr: ErrReleasePinMismatch},
			{name: "a transient error under a pin is retried", pin: &ReleasePin{Version: target, SHA256: targetSum}, inner: errors.New("connection refused")},
		} {
			t.Run(tc.name, func(t *testing.T) {
				wd := t.TempDir()
				if tc.pin != nil {
					wd = pinWorkDir(t, tc.pin.Version, tc.pin.SHA256)
				}
				rel, err := pinned(&fakeResolver{err: tc.inner}, wd).Resolve(ctx, target)
				switch {
				case tc.wantErr != nil:
					if !errors.Is(err, tc.wantErr) || !errors.Is(err, ErrRelease) {
						t.Fatalf("err = %v, want %v wrapping ErrRelease", err, tc.wantErr)
					}
				case tc.inner != nil:
					if err == nil || errors.Is(err, ErrRelease) {
						t.Fatalf("err = %v, want the transient error unchanged", err)
					}
				case err != nil:
					t.Fatalf("resolve: %v", err)
				case rel.Pinned != tc.wantPinned || rel.SHA256 != targetSum:
					t.Fatalf("release %+v, want pinned=%v", rel, tc.wantPinned)
				}
			})
		}
	})

	t.Run("a pin that cannot be trusted refuses", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			setup func(t *testing.T, wd string)
			owner uint32
		}{
			{name: "group-writable file", setup: func(t *testing.T, wd string) { chmod(t, ReleasePinPath(wd), 0o664) }},
			{name: "world-writable directory", setup: func(t *testing.T, wd string) { chmod(t, ReleasePinDir(wd), 0o757) }},
			{name: "another owner", owner: testOwner() + 1},
			{name: "symlinked file", setup: func(t *testing.T, wd string) {
				elsewhere := filepath.Join(t.TempDir(), "pin")
				mv(t, ReleasePinPath(wd), elsewhere)
				symlink(t, elsewhere, ReleasePinPath(wd))
			}},
			{name: "symlinked directory", setup: func(t *testing.T, wd string) {
				elsewhere := filepath.Join(t.TempDir(), "update")
				mv(t, ReleasePinDir(wd), elsewhere)
				symlink(t, elsewhere, ReleasePinDir(wd))
			}},
			{name: "malformed record", setup: func(t *testing.T, wd string) { write(t, ReleasePinPath(wd), "{not json") }},
			{name: "unknown field", setup: func(t *testing.T, wd string) {
				write(t, ReleasePinPath(wd), `{"version":"v0.2.0","sha256":"`+targetSum+`","at":"2026-10-18T00:00:00Z","extra":1}`)
			}},
			{name: "bad digest", setup: func(t *testing.T, wd string) {
				write(t, ReleasePinPath(wd), `{"version":"v0.2.0","sha256":"ABC","at":"2026-10-18T00:00:00Z"}`)
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				wd := pinWorkDir(t, target, targetSum)
				if tc.setup != nil {
					tc.setup(t, wd)
				}
				r := pinned(&fakeResolver{}, wd)
				if tc.owner != 0 {
					r.owner = tc.owner
				}
				// Another version: an untrusted pin refuses whatever the target.
				for _, tag := range []string{target, "v0.3.0"} {
					if _, err := r.Resolve(ctx, tag); !errors.Is(err, ErrReleasePinMismatch) || !errors.Is(err, ErrRelease) {
						t.Fatalf("resolve %s: err = %v, want ErrReleasePinMismatch", tag, err)
					}
				}
			})
		}
	})

	t.Run("a mismatch fails the Update before any node is cordoned", func(t *testing.T) {
		r := newRig(t, threeNodes()...)
		wd := pinWorkDir(t, target, otherSum)
		r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
		r.drive(pinnedController(r, wd), nil)
		u := r.update(updatesv1alpha1.UpdateName)
		failed := meta.FindStatusCondition(u.Status.Conditions, ConditionFailed)
		if u.Status.Phase != updatesv1alpha1.UpdatePhaseFailed || failed == nil || failed.Reason != ReasonReleasePinMismatch ||
			!strings.Contains(failed.Message, otherSum) || !strings.Contains(failed.Message, targetSum) {
			t.Fatalf("phase %q, Failed %+v", u.Status.Phase, failed)
		}
		if c := meta.FindStatusCondition(u.Status.Conditions, ConditionResolved); c == nil || c.Reason != ReasonReleasePinMismatch {
			t.Fatalf("Resolved %+v", c)
		}
		if u.Status.Resolved != nil {
			t.Fatalf("a refused release was recorded: %+v", u.Status.Resolved)
		}
		if !finished(u) {
			t.Fatal("the refused Update is not finished")
		}
		if got := r.log(); len(got) != 0 {
			t.Fatalf("a node was touched: %v", got)
		}
	})

	t.Run("a match records ResolvedPinned and signs the pinned digest", func(t *testing.T) {
		r := newRig(t, threeNodes()...)
		wd := pinWorkDir(t, target, targetSum)
		r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
		c := pinnedController(r, wd)
		if _, err := c.reconcile(ctx); err != nil {
			t.Fatal(err)
		}
		u := r.update(updatesv1alpha1.UpdateName)
		if res := u.Status.Resolved; res == nil || res.Digest != "sha256:"+targetSum {
			t.Fatalf("resolved %+v", res)
		}
		if cond := meta.FindStatusCondition(u.Status.Conditions, ConditionResolved); cond == nil || cond.Reason != ReasonResolvedPinned {
			t.Fatalf("Resolved %+v", cond)
		}
		if p := r.node("w1").Annotations[updatesv1alpha1.AnnotationUpdatePayload]; !strings.Contains(p, targetSum) {
			t.Fatalf("payload %s", p)
		}
		r.drive(c, nil)
		if got := r.update(updatesv1alpha1.UpdateName).Status.Phase; got != updatesv1alpha1.UpdatePhaseSucceeded {
			t.Fatalf("phase %q", got)
		}
	})

	t.Run("a required pin that is missing or for another tag refuses", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			pin      *ReleasePin
			required string
		}{
			{name: "no pin", required: target},
			{name: "a pin for another tag", pin: &ReleasePin{Version: "v0.1.9", SHA256: targetSum}, required: target},
			{name: "the annotation names another tag", pin: &ReleasePin{Version: target, SHA256: targetSum}, required: "v0.1.9"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				r := newRig(t, threeNodes()...)
				wd := t.TempDir()
				if tc.pin != nil {
					wd = pinWorkDir(t, tc.pin.Version, tc.pin.SHA256)
				}
				r.createUpdateWith(updatesv1alpha1.UpdateName, map[string]string{ReleasePinRequiredAnnotation: tc.required}, updatesv1alpha1.UpdateSpec{Version: target})
				r.drive(pinnedController(r, wd), nil)
				u := r.update(updatesv1alpha1.UpdateName)
				failed := meta.FindStatusCondition(u.Status.Conditions, ConditionFailed)
				if u.Status.Phase != updatesv1alpha1.UpdatePhaseFailed || failed == nil || failed.Reason != ReasonReleasePinMismatch || u.Status.Resolved != nil {
					t.Fatalf("phase %q, Failed %+v, resolved %+v", u.Status.Phase, failed, u.Status.Resolved)
				}
				if got := r.log(); len(got) != 0 {
					t.Fatalf("a node was touched: %v", got)
				}
			})
		}
		// The plain resolver, without PinnedResolver, can never satisfy it.
		r := newRig(t, threeNodes()...)
		r.createUpdateWith(updatesv1alpha1.UpdateName, map[string]string{ReleasePinRequiredAnnotation: target}, updatesv1alpha1.UpdateSpec{Version: target})
		r.drive(r.controller(), nil)
		if u := r.update(updatesv1alpha1.UpdateName); u.Status.Phase != updatesv1alpha1.UpdatePhaseFailed || len(r.log()) != 0 {
			t.Fatalf("an unpinned resolver satisfied a required pin: %q %v", u.Status.Phase, r.log())
		}
	})

	t.Run("a required and matching pin is what every node's signed payload carries", func(t *testing.T) {
		r := newRig(t, threeNodes()...)
		wd := pinWorkDir(t, target, targetSum)
		r.createUpdateWith(updatesv1alpha1.UpdateName, map[string]string{ReleasePinRequiredAnnotation: target}, updatesv1alpha1.UpdateSpec{Version: target})
		c := pinnedController(r, wd)
		if _, err := c.reconcile(ctx); err != nil {
			t.Fatal(err)
		}
		pin, err := readReleasePin(wd, testOwner())
		if err != nil || pin == nil {
			t.Fatalf("pin %+v, %v", pin, err)
		}
		u := r.update(updatesv1alpha1.UpdateName)
		raw, err := c.payload(u)
		if err != nil {
			t.Fatal(err)
		}
		p, err := update.ParsePayload(string(raw))
		if err != nil || p.SHA256 != pin.SHA256 {
			t.Fatalf("payload() %+v, %v; want sha256 %s", p, err, pin.SHA256)
		}
		ann := r.node("w1").Annotations
		if ann[update.AnnotationUpdatePayload] != string(raw) {
			t.Fatalf("the handed-over payload is not payload(): %s", ann[update.AnnotationUpdatePayload])
		}
		signed, err := update.VerifySignedPayload(update.CAPool(testSigning().ca.CertPEM), []byte(ann[update.AnnotationUpdatePayload]),
			ann[update.AnnotationUpdatePayloadSig], ann[update.AnnotationUpdateSigner], r.now)
		if err != nil || signed.Payload.SHA256 != pin.SHA256 {
			t.Fatalf("the signed payload does not verify to the pin: %v (%+v)", err, signed.Payload)
		}
	})

	t.Run("without a pin the reason stays Resolved", func(t *testing.T) {
		r := newRig(t, threeNodes()...)
		r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
		if _, err := pinnedController(r, t.TempDir()).reconcile(ctx); err != nil {
			t.Fatal(err)
		}
		u := r.update(updatesv1alpha1.UpdateName)
		if cond := meta.FindStatusCondition(u.Status.Conditions, ConditionResolved); cond == nil || cond.Reason != ReasonResolved {
			t.Fatalf("Resolved %+v", cond)
		}
	})
}

// TestReleasePinWriteAndRemove pins the writer: the record round-trips, the
// file is 0644 in a 0755 directory, a bad record or an untrusted directory is
// refused, and removing is idempotent.
func TestReleasePinWriteAndRemove(t *testing.T) {
	wd := t.TempDir()
	want := ReleasePin{Version: target, SHA256: targetSum, At: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
	if err := writeReleasePin(wd, want, testOwner()); err != nil {
		t.Fatal(err)
	}
	got, err := readReleasePin(wd, testOwner())
	if err != nil || got == nil || *got != want {
		t.Fatalf("read back %+v, %v", got, err)
	}
	for path, mode := range map[string]os.FileMode{ReleasePinDir(wd): 0o755, ReleasePinPath(wd): 0o644} {
		fi, err := os.Lstat(path)
		if err != nil || fi.Mode().Perm() != mode {
			t.Fatalf("%s: %v, %v; want %v", path, fi.Mode(), err, mode)
		}
	}
	for _, bad := range []ReleasePin{{Version: "v0.2.0;rm", SHA256: targetSum}, {Version: target, SHA256: strings.ToUpper(targetSum)}} {
		if err := writeReleasePin(wd, bad, testOwner()); err == nil {
			t.Fatalf("wrote %+v", bad)
		}
	}
	if err := writeReleasePin(wd, want, testOwner()+1); err == nil {
		t.Fatal("wrote into a directory another uid owns")
	}
	if c, err := clearReleasePin(wd, testOwner()); c.Path != ReleasePinPath(wd) || c.Untrusted != "" || err != nil {
		t.Fatalf("clear: %+v, %v", c, err)
	}
	if _, err := os.Lstat(ReleasePinDir(wd)); err != nil {
		t.Fatalf("clearing a trusted pin removed its directory: %v", err)
	}
	if c, err := clearReleasePin(wd, testOwner()); c.Path != "" || err != nil {
		t.Fatalf("second clear: %+v, %v", c, err)
	}
	if c, err := clearReleasePin(t.TempDir(), testOwner()); c.Path != "" || err != nil {
		t.Fatalf("clear with no directory: %+v, %v", c, err)
	}
	if c, err := clearReleasePin(filepath.Join(t.TempDir(), "absent"), testOwner()); c.Path != "" || err != nil {
		t.Fatalf("clear with no work dir: %+v, %v", c, err)
	}
	if got, err := readReleasePin(wd, testOwner()); got != nil || err != nil {
		t.Fatalf("read after clear: %+v, %v", got, err)
	}
	if entries, _ := os.ReadDir(ReleasePinDir(wd)); len(entries) != 0 {
		t.Fatalf("left behind: %v", entries)
	}
}

// TestReleasePinWriterFailsClosedOnADirectorySwap swaps the pin directory for
// a symlink between the writer's check and its write, as the service user that
// owns the work dir could: the write must fail, and nothing may land where the
// symlink points.
func TestReleasePinWriterFailsClosedOnADirectorySwap(t *testing.T) {
	for _, tc := range []struct {
		name     string
		existing bool
	}{{"a new directory", false}, {"an existing directory", true}} {
		t.Run(tc.name, func(t *testing.T) {
			wd := t.TempDir()
			if tc.existing {
				if err := os.Mkdir(ReleasePinDir(wd), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			victim := t.TempDir()
			chmod(t, victim, 0o700)
			moved := filepath.Join(t.TempDir(), "moved")
			swapped := false
			pinDirChecked = func() {
				mv(t, ReleasePinDir(wd), moved)
				symlink(t, victim, ReleasePinDir(wd))
				swapped = true
			}
			t.Cleanup(func() { pinDirChecked = func() {} })
			err := writeReleasePin(wd, ReleasePin{Version: target, SHA256: targetSum, At: rigStart}, testOwner())
			if !swapped || err == nil || !strings.Contains(err.Error(), "was replaced during the write") {
				t.Fatalf("swapped %v, err %v", swapped, err)
			}
			if entries, _ := os.ReadDir(victim); len(entries) != 0 {
				t.Fatalf("the write reached the symlink's target: %v", entries)
			}
			fi, err := os.Stat(victim)
			if err != nil || fi.Mode().Perm() != 0o700 {
				t.Fatalf("the symlink's target was chmodded: %v, %v", fi.Mode(), err)
			}
			if entries, _ := os.ReadDir(moved); len(entries) != 0 {
				t.Fatalf("the moved directory kept a pin or a temp file: %v", entries)
			}
			if pin, err := readReleasePin(wd, testOwner()); pin != nil || err == nil {
				t.Fatalf("the swapped path reads as a pin: %+v, %v", pin, err)
			}
		})
	}
}

// TestClearReleasePinRemovesAnUntrustedDirectory is root's recovery from a pin
// directory entry a less privileged user planted: whatever its shape, depth or
// refills, the entry is moved aside whole and never walked, a fresh pin
// directory takes its place, and root can pin again at once. Nothing a symlink
// points at is touched.
func TestClearReleasePinRemovesAnUntrustedDirectory(t *testing.T) {
	victim := t.TempDir()
	write(t, filepath.Join(victim, "keep"), "keep")
	writable := func(mode os.FileMode) func(t *testing.T, dir string) {
		return func(t *testing.T, dir string) { plantTree(t, dir); chmod(t, dir, mode) }
	}
	for _, tc := range []struct {
		name   string
		plant  func(t *testing.T, dir string)
		refill bool
		want   string
	}{
		{name: "a symlink to a directory", plant: func(t *testing.T, dir string) { symlink(t, victim, dir) }, want: "a symlink"},
		{name: "a dangling symlink", plant: func(t *testing.T, dir string) { symlink(t, filepath.Join(victim, "absent"), dir) }, want: "a symlink"},
		{name: "a regular file", plant: func(t *testing.T, dir string) { write(t, dir, "x") }, want: "not a directory"},
		{name: "group-writable", plant: writable(0o775), want: "writable by its group or others"},
		{name: "world-writable", plant: writable(0o757), want: "writable by its group or others"},
		{name: "a tree 64 directories deep", plant: func(t *testing.T, dir string) {
			deep := dir
			for i := range 64 {
				deep = filepath.Join(deep, fmt.Sprintf("d%02d", i))
			}
			if err := os.MkdirAll(deep, 0o755); err != nil {
				t.Fatal(err)
			}
			write(t, filepath.Join(deep, "f"), "f")
			chmod(t, dir, 0o775)
		}, want: "writable by its group or others"},
		{name: "a tree refilled while it is cleared", plant: writable(0o775), refill: true, want: "writable by its group or others"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wd := t.TempDir()
			tc.plant(t, ReleasePinDir(wd))
			if tc.refill {
				// The planter keeps writing into the entry between root's
				// check and root's act.
				pinClearChecked = func() {
					for i := range 200 {
						write(t, filepath.Join(ReleasePinDir(wd), fmt.Sprintf("refill-%03d", i)), "x")
					}
				}
				t.Cleanup(func() { pinClearChecked = func() {} })
			}
			c, err := clearReleasePin(wd, testOwner())
			if err != nil || c.Path != ReleasePinDir(wd) || !strings.Contains(c.Untrusted, tc.want) ||
				!strings.HasPrefix(filepath.Base(c.Aside), "update.untrusted-") || filepath.Dir(c.Aside) != wd {
				t.Fatalf("clear: %+v, %v; want %q", c, err, tc.want)
			}
			if _, err := os.Lstat(c.Aside); err != nil {
				t.Fatalf("the aside entry is gone: %v", err)
			}
			fi, err := os.Lstat(ReleasePinDir(wd))
			if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o755 {
				t.Fatalf("no fresh pin directory: %v, %v", fi, err)
			}
			if entries, _ := os.ReadDir(ReleasePinDir(wd)); len(entries) != 0 {
				t.Fatalf("the fresh pin directory is not empty: %v", entries)
			}
			if b, err := os.ReadFile(filepath.Join(victim, "keep")); err != nil || string(b) != "keep" {
				t.Fatalf("the symlink's target was touched: %q, %v", b, err)
			}
			if entries, _ := os.ReadDir(victim); len(entries) != 1 {
				t.Fatalf("the symlink's target gained entries: %v", entries)
			}
			if err := writeReleasePin(wd, ReleasePin{Version: target, SHA256: targetSum, At: rigStart}, testOwner()); err != nil {
				t.Fatalf("pin after clear: %v", err)
			}
			if pin, err := readReleasePin(wd, testOwner()); err != nil || pin == nil || pin.SHA256 != targetSum {
				t.Fatalf("read after the new pin: %+v, %v", pin, err)
			}
			if tc.refill {
				// The planter refills its aside tree and plants a new
				// untrusted entry between root's calls: the next clear moves
				// that one aside too, under a new name.
				pinClearChecked = func() {}
				for i := range 50 {
					write(t, filepath.Join(c.Aside, fmt.Sprintf("later-%02d", i)), "x")
				}
				mv(t, ReleasePinDir(wd), filepath.Join(t.TempDir(), "root-dir"))
				writable(0o777)(t, ReleasePinDir(wd))
				c2, err := clearReleasePin(wd, testOwner())
				if err != nil || c2.Aside == "" || c2.Aside == c.Aside {
					t.Fatalf("second clear: %+v, %v (first aside %s)", c2, err, c.Aside)
				}
				if err := writeReleasePin(wd, ReleasePin{Version: target, SHA256: targetSum, At: rigStart}, testOwner()); err != nil {
					t.Fatalf("pin after the second clear: %v", err)
				}
			}
		})
	}
}

// TestClearReleasePinRetriesARaceToReplant plants a new untrusted entry
// between root's rename aside and its mkdir: root moves that one aside too and
// still ends with a fresh pin directory.
func TestClearReleasePinRetriesARaceToReplant(t *testing.T) {
	wd := t.TempDir()
	symlink(t, t.TempDir(), ReleasePinDir(wd))
	replants := 0
	pinClearChecked = func() {}
	t.Cleanup(func() { pinClearChecked = func() {}; renameAsideHook = func() {} })
	renameAsideHook = func() {
		if replants < 2 {
			replants++
			symlink(t, t.TempDir(), ReleasePinDir(wd))
		}
	}
	c, err := clearReleasePin(wd, testOwner())
	if err != nil || replants != 2 || c.Untrusted != "a symlink" {
		t.Fatalf("clear: %+v, %v, replants %d", c, err, replants)
	}
	fi, err := os.Lstat(ReleasePinDir(wd))
	if err != nil || !fi.IsDir() {
		t.Fatalf("no fresh pin directory: %v, %v", fi, err)
	}
	asides, _ := filepath.Glob(filepath.Join(wd, "update.untrusted-*"))
	if len(asides) != 3 || len(c.Asides) != 3 || c.Aside != c.Asides[0] {
		t.Fatalf("asides on disk %v, reported %v (first %s), want 3", asides, c.Asides, c.Aside)
	}
}

// TestClearReleasePinGivesUpOnARelentlessReplant replants the entry after every
// attempt: the clear gives up after maxAsideAttempts with an error that names
// every entry it moved aside and the documented recovery.
func TestClearReleasePinGivesUpOnARelentlessReplant(t *testing.T) {
	wd := t.TempDir()
	symlink(t, t.TempDir(), ReleasePinDir(wd))
	t.Cleanup(func() { renameAsideHook = func() {} })
	renameAsideHook = func() { symlink(t, t.TempDir(), ReleasePinDir(wd)) }
	_, err := clearReleasePin(wd, testOwner())
	var contested *PinDirContestedError
	if !errors.As(err, &contested) || contested.Attempts != maxAsideAttempts || len(contested.Asides) != maxAsideAttempts {
		t.Fatalf("err %v (%+v)", err, contested)
	}
	onDisk, _ := filepath.Glob(filepath.Join(wd, "update.untrusted-*"))
	if len(onDisk) != maxAsideAttempts {
		t.Fatalf("asides on disk %v", onDisk)
	}
	for _, a := range contested.Asides {
		if !strings.Contains(err.Error(), a) {
			t.Errorf("the error does not name %s: %v", a, err)
		}
	}
	for _, want := range []string{
		"sudo launchctl bootout system/io.k3sm.server",
		"sudo k3sm update apply --clear-pin",
		"sudo launchctl bootstrap system /Library/LaunchDaemons/io.k3sm.server.plist",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not name the recovery step %q: %v", want, err)
		}
	}
}

// plantTree makes dir a directory holding a pin, a nested directory and a
// symlink out of the tree, so a whole-entry clear is non-trivial.
func plantTree(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "a", "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, releasePinFileName), `{"version":"v0.2.0","sha256":"`+targetSum+`","at":"2026-10-18T00:00:00Z"}`)
	write(t, filepath.Join(dir, "a", "b", "f"), "f")
	symlink(t, t.TempDir(), filepath.Join(dir, "a", "out"))
}

func pinnedController(r *rig, wd string) *Controller {
	r.t.Helper()
	c, err := New(Config{
		Client: r.cs, Dynamic: r.dyn, Resolver: pinned(r.resolver, wd), ServerNode: serverName,
		IssueSigner: func() (*certs.UpdateSigner, error) { return testSigning().signer, nil },
		Now:         func() time.Time { return r.now }, Recorder: r.recorder,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return c
}

func chmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func mv(t *testing.T, from, to string) {
	t.Helper()
	if err := os.Rename(from, to); err != nil {
		t.Fatal(err)
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
