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
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"strings"
	"testing"
)

// The staged-install-root gate (B352). Every test here is about WHERE an
// artifact is written and WHEN it becomes visible; none of them changes what
// any existing check verifies.
//
// The shared vocabulary: liveRoot is the tree the daemons execute out of, and
// stagingRoot is its sibling. The whole feature is the claim that nothing lands
// in the first until everything has landed in the second.

func stageCfg() Config {
	return Config{BinarySource: "/tmp/k3sm", TargetUser: "alice"}
}

// liveWrites are the copies this install made INTO the live install root — the
// thing that must be empty until the publish, and empty forever afterwards
// (the swap moves a tree; it does not copy into one).
func liveWrites(calls []string, cfg Config) []string {
	prefix := "CopyToRootOwned:" + strings.TrimSuffix(cfg.InstallDir, "/") + "/"
	var out []string
	for _, c := range calls {
		if strings.HasPrefix(c, prefix) {
			out = append(out, c)
		}
	}
	return out
}

// stagedWrites are the copies into the staging tree, in order.
func stagedWrites(calls []string, cfg Config) []string {
	prefix := "CopyToRootOwned:" + cfg.stagingDir() + "/"
	var out []string
	for _, c := range calls {
		if strings.HasPrefix(c, prefix) {
			out = append(out, c)
		}
	}
	return out
}

// TestInstallStagesTheRootAndPublishesItOnce is the gate's spine: on a
// reinstall over a live tree, every install-root artifact is written to the
// staging sibling, the publish happens exactly once and after the last of them,
// the launcher link and the plists follow it, and the previous tree is reaped
// only after the daemons have been verified.
func TestInstallStagesTheRootAndPublishesItOnce(t *testing.T) {
	shrinkRestartBudgets(t)
	cfg := stageCfg().withDefaults()
	f := &fakeSystem{}

	// Run 1 is the first install (nothing at the live path); run 2 is the
	// upgrade this item exists for — a live tree being replaced under running
	// daemons.
	if err := Install(context.Background(), f, stageCfg()); err != nil {
		t.Fatalf("first Install: %v", err)
	}
	firstTree := f.treeUnder(cfg.InstallDir)
	f.calls = nil
	if err := Install(context.Background(), f, stageCfg()); err != nil {
		t.Fatalf("reinstall: %v", err)
	}
	calls := f.calls
	swap := fmt.Sprintf("SwapInstallRoot:%s<->%s:swap", cfg.stagingDir(), cfg.InstallDir)

	t.Run("no artifact is written into the live install root", func(t *testing.T) {
		if got := liveWrites(calls, cfg); len(got) > 0 {
			t.Errorf("the install copied into the LIVE root: %v", got)
		}
	})

	t.Run("every install-root artifact is staged", func(t *testing.T) {
		want := []string{
			cfg.stagedBinary(),
			cfg.stagedExecShim(),
			cfg.stagedPathShim(),
			cfg.stagedDNSShim(),
			cfg.stagedVMHost(),
			cfg.stagedPayloadFile("kube-apiserver"),
			cfg.stagedPayloadFile("kine"),
		}
		for _, p := range want {
			if idx(calls, "CopyToRootOwned:"+p) < 0 {
				t.Errorf("%s was never staged; calls =\n%s", p, strings.Join(calls, "\n"))
			}
		}
	})

	t.Run("the publish happens exactly once and after every staged write", func(t *testing.T) {
		if n := countCalls(f, swap); n != 1 {
			t.Fatalf("the install root was published %d times, want exactly 1; calls =\n%s", n, strings.Join(calls, "\n"))
		}
		at := idx(calls, swap)
		staged := stagedWrites(calls, cfg)
		if len(staged) < 7 {
			t.Fatalf("only %d staged writes were recorded, want the whole install root; calls =\n%s", len(staged), strings.Join(calls, "\n"))
		}
		if last := idx(calls, staged[len(staged)-1]); last > at {
			t.Errorf("a staged write (%s, %d) happened AFTER the publish (%d)", staged[len(staged)-1], last, at)
		}
	})

	t.Run("the launcher link, the plists and the restart follow the publish", func(t *testing.T) {
		at := idx(calls, swap)
		for _, after := range []string{
			"EnsureSymlink:" + cfg.installedBinary() + "->" + cfg.installedLink(),
			"WriteLaunchDaemon:" + cfg.plistPath(NetdLabel),
			"WriteLaunchDaemon:" + cfg.plistPath(ServerLabel),
			"Bootout:" + NetdLabel,
		} {
			if i := idx(calls, after); i < at {
				t.Errorf("%s (%d) happened BEFORE the publish (%d): it names a fixed path inside the tree the publish makes live", after, i, at)
			}
		}
	})

	t.Run("the reap runs only after the verification succeeded", func(t *testing.T) {
		reap := idx(calls, "RemoveTree:"+cfg.stagingDir())
		if reap < 0 {
			t.Fatalf("the previous install root was never reaped; calls =\n%s", strings.Join(calls, "\n"))
		}
		// verifyDaemons' last read is the server's crash-loop record: a daemon
		// parked by its breaker reports a healthy pid while serving nothing, so
		// that read is the end of the verification, not the pid reads.
		verify := idx(calls, "ReadFile:/var/lib/k3sm/server/crashloop.json")
		if verify < 0 || reap < verify {
			t.Errorf("the reap (%d) did not wait for the verification (%d); calls =\n%s", reap, verify, strings.Join(calls, "\n"))
		}
	})

	t.Run("the published tree is this install's, and the previous one is gone", func(t *testing.T) {
		live := f.treeUnder(cfg.InstallDir)
		if len(live) != len(firstTree) {
			t.Errorf("the live root holds %d artifacts, want the %d this install staged", len(live), len(firstTree))
		}
		if got := f.treeUnder(cfg.stagingDir()); len(got) != 0 {
			t.Errorf("the staging path still holds %v after the reap", got)
		}
	})

	t.Run("the install lock is held across the whole run and then released", func(t *testing.T) {
		lock := idx(calls, "LockInstall:"+cfg.installLockPath())
		unlock := idx(calls, "UnlockInstall:"+cfg.installLockPath())
		if lock < 0 || unlock < 0 {
			t.Fatalf("the install lock was not taken and released; calls =\n%s", strings.Join(calls, "\n"))
		}
		if lock > idx(calls, "EnsureRootDir:"+cfg.stagingDir()) {
			t.Error("the lock was taken after the staging directory was created")
		}
		if unlock < idx(calls, "RemoveTree:"+cfg.stagingDir()) {
			t.Error("the lock was released before the reap")
		}
	})
}

// TestInstallStagingFailureLeavesTheLiveRootUntouched is the defect itself: a
// copy that fails part-way through the set must leave the tree the daemons are
// executing from byte-for-byte as it was.
//
// RED BEFORE this change: the same injection left CopyToRootOwned calls against
// /Library/k3sm/k3sm, /Library/k3sm/k3sm-execshim and the two shims in the log
// — the new binary beside the old helpers, with launchd free to re-exec either.
func TestInstallStagingFailureLeavesTheLiveRootUntouched(t *testing.T) {
	shrinkRestartBudgets(t)
	cfg := stageCfg().withDefaults()
	f := &fakeSystem{}
	if err := Install(context.Background(), f, stageCfg()); err != nil {
		t.Fatalf("first Install: %v", err)
	}
	before := f.treeUnder(cfg.InstallDir)
	f.calls = nil

	// The disk fills up half way through the set — after the binary and two
	// shims, before the payload.
	full := errors.New("ditto: No space left on device")
	f.putCopyErr(cfg.stagedVMHost(), full)
	err := Install(context.Background(), f, stageCfg())
	if err == nil {
		t.Fatal("Install succeeded with a copy that could not be made")
	}
	if !strings.Contains(err.Error(), "No space left on device") {
		t.Errorf("error = %v, want the copy failure named", err)
	}
	if got := liveWrites(f.calls, cfg); len(got) > 0 {
		t.Errorf("a failed install wrote into the LIVE root: %v", got)
	}
	if idx(f.calls, fmt.Sprintf("SwapInstallRoot:%s<->%s:swap", cfg.stagingDir(), cfg.InstallDir)) >= 0 {
		t.Error("a failed install published its partial tree")
	}
	if !maps.Equal(f.treeUnder(cfg.InstallDir), before) {
		t.Errorf("the live root changed: %v, want %v", f.treeUnder(cfg.InstallDir), before)
	}
	// The daemons were never touched either: the restart is on the far side of
	// the publish, so a staging failure costs no downtime at all.
	if idx(f.calls, "Bootout:"+NetdLabel) >= 0 {
		t.Error("a staging failure booted a daemon out")
	}
}

// TestInstallFirstInstallRenamesTheStagedRootIntoPlace pins the other publish
// branch: with no install root on the Mac there is nothing to exchange, so the
// staged tree is renamed into place, nothing is left at the staging path, and
// there is no reap.
func TestInstallFirstInstallRenamesTheStagedRootIntoPlace(t *testing.T) {
	shrinkRestartBudgets(t)
	cfg := stageCfg().withDefaults()
	f := &fakeSystem{}
	if err := Install(context.Background(), f, stageCfg()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if at := idx(f.calls, fmt.Sprintf("SwapInstallRoot:%s<->%s:rename", cfg.stagingDir(), cfg.InstallDir)); at < 0 {
		t.Fatalf("a first install did not take the plain-rename publish; calls =\n%s", strings.Join(f.calls, "\n"))
	}
	if at := idx(f.calls, "RemoveTree:"+cfg.stagingDir()); at >= 0 {
		t.Error("a first install reaped a previous tree it never had")
	}
	if got := f.treeUnder(cfg.InstallDir); len(got) == 0 {
		t.Error("the staged tree was not published at the live path")
	}
}

// TestInstallRevertsTheSwapWhenTheWiringFails is the rollback. A failure after
// the publish and before the reap — here the daemons refusing to come back —
// swaps the previous tree back, restarts the daemons against it, and says all
// of that in one sentence.
func TestInstallRevertsTheSwapWhenTheWiringFails(t *testing.T) {
	shrinkRestartBudgets(t)
	cfg := stageCfg().withDefaults()
	f := &fakeSystem{}
	if err := Install(context.Background(), f, stageCfg()); err != nil {
		t.Fatalf("first Install: %v", err)
	}
	before := f.treeUnder(cfg.InstallDir)
	f.putLoaded(NetdLabel, ServerLabel)
	f.calls = nil

	// The new netd will not bootstrap. The publish has already happened by the
	// time the restart runs, which is exactly the window the revert exists for.
	f.putBootstrapAlways(NetdLabel, errors.New("Bootstrap failed: 125: Domain does not support specified action"))
	err := Install(context.Background(), f, stageCfg())
	if err == nil {
		t.Fatal("Install succeeded with a daemon that never came up")
	}
	// Twice: the publish, then the reverse that puts the previous tree back.
	swap := fmt.Sprintf("SwapInstallRoot:%s<->%s:swap", cfg.stagingDir(), cfg.InstallDir)
	if n := countCalls(f, swap); n != 2 {
		t.Fatalf("the install root was swapped %d times, want 2 (publish then revert); calls =\n%s", n, strings.Join(f.calls, "\n"))
	}
	if !maps.Equal(f.treeUnder(cfg.InstallDir), before) {
		t.Errorf("after the revert the live root is %v, want the original tree %v", f.treeUnder(cfg.InstallDir), before)
	}
	if at := idx(f.calls, "RemoveTree:"+cfg.stagingDir()); at >= 0 {
		t.Error("a failed install reaped the tree it had just rolled back to")
	}
	// One sentence, in restartDaemons' existing shape: the cause, the rollback,
	// and which daemons are up.
	for _, want := range []string{"Bootstrap failed", "rolled back to the previous install root", "daemon state:"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not carry %q", err, want)
		}
	}
}

// TestInstallRefusesASecondConcurrentInstall pins the install-wide lock. Two
// installs interleaving their copies into one staging tree would have the swap
// publish a mixture of two builds — complete-looking and never tested — so the
// second one is refused before it writes anything at all.
func TestInstallRefusesASecondConcurrentInstall(t *testing.T) {
	cfg := stageCfg().withDefaults()
	f := &fakeSystem{}
	// The lock another install is holding.
	release, err := f.LockInstall(cfg.installLockPath())
	if err != nil {
		t.Fatalf("take the lock: %v", err)
	}
	f.calls = nil

	err = Install(context.Background(), f, stageCfg())
	if !errors.Is(err, ErrInstallInProgress) {
		t.Fatalf("Install error = %v, want ErrInstallInProgress", err)
	}
	for _, c := range f.calls {
		for _, write := range []string{"CopyToRootOwned:", "EnsureRootDir:", "EnsureServiceUser:", "WriteLaunchDaemon:", "SwapInstallRoot:"} {
			if strings.HasPrefix(c, write) {
				t.Errorf("the refused install wrote something: %s", c)
			}
		}
	}
	if err := release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	// ...and once the other install finishes, this one proceeds.
	shrinkRestartBudgets(t)
	if err := Install(context.Background(), f, stageCfg()); err != nil {
		t.Fatalf("Install after the lock was released: %v", err)
	}
}

// TestInstallRefusesAnUntrustedStagingPath pins the check that stands between
// "clean up after a crashed install" and "root deletes whatever is at this
// path". A symlink at the staging path is refused, and nothing is removed.
func TestInstallRefusesAnUntrustedStagingPath(t *testing.T) {
	cfg := stageCfg().withDefaults()
	for _, tc := range []struct {
		name string
		seed func(f *fakeSystem)
		want string
	}{
		{
			name: "a symlink",
			seed: func(f *fakeSystem) {
				f.putOwned(cfg.stagingDir(), 0, 0, 0o755|fs.ModeSymlink, EntrySymlink)
			},
			want: "is a symlink",
		},
		{
			name: "a regular file",
			seed: func(f *fakeSystem) { f.putOwned(cfg.stagingDir(), 0, 0, 0o644, EntryRegular) },
			want: "not a directory",
		},
		{
			name: "owned by somebody else",
			seed: func(f *fakeSystem) { f.putOwned(cfg.stagingDir(), 501, 0, 0o755|fs.ModeDir, EntryDir) },
			want: "owned by uid 501, not root",
		},
		{
			name: "group-writable",
			seed: func(f *fakeSystem) { f.putOwned(cfg.stagingDir(), 0, 0, 0o775|fs.ModeDir, EntryDir) },
			want: "group- or world-writable",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeSystem{}
			tc.seed(f)
			err := Install(context.Background(), f, stageCfg())
			if err == nil {
				t.Fatal("Install accepted an untrusted staging path")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to name %q", err, tc.want)
			}
			if at := idx(f.calls, "RemoveTree:"+cfg.stagingDir()); at >= 0 {
				t.Error("root removed the untrusted path instead of refusing it")
			}
			if at := idx(f.calls, "CopyToRootOwned:"+cfg.stagedBinary()); at >= 0 {
				t.Error("the install staged into a path it had refused")
			}
		})
	}
}

// TestStaleStagingTreeIsRemovedBeforeStaging is the other half of that check: a
// trusted tree an earlier run left behind IS removed, because staging this
// install's artifacts over another run's leftovers would publish exactly the
// mixture the staging exists to prevent.
func TestStaleStagingTreeIsRemovedBeforeStaging(t *testing.T) {
	shrinkRestartBudgets(t)
	cfg := stageCfg().withDefaults()
	f := &fakeSystem{}
	f.putOwned(cfg.stagingDir(), 0, 0, 0o755|fs.ModeDir, EntryDir)
	f.putTree(cfg.stagedBinary(), "/tmp/an-older-run/k3sm")
	if err := Install(context.Background(), f, stageCfg()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	remove := idx(f.calls, "RemoveTree:"+cfg.stagingDir())
	create := idx(f.calls, "EnsureRootDir:"+cfg.stagingDir())
	stage := idx(f.calls, "CopyToRootOwned:"+cfg.stagedBinary())
	if remove < 0 || create < remove || stage < create {
		t.Fatalf("the stale tree was not removed before the staging directory was created and filled; calls =\n%s", strings.Join(f.calls, "\n"))
	}
}

// TestDataVolumeStagingIsNeverRedirected is the regression pin for the one
// path under the install root that must NOT be staged: the data
// volume's own staging mount point is a real transient APFS mount NESTED in the
// install root, it runs and tears down at step 0 before the install root is
// staged at all, and it must never be routed through the redirection — a
// migration mounted inside <InstallDir>.staging would be published into the
// install root by the swap, or unmounted out from under itself.
func TestDataVolumeStagingIsNeverRedirected(t *testing.T) {
	cfg := stageCfg().withDefaults()
	// The path is under the install root, so the redirection WOULD move it...
	if got := cfg.stagedPath(cfg.datavolStaging()); got == cfg.datavolStaging() {
		t.Fatalf("stagedPath(%s) = %s: the pin is vacuous unless the datavol mount point is under the install root", cfg.datavolStaging(), got)
	}
	// ...and nothing in the product asks it to. The one call site takes the
	// nested path verbatim; see datavol.go's migrateDataRoot.
	if cfg.datavolStaging() != DefaultInstallDir+"/"+datavolStagingName {
		t.Errorf("datavolStaging() = %s, want the nested mount point %s", cfg.datavolStaging(), DatavolStagingDir)
	}
	if strings.HasPrefix(cfg.datavolStaging(), cfg.stagingDir()) {
		t.Error("the data-volume mount point lives inside the install root's staging tree")
	}
}

// TestStagedPath pins the redirection itself: under the install root it moves,
// anywhere else it does not.
func TestStagedPath(t *testing.T) {
	cfg := Config{InstallDir: "/Library/k3sm"}.withDefaults()
	for _, tc := range []struct{ in, want string }{
		{"/Library/k3sm/k3sm", "/Library/k3sm.staging/k3sm"},
		{"/Library/k3sm/bin/kine", "/Library/k3sm.staging/bin/kine"},
		{"/Library/k3sm", "/Library/k3sm.staging"},
		// Outside the install root: written where it says it is. The plists and
		// the launcher depend on this — redirecting either would move them out
		// from under launchd and off the operator's PATH.
		{"/Library/LaunchDaemons/io.k3sm.server.plist", "/Library/LaunchDaemons/io.k3sm.server.plist"},
		{"/usr/local/bin/k3sm", "/usr/local/bin/k3sm"},
		{"/var/lib/k3sm/server/token", "/var/lib/k3sm/server/token"},
		// The sibling is NOT under the install root, even though its name shares
		// the prefix — the check is path-segment-wise, not string-wise.
		{"/Library/k3sm.staging/k3sm", "/Library/k3sm.staging/k3sm"},
		{"/Library/k3sm-other/k3sm", "/Library/k3sm-other/k3sm"},
	} {
		if got := cfg.stagedPath(tc.in); got != tc.want {
			t.Errorf("stagedPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// The staging directory is a SIBLING, never a child: the kernel cannot
	// exchange a directory with its own parent.
	if strings.HasPrefix(cfg.stagingDir(), cfg.InstallDir+"/") {
		t.Errorf("stagingDir() = %s is inside the install root", cfg.stagingDir())
	}
	// ...and so is the lock, for the same reason: a lock held on a file in the
	// tree being swapped would travel with that tree.
	if strings.HasPrefix(cfg.installLockPath(), cfg.InstallDir+"/") {
		t.Errorf("installLockPath() = %s is inside the install root", cfg.installLockPath())
	}
}

// TestStagingTrustVerdict states every arm of the refusal in a table, including
// the ones no unprivileged filesystem can reach.
func TestStagingTrustVerdict(t *testing.T) {
	const path = "/Library/k3sm.staging"
	for _, tc := range []struct {
		name  string
		entry OwnedEntry
		want  string
	}{
		{name: "root-owned directory", entry: OwnedEntry{UID: 0, Mode: 0o755 | fs.ModeDir, Kind: EntryDir}},
		{name: "symlink", entry: OwnedEntry{UID: 0, Mode: 0o755 | fs.ModeSymlink, Kind: EntrySymlink}, want: "is a symlink"},
		{name: "regular file", entry: OwnedEntry{UID: 0, Mode: 0o644, Kind: EntryRegular}, want: "not a directory"},
		{name: "another owner", entry: OwnedEntry{UID: 501, Mode: 0o755 | fs.ModeDir, Kind: EntryDir}, want: "owned by uid 501, not root"},
		{name: "group-writable", entry: OwnedEntry{UID: 0, Mode: 0o775 | fs.ModeDir, Kind: EntryDir}, want: "group- or world-writable"},
		{name: "world-writable", entry: OwnedEntry{UID: 0, Mode: 0o757 | fs.ModeDir, Kind: EntryDir}, want: "group- or world-writable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := stagingTrustVerdict(path, tc.entry)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("stagingTrustVerdict = %v, want nil", err)
			case tc.want == "":
				return
			case err == nil:
				t.Fatalf("stagingTrustVerdict = nil, want a refusal naming %q", tc.want)
			case !strings.Contains(err.Error(), tc.want):
				t.Errorf("stagingTrustVerdict = %v, want it to name %q", err, tc.want)
			}
			// Every refusal names the path and what to do about it.
			if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "move it aside") {
				t.Errorf("refusal %q does not name the path and the remedy", err)
			}
		})
	}
}

// TestFreeSpacePreflight pins the legibility check: a volume that cannot hold a
// staged copy says so before anything is written, and a volume that can — or an
// estimate that cannot be taken at all — never blocks an install.
func TestFreeSpacePreflight(t *testing.T) {
	t.Run("the verdict", func(t *testing.T) {
		for _, tc := range []struct {
			name       string
			need, free uint64
			wantErr    bool
		}{
			{name: "room to spare", need: 1 << 20, free: 1 << 30},
			{name: "exactly enough", need: 1 << 20, free: 1 << 20},
			{name: "short", need: 2 << 30, free: 1 << 20, wantErr: true},
			{name: "nothing measured", need: 0, free: 0},
		} {
			err := freeSpaceVerdict("/Library", tc.need, tc.free)
			if tc.wantErr != (err != nil) {
				t.Errorf("%s: freeSpaceVerdict(need=%d, free=%d) = %v", tc.name, tc.need, tc.free, err)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "free") {
				t.Errorf("%s: %v does not name what is free and what is needed", tc.name, err)
			}
		}
	})

	t.Run("a short volume refuses before the first write", func(t *testing.T) {
		f := &fakeSystem{}
		f.putSpace(1<<20, 4<<30)
		err := Install(context.Background(), f, stageCfg())
		if err == nil {
			t.Fatal("Install proceeded onto a volume that cannot hold the staged tree")
		}
		if !strings.Contains(err.Error(), "GiB") {
			t.Errorf("error = %v, want the sizes named", err)
		}
		for _, c := range f.calls {
			if strings.HasPrefix(c, "CopyToRootOwned:") || strings.HasPrefix(c, "EnsureServiceUser:") {
				t.Errorf("the refused install wrote something: %s", c)
			}
		}
	})

	t.Run("an estimate that cannot be taken never blocks the install", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		f.putSpaceErr(errors.New("statfs: operation not permitted"))
		if err := Install(context.Background(), f, stageCfg()); err != nil {
			t.Fatalf("Install: %v", err)
		}
	})
}
