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
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/datavol/datavoltest"
)

// purgeRig is one purge test's world: the fake System, the Config the CLI
// would hand Uninstall for `sudo k3sm uninstall --purge --yes`, and the log.
type purgeRig struct {
	f    *fakeSystem
	cfg  Config
	logs *bytes.Buffer
	// disk is the fake diskutil when the rig carries a data volume.
	disk *datavoltest.Fake
	// leftBehind is what deleting the data volume leaves at the data root,
	// which is never the marked tree: the marker lived on the volume.
	leftBehind mountLeftover
}

// mountLeftover is the data root's posture once its volume is deleted.
type mountLeftover int

const (
	// leftEmpty is the ordinary case: an empty mount point directory.
	leftEmpty mountLeftover = iota
	// leftAbsent: the mount point was removed with the volume.
	leftAbsent
	// leftNonEmpty: something sat under the mount point (shadow content), and
	// nothing marks it as k3sm's.
	leftNonEmpty
)

// purgeVolumeUUID is the recorded data volume in the data-volume rigs.
const purgeVolumeUUID = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"

// newPurgeRig builds a confirmed purge of a healthy install of role, every
// preserved tree present and marked. withVolume puts the data root on a
// recorded, mounted k3sm data volume (and the data root under a t.TempDir(), so
// datavol.Delete's own filesystem steps stay inside the test).
func newPurgeRig(t *testing.T, role Role, withVolume bool) *purgeRig {
	t.Helper()
	shrinkPurgeBudgets(t)
	r := &purgeRig{logs: &bytes.Buffer{}}
	if withVolume {
		dv := newDatavolRig(t)
		dv.seedRecord(t, purgeVolumeUUID)
		dv.disk.Vols[purgeVolumeUUID].Mountpoint = dv.cfg.DataRoot
		r.f, r.cfg, r.disk = dv.sys, dv.cfg, dv.disk
		// Deleting the volume takes its contents, marker included, with it:
		// what remains at the data root is the bare mount point, or nothing.
		f, dataRoot := r.f, dv.cfg.DataRoot
		dv.disk.Log = func(line string) {
			f.calls = append(f.calls, "datavol."+line)
			if !strings.HasPrefix(line, "deletevolume ") {
				return
			}
			delete(f.purge.markers, dataRoot)
			switch r.leftBehind {
			case leftAbsent:
				delete(f.purge.stats, dataRoot)
			case leftNonEmpty:
				if f.purge.nonEmpty == nil {
					f.purge.nonEmpty = map[string]bool{}
				}
				f.purge.nonEmpty[dataRoot] = true
			}
		}
	} else {
		r.f = &fakeSystem{}
		// The default data root, read through a fake: the dev Mac running the
		// tests may carry a real k3sm volume at /var/lib/k3sm.
		r.disk = datavoltest.New()
		r.cfg = Config{DataRootFS: r.disk.FS(), DataVolumeDeps: r.disk.Deps()}
	}
	r.cfg.Role = role
	r.cfg.Purge, r.cfg.PurgeConfirmed = true, true
	r.cfg.TargetUser, r.cfg.TargetHome = "alice", "/Users/alice"
	r.cfg.Logger = slog.New(slog.NewTextHandler(r.logs, nil))
	d := r.cfg.withDefaults()
	r.f.purge.user = &ServiceUserRecord{Exists: true, UID: 271, RealName: serviceUserRealName, Shell: serviceUserShell, Home: d.DataRoot}
	for _, a := range r.manifest() {
		if a.disp == dispPreserve && a.kind == kindDir {
			r.f.seedPurgeable(a.path)
		}
	}
	return r
}

// manifest is artifactManifest itself, for the Config the rig describes.
func (r *purgeRig) manifest() []artifact {
	d := r.cfg.withDefaults()
	d.dataVolumeDeclared = r.f != nil && r.disk != nil && len(r.disk.Files) > 0
	return artifactManifest(d)
}

func (r *purgeRig) run() error { return Uninstall(context.Background(), r.f, r.cfg) }

// called reports whether the log holds a call with this exact text.
func (r *purgeRig) called(c string) bool { return slices.Contains(r.f.calls, c) }

// anyCall reports whether the log holds a call starting with prefix.
func (r *purgeRig) anyCall(prefix string) bool { return callIndex(r.f.calls, prefix) >= 0 }

// TestPurgeRemovesEveryPreservedArtifact is the gate's completeness half: it
// walks artifactManifest itself and demands a removal for EVERY entry the
// ordinary uninstall keeps, dispatched on kind. A preserved kind this test has
// no arm for fails it, so a new kind cannot be added without deciding how the
// purge removes it.
func TestPurgeRemovesEveryPreservedArtifact(t *testing.T) {
	for _, tc := range []struct {
		name   string
		role   Role
		volume bool
	}{
		{"server", RoleServer, false},
		{"agent", RoleAgent, false},
		{"server on a data volume", RoleServer, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newPurgeRig(t, tc.role, tc.volume)
			m := r.manifest()
			if err := r.run(); err != nil {
				t.Fatalf("purge: %v\ncalls:\n%s", err, strings.Join(r.f.calls, "\n"))
			}
			var purged []string
			for _, c := range r.f.calls {
				if p, ok := strings.CutPrefix(c, "PurgeTree:"); ok {
					purged = append(purged, p)
				}
				// A root removed as an empty directory (the mount point a
				// deleted volume left) is gone with everything that was in it.
				if e, ok := strings.CutPrefix(c, "RemoveEntry:"); ok {
					if dir, name, ok := strings.Cut(e, ":"); ok && slices.Contains(m, artifact{kind: kindDir, disp: dispPreserve, path: filepath.Join(dir, name)}) {
						purged = append(purged, filepath.Join(dir, name))
					}
				}
			}
			inPurged := func(p string) bool {
				return slices.Contains(purged, p) || coveredBy(p, purged)
			}
			seen := 0
			for _, a := range m {
				if a.disp != dispPreserve {
					continue
				}
				seen++
				switch a.kind {
				case kindServiceUser:
					if !r.called("DeleteServiceUser:" + a.user) {
						t.Errorf("service user %s was not deleted", a.user)
					}
				case kindKubeconfig:
					if !r.called("RemoveAdminKubeconfigContext:" + a.user) {
						t.Errorf("the k3sm context in %s's kubeconfig was not removed", a.user)
					}
				case kindDir:
					if !inPurged(a.path) && !r.called("RemoveEntry:"+filepath.Dir(a.path)+":"+filepath.Base(a.path)) {
						t.Errorf("preserved dir %s was not purged (purged: %v)", a.path, purged)
					}
				case kindFile:
					if !inPurged(a.path) && !r.called("RemoveEntry:"+filepath.Dir(a.path)+":"+filepath.Base(a.path)) {
						t.Errorf("preserved file %s was neither removed nor inside a purged tree", a.path)
					}
				default:
					t.Fatalf("preserved artifact of kind %v (%s) has no purge assertion", a.kind, a.path)
				}
			}
			if seen == 0 {
				t.Fatal("the manifest preserves nothing; the test asserted nothing")
			}
			if tc.volume {
				if !r.anyCall("datavol.deletevolume " + purgeVolumeUUID) {
					t.Errorf("the data volume was not deleted through datavol.Delete")
				}
				if !slices.Contains(m, artifact{kind: kindFile, disp: dispPreserve, path: dataroot.DefaultRecordPath}) {
					t.Errorf("the data-volume config did not declare the record; the case is vacuous")
				}
			}
			out := r.logs.String()
			if strings.Contains(out, "kept, so a reinstall") || !strings.Contains(out, "k3sm purged") {
				t.Errorf("purge output must say what it removed and not claim anything was kept:\n%s", out)
			}
		})
	}
}

// TestPurgeOrderIsBootoutsThenProcessesThenVolumeThenTreesThenUser pins the one
// order the purge may run in, on one interleaved call log.
func TestPurgeOrderIsBootoutsThenProcessesThenVolumeThenTreesThenUser(t *testing.T) {
	r := newPurgeRig(t, RoleServer, true)
	r.f.putLoaded("io.k3sm.server", "io.k3sm.stray")
	r.f.purge.procs = []int{4242}
	d := r.cfg.withDefaults()
	if err := r.run(); err != nil {
		t.Fatalf("purge: %v", err)
	}
	assertOrder(t, r.f.calls,
		"Bootout:io.k3sm.server", // the ordinary uninstall
		"FlushLo0Aliases:",       // ...ran to its end
		"LoadedLabels:io.k3sm.",  // then every k3sm job is listed
		"Bootout:io.k3sm.stray",  // and the one it did not know is booted out
		"BootoutUserDomain:271",  // _k3sm's own launchd domain is booted out
		"ProcessesOfUID:271",     // no process may still run as _k3sm
		"KillProcess:4242",       // the one that would not exit is killed once
		"datavol.unmount",        // the volume is unmounted
		"datavol.deletevolume",   // and deleted, never walked
		// then the trees: the bare mount point the volume left, then the logs
		"RemoveEntry:"+filepath.Dir(r.cfg.DataRoot)+":"+filepath.Base(r.cfg.DataRoot),
		"PurgeTree:"+LogDir,
		// the files outside them, both arguments records included
		"RemoveEntry:"+filepath.Dir(d.ServerArgsRecord)+":"+filepath.Base(d.ServerArgsRecord),
		"RemoveEntry:"+filepath.Dir(d.AgentArgsRecord)+":"+filepath.Base(d.AgentArgsRecord),
		"RemoveAdminKubeconfigContext:", // the kubeconfig context
		"DeleteServiceUser:_k3sm",       // and the user last
	)
}

// TestPurgeRefusals is the negative table: every case ends in an error with no
// tree removed and no user deleted. Those refused in the preflight have also
// booted nothing out: the Mac is exactly as it was.
func TestPurgeRefusals(t *testing.T) {
	errBoom := errors.New("boom")
	for _, tc := range []struct {
		name string
		// volume puts the data root on a recorded data volume.
		volume bool
		edit   func(r *purgeRig)
		// preflight cases leave the install untouched.
		preflight bool
		want      error
		// reason is a fragment of the refusal, so each case fails for its own
		// reason and not an incidental one.
		reason string
	}{
		{name: "the data root is /", reason: "is a system directory", preflight: true, want: ErrPurgeRefused, edit: func(r *purgeRig) {
			r.cfg.DataRoot = "/"
			r.f.seedPurgeable("/")
		}},
		{name: "the data root is the invoking user's home", reason: "overlaps the home directory", preflight: true, want: ErrPurgeRefused, edit: func(r *purgeRig) {
			r.cfg.TargetHome = "/opt/home/alice"
			r.cfg.DataRoot = "/opt/home/alice"
			r.f.seedPurgeable(r.cfg.DataRoot)
			r.f.purge.user.Home = r.cfg.DataRoot
		}},
		{name: "the data root contains the invoking user's home", reason: "overlaps the home directory", preflight: true, want: ErrPurgeRefused, edit: func(r *purgeRig) {
			r.cfg.TargetHome = "/opt/k3sm/alice"
			r.cfg.DataRoot = "/opt/k3sm"
			r.f.seedPurgeable(r.cfg.DataRoot)
			r.f.purge.user.Home = r.cfg.DataRoot
		}},
		{name: "the data root is under /Users", reason: "under /Users or /Volumes", preflight: true, want: ErrPurgeRefused, edit: func(r *purgeRig) {
			r.cfg.TargetHome = ""
			r.cfg.DataRoot = "/Users/Shared/k3sm"
			r.f.seedPurgeable(r.cfg.DataRoot)
			r.f.purge.user.Home = r.cfg.DataRoot
		}},
		{name: "the data root resolves under /Users", reason: "under /Users or /Volumes", preflight: true, want: ErrPurgeRefused, edit: func(r *purgeRig) {
			r.f.purge.resolved = map[string]string{DefaultDataRoot: "/Users/alice/k3sm"}
		}},
		{name: "the data root is a symlink", reason: "is a symlink", preflight: true, want: ErrPurgeRefused, edit: func(r *purgeRig) {
			st := r.f.purge.stats[DefaultDataRoot]
			st.Kind = EntrySymlink
			r.f.purge.stats[DefaultDataRoot] = st
		}},
		{name: "the log dir is a mount point", reason: "is a mount point", preflight: true, want: ErrPurgeRefused, edit: func(r *purgeRig) {
			st := r.f.purge.stats[LogDir]
			st.Dev = 7
			r.f.purge.stats[LogDir] = st
		}},
		{name: "the data root is mounted with no k3sm record", reason: "mounted filesystem with no k3sm data-volume record", preflight: true, want: ErrPurgeRefused, edit: func(r *purgeRig) {
			r.disk.Add(datavoltest.Volume{UUID: "FFFFFFFF-0000-0000-0000-000000000000", Name: "theirs", Mountpoint: DefaultDataRoot})
		}},
		{name: "the data root has no marker and is not empty", reason: "run `sudo k3sm install` once", preflight: true, want: ErrPurgeRefused, edit: func(r *purgeRig) {
			delete(r.f.purge.markers, DefaultDataRoot)
			r.f.purge.nonEmpty = map[string]bool{DefaultDataRoot: true}
		}},
		{name: "the marker is not root-owned", reason: "not root", preflight: true, want: ErrPurgeRefused, edit: func(r *purgeRig) {
			m := r.f.purge.markers[LogDir]
			m.UID = 271
			r.f.purge.markers[LogDir] = m
		}},
		{name: "the marker is group-writable", reason: "group- or world-writable", preflight: true, want: ErrPurgeRefused, edit: func(r *purgeRig) {
			m := r.f.purge.markers[DefaultDataRoot]
			m.Mode = 0o664
			r.f.purge.markers[DefaultDataRoot] = m
		}},
		{name: "the marker is world-writable", reason: "group- or world-writable", preflight: true, want: ErrPurgeRefused, edit: func(r *purgeRig) {
			m := r.f.purge.markers[DefaultDataRoot]
			m.Mode = 0o646
			r.f.purge.markers[DefaultDataRoot] = m
		}},
		{name: "the marker names another path", reason: "names \"/var/log/k3sm\"", preflight: true, want: ErrPurgeRefused, edit: func(r *purgeRig) {
			m := r.f.purge.markers[DefaultDataRoot]
			m.Content = dataroot.MarkerContent(LogDir)
			r.f.purge.markers[DefaultDataRoot] = m
		}},
		{name: "the service user is not the account k3sm created", reason: "not the account k3sm created", preflight: true, want: ErrPurgeRefused, edit: func(r *purgeRig) {
			r.f.purge.user.RealName = "Someone Else"
		}},
		{name: "a legacy-shaped service user with another home", reason: "not the data root", preflight: true, want: ErrPurgeRefused, edit: func(r *purgeRig) {
			r.f.purge.user.RealName, r.f.purge.user.Home = DefaultServiceUser, "/Users/alice"
		}},
		{name: "the service uid is root", reason: "outside the range", preflight: true, want: ErrPurgeRefused, edit: func(r *purgeRig) {
			r.f.purge.user.UID = 0
		}},
		{name: "the service uid is a login user's", reason: "outside the range", preflight: true, want: ErrPurgeRefused, edit: func(r *purgeRig) {
			r.f.purge.user.UID = 501
		}},
		{name: "a bootout fails in the uninstall phase", reason: "the purge did not run", want: errBoom, edit: func(r *purgeRig) {
			r.f.purge.bootoutErrs = map[string]error{ServerLabel: errBoom}
		}},
		{name: "a k3sm job never leaves launchd", reason: "still loaded after bootout: io.k3sm.stray", want: ErrPurgeRefused, edit: func(r *purgeRig) {
			r.f.putLoaded("io.k3sm.stray")
			r.f.purge.stuck = map[string]bool{"io.k3sm.stray": true}
		}},
		{name: "a _k3sm process survives SIGKILL", reason: "after SIGKILL: 4242", want: ErrPurgeRefused, edit: func(r *purgeRig) {
			r.f.purge.procs = []int{4242}
			r.f.purge.unkillable = map[int]bool{4242: true}
		}},
		{name: "a _k3sm process survives SIGKILL after a failed domain bootout", reason: "after SIGKILL: 4242 (launchctl bootout user/271: boom)", want: ErrPurgeRefused, edit: func(r *purgeRig) {
			r.f.purge.procs = []int{4242}
			r.f.purge.unkillable = map[int]bool{4242: true}
			r.f.purge.domainBootoutErr = fmt.Errorf("launchctl bootout user/271: %w", errBoom)
		}},
		{name: "datavol.Delete fails", reason: "delete the data volume", volume: true, want: errBoom, edit: func(r *purgeRig) {
			r.disk.SetErr("deletevolume", errBoom)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newPurgeRig(t, RoleServer, tc.volume)
			tc.edit(r)
			err := r.run()
			if !errors.Is(err, tc.want) {
				t.Fatalf("purge = %v, want %v\ncalls:\n%s", err, tc.want, strings.Join(r.f.calls, "\n"))
			}
			if !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("purge refused for the wrong reason: %v (want %q)", err, tc.reason)
			}
			if r.anyCall("PurgeTree:") || r.anyCall("DeleteServiceUser:") || r.anyCall("RemoveAdminKubeconfigContext:") {
				t.Fatalf("a refused purge removed something:\n%s", strings.Join(r.f.calls, "\n"))
			}
			if tc.preflight && (r.anyCall("Bootout:") || r.anyCall("RemoveAll:") || r.anyCall("ProcessesOfUID:") || r.anyCall("KillProcess:")) {
				t.Fatalf("a preflight refusal tore the install down:\n%s", strings.Join(r.f.calls, "\n"))
			}
		})
	}

	t.Run("no --yes makes no system call at all", func(t *testing.T) {
		r := newPurgeRig(t, RoleServer, false)
		r.cfg.PurgeConfirmed = false
		if err := r.run(); !errors.Is(err, ErrPurgeNotConfirmed) {
			t.Fatalf("purge = %v, want ErrPurgeNotConfirmed", err)
		}
		if len(r.f.calls) != 0 {
			t.Fatalf("an unconfirmed purge made system calls: %v", r.f.calls)
		}
	})

	t.Run("a different-device child stops the purge before the user is deleted", func(t *testing.T) {
		r := newPurgeRig(t, RoleServer, false)
		r.f.purge.purgeErrs = map[string]error{DefaultDataRoot: errors.New(DefaultDataRoot + "/pods/x is on another filesystem")}
		if err := r.run(); err == nil || !strings.Contains(err.Error(), "another filesystem") {
			t.Fatalf("purge = %v, want the cross-device error", err)
		}
		if r.anyCall("DeleteServiceUser:") {
			t.Fatal("the service user was deleted although a tree could not be purged")
		}
		// An ordinary walk failure is collected and the pass goes on.
		if !r.called("PurgeTree:" + LogDir) {
			t.Fatal("a walk failure in one tree stopped the purge of the next")
		}
	})
}

// TestPurgeAbortsWhenTheSecondPassRefuses pins the abort: a guard refusal, or a
// tree that is no longer the one approved, in the removal pass stops the purge
// there. No further root, no preserved file, no kubeconfig edit, no user delete.
func TestPurgeAbortsWhenTheSecondPassRefuses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		volume bool
		edit   func(r *purgeRig)
		want   error
	}{
		{"the volume left a non-empty, unmarked mount point", true, func(r *purgeRig) { r.leftBehind = leftNonEmpty }, ErrPurgeRefused},
		{"the data root was swapped after the guard", false, func(r *purgeRig) {
			r.f.purge.purgeErrs = map[string]error{DefaultDataRoot: fmt.Errorf("%s: %w", DefaultDataRoot, ErrPurgeTreeChanged)}
		}, ErrPurgeTreeChanged},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newPurgeRig(t, RoleServer, tc.volume)
			tc.edit(r)
			args := r.cfg.withDefaults().argsRecordPath()
			if err := r.run(); !errors.Is(err, tc.want) {
				t.Fatalf("purge = %v, want %v", err, tc.want)
			}
			for _, c := range []string{"PurgeTree:" + LogDir, "RemoveEntry:" + filepath.Dir(args) + ":" + filepath.Base(args), "RemoveAdminKubeconfigContext:alice", "DeleteServiceUser:_k3sm"} {
				if r.called(c) {
					t.Errorf("an aborted purge went on to %s:\n%s", c, strings.Join(r.f.calls, "\n"))
				}
			}
		})
	}
}

// TestPurgeIsRerunnable pins the two postures a half-finished purge, or a
// deleted data volume, leaves at a root: absent, or an empty directory with no
// marker. Both count as already purged, so the purge completes.
func TestPurgeIsRerunnable(t *testing.T) {
	t.Run("the volume left an empty mount point", func(t *testing.T) {
		r := newPurgeRig(t, RoleServer, true)
		r.leftBehind = leftEmpty
		if err := r.run(); err != nil {
			t.Fatalf("purge: %v", err)
		}
		if !r.called("RemoveEntry:"+filepath.Dir(r.cfg.DataRoot)+":"+filepath.Base(r.cfg.DataRoot)) || !r.called("DeleteServiceUser:_k3sm") {
			t.Fatalf("the empty mount point was not removed, or the purge did not finish:\n%s", strings.Join(r.f.calls, "\n"))
		}
		if r.called("PurgeTree:" + r.cfg.DataRoot) {
			t.Fatal("an empty, unmarked directory was walked rather than rmdir'd")
		}
	})
	t.Run("the volume took the mount point with it", func(t *testing.T) {
		r := newPurgeRig(t, RoleServer, true)
		r.leftBehind = leftAbsent
		if err := r.run(); err != nil {
			t.Fatalf("purge: %v", err)
		}
		if !r.called("DeleteServiceUser:_k3sm") {
			t.Fatal("the purge did not finish")
		}
	})
	t.Run("an empty, unmarked data root from an interrupted purge", func(t *testing.T) {
		r := newPurgeRig(t, RoleServer, false)
		delete(r.f.purge.markers, DefaultDataRoot)
		if err := r.run(); err != nil {
			t.Fatalf("purge: %v", err)
		}
		if !r.called("RemoveEntry:/var/lib:k3sm") || r.called("PurgeTree:"+DefaultDataRoot) {
			t.Fatalf("the empty root was not rmdir'd:\n%s", strings.Join(r.f.calls, "\n"))
		}
	})
}

// TestPurgeSettleToleratesABootoutErrorThatUnloads pins the bootout race: an
// error from a bootout is not the verdict, the label still being loaded is.
func TestPurgeSettleToleratesABootoutErrorThatUnloads(t *testing.T) {
	r := newPurgeRig(t, RoleServer, false)
	r.f.putLoaded("io.k3sm.stray")
	r.f.purge.bootoutErrs = map[string]error{"io.k3sm.stray": errors.New("Boot-out failed: 5: Input/output error")}
	r.f.purge.unloadDespiteErr = map[string]bool{"io.k3sm.stray": true}
	if err := r.run(); err != nil {
		t.Fatalf("purge = %v, want success: the label left launchd", err)
	}

	r = newPurgeRig(t, RoleServer, false)
	r.f.putLoaded("io.k3sm.stray")
	r.f.purge.bootoutErrs = map[string]error{"io.k3sm.stray": errors.New("Boot-out failed: 5: Input/output error")}
	err := r.run()
	if !errors.Is(err, ErrPurgeRefused) || !strings.Contains(err.Error(), "Input/output error") {
		t.Fatalf("purge = %v, want a refusal naming the bootout error", err)
	}
}

// TestPurgeGuardPathRules pins the pure path half of the guard.
func TestPurgeServiceUserIdentity(t *testing.T) {
	const name = DefaultServiceUser
	current := ServiceUserRecord{Exists: true, UID: 271, RealName: serviceUserRealName, Shell: serviceUserShell, Home: DefaultDataRoot}
	for _, tc := range []struct {
		name   string
		edit   func(*ServiceUserRecord)
		reason string // "" = accepted
	}{
		{name: "the current shape", edit: func(*ServiceUserRecord) {}},
		{name: "a legacy RealName equal to the account name", edit: func(r *ServiceUserRecord) { r.RealName = name }},
		{name: "a legacy empty RealName", edit: func(r *ServiceUserRecord) { r.RealName = "" }},
		{name: "the shape a purge that could not delete it left", edit: func(r *ServiceUserRecord) { r.RealName = serviceUserDisabledRealName }},
		{name: "a legacy RealName with the wrong home", reason: "not the data root", edit: func(r *ServiceUserRecord) {
			r.RealName, r.Home = name, "/Users/alice"
		}},
		{name: "a legacy RealName with the wrong shell", reason: "shell", edit: func(r *ServiceUserRecord) {
			r.RealName, r.Shell = name, "/bin/zsh"
		}},
		{name: "a legacy RealName with a login uid", reason: "outside the range", edit: func(r *ServiceUserRecord) {
			r.RealName, r.UID = name, 501
		}},
		{name: "a legacy RealName with uid 0", reason: "outside the range", edit: func(r *ServiceUserRecord) {
			r.RealName, r.UID = name, 0
		}},
		{name: "a human-looking RealName", reason: "(or, for an account an older install created, empty or \"_k3sm\")", edit: func(r *ServiceUserRecord) {
			r.RealName = "Alice Example"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := current
			tc.edit(&rec)
			err := checkServiceUser(name, rec, DefaultDataRoot)
			if tc.reason == "" {
				if err != nil {
					t.Fatalf("checkServiceUser = %v, want accepted", err)
				}
				return
			}
			if !errors.Is(err, ErrPurgeRefused) || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("checkServiceUser = %v, want ErrPurgeRefused mentioning %q", err, tc.reason)
			}
		})
	}

	t.Run("a purge deletes the account an older install created", func(t *testing.T) {
		r := newPurgeRig(t, RoleServer, false)
		r.f.purge.user.RealName = DefaultServiceUser
		if err := r.run(); err != nil {
			t.Fatalf("purge: %v", err)
		}
		if !r.called("DeleteServiceUser:" + DefaultServiceUser) {
			t.Fatalf("the legacy service user was not deleted:\n%s", strings.Join(r.f.calls, "\n"))
		}
	})
}

func TestPurgeGuardPathRules(t *testing.T) {
	home := []string{"/Users/alice"}
	for _, tc := range []struct {
		target, resolved string
		ok               bool
	}{
		{"/var/lib/k3sm", "/private/var/lib/k3sm", true},
		{"/var/log/k3sm", "/private/var/log/k3sm", true},
		{"/private/var", "/private/var", false},
		{"/var", "/private/var", false},
		{"/var/lib/k3sm", "/private/var", false},
		{"/Library", "/Library", false},
		{"/Users/Shared", "/Users/Shared", false},
		{"/Users/alice/k3sm", "/Users/alice/k3sm", false},
		{"/USERS/alice/k3sm", "/USERS/alice/k3sm", false},
		{"/Volumes/k3sm", "/Volumes/k3sm", false},
		{"/System/Volumes/Data/Users/bob", "/System/Volumes/Data/Users/bob", false},
		{"/System/Volumes/Data/private/var/lib/k3sm", "/System/Volumes/Data/private/var/lib/k3sm", true},
		{"/opt", "/opt", false},
		{"/var/lib/k3sm", "/Users/alice", false},
	} {
		err := purgePathRules(tc.target, tc.resolved, home)
		if (err == nil) != tc.ok {
			t.Errorf("purgePathRules(%s -> %s) = %v, want ok=%v", tc.target, tc.resolved, err, tc.ok)
		}
	}
}

// TestPurgeBootsOutTheServiceUserDomain pins the user-domain step: launchd
// keeps a per-user domain for the service account and respawns its agents
// (distnoted among them) after a SIGKILL, so the domain is booted out before
// the process sweep, and the sweep's verdict, not the bootout's exit, decides.
func TestPurgeBootsOutTheServiceUserDomain(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(r *purgeRig)
	}{
		{"a respawning domain agent is ended by the bootout", func(r *purgeRig) {
			r.f.purge.procs = []int{4242}
			r.f.purge.domainProcs = []int{4242}
		}},
		{"a bootout error whose domain still ends is tolerated", func(r *purgeRig) {
			r.f.purge.procs = []int{4242}
			r.f.purge.domainProcs = []int{4242}
			r.f.purge.domainBootoutErr = errors.New("Boot-out failed: 5: Input/output error")
		}},
		{"a killed process reaped by the re-check is not a survivor", func(r *purgeRig) {
			r.f.purge.procs = []int{4242}
			r.f.purge.slowDeath = map[int]int{4242: 1}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newPurgeRig(t, RoleServer, false)
			tc.edit(r)
			if err := r.run(); err != nil {
				t.Fatalf("purge: %v\ncalls:\n%s", err, strings.Join(r.f.calls, "\n"))
			}
			assertOrder(t, r.f.calls, "LoadedLabels:io.k3sm.", "BootoutUserDomain:271", "ProcessesOfUID:271", "PurgeTree:"+DefaultDataRoot, "DeleteServiceUser:_k3sm")
		})
	}

	t.Run("no service uid, no domain bootout", func(t *testing.T) {
		r := newPurgeRig(t, RoleServer, false)
		r.f.purge.user = &ServiceUserRecord{}
		if err := r.run(); err != nil {
			t.Fatalf("purge: %v", err)
		}
		if r.anyCall("BootoutUserDomain:") {
			t.Fatalf("a purge with no service user booted out a user domain:\n%s", strings.Join(r.f.calls, "\n"))
		}
	})

	for _, out := range []struct {
		text string
		gone bool
	}{
		{"Boot-out failed: 3: No such process", true},
		{"Could not find domain for user 271", true},
		{"Boot-out failed: 113: Could not find specified service", true},
		{"Boot-out failed: 5: Input/output error", false},
		{"Boot-out failed: 1: Operation not permitted", false},
	} {
		if got := launchctlDomainGone(out.text); got != out.gone {
			t.Errorf("launchctlDomainGone(%q) = %v, want %v", out.text, got, out.gone)
		}
	}
}

// TestPurgeServiceUserDeletionBound pins the deletion's own bound: long enough
// for a person at the screen to answer macOS's approval prompt, short enough
// that an unattended purge does not sit on a prompt nobody will answer.
func TestPurgeServiceUserDeletionBound(t *testing.T) {
	if purgeUserDeleteTimeout < 60*time.Second || purgeUserDeleteTimeout > 120*time.Second {
		t.Fatalf("purgeUserDeleteTimeout is %s, want between 1m and 2m", purgeUserDeleteTimeout)
	}
	r := newPurgeRig(t, RoleServer, false)
	if err := r.run(); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if b := r.f.purge.deleteBound; b <= purgeCommandTimeout || b > purgeUserDeleteTimeout {
		t.Fatalf("the user deletion ran under a %s bound, want purgeUserDeleteTimeout (%s)", b, purgeUserDeleteTimeout)
	}
}

// TestPurgeServiceUserOutcomes pins the last step's three outcomes. A deletion
// macOS refused, or one still waiting on an approval at the bound, is not a
// purge failure: everything else is already removed, the account is left
// disabled, and the final line says how to finish by hand.
func TestPurgeServiceUserOutcomes(t *testing.T) {
	denied := fmt.Errorf("dscl . -delete /Users/_k3sm: DS Error: -14120 (eDSPermissionError): %w", errServiceUserDeleteDenied)
	timedOut := fmt.Errorf("dscl . -delete /Users/_k3sm: signal: killed: %w", context.DeadlineExceeded)
	for _, tc := range []struct {
		name string
		edit func(r *purgeRig)
		// deleted: the account is gone and the normal line is printed.
		deleted bool
		// want are fragments of the final line, when the account remains.
		want []string
	}{
		{name: "deleted", deleted: true, edit: func(*purgeRig) {}},
		{name: "refused by macOS (-14120)", edit: func(r *purgeRig) { r.f.purge.deleteErr = denied }, want: []string{
			"the _k3sm account remains (disabled",
			"would not let an unattended process delete it",
			"needs a person at the screen to approve it",
			"delete it by hand, run `sudo dscl . -delete /Users/_k3sm` in Terminal and click Allow",
			"Re-running `sudo k3sm uninstall --purge --yes`",
		}},
		{name: "timed out waiting for an approval", edit: func(r *purgeRig) { r.f.purge.deleteErr = timedOut }, want: []string{
			"the _k3sm account remains (disabled",
			"did not allow the deletion within 1m30s",
			"an approval prompt may still be waiting on the screen",
			"delete it by hand, run `sudo dscl . -delete /Users/_k3sm`",
		}},
		{name: "dscl reported success but the record is still there", edit: func(r *purgeRig) {
			r.f.purge.deleteErr = nil
			r.f.purge.deleteIsNoop = true
		}, want: []string{"the _k3sm account remains (disabled", "delete it by hand"}},
		{name: "disabling the leftover account fails too", edit: func(r *purgeRig) {
			r.f.purge.deleteErr = denied
			r.f.purge.disableErr = errors.New("boom")
		}, want: []string{"the _k3sm account remains (hidden, with no login shell", "relabelling it failed: boom", "delete it by hand"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newPurgeRig(t, RoleServer, false)
			tc.edit(r)
			if err := r.run(); err != nil {
				t.Fatalf("purge = %v, want success\ncalls:\n%s", err, strings.Join(r.f.calls, "\n"))
			}
			// Every other removal happened, and before the deletion.
			assertOrder(t, r.f.calls, "PurgeTree:"+DefaultDataRoot, "PurgeTree:"+LogDir, "RemoveAdminKubeconfigContext:alice", "DeleteServiceUser:_k3sm")
			out := r.logs.String()
			if tc.deleted {
				if !strings.Contains(out, "the _k3sm service user") || strings.Contains(out, "account remains") || r.anyCall("DisableServiceUser:") {
					t.Fatalf("a deleted account must be reported removed, and nothing disabled:\n%s", out)
				}
				return
			}
			if !r.called("DisableServiceUser:_k3sm") {
				t.Fatalf("the account that remains was not disabled:\n%s", strings.Join(r.f.calls, "\n"))
			}
			if strings.Contains(out, "the _k3sm service user") {
				t.Errorf("an account that remains was reported removed:\n%s", out)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("final line lacks %q:\n%s", w, out)
				}
			}
			if !strings.Contains(out, "k3sm purged; removed: ") || strings.Index(out, "account remains") < strings.Index(out, "k3sm purged") {
				t.Errorf("the account line must come after the purged line:\n%s", out)
			}
		})
	}
}

// TestPurgeRerunWithOnlyTheAccountLeft pins the re-run over a Mac where a
// purge removed everything but the account it could not delete: no data root,
// no logs, no records, no jobs. It is clean, it tries the deletion again, and
// it reports the same way, or the normal line once the deletion is allowed.
func TestPurgeRerunWithOnlyTheAccountLeft(t *testing.T) {
	r := newPurgeRig(t, RoleServer, false)
	r.f.purge.deleteErr = fmt.Errorf("DS Error: -14120 (eDSPermissionError): %w", errServiceUserDeleteDenied)
	if err := r.run(); err != nil {
		t.Fatalf("first purge: %v", err)
	}
	if !r.f.purge.disabled || r.f.purge.user.RealName != serviceUserDisabledRealName {
		t.Fatal("the first purge did not leave the account disabled; the case is vacuous")
	}
	for _, p := range []string{DefaultDataRoot, LogDir} {
		if _, ok := r.f.purge.stats[p]; ok {
			t.Fatalf("the first purge left %s behind; the case is vacuous", p)
		}
	}
	if len(r.f.purge.markers) != 0 {
		t.Fatalf("the first purge left markers behind (%v); the case is vacuous", r.f.purge.markers)
	}

	for _, allowed := range []bool{false, true} {
		r.f.calls = nil
		r.logs.Reset()
		if allowed {
			r.f.purge.deleteErr = nil
		}
		if err := r.run(); err != nil {
			t.Fatalf("re-run (allowed=%v) = %v, want success\ncalls:\n%s", allowed, err, strings.Join(r.f.calls, "\n"))
		}
		if !r.called("DeleteServiceUser:_k3sm") {
			t.Fatalf("re-run (allowed=%v) did not try the deletion again:\n%s", allowed, strings.Join(r.f.calls, "\n"))
		}
		out := r.logs.String()
		if allowed {
			if !r.f.purge.userDeleted || !strings.Contains(out, "the _k3sm service user") || strings.Contains(out, "account remains") {
				t.Fatalf("an allowed re-run must delete and report the account:\n%s", out)
			}
			continue
		}
		if !strings.Contains(out, "the _k3sm account remains (disabled") || !strings.Contains(out, "sudo dscl . -delete /Users/_k3sm") {
			t.Fatalf("a refused re-run must report the account the same way:\n%s", out)
		}
	}
}

func TestDsclPermissionDenied(t *testing.T) {
	for _, tc := range []struct {
		out  string
		want bool
	}{
		{"<dscl_cmd> DS Error: -14120 (eDSPermissionError)", true},
		{"DS Error: -14120", true},
		{"eDSPermissionError", true},
		{"<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)", false},
		{"", false},
	} {
		if got := dsclPermissionDenied(tc.out); got != tc.want {
			t.Errorf("dsclPermissionDenied(%q) = %v, want %v", tc.out, got, tc.want)
		}
	}
}

// TestPurgeRemovesBothArgsRecordsWithoutTheManifest pins that both arguments
// records go whatever the manifest names: a server purge's manifest carries
// only the server record (no agent plist is on disk), and a re-run over a
// partially purged Mac still removes, and tolerates the absence of, both.
func TestPurgeRemovesBothArgsRecordsWithoutTheManifest(t *testing.T) {
	r := newPurgeRig(t, RoleServer, false)
	d := r.cfg.withDefaults()
	if slices.ContainsFunc(r.manifest(), func(a artifact) bool { return a.path == d.AgentArgsRecord }) {
		t.Fatal("the server manifest names the agent record; the case is vacuous")
	}
	r.f.files = map[string][]byte{d.ServerArgsRecord: []byte("{}"), d.AgentArgsRecord: []byte("{}")}
	for run := 1; run <= 2; run++ {
		r.f.calls = nil
		if err := r.run(); err != nil {
			t.Fatalf("purge run %d: %v\ncalls:\n%s", run, err, strings.Join(r.f.calls, "\n"))
		}
		for _, p := range []string{d.ServerArgsRecord, d.AgentArgsRecord} {
			if !r.called("RemoveEntry:" + filepath.Dir(p) + ":" + filepath.Base(p)) {
				t.Errorf("purge run %d did not remove %s", run, p)
			}
			if _, ok := r.f.files[p]; ok {
				t.Errorf("purge run %d left %s", run, p)
			}
		}
	}
}
