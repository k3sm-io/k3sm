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
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// podLogEntry is how a test describes one entry of the container-log tree an
// OLDER install left on disk: where it is (relative to the tree root it is
// seeded under), who owns it, what it permits, and what it IS.
//
// The kind is explicit for the same reason seedLegacyEntry's is: EntryOther is
// the zero value, so a row that means "a regular file" has to say so, and the
// entry these rows most need to be able to plant — a symlink in a tree a root
// walk is about to descend — is the one a fake that could only say "file or
// directory" could not express.
type podLogEntry struct {
	// rel is the path under the tree root. "" is the root directory itself.
	rel  string
	uid  int
	gid  int
	mode fs.FileMode
	kind EntryKind
}

// TestAgentInstallAdoptsThePodLogTree is the gate for B327: a reinstall over a
// worker whose agent once ran as root hands the PER-POD log directories to the
// service user, not just the root of the tree.
//
// The failure it closes is every pod on the node. The existing log-dir step
// chowns /var/log/pods itself, so the tree looked repaired; the
// <ns>_<pod>_<uid> directories a root-era agent had already created stayed
// root-owned 0700, and the _k3sm node then failed each CreatePod with
//
//	failed to create container log directory
//	/var/log/pods/<ns>_<pod>_<uid>/<container>: permission denied
//
// What it asserts is STATE, through the fake's per-path ownership table that
// Chown really mutates — plus, in one row, the ORDER, because parent-before-
// child is a property of the walk rather than of its outcome.
//
// Six properties, each a way to get this wrong:
//
//   - a root-owned per-pod directory, its container subdirectory and the log
//     file inside it are ALL adopted, each keeping its own mode — this is a
//     migration to the posture a fresh install produces, not a re-decision of
//     what the tree permits;
//   - a per-pod directory already the service user's own is not touched at all,
//     so a healthy reinstall performs no chown whatsoever;
//   - a symlink inside the tree is reported and stepped over, and its target is
//     never chowned: a walk running as root must not follow a link planted in a
//     directory the service user can write in;
//   - an entry k3sm cannot account for at the root of the tree — not a
//     directory, or a directory whose name is not the <ns>_<pod>_<uid> shape
//     k3sm writes — is REPORTED and left alone, and does not refuse the install:
//     unlike the credential directory, this tree is GC-pending debris by nature,
//     and a node with a stale file under /var/log/pods must still install;
//   - the flat per-container link directory is adopted too, by lchown on the
//     LINK, because there the symlink IS the artifact the node must replace;
//   - a node that has never run a pod has no tree, and that is a posture rather
//     than a problem.
func TestAgentInstallAdoptsThePodLogTree(t *testing.T) {
	// The tree as the existing log-dir step leaves it: the root is already the
	// service user's, which is exactly why the root alone was never enough.
	podsRoot := podLogEntry{mode: ContainerLogDirMode, uid: legacyServiceUID, gid: ContainerLogDirGID, kind: EntryDir}
	linksRoot := podLogEntry{mode: ContainerLogDirMode, uid: legacyServiceUID, gid: ContainerLogDirGID, kind: EntryDir}

	const podDirName = "default_web-0_9f1c"
	pod := func(rest ...string) string {
		return filepath.Join(append([]string{PodLogsDir, podDirName}, rest...)...)
	}
	link := func(name string) string { return filepath.Join(ContainerLogsDir, name) }
	// A path OUTSIDE the tree, for the rows that plant a symlink: if the walk
	// ever resolved a link, this is what it would have chowned.
	const linkTarget = "/var/lib/k3sm/agent/node.key"

	chownCall := func(path string) string {
		return fmt.Sprintf("Chown:%s:%d:%d", path, legacyServiceUID, ContainerLogDirGID)
	}

	type wantOwner struct {
		path string
		uid  int
		gid  int
		mode fs.FileMode
	}

	cases := []struct {
		name string
		// pods and links are the two tree roots, seeded relative to PodLogsDir
		// and ContainerLogsDir. nil means the directory does not exist at all.
		pods, links []podLogEntry
		// extra is seeded verbatim, at an absolute path: the symlink targets.
		extra []wantOwner
		// want is the ownership each path must have once the install is done.
		want []wantOwner
		// wantNoChown asserts the install changed no ownership at all.
		wantNoChown bool
		// wantChownOrder is the exact sequence of Chown calls, for the one row
		// whose property is the walk's order rather than its result.
		wantChownOrder []string
		// wantNoChownOf are paths no Chown call may name, however it got there.
		wantNoChownOf []string
		// wantLog are substrings the operator must have been shown.
		wantLog []string
		// server runs the row as a CONTROL-PLANE install instead of a worker.
		// The adoption is role-unconditional because the step it repairs is: a
		// single-node server runs pods and writes this same tree.
		server bool
	}{
		{
			name: "a root-era per-pod directory, its container dir and its log file are all adopted, parent before child",
			pods: []podLogEntry{
				podsRoot,
				{rel: podDirName, mode: 0o700, kind: EntryDir},
				{rel: filepath.Join(podDirName, "web"), mode: 0o700, kind: EntryDir},
				// Deliberately not 0700: a mode the adoption re-decided rather
				// than carried across would show up here.
				{rel: filepath.Join(podDirName, "web", "0.log"), mode: 0o644, kind: EntryRegular},
			},
			want: []wantOwner{
				{pod(), legacyServiceUID, ContainerLogDirGID, 0o700},
				{pod("web"), legacyServiceUID, ContainerLogDirGID, 0o700},
				{pod("web", "0.log"), legacyServiceUID, ContainerLogDirGID, 0o644},
			},
			// Parent BEFORE child: the walk descends into a directory it has
			// just handed over, so the service user never has to traverse a
			// directory still root's to reach what it owns.
			wantChownOrder: []string{
				chownCall(pod()),
				chownCall(pod("web")),
				chownCall(pod("web", "0.log")),
			},
			wantLog: []string{"adopted container-log entries", "adopted=3"},
		},
		{
			name: "a per-pod directory already the service user's own is left completely alone",
			pods: []podLogEntry{
				podsRoot,
				{rel: podDirName, uid: legacyServiceUID, gid: ContainerLogDirGID, mode: 0o700, kind: EntryDir},
				{rel: filepath.Join(podDirName, "web"), uid: legacyServiceUID, gid: ContainerLogDirGID, mode: 0o700, kind: EntryDir},
			},
			wantNoChown: true,
			want: []wantOwner{
				{pod(), legacyServiceUID, ContainerLogDirGID, 0o700},
				{pod("web"), legacyServiceUID, ContainerLogDirGID, 0o700},
			},
		},
		{
			name: "a symlink inside a per-pod directory is reported and stepped over, and its target is never chowned",
			pods: []podLogEntry{
				podsRoot,
				{rel: podDirName, mode: 0o700, kind: EntryDir},
				// Plantable by anything that can write in the tree. A root-run
				// walk that followed it would hand this node's credential to
				// whoever planted the link.
				{rel: filepath.Join(podDirName, "0.log"), mode: 0o777, kind: EntrySymlink},
			},
			extra: []wantOwner{{linkTarget, 0, 0, 0o600}},
			want: []wantOwner{
				// The directory is still adopted — the link is skipped, not the
				// whole pod.
				{pod(), legacyServiceUID, ContainerLogDirGID, 0o700},
				// The link itself: untouched inside the pod tree.
				{pod("0.log"), 0, 0, 0o777},
				{linkTarget, 0, 0, 0o600},
			},
			wantNoChownOf: []string{pod("0.log"), linkTarget},
			wantLog:       []string{"left an entry in the container-log tree alone", pod("0.log"), "a symlink"},
		},
		{
			name: "an unaccountable root-owned entry at the root of the tree is reported, not adopted, and the install proceeds",
			pods: []podLogEntry{
				podsRoot,
				// Neither of these is a pod log directory k3sm wrote: one is not
				// a directory at all, the other's name is not the
				// <ns>_<pod>_<uid> shape. A root-run walk descends into the
				// shape it wrote and reports the rest — adopting an unaccountable
				// entry would be handing the service user something k3sm cannot
				// account for, and refusing would fail the install of an
				// otherwise healthy node over GC-pending debris.
				{rel: "rotation.state", mode: 0o600, kind: EntryRegular},
				{rel: "not-a-pod-dir", mode: 0o700, kind: EntryDir},
				{rel: podDirName, mode: 0o700, kind: EntryDir},
			},
			want: []wantOwner{
				{filepath.Join(PodLogsDir, "rotation.state"), 0, 0, 0o600},
				{filepath.Join(PodLogsDir, "not-a-pod-dir"), 0, 0, 0o700},
				// The pod directory beside them is still adopted: one
				// unaccountable entry does not stop the walk.
				{pod(), legacyServiceUID, ContainerLogDirGID, 0o700},
			},
			wantChownOrder: []string{chownCall(pod())},
			wantNoChownOf: []string{
				filepath.Join(PodLogsDir, "rotation.state"),
				filepath.Join(PodLogsDir, "not-a-pod-dir"),
			},
			wantLog: []string{
				filepath.Join(PodLogsDir, "rotation.state"),
				filepath.Join(PodLogsDir, "not-a-pod-dir"),
				"is not the <namespace>_<pod>_<uid> shape",
			},
		},
		{
			name:  "a root-owned container log link is lchowned, and only the link",
			pods:  []podLogEntry{podsRoot},
			links: []podLogEntry{linksRoot, {rel: "web-0_default_web-9f1c.log", mode: 0o777, kind: EntrySymlink}},
			extra: []wantOwner{{linkTarget, 0, 0, 0o600}},
			want: []wantOwner{
				{link("web-0_default_web-9f1c.log"), legacyServiceUID, ContainerLogDirGID, 0o777},
				{linkTarget, 0, 0, 0o600},
			},
			wantChownOrder: []string{chownCall(link("web-0_default_web-9f1c.log"))},
			wantNoChownOf:  []string{linkTarget},
		},
		{
			name:   "a control-plane node's own pod directories are adopted too",
			server: true,
			pods: []podLogEntry{
				podsRoot,
				{rel: podDirName, mode: 0o700, kind: EntryDir},
				{rel: filepath.Join(podDirName, "web"), mode: 0o700, kind: EntryDir},
			},
			want: []wantOwner{
				{pod(), legacyServiceUID, ContainerLogDirGID, 0o700},
				{pod("web"), legacyServiceUID, ContainerLogDirGID, 0o700},
			},
			wantChownOrder: []string{chownCall(pod()), chownCall(pod("web"))},
		},
		{
			name:        "a node that has never run a pod has no tree to adopt",
			pods:        nil,
			links:       nil,
			wantNoChown: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			shrinkRestartBudgets(t)
			f := &fakeSystem{}
			seedOperatorToken(f)
			seed := func(root string, entries []podLogEntry) {
				for _, e := range entries {
					path := root
					if e.rel != "" {
						path = filepath.Join(root, e.rel)
					}
					f.putOwned(path, e.uid, e.gid, e.mode, e.kind)
				}
			}
			seed(PodLogsDir, tc.pods)
			seed(ContainerLogsDir, tc.links)
			for _, e := range tc.extra {
				f.putOwned(e.path, e.uid, e.gid, e.mode, EntryRegular)
			}
			// No --token-file: B327's shape is a reinstall over a node that has
			// already joined and already run pods. The server row is the same
			// reinstall one role up — a single-node control plane that has run
			// pods of its own.
			cfg := agentCfg(t)
			cfg.TokenFile = ""
			if tc.server {
				cfg = Config{Role: RoleServer, BinarySource: "/tmp/k3sm", TargetUser: "alice"}
			}
			var log bytes.Buffer
			cfg.Logger = testLogger(&log)

			if err := Install(context.Background(), f, cfg); err != nil {
				// Never a refusal: this tree is debris, and an install that
				// failed over it would hand back the broken node it was run to
				// repair.
				t.Fatalf("Install: %v", err)
			}

			var chowns []string
			for _, c := range f.calls {
				if strings.HasPrefix(c, "Chown:") {
					chowns = append(chowns, c)
				}
			}
			if tc.wantNoChown && len(chowns) > 0 {
				t.Errorf("the install changed ownership when it had no reason to: %v", chowns)
			}
			if tc.wantChownOrder != nil && !slices.Equal(chowns, tc.wantChownOrder) {
				t.Errorf("ownership was handed over as %v, want %v", chowns, tc.wantChownOrder)
			}
			for _, path := range tc.wantNoChownOf {
				if slices.Contains(chowns, chownCall(path)) {
					t.Errorf("the walk chowned %s, which it must never touch (calls: %v)", path, chowns)
				}
			}
			for _, want := range tc.wantLog {
				if !strings.Contains(log.String(), want) {
					t.Errorf("the operator was never told %q; log =\n%s", want, log.String())
				}
			}
			for _, w := range tc.want {
				got, ok := f.owners[w.path]
				if !ok {
					t.Errorf("%s is gone from the tree; this step deletes nothing", w.path)
					continue
				}
				if got.UID != w.uid || got.GID != w.gid || got.Mode != w.mode {
					t.Errorf("%s is %d:%d %#o, want %d:%d %#o", w.path, got.UID, got.GID, got.Mode, w.uid, w.gid, w.mode)
				}
			}
		})
	}
}
