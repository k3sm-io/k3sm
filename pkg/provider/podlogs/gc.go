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

package podlogs

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"
)

// Ported from k8s.io/kubernetes@v1.36.2
// pkg/kubelet/kuberuntime/kuberuntime_gc.go (Apache-2.0): evictPodLogsDirectories
// and the dead-symlink sweep, plus the MaxPerPodContainer instance pruning the
// kubelet performs through container removal.
//
// This package is the SOLE deleter of anything under the pod log tree. runtimed
// writes files and never unlinks one, so there is exactly one component that can
// remove output and exactly one place to look when output goes missing.

const (
	// ContainerGCPeriod is how often the sweep runs (upstream's
	// ContainerGCPeriod).
	ContainerGCPeriod = time.Minute

	// MaxPerPodContainer is how many DEAD instances of one container keep their
	// log files. Upstream's kubelet default is 1, which is what makes
	// `kubectl logs --previous` work and what bounds the tree at the same time:
	// the current instance's files plus exactly one older instance's.
	MaxPerPodContainer = 1
)

// instanceFileRe matches a container instance log file and captures its restart
// count: "0.log", "3.log.20260913-101500", "3.log.20260913-101500.gz". It is the
// same expression the kubelet uses to recover a restart count from a log
// directory, so the two agree on what counts as an instance file.
var instanceFileRe = regexp.MustCompile(`^(\d+)\.log(\..*)?$`)

// PodStateSource answers the two questions the sweep may not guess at: which
// pods this node still has, and whether a container is still running. It is a
// consumer-side seam so the provider can answer from its own tracking and a test
// can answer from a map.
type PodStateSource interface {
	// KnownPodUIDs returns the UIDs of pods the node is tracking and whether the
	// source has SYNCED. An unsynced source reports false and the sweep performs
	// no deletion at all: right after a restart "I have not heard of this pod"
	// and "this pod is gone" are indistinguishable, and only one of them is a
	// reason to delete a pod's logs.
	KnownPodUIDs(ctx context.Context) (map[string]struct{}, bool)
	// ContainerRunning reports whether the container id is running right now.
	ContainerRunning(ctx context.Context, id string) (bool, error)
}

// GC removes container log files this node no longer owes anyone.
type GC struct {
	// PodLogsDir is the root of the pod log tree.
	PodLogsDir string
	// ContainerLogsDir is the flat symlink directory (/var/log/containers).
	ContainerLogsDir string
	// Pods answers the sweep's two questions. Required.
	Pods PodStateSource
	// Locks is shared with the rotator so a sweep never deletes a file out from
	// under an in-progress rotation of the same pod.
	Locks *DirLocks
	// Log is the structured logger; nil discards.
	Log *slog.Logger
}

// NewGC returns a GC over the given trees. locks may be nil (a private set is
// allocated), but sharing the rotator's is the intended wiring.
func NewGC(podLogsDir, containerLogsDir string, pods PodStateSource, locks *DirLocks, log *slog.Logger) *GC {
	if locks == nil {
		locks = NewDirLocks()
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &GC{
		PodLogsDir:       podLogsDir,
		ContainerLogsDir: containerLogsDir,
		Pods:             pods,
		Locks:            locks,
		Log:              log,
	}
}

// Run sweeps every ContainerGCPeriod until ctx is done. The first sweep happens
// after one period, not immediately: at start-up the pod source has not synced
// and a sweep would do nothing anyway.
func (g *GC) Run(ctx context.Context) {
	t := time.NewTicker(ContainerGCPeriod)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.RunOnce(ctx)
		}
	}
}

// RunOnce performs one sweep: prune dead instances, drop orphan pod directories,
// and remove dangling symlinks.
//
// Its latency depends on rotation. Each pod is swept under the same DirLocks
// mutex the rotator holds while it renames, gzips and asks the writer to reopen
// (logmanager.go, processContainer), so a slow gzip or a stalled reopen delays
// the sweep pod by pod, with no bound. A slow cleanup starts there.
func (g *GC) RunOnce(ctx context.Context) {
	known, synced := g.Pods.KnownPodUIDs(ctx)
	if !synced {
		g.Log.Debug("skipping container log GC: the pod source has not synced")
		return
	}
	entries, err := os.ReadDir(g.PodLogsDir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			g.Log.Error("failed to read the pod logs directory", "path", g.PodLogsDir, "err", err)
		}
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(g.PodLogsDir, e.Name())
		uid := ParsePodUIDFromLogsDirectory(e.Name())
		if _, ok := known[uid]; !ok {
			// The pod is gone (or was never this node's). Its whole tree goes.
			g.Locks.Do(dir, func() {
				if err := os.RemoveAll(dir); err != nil {
					g.Log.Error("failed to remove an orphaned pod log directory", "path", dir, "err", err)
					return
				}
				g.Log.Info("removed an orphaned pod log directory", "path", dir, "pod-uid", uid)
			})
			continue
		}
		g.Locks.Do(dir, func() { g.pruneInstances(dir) })
	}
	g.sweepDanglingSymlinks(ctx)
}

// RemovePodLogs removes one pod's whole log directory. The caller invokes it
// AFTER the runtime has confirmed the pod is deleted — deleting the tree of a pod
// whose containers are still writing would strand open descriptors on unlinked
// files, which is exactly how output disappears with nothing to show for it.
//
// A missing directory is success: a pod whose containers never started has none.
func (g *GC) RemovePodLogs(podNamespace, podName, podUID string) error {
	dir := BuildPodLogsDirectory(g.PodLogsDir, podNamespace, podName, podUID)
	var err error
	g.Locks.Do(dir, func() {
		err = os.RemoveAll(dir)
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// pruneInstances keeps, per container directory, the file sets of the newest
// MaxPerPodContainer+1 instances (the current one plus that many previous) and
// removes the rest. Files that are not instance files are left alone: this sweep
// deletes only what it can prove it wrote.
//
// The caller holds dir's lock.
func (g *GC) pruneInstances(dir string) {
	containers, err := os.ReadDir(dir)
	if err != nil {
		g.Log.Error("failed to read a pod log directory", "path", dir, "err", err)
		return
	}
	for _, c := range containers {
		if !c.IsDir() {
			continue
		}
		cdir := filepath.Join(dir, c.Name())
		files, err := os.ReadDir(cdir)
		if err != nil {
			g.Log.Error("failed to read a container log directory", "path", cdir, "err", err)
			continue
		}
		byInstance := map[int][]string{}
		for _, f := range files {
			if f.IsDir() {
				continue
			}
			m := instanceFileRe.FindStringSubmatch(f.Name())
			if m == nil {
				continue
			}
			n, err := strconv.Atoi(m[1])
			if err != nil {
				continue
			}
			byInstance[n] = append(byInstance[n], filepath.Join(cdir, f.Name()))
		}
		if len(byInstance) <= MaxPerPodContainer+1 {
			continue
		}
		nums := make([]int, 0, len(byInstance))
		for n := range byInstance {
			nums = append(nums, n)
		}
		// Newest instance first, so the slice past the keep count is exactly the
		// set to delete, oldest last.
		sort.Sort(sort.Reverse(sort.IntSlice(nums)))
		for _, n := range nums[MaxPerPodContainer+1:] {
			for _, path := range byInstance[n] {
				if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
					g.Log.Error("failed to remove an old container log", "path", path, "err", err)
					continue
				}
				g.Log.Debug("removed an old container log instance", "path", path)
			}
		}
	}
}

// sweepDanglingSymlinks removes /var/log/containers entries whose target is
// gone — but only for containers that are NOT running.
//
// The exception is not caution, it is a known race (kubernetes#52172): rotation
// renames the current file, then asks the writer to reopen it, and between those
// two steps the symlink's target genuinely does not exist. Deleting the symlink
// in that window would break every shipper watching a perfectly healthy
// container. A container that is not running has no such window.
func (g *GC) sweepDanglingSymlinks(ctx context.Context) {
	if g.ContainerLogsDir == "" {
		return
	}
	links, err := filepath.Glob(filepath.Join(g.ContainerLogsDir, "*."+logSuffix))
	if err != nil {
		g.Log.Error("failed to list container log symlinks", "path", g.ContainerLogsDir, "err", err)
		return
	}
	for _, link := range links {
		if _, err := os.Stat(link); !errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if id, err := ContainerIDFromLogSymlink(link); err == nil {
			running, rerr := g.Pods.ContainerRunning(ctx, id)
			if rerr != nil {
				g.Log.Debug("could not determine whether a container is running; leaving its symlink", "container", id, "err", rerr)
				continue
			}
			if running {
				continue
			}
		}
		if err := os.Remove(link); err != nil && !errors.Is(err, fs.ErrNotExist) {
			g.Log.Error("failed to remove a dangling container log symlink", "path", link, "err", err)
			continue
		}
		g.Log.Debug("removed a dangling container log symlink", "path", link)
	}
}
