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
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"
)

// Ported from k8s.io/kubernetes@v1.36.2 pkg/kubelet/logs/container_log_manager.go
// (Apache-2.0). Rotation is what makes on-disk logs safe to keep: without it a
// chatty container fills the system volume, and a node that runs out of disk is a
// node that evicts everything on it.

const (
	// DefaultContainerLogMaxSize is the kubelet's containerLogMaxSize default.
	DefaultContainerLogMaxSize = "10Mi"
	// DefaultContainerLogMaxFiles is the kubelet's containerLogMaxFiles default.
	DefaultContainerLogMaxFiles = 5
	// DefaultContainerLogMaxWorkers is the kubelet's containerLogMaxWorkers default.
	DefaultContainerLogMaxWorkers = 1
	// DefaultContainerLogMonitorInterval is the kubelet's
	// containerLogMonitorInterval default.
	DefaultContainerLogMonitorInterval = 10 * time.Second

	// timestampFormat is the suffix a rotated file carries
	// (<path>.20060102-150405). It sorts lexicographically in time order, which
	// is what lets removeExcessLogs delete oldest-first with a plain string sort.
	timestampFormat = "20060102-150405"
	// compressSuffix marks a rotated file that has been gzipped.
	compressSuffix = ".gz"
	// tmpSuffix marks the in-progress gzip output. A file with this suffix is
	// debris from an interrupted compression and is never in use.
	tmpSuffix = ".tmp"
)

// ContainerLogRef is one container instance's current log file, as the runtime
// reports it.
type ContainerLogRef struct {
	// ID is the runtime's container id — the rotation queue's key.
	ID string
	// Path is the absolute path of the instance's CURRENT log file.
	Path string
}

// podDirOfContainerLog returns the pod log directory that owns a container log
// file's path — two levels up, per paths.go's BuildContainerLogsPath shape:
// <podLogsDir>/<ns>_<pod>_<uid>/<container>/<n>.log. This is the ONLY correct
// way to compute a DirLocks key from a container log path: DirLocks' own doc
// comment says "one mutex per pod log directory", and gc.go keys on the same
// pod directory (via BuildPodLogsDirectory) for its os.RemoveAll of that tree.
// Both Clean and processContainer below call this rather than each inlining
// filepath.Dir twice, specifically so there is one place, not two, that can
// drift from gc.go's key shape. Found during the 2026-09-23 A1 audit: before
// this helper existed, Clean and processContainer each independently keyed on
// the CONTAINER directory (filepath.Dir once, not twice) — a different string
// from gc.go's pod-directory key, so DirLocks handed out two different mutexes
// and rotation/GC ran fully concurrently on the same tree with no exclusion at
// all. Pinned per call site by TestCleanLocksOnThePodDirectoryGCUses and
// TestProcessContainerLocksOnThePodDirectoryGCUses; the concurrent
// reproduction is TestRotationAndGCSerializeOnSharedPodLock.
func podDirOfContainerLog(containerLogPath string) string {
	return filepath.Dir(filepath.Dir(containerLogPath))
}

// Runtime is the consumer-side seam the rotator drives. The provider implements
// it over runtimed's in-process status and ReopenContainerLog RPCs; a test
// implements it over a temp directory.
type Runtime interface {
	// RunningContainerLogs returns one ref per RUNNING container. Non-running
	// containers are excluded by the implementation, not filtered here: a
	// container that has exited writes nothing more, so rotating its file would
	// only strand an empty current log.
	RunningContainerLogs(ctx context.Context) ([]ContainerLogRef, error)
	// ContainerLog returns one container's current ref, re-read at the moment of
	// rotation (the queue entry may be stale by then).
	ContainerLog(ctx context.Context, id string) (ContainerLogRef, error)
	// ReopenContainerLog makes the runtime close its current file descriptor and
	// open the configured path again, creating the file. It is the half of
	// rotation only the WRITER can perform.
	ReopenContainerLog(ctx context.Context, id string) error
}

// ContainerLogManager rotates container logs and removes a container's files.
type ContainerLogManager interface {
	// Start begins the monitor loop and its workers. It returns immediately.
	Start(ctx context.Context)
	// Clean removes every file belonging to one container log path, including
	// its rotated and compressed siblings.
	Clean(ctx context.Context, logPath string) error
}

// LogRotatePolicy is the node-wide rotation policy.
type LogRotatePolicy struct {
	// MaxSize is the size in bytes at which a log file is rotated.
	MaxSize int64
	// MaxFiles is the total number of files one container may have on disk: the
	// current one, the one just rotated, and MaxFiles-2 older rotated files.
	MaxFiles int
}

// stubContainerLogManager is the manager installed when rotation is DISABLED (a
// negative max size). It is a type rather than a nil check at every call site so
// "rotation is off" cannot be confused with "the manager was never wired".
type stubContainerLogManager struct{}

// Start does nothing: rotation is disabled.
func (stubContainerLogManager) Start(context.Context) {}

// Clean does nothing: with rotation disabled this package still never deletes a
// file the operator chose to keep unbounded.
func (stubContainerLogManager) Clean(context.Context, string) error { return nil }

// NewStubContainerLogManager returns the no-op manager used when rotation is
// disabled.
func NewStubContainerLogManager() ContainerLogManager { return stubContainerLogManager{} }

// containerLogManager is the real rotator.
type containerLogManager struct {
	runtime          Runtime
	policy           LogRotatePolicy
	clock            clock.Clock
	log              *slog.Logger
	locks            *DirLocks
	queue            workqueue.TypedRateLimitingInterface[string]
	maxWorkers       int
	monitoringPeriod time.Duration
	// mutex serialises the SCAN (rotateLogs) against Clean, mirroring upstream.
	// Per-file exclusion between a worker and the GC is the DirLocks' job.
	mutex sync.Mutex
}

// ParseMaxSize parses a resource.Quantity string ("10Mi") into bytes. It is
// exported because the node command validates the flag at parse time, before any
// manager exists — an operator finds out about a typo at startup, not an hour
// later when the first rotation would have run.
func ParseMaxSize(size string) (int64, error) {
	quantity, err := resource.ParseQuantity(size)
	if err != nil {
		return 0, err
	}
	maxSize, ok := quantity.AsInt64()
	if !ok {
		return 0, errors.New("invalid max log size")
	}
	return maxSize, nil
}

// NewContainerLogManager builds the rotator.
//
// maxFiles <= 1 is an ERROR, not a clamp: MaxFiles counts the current file plus
// the rotated ones, so 1 would mean "rotate, then immediately delete what you
// rotated", which loses output silently. A NEGATIVE maxSize disables rotation and
// yields the stub manager, which is upstream's documented opt-out.
//
// locks may be nil, in which case the manager allocates its own — a manager that
// shares no tree with a garbage collector needs no shared lock.
func NewContainerLogManager(runtime Runtime, maxSize string, maxFiles, maxWorkers int, monitorInterval time.Duration, locks *DirLocks, log *slog.Logger) (ContainerLogManager, error) {
	if maxFiles <= 1 {
		return nil, fmt.Errorf("invalid MaxFiles %d, must be > 1", maxFiles)
	}
	parsedMaxSize, err := ParseMaxSize(maxSize)
	if err != nil {
		return nil, fmt.Errorf("failed to parse container log max size %q: %w", maxSize, err)
	}
	if parsedMaxSize < 0 {
		return NewStubContainerLogManager(), nil
	}
	if locks == nil {
		locks = NewDirLocks()
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if maxWorkers < 1 {
		maxWorkers = 1
	}
	if monitorInterval <= 0 {
		monitorInterval = DefaultContainerLogMonitorInterval
	}
	return &containerLogManager{
		runtime:    runtime,
		policy:     LogRotatePolicy{MaxSize: parsedMaxSize, MaxFiles: maxFiles},
		clock:      clock.RealClock{},
		log:        log,
		locks:      locks,
		maxWorkers: maxWorkers,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[string](),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "k3sm_log_rotate_manager"},
		),
		monitoringPeriod: monitorInterval,
	}, nil
}

// Start launches the workers and the periodic scan. Both stop with ctx.
func (c *containerLogManager) Start(ctx context.Context) {
	c.log.Info("starting container log rotation", "workers", c.maxWorkers, "interval", c.monitoringPeriod, "max-size", c.policy.MaxSize, "max-files", c.policy.MaxFiles)
	for i := 0; i < c.maxWorkers; i++ {
		worker := i + 1
		go c.processQueueItems(ctx, worker)
	}
	go func() {
		// ShutDown unblocks every worker parked in queue.Get, so the goroutines
		// above end with ctx rather than outliving the node.
		<-ctx.Done()
		c.queue.ShutDown()
	}()
	go wait.UntilWithContext(ctx, func(ctx context.Context) {
		if err := c.rotateLogs(ctx); err != nil {
			c.log.Error("failed to rotate container logs", "err", err)
		}
	}, c.monitoringPeriod)
}

// Clean removes every file of one container log path — the current file and each
// rotated or compressed sibling. It is called after a container's instance is
// pruned, so the glob is the authority on what belonged to it.
// Not yet wired: nothing in the tree calls Clean from instance pruning.
func (c *containerLogManager) Clean(_ context.Context, logPath string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	pattern := logPath + "*"
	logs, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("failed to list all log files with pattern %q: %w", pattern, err)
	}
	var firstErr error
	c.locks.Do(podDirOfContainerLog(logPath), func() {
		for _, l := range logs {
			if err := os.Remove(l); err != nil && !errors.Is(err, fs.ErrNotExist) && firstErr == nil {
				firstErr = fmt.Errorf("failed to remove container log %q: %w", l, err)
			}
		}
	})
	return firstErr
}

// processQueueItems drains the rotation queue until it is shut down.
func (c *containerLogManager) processQueueItems(ctx context.Context, worker int) {
	for c.processContainer(ctx, worker) {
	}
}

// rotateLogs enqueues every running container for a size check.
func (c *containerLogManager) rotateLogs(ctx context.Context) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	refs, err := c.runtime.RunningContainerLogs(ctx)
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}
	for _, ref := range refs {
		if ref.ID == "" {
			continue
		}
		c.queue.Add(ref.ID)
	}
	return nil
}

// processContainer rotates one queued container if its file has reached the
// size limit. It reports whether the worker should keep going.
func (c *containerLogManager) processContainer(ctx context.Context, worker int) (ok bool) {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer func() {
		c.queue.Done(key)
		c.queue.Forget(key)
	}()
	// A failure below is logged and dropped, never retried into a hot loop: the
	// next monitor tick re-enqueues the same container anyway.
	ok = true
	ref, err := c.runtime.ContainerLog(ctx, key)
	if err != nil {
		c.log.Error("failed to get container log path", "worker", worker, "container", key, "err", err)
		return
	}
	path := ref.Path
	if path == "" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			c.log.Error("failed to stat container log", "worker", worker, "container", key, "path", path, "err", err)
			return
		}
		// The file is gone but the container is running: ask the writer to open
		// it again rather than leaving the container's output on the floor.
		if err := c.runtime.ReopenContainerLog(ctx, key); err != nil {
			c.log.Error("container log does not exist and could not be reopened", "worker", worker, "container", key, "path", path, "err", err)
			return
		}
		info, err = os.Stat(path)
		if err != nil {
			c.log.Error("failed to stat container log after reopen", "worker", worker, "container", key, "path", path, "err", err)
			return
		}
	}
	if info.Size() < c.policy.MaxSize {
		return
	}
	c.locks.Do(podDirOfContainerLog(path), func() {
		if err := c.rotateLog(ctx, key, path); err != nil {
			c.log.Error("failed to rotate container log", "worker", worker, "container", key, "path", path, "size", info.Size(), "max", c.policy.MaxSize, "err", err)
		}
	})
	return
}

// rotateLog performs one rotation: clean up debris, drop the excess, compress
// what is left, then rename the current file and have the writer reopen it.
func (c *containerLogManager) rotateLog(ctx context.Context, id, log string) error {
	pattern := log + ".*"
	logs, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("failed to list all log files with pattern %q: %w", pattern, err)
	}
	logs, err = c.cleanupUnusedLogs(logs)
	if err != nil {
		return fmt.Errorf("failed to cleanup logs: %w", err)
	}
	logs, err = c.removeExcessLogs(logs)
	if err != nil {
		return fmt.Errorf("failed to remove excess logs: %w", err)
	}
	for _, l := range logs {
		if strings.HasSuffix(l, compressSuffix) {
			continue
		}
		if err := c.compressLog(l); err != nil {
			return fmt.Errorf("failed to compress log %q: %w", l, err)
		}
	}
	if err := c.rotateLatestLog(ctx, id, log); err != nil {
		return fmt.Errorf("failed to rotate log %q: %w", log, err)
	}
	return nil
}

// cleanupUnusedLogs removes files a previous, interrupted rotation left behind.
func (c *containerLogManager) cleanupUnusedLogs(logs []string) ([]string, error) {
	inuse, unused := filterUnusedLogs(logs)
	for _, l := range unused {
		if err := os.Remove(l); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("failed to remove unused log %q: %w", l, err)
		}
	}
	return inuse, nil
}

// filterUnusedLogs splits rotated files into the ones still in use and the debris.
func filterUnusedLogs(logs []string) (inuse, unused []string) {
	for _, l := range logs {
		if isInUse(l, logs) {
			inuse = append(inuse, l)
		} else {
			unused = append(unused, l)
		}
	}
	return inuse, unused
}

// isInUse reports whether a rotated file is still the live copy of its content:
// a .tmp is never in use, a .gz always is, and a plain file whose .gz twin
// exists has already been superseded.
func isInUse(l string, logs []string) bool {
	if strings.HasSuffix(l, tmpSuffix) {
		return false
	}
	if strings.HasSuffix(l, compressSuffix) {
		return true
	}
	for _, another := range logs {
		if l+compressSuffix == another {
			return false
		}
	}
	return true
}

// removeExcessLogs deletes oldest-first until at most MaxFiles-2 rotated files
// remain. Two slots are reserved: the file about to be rotated, and the new
// current file the writer will open — so the container ends up with MaxFiles.
// Deleting oldest-first is what keeps an in-flight `kubectl logs` from having
// the file under it removed.
func (c *containerLogManager) removeExcessLogs(logs []string) ([]string, error) {
	sort.Strings(logs)
	maxRotatedFiles := c.policy.MaxFiles - 2
	if maxRotatedFiles < 0 {
		maxRotatedFiles = 0
	}
	i := 0
	for ; i < len(logs)-maxRotatedFiles; i++ {
		if err := os.Remove(logs[i]); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("failed to remove old log %q: %w", logs[i], err)
		}
	}
	return logs[i:], nil
}

// compressLog gzips one rotated file to <name>.gz through a .tmp, then removes
// the original. The rename is what makes the .gz appear atomically, so a reader
// never sees a half-written archive.
func (c *containerLogManager) compressLog(log string) error {
	logInfo, err := os.Stat(log)
	if err != nil {
		return fmt.Errorf("failed to stat log file: %w", err)
	}
	r, err := os.Open(log)
	if err != nil {
		return fmt.Errorf("failed to open log %q: %w", log, err)
	}
	defer func() { _ = r.Close() }()
	tmpLog := log + tmpSuffix
	f, err := os.OpenFile(tmpLog, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, logInfo.Mode())
	if err != nil {
		return fmt.Errorf("failed to create temporary log %q: %w", tmpLog, err)
	}
	defer func() { _ = os.Remove(tmpLog) }()
	defer func() { _ = f.Close() }()
	w := gzip.NewWriter(f)
	defer func() { _ = w.Close() }()
	if _, err := io.Copy(w, r); err != nil {
		return fmt.Errorf("failed to compress %q to %q: %w", log, tmpLog, err)
	}
	// Close the archive and the file BEFORE the rename: the gzip trailer is
	// written by Close, so a rename before it would publish a truncated archive.
	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to finish compressing %q: %w", log, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close temporary log %q: %w", tmpLog, err)
	}
	compressedLog := log + compressSuffix
	if err := os.Rename(tmpLog, compressedLog); err != nil {
		return fmt.Errorf("failed to rename %q to %q: %w", tmpLog, compressedLog, err)
	}
	_ = r.Close()
	if err := os.Remove(log); err != nil {
		return fmt.Errorf("failed to remove log %q after compress: %w", log, err)
	}
	return nil
}

// rotateLatestLog renames the current file to <path>.<timestamp> and asks the
// writer to reopen. It is left UNCOMPRESSED so an in-flight reader can finish.
//
// If the reopen fails the rename is UNDONE, so the next tick can try again
// rather than leaving the container writing into an unlinked descriptor with no
// file at the configured path. Upstream's honest caveat applies here too: if the
// node dies between the rename and the rollback, the original file keeps its
// timestamped name and `kubectl logs` will not find it.
func (c *containerLogManager) rotateLatestLog(ctx context.Context, id, log string) error {
	timestamp := c.clock.Now().Format(timestampFormat)
	rotated := fmt.Sprintf("%s.%s", log, timestamp)
	if err := os.Rename(log, rotated); err != nil {
		return fmt.Errorf("failed to rotate log %q to %q: %w", log, rotated, err)
	}
	if err := c.runtime.ReopenContainerLog(ctx, id); err != nil {
		if renameErr := os.Rename(rotated, log); renameErr != nil {
			c.log.Error("failed to rename rotated log back", "rotated", rotated, "log", log, "container", id, "err", renameErr)
		}
		return fmt.Errorf("failed to reopen container log %q: %w", id, err)
	}
	return nil
}
