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
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/provider/podlogs"
	"k3sm.io/k3sm/pkg/provider/vkadapter"
)

// containerLogOptions is the container-log flag group shared by `k3sm server`,
// `k3sm agent` and `k3sm node`.
//
// Every flag NAME and DEFAULT is the kubelet's KubeletConfiguration field of the
// same name, spelled the way kubelet spells it. That is the whole point: an
// operator who knows what --container-log-max-size does on a kubelet knows what
// it does here, and a k3s or kubeadm runbook transfers without translation. k3s
// sets none of these, so upstream's defaults are what a k3s user experiences, and
// they are what k3sm ships.
type containerLogOptions struct {
	// dir is --pod-logs-dir.
	dir string
	// maxSize is --container-log-max-size, a resource.Quantity string.
	maxSize string
	// maxFiles is --container-log-max-files.
	maxFiles int
	// maxWorkers is --container-log-max-workers.
	maxWorkers int
	// monitorInterval is --container-log-monitor-interval.
	monitorInterval time.Duration
}

// registerContainerLogFlags binds the container-log flag group onto fs.
func registerContainerLogFlags(fs *flag.FlagSet, opts *containerLogOptions) {
	fs.StringVar(&opts.dir, "pod-logs-dir", podlogs.DefaultPodLogsDir,
		"directory holding container logs as <dir>/<namespace>_<pod>_<uid>/<container>/<restartCount>.log (the kubelet layout; created by `k3sm install`)")
	fs.StringVar(&opts.maxSize, "container-log-max-size", podlogs.DefaultContainerLogMaxSize,
		"size at which a container log file is rotated (a resource quantity, e.g. 10Mi); a negative value disables rotation")
	fs.IntVar(&opts.maxFiles, "container-log-max-files", podlogs.DefaultContainerLogMaxFiles,
		"maximum number of log files kept per container, counting the current one (must be > 1)")
	fs.IntVar(&opts.maxWorkers, "container-log-max-workers", podlogs.DefaultContainerLogMaxWorkers,
		"number of workers performing log rotation")
	fs.DurationVar(&opts.monitorInterval, "container-log-monitor-interval", podlogs.DefaultContainerLogMonitorInterval,
		"how often container log sizes are checked for rotation")
}

// validate rejects a rotation policy that cannot work, at PARSE time.
//
// The two checks are upstream's own construction-time refusals, hoisted to the
// flag layer on purpose: the rotation manager degrades rather than killing a
// node, so without this an operator's typo would show up as a line in server.log
// an hour later and a full disk a week later, instead of as a refusal to start.
func (o containerLogOptions) validate() error {
	if o.maxFiles <= 1 {
		return fmt.Errorf("--container-log-max-files is %d, must be > 1 (it counts the current file plus the rotated ones, so 1 would mean rotating and immediately discarding)", o.maxFiles)
	}
	if _, err := podlogs.ParseMaxSize(o.maxSize); err != nil {
		return fmt.Errorf("--container-log-max-size %q is not a resource quantity (e.g. 10Mi): %w", o.maxSize, err)
	}
	if o.maxWorkers < 1 {
		return fmt.Errorf("--container-log-max-workers is %d, must be >= 1", o.maxWorkers)
	}
	if o.monitorInterval <= 0 {
		return fmt.Errorf("--container-log-monitor-interval is %s, must be positive", o.monitorInterval)
	}
	return nil
}

// ensureWritable fails fast when the pod-logs directory is missing or the node
// cannot write in it.
//
// It is a REFUSAL, not a mkdir. The tree is root-equivalent (`_k3sm:wheel 0700`)
// and only root can create it that way, so a node that finds it absent is a node
// running on an install that did not happen — and a node that started anyway
// would run every pod with nowhere to write, answer `kubectl logs` with "no log
// file" for the rest of its life, and give no hint why. The error names
// `k3sm install` because that is the fix.
//
// The writability probe is a real create-and-remove rather than a mode check:
// ownership, ACLs and a read-only mount all produce the same answer that way, and
// a mode check would pass on a directory owned by somebody else.
func (o containerLogOptions) ensureWritable() error {
	info, err := os.Stat(o.dir)
	if err != nil {
		return fmt.Errorf("container log directory %s is not available: %w (run `sudo k3sm install`, which creates it, or pass --pod-logs-dir)", o.dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("container log directory %s is not a directory (run `sudo k3sm install`, or pass --pod-logs-dir)", o.dir)
	}
	probe := filepath.Join(o.dir, ".k3sm-write-probe")
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("container log directory %s is not writable by this node: %w (run `sudo k3sm install`, which creates it owned by the service user, or pass --pod-logs-dir)", o.dir, err)
	}
	_ = f.Close()
	_ = os.Remove(probe)
	return nil
}

// containerLogsDir returns the flat per-container symlink directory to maintain,
// or "" to maintain none.
//
// It is the INSTALLED tree's /var/log/containers, and only when that directory
// already exists. The symlinks are a convenience for host-level log shippers, not
// something `kubectl logs` depends on, so a node running outside an install (a
// `k3sm dev` instance, a standalone `k3sm node`) simply keeps none rather than
// logging a failed symlink per container start.
func (o containerLogOptions) containerLogsDir() string {
	if o.dir != podlogs.DefaultPodLogsDir {
		return ""
	}
	if info, err := os.Stat(install.ContainerLogsDir); err != nil || !info.IsDir() {
		return ""
	}
	return install.ContainerLogsDir
}

// containerLogBackend is the optional provider capability the node's
// /containerLogs route is built over. It is declared at this consumer so the node
// command depends on the one method it needs rather than on a concrete provider
// type, matching runtimeHealthReporter next door.
type containerLogBackend interface {
	ContainerLogBackend() (podlogs.Backend, bool)
}

// containerLogMaintainer is the optional provider capability that owns log
// rotation and log garbage collection.
type containerLogMaintainer interface {
	StartLogMaintenance(ctx context.Context)
}

// containerLogRoutes returns the kubelet /containerLogs route to register on the
// node's HTTP mux, or nothing when the provider keeps no CRI log tree.
//
// Nothing is the hostprocess node's answer, and it is the right one: that
// provider writes a single undifferentiated file per container with no instances
// and no rotation, so Virtual Kubelet's own logs route describes what it can
// actually serve and this handler would not.
func containerLogRoutes(prov any) []vkadapter.Route {
	p, ok := prov.(containerLogBackend)
	if !ok {
		return nil
	}
	backend, ok := p.ContainerLogBackend()
	if !ok {
		return nil
	}
	return []vkadapter.Route{{
		Pattern: podlogs.HandlerPath,
		Handler: podlogs.NewHandler(backend, slog.Default()),
	}}
}

// startContainerLogMaintenance starts rotation and the log GC if the provider
// supports them. A provider without them has no CRI log tree to maintain, so this
// is a no-op rather than an error.
func startContainerLogMaintenance(ctx context.Context, prov any) {
	if m, ok := prov.(containerLogMaintainer); ok {
		m.StartLogMaintenance(ctx)
	}
}
