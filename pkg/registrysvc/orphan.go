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

package registrysvc

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"time"
)

// Reclaiming a previous server's registry child.
//
// The zot child runs in its own process group (spawn), so launchd's kill of
// the daemon's job does not reach it, and its only teardown is Shutdown, which
// runs from the server's deferred stop. A daemon that never reaches that defer,
// because launchd SIGKILLed it at ExitTimeOut, it crashed, or it was killed by
// hand, leaves the child running under launchd (ppid 1) and still LISTENING on
// the registry port. Nothing exits it after that: every later server finds the
// port held, preflightPort refuses, and the registry stays disabled on every
// restart until a human kills the survivor. The retry bound cannot help,
// because the holder is not on its way out.
//
// So before the preflight, Start reclaims exactly such a survivor: a process
// of this uid whose parent is gone (ppid 1) and whose argv is the one spawn
// gives this service's child, byte for byte (ZotPath(BinDir) serve
// ConfigPath(WorkDir)). The config path lives under this server's own work
// dir, so a process matching it is a previous instance of this service and
// nothing else. A zot whose parent is alive is somebody's live child and is
// never touched, and any other holder still gets preflightPort's fail-closed
// refusal.

// reclaimKillWait bounds the wait for the kernel to reap a survivor after the
// SIGKILL escalation. A SIGKILLed process exits at once; the bound only stops a
// wedged reap from holding the bring-up open.
const reclaimKillWait = 5 * time.Second

// reclaimPoll is how often a reclaim checks whether the survivor is gone.
const reclaimPoll = 50 * time.Millisecond

// launchdPID is the pid an orphan is re-parented to on macOS.
const launchdPID = 1

// procEntry is one process as the reclaim sees it.
type procEntry struct {
	pid, ppid, pgid int
	// argv is the process's argument vector, argv[0] included.
	argv []string
}

// isOrphanedChild reports whether p is a previous instance of this service's
// child that its parent left behind.
func (s *Service) isOrphanedChild(p procEntry) bool {
	return p.ppid == launchdPID &&
		len(p.argv) == 3 &&
		p.argv[0] == ZotPath(s.cfg.BinDir) &&
		p.argv[1] == "serve" &&
		p.argv[2] == ConfigPath(s.cfg.WorkDir)
}

// claimPort makes the registry port this service's to bind: it reclaims a
// previous server's orphaned child, then runs the fail-closed preflight.
func (s *Service) claimPort(ctx context.Context) error {
	if err := s.reclaimOrphans(ctx); err != nil {
		return err
	}
	return preflightPort(s.cfg.BindAddress, s.cfg.Port)
}

// reclaimOrphans stops every orphaned child of this service (isOrphanedChild):
// SIGTERM to its process group, drainGrace for it to close its storage, then
// SIGKILL, and a wait until it is gone, so the port is free when it returns.
//
// A process list that cannot be read is logged and skipped: the preflight
// after it still refuses a held port, so the failure mode is today's refusal,
// never a bind over a live holder.
func (s *Service) reclaimOrphans(ctx context.Context) error {
	procs, err := listOwnProcesses()
	if err != nil {
		s.cfg.Logger.Warn("could not list processes to look for an orphaned ingest registry child", "err", err)
		return nil
	}
	for _, p := range procs {
		if !s.isOrphanedChild(p) {
			continue
		}
		if err := reclaim(ctx, p); err != nil {
			return fmt.Errorf("reclaim the orphaned ingest registry child pid %d: %w", p.pid, err)
		}
		s.cfg.Logger.Warn("reclaimed an ingest registry child a previous server left running on the registry port",
			"pid", p.pid, "addr", s.Addr())
	}
	return nil
}

// reclaim stops p and waits for it to be gone.
func reclaim(ctx context.Context, p procEntry) error {
	// spawn makes the child its own process-group leader; signalling the group
	// also reaches anything it started. A leader that is not one any more gets
	// the signal alone.
	target := p.pid
	if p.pgid == p.pid {
		target = -p.pid
	}
	if err := syscall.Kill(target, syscall.SIGTERM); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return fmt.Errorf("SIGTERM: %w", err)
	}
	if gone(ctx, p.pid, drainGrace) {
		return nil
	}
	if err := syscall.Kill(target, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("SIGKILL: %w", err)
	}
	if gone(ctx, p.pid, reclaimKillWait) {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return fmt.Errorf("still running %s after SIGKILL", reclaimKillWait)
}

// gone polls until pid no longer exists, within bound or until ctx ends.
func gone(ctx context.Context, pid int, bound time.Duration) bool {
	deadline := time.Now().Add(bound)
	for {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(reclaimPoll):
		}
	}
}
