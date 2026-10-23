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

package builder

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// The build cache is BuildKit's, so it is measured and pruned by BuildKit:
// buildctl, exec'd in the engine Pod against the daemon's own socket, the same
// path the readiness probe takes. Both commands print JSON (`--format '{{json
// .}}'`), never the human table, so nothing here parses a rounded size.
//
// The selection is buildkitd's (BuildKit's cache/manager.go prune):
// a record held by a running build is never removed; a default prune also
// keeps the internal and frontend records (the Dockerfile frontend, the
// engine's own bookkeeping) and the cache shared with images the engine
// built; --all removes those too.
var (
	buildctlBase   = []string{"buildctl", "--addr", "unix:///run/buildkit/buildkitd.sock"}
	jsonFormatFlag = []string{"--format", "{{json .}}"}
)

// CacheRecord is one BuildKit cache record, as buildctl reports it.
type CacheRecord struct {
	ID         string `json:"id"`
	InUse      bool   `json:"inUse"`
	Size       int64  `json:"size"`
	RecordType string `json:"recordType"`
	Shared     bool   `json:"shared"`
}

// CacheReport is what a prune reclaimed, or would reclaim.
type CacheReport struct {
	// Records is how many cache records were (or would be) removed.
	Records int
	// Bytes is their total size.
	Bytes int64
}

// prunable is whether a prune of the given scope removes r, by buildkitd's
// own selection.
func prunable(r CacheRecord, all bool) bool {
	if r.InUse {
		return false
	}
	if all {
		return true
	}
	return r.RecordType != "internal" && r.RecordType != "frontend" && !r.Shared
}

// PlanPrune reports what PruneCache would reclaim, without removing anything.
// It is an estimate from `buildctl du`: buildkitd may also free a parent record
// whose last child a prune removes, so a real prune can reclaim somewhat more.
func (m *Manager) PlanPrune(ctx context.Context, all bool) (CacheReport, error) {
	out, err := m.buildctl(ctx, "du")
	if err != nil {
		return CacheReport{}, err
	}
	recs, err := parseDiskUsage(out)
	if err != nil {
		return CacheReport{}, err
	}
	var rep CacheReport
	for _, r := range recs {
		if prunable(r, all) && r.Size > 0 {
			rep.Records++
			rep.Bytes += r.Size
		}
	}
	return rep, nil
}

// PruneCache removes the engine's unused build cache, and with all the
// internal, frontend and shared records too, and reports what was reclaimed.
func (m *Manager) PruneCache(ctx context.Context, all bool) (CacheReport, error) {
	args := []string{"prune"}
	if all {
		args = append(args, "--all")
	}
	out, err := m.buildctl(ctx, args...)
	if err != nil {
		return CacheReport{}, err
	}
	recs, err := parsePruned(out)
	if err != nil {
		return CacheReport{}, err
	}
	var rep CacheReport
	for _, r := range recs {
		rep.Records++
		if r.Size > 0 {
			rep.Bytes += r.Size
		}
	}
	return rep, nil
}

// buildctl runs one buildctl subcommand in a READY engine and returns its
// stdout. An engine that is not serving is refused with its own state, so the
// fix is named (ErrAbsent says `k3sm builder up`).
func (m *Manager) buildctl(ctx context.Context, args ...string) (string, error) {
	if m.exec == nil {
		return "", fmt.Errorf("builder cache: no exec seam configured")
	}
	st, err := m.Status(ctx)
	if err != nil {
		return "", err
	}
	switch st.State {
	case StateReady:
	case StateAbsent:
		return "", fmt.Errorf("the build cache is managed through the engine: %w", ErrAbsent)
	default:
		return "", fmt.Errorf("builder engine is %s, not Ready: %s", st.State, st.Message)
	}
	cmd := append(append(append([]string{}, buildctlBase...), args...), jsonFormatFlag...)
	stdout, stderr, err := m.exec.Exec(ctx, m.cfg.Namespace, m.cfg.Name, containerName, cmd)
	if err != nil {
		if msg := strings.TrimSpace(stderr); msg != "" {
			return "", fmt.Errorf("buildctl %s: %w: %s", args[0], err, msg)
		}
		return "", fmt.Errorf("buildctl %s: %w", args[0], err)
	}
	return stdout, nil
}

// parseDiskUsage reads `buildctl du --format '{{json .}}'`: one JSON array.
func parseDiskUsage(out string) ([]CacheRecord, error) {
	out = strings.TrimSpace(out)
	if out == "" || out == "null" {
		return nil, nil
	}
	var recs []CacheRecord
	if err := json.Unmarshal([]byte(out), &recs); err != nil {
		return nil, fmt.Errorf("read buildctl du output: %w", err)
	}
	return recs, nil
}

// parsePruned reads `buildctl prune --format '{{json .}}'`: one JSON object per
// removed record, one per line.
func parsePruned(out string) ([]CacheRecord, error) {
	var recs []CacheRecord
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r CacheRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, fmt.Errorf("read buildctl prune output: %w", err)
		}
		recs = append(recs, r)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read buildctl prune output: %w", err)
	}
	return recs, nil
}
