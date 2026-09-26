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
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"strconv"
	"strings"

	"k3sm.io/darwin-net/pkg/proxy"
)

// fileLimitChange is a node daemon whose plist this install rewrites with a
// different NumberOfFiles than the plist it replaces. Install reports it only
// after the restart, because the restart is what binds the new value.
type fileLimitChange struct {
	label    string
	old, new int
}

// checkFileLimit is the deployment side of serverFileLimit, run for each daemon
// plist before it is written. It never fails an install: both halves are
// operator notices about a limit launchd applies without saying anything.
//
//   - Kernel fd cap. launchd grants the daemon the requested soft limit
//     whatever the kernel ceiling, but the kernel allocates a process at most
//     kern.maxfilesperproc descriptors (opens past it fail with EMFILE while the
//     rlimit still reads the requested value). That ceiling scales with
//     installed RAM (measured 2026-09-26 on macOS 26: 245760 at 64 GB, 10240 at
//     8 GB), so a small Mac sits below serverFileLimit. It gets a WARN naming
//     both numbers, the UDP flow budget darwin-net derives from the cap, and the
//     runtime remedy.
//   - Reload. launchd captures *ResourceLimits from the job definition at
//     bootstrap, so a changed limit binds on bootout→bootstrap and never on
//     `launchctl kickstart -k`. When the plist on disk requested a different
//     limit (including none, the pre-limit layout), the change is returned for
//     the caller to report once the restart has rebound it. An absent plist is
//     a fresh install and reports nothing. Verified live on 2026-09-26: with the
//     plist limit edited to 9000, `launchctl kickstart -k` respawned the daemon
//     still at 131072, and bootout+bootstrap applied 9000.
//
// Plists that request no limit (netd, the datavol oneshot) are skipped.
func checkFileLimit(sys System, log *slog.Logger, label, path string, content []byte) (fileLimitChange, bool) {
	limit, err := plistSoftFileLimit(content)
	if err != nil || limit <= 0 {
		return fileLimitChange{}, false
	}
	warnKernelFDCap(sys, log, label, limit)

	prev, err := sys.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fileLimitChange{}, false
	case err != nil:
		log.Debug("could not read the installed plist to compare its open-file limit; skipping the reload notice", "path", path, "err", err)
		return fileLimitChange{}, false
	}
	old, err := plistSoftFileLimit(prev)
	if err != nil {
		log.Debug("could not parse the installed plist's open-file limit; skipping the reload notice", "path", path, "err", err)
		return fileLimitChange{}, false
	}
	if old == limit {
		return fileLimitChange{}, false
	}
	return fileLimitChange{label: label, old: old, new: limit}, true
}

// warnKernelFDCap logs a WARN when limit exceeds kern.maxfilesperproc. A
// probe error is logged at DEBUG and skipped: a probe must not block an install.
//
// The facts it states were measured on 2026-09-26 (macOS 26, an 8 GB Mac with
// kern.maxfilesperproc 10240): launchd reported the requested 131072 soft limit,
// and a root process holding it got EMFILE at exactly 10240 opens. `sysctl -w`
// raises both values at runtime (kern.maxfiles first) but the change does not
// survive a reboot, and /etc/sysctl.conf is not honoured.
func warnKernelFDCap(sys System, log *slog.Logger, label string, limit int) {
	kmax, err := sys.MaxFilesPerProc()
	if err != nil {
		log.Debug("could not read kern.maxfilesperproc; skipping the open-file cap check", "err", err)
		return
	}
	if uint64(limit) <= kmax {
		return
	}
	budget := proxy.UDPFlowBudgetFor(uint64(limit), kmax)
	remedy := fmt.Sprintf("sudo sysctl -w kern.maxfiles=%d kern.maxfilesperproc=%d", limit, limit)
	log.Warn(fmt.Sprintf("the daemon keeps its requested open-file soft limit %d, but this Mac's kernel allocates at most kern.maxfilesperproc=%d file descriptors to it (the value scales with installed RAM); "+
		"the UDP relay derives its flow budget from that cap, so UDP flow capacity on this Mac is reduced to %d (the floor is %d, the budget at the requested limit %d). "+
		"To raise the cap run `%s`; it does not survive a reboot",
		limit, kmax, budget, proxy.MaxUDPFlows, proxy.UDPFlowBudgetFor(uint64(limit), 0), remedy),
		"label", label, "requested", limit, "kern.maxfilesperproc", kmax, "udp-flow-budget", budget, "remedy", remedy)
}

// plistSoftFileLimit returns the NumberOfFiles inside a launchd plist's
// SoftResourceLimits dict, or 0 when the plist carries none. It streams the XML
// for parseProgramArguments' reason: the dict wanted is the element that
// FOLLOWS its key, which no Go struct shape mirrors.
func plistSoftFileLimit(plist []byte) (int, error) {
	dec := xml.NewDecoder(bytes.NewReader(plist))
	var (
		text      strings.Builder
		lastKey   string
		expectDic bool // the previous element was <key>SoftResourceLimits</key>
		softDepth int  // dict nesting depth inside the soft dict; 0 = outside it
		collect   bool
	)
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return 0, nil
		}
		if err != nil {
			return 0, fmt.Errorf("decode plist XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "dict" {
				switch {
				case softDepth > 0:
					softDepth++
				case expectDic:
					softDepth = 1
				}
			}
			expectDic = false
			if t.Name.Local == "key" || t.Name.Local == "integer" {
				collect = true
				text.Reset()
			}
		case xml.CharData:
			if collect {
				text.Write(t)
			}
		case xml.EndElement:
			collect = false
			switch t.Name.Local {
			case "key":
				lastKey = strings.TrimSpace(text.String())
				expectDic = softDepth == 0 && lastKey == "SoftResourceLimits"
			case "integer":
				if softDepth == 1 && lastKey == "NumberOfFiles" {
					n, err := strconv.Atoi(strings.TrimSpace(text.String()))
					if err != nil {
						return 0, fmt.Errorf("SoftResourceLimits NumberOfFiles: %w", err)
					}
					return n, nil
				}
			case "dict":
				if softDepth > 0 {
					softDepth--
				}
			}
		}
	}
}
