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
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/executor"
)

// legacyAgentPodRoot is the pod root `k3sm agent` used to COMPILE IN as its
// flag default: the process's temp dir plus a fixed name. On macOS that resolves
// to the daemon user's per-user `$TMPDIR` under /var/folders, which the OS purges
// on its own schedule — and the directory is not "logs/state", it is runtimed's
// on-disk root: the image cache, every pod dir, and the data of every PVC bound
// on this node. A joined worker therefore kept its durable data somewhere the
// system is entitled to delete.
//
// It survives as the MIGRATION probe, nothing more: resolveAgentPodRoot keeps an
// already-joined worker on it when it holds data, so a binary upgrade never moves
// a running node's pods and volumes out from under it.
func legacyAgentPodRoot() string { return filepath.Join(os.TempDir(), "k3sm-pods") }

// podRootChoice is the resolved pod-root decision for one agent start: the root
// runtimed will use, the durable default derived alongside it, and how the two
// relate.
//
// The durable default travels WITH the choice rather than being re-derived by the
// logger, so executor.RuntimeRoot runs exactly once per start and the path named
// in the legacy Warn is provably the path a fixed node would land on — two
// derivations of "the durable default" could disagree, and the one in the operator
// message would be the one nobody tested.
type podRootChoice struct {
	root    string // the root this start uses
	durable string // executor.RuntimeRoot(workDir) — equal to root unless legacy
	legacy  bool   // the legacy temp-dir root was kept because it holds data
	// probeErr is why the legacy root could not be read, when legacy was chosen
	// on an unreadable probe rather than on observed entries. Reported to the
	// operator; never fatal.
	probeErr error
}

// resolveAgentPodRoot decides the joined worker's runtimed on-disk root from the
// `--pod-root` flag, the agent work dir, and what the legacy temp-dir root holds.
// It is pure — the only filesystem question it asks goes through hasData — so the
// whole decision is unit-testable without a live join.
//
// The three cases, in order:
//
//   - an explicit --pod-root always wins, unchanged and unexamined (hasData is
//     not consulted: the operator named a path, and probing another one could
//     only produce a surprise);
//   - else, when legacyDir holds data — or cannot be read, see below — that
//     legacy path is returned with legacy=true. An upgraded binary must not
//     relocate a running node's image cache, pod dirs and PVC data as a side
//     effect of starting; the move is an operator act, and the Warn
//     logAgentPodRoot emits is how they are told to make it;
//   - else the durable default, executor.RuntimeRoot(workDir) — the work dir's
//     PARENT, which is exactly the derivation `k3sm server` uses for an empty
//     --pod-root (cmd/k3sm/server.go:321). One rule, two roles: the SBPL work
//     dir then resides under the daemon home and the sandbox's containment check
//     stays active.
//
// The probe's verdict is deliberately THREE-way (see podRootHasData), and an
// indeterminate one counts as data. Treating "I could not tell" as "no data"
// would silently strand a joined worker's volumes: it would start a second, empty
// image cache at the durable default beside the still-populated legacy root, with
// no warning, because the warning is attached to the branch it did not take.
// Keeping the legacy root on an unreadable probe loses nothing in the opposite
// case — the operator gets a Warn naming the error and can move the directory by
// hand.
//
// On a stock Mac the two roles' derivations COINCIDE — /var/lib/k3sm/server and
// /var/lib/k3sm/agent both have /var/lib/k3sm as their parent — which is safe
// only because the two daemons never share a Mac: pkg/install's cross-role
// refusal (refuseCrossRole, B294) rejects installing the second role over the
// first rather than letting two daemons fight over one root.
func resolveAgentPodRoot(explicit, workDir, legacyDir string, hasData func(dir string) (bool, error)) podRootChoice {
	durable := executor.RuntimeRoot(workDir)
	if explicit != "" {
		return podRootChoice{root: explicit, durable: durable}
	}
	if legacyDir != "" && hasData != nil {
		if data, err := hasData(legacyDir); data {
			return podRootChoice{root: legacyDir, durable: durable, legacy: true, probeErr: err}
		}
	}
	return podRootChoice{root: durable, durable: durable}
}

// podRootHasData reports whether dir holds data worth keeping a node on — the
// production probe for resolveAgentPodRoot. Its verdict is three-way:
//
//   - dir is absent or is not a directory (ENOENT/ENOTDIR): (false, nil). A
//     purged /var/folders root and a first join both look like this, and there
//     is nothing there to preserve.
//   - dir reads: (entries > 0, nil). "Has data" is deliberately "is a non-empty
//     directory" and not a search for anything runtimed-shaped — anything under
//     a path a previous agent was pointed at is data this decision must not step
//     on.
//   - dir exists but cannot be read (EACCES on the daemon user, an I/O error):
//     (true, err). The directory is THERE; only its contents are unknown, and the
//     answer that loses nothing is to keep the node on it and report why.
func podRootHasData(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	switch {
	case err == nil:
		return len(entries) > 0, nil
	case errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENOTDIR):
		return false, nil
	default:
		return true, err
	}
}

// logAgentPodRoot reports the resolved pod root once at agent start.
//
// The legacy case is a WARN carrying both the path in use and the durable
// default it is not using, plus the two moves that end the warning — because
// nothing else will tell the operator that this node's PVC data sits in a
// directory macOS may purge, and the fix is theirs to make, not the binary's.
// When the legacy root was kept because it could not be READ, that error rides
// the same line: it is the difference between "you have data here" and "I could
// not check, so I did not move you", and only the operator can resolve the
// second.
func logAgentPodRoot(logger *slog.Logger, choice podRootChoice) {
	if logger == nil {
		return
	}
	if choice.legacy {
		attrs := []any{"podRoot", choice.root, "durableDefault", choice.durable}
		if choice.probeErr != nil {
			attrs = append(attrs, "probeErr", choice.probeErr)
		}
		logger.Warn("this node is still using the legacy temp-dir pod root, which macOS may purge; it holds the image cache, the pod dirs and every PVC bound here. To move it: pass --pod-root explicitly, or stop the agent, move the directory to the durable default and restart",
			attrs...)
		return
	}
	logger.Info("runtimed on-disk root (image cache + pod dirs)", "podRoot", choice.root)
}
