#!/usr/bin/env bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# The ingest registry is served by k3sm itself, as a verified child process.
#
# --check runs, in pkg/registrysvc, under -race:
#   TestServiceRunsTheK3smRegistry          a real child on a real socket: 200 on an
#                                           anonymous /v2/, 401 on an anonymous push, 202
#                                           with each credential, zot's databases untouched
#   TestServedRegistryRefusesAnonymousPush  the served registry refuses an anonymous write
#   TestRestartRebindsTheIngestPort         an orphan is reclaimed by exact argv, the k3sm
#                                           child and the legacy zot alike
#   TestChildCommand, TestSpawnRefusesAMovedExecutable, TestStartRefusesARootDaemon,
#   TestProvisionWritesTheChildsConfig, TestRecordKeepsTheServersFields,
#   TestIsOrphanedChild, TestReclaimRechecksBeforeEachSignal, TestAwaitNeedsA200
#   TestStoreLeavesZotsDatabasesAlone       cache.db and meta.db are neither deleted nor written
#   TestGateAndServerAgree                  the gate and the server read one repository and
#                                           one mount source, over the classifier's corpus
#                                           and near-miss spellings
#   TestTestManifestIsComplete              no test left this package without a recorded reason
# then the status probe, the executor's zot tolerance and reap tiers, and the
# install's removal of a leftover zot.
#
# Usage: hack/acceptance/B1022.sh --check
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"

if [ "${1:-}" != "--check" ] || [ $# -ne 1 ]; then
	echo "usage: $0 --check" >&2
	exit 2
fi

cd "$K3SM_ROOT"
export CGO_ENABLED=1

go test -race -count=1 -v -tags integration \
	-run '^(TestServiceRunsTheK3smRegistry|TestServedRegistryRefusesAnonymousPush|TestRestartRebindsTheIngestPort|TestChildCommand|TestSpawnRefusesAMovedExecutable|TestStartRefusesARootDaemon|TestProvisionWritesTheChildsConfig|TestRecordKeepsTheServersFields|TestIsOrphanedChild|TestReclaimRechecksBeforeEachSignal|TestAwaitNeedsA200|TestStoreLeavesZotsDatabasesAlone|TestGateAndServerAgree|TestTestManifestIsComplete)$' \
	./pkg/registrysvc
go test -race -count=1 -v -run '^TestRegistryAnswered$' ./pkg/status
go test -race -count=1 -v -run '^(TestVerifyPayloadSetToleratesZot|TestReapTiersKeepZotAndNeverListK3sm)$' ./pkg/executor
go test -race -count=1 -v -run '^TestInstallRemovesTheLeftoverZot$' ./pkg/install
echo "the ingest registry is served by k3sm: ok"
