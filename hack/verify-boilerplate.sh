#!/usr/bin/env bash
# k3sm per-file Apache-2.0 license-header gate. Wraps hack/boilerplate/boilerplate.py.
# Adapted from the Kubernetes hack/boilerplate verifier (Apache License 2.0, The
# Kubernetes Authors). Run from a repo root:
#   hack/verify-boilerplate.sh           # check; exit 1 if any .go file lacks the header
#   hack/verify-boilerplate.sh --apply   # insert the header into files that lack it
set -euo pipefail
cd "$(dirname "$0")/.."   # repo root
exec python3 hack/boilerplate/boilerplate.py --rootdir . "$@"
