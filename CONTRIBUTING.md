# Contributing to k3sm

Thank you for your interest in contributing to k3sm. This document covers the
contribution workflow and the legal sign-off we require.

By participating, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Building and testing

k3sm is a multi-repo Go workspace (`apis`, `runtimed`, `darwin-net`, `k3sm`).
Each repository documents its own build and test commands in its `CLAUDE.md` and
`docs/GO-STANDARDS.md`. The commit gate for every repository is its `hack/ci.sh`
(`gofmt -l`, `go vet`, `go build`, `go test`, plus the per-file license-header
check). Run it before opening a pull request.

## Developer Certificate of Origin (DCO)

All contributions to k3sm are certified under the
[Developer Certificate of Origin](DCO). Every commit must carry a `Signed-off-by`
line with your real name and a reachable email:

```
Signed-off-by: Jane Doe <jane.doe@example.com>
```

Add it automatically with the `-s` flag:

```
git commit -s -m "your message"
```

The sign-off certifies that you wrote the patch, or otherwise have the right to
submit it under the project's license. It is required on **every** commit; a PR
with unsigned commits will not be merged.

> **`Signed-off-by` vs `Co-Authored-By`.** k3sm is developed with AI agent
> assistance, and agent-authored commits additionally carry a
> `Co-Authored-By: Claude ...` trailer. That trailer is an **authorship
> attribution** convention — it is **not** the DCO sign-off and does not certify
> the DCO. The DCO is certified solely by the human committer's `Signed-off-by`
> line. Human contributors should add `Signed-off-by` (via `git commit -s`) and
> should **not** add a `Co-Authored-By: Claude` line.

## Pull requests

1. Fork (or branch off `main`) and make your change with signed-off commits.
2. Ensure `hack/ci.sh` passes locally.
3. Open a PR against `main` with a clear description of the change and its motivation.
4. Address review feedback; keep commits focused and signed off.

## Reporting security issues

Do **not** open a public issue for a security vulnerability — see
[SECURITY.md](SECURITY.md) for the private disclosure process.
