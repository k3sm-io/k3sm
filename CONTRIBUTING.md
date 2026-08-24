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

## Commit messages and pull requests

k3sm uses [Conventional Commits](https://www.conventionalcommits.org/). This is **additive** —
the DCO sign-off above is still required on every commit, and so is any `Co-authored-by:`
trailer your tooling adds.

### Subject line

```
<type>(<scope>)<!>: <summary>
```

The summary is **imperative mood**, starts **lowercase**, has **no trailing period**, and the
whole subject line is at most **72 characters**. One commit does one thing: a subject that needs
`+` or `;` to list what it did is describing two commits.

The `type` is one of, and only one of:

| `type` | Use it for |
|---|---|
| `feat` | New user- or API-visible behavior — a flag, a field, a service, a capability |
| `fix` | Correcting behavior that was wrong against its own contract or spec |
| `docs` | Documentation only (`*.md`, `docs/`, doc comments) |
| `test` | Tests only — `*_test.go`, `testdata/`, test fixtures |
| `refactor` | Restructuring with no externally observable change |
| `perf` | A change only in the resource dimension; the body must carry a measurement |
| `build` | Build, dependency, and packaging surface — `go.mod`, `hack/*.sh`, packaging config |
| `ci` | Continuous-integration configuration |
| `chore` | Repo housekeeping with no product surface — `.gitignore`, tooling config |
| `revert` | Reverting a commit; the body names the reverted sha, its subject, and why |

The `scope` is the **directory name of the package or subsystem you changed** — literally what
`ls` prints (`dns`, `sandbox`, `provider`, `runtime/v1`, `svclb`, `certs`, …), or a
cross-cutting area (`docs`, `hack`, `deps`, `ci`). Do not invent a scope the tree does not
have. Omit the scope entirely for a genuinely repo-wide change; never write empty parentheses.

Examples:

```
fix(dns): honour TC by refetching the query over TCP
feat(provider): expose container restart policy on the pod spec
docs(roadmap): record the conformance-hardening milestone as shipped
refactor(image): extract the blob-digest verifier
```

### Breaking changes

If a consumer that compiled or ran against the previous shape stops working — a removed or
renamed proto/CRD field, a changed field number, a wire or datastore encoding change — mark it
**both** ways: a `!` after the scope **and** a `BREAKING CHANGE:` footer explaining what breaks
and how to migrate.

```
feat(runtime/v1)!: carve a separate Images service

BREAKING CHANGE: ListImages/ImageFsInfo/RemoveImage/PruneImages/LoadImage move
off the Runtime service. Clients must dial Images for these RPCs.
```

### Body

Separated from the subject by a blank line, wrapped at 72–80 columns. Say **why** — what was
wrong, why this shape of fix, and any non-obvious constraint (a platform API that forced the
approach, an invariant that must not break). Do not restate the diff; `git show` already does
that. A one-line change with a self-explanatory subject needs no body.

### Pull requests

1. Fork (or branch off `main`) and make your change with signed-off commits.
2. Ensure `hack/ci.sh` passes locally.
3. Open a PR against `main`. **The PR title follows the same `type(scope): summary` grammar** —
   PRs are squash-merged, so the title becomes the commit subject on `main`.
4. Structure the PR body in this order, keeping every heading. If a section has nothing to
   report, write "None." — do not delete it.

   ```markdown
   ## Summary
   <1–3 sentences: what changed and why.>

   ## Gate
   - **Named gate**: `<the exact command that proves this change>`
   - **Verdict**: pass | not run (<why>)
   - **Evidence**: failing before → passing after (or, for a new test, what it asserts)
   - **`hack/ci.sh`**: green | not run (<why>)

   ## Merge preconditions
   <"None." — or anything that must happen before a maintainer merges.>

   ## Review
   - **Notes**: <review context, known trade-offs, rejected alternatives>

   ## Ledger
   <Docs or status updates riding this PR, or "None.">

   ## Checklist
   - [ ] Commits signed off (`git commit -s`) — DCO
   - [ ] `hack/ci.sh` green locally
   - [ ] Tests added or updated for the change
   - [ ] Docs updated if behavior changed
   ```
5. Address review feedback; keep commits focused and signed off.

## Reporting security issues

Do **not** open a public issue for a security vulnerability — see
[SECURITY.md](SECURITY.md) for the private disclosure process.
