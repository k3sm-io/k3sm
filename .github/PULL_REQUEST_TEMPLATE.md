## Summary

<!-- 1-3 sentences: what changed and why. Link any related issue. -->

## Gate

- **Named gate**: `<the exact command that proves this change>`
- **Verdict**: pass | not run (<why>)
- **Evidence**: failing before, passing after (or, for a new test, what it asserts)
- **`hack/ci.sh`**: green | not run (<why>)

## Merge preconditions

None.

## Review

- **Notes**: <review context, known trade-offs, rejected alternatives>

## Ledger

None.

## Checklist

- [ ] Commits are signed off: `git commit -s` (see [CONTRIBUTING](../CONTRIBUTING.md) / [DCO](../DCO))
- [ ] `hack/ci.sh` passes locally (this repository's gate: build, tests, license headers, and its linters)
- [ ] Tests added or updated for the change
- [ ] Docs updated if behavior changed
