# Known disagreements

Cases where the copies of the quarantine rules do not agree. Each names the
verdict this corpus holds to be right in `expected.json`, and the diverging
copy's actual behaviour under `diverges`. Resolving one means fixing that copy
and deleting its `diverges` entry and its section here, in the same change.

The Go copy is `hack/lib/testresults.go` in this repository; the Python copy
is `hack/lib/quarantine.py`, which the k3sm project tooling carries.

## parent-failnow-no-output (both copies)

A parent test that fails through `t.Fail` or `t.FailNow` writes no output line,
so when its only failing subtest is quarantined, both copies read the parent as
failing only through that subtest and excuse it. The parent failed on its own,
so the corpus holds `red` to be right. Both copies document this as the blind
spot of the parent-coverage rule: the `go test -json` stream carries nothing
that tells a parent's own silent failure apart from the failure its subtest
propagated. The `diverges` entries for `go` and `python` pin the excused
verdict until a copy can tell them apart.
