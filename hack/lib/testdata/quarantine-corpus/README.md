# Quarantine corpus

Shared cases for the flake quarantine rules. Every k3sm repository gates itself
with its own copy of those rules; this corpus is what every copy must agree on,
and each copy runs every case (here, `TestQuarantineCorpusParity` in
`hack/lib/testresults_test.go`).

Each case is a directory holding:

- `stream.jsonl`: a `go test -json` stream.
- `quarantine.txt`: a registry in the `hack/quarantine.txt` format.
- `expected.json`: the run's inputs and verdicts:
  - `tier` (`affected` or `full`), `today` (the date deadlines are judged
    against), and `edited` (the packages the change edits directly);
  - `tests`: per test id, `passed`, `excused` or `failed`. A synthetic id
    ends in `::(package)` (a package that failed outside any test) or
    `::(build)` (a failed build). An id is `excused` when its report line
    reads QUARANTINED and `failed` when it reads RED; an expired entry's
    line is about the registry and counts toward the run verdict only;
  - `verdict`: `green` (no failure), `excused` (every failure excused) or
    `red`;
  - `diverges` (optional): per copy (`go` or `python`), that copy's actual
    verdicts where it disagrees with the expected ones. Each entry is listed in
    `DISAGREEMENTS.md`, and the copy's test pins its actual behaviour until the
    disagreement is resolved, so a fix there reds until the entry is removed.

A new case needs no code change: add the directory and every copy picks it up.
