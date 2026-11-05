# `hack/lab/runs/` — the lab-gate evidence convention

A lab gate is run by hand, on real hardware, and then it is over. Nothing about that
run survives in CI, so the **log is the evidence** — the only artifact a later reader
can use to decide whether a gate row in `hack/acceptance/phases.json` was actually satisfied, and by *what*. This
file is the convention those logs follow.

## The logs themselves are NOT tracked

A lab log is a transcript of a real machine. It carries that machine's host name, its
LAN addresses, its hardware model and OS build, and whatever else the gate printed
while it ran — none of which belongs in a public repository. So `hack/lab/runs/*.log`
is **gitignored**: the logs are retained by the maintainers outside the repo,
and this README is the only tracked file in the directory.

That does not weaken the evidence chain, because the chain never ran through git. A
gate row is discharged by citing a log by its **run id** — the file name below, which already encodes
the gate, the artifact under test and the UTC date — and the maintainers hold the log
that name refers to. A reader who needs the transcript asks for it by run id; a reader
who only needs to know *which* run discharged a row reads the id in the record that cites it.

## File name (the run id)

```
hack/lab/runs/<gate>-<rc-tag>-<UTCdate>.log
```

- **`<gate>`** — the `phases.json` row key, lowercased: `<row>-core`, `<row>-lab`.
  One row per file; a log that covers two rows proves neither cleanly.
- **`<rc-tag>`** — the release-candidate tag the artifact under test came from
  (`v0.2.0-rc.1`), or `local` for a developer build.
- **`<UTCdate>`** — `YYYY-MM-DD`, **UTC**. Lab Macs sit in whatever timezone they sit
  in; UTC is what makes two logs orderable.

## Header

Every log opens with the header emitted by the gate script itself (see
`emit_run_log_header` in `hack/lab/lib/runlog.sh`). Four fields are **required**; a log
missing any of them is not evidence:

| Field | Why it is required |
|---|---|
| `gate` | Which row this log is evidence for. A `<row>-core` run is a strict SUBSET of the `<row>-lab` run; a log that does not say which one it ran cannot discharge either. |
| `artifact_sha256` | *What* was tested. `local:<sha>` for a developer build, the **bare sha** for the release-candidate run. A gate row bound to an rc artifact is satisfied only by a bare-sha log whose sha matches the published artifact. |
| `git_sha.<repo>` | The commit each of the four modules was built from — `apis`, `runtimed`, `darwin-net`, `k3sm`. One binary, four repos; a single "the SHA" would be a lie. `unknown` when a sibling repo is not checked out, which is an evidence gap to see, not to hide. |
| `result` | `PASS` or `FAIL`, recorded **in the log**. Exit status is not archived; a log whose verdict must be inferred from its prose gets inferred wrong. The header opens with a provisional, fail-closed `result:` line; the **last** `result:` line in the log is authoritative (`emit_run_log_verdict` in `hack/lab/lib/runlog.sh`). |

`mode`, `rc_tag`, `started_utc` and `tolerate_keys` ride along for context; the closing verdict adds `finished_utc`.

## Running a gate

```sh
K3SM_LAB=1 K3SM_RC_TAG=v0.2.0-rc.1 K3SM_ARTIFACT=/path/to/k3sm \
  hack/lab/m11.sh --core | tee hack/lab/runs/<row>-core-v0.2.0-rc.1-2026-09-01.log
```

The redirect target is inside this directory purely for convenience — the file is
gitignored the moment it is written. Move or copy it to wherever you keep lab evidence;
never `git add -f` one.

`K3SM_ARTIFACT` is the binary under test (it is what `artifact_sha256` hashes);
`K3SM_RC_TAG` promotes the recorded sha from `local:<sha>` to the bare rc form. With
`K3SM_LAB` unset a lab gate prints a PENDING notice and exits 0 — a **skip, never a
pass** — and produces no log worth keeping.
The memory-pressure lab gate is the exception: with `K3SM_LAB` unset it prints a
"pending, not a pass" notice and exits **3**, not 0, and its `--self-test` pins that.

There is deliberately **no generator**: the gate emits its own header and whoever runs it
redirects it. A tool that wrote these logs would be a tool that could write one for a
run that never happened.

## Two runs for an rc-bound row

An rc-bound row (a `<row>-core` row) is typically run **twice**: once functionally during
development, recording `artifact_sha256: local:<sha>`, and once against the published
release candidate, recording the bare sha. Only the second discharges the gate row.
Keep both — the first is how the leg was debugged, the second is how it was proven.
