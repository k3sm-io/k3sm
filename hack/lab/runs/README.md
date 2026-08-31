# `hack/lab/runs/` — the lab-gate evidence convention

A lab gate is run by hand, on real hardware, and then it is over. Nothing about that
run survives in CI, so the **log is the evidence** — the only artifact a later reader
can use to decide whether a ledger row was actually satisfied, and by *what*. This
directory is where those logs live, and this file is the convention they follow.

## File name

```
hack/lab/runs/<gate>-<rc-tag>-<UTCdate>.log
```

- **`<gate>`** — the `phases.json` row key, lowercased: `m11-core`, `m11-lab`, `m3-lab`.
  One row per file; a log that covers two rows proves neither cleanly.
- **`<rc-tag>`** — the release-candidate tag the artifact under test came from
  (`v0.1.0-rc.3`), or `local` for a developer build.
- **`<UTCdate>`** — `YYYY-MM-DD`, **UTC**. Lab Macs sit in whatever timezone they sit
  in; UTC is what makes two logs orderable.

## Header

Every log opens with the header emitted by the gate script itself (see
`emit_run_log_header` in `hack/lab/m11.sh`). Four fields are **required**; a log
missing any of them is not evidence:

| Field | Why it is required |
|---|---|
| `gate` | Which row this log is evidence for. `M11-core` is a strict SUBSET of `M11-lab`; a log that does not say which one it ran cannot discharge either. |
| `artifact_sha256` | *What* was tested. `local:<sha>` for a developer build, the **bare sha** for the release-candidate run. A ledger row bound to an rc artifact is satisfied only by a bare-sha log whose sha matches the published artifact. |
| `git_sha.<repo>` | The commit each of the four modules was built from — `apis`, `runtimed`, `darwin-net`, `k3sm`. One binary, four repos; a single "the SHA" would be a lie. `unknown` when a sibling repo is not checked out, which is an evidence gap to see, not to hide. |
| `result` | `PASS` or `FAIL`, recorded **in the log**. Exit status is not archived; a log whose verdict must be inferred from its prose gets inferred wrong. |

`mode`, `rc_tag` and `started_utc` ride along for context.

## Running a gate

```sh
K3SM_LAB=1 K3SM_RC_TAG=v0.1.0-rc.3 K3SM_ARTIFACT=/path/to/k3sm \
  hack/lab/m11.sh --core | tee hack/lab/runs/m11-core-v0.1.0-rc.3-2026-09-01.log
```

`K3SM_ARTIFACT` is the binary under test (it is what `artifact_sha256` hashes);
`K3SM_RC_TAG` promotes the recorded sha from `local:<sha>` to the bare rc form. With
`K3SM_LAB` unset a lab gate prints a PENDING notice and exits 0 — a **skip, never a
pass** — and produces no log worth keeping.

There is deliberately **no generator**: the gate emits its own header and the operator
redirects it. A tool that wrote these logs would be a tool that could write one for a
run that never happened.

## Two runs for an rc-bound row

An rc-bound row (`M11-core`) is typically run **twice**: once functionally during
development, recording `artifact_sha256: local:<sha>`, and once against the published
release candidate, recording the bare sha. Only the second discharges the ledger row.
Keep both — the first is how the leg was debugged, the second is how it was proven.
