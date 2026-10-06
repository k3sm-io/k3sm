# Status JSON

`k3sm status` has two machine-readable shapes. Both are versioned, and this page is their contract:
what each field means, which values an enum can take, and what a version bump promises.

```sh
k3sm status -o json            # the full report
k3sm status daemons -o json    # the daemons probe
```

The full report probes every subsystem: the LaunchDaemons, the apiserver, the node, the workloads,
the data root, the datastore and the runtime daemon. It talks to the apiserver, so it is the slower of
the two.

The daemons probe answers one question, "are this Mac's k3sm daemons up", from launchd and local
files alone. It builds no apiserver client, opens no runtime socket and lists no workloads, so it is
cheap enough to poll.

## Versioning

Both shapes carry `"schemaVersion": 1`, and so does `k3sm doctor --json`, which emits the full
report's shape.

Output from releases before the stamp has no `schemaVersion` key; treat it as version 0. Version 1
renamed the keys under `version` from capitalised (`Version`, `Commit`, `GoVersion`) to the
lowerCamel spelling every other key uses, so a script written against version 0 that reads
`.version.Version` must read `.version.version`.

- `schemaVersion` changes only on a **breaking** change: a field removed or renamed, a field whose
  type changes, or a field or enum value whose meaning changes.
- New fields and new enum values are **not** breaking and do not change `schemaVersion`.

So a reader should:

- check `schemaVersion` and refuse, or degrade, on a version it does not know;
- **ignore keys it does not know**;
- treat an **enum value it does not know as `unknown`**, never as healthy.

## Exit codes and stdout

Both commands write their JSON document to stdout **whatever the exit code**. A non-zero exit is a
verdict, not a failure to answer, so read stdout first and use the exit code as a shortcut.

| exit | meaning |
|---|---|
| 0 | `running` |
| 1 | internal error: no JSON is guaranteed on stdout |
| 2 | bad usage: no JSON on stdout |
| 3 | `stopped` |
| 4 | `degraded` |
| 5 | `not-installed` |
| 6 | `unknown` |

## Shared enums

**`verdict`** is one of:

| value | meaning |
|---|---|
| `running` | the node is up and every probed subsystem is healthy |
| `degraded` | the node is up, and at least one subsystem is failing or warning |
| `stopped` | k3sm is installed and its node daemon is not serving (stopped, disabled, failed or crash-looping); `summary` says which |
| `not-installed` | there is no k3sm install on this Mac |
| `unknown` | the state could not be read from this account; re-run with `sudo` |

**`role`** is which node this Mac is installed as: `server` (the control plane) or `agent` (a worker
that joined one). A Mac with no install reports `server`.

**`severity`**, on every row, is one of `ok`, `warn`, `fail`, `skip` (nothing to probe) or `unknown`
(could not probe).

## The daemons probe

```json
{
  "schemaVersion": 1,
  "verdict": "running",
  "role": "server",
  "summary": "the control-plane daemon and netd are running (the apiserver was not probed)",
  "daemons": [
    { "name": "netd", "state": "running", "severity": "ok", "detail": "pid 1292 · socket /var/lib/k3sm/run/netd.sock", "wide": { "...": "..." } },
    { "name": "server", "state": "running", "severity": "ok", "detail": "pid 1340", "wide": { "...": "..." } }
  ]
}
```

| field | type | notes |
|---|---|---|
| `schemaVersion` | number | `1` |
| `verdict` | string | see [Shared enums](#shared-enums) |
| `role` | string | `server` or `agent` |
| `summary` | string | one sentence for a person; do not parse it |
| `daemons` | array of rows | always two: `netd`, then the node daemon (`server` on a control plane, `agent` on a worker) |

The rows are the same rows, built the same way, as the full report's rows of the same names. The
verdict comes from the same function as the full report's, fed the install check and these two
daemons. When the cause of a problem is something only the apiserver or the disk can show (a Pod
stuck pending, an unmounted data root), the full report says `degraded` or `stopped` and the probe
does not; for every cause the probe can see, the two agree.

### Daemon row states

A daemon row's `state` is one of:

| state | rows | meaning |
|---|---|---|
| `running` | all | launchd has a live process for the job |
| `stopped` | all | loaded and idle, with no failure recorded |
| `not-loaded` | all | not bootstrapped in the system domain |
| `disabled` | all | disabled in launchd, so it will not start |
| `failed` | all | not running; its one run exited non-zero |
| `crash-loop` | all | launchd keeps restarting it into the same failure; on `server` also the control plane restarting after crashes (`warn`) or parked after too many (`fail`) |
| `unknown` | all | launchctl's output could not be read, or launchd says running and the pid is gone |
| `waiting` | `agent` | the daemon is up and this Mac has not joined a cluster yet |
| `expired` | `agent` | the node credential has expired |
| `corrupt` | `agent` | the stored node credential does not parse |
| `address-mismatch` | `agent` | the node's serving certificate names an address this node is not assigned |

The four `agent` states describe the node credential, not the process: the daemon is running in all
four.

## The full report

```json
{
  "schemaVersion": 1,
  "verdict": "running",
  "role": "server",
  "summary": "1/1 nodes ready",
  "rows": [ { "name": "install", "state": "ok", "severity": "ok", "detail": "..." } ],
  "next": [ "k3sm kubectl get pods -A" ],
  "version": { "version": "v0.1.7", "commit": "...", "dirty": false, "date": "...", "goVersion": "go1.26.1", "platform": "darwin/arm64", "kubeVersion": "v1.36.2", "kineVersion": "v1.14.2", "modules": [ { "path": "k3sm.io/k3sm", "sha": "..." } ] },
  "host": "26.1",
  "timestamp": "2026-10-01T09:30:00Z"
}
```

| field | type | notes |
|---|---|---|
| `schemaVersion` | number | `1` |
| `verdict` | string | see [Shared enums](#shared-enums) |
| `role` | string | `server` or `agent` |
| `summary` | string | one sentence for a person; do not parse it |
| `rows` | array of rows | one per subsystem, in display order |
| `next` | array of strings | the commands to run next, most urgent first; omitted when empty |
| `peers` | array | reserved for mesh peers (`name`, `state`, `detail`); not emitted yet |
| `version` | object | the build that produced the report; `modules` is omitted when unknown |
| `host` | string | the macOS version, empty when it could not be read |
| `timestamp` | string | RFC 3339 |

Row names in the full report include `install`, `netd`, `server` or `agent`, `apiserver`, `node`,
`workloads`, `data-root`, `datastore`, `kubeconfig` and `runtimed`; some rows appear only when the
thing they describe exists (`datavol`, `server-args`, `pre-volume`, `etcd`, `mesh-claims`,
`node-resolver`, `shadow-shells`). Besides the daemon states above, a row's `state` may be `ok`,
`ready`, `down`, `not-ready`, `wrong-owner`, `not-mounted`, `absent`, `partial`, `missing`, `skip`,
`drift`, `healthy` or `unhealthy`.

## Rows

| field | type | notes |
|---|---|---|
| `name` | string | stable lowercase token |
| `state` | string | see the state tables above |
| `severity` | string | `ok`, `warn`, `fail`, `skip` or `unknown` |
| `detail` | string | one sentence for a person; do not parse it |
| `remedy` | string | the command or commands that fix this row, one per line; omitted when there is nothing to do |
| `wide` | object of strings | extra detail (label, pid, run count, last exit, plist and log paths); informational, and its keys are not part of the contract |

Text taken from a daemon's log or arguments is redacted before it reaches any field: no join token,
bootstrap token or URL password appears in either shape.
