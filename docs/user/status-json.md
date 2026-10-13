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
| `stoppedBy` | object | who stopped k3sm on this Mac (see [Stopped by](#stopped-by)); omitted when no stop is recorded |

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
| `interconnect` | object | the cluster's interconnect and its attached Pods (see [Interconnect](#interconnect)); omitted when the cluster has none, or the report could not read it |
| `stoppedBy` | object | who stopped k3sm on this Mac (see [Stopped by](#stopped-by)); omitted when no stop is recorded |
| `version` | object | the build that produced the report; `modules` is omitted when unknown |
| `host` | string | the macOS version, empty when it could not be read |
| `timestamp` | string | RFC 3339 |

Row names in the full report include `install`, `netd`, `server` or `agent`, `apiserver`, `node`,
`workloads`, `data-root`, `datastore`, `kubeconfig` and `runtimed`; some rows appear only when the
thing they describe exists (`datavol`, `server-args`, `heartbeat`, `pre-volume`, `etcd`,
`mesh-claims`, `node-resolver`, `shadow-shells`, `request-header`, `interconnect`). Besides the daemon states above, a row's `state` may
be `ok`, `ready`, `down`, `not-ready`, `wrong-owner`, `not-mounted`, `absent`, `partial`, `missing`,
`skip`, `drift`, `healthy`, `unhealthy` or `stale`.

The `heartbeat` row reports how long ago this Mac's node last posted its status and renewed its
Lease, as the apiserver holds them. It appears when the apiserver answered and this Mac's node was
identified. Its `state` is `ok`, or `stale` (severity `warn`) when the Lease renewal is older than 40
seconds or the status post is older than 100 seconds. `detail` gives both ages; `wide` carries them
as `leaseAgeSeconds` and `statusAgeSeconds` when known.

The `etcd` row's `wide` carries the scheduled etcd snapshots: `snapshot-schedule` (the cron
expression, or `off`), and when a schedule is set, `last-scheduled-snapshot` (RFC 3339, or
`none yet`) and `scheduled-snapshots-kept` (`<kept> of <retention>`). Until the next successful
snapshot it also carries `last-scheduled-snapshot-error` (the last failure) and
`last-scheduled-snapshot-skipped` (when a snapshot was skipped and why: not enough free space, or
the free space could not be read). Like every `wide` key, these are informational and not part of
the contract.

## Stopped by

Both shapes carry an optional `stoppedBy` object while `k3sm stop` has recorded a stop on this Mac.
It is additive: `schemaVersion` stays `1`, and the `verdict` and every row `state` keep their
words (a stopped Mac still reports `stopped`, or a daemon `disabled`). `stoppedBy` only says who
asked for it.

```json
"stoppedBy": {
  "actor": "user",
  "reason": "maintenance window",
  "at": "2026-09-05T09:28:30Z",
  "phase": "stopped"
}
```

| field | type | notes |
|---|---|---|
| `actor` | string | `user` for a person's `k3sm stop`, `auto` for a stop k3sm itself made |
| `reason` | string | the reason given at the stop; may be empty |
| `at` | string | RFC 3339, when the stop began |
| `phase` | string | `stopping` while a stop has left something behind (re-run `sudo k3sm stop` to converge), `stopped` once nothing was left |

The object is omitted when there is no stop marker, and also when the marker cannot be read or
parsed: a damaged marker never fails the report. Readers must treat a missing `stoppedBy` as
"no recorded stop", not as "running".

## Interconnect

The `interconnect` object describes the cluster's [interconnect](interconnects.md), read from the
`Interconnect` named `thunderbolt`. The `interconnect` row says the same thing as a sentence.

```json
"interconnect": {
  "name": "thunderbolt",
  "armed": true,
  "armedBy": "alice",
  "plaintext": true,
  "members": 3,
  "up": 2,
  "segments": 1,
  "outOfRange": [ "far-mac" ],
  "pods": [ { "namespace": "mlx", "pod": "llama-0", "node": "node-a", "address": "169.254.0.2" } ]
}
```

| field | type | notes |
|---|---|---|
| `name` | string | the interconnect's name, its medium |
| `armed` | boolean | whether an admin enabled it; nothing has an interconnect address until one does |
| `armedBy` | string | the identity recorded when it was armed; omitted when none is recorded |
| `plaintext` | boolean | `true` whenever it is armed: opted-in Pod traffic crosses the cable unencrypted |
| `members` | number | the cabled nodes the server resolved |
| `up` | number | the members that are usable |
| `segments` | number | the groups of members that reach each other over cables |
| `outOfRange` | array of strings | cabled nodes whose cluster index is above 30, which get no interconnect address; omitted when empty |
| `pods` | array | every Pod whose `k3sm.io/InterconnectAttached` condition is `True`, sorted by namespace and name: `namespace`, `pod`, `node`, `address`; omitted when empty |

The row's `state` is `disabled` (severity `skip`) while the interconnect is disarmed, `ok` when every
member is up, and `partial` or `down` (severity `warn`) when a member is not up or a cabled node is
out of range. The row never moves `verdict`. On a worker, whose node credential may not read the
`Interconnect`, the row is `skip` and the object is omitted. `k3sm status cluster` lists each
attached Pod in the row's `wide` keys.

## Rows

| field | type | notes |
|---|---|---|
| `name` | string | stable lowercase token; look a row up by its `name`, never by its position, because rows appear only when the thing they describe exists |
| `state` | string | see the state tables above |
| `severity` | string | `ok`, `warn`, `fail`, `skip` or `unknown` |
| `detail` | string | one sentence for a person; do not parse it |
| `remedy` | string | the command or commands that fix this row, one per line; omitted when there is nothing to do |
| `wide` | object of strings | extra detail (label, pid, run count, last exit, plist and log paths); informational, and its keys are not part of the contract |

Text taken from a daemon's log or arguments is redacted before it reaches any field: no join token,
bootstrap token or URL password appears in either shape.
