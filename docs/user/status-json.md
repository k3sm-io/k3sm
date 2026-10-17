# Status JSON

`k3sm status` has two machine-readable shapes, and `k3sm alerts` a third cut from the first. All are
versioned, and this page is their contract: what each field means, which values an enum can take,
and what a version bump promises.

```sh
k3sm status -o json            # the full report
k3sm status daemons -o json    # the daemons probe
k3sm alerts -o json            # only the rows that need attention, with their alerts
```

The full report probes every subsystem: the LaunchDaemons, the apiserver, the node, the workloads,
the data root, the datastore and the runtime daemon. It talks to the apiserver, so it is the slower of
the two.

The daemons probe answers one question, "are this Mac's k3sm daemons up", from launchd and local
files alone. It builds no apiserver client, opens no runtime socket and lists no workloads, so it is
cheap enough to poll.

## Versioning

Every shape carries `"schemaVersion": 1`, and so does `k3sm doctor --json`, which emits the full
report's shape. The `alert` object on rows and the `k3sm alerts` shape are additions under version 1.

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

The `verdict` describes k3sm's own health: the daemons, the apiserver, the node, networking and the data root decide it, and the `workloads` row never does, at any severity.

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
| `network` | object | this node's LAN access setting (see [Network](#network)), without `applied` and `appliedReadable`; omitted when k3sm is not installed, or by a k3sm older than the setting |

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
| `network` | object | this node's LAN access setting (see [Network](#network)); omitted when k3sm is not installed, or by a k3sm older than the setting |
| `workers` | array | on a server, the cluster's other nodes and their versions (see [Workers and join target](#workers-and-join-target)); omitted when unknown |
| `joinTarget` | string | on a worker, the server endpoint it joined (see [Workers and join target](#workers-and-join-target)); omitted when unknown |
| `version` | object | the build that produced the report; `modules` is omitted when unknown |
| `host` | string | the macOS version, empty when it could not be read |
| `timestamp` | string | RFC 3339 |

Row names in the full report include `install`, `netd`, `server` or `agent`, `apiserver`, `node`,
`workloads`, `data-root`, `datastore`, `kubeconfig`, `runtimed` and `dns`; some rows appear only when the
thing they describe exists (`datavol`, `server-args`, `settings`, `heartbeat`, `pre-volume`, `etcd`,
`mesh-claims`, `services`, `update`, `node-resolver`, `shadow-shells`, `request-header`, `interconnect`, `ingest-registry`). Besides the daemon states above, a row's `state` may
be `ok`, `ready`, `down`, `not-ready`, `wrong-owner`, `not-mounted`, `absent`, `partial`, `missing`,
`skip`, `drift`, `healthy`, `unhealthy`, `stale`, `needs-admin`, `behind`, `ahead` or `rolling`.

`ingest-registry`, on a server started with `--registry-port`, is `ok` when the registry the server recorded as serving answers `/v2/` on its loopback port, `down` (`warn`) when it does not, `disabled` (`warn`, with the reason in `detail`) when the server gave up starting it, and `stopped` (`skip`) after the server tore it down; `wide.port` and `wide.since` carry the port and when it entered that state, and the row reads the copy of the server's record in `/var/lib/k3sm/status/` (mode 0644, no credential), so any account sees the same row; `wide.record` names the file read.

`needs-admin` marks a check that only root can run, so nothing was checked and nothing is wrong. Its
`remedy` is `sudo k3sm status`, and it never changes the `verdict`. A client can show it as not
checked rather than as a fault. Run as any account other than root, these rows report it:

| row | what needs root |
|---|---|
| `runtimed` | the runtime daemon's control socket is owner-only; severity `skip` |
| `admin-kubeconfig` | only root reads the admin kubeconfig install recorded; severity `skip` |
| `server-args` | the server's LaunchDaemon plist is readable by root only; severity `skip` |
| `settings` | the node daemon's arguments are readable by root only; those values read `restricted`, the others are still read; severity `skip` |
| `pre-volume` | the size is a lower bound because part of the copy is root-only; severity stays `warn`, because the copy is there whoever reads it |

Other rows read what your account can, through the apiserver, instead of a file only root can read:

- `datastore`: `ok` with `detail` `answers (the apiserver's readiness check reached it); the WAL and
  user_version checks run only as root` when the apiserver is ready, because its readiness check
  includes the datastore. `wide.source` is `apiserver readyz`. The row counts the answer only when
  your kubeconfig's server is one of this cluster's endpoints (see the endpoints record below).
  Otherwise it is `unknown`, saying the kubeconfig does not point at this server. It is also
  `unknown` when the apiserver did not answer.
- `serving-cert`: reads the certificate the apiserver presents when it is reached with your
  kubeconfig, and checks it as root checks the file: in date, issued by the CA your kubeconfig
  pins, and naming the host you reached it by. `wide.source` is `handshake`. The same test of the
  server applies as for `datastore`. It is `unknown` when that test fails, the handshake fails, or
  your kubeconfig pins no CA.
- `mesh-claims` and `services`: a server writes each record twice, mode 0600 in its own work dir
  and mode 0644 in `/var/lib/k3sm/status/`, which any account can read. The records hold
  cluster-internal names and addresses, never a credential. The rows read the second copy when the
  first is not readable, and `wide.record` names the file read. A server older than the status
  directory writes no second copy, and then the rows say `needs-admin`.
- On a worker whose node credential your account cannot read, `apiserver`, `node` and `workloads`
  read the cluster with your own kubeconfig: its `k3sm` context (or the name given to `k3sm install
  --kubeconfig-name`), else the current context, and either only when its server is one of this
  cluster's endpoints (see below). A context is never used by its name alone. The `kubeconfig` row
  then names that file and context, with `wide.source` `user-kubeconfig`.

The endpoints record, `/var/lib/k3sm/status/endpoints.json` (mode 0644), is how a report run as an
ordinary account knows which endpoints are this cluster's. The node daemon writes it at start: the
apiserver `port`, and the `hosts` that name the apiserver. On a server those are its serving
certificate's names and addresses, loopback, and this Mac's own addresses. On a worker they are the
host it joined, the apiserver address it uses, and the names on the serving certificate that
apiserver presents, read over a connection verified against the cluster CA the worker pinned when
it joined. A kubeconfig context counts as this cluster's when its server's host is in `hosts` and its
port is `port`. A node older than the record writes none; then a server accepts a loopback address or
one of this Mac's addresses at port 6444, and a worker accepts the host it joined.

The `dns` row asks this node's resolver for `kubernetes.default.svc.cluster.local`: one query over
UDP to the cluster DNS address (`10.43.0.10`, or the `--dns-vip` the node daemon was installed
with), port 53, with a 3 second timeout. It appears on every role and needs no root. Its `state` is:

- `ok` when the resolver answers with an address. `detail` and `wide.answer` give the address.
- `down` (severity `warn`) when no answer arrives over UDP in 3 seconds. The report then asks the
  same question over TCP, and when TCP answers, `wide.tcp` gives that answer: the resolver is up and
  its UDP socket is not receiving, which pods and the host resolver see as names that time out.
  `remedy` restarts the node daemon (`sudo launchctl kickstart -k system/io.k3sm.server` on a
  server, `system/io.k3sm.agent` on a worker).
- `unhealthy` (severity `warn`) when the resolver answers over UDP with no address, such as a
  name error. `detail` gives the reply's code.
- `skip` when k3sm is not installed or the node daemon is not running.
- `unknown` when the node daemon's `--dns-vip` is not an address.

Unlike `node-resolver`, which reports whether the host routes cluster names to that address, this
row reports whether anything answers there, and a `warn` makes the `verdict` `degraded`. `wide.vip`
and `wide.name` give the address and the name asked.

The `settings` row reports the node's install settings: the values `k3sm install` recorded in the
node daemon's arguments (or the default the daemon takes when none is recorded), the data volume, and
LAN access. It appears on an installed Mac, after the `server-args` row on a server and the `agent`
row on a worker, and it never changes the `verdict`. Its `wide` keys are part of the contract:

| key | value |
|---|---|
| `nodeport-addresses` | the `--nodeport-addresses` value, or `every interface` |
| `registry-port` | the node registry's port, or `off`; server only |
| `tls-sans` | the extra apiserver certificate names, comma-separated, or `none`; server only |
| `mesh-ip` | the mesh address, or `none`; server only |
| `kubeconfig-name` | the name the admin kubeconfig is merged under; server only |
| `release-base` | the release index the managed update reads, or `default`; a password in the URL is masked |
| `data-volume` | `none` for a plain directory, else the volume's name, quota and encryption |
| `lan-access` | `on` or `off`, the value the node daemon serves; `unreadable` when the record cannot be used |

A value read from a file only root can read is `restricted`, and the row's `state` is then
`needs-admin`. A value whose source could not be read for another reason is `unknown`, and so is
the row's `state` when that source is the node daemon's arguments. No value is a token, key or
password: the row names a fixed set of settings, none of which is a credential. `detail` gives the
same values in one line.

The `heartbeat` row reports how long ago this Mac's node last posted its status and renewed its
Lease, as the apiserver holds them. It appears when the apiserver answered and this Mac's node was
identified. Its `state` is `ok`, or `stale` (severity `warn`) when the Lease renewal is older than 40
seconds or the status post is older than 100 seconds. `detail` gives both ages; `wide` carries them
as `leaseAgeSeconds` and `statusAgeSeconds` when known.

The `services` row appears on a server. It compares the backends the server's Service proxy routes
each Service port to with the Ready endpoints in the cluster's EndpointSlices. The server records
its proxy in a file in its work dir, once the proxy has loaded every Service and then every 30
seconds, with a copy any account can read in `/var/lib/k3sm/status/`. Its `state` is:

- `ok` when every compared port matches. `detail` gives the port count.
- `unhealthy` (severity `warn`) when a port's backends differ. `detail` names each such Service
  (`namespace/name`), its port (`clusterIP:port/protocol`), the Ready endpoints the proxy does not
  route (`missing`) and the backends it routes that are not Ready (`extra`).
- `unknown` when a port differs but its Service or EndpointSlices changed after the record was
  written, or its Service has been deleted, so the record cannot have seen the change. `detail` and
  `wide.settling` name those ports. Such a port is never reported as `ok`.
- `unknown` when the record is absent (a server writes its first one once its proxy has loaded the
  cluster's Services), older than 60 seconds, or unreadable, or when the apiserver is not serving
  or the list fails.

`detail` and `wide.settling` name at most eight ports, then how many more, and at most four
addresses in each `missing` or `extra` list, then how many more.

The cluster DNS address is not compared, because the server's own resolver answers it, not the
proxy. On a single-node server the `kubernetes` Service has no EndpointSlice; the server pins its
backend and records the pinned backend beside the proxy's table, and the row compares the table
with that, so a `kubernetes` port that lost its backend or left the table is `unhealthy` naming the
pinned backend. Each report lists every Service and every EndpointSlice once from the apiserver, so
a script that polls the full report pays for those two lists on every poll; poll the daemons probe
when that is all you need.

The `update` row appears on an installed server and an installed worker. It reports whether every node runs the latest k3sm
release, from the record the last update check left (see [Upgrade](upgrade.md#checking-for-an-update)).
The server checks at most once an hour and `sudo k3sm update check` checks on demand; the report itself
never contacts GitHub. The record is `/var/lib/k3sm/status/update.json` (mode 0644), so any account
reads the row. Its `state` is:

On a worker the row is read-only. After each check a server publishes the latest release and when it
checked on its own Node (the `k3sm.io/release-latest` and `k3sm.io/release-checked` annotations),
and the worker's report reads them from the node list, so it compares every node with the same
release the server does; `wide.record` is `node/<server>`. Only a control-plane Node's annotations
count, and with more than one server the most recent check wins. The row offers no check remedy,
since a worker cannot refresh the server's record. When the report cannot list nodes (the apiserver
does not answer, or the credential it reads with may not list them) or no server has published a
check yet, the row is `unknown` and `detail` says why.

The row's `state` is:

- `ok` when every node's kubelet reports the latest release.
- `behind` (severity `warn`) when a node runs an older release. `detail` names each such node and the
  version its kubelet reports, and `remedy` is the install one-liner. The row never moves the verdict:
  a cluster with an update available is still `running`.
- `ahead` (severity `ok`) when a node runs a release newer than the latest and none is behind.
  `detail` names those nodes; there is no remedy.
- `rolling` (severity `ok`) while a managed update is in progress (see
  [Upgrade](upgrade.md#managed-update)): the server reads the `Update` every 30 seconds and records
  it beside the check, so a roll started from any Mac shows here. `detail` names the target release,
  the update's phase and the node being updated with its step, for example `updating the cluster to
  k3sm v0.2.0: Rolling, node laptop Installing`. `wide.target` is the release, `wide.phase` the
  update's phase (`Pending` before the first node starts), `wide.node` and `wide.node-phase` the node
  being updated and its step (omitted before the first node starts), and `wide.observed` when the
  server last read the update. `wide.latest` is the latest release the last check found, when it
found one. There is no remedy and the verdict does not move. A roll the server
  has not refreshed for five minutes (the server is down, say) is no longer reported, and the row
  falls back to the check's state. Once the update finishes the row returns to the check's state.
- `unknown` when the last check could not finish (`detail` carries its error, first line only and
  redacted), when a node reports no tagged k3sm release, when no check is recorded, or when the record
  is older than 24 hours, dated more than five minutes in the future, or fails validation. The remedy
  is `sudo k3sm update check`, or `k3sm update check` when the report runs as root or the
  service user, who may write the record.

Each node's state is recomputed from the version in the record, in semver order, and the versions
are what the nodes report of themselves: the row is a convenience signal, not an attestation.

`wide.checked` is when the check ran, `wide.latest` the release tag and `wide.latest-kubernetes` the
Kubernetes version that release ships, when its notes say.

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
"no recorded stop", not as "running". [Stopping and starting](stop-start.md) covers the verbs that write it.

## Network

The full report carries an optional `network` object on an installed Mac: the LAN access setting
`k3sm network lan` and `k3sm install --lan` record, and, when the caller can read it, what the node
daemon reports applying. It is additive: `schemaVersion` stays `1`, and it adds no `verdict` or row
`state` word. The daemons probe carries the same object, built the same way, except `applied` and
`appliedReadable`: the daemon's report is readable by root only, and the probe never reads it.

```json
"network": {
  "lan": "off",
  "recorded": true,
  "covers": ["nodeports", "loadbalancers", "ingress"],
  "alwaysOn": ["apiserver", "join", "mesh"],
  "applied": { "lan": "off", "serial": "4f0c2a9e1b7d3c55" }
}
```

| field | type | notes |
|---|---|---|
| `lan` | string | the recorded setting: `on` (the covered listeners answer on every interface) or `off` (only on this Mac and the cluster mesh); `off` when the record cannot be used, which is what the node daemon serves then |
| `recorded` | boolean | `false` when no setting is recorded (an install from before the switch), in which case `lan` is `on` |
| `recordState` | string | `unreadable` when a record exists but cannot be used (it is damaged, or its owner or mode is wrong); omitted when the record was read or there is none. The reason is not included: run `sudo k3sm network lan status` to see it |
| `covers` | array of strings | the listener families the setting controls: `nodeports`, `loadbalancers`, and `ingress` on a server |
| `alwaysOn` | array of strings | the network-facing listeners it does not control: `apiserver`, `join` and `mesh` on a server, `mesh` on a worker |
| `applied` | object | the node daemon's own report: `lan` (what it serves), `serial` (the write it acted on) and `error` (why its last change was refused, omitted when none); omitted when the caller cannot read the report, which is in the daemon's work dir and readable by root |
| `appliedReadable` | boolean | `false` when the daemon's report exists but the caller may not read it; omitted otherwise |

When `applied.lan` differs from `lan`, or `applied.error` is set, the node is not serving the recorded
setting; the human view says so on its own line, and also says when the applied state is readable by
root only. `sudo k3sm network lan on|off` checks the daemon's listening sockets itself before it
reports success.

A missing `network` means k3sm is not installed on this Mac, or the k3sm that wrote the report is
older than the LAN access setting. Readers must treat it as "unknown", not as either value. A record
that cannot be read is never left out: it is reported as `lan` `off`, `recorded` `true` and
`recordState` `unreadable`. A `recordState` word a reader does not know means the setting is unknown.

## Workers and join target

Two optional fields describe the cluster around this Mac. Both are additive: `schemaVersion` stays
`1`, and neither adds a `verdict` or row `state` word. The daemons probe carries neither.

On a server, `workers` lists every other node in the cluster, sorted by name, from the same node list
the `node` row reads:

```json
"workers": [
  { "name": "node-a", "role": "server", "version": "v1.36.2+k3sm.0.1.7" },
  { "name": "node-b", "role": "agent", "version": "v1.36.2+k3sm.0.1.6" }
]
```

| field | type | notes |
|---|---|---|
| `name` | string | the node's name |
| `role` | string | `server` when the node carries the `node-role.kubernetes.io/control-plane` label, `agent` otherwise |
| `version` | string | the kubelet version the node reports: the Kubernetes version, then `+k3sm.` and the k3sm release as semver build metadata; omitted while the node has reported none |

A node cannot set the `node-role.kubernetes.io/control-plane` label on itself. Each server sets it
to `true` on its own Node at start with its admin credentials, as k3s does, so every server reports
`server`. A worker never carries the label.

`version` is the node's own report of its kubelet version. It is advisory, not an attestation: the
node writes it, and nothing verifies it against the binary the node runs. A missing `version` means
unknown, and a reader comparing versions must treat it as not satisfying any minimum.

An empty list means the server read its nodes, found its own node by name, and there are no others.
A missing `workers` means the answer is unknown: this Mac is a worker, the apiserver did not answer,
the node list could not be read, or no node in the list carries this server's name (even when the
list holds a single node). Readers must not treat a missing `workers` as "no workers".

On a worker, `joinTarget` is the bootstrap endpoint of the server this Mac was installed to join, as
`host:port`:

```json
"joinTarget": "192.0.2.10:9345"
```

It is the `--server` host of the installed worker daemon with the join port, and nothing else from
that daemon's arguments. The host is reported only when it is an IPv4 address or a DNS name made of
letters, digits, `-` and `.`, at most 253 characters long. `joinTarget` is omitted on a server, on a
worker whose daemon configuration cannot be read, and when the `--server` value is anything else:
an IPv6 address, a value that already carries a port, or one with any other character.

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
| `wide` | object of strings | extra detail (label, pid, run count, last exit, plist and log paths); informational, and its keys are not part of the contract, except the `settings` row's (above) |
| `alert` | object | what is wrong and how to fix it (see [Alerts](#alerts)); present on every row whose `severity` is `warn`, `fail` or `unknown`, and on every `needs-admin` row; omitted on every other row |

Text taken from a daemon's log or arguments is redacted before it reaches any field: no join token,
bootstrap token or URL password appears in either shape.

## Alerts

Every row that needs attention carries an `alert` object, in the full report, in the daemons probe
and in `k3sm alerts`. A row needs attention when its `severity` is `warn`, `fail` or `unknown`, or its
`state` is `needs-admin` (whose severity is `skip`: nothing is known to be wrong, but only an
administrator can say so). A row that is `ok`, or `skip` for any other reason, has no `alert`. The
row's `detail` and `remedy` stay as they were, so a reader that predates the alert loses nothing.

```json
"alert": {
  "cause": "The control-plane daemon is loaded in launchd but not running, so the cluster's control plane is not serving.",
  "evidence": [ "io.k3sm.server is loaded but not running", "label: io.k3sm.server", "last-exit: 1" ],
  "fix": [
    { "step": "Restart the daemon", "command": "sudo launchctl kickstart -k system/io.k3sm.server", "needsAdmin": true, "confirm": false }
  ],
  "docs": "troubleshooting.md#a-k3sm-daemon-is-not-running",
  "since": "2026-10-01T09:28:12Z"
}
```

| field | type | notes |
|---|---|---|
| `cause` | string | one sentence: what is wrong, in plain words; for a person, do not parse it |
| `evidence` | array of strings | the facts the check saw: the row's `detail` first, then the ones that bear on it (the quoted log line, the last exit, the file read, the counts); every entry is redacted (tokens, bearer credentials, PEM blocks, kubeconfig keys and passwords are masked) |
| `fix` | array of steps | the steps that repair the row, in order; never empty |
| `fix[].step` | string | what the step does, in a sentence |
| `fix[].command` | string | the shell command that does it, ready to run as written; omitted for a step done by hand, including any step whose command would need a name filled in or would name a cluster object whose name is not a valid Kubernetes name |
| `fix[].needsAdmin` | boolean | `true` when the step needs an administrator: its command runs `sudo` anywhere, pipes a download into a shell, or runs the install script |
| `fix[].confirm` | boolean | `true` when the step destroys state or relaxes trust, so a person should confirm it before it runs: removing files, force-deleting a pod, the out-of-service taint, minting a join token, an etcd cluster reset, clearing the crash-loop breaker, a download piped into a shell |
| `docs` | string | the page and anchor that covers the failure, relative to the `docs/user/` directory of the k3sm repository (`troubleshooting.md#...` is `docs/user/troubleshooting.md`) |
| `since` | string | when the condition began, RFC 3339 in UTC; omitted when it is not known |

`needsAdmin: false` does not mean a step is safe to run unattended. It says only that the step does
not need an administrator. A tool that runs fix steps for a person should ask before any step whose
`confirm` is `true`, and should show every command before it runs.

`evidence` is diagnostic. It can name local paths, the user name in them, node and pod names and
addresses. Review it before you share it outside your own machines.

### `k3sm alerts`

`k3sm alerts` runs the same checks as `k3sm status`, no more, and prints only the rows that need
attention with their alerts. It is the one call a tool or a model makes to ask "what is wrong here,
and how do I fix it". Its exit code is the verdict, exactly as `k3sm status`'s is.

```json
{
  "schemaVersion": 1,
  "verdict": "degraded",
  "role": "server",
  "summary": "dns: the resolver at 10.43.0.10 did not answer over UDP in 3 s",
  "node": "my-mac",
  "alerts": [ { "name": "dns", "state": "down", "severity": "warn", "detail": "the resolver at 10.43.0.10 did not answer over UDP in 3 s", "remedy": "...", "alert": { "cause": "..." } } ],
  "version": { "version": "v0.1.7", "kubeVersion": "v1.36.2" },
  "timestamp": "2026-10-01T09:30:00Z"
}
```

| field | type | notes |
|---|---|---|
| `schemaVersion` | number | `1` |
| `verdict` | string | the full report's verdict; see [Shared enums](#shared-enums) |
| `role` | string | `server` or `agent` |
| `summary` | string | the full report's summary; do not parse it |
| `node` | string | the Kubernetes node this Mac runs as when the report could tell, otherwise this Mac's short host name; omitted when neither is known |
| `alerts` | array of rows | the rows that carry an `alert`, in the full report's order, each in the [Rows](#rows) shape; an empty array (never `null`) when nothing needs attention |
| `version` | object | the build that produced the report, as in the full report |
| `timestamp` | string | RFC 3339 |

Without `-o json`, `k3sm alerts` prints the same content for a person: the verdict line, then each
row with its cause, evidence, numbered fix steps (a step that needs an administrator is marked) and
documentation page.
