# Stopping and Starting k3sm

`k3sm stop` shuts k3sm down on a Mac completely and keeps it down across reboots. `k3sm start`
brings it back. Use them for a maintenance window, to free the Mac for other work, or to take a
node out of a cluster without uninstalling it. All three verbs need root.

| Command | What it does |
|---|---|
| `sudo k3sm stop` | Stops every k3sm daemon, pod and network change on this Mac, and records the stop. The node stays stopped until you start it. |
| `sudo k3sm start` | Undoes a stop: brings the network helper and the node daemon back and clears the record. On a node that is already running it does nothing. |
| `sudo k3sm restart` | Restarts the k3sm daemons. Pods keep running. On a stopped node it refuses; add `--start` to start the node instead. |

Each verb takes `--reason TEXT`, which is recorded in the stop record and in the logs.

## What a Stop Does

In order:

1. Writes the stop record. If it cannot be written, nothing else happens.
2. Cordons the Node and annotates it `k3sm.io/stopped-by-user`. This is best effort and bounded
   at 15 seconds, so a stop still completes when the cluster is unreachable.
3. Disables and stops the node daemon.
4. Stops every pod: `SIGTERM`, ten seconds of grace, then `SIGKILL`. Linux VM helpers are stopped
   too.
5. Removes the WireGuard mesh.
6. Removes the addresses k3sm added to `lo0` and to the interconnect, and the pf anchor.
7. Disables and stops the network helper (`io.k3sm.netd`).
8. Marks the stop complete.

The LaunchDaemon plists stay installed, and the node identity is kept. Your cluster data is not
touched.

Pods that use a local-path volume are pinned to this node (see [Storage](storage.md)), so they stay
down until you start it. Nothing reschedules them elsewhere.

## Server and Worker

On a server, the node daemon is the control plane. Stopping it halts the cluster's control plane,
and every joined worker loses the apiserver until `sudo k3sm start` runs on the server. The stop
counts the joined workers first and prints a warning with the number. It never asks for
confirmation, so a script can run it unattended.

On a worker, a stop affects only that Mac. The control plane keeps running and sees the Node as
cordoned. A worker uses its own node credential for the cordon.

`k3sm start` removes the annotation and uncordons the Node, but only when the stop did the cordon.
A Node you had already cordoned for another reason stays cordoned.

## A Stop Survives Reboot

The stop disables the daemons in launchd and writes a record at
`/Library/Preferences/io.k3sm.stop.json`. A reboot does not bring the node back. Only
`sudo k3sm start` does.

The record also governs the other commands:

- `sudo k3sm install`, including an install that upgrades k3sm, updates the node and leaves it
  stopped. Pass `--start` to start it as part of the install.
- `sudo k3sm restart` refuses, unless you pass `--start`.
- `sudo k3sm uninstall` enables the daemons again and removes the record.

## Seeing a Stop

`k3sm status` prints a line above the rows while a stop is recorded:

```text
stopped by user: maintenance window, 2h14m0s ago
```

`k3sm status -o json` carries the same facts in the `stoppedBy` object (`actor`, `reason`, `at`,
`phase`). The field is documented in [Status JSON](status-json.md#stopped-by). A stopped Mac still
reports the verdict `stopped`; `stoppedBy` only says that someone asked for it.

## A Stop That Left Something Behind

If a stop cannot finish a step, it carries on with the rest, keeps the record in the `stopping`
phase, and exits with a code from 33 to 95. The code is 32 plus one bit for each thing left:

| Bit | Left behind |
|---|---|
| 1 | the node daemon |
| 2 | pods, VM helpers or control-plane processes |
| 4 | the mesh |
| 8 | `lo0`, interconnect or pf state |
| 16 | the network helper |
| 32 | the stop record |

The error message names every leftover and the reason. Run `sudo k3sm stop` again: it finishes an
interrupted stop. A stop that is already complete does nothing and exits 0. `sudo k3sm start` also
cleans up after an interrupted stop before it starts the daemons.

Other exit codes: 1 for a refusal or failure before anything was stopped, 2 for a usage error, and
3 when the command was not run as root (nothing was done).

## Time Bound

A server stop takes at most 150 seconds: the cordon (15), the node daemon's unload (75), the mesh
removal (15), pod grace (10), VM helpers (5) and the network helper (30). A worker's stop is never
longer. The command is cut off 30 seconds after that bound, or by `SIGINT`, `SIGTERM` or `SIGHUP`,
and then exits naming what it left. Re-running it converges.

`k3sm start` is cut off after about eight minutes, or by the same signals. The stop record stays
until the daemons are up, so a start that fails leaves the node reported as stopped, and running
`sudo k3sm start` again is safe.

## Starting a Node an Older k3sm Does Not Know About

Releases before `k3sm stop` do not read the stop record, and they have no `start` verb. If you
stop a node with a newer k3sm and then install an older release over it, the older install starts
the node again, because it always re-enables and starts the k3sm services. It does not clear the
record, so `k3sm status` from a newer binary would still report the node as stopped while it runs.
Run `sudo k3sm start` with the newer `k3sm` before you install the older release, so the record is
cleared first.

## Next

- [Install](install.md) covers `k3sm install` and `k3sm uninstall`.
- [Upgrade](upgrade.md) covers how an upgrade restarts the daemons.
- [Multi-node clusters](multi-node.md) covers joining and removing workers.
- [Troubleshooting](troubleshooting.md) covers a node that will not come back.
