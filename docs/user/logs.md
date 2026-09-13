# Container logs

`kubectl logs` on a k3sm node reads the same files, in the same format, with the same options and
the same rotation policy a kubelet uses. If you already know where container logs live on a
Kubernetes node, you know where they live here.

## Where they live

Each container instance writes one file:

```
/var/log/pods/<namespace>_<pod>_<uid>/<container>/<restartCount>.log
```

`restartCount` starts at `0` and goes up each time the container restarts, so a Pod that has
crashed twice has `0.log`, `1.log` and `2.log` in its container directory.

A flat directory of symlinks points into that tree, one per container instance:

```
/var/log/containers/<pod>_<namespace>_<container>-<containerID>.log
```

This is the directory host-level log tools glob. It exists so a tool does not have to walk the pod
tree, and it is created after a container starts, once its file exists.

Both paths are the upstream ones. Nothing about them is k3sm-specific.

## The file format

Every line is one CRI log line:

```
2026-09-13T10:15:04.132991000Z stdout F the container printed this
2026-09-13T10:15:04.133410000Z stderr F and this on stderr
```

Four fields: an RFC 3339 timestamp in UTC with nanosecond precision, the stream (`stdout` or
`stderr`), a tag, and the content. The tag is `F` for a complete line and `P` for a fragment of a
longer one. A line larger than 16 KiB is split into `P` fragments ending with an `F`, and
`kubectl logs` joins them back into one line with one timestamp. Reading the file directly, you see
the fragments.

## Reading them

`kubectl logs` is the normal way, and every option behaves as it does on a kubelet:

```sh
kubectl logs mypod                      # the whole current file
kubectl logs mypod --tail 20            # the last 20 lines of the file
kubectl logs mypod --timestamps         # each line prefixed with its timestamp
kubectl logs mypod --since 5m           # lines at or after a point in time
kubectl logs mypod --limit-bytes 4096   # at most this many bytes, cut mid-line
kubectl logs mypod -f                   # follow, until the container exits
kubectl logs mypod --previous           # the instance before the current one
kubectl logs mypod -c init0             # a named container, including init containers
```

`--tail` counts lines in the file, so a line split into `P` fragments counts once per fragment.
`--since` keeps a line stamped exactly at the given time. `--limit-bytes` counts the bytes actually
written out, including the `--timestamps` prefix, and cuts wherever the budget runs out, which can
be in the middle of a line or of a multi-byte character. `-f` ends when the container exits, after
one final read that picks up whatever it printed on the way out.

`--previous` reads the previous instance's file. k3sm keeps exactly one previous instance per
container, which is the kubelet default, so `--previous` works after one restart and reports
`previous terminated container "c" in pod "p" not found` once the older files have been collected.

## Rotation

A container's current file is rotated when it reaches a size limit. The rotated file is renamed
with a timestamp suffix, the runtime opens a fresh file at the original path, and older rotated
files are compressed with gzip:

```
0.log                      the current file
0.log.20260913-101504      the file just rotated, left uncompressed
0.log.20260913-093000.gz   older, compressed
```

A container keeps five files in total by default: the current one, the one just rotated, and three
compressed. Once that is reached, the oldest is deleted on each rotation, so a single container's
logs are bounded at roughly five times the size limit.

`kubectl logs` reads **only the current file**. A rotation you just missed is on disk but not in the
`kubectl logs` output, which is upstream's behavior and upstream's limitation. Read the rotated
files directly, or ship them off the node, if you need more than the current file holds.

## Configuration

Five flags on `k3sm server`, `k3sm agent` and `k3sm node`. The names and the defaults are the
kubelet's KubeletConfiguration fields of the same name, and k3s sets none of them, so these are the
defaults a k3s user already has:

| flag | default | what it does |
|---|---|---|
| `--pod-logs-dir` | `/var/log/pods` | the root of the log tree |
| `--container-log-max-size` | `10Mi` | size at which a file is rotated; a negative value turns rotation off |
| `--container-log-max-files` | `5` | total files kept per container, counting the current one; must be greater than 1 |
| `--container-log-max-workers` | `1` | workers performing rotation |
| `--container-log-monitor-interval` | `10s` | how often file sizes are checked |

`sudo k3sm install` creates `/var/log/pods` and `/var/log/containers`. A node refuses to start when
the directory is missing or it cannot write there, and says so, rather than running Pods that have
nowhere to write.

`k3sm dev` puts each instance's logs under that instance's own runtime root instead of the shared
tree, so two dev instances never mix their output and `k3sm dev down` takes the logs with it.

## Permissions

The tree is `0700` directories and `0600` files, owned by the `_k3sm` service user. Upstream's
`/var/log/pods` is root-owned, which on Linux means root reads it and nobody else does; on a Mac the
service user's primary group is `staff`, the default group of every ordinary account, so a mode
copied across verbatim would let any local user read every Pod's output. `0700` is the equivalent of
upstream's posture here.

So there are two ways to read a log: `kubectl logs`, which the node serves, and `sudo` on the node.

```sh
sudo ls /var/log/pods/default_myapp_*/myapp/
sudo cat /var/log/pods/default_myapp_*/myapp/0.log
```

## Shipping logs off the node

A log shipper on k3sm is a **host-level tool**, run as root, reading `/var/log/containers`. Run it
under launchd, or however you run host agents, and point it at that directory. Everything it needs
is there: the pod, namespace and container names are in each symlink's filename, and the content is
the standard CRI format every shipper already parses.

An **in-cluster** shipper, the DaemonSet that mounts `/var/log` as a `hostPath` and is the usual
pattern on Linux, is not possible. Native Pods have no `hostPath` volumes at all: a native Pod is a
Darwin process under a Seatbelt profile, and that profile denies the log tree along with the rest of
the host filesystem, so a Pod cannot read another Pod's output. That denial is the reason the
in-cluster pattern does not work, and it is the same reason the host-level one is the right shape
here.

Pods running under `runtimeClassName: vm` are no different. Their output is relayed out of the guest
and written into the same files by the same writer, so they are read the same way and shipped the
same way.

## Related

- [Troubleshooting](troubleshooting.md) covers the node's own daemon logs, which are a different
  tree (`/var/log/k3sm`).
- [Linux images](vm-runtimeclass.md) covers `runtimeClassName: vm`.
- [Limitations](limitations.md) lists the gaps across the whole system.
