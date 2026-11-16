# Host shares design

Status: implemented on two stacked changes (the root-owned allowlist, then delegation). The user
guide is [Host Shares for Native Pods](../user/storage.md#host-shares-for-native-pods).

## Problem

A native Pod is a macOS process under a Seatbelt profile, with no mount namespace. A `hostPath`
volume cannot be bound to a new path inside it. Workloads that work on a host tree in place (a
coding agent in a repository, a build that talks to a host socket) need a way to reach that tree at
its own path, and the node must decide which trees, never the Pod spec.

The first change made that decision root's alone: a root-owned allowlist, written with
`sudo k3sm share add`. That puts root on the path of every project a user onboards, although the
trees involved are the user's own. Delegation removes it: root grants a user a prefix once, and the
user then adds and removes shares under it without root.

## Scope

- The allowlist, its file format and its refusal rules.
- Enforcement in the node daemon and in runtimed, from the same files, on every create.
- Delegation: the root-owned record, the user's own file, and the checks that bind one to the other.
- The permissions `k3sm share` sets on a shared tree.

Out of scope: per-Pod identities (every native Pod runs as `_k3sm`), revoking a share from a Pod
that is already running, and `vm` Pods, which refuse `hostPath`.

## Threat model

One node is one trust domain for Pods: every native Pod runs as the same service user, `_k3sm`, the
same user the node daemon and runtimed run as. A Pod can reach runtimed's socket. So nothing a Pod
spec or a runtime request says can carry permission, and nothing `_k3sm` can write can be trusted.

The parties:

- **Root** (the node admin) is trusted. It writes the node file and the delegations in it.
- **A delegated user** is trusted with what they own under their prefix, and nothing else. Any
  process running as that user can add shares under the prefix; delegation means the user, not the
  admin, decides which of their own trees every Pod can reach.
- **A Pod** is untrusted. It runs as `_k3sm`, it can write inside its read-write shares, and it can
  send arbitrary requests to runtimed.
- **Another local user** is untrusted with respect to the delegated user's trees.

What must hold:

1. A Pod cannot widen what any Pod reaches: it can write neither the node file nor any user file,
   and it can never be a delegated user.
2. A delegated user cannot share a path outside their prefix, nor a path they do not own, nor
   anything the general rules refuse, however they edit their own file.
3. Removing a delegation drops every share made under it at the next create.
4. Setting permissions for a share never extends `_k3sm`'s file access beyond the shared tree.

What is not protected: a Pod that is already running keeps its profile until it is recreated; a
read-write share of a repository lets a Pod plant code (git hooks, build scripts) the owner may
later run; and hard links (next paragraph).

**Hard links.** Seatbelt matches the path used to reach a file, so a hard link inside a share
reaches its file wherever it lives, and `link(2)` does not require owning the source. A Pod cannot
make such a link (Seatbelt checks the source path), but the share's owner can, for any file in a
directory they can search. Every file `_k3sm`'s own permission bits let it read or write is then
open to every Pod that mounts the share. The install therefore keeps the data root's stores
(`blobs`, `guest-artifacts`, `pods`, `storage`, `snapshots`, `unpacked`, and the service user's
`.kube`) at mode 0700: every reader of those trees runs as `_k3sm` or as root, so no group or other
bit is an access path. Earlier installs left them 0750 with group `staff`, which every login user
is in; the next install or node-daemon start re-applies the mode.

A private primary group for `_k3sm` was considered and rejected: the group bit would have no member
and no reader, and it would need a directory-service migration, a run-time group id and an
ordering for purge. What is still linkable is listed under residual risks.

## Decisions

### The node file

`/Library/k3sm.host-shares`, one `<rw|ro|socket> <absolute path>` per line. It is read with
`O_NOFOLLOW` and trusted only as a regular file owned by root and writable by root alone; a missing
file shares nothing. Paths are ASCII, absolute and clean. Refused: system and k3sm trees, `/var`,
`/Users`, a whole home, a dot directory or `Library` under a home, and the delegation tree below.
Every comparison folds ASCII case, the way APFS and Seatbelt compare paths.

A Pod may mount a share only at its own path (`mountPath == hostPath.path`, no `subPath`), and only
when the path resolves to itself. The most specific entry decides.

### Delegation record

A delegation is a line in the node file:

```
delegate uid=501 user=dev modes=rw,ro,socket /Users/dev/Code
```

The uid is what is checked; the name is for display. A delegation is refused for a uid below 500
(every system and service account on macOS, `_k3sm` among them), for a prefix the general rules
refuse as an rw share (so never a whole home or `/Users`), and, at `delegate` time, for a prefix not
owned by that uid. The enforcing daemon additionally ignores a delegation to its own uid, whatever
the file says.

### Where a delegated user's entries live

`/Library/k3sm.host-shares.d/<uid>/host-shares`. The parent `.d` is root-owned and writable by root
alone; `<uid>` is created by `delegate`, owned by the user, mode 0755. The user can replace their
file atomically (temp file and rename in their own directory) but can neither remove their
directory nor create one for another uid. `_k3sm` can read the file but not write it.

Alternatives considered:

- **A file under the user's `~/Library/Application Support`.** Rejected: the daemons, which run as
  `_k3sm`, would need search and read access into the user's `Library`, which holds keychains and
  application state, and a share rule refuses that tree for good reason.
- **A local API on the node daemon that checks the caller's uid with peer credentials and writes
  the entry itself.** Rejected: the daemon runs as `_k3sm`, the user every Pod shares, so anything
  it writes is writable by a Pod in principle, and the store would need a second trust root. It
  also adds a socket and a daemon dependency to a command that today works with the node stopped.

The file is never trusted on its own, so where it lives decides only who can write it, not what it
can admit.

### Re-validation at enforcement

`hostshare.LoadEffective`, called by the node daemon before the RPC and by runtimed when it
compiles the Pod's profile, reads the node file, then for each delegated uid reads that uid's file
(each of `.d`, `<uid>` and the file checked for type, owner and mode, the file opened with
`O_NOFOLLOW`) and admits a line only if a delegation of that uid passes `CheckDelegated`:

- the line passes the general rules and the delegation allows its mode;
- its path is the prefix or under it (components, case folded);
- the path resolves to itself (no symlink anywhere);
- each component from the prefix down is not a symlink and is owned by the delegated uid, and the
  first one is the same directory (device and inode) as the recorded prefix, so a differently cased
  spelling on a case-sensitive volume cannot name a sibling;
- the path is a directory, or a socket for a socket entry.

- the path is on a case-insensitive volume. Seatbelt matches granted paths without regard to case
  even on a case-sensitive volume, where a grant of `/V/a` would also reach a sibling `/V/A`
  someone else may own, so a share or prefix there is refused (this applies to root's entries
  too, in `Authorize`).

A user file holds at most 64 lines, because each costs the node a walk of its path on every
create that mounts a `hostPath`. A line that fails, or a whole user file that fails its checks, is dropped, logged at Warn by
runtimed, and shown by `k3sm share list`; it never fails the node file. The same check runs in
`k3sm share add` before the user's file is written, so a refusal is reported at the command.

`CheckDelegated` runs at create, and the profile names paths, so a component the user replaces with
a symlink afterwards reaches nothing: Seatbelt resolves the link and matches the real path against
the granted literal. A delegated entry more specific than a root entry decides, as any more specific
entry does; it can only concern a tree the delegated user owns.

Revocation is the node file: removing the delegation line removes the only record that admits any
line of the user's file. `undelegate` also removes the user's directory and takes back the
permissions their shares set.

### Permissions

The Seatbelt profile is the boundary; file permissions are the other half, because `_k3sm` is not the
owner. `k3sm share add` sets them, as the owner (or as root for a root share), through
`internal/hostacl`, which uses acl(3) on descriptors opened with `O_NOFOLLOW`:

- read-write: an inheritable allow entry for `_k3sm` and the same for the owner, on the directory
  and every directory and file under it the owner owns;
- read-only: a read entry for `_k3sm`;
- socket: read and write (connect) for `_k3sm` on the socket;
- search for `_k3sm` on each parent directory the owner owns that `_k3sm` cannot already pass.

The walk skips symlinks, mount points (it never leaves the root's device), regular files with more
than one link (an entry there would also reach
their names outside the share) and anything the owner does not own. `chmod -R +a` was rejected
because it follows symlinks inside the tree it walks, with or without `-P`: a symlink a Pod left in
a read-write share would carry the entry to its target. `remove` and `undelegate` take back the
`_k3sm` entries, including inherited ones, unless a remaining share still covers the path, and the
search entries no remaining share needs. A stale entry reaches nothing a Pod's profile does not
grant.

## Residual risks

- A Pod that is running keeps a share after it is removed, until the Pod is recreated.
- The Pod fields in runtimed's `host share granted` log line come from the request; the path, mode,
  entry and delegated uid are the node's own decision.
- A hard link that already exists inside a share reaches its target.
- Files a login user can still search to: the world-readable status records (`status/`, which
  consumers may use only to refuse or delay an action), the artifact views under the 0711
  `artifacts/` root (clones of image blobs, so a rewrite reaches the Pods that mount that view, not
  the store), `runtimed.lock` in the data root, and the node logs, which admin users can read. A
  user who links one of these into a read-write share lets a Pod rewrite it.
- A hard link made before an install closed the stores survives the mode change, and installing a
  build older than that change reopens them.
- A socket cannot be opened, so its entry is set by path. Run as root, a path through directories
  the socket's owner controls could be raced to another file, so root never sets it: `sudo k3sm
  share add --socket` prints the `chmod +a` for the owner instead. Run as the owner, a race can
  only reach the owner's own files.
- The file-safety checks read owner and mode bits, not ACLs. A user who puts a write ACL for
  another group on their own list file lets that group (which may include `_k3sm`) edit it in
  place; every edited line still has to pass the delegation's checks.
- Seatbelt checks a shared socket against the path it was bound to: a socket renamed after
  `bind(2)` does not connect through the share.
