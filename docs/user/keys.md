# Keys

`k3sm keys` keeps key material on a k3sm server: a service's signing key, a third-party API
token, an HMAC key two of your Pods share. Each entry has a name and a history of versions, and
every version is encrypted at rest. You can list the entries, rotate one to a new value, roll it
back, and delete it, all without the value ever appearing on a command line.

Every verb runs as root, on the server that holds the keystore. Never delegate the `keys` verbs
through `sudoers`: `put --in` and `show --reveal` read any file root can read, so a user allowed
to run them can read any root-readable file.

## What It Protects, and What It Does Not

The keystore protects values on disk. Each version is sealed with AES-256-GCM under a master key
that k3sm creates for you, so a copy of the entries alone opens nothing. A file changed or moved
by hand is refused rather than read as a different value, and an older copy of an entry put back
over a newer one is refused too (see [Restoring an older keystore/](#restoring-an-older-keystore)).

It does not protect a value from root on the Mac, and it does not keep one native Pod from
another: every native Pod runs as the same service user, `_k3sm`
(see [Concepts](concepts.md)). Treat it as an encrypted, versioned home for the value, not as a
wall between workloads.

## Names

Every name says which scope it belongs to. This build has one scope, `system`, the server's own
store:

```
system/signer-key
system/payments.api-token
```

The part after `system/` is 1 to 253 bytes of dot-separated labels of lowercase letters, digits
and `-`, each starting and ending with a letter or digit, the same rule as a Kubernetes object
name.

- A name without a scope, such as `signer-key`, is refused, and the message shows the
  `system/<name>` form to use. It does not repeat what you typed, in case that was a value.
- A `user/...` name is refused with "user scopes are not supported by this build".
- A `system/` name that breaks the rule above is refused with "the entry name is not valid
  (DNS-1123 subdomain); it is not echoed". An invalid flag value is refused the same way: the
  message names the flag, never the value. That holds for the path flags too (`--in`,
  `--key-in`, `--key-out`, `--work-dir`): their errors and warnings name the flag and the reason,
  such as "open --in: no such file or directory (the path is not echoed)", never the path. An
  error from the keystore itself shows the paths under `--work-dir` as `<work-dir>`,
  `<master-dir>` and `<data-root>`.

## The Verbs

| Command | What it does |
|---|---|
| `sudo k3sm keys put system/NAME --in FILE` | Creates the entry at version 1. `--kind ed25519` stores an Ed25519 private key (a 32-byte seed or the 64-byte expanded key) and checks it; the default kind is `opaque`, any bytes. The first `put` on a server creates the master key. |
| `sudo k3sm keys list` | One line per entry: name, kind, current version, when it was created (UTC), fingerprint and status. Status is `ok`, or `corrupt` with the reason. `-o json` prints the same as JSON. Exits 1 if any entry is not `ok`, after listing every entry. |
| `sudo k3sm keys show system/NAME` | Prints the entry's metadata, never its value. `--version N` shows an older version. |
| `sudo k3sm keys show system/NAME --reveal` | Prints the stored value and nothing else: no label, no newline added. To a terminal it also needs `--yes`, so a value does not land on screen and in scrollback by accident. It writes the raw bytes, so a value holding terminal escape sequences is interpreted by the terminal. |
| `sudo k3sm keys rotate system/NAME --in FILE` | Stores a new version and makes it current. Earlier versions are kept. |
| `sudo k3sm keys rotate system/NAME --from-version N` | Stores a copy of version N as a new version. The copy is made inside k3sm and the value is never printed. This is the rollback. |
| `sudo k3sm keys rm system/NAME --yes` | Deletes the entry and every version. This cannot be undone, so it needs `--yes`. It also removes an entry `list` reports as corrupt. |
| `sudo k3sm keys adopt system/NAME` | Finishes a rotation that was interrupted: shows the current version beside the newer one a crash left behind, and makes the newer one current once you confirm (see [Finishing an interrupted rotation](#finishing-an-interrupted-rotation)). |
| `sudo k3sm keys rewrap --key-out FILE` | Re-seals every entry under a new master key (see [Changing the master key](#changing-the-master-key)). |
| `sudo k3sm keys deliver system/NAME --namespace NS` | Declares that the server delivers the entry's current version into the cluster as a Secret (see [Delivering an entry as a Secret](#delivering-an-entry-as-a-secret)). |
| `sudo k3sm keys undeliver system/NAME --namespace NS [--secret S]` | Withdraws that declaration. The Secret stays. |
| `sudo k3sm keys floor --rebuild` | Rebuilds the user-scope floor log, `/var/lib/k3sm/keystore-logs/floor/keystore-user-floor.log`, after a restore. It keeps every revocation and sequence of the old log that still reads, however large the log has grown, and adds each user scope's entries. If it dropped anything it lists the counts by class (lines that did not read, over-long lines, lines of a scope on disk past its user's share, lines of absent scopes past their share or the floor's key limit, lines of scopes root removed) and exits 4: the new floor is in place, read the list. It exits 0 only when nothing was dropped, and 1 when it refused, changing nothing. If any user scope does not open, it refuses, names the scope and changes nothing (see [When a user scope blocks the rebuild](#when-a-user-scope-blocks-the-rebuild)). If it stopped part-way, run it again: if the first run had already put the new floor in place, the second prints the first run's report, saying `an earlier run committed; this run did not rebuild`, and exits the same way, 0 or 4. A run that failed after the new floor was in place still prints its report and exits 4, never 1. If `audit --rotate` or `sudo k3sm install` runs first, it prints that run's report to stderr as `an earlier floor --rebuild committed and was not reported: …` (`… committed and dropped N lines, …` when it dropped any) and records it in the audit log; when that run dropped lines, `audit --rotate` exits 4 even if its own work was clean; `install` keeps its own exit code, and its line adds `install does not exit 4 for it: the earlier run's drop counts are kept in keystore-maintenance-runs in the data root, which k3sm doctor reads` (the file below). If install could not record them, it says why and adds `install does not exit 4 for it: the earlier run's drop counts could not be recorded, so they are in this line only (the audit log holds a committed line for that run, without them): copy this line down`: copy it down, as the counts are nowhere else. While a run's marker stands, `k3sm doctor` warns, naming the verb to run again. A run that dropped anything (or an `audit --rotate`, rerun or `install` that reports such a run) also records its drop counts by class, with its run id, time and the new log's inode, in `/var/lib/k3sm/keystore-maintenance-runs`, which keeps the newest 64 such runs after the run's own report is gone; `k3sm doctor` warns `keystore maintenance: N lossy run(s), latest <time> dropped <total> line(s)` while it holds any. If that file is damaged, the run still finishes, exits 4 and says the counts were not recorded, and doctor warns: move the file aside as root and keep it. |
| `sudo k3sm keys rm-scope user/UID --yes` | Removes a user scope and every entry in it. This cannot be undone. It refuses while the scope's delivery record names a delivery, so withdraw those deliveries first. It checks that record against the floor log: an older copy put back counts as damaged, and if the floor log cannot be read it removes the scope but exits 4, saying the deliveries are not confirmed. If that record is damaged or missing, it still removes the scope, says the record could not be read, so deliveries from this scope were not checked and any Secret it delivered stays until it is withdrawn, and exits 4. It records the removed scope in `/var/lib/k3sm/keystore-removed-scopes.json`, so a copy of the old scope directory put back never opens: the refusal names `sudo k3sm keys rm-scope user/UID --yes`, which removes the copy. A scope the user creates afresh opens normally. If that record is full, the scope is still removed, the verb says so and exits 4; its floor lines are then kept. If the scope directory has no `scope.key` and the record does not list the scope (an earlier `rm-scope` interrupted before it listed it, or tampering), the directory is removed but cannot be listed, so the verb says the scope was removed without being listed, and that a copy of its directory put back by the server's user opens again, held only to the scope's floor lines, which are kept, and exits 4. A `scope.key` with a second link or a mode wider than 0600 (which any local user can cause) whose key still opens under the master is listed and the scope removed; the verb notes that the key file's link count or mode was wrong and exits 4. A `scope.key` whose content does not read is handled like a missing one: the scope is removed without being listed, the verb says its key file could not be trusted, and that a copy of its directory put back by the server's user opens again, held only to the scope's floor lines, which are kept, and exits 4. Run `floor --rebuild` afterwards to free the scope's lines in the floor log. If the record itself is damaged or untrusted, no user scope opens and `rm-scope` and `floor --rebuild` refuse; the repair is root restoring `/var/lib/k3sm/keystore-removed-scopes.json` from a backup (root:wheel, mode 0644: the server's user must be able to read it). Scopes removed after that backup are then no longer listed, so a copy of their directories put back would open, though their floor lines are still kept. It exits 0 when the scope is removed and listed, 4 when it was removed but not listed, its delivery record could not be read, or its key file's link count or mode was wrong, or when it stopped part-way after it had already changed something (added the scope's key to the record, removed entries, or took or unlocked part of the tree; saving a record that already listed the scope again, unchanged, does not count), including when it listed the scope but could not confirm the record was saved to disk (it says the record lists the scope but its durability is unknown), or when it removed a directory at the scope's name but could not confirm it was the scope's (it says so), and 1 when it refused or stopped before changing anything. It says the scope is removed and listed (exit 0) only when the `scope.key` it read in the directory it removed is in the record. If the scope directory does not exist, it says it found it absent and exits 1, with nothing to repair. If the scope directory was already gone when it came to remove it, it says it found the scope absent rather than that it removed it: exit 4 when this run had added the scope's key to the record, 1 otherwise. When running it again can finish the removal, the message ends with `rerun sudo k3sm keys rm-scope user/UID --yes`; when running it again would stop the same way, it prints no rerun line (see below for the only other commands it prints). Running it again finishes any scope directory an interrupted run left root's, mode 0700. If it could not read the delivery record for a passing reason (it says nothing was changed), run it again. |
| `sudo k3sm keys audit --rotate [--discard-oldest]` | Moves the audit log, `/var/lib/k3sm/keystore-logs/audit/keystore-audit.log`, aside to `keystore-audit.log.1` in `/var/lib/k3sm/keystore-logs/audit/archives/` and starts a new one, empty but for one line per kind of count the server could not record: refusals, and revocations with no audit line (see [Refusals the server could not record](#refusals-the-server-could-not-record)). It exits 0 when done and 1 when it refused, changing nothing. The older archives move up one number, and four are kept, `.1` the newest to `.4` the oldest, each readable only by root, in a directory only root can open. While `.4` exists it refuses and changes nothing: export the archives first, as root (for example `sudo cp /var/lib/k3sm/keystore-logs/audit/archives/keystore-audit.log.* <destination>`), copying them off the Mac, then run it again with `--discard-oldest`, which deletes `.4` to make room. After a restore, run it to make the restored audit log append-only again. If it stopped part-way, run it again before any other maintenance verb: it does not rotate twice. |

These three maintenance verbs run while the server runs: you do not need to stop it first.
`floor --rebuild`, `audit --rotate` and `rm-scope` wait up to 30 seconds for the keystore lock. If
they stop with "a process running as the service user held the store lock", the server or one of
its processes is holding it and has not let go: stop the server with `sudo k3sm stop`, or stop
that process, then run the verb again. Nothing was changed.

Each log lives in its own directory: the floor log in `/var/lib/k3sm/keystore-logs/floor/` and
the audit log in `/var/lib/k3sm/keystore-logs/audit/`, with its archives in `archives/` there, which only root can open. While
`floor --rebuild` or `audit --rotate` runs, it builds the complete new log directory in
`/var/lib/k3sm/keystore-staging/`, which only root can open, and the file
`/var/lib/k3sm/keystore-maintenance` exists. It then exchanges the new directory with the old
one in a single step, so the log in `keystore-logs/` is always either the whole old log or the
whole new one. Both extra names are gone when the verb finishes.

If the verb stopped part-way (a crash, a power cut, an error it printed), the log in place is
still a complete log. Run the same verb again: `sudo k3sm keys floor --rebuild` or
`sudo k3sm keys audit --rotate`. It throws away whatever the first run left in
`keystore-staging/`. If the first run had already put its new log in place, the second run prints
the first run's report and exits as the first would have; otherwise it runs from the start.
Running the other verb in between does no harm to either log, but the first verb's next run then
starts from the beginning, so a second `audit --rotate` rotates again.

Lines that the server appends to a log while `floor --rebuild` or `audit --rotate` is reading it
wait for the verb and land in the new log. A line written to the old log by a process that does
not wait for the keystore lock, after the verb has read the log, is dropped with the old log.

### When the server refuses a log

The server refuses to start, and `doctor` names the problem, when a log is not what install
makes: missing, not append-only (after a restore, for example), owned by someone else, carrying
an extra flag or access list, or linked under a second name. What to run:

- a log that is missing: `sudo k3sm install`, which creates the log and its directory and
  leaves a good log alone;
- a log at a location that is not a supported layout (the top of `/var/lib/k3sm`, or directly
  in `keystore-logs/`): the logs belong under `keystore-logs/floor/` and
  `keystore-logs/audit/`; restore the data root from a backup;
- a floor log that is not append-only after a restore, or that has a second link:
  `sudo k3sm keys floor --rebuild`;
- an audit log that is not append-only after a restore, or that has a second link:
  `sudo k3sm keys audit --rotate`.

When the message names a verb, run that verb. Each of them replaces the log with a fresh file.

### Refusals the server could not record

The server writes a line to the audit log for each connection it refuses before the first
request. When it cannot (the log's share for refusals is spent, or the keystore was busy), it
counts the refusal instead, keeps the counts in `.preframe-dropped` in its keystore directory so
a restart does not lose them, and writes them with its next refusal line. The same file keeps
two more counts: the refusal lines of requests the server refused that it did not write
(past a user's limit of refusal lines a minute, or that user's share of the log, or, for a
request the store refused before it took its lock, the lock not had), which it writes as one
summary line with that user's next refusal; and the revocations (`rm`, `rotate`,
a delivery's withdrawal) that went ahead while the audit log took no appends, so they have no
audit line. While any are unwritten, the `keystore-logs` row in `k3sm doctor` warns
`N pre-frame refusal(s) not recorded for M uid(s)`,
`N post-frame refusal line(s), the socket's and the store's, not recorded for M uid(s)` and
`N committed keystore revocation(s) have no audit line`, each when its count is not zero, and
names `sudo k3sm keys audit --rotate`, which writes one line per kind of count into the new
audit log and clears the counts. If the file cannot be read, the row warns that
`the persisted pre-frame refusal count is unreadable`: the server keeps counting in memory and
does not overwrite the file. Run `doctor` with `sudo` to see this part of the row; as another
user it is left out.

### A log past its hard cap

Past its hard cap a log takes only revocations (`rm`, `rotate`, a delivery's withdrawal), each
user's bounded by that user's own budgets, and every other user-scope change is refused. The
`keystore-logs` row in `k3sm doctor` then warns
`the audit log is N bytes, M bytes past its hard cap of H` (or the same for the user-scope floor
log) and names `sudo k3sm keys audit --rotate` for the audit log or
`sudo k3sm keys floor --rebuild` for the floor. At or below the hard cap it names no overshoot.

### The keystore user scope row in `k3sm doctor`

The server creates `/var/lib/k3sm/server/keystore/` when it starts, as its own user at mode 0700,
the way the first `put` would. So on a fresh install the user scope comes up once the server
has started, without a `sudo k3sm keys put` first. The master key is still created only by the
first root `put` (see the table above), so until then a user's `put` fails.

`doctor` runs in its own process and cannot ask the server whether the listener is serving, so
its `keystore-user-scope` row says only what it can check:

- `keystore user scope: start checks pass; a root-owned <mode> socket is at <path> (path facts
  only: whether the server is serving it is not checked)` (PASS):
  every check the server makes before it starts the listener passes, and the socket at the path
  is owned by root, in the daemon group, at the mode the server's LaunchDaemon plist names (the
  row prints it), in a directory owned by root:wheel that only root can write to. launchd
  creates the socket, as root, from the `Sockets` entry that `sudo k3sm install` writes into
  that plist, and hands it to the server. `doctor` looks at the path; it never connects, since
  the server refuses root and the service user.
- `keystore user scope: start checks pass, but no listening socket at <path>` (WARN): the
  checks pass but nothing, something other than a socket, a socket with another owner, group
  or mode, or a socket in a directory with another owner or mode is at the path. The remedy
  depends on the installed server plist:
  - without the `Sockets` entry (a plist written by an install from before the socket existed)
    it names `run sudo k3sm install (it rewrites the server plist and re-bootstraps the job)`;
    launchd reads that entry only when the job is bootstrapped, and a server whose plist lacks
    it is refused the socket (measured). The server logs one warning, `launchd activated no
    socket for this server`, and does not retry.
  - with the entry, launchd has no `keys` socket for this job: its loaded definition has no
    such entry, or a parent of the socket path is missing (measured with three missing
    levels); or the server has not started yet or is restarting. It names `run sudo k3sm
    install (it rewrites and reloads the server's definition); if the data root is on a volume
    that is not mounted, mount it first`. The server logs one warning, `launchd has no keys
    socket for this job`, and does not retry until it is restarted.
  The PASS line states path facts only. `doctor` cannot see inside the server, so it cannot
  tell whether the server is serving the socket. A socket stays at the path in two cases where
  nothing serves it: after the job is unloaded (`launchctl bootout` leaves `keys.sock`), and
  after the server refused the socket it was handed (a wrong descriptor or path, or one
  without `FD_CLOEXEC`); the server's log names that refusal.
- `keystore user scope: off (<reason>)` (WARN): a check fails, with the server's own reason.
  For a missing, wrong or unflagged log or socket directory it adds `run sudo k3sm install`;
  for `more than one server registered` it names the servers (up to 8, then how many more);
  for `the append-only logs cannot be opened (logs-unavailable)` it shows the error;
  for `the store directory is missing or refused` it shows why: before the server's first start
  there is no `/var/lib/k3sm/server/keystore/` yet, and the row says the server creates the store
  directory at start; once the server has started, the row passes. A directory that is there but
  not the server's user's at mode 0700 is refused, by the server and by `doctor`, and the server
  never repairs it: as root, make it the server's user's at 0700, or remove it if it holds
  nothing, and the server creates it again;
  `the service uid is in the login range` means the service user's uid is 501 or above, where
  login users' uids start, and the listener does not start until the service user is a system
  account below 501;
  for `the user scope's start step failed` it shows the store's error (the log bounds check
  the server runs before it serves).
- `keystore user scope: the server count cannot be read as this user` (WARN): run
  `sudo k3sm doctor`; this does not mean the user scope is off.

The server makes one check `doctor` does not repeat: before it serves the socket, it renders the
Pod profile its built-in runtime gives Pods on this node and checks that the profile denies Pods
the socket under this node's data root. If it does not, the user scope stays off for the life of
the server, with `this build's Pod profile does not deny the keystore socket`. The server logs
one warning naming the remedy, `install a k3sm built with a matching runtimed`, and keeps
running; reinstalling or restarting the same build does not change it.

### When a user scope blocks the rebuild

`floor --rebuild` refuses, changing nothing, when a user scope does not open, or when a scope has
filled the floor log with so many entries and deletions that the rebuild cannot keep them all.
It names the scope, `user/UID`. Remove that scope, then rebuild. `rm-scope` removes it even when its
`scope.key` cannot be trusted; it then exits 4, saying the scope was removed without being listed:

```sh
sudo k3sm keys rm-scope user/UID --yes
sudo k3sm keys floor --rebuild
```

`rm-scope` deletes the scope and every entry in it, and the user loses those values. It refuses
while the scope's delivery record names a delivery; withdraw those deliveries first. A scope
whose delivery record is damaged or missing is still removed, and `rm-scope` exits 4: it could
not check that scope's deliveries, so any Secret it delivered stays until it is withdrawn. A file in the scope locked with a user flag (`chflags uchg`, `uappnd` or
`uunlnk`) is unlocked and removed, whoever owns it, when it has one link, and even when it is a
FIFO, socket or device, which `rm-scope` unlocks without opening; the service user's own file is
unlocked even when it also has a name outside the scope. `rm-scope` unlocks up to 4096 entries
per run: if the scope holds more, it says so, and running it again unlocks up to 4096 more.
It stops at an entry with a system flag (only root sets one) and at a flagged entry with more
than one link that it does not unlock (another user's, or a FIFO, socket or device), naming the
entry, the flag and its owner, saying it left the flag, whether the scope is already listed as
removed, and that the leftover directory blocks a fresh scope for that uid; running it again
would stop at the same entry, so it offers no command. If a flag it unlocked is set again while
it runs, it stops and says to run it again once nothing sets the flag.
Before it touches anything in a directory of the scope, `rm-scope` makes the directory root's,
mode 0700, so nothing running as the server's user can add names there or move names in while it
works (on macOS a file carrying an ACL entry that allows its deletion can still be moved out). A
scope directory left root's, mode 0700, by an interrupted run is finished by running it again,
whatever it holds, since no open serves a root-owned directory. That run exits 0 only when the
directory carried no ACL and its `scope.key` was already listed before the run, which is what an
interrupted run leaves. Otherwise it still removes the directory (removing any ACL first, and
listing a `scope.key` that opens as this user's), but exits 4, saying it cannot confirm the
directory was the user's live scope, or that it removed it without listing it: the server's user
can move another uid's leftover onto the name, or, with an ACL entry, a root-owned directory from
elsewhere. A root-owned directory found at the name in place of the scope directory it checked is
removed with exit 4, saying the directory it checked was not at its name. A mode the server's user set on its scope directory, on the directory of user scopes
that holds it, or on `keystore/` itself, does not stop `rm-scope`: it checks who owns them, not
their mode. When the scope directory has no `scope.key`, or one it cannot trust, it removes only
the very directory it checked: another directory moved to the name meanwhile is refused and left
untouched. It exits 0 only when, beyond a listed key, the user-scope floor log shows no activity
of that user after the key was listed. If the user's server activity continued after the key
was listed (a newer scope), or the floor log cannot be read, it still removes what it found but
exits 4, saying it cannot confirm the user's current scope is the one removed, and that the
current scope may have been moved away from its name. A first removal can meet this too: when
the floor log cannot be read, or when a process of the server's user writes a line for that user
to the floor log while `rm-scope` runs (it can, without the keystore lock). Exit 4 then still
means the scope at the name is removed and listed; only the confirmation is missing, and running
it again finds the scope absent, so that confirmation cannot be had later. A run repeated after
the user made changes, or after a floor rebuild that kept a line of that user, meets it as well;
on a file system without birth time (any system other than macOS) every repeated run exits 4. It
also exits 4 when the floor log shows that the user's scope was created more than once since it
was last listed: another scope of that user may then be kept away from its name, and `rm-scope`
removed and listed only the one at the name. A floor rebuild between those creations erases
that evidence, so this check can miss it, and a forged line in the floor log only costs a
needless exit 4. It removes only the
scope directory it checked:
if another directory is at the scope's name by the time it removes it (one renamed there by the
server's user, for example), it stops, leaves that directory untouched, and says the directory
is not the scope it checked. The one exception is an empty directory renamed onto the name at
the very moment of the last step: that one can be removed, and `rm-scope` says another directory
was removed at the name. If the emptied scope directory was moved from its name before the
last step, it says so and does not report the scope removed; if it cannot tell whether the
directory it removed last was the scope's, it says it could not confirm the removal and exits 4. It does not go into a directory in
the scope that another user owns (one moved in from a shared directory, for example): it leaves
that directory and its contents in place and stops, saying who owns it. Each message names the
entry for you to read, not to paste, and offers no action by hand. The commands it prints are
exactly these: its own `sudo k3sm keys rm-scope user/UID --yes`, with the number of the scope you
named, only where running it again can finish the removal; `sudo k3sm keys floor --rebuild`
after a removal that exits 0; `sudo k3sm stop` when a process of the server's user held the
keystore lock; and, for a root-owned file in `/var/lib/k3sm` such as the removed-scopes record,
the repair that file's messages always give (`sudo chflags 0` on that file).

In short, `rm-scope` exits 0 when it removed the scope and confirmed its key is listed; 4 when
this run changed something, or the durability of the record is uncertain (it saved a record that
already listed the scope again, unchanged, and could not confirm that save reached the disk),
and the message says what is unconfirmed or where it stopped; and 1 when it refused, or stopped
before changing anything.
Exit 0 means the directory at the scope's name was removed and its key is listed, so no copy of
that scope opens again. It does not mean no other scope of that user exists. `rm-scope` can only
list a key it reads at the scope's name, so a scope the server's user moved away from its name
before `rm-scope` ran is not removed at all, also when earlier scopes of that user were removed:
if the name is left empty, `rm-scope` says it found the scope absent (exit 1); if a file or a
symlink is put there, it refuses (exit 1); if the server made a new scope in its place,
`rm-scope` removes and lists only the new one (exit 0, or exit 4 when the floor log shows the
scope was created twice). In each case the moved scope, put back, opens. Closing this needs a
change to the server, not to `rm-scope`, and is not done yet.
When the message ends with `rerun sudo k3sm keys rm-scope user/UID --yes`, running that continues
where it stopped. When it does not, running it again would meet the same state; the message
names what it found, for you to read.

`--work-dir DIR` points every verb at a server work dir other than the default
`/var/lib/k3sm/server`. The data root is its parent.

Exit codes: 0 done, 1 refused or failed, 2 usage error, 3 `rewrap` finished an earlier
interrupted rewrap instead of yours (run it again with a new key), 4 `put`, `rotate`, `rm` or
`floor merge` wrote the floor, but the floor dropped a recorded deletion to stay within its
limits, so a copy of that deleted entry put back is accepted. An `rm` that exits 4 and prints
`deleted` deleted the entry, even when it says its files were left behind; one that prints no
`deleted` found nothing to delete. `list` and `show` print such a drop as a warning and exit 0.
Delete entries you no longer use to make room. `floor --rebuild` also exits 4 when it dropped
lines or keys of the old floor; it lists the counts. 5 `floor merge` wrote the merge, but did not
rename `keystore-floor.json.pre-restore`: run it again to finish the restore. Exit 5 wins over 4,
and the report still lists every dropped deletion.

Exit 4 also means a `put`, `rotate` or `adopt` made its change and a step after it failed. The
new version is current, so do not run the command again without checking: `keys show` tells you
which version is current, and the next `keys` verb finishes what was left.

## Giving a Value

A value never comes from the command line. Anything there is visible to every local user through
`ps` and is saved in your shell history. `put` and `rotate` read the value from:

- `--in FILE`: a regular file. A symlink, FIFO or directory is refused. Keep the file owned by
  root and readable and writable by root only, and delete it once the value is stored. A file
  group or others can read or write, or that another user owns, draws a warning.
- `--in -`: standard input, which is also the default. The value must be piped in:

  ```
  issue-token-command | sudo k3sm keys put system/api-token --in -
  ```

  If standard input is a terminal, the verb refuses rather than wait for you to type the value,
  since typed text is echoed and kept in scrollback.

The value is stored byte for byte. Nothing is trimmed, so a trailing newline in the file is part of
the value. Values are capped at 64 KiB.

## Rolling Back

There is no verb that points an entry back at an old version. A rollback writes the old value
forward as a new version, so the version number only goes up:

```
sudo k3sm keys rotate system/signer-key --from-version 3
```

`show --reveal` piped into `rotate --in -` does the same thing, and the copy is byte-exact:

```
sudo k3sm keys show system/signer-key --version 3 --reveal | sudo k3sm keys rotate system/signer-key --in -
```

Use a pipe here, not `<( ... )`: `sudo` closes inherited file descriptors, so that path would not
open.

## Finishing an Interrupted Rotation

If a rotation stops after it wrote the new version but before it made that version current,
`keys show` and the other reads of the entry report a newer version than the current one and say
to inspect it with `k3sm keys adopt`. Until you deal with it, a retried
`rotate` is refused, so it cannot overwrite what the crash left.

```
sudo k3sm keys adopt system/signer-key
```

The command prints the name, then the current version and the newer one (the orphan), one after
the other. For each it shows the version number and kind, the fingerprint, the record digest, the
time sealed inside a token or OAuth pair (`issuedAt`) and the created time, which is not
authenticated. It never prints a value. If versions exist beyond the orphan, it lists them and
refuses to adopt.

Compare the two sides, then confirm. At a terminal it asks `make version N current? [y/N]`;
answer `y` or `yes`. Anywhere else, such as a script, pass `--yes`, or it changes nothing and
exits 2. Any other answer changes nothing and exits 1.

On confirmation the orphan becomes the current version. The version that was current stays in
the history, so you can still roll back to it (see [Rolling back](#rolling-back)). The exception
is an OAuth pair, which keeps only the previous current version beside the new one. Older ones
are removed.

For an OAuth pair, the orphan may hold the only valid refresh token, because the old one may
already be spent at the provider. Inspect it and adopt it. Do not delete its file.

## Changing the Master Key

`sudo k3sm keys rewrap --key-out FILE` creates a new master key and re-seals every entry under it.
k3sm never prints the key. Before it changes anything, it writes the new key to `FILE`, which must
not exist yet: it is created new, readable by root only (mode 0600), and an existing file or link
at that path is refused.

Name a file in a directory only root can write, such as a new `sudo mkdir -m 700` directory. The
verb refuses a directory that is not root's or that group or others can write. Keep the file out
of any synced folder (iCloud Drive, Dropbox and the like) and out of Time Machine's reach, since a
copy there outlives the rewrap.

`FILE` must be an absolute path; a relative one is refused with "give an absolute path".

Keep that file until `rewrap` reports success, then delete it. After a successful rewrap, `FILE`
is a second copy of the live master key: delete it, or move it to offline storage, and never keep
it beside a backup of the entries. If `rewrap` is refused before it
seals anything under the new key, it deletes the file itself and says nothing was changed. If it
is interrupted or fails partway, some entries may already be sealed under the new key, and that
file is the only copy of it. `rewrap` then keeps the file, says a resume may need it, and you
finish with the same key:

```
sudo k3sm keys rewrap --key-in FILE
```

If the failure came after the master key was already swapped to the new key, `rewrap` says "the
master swap completed but did not sync; this run's key file is now a copy of the live master: keep
it until a later rewrap succeeds, then delete it." The rewrap is done; keep `FILE` as that message
says.

`--key-in` is for that recovery only. It accepts the key the interrupted rewrap recorded, or one
that some entry is already sealed under, and refuses any other, so it never makes a key you made
yourself the master key.

If `rewrap` exits 3, it found an earlier rewrap that had been interrupted, finished that one with
its key, and stopped. Run `rewrap --key-out` again with a new file.

If `rewrap` instead fails while finishing that earlier rewrap, it says:

```
an earlier interrupted rewrap was advanced and did not finish; keep the earlier rewrap's key file; finish with: sudo k3sm keys rewrap --key-in <that earlier file>
```

If what failed was the last step of that earlier rewrap, after its master key was already
swapped in, it says instead:

```
the earlier rewrap's master swap completed but did not sync; run sudo k3sm keys rewrap --key-out FILE again; the earlier rewrap's key file is now a copy of the live master; delete it after this rewrap succeeds
```

That rewrap is done, and a new one retires its key. Until then the earlier rewrap's key file is a
second copy of the live master key: delete it once the new rewrap succeeds.

Otherwise, the earlier rewrap's key file is the one to finish with. `rewrap` keeps this run's `FILE` too;
it was never used, so delete it once the earlier rewrap is finished.

If `rewrap` refuses because `keystore/.user` exists, this build cannot re-seal what that path
holds. The message names the path. Nothing was changed.

After a rewrap, backups of the keystore taken before it no longer open (see below), and the
fingerprints of `opaque` entries change.

## Delivering an Entry as a Secret

A Pod reads a key the usual Kubernetes way, from a Secret. `deliver` tells the server which entry
goes into which Secret:

```
sudo k3sm keys deliver system/signer-key --namespace payments
sudo k3sm keys deliver system/signer-key --namespace payments --secret signer --data-key private.key
```

The server then keeps an `Opaque` Secret in that namespace holding the entry's current version.
The Secret is named after the entry, without `system/`, unless you pass `--secret`, and the
value is under the data key `value` unless you pass `--data-key`. An `ed25519` entry is
delivered as the stored 32-byte seed or 64-byte key, with no PEM wrapping. The entry must exist when you run `deliver`.

- **Rotation reaches the Secret.** After a `rotate`, the server updates the Secret within a
  minute. The Secret's `k3sm.io/keystore-version` annotation says which version it holds.
- **Edits are undone.** The server compares the Secret's data with the stored value, so a hand
  edit is put back within a minute, and logged without the value.
- **An immutable Secret is re-created.** If someone sets `immutable: true` on a Secret the server
  created, the server cannot update its data. After a rotation, or if its data drifted from the
  stored value, the server deletes that Secret, only if its UID is still the recorded one,
  creates it again with the current value, and logs both steps. If only its label or
  annotations changed, the server puts them back without deleting it.
- **Only its own Secrets.** The server labels each Secret it creates
  `k3sm.io/keystore-delivery: <entry>`, and records the Secret's UID in
  `/var/lib/k3sm/server/keystore-delivery-state.json` (owned by the server's user, mode 0600).
  It only ever updates a Secret that has the recorded UID, and puts the label back if someone
  removed or changed it. Anyone who can write Secrets in the namespace can set the label, so the
  label alone does not count: a Secret of that name that someone else created first, or that was deleted and created
  again, is "not created by this server". The server leaves it alone and logs why: delete it, or
  pick another `--secret`. The server never lists Secrets, and deletes one only to re-create an
  immutable Secret it created after a rotation or a change to its data, or after an `rm`.
  After an `rm`, the next sweep deletes the Secret the server delivered for that entry, if it
  still has the recorded UID, and logs the names.
- **A namespace that does not exist yet.** Delivering into it goes to whoever later creates that
  namespace.
- **Withdrawing.** `undeliver` removes every delivery of the entry into that namespace from the
  declaration (with `--secret S`, only the one into Secret `S`), and prints: the Secret stays; delete it with kubectl, and rotate the entry to
  revoke. A Pod that read the value still has it, which is why revoking it means rotating.
- **Deleting a delivered entry.** `rm` does not withdraw its deliveries. For each one still
  declared, it warns: still declared for delivery to `<namespace>/<secret>`; the server deletes
  that Secret on its next sweep, unless the delivery breaker or a restore hold stops it; the
  server log says so. `k3sm keys undeliver` does not change that. The delete is made only on
  the Secret with the UID the server recorded when it created it, for the entry it recorded
  then (a label someone changed on the Secret does not count), and it runs while plaintext
  delivery is refused too. It removes the Secret from the Kubernetes API and nothing more: a
  Pod that already read the value still has it, and the datastore's history and its backups
  keep it, so revoking a credential still means rotating or disabling it where it is
  accepted. Anyone who can read the Secret already has the value. Since the delete cannot be
  undone, these hold it back:
  - `rm` records the entry as deleted in root's record, `/var/lib/k3sm/keystore-floor.json`,
    and it is no longer current there. An entry that record still lists as current but whose
    files are missing was not removed with `rm`: it is a restored or rolled-back `keystore/`,
    and its Secret is kept, with a warning naming the entry in the server log (see
    [Restoring an older keystore/](#restoring-an-older-keystore)). If an earlier `rm` was
    interrupted after removing the files, run `rm` again: it records the deletion even with
    the files gone.
  - The restore hold: after the server starts, and after `keystore/` is replaced, nothing is
    deleted until the first sweep has passed **and** 10 minutes have. The server warns when
    the hold starts, naming the time it ends. There is no flag to shorten it.
  - The breaker counts entries, not Secrets: an `rm` of one entry delivered into many
    namespaces is one. When the number of delivered entries gone at once is above 3 **and**
    above a quarter of the live delivered entries, none of their Secrets is deleted and the
    server logs an error with the count, again every hour while it holds. It keeps holding
    until enough entries are back, or until you delete those Secrets yourself with kubectl.
  - A delete counts as done only once the Secret is gone. A Secret already being deleted (a
    finalizer holds it), still there after its delete, or whose delete keeps failing is
    stuck: it is retried every sweep and does not count toward the breaker.
  - The entry is checked again just before each delete, so one put back meanwhile keeps its
    Secret.
  - Every Secret kept back for a reason that names it (root's record still lists the entry,
    the entry's absence cannot be confirmed, the Secret cannot be read) and every stuck
    delete gets one warning when it starts, and a summary every hour while any lasts,
    naming each, why, and for how long.

The declaration is `/var/lib/k3sm/keystore-delivery.json`, owned by root, mode 0644, and only
`k3sm keys deliver` and `undeliver` write it. It decides which namespace the server writes a
Secret into, so the server refuses the whole file, and delivers nothing from it, if it is not
owned by root, is writable by its group or by others, is a symlink, is over 64 KiB, or holds a
field or a version it does not know. The refusal is in the server log, and the verbs refuse that
file too rather than overwrite it. Two `deliver` or `undeliver` runs at once take turns on the lock file
`/var/lib/k3sm/.keystore-delivery.lock`, so neither loses the other's change.

### Limitation: one server

Delivery is for single-server clusters. On more than one server, each delivers from its own
keystore: every server runs the delivery from its own declaration and its own keystore, and
they do not coordinate. Two servers declaring the same Secret do not share it: the one that
creates it owns it, and the other logs that it was not created by this server and leaves it alone.

### While secrets encryption is off

A delivered Secret is stored in the datastore like any other. With secrets encryption off (see
`sudo k3sm secrets-encrypt status`), it would be stored there in plaintext, so the server refuses
every delivery and logs a warning for each target. `deliver` still records the target and warns
that the server refuses it unless the server was started with the override
(`--allow-plaintext-secrets-delivery`). It cannot see a running server's flags, so it does not
know whether the server was.

The better fix is to turn secrets encryption on. To deliver without it instead, turn the override
on:

1. Add `--allow-plaintext-secrets-delivery` to the server daemon's arguments, in the
   LaunchDaemon plist.
2. Restart the server daemon. The server reads the flag only at start.
3. Run `sudo k3sm install`, so the server-arguments record keeps the flag. A flag that is only in
   the plist is lost if you uninstall before the next install (see
   [Server flags across a reinstall](install.md#server-flags-across-a-reinstall)).

To turn it off, remove the flag from the plist, restart the server daemon, and run
`sudo k3sm install`. If the record still carries the flag, remove it there too. A Secret delivered
while the override was on stays as it is: the server stops updating it, and deletes it only
after an `rm` of its entry.

## Backing Up and Restoring

The keystore is not part of `k3sm snapshot save`. It lives in three places:

| Path | What it is |
|---|---|
| `/var/lib/k3sm/server/keystore/` | The entries and all their versions. The server creates it, empty, when it starts. |
| `/var/lib/k3sm/server/cred/keystore-master/` | The master key and its fingerprint. |
| `/var/lib/k3sm/keystore-floor.json` | Root's record of the newest version of each entry, which is how an older copy put back is caught. |
| `/var/lib/k3sm/keystore-delivery.json` | Which entries are delivered as which Secrets. It holds no value. |

Back up the entries and the master key **to different places**, so a copy of the entries that
leaks does not come with the key that opens it. They are still a matched pair: entries open only
with the master key that was current when they were saved, so take both again after every
`rewrap`.

Your datastore backups copy `/var/lib/k3sm/server/cred`, which holds the master key directory too.
Exclude `cred/keystore-master/` from them, and back the master key up on its own, as below.

To save, while no `k3sm keys` verb is running (`ditto` keeps owners and modes), give the backup a
name, here `2026-11-22`, and save its floor under that name:

```
B=2026-11-22
sudo install -d -o root -g wheel -m 0755 /path/to/backup
sudo install -d -o root -g wheel -m 0700 /path/to/backup/$B
sudo ditto /var/lib/k3sm/server/keystore /path/to/backup/$B/keystore
sudo ditto /var/lib/k3sm/server/cred/keystore-master /other/place/keystore-master
sudo install -d -o root -g wheel -m 0700 /var/root/keystore-floor-backup/$B
sudo install -o root -g wheel -m 0644 /var/lib/k3sm/keystore-floor.json /var/root/keystore-floor-backup/$B/keystore-floor.json
sudo shasum -a 256 /var/root/keystore-floor-backup/$B/keystore-floor.json | sudo tee /var/root/keystore-floor-backup/$B/keystore-floor.json.sha256
```

Keep `/path/to/backup` owned by root with no write access for group or others, and each backup's
directory in it owned by root with mode 0700, as the `install -d` lines make them: the restore
copies from there as root, and checks both first. Save `keystore/` and the floor file in the same run, and keep them as a pair. A floor file saved
at another moment does not describe the saved entries: some of them are refused, or deletions
recorded after it are lost. Each backup keeps its own floor, in the directory named after it, so
an older backup still has the floor that matches it. Never save every backup's floor to one
path: the newest would replace the floor an older backup needs.

The saved floor file goes to a directory on this Mac owned by root with mode 0700, such as
`/var/root/keystore-floor-backup/$B` above, not beside `keystore/` in a path your user can write.
The floor decides which entries are live, so a floor someone else could replace would let them
mark a revoked entry live again. Never keep the saved floor on a volume that ignores ownership,
such as an external drive set to ignore ownership, or on a volume others can write, such as a
network share. The SHA-256 that the last line records stays in root's directory on this Mac,
and the restore checks it before it puts the floor back, so a floor damaged since you saved it
is never used. The SHA-256 catches corruption, not tampering: anyone who could replace the saved
floor could replace its SHA-256 beside it, which is why the directory must be root's alone. If this Mac is lost, its saved floors are lost with it: restore as in
"Restoring an older keystore/" below.

To restore a backup, for example after deleting an entry by mistake, you move the live
`keystore/` and the live `keystore-floor.json` aside rather than deleting or overwriting them, so
a bad restore can be undone, and put back the `keystore-floor.json` you saved with that backup.
First stop the server, check that no copy from an earlier restore is still set aside, and check
the saved floor against its SHA-256, as root:

```
sudo k3sm stop
B=2026-11-22
sudo ls -d /var/lib/k3sm/pre-restore.d /var/lib/k3sm/keystore-floor.json.pre-restore
sudo shasum -a 256 -c /var/root/keystore-floor-backup/$B/keystore-floor.json.sha256
```

`ls` must report both paths missing ("No such file or directory"). If either exists, an earlier
restore was never finished or undone, and moving the live copies aside now would replace it:
finish or undo that restore first, as below, and do not go on. `shasum` must print `OK`. If it
does not, the saved floor has changed since you saved it: do not use it. Then move the live
copies aside and put the backup in place. `mkdir` makes a new directory that only root can
open, in `/var/lib/k3sm`, which root owns, and fails if the name already exists. `mv` then moves the live `keystore/` into it, so
nothing running as the service user can reach the moved-aside entries or copy one back into the
restored keystore. The files inside are not changed: they keep their owner and mode, so an undo
needs no ownership change. Never run `chown -R` or `chmod -R` as root over the moved-aside
`keystore/`. The service user wrote that tree, and a hard link it placed there would make root
change a file somewhere else. `ditto` copies the backup into `pre-restore.d/restored`, beside
the moved-aside copy, not into `server/`: the merge below moves it into place and hands it to the
service user itself, one file at a time, never following a link. It first checks the whole copy
and refuses it, changing nothing, if it holds anything the keystore does not write: a name the
keystore does not use, a link, a FIFO or socket, a file with a second hard link, a setuid, setgid
or sticky bit, an ACL or a file flag, a file larger than its kind can be, or a file owned by
anyone but the service user (or the unknown owner a volume that ignores ownership reports). A
file owned by root is refused too. The message names the path inside the copy. Leave
`/var/lib/k3sm/server/keystore` absent. If anything is there when the merge runs, such as a
directory or link the service user made, the merge moves it into `pre-restore.d` as
`planted-<time>`, where only root can reach it, without reading it or following a link. It says
so on stderr and in a `moved aside` line of its report, then goes on, and exits 4 so you read it. With `--dry-run` it prints
where it would move it and moves nothing. Every line ends in
`|| exit 1`, so the first one that fails stops the steps (and closes the shell), and no later
line moves a copy into or over one that is set aside. Before anything moves, the first three
lines check that nothing runs as the service user, that `/path/to/backup` is owned by root with
no write access for group or others, and that `/path/to/backup/$B` is owned by root with mode
0700.
If `pgrep` prints process IDs, the server has not stopped yet: wait for it and start the steps
again. If the second or third check fails, fix the owner or mode it names (`sudo chown root:wheel`
on either directory, `sudo chmod go-w /path/to/backup`, `sudo chmod 0700 /path/to/backup/$B`)
and start again. The
`test ! -L` before `ditto` stops if the backup's `keystore` is a link, which `ditto` would follow:

```
! pgrep -u _k3sm || exit 1
test "$(sudo find /path/to/backup -maxdepth 0 -user root \! -perm +022 | grep -c .)" -eq 1 || exit 1
test "$(sudo find /path/to/backup/$B -maxdepth 0 -user root -perm 0700 | grep -c .)" -eq 1 || exit 1
sudo mkdir -m 0700 /var/lib/k3sm/pre-restore.d || exit 1
sudo mv /var/lib/k3sm/server/keystore /var/lib/k3sm/pre-restore.d/keystore || exit 1
sudo test ! -e /var/lib/k3sm/keystore-floor.json.pre-restore || exit 1
sudo mv /var/lib/k3sm/keystore-floor.json /var/lib/k3sm/keystore-floor.json.pre-restore || exit 1
sudo test ! -e /var/lib/k3sm/pre-restore.d/restored || exit 1
sudo test ! -L /path/to/backup/$B/keystore || exit 1
sudo ditto /path/to/backup/$B/keystore /var/lib/k3sm/pre-restore.d/restored || exit 1
sudo install -o root -g wheel -m 0644 /var/root/keystore-floor-backup/$B/keystore-floor.json /var/lib/k3sm/keystore-floor.json || exit 1
```

Before you start the server, carry over every deletion recorded since the backup. The floor you
moved aside records every entry deleted while it was live. Until you merge it, `put`, `rotate`
and `rewrap` refuse with a message that names `keys floor merge`, and `list` and `show` run with a
warning on stderr but find no entries, since the restored ones are not in place yet. `rm` still deletes, with
the same warning, and the merge keeps each deletion it records. An `rm` at this point records
the deletion, but the restored entry's files are still in `pre-restore.d/restored`, out of its
reach. The merge removes those files before it moves the restored copy into place, so you do not
need to run `rm` again. A server started before the merge delivers no keys to the cluster and
deletes no delivered Secret: it logs an error and tries again until the merge has run. It also
creates an empty `/var/lib/k3sm/server/keystore` at start, which the merge then moves aside as
`planted-<time>` and reports, exiting 4, so keep the server stopped until the merge has run. Once it
has, the server deletes the Secret delivered from each entry the merge or an `rm` deleted, as
after any `rm`: once the restore hold has passed and unless the breaker holds (see [Delivering
an Entry as a Secret](#delivering-an-entry-as-a-secret)). Merge those deletions into the restored floor:

```
sudo k3sm keys floor merge
```

Once the merge is written, it moves `pre-restore.d/restored` to `/var/lib/k3sm/server/keystore`,
then renames the file to `keystore-floor.json.merged-<time>`, the time in
seconds since 1970, and the other verbs work again. If it prints its report and exits 5, the merge is
written, but the restored copy was not moved into place or the file was not renamed: run the same
command again. The second run never works the merge out again: it checks that the floor is the one
the first run recorded writing in `keystore-floor.json.pre-restore.retired`, writes nothing more,
prints `already merged` with the first run's report, moves the restored copy if it is still staged
and renames the file. `k3sm keys rm` still works before that second run: the second run accepts
the floor the first run wrote plus the deletions `rm` recorded since, keeps them, and removes the
restored files of each entry deleted. If the floor changed in any other way, it refuses, says so
and exits 5. The merge takes no file name: it reads only `/var/lib/k3sm/keystore-floor.json.pre-restore`,
the floor the steps above moved aside, so it never reads the floor saved with the backup or any
other copy. It refuses, and changes nothing, if that file is missing, if the restored
`keystore-floor.json` is not in place yet (put it back with `install` first), if the file is
the live floor itself, or if the restored floor holds none of the entries the moved-aside floor
holds, which means it is not the floor saved with this backup. It also refuses, and changes
nothing, if `/var/lib/k3sm/pre-restore.d` is on another volume than `/var/lib/k3sm/server`: it
moves the restored copy into place with a rename, which cannot cross volumes, so make
`pre-restore.d` in `/var/lib/k3sm` as the steps above do. `rm` also refuses until the
restored `keystore-floor.json` is in place.

The merge keeps every system-store key revoked since the backup refused: a key created after the
backup, every older version of a name deleted more than once, and an entry the backup holds that
you deleted since. User-scope entries (`user/<uid>/...`) have no floor the merge reads yet, so a
user-scope deletion since the backup is not carried over: such an entry comes back with the
restore, and when the restored keystore holds user-scope entries the merge prints a `user scope`
line saying so. That last kind is restored and then deleted again by the merge, because a deletion since
the backup may have revoked the key. To bring back an entry you deleted by mistake, which is the
reason to restore, name it with `--keep`, once for each entry:

```
sudo k3sm keys floor merge --keep system/<name>
```

Decide before you run the merge: once it has deleted an entry again, running it once more with
`--keep` does not bring that entry back. To see what it would do first, add `--dry-run`: it
prints the same report and changes nothing. The merge also deletes each version that was current in
the floor you moved aside but is not the restored one, such as an entry you put again after
deleting it since the backup: by restoring the backup you chose its version, so a copy of the
newer one put back is refused. `--keep` keeps only the restored version: an entry you deleted and
put again since the backup comes back as the backup's version, and the version you put since is
still retired, so a copy of it stays refused even after you remove the entry. Only an entry the
backup does not hold at all keeps its newer version when `--keep` names it: the merge records
that version as current, so a copy of an older one put back is refused. An entry you rotated since the
backup is restored at its older version, and the merge records how far it had been rotated, so a
copy of a newer version from before the restore is refused, before and after the next `rotate`
(which numbers past it). The merge prints how many
deletions it merged, how many the restored floor already had, how many restored entries it
deleted again, how many it kept because `--keep` named them, how many moved-aside versions it
retired, how many it had to drop to stay within the floor's limits, and how many restored entries
it fenced off from their newer pre-restore copies. It
lists each entry it deleted again as `buried live system/<name>`, each one it kept as `kept
system/<name>` and each one whose pre-restore version it retired as `retired system/<name>`. A
`kept` line says `revoked, kept live` for an entry deleted since the backup, and `recorded the
moved-aside version` for an entry the backup does not hold. It warns on stderr about each
revoked entry it keeps, since keeping it brings back a key that may have been deleted to revoke
it. A `--keep` name the merge would not delete, such as a
typo, makes it refuse and change nothing. The merge removes the restored files of each entry it
deletes again before it moves the copy into place, so you do not run `rm` for them.
A line starting `dropped` names a deletion the floor could not keep: a copy of that entry put
back is accepted. If the merge would drop any deletion to fit, even one the restored floor
already held, it refuses with a message that the floor is full, changes nothing and leaves the
file in place, so the other verbs still refuse. To make room, delete each entry you no longer
need with `sudo k3sm keys rm system/<name> --yes`, which works while the merge is pending, then
run the merge again. When the message names `--accept-drops`, deleting entries cannot help, and
`--accept-drops` lets the merge drop the oldest deletions to fit. It never drops the deletion of
an entry the merge deletes again: the restored copy would then be accepted with nothing to
refuse it. If that is the only way to fit, the merge refuses even with `--accept-drops` and names
the entries: delete each one with `sudo k3sm keys rm system/<name> --yes` first, then run the
merge again. A line starting `unverified` names a restored entry whose current version the
merge could not check with the master key, most often because the master key is missing. The
merge then leaves the restored floor's record of that entry as it is. A copy older than that
record is refused and a copy at it is accepted. If the merge also fenced the entry, a newer copy
up to the fence is refused until the next `rotate`, so if the backup's copy is newer than the
floor saved with it, `show` refuses the entry as a copy from before the restore. An
`unverified` line that names the moved-aside pointer is about the copy in
`pre-restore.d/keystore`: the merge could not check its current version with the master key, so
it fences the entry only past the version the moved-aside floor records, and a copy from before
the restore numbered above that may still be accepted.

The merge exits 0 when it is written and there is nothing to read in the report. It exits 4 when
it is written but dropped a deletion, kept an entry because `--keep` named it, left an entry
`unverified` (with no `pre-restore.d/keystore`, each entry the moved-aside floor holds live), or
moved aside what it found at `server/keystore`, or carried over user-scope entries without a
floor check, so read the report. It exits 5 when it is written
but the restored copy was not moved into place, the move may not survive a crash, or the file was
not renamed (run it again), and 1 when it refuses and changes
nothing. A run after an exit 5 finds the merge already written, so if it then refuses the
restored copy, or cannot move aside what is at `server/keystore`, it says the merge is written
and exits 5 again, with `--dry-run` too: fix what it names and run it once more. With `--dry-run` it exits with the code the merge itself would return. Then start the server and check the entries:

```
sudo k3sm start
sudo k3sm keys list
```

Restore the floor file with `install` as shown. The floor is refused unless root owns it,
and on a volume that ignores ownership, such as an external drive set to ignore
ownership or a network share, `cp -p` gives the copy a non-root owner. `install -o root -g wheel
-m 0644` sets the owner and mode whatever the volume reports. The merge reads the floor you
moved aside only from a directory root owns that group and others cannot write, such as
`/var/lib/k3sm`, where the recipe leaves it.

Restore the floor file too, or the entry stays refused. When you delete an entry, root's record
notes the deletion, and any copy of that entry put back later is refused with a message saying
the floor records it as deleted, because the check cannot tell your restore from someone
putting a deleted key back. The floor file saved with the backup still lists the entry as live,
so restoring it with `keystore/`, and naming the entry with `--keep` in the merge, brings the
entry back.

A restore puts back the whole keystore as it was when you saved it, not one entry:

- Every `rotate` since the backup is undone. Each entry's current version is the one it had
  then.
- Every entry you deleted since the backup comes back, and root's record of those deletions is
  gone, until the merge above carries those deletions over. The merge deletes each of those
  entries again unless `--keep` names it, so a key you deleted to revoke it stays deleted.

Only when `list` shows every entry `ok`, delete the copies you moved aside:

```
sudo rm -rf /var/lib/k3sm/pre-restore.d
sudo rm /var/lib/k3sm/keystore-floor.json.merged-*
```

To undo the restore instead, stop the server and stage the two copies the other way round inside
`pre-restore.d`: the copy you moved aside becomes `restored`, which the merge moves into place,
and the restored `keystore/` becomes the moved-aside copy. Every line ends in `|| exit 1`, as
above. The floors swap places: the floor you moved aside
goes back in place, and the restored floor becomes `keystore-floor.json.pre-restore`, so the
merge runs in reverse and keeps every deletion you made after the restore. If you already ran
the merge, the floor you moved aside is now `keystore-floor.json.merged-<time>`: use that name
in the first floor `mv` instead. `--undo` tells the reverse merge to read the record the first
merge left beside that file, `keystore-floor.json.merged-<time>.retired`, which lists what the
first merge retired; leave that record in place. `--undo` uses only the record whose merge read
the floor you put back, so it refuses when that floor is not the first merge's input, or when no
record matches it, and says so. If you never ran the first merge there is no record and `--undo`
refuses: run the two merge lines without `--undo`. The `pgrep` line stops
the steps while anything still runs as the service user, as in the restore.

```
sudo k3sm stop
! pgrep -u _k3sm || exit 1
sudo test ! -e /var/lib/k3sm/pre-restore.d/restored || exit 1
sudo mv /var/lib/k3sm/pre-restore.d/keystore /var/lib/k3sm/pre-restore.d/restored || exit 1
sudo mv /var/lib/k3sm/server/keystore /var/lib/k3sm/pre-restore.d/keystore || exit 1
sudo mv /var/lib/k3sm/keystore-floor.json.pre-restore /var/lib/k3sm/keystore-floor.json.undo || exit 1
sudo mv /var/lib/k3sm/keystore-floor.json /var/lib/k3sm/keystore-floor.json.pre-restore || exit 1
sudo mv /var/lib/k3sm/keystore-floor.json.undo /var/lib/k3sm/keystore-floor.json || exit 1
sudo k3sm keys floor merge --undo --dry-run
sudo k3sm keys floor merge --undo
sudo rm -rf /var/lib/k3sm/pre-restore.d
sudo k3sm start
```

The last `rm -rf` removes the restored copy, which the steps above left in `pre-restore.d`.

Read the `--dry-run` report before you run the merge. A `buried live` line names an entry that
the restored floor records as deleted, and says which kind it is. `retired by the restore` is a
version the first merge retired, live again in the keystore you moved back: the reverse merge
deletes it, files and all, unless you run the merge with `--keep system/<name>` for it, so name
each one with `--keep` and run `--dry-run` with the same flags first to check that none is left.
`deleted since the restore` is an entry you deleted after the restore: it stays deleted, the
merge removes its files, and `--keep` on it is refused.

The values come back byte for byte: `show --reveal` prints exactly what it printed before. Restore
the master key the same way, from its own backup, if it was lost too.

### Restoring an older keystore/

If you restore a backup that is older than the live keystore, for example from before a
`rotate`, every rotated entry is refused as "older than the recorded floor". That is the check
doing its job: it cannot tell your restore from someone putting an old copy back. If the restore
is deliberate:

1. Stop the server: `sudo k3sm stop`.
2. Move the live `keystore/` aside, as above, and restore `keystore/` and the master key that
   matches it.
3. Remove root's record: `sudo rm /var/lib/k3sm/keystore-floor.json`.
4. Run any keys verb, such as `sudo k3sm keys list`. It writes the record again from the restored
   entries.
5. Start the server: `sudo k3sm start`.
6. Once `sudo k3sm keys list` shows every entry `ok`, delete the copy you moved aside.

Only remove the record when you know the restored entries are the ones you want current, since
the next keys verb accepts them as the newest. Removing it also discards every deletion it
recorded: a copy of a deleted entry put back later is no longer refused.

A restore also changes which entries exist, and the server does not delete a delivered Secret
because a restore lost its entry:

- After a restore of a backup with its saved floor and `keys floor merge` (the steps under
  "Backing Up and Restoring"), the merge records as deleted each entry the backup lacks and the
  moved-aside floor holds, unless `--keep` names it, so the server deletes their Secrets as after
  an `rm`, once the restore hold has passed and unless the breaker holds. Root's record still
  lists as current an entry whose files are missing only when the restored `keystore/` lacks
  what the record names, such as an entry `--keep` kept that the backup does not hold, or a
  `keystore/` put back without its floor. The server keeps those Secrets for as long as that
  lasts and warns once per entry in its log. To revoke one, `rm` it, or delete the Secret with
  kubectl.
- After the steps above, which remove root's record and write it again from the restored
  entries, the record no longer lists the entries the restored copy lacks, so it cannot tell
  them from an `rm`. The server holds back for 10 minutes after `start` (and after
  `keystore/` is replaced while it runs), and for every sweep while the breaker holds (above
  3 and above a quarter of the delivered entries gone at once). You have those 10 minutes
  after `start` to put back any entry that is still delivered. After that, an entry the
  restored copy does not hold has its Secret deleted, as after an `rm`, so restore every entry
  you still deliver.
