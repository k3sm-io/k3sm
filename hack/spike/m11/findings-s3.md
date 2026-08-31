# S3 findings — virtiofs semantics and performance

> Status: the **hard gate S3(2) is ANSWERED — NO**, and the cheap recordings
> (1-lite fsync, 4 emptyDir-shaped IO, 5 APFS case-collision) are RECORDED, from
> the 2026-08-31 sitting run by `s3-run.sh` on the same rig as S1 and S5.
> S3(1)'s **pgbench ratio**, S3(3) the **ownership sidecar** and S3(6)
> **confined-vs-unconfined throughput** are **NOT RUN**, each for a stated
> reason, and no value below is inferred from a leg that did not run.
>
> This file is a DECISION TABLE, not a report. Every row carries the observed
> value AND the pre-named consequence that value selects; the branch wording is
> `s3.sh`'s, quoted rather than paraphrased. Every `S3_*=` line quoted below
> appears verbatim in the run's captured console at `out/s3-guest.log` under the
> lab prefix.

## What unblocked this sitting

The 2026-08-31 S5 sitting recorded that S3 **could not start**: the S1/S5
throwaway kernel (Ubuntu `6.8.0-138-generic`) builds `virtio_fs` as a **module**
and an initramfs holds no module tree, so the share would not mount
(`S5_VIRTIOFS=unavailable err=no such device`) — and 6.8 is below the ≥6.12
floor S3(2) needs in any case.

`s3-run.sh` replaces the throwaway with the Ubuntu 25.04 (plucky) arm64 cloud
kernel, **6.14.0-37-generic**, and ships **only** the modules the mount needs,
extracted from the exact matching `linux-modules` package. Which modules those
are is derived from the artifacts, not assumed:

```
S3_MOD_FUSE_BUILTIN=1
S3_MOD_VIRTIO_BUILTIN=3
S3_MOD_CANDIDATES=./lib/modules/6.14.0-37-generic/kernel/fs/fuse/virtiofs.ko.zst
S3_MOD_EXTRACTED=virtiofs.ko bytes=69665
S3_MOD_DEPENDS_virtiofs.ko=depends=
S3_MOD_VERMAGIC_virtiofs.ko=vermagic=6.14.0-37-generic SMP preempt mod_unload modversions aarch64
```

`fuse.ko` is **built in** to that kernel and `virtiofs.ko` declares **no**
dependencies, so the load is a single `finit_module(2)` from the guest's Go
PID 1 — no `depmod`, no module tree, no ordering problem:

```
S3_MODLOAD_virtiofs.ko=ok
S3_GUEST_HAS_VIRTIOFS=true
S3_VIRTIOFS=mounted tag=s3share
S3_VIRTIOFS_MOUNTINFO=32 2 0:28 / /mnt/share rw,relatime - virtiofs s3share rw
S3_SHARE_RW=yes
```

This kernel stays a **throwaway**. The pinned product kernel is human-gated
B111's job; what this one buys is the floor — ≥6.12 with a loadable virtiofs —
on which S3(2) is even askable. It does not pre-empt S4's config work; if
anything it supplies S4 with a second data point (see the M11.0-d4 note below).

## Rig, kernel and guest

| | |
|---|---|
| host | the lab Mac (the lab host), run locally through the harness's ssh path |
| macOS | 26.6.2 · `hw.model` Apple silicon · arm64 |
| date (UTC) | 2026-08-31 |
| guest kernel | `6.14.0-37-generic` (Ubuntu 25.04 plucky, arm64 generic cloud) |
| kernel URL | `https://cloud-images.ubuntu.com/releases/25.04/release/unpacked/ubuntu-25.04-server-cloudimg-arm64-vmlinuz-generic` |
| kernel sha256 (as fetched, gzip) | `d2e9d1adff7ac3d40672ad9d2c2b3215cfa8b0982ad61886844e2439b11e7e6c` |
| kernel, decompressed | 63361416 bytes — `VZLinuxBootLoader` rejects gzip (S1 criterion 2's control), so it is expanded host-side |
| modules URL | `http://ports.ubuntu.com/ubuntu-ports/pool/main/l/linux/linux-modules-6.14.0-37-generic_6.14.0-37.37_arm64.deb` |
| modules sha256 | `303be0928f375883f67f9739327036dcb5680df648769b08eb88b1a58b645a13` |
| module shipped | `virtiofs.ko`, 69665 bytes, decompressed host-side from `.ko.zst` |
| guest rootfs | `alpine-minirootfs-3.24.1-aarch64.tar.gz` — the SAME pin S5 used, so only the kernel differs between the two spikes |
| rootfs sha256 | `f55a90f69052c5bd6f92cb09a8f47065970830b194c917a006fb94028e721259` |
| initramfs | 10828288 bytes (the Alpine tree + `virtiofs.ko` + a static Go `/init` that IS every probe) |
| share | `<lab prefix>/s3/share`, attached **read-write** (S5's was read-only) |
| VM | 2 vCPU, 2048 MiB; `VZS3_CREATE_TO_START_NS=136156583` |

Both pins are re-verified on **every** run, not only on first fetch: a
moved-on archive artifact would silently change the kernel every figure below
was taken under.

## Decision table

| # | criterion | observed | consequence this selects |
|---|---|---|---|
| **2** | **HARD GATE** — does Apple's virtiofs advertise FUSE idmapped-mount support? | **NO.** `mount_setattr(MOUNT_ATTR_IDMAP)` on a detached clone of the virtiofs mount fails **`EINVAL` (errno 22)**, on kernel `6.14.0-37-generic`, while the tmpfs control succeeds and a `MOUNT_ATTR_NOSUID` on the *same* virtiofs tree also succeeds | `s3.sh` verbatim: **"NO ⇒ human-reviewed fsGroup re-plan. Do NOT adopt a chmod fallback here; it is banned as a dual path, and adopting one in a lab session is exactly the silent divergence the M11 plan's Resolution 1 forbids."** Its pre-decided consequence also fires: **"on NO, the CORE storage leg substitutes a root-in-guest image and PVC-PGDATA-with-fsGroup moves to the follow-on."** B112 does **not** unblock on this evidence |
| **1-lite** | guest fsync on the RW share, N=50 | **all 50 succeeded**, `min 393 µs · median 422 µs · p95 450 µs · max 480 µs`; the tmpfs contrast in the same boot is `median 12 µs` — virtiofs fsync costs ≈**35×** a tmpfs fsync and the distribution is **tight** (p95/median = 1.07), i.e. single-mode | a durable per-file sync on a virtiofs volume costs sub-millisecond on this rig, and there is **no bimodal tail** that would suggest some syncs take an APFS `F_FULLFSYNC` path and others do not. It does **NOT** establish that any of them do — see the ceiling note below |
| **1** | pgbench on a virtiofs-backed PGDATA vs the 0.25× native bar | **NOT RUN** — no database in the throwaway guest | **NEITHER branch fires.** The virtio-blk escape hatch is neither un-parked (R24c) nor deleted; it stays **parked**, exactly as before this sitting |
| **4** | emptyDir-shaped IO on the RW share | seq write 64 MiB (1 MiB records, fsync at end): **1237.4 MiB/s**; seq read after a guest cache drop: **2765.9 MiB/s**; random 4 KiB write ×1024 + fsync: **31.0 MiB/s / 7935 IOPS**. Same passes on guest tmpfs: **9724.1 / 24444.6 MiB/s** and **2721.0 MiB/s / 696579 IOPS** | streaming IO over virtiofs is ≈**1/8** of guest tmpfs and small random writes are ≈**1/88** — the shape is *transport-bound per operation*, not bandwidth-bound. An emptyDir served from virtiofs is fine for streaming and poor for small-random. Read the caveats before quoting any of these |
| **5** | APFS case-collision through virtiofs | the host wrote `File` then `file` on a **case-insensitive** volume, leaving **ONE** entry; the guest lists **`File` only**, and `stat("File")` and `stat("file")` return the **same inode (4)** with the same content `content-of-file`. A guest-side `Guest`/`guest` pair collapses the same way (`upper_after=guest-lower`) | virtiofs **passes the host volume's case-insensitivity straight through**: the guest's own case-sensitive semantics do not survive the share. An extractor writing a case-colliding pair of layer entries onto a virtiofs volume **silently loses one**, in both directions, with no error to detect it by. Collision detection must be the extractor's, host-side — the guest cannot see the collision at all |
| **3** | ownership-sidecar apply cost on a real image | **NOT RUN** — needs the product unpacker's extracted image tree, which does not exist yet | no figure; the sidecar's cost is unmeasured |
| **6** | confined-vs-unconfined vmhost throughput | **NOT RUN** — needs the vmhost confinement wiring. S1(5) answered **coexistence** (does `sandbox_init` coexist with VZ VM construction), which is a different question | Resolution 7 still has no throughput data |

## Criterion 2 — the idmapped-mount gate · verbatim

Three probes in one boot, differing in **one variable each**, so a failure on
the gate cannot be blamed on the helper, the namespace, or the syscall's
availability:

```
S3_GUEST_KVER=Linux version 6.14.0-37-generic (buildd@bos03-arm64-047) (aarch64-linux-gnu-gcc-14 (Ubuntu 14.2.0-19ubuntu2) 14.2.0, GNU ld (GNU Binutils for Ubuntu) 2.44) #37-Ubuntu SMP PREEMPT_DYNAMIC Fri Nov 14 23:05:04 UTC 2025
S3_C2_USERNS=ok map=0:1000:65536
S3_C2_CONTROL_TMPFS_IDMAP=OK path=/ctl
S3_C2_VIRTIOFS_NOSUID=OK path=/mnt/share
S3_C2_VIRTIOFS_IDMAP=FAIL err=EINVAL(errno=22) "invalid argument"
S3_C2_VERDICT=NO
```

The probe is `open_tree(AT_FDCWD, path, OPEN_TREE_CLONE|AT_RECURSIVE)` followed
by `mount_setattr(fd, "", AT_EMPTY_PATH, {attr_set: MOUNT_ATTR_IDMAP,
userns_fd})`, exactly the call `s3.sh` specifies. The user namespace is created
by a child (`CLONE_NEWUSER` with an explicit `0:1000:65536` map), because a
process cannot hand `mount_setattr` its own namespace and giving up the init
namespace would cost the `CAP_SYS_ADMIN` the syscall requires.

**Why the two controls are the whole point.**

* `CONTROL_TMPFS_IDMAP=OK` — the **same helper**, the **same userns fd**, the
  **same syscall**, against a filesystem that does allow idmapped mounts. So the
  helper works, the namespace is valid, `mount_setattr` exists on this kernel,
  and this process holds the privilege. "The test is broken" is excluded.
* `VIRTIOFS_NOSUID=OK` — the **same virtiofs mount**, the **same `open_tree`
  clone**, a **different attribute**. So `open_tree` can clone a virtiofs tree
  and `mount_setattr` accepts attributes on it. "virtiofs cannot be cloned" and
  "mount_setattr does not work on this mount" are both excluded.

What is left is the single bit under test: `MOUNT_ATTR_IDMAP` **on this
filesystem instance**.

**The errno matters, and `s3.sh` says so** — *"a generic 'unsupported' is not a
finding — EINVAL and EOPNOTSUPP point at different causes (the mount vs the
filesystem type), and the re-plan depends on which."* The observed value is
**`EINVAL`**, which is what the kernel returns when the superblock is not marked
as permitting idmapped mounts — i.e. the **filesystem instance** refuses, not
the mount and not the syscall. On FUSE ≥6.12 that marking is the **server's**
opt-in, which is precisely the "host-side server opt-in is the unknown" that
`s3.sh` named as the open question. Recorded as an errno, not as a mechanism
claim: the errno is observed, the server-side reason for it is not.

### The ownership fact the re-plan will want

Recorded next to the gate rather than left to be inferred:

```
S3_SHARE_OWNERSHIP=uid=0 gid=0 mode=100644 (as the GUEST sees a host-created file)
S3_C5_HOST_MARKER_OWNER=uid=501 gid=20
```

The same file is `uid=501 gid=20` on the host and `uid=0 gid=0` in the guest.
Apple's virtiofs is already **presenting host files as guest-root-owned**. This
is an observation, not a design conclusion: it says a root-in-guest workload
sees a writable tree, and it says nothing about whether the `fsGroup` semantics
k8s specifies (group ownership + setgid propagation for a *non-root* container
uid) can be delivered without the idmapped mount. Deciding that is the
human-reviewed re-plan's job, and this file deliberately does not pre-empt it.

### Scope of the claim

One rig, one macOS build (26.6.2 / (redacted)), one guest kernel, one
`VZVirtioFileSystemDeviceConfiguration` single-directory share. **The host-side
server behaviour was observed on THIS macOS build only.** Apple documents no
FUSE feature-negotiation contract for its virtiofs device, so a later macOS may
advertise `FUSE_ALLOW_IDMAP` and flip this answer. The gate is answered for the
decision that has to be made now; it is not a permanent property of the
platform, and B112's merge-precondition should be re-measured against the
shipping macOS floor before the fsGroup leg is declared either way.

## Criterion 1-lite — fsync on the RW share · verbatim

```
S3_C1_SHARE_FSYNC=ok n=50 failures=0 min_us=393 median_us=422 p95_us=450 max_us=480 mean_us=425
S3_C1_TMPFS_FSYNC=ok n=50 failures=0 min_us=11 median_us=12 p95_us=17 max_us=25 mean_us=13
S3_C1_FSYNC_HOST_MAPPING=NOT OBSERVABLE from the guest (whether the host server issues fsync(2) or F_FULLFSYNC needs host-side tracing, which needs root)
S3_PGBENCH=NOT RUN (no database in the throwaway guest)
```

Each iteration is create → write 4 KiB → `fsync` → close, timed end to end.
Zero failures in 50, on both filesystems.

**The half this does NOT answer.** `s3.sh` asks *"whether guest fsync maps to
host `fsync(2)` or `F_FULLFSYNC`: on APFS those differ by roughly an order of
magnitude, and a PGDATA whose fsync is not durable is a correctness claim, not a
performance one."* That question is about what the **host** server does, and it
is **not observable from inside the guest** — answering it needs host-side
tracing, which needs root. The tight distribution above is *consistent with* a
single code path but does not identify which one, and 422 µs is not by itself
evidence either way. **It is therefore still open**, and it is a correctness
question, so it should not be closed by inference.

## Criterion 4 — emptyDir-shaped IO · verbatim

```
S3_C4_SHARE_SEQW=ok mib=64 elapsed_ms=51 mib_per_s=1237.4
S3_C4_DROPCACHES=ok
S3_C4_SHARE_SEQR=ok bytes=67108864 elapsed_ms=23 mib_per_s=2765.9
S3_C4_SHARE_RANDW=ok ops=1024 block=4096 elapsed_ms=129 mib_per_s=31.0 iops=7935
S3_C4_TMPFS_SEQW=ok mib=64 elapsed_ms=6 mib_per_s=9724.1
S3_C4_DROPCACHES=ok
S3_C4_TMPFS_SEQR=ok bytes=67108864 elapsed_ms=2 mib_per_s=24444.6
S3_C4_TMPFS_RANDW=ok ops=1024 block=4096 elapsed_ms=1 mib_per_s=2721.0 iops=696579
```

Mechanism: a static Go pass, not `dd`. busybox `dd`'s rate reporting is
version-dependent and its writes are unsynced, so a `dd` figure would have been
neither comparable across runs nor inclusive of the sync cost. The Go pass
writes 1 MiB records, `fsync`s once at the end of the sequential write, drops
the guest page cache before the read, and issues 1024 4 KiB `pwrite`s at
seeded-random offsets before a final `fsync`.

**Three caveats, all of which bound what these numbers mean.**

1. **`drop_caches` drops the GUEST page cache only.** The host's APFS cache is
   untouched — dropping it needs root on the host. The read figure is therefore
   an **upper bound on the virtiofs transport**, not a storage figure; the data
   was very likely still in the host's cache.
2. **64 MiB is small.** The host absorbed the whole write; the sequential write
   figure measures the transport plus the host's buffer cache, not durable
   media throughput. It is a shape measurement for a design decision, as
   `s3.sh` frames criterion 4, and not a benchmark result.
3. **One rig, one boot, single samples.** No repetitions, no error bars. The
   ratios (≈8× on streaming, ≈88× on small random) are the transferable part;
   the absolute numbers are not.

**What the shape says.** The random-write collapse relative to streaming is the
signature of a **per-operation** cost — every 4 KiB write is a round trip
through the FUSE/virtiofs transport, while a 1 MiB write amortises it. An
emptyDir on virtiofs will look fine to a workload that streams and poor to one
that does many small synchronous writes. That is the same axis pgbench would
have measured, which is exactly why the pgbench bar is not answered by these
numbers and is recorded as NOT RUN.

## Criterion 5 — APFS case-collision through virtiofs · verbatim

Host side, before the boot:

```
S3_C5_HOST_VOLUME=case-insensitive (writing File then file left ONE entry)
S3_C5_HOST_ENTRIES=File,MARKER,
S3_C5_HOST_FILE_CONTENT=content-of-file
S3_C5_HOST_file_CONTENT=content-of-file
```

Guest side, through virtiofs:

```
S3_C5_GUEST_LIST=File,GUEST_WROTE,MARKER
S3_C5_STAT_UPPER=ino=4 uid=0 gid=0 mode=100644 size=16
S3_C5_STAT_LOWER=ino=4 uid=0 gid=0 mode=100644 size=16
S3_C5_SAME_INODE=true ino_upper=4 ino_lower=4
S3_C5_CONTENT_UPPER=content-of-file
S3_C5_CONTENT_LOWER=content-of-file
S3_C5_GUEST_CREATE=err=<nil> upper_after=guest-lower
```

Host side, after the guest ran:

```
S3_POST_HOST_ENTRIES=File,fsyncdir,Guest,GUEST_WROTE,iodir,MARKER,
S3_POST_HOST_Guest_CONTENT=guest-lower
```

Both directions collapse. The host's `File`+`file` became one file that the
guest sees under one name; the guest's `Guest`+`guest` became one host file
holding the *second* write. **`S3_C5_GUEST_CREATE=err=<nil>`** is the load-bearing
half: the collapsing write **returned success**. There is no errno for the guest
to detect, and `readdir` shows one entry rather than two, so a guest-side
extractor cannot discover the collision at all.

**Consequence.** Case-collision detection is the **extractor's**, and it must
run **host-side against the target volume's actual case behaviour** — it cannot
be delegated to the guest and it cannot rely on an error return. This is
narrower than "Linux images with case-colliding paths break": they break
*silently*, which is the worse failure and the one the detection has to be
designed for.

## NOT RUN — with the reason, never approximated

| leg | why it did not run |
|---|---|
| S3(1) pgbench ratio vs the 0.25× bar | there is no database in a throwaway minirootfs guest, and installing one in the sitting would have made the measurement about the install rather than about virtiofs. **Neither the un-park nor the delete branch fires**; the virtio-blk escape hatch stays parked |
| S3(1) guest-fsync → host `fsync(2)` vs `F_FULLFSYNC` | needs host-side tracing of the virtiofs server, which needs root. Not inferable from guest-side timing |
| S3(3) ownership-sidecar apply cost | needs the product unpacker's extracted image tree (thousands of non-root-owned files); that tree does not exist yet |
| S3(6) confined-vs-unconfined vmhost throughput | needs the vmhost confinement wiring. S1(5) answered coexistence, which is a different question |
| anything requiring host root | out of bounds for the spike guardrails in `lib.sh`; the root-needing S5 legs have their own operator-run driver (`s5-root.sh`) and this file adds none |

## Incidental finding — a second data point for S4 (M11.0-d4)

S4 must produce a kernel config with the virtiofs stack **built in**. This
sitting is evidence for the *shape* of that requirement rather than for a
particular config: Ubuntu's 6.14 generic already ships `fuse` as `=y` and only
`virtiofs` as `=m`, and `virtiofs.ko` declares no dependencies — so the pinned
kernel needs `CONFIG_VIRTIO_FS=y` on top of a `FUSE_FS=y` that is already the
common distro default, and nothing more elaborate. It also confirms the negative
S5 recorded: a kernel with `virtio_fs=m` and no module tree cannot mount a
share, and every M11 feature that assumes a virtiofs rootfs or virtiofs volumes
fails closed on such a kernel.

## Deviations from the guardrails in lib.sh

1. **A different throwaway kernel from S1's and S5's** (`6.14.0-37-generic`
   rather than `6.8.0-138-generic`), because S3(2) requires ≥6.12 and S5's
   kernel cannot mount a share at all. Pinned by URL and sha256, re-verified on
   every run, and recorded above. This is a spike artifact, not a product pin;
   B111 remains the pinned-kernel owner.
2. **The virtiofs share is READ-WRITE**, where S5's was read-only. Every S3
   figure is a write figure, so a read-only share would have made criteria 1, 4
   and 5 unmeasurable. The share is a fresh directory under the lab prefix
   (`<lab prefix>/s3/share`), created by the harness and holding nothing else.
3. **No allow-set, privilege, or system-state widening was adopted.** No sudo,
   no host root, no `/etc`, no sysctl, no interface or route change. Every
   privileged operation happens **inside the guest**, where PID 1 is root by
   construction, and the guest is destroyed at the end of the run
   (`VZS3_STOPPED=yes`, then `S3_CLEANUP=done`).
