# S4 findings — the reproducible guest-kernel build (executed as the production build)

Recorded 2026-08-31. S4's dry-run was overtaken by events: the production
`runtimed/hack/guest-kernel/build.sh` was built, run twice, and published the same
day, so this file records the real build rather than a rehearsal. Rig: the M11
lab host (Mac13,2, macOS 26.6.x, Docker 29.6.2 aarch64).

## The artifact

| fact | value |
|---|---|
| kernel | upstream linux-6.18.48 (6.18 LTS), unmodified tarball |
| tarball sha256 | `5ebdadb10a4b5708fc6b1c457764a110bc49f8150cc3502c59b921ead8c6fc8c` |
| Image (uncompressed arm64) | 77,818,368 bytes |
| Image sha256 | `d50508b08205453e5f5f710978743449dc4fafe957aa8694e6da8e5780d93308` |
| config hash (configver) | `9c05f8f3b26c00124053cbbe8db3044888a3c737866abf4529fb956ef1c154c4` |
| toolchain | `debian@sha256:7215f78f35ffe58fe13f244fac9c4f21326d55187271fbb3e1a8aa5cc7e387ab` (trixie-20260824-slim, arm64), gcc 14.2.0 |
| two-run verdict | IDENTICAL (`build.sh --repro`, byte-compare of two clean-tree builds) |
| published | github.com/k3sm-io/linux-guest release v6.18.48-k3sm.1 |
| pinned | `runtimed/pkg/guestartifacts` `ActiveGuestKernel = "v6.18.48-9c05f8f3b26c"`; digests minted from the RE-DOWNLOADED published assets |

The 77.8 MB size is the bundle-vs-ensure decision input: with the ~132 MB installer
tarball, bundling the kernel would grow it ~60%; the install-time ensure (B108)
ships instead, and an air-gapped install pre-seeds the artifact dir.

## PGP first mint (dual anchor)

Two independent trust chains, both required by `build.sh` on every run:

1. **Autosigner sums**: `sha256sums.asc` fetched and PGP-verified — GOODSIG +
   VALIDSIG `B8868C80BA62A1FFFAF5FDA9632D3A06589DA6B1` ("Kernel.org checksum
   autosigner", signature of 2026-08-28); the tarball pin is the linux-6.18.48
   line of the verified cleartext.
2. **Developer signature**: `linux-6.18.48.tar.sign` verified over the
   uncompressed tar — Good signature, Greg Kroah-Hartman
   `647F28654894E3BD457199BE38DBBDC86092693E`, the stable-release key published
   on kernel.org/signature.html (fetched and matched 2026-08-31). kernel.org's
   own page calls the developer signature the stronger assurance.

Every key import asserts the keyring holds the pinned fingerprint after recv.
One build defect found and fixed en route: trixie-slim lacks python3, which the
kernel's generated-header steps need (first hit: drivers/gpu/drm/msm under the
arm64 defconfig base) — added to BUILD_DEPS.

## Initramfs

Composed byte-deterministically by `guest-initramfs` (runtimed) from
`k3sm-guest-init` built at runtimed `59621dfa5eee` with
`GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -buildid="`
(go1.27.0): 11,076,532 bytes,
`0c6e88e94d1d9ff2b178ace58dd94343869e301d1ff9defa5550abc7880bb695`; composing
twice and rebuilding guest-init are both byte-identical.

## The S3(2) idmapped-mount re-probe on 6.18

The 6.14 measurement was NO (virtiofs MOUNT_ATTR_IDMAP -> EINVAL, tmpfs control
positive). Source-level check on the built 6.18.48: `fs/fuse/virtio_fs.c:1759`
declares `FS_ALLOW_IDMAP` — the kernel-side refusal that produced the EINVAL is
gone in this series, so the answer LIKELY flips to YES. The live in-guest probe
was attempted and blocked by harness shape, not by the kernel: `s3-run.sh`
phase 0 requires a gzipped vmlinuz plus its matching Ubuntu linux-modules .deb
(virtiofs.ko extraction), and the k3sm kernel is modules-off with virtiofs
built in, which that pairing cannot express. Follow-up: a small s3-run.sh
adaptation (skip module extraction, accept an uncompressed kernel) re-runs the
probe as-is. OPERATOR FLAG per the plan: a measured YES reopens the fsGroup
path (B112's precondition); nothing in this build acts on it.

## Live verification on this rig (same day)

- Ensure from the published release: 3.2 s fetch + digest-verify into the
  sha-keyed set; per-boot locator re-verify OK; warm-cache re-ensure 49 ms with
  the fetcher provably not called.
- Boot smoke on the ensured kernel: create -> guest Health -> Running in
  1.34 s; clean teardown (helper exited, socket cleared).
- Cold rebuild from the published corresponding-source assets alone
  (build.sh + kernel.config + sha256sums downloaded from the release into a
  clean directory, no local build state): BYTE-IDENTICAL — the rebuilt Image
  hashes to the published/pinned
  `d50508b08205453e5f5f710978743449dc4fafe957aa8694e6da8e5780d93308`, same
  77,818,368 bytes, same configver. A self-built artifact with no upstream
  registry to re-pull from now has an independent re-derivation on record.
