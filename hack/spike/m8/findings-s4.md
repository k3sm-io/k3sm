# S4 — image size & materialize latency (M8.0-d4) — **PASS on both thresholds; ONE packaging defect found**

> **Verdict: PASS.** Both pruning thresholds clear by an order of magnitude
> (0.37 GB unpacked against >2 GB; 3.2 s to first token against >1 min), so the
> "S4 remediable (prune → rerun)" halt semantics do not fire and **no payload
> pruning is required**.
>
> **The packaging premise HOLDS: `PREMISE_SYMLINKS=PASS`, `PREMISE_CONTENT=PASS`.**
> All 9 python-build-standalone symlinks survive COPY → layer → unpack with
> byte-identical targets, all 7 963 regular files survive with an identical
> whole-tree content digest, and the unpacked tree execs *through* the
> `bin/python3` symlink. M8.4 needs no re-plan on this axis.
>
> **But the spike found a real defect while proving it:** the emitted layer blob
> is **gzip bytes carrying an UNCOMPRESSED mediaType**. It did not break the
> round-trip here only because bsdtar sniffs gzip. See §The layer-format defect —
> this is a **blocking prerequisite for M8.4**, not an S4 threshold failure.

Run: 2026-08-29 on the S1 rig, agent-driven over ssh. Re-run with
`hack/spike/m8/s4.sh` (`--restage` to rebuild the staged rootfs, `--no-build` to
skip the source push + `go build`).

## Rig & method

Same rig as S1–S3 (**Apple M1 Ultra**, 20-core, 64 GiB unified, macOS **26.5.2**
build **25F84**). Every write confined to the spike prefix; **no sudo, no root**,
no host-config mutation.

The `k3sm` binary under test is built **on the lab** (`CGO_ENABLED=1
GOARCH=arm64`, Go 1.27.0, `GOWORK=off`) from a source copy pushed into the
prefix, so the arch-sensitive parts of the measurement are native rather than
translated.

### The staged rootfs — what M8.4-d1 will actually ship

```
python-build-standalone CPython 3.12.14 (macos-aarch64)
  + uv pip install --require-hashes -r <lockfile>   34 pinned packages, 555 hashes
  = mlx 0.32.2 / mlx-metal 0.32.2 / mlx-lm 0.31.3 + closure
  NO model weights (weights are a PVC concern, never image content)
```

Three mechanical facts about that assembly, each of which M8.4-d1 must encode:

1. **`uv pip compile --generate-hashes` must NOT be given `--python-platform macos`.**
   Its default is macOS 13.0, for which **no `mlx` wheel exists** — mlx ships
   `macosx_14_0_arm64` and newer — so the lockfile is unsatisfiable:
   `Because mlx==0.32.2 has no wheels with a matching platform tag (e.g.
   macosx_13_0_arm64) … your requirements are unsatisfiable`. Compile the
   lockfile natively (or explicitly for macOS 14+ arm64).
2. **`uv python install` stamps its interpreters `EXTERNALLY-MANAGED`.** A copy
   of that dist refuses `uv pip install` with *"This Python installation is
   managed by uv and should not be modified"*. The image build must **delete
   `lib/python3.12/EXTERNALLY-MANAGED`** — not pass `--break-system-packages`,
   which would also silence a genuine misconfiguration.
3. **`--require-hashes` works end-to-end** against the S1 pin set with no
   exceptions or `--no-deps` escapes: 34 packages, 555 hashes, install to a
   working `Device(gpu, 0)` interpreter.

## A. Size — **PASS** (0.37 GB against the >2 GB threshold)

| | |
|---|---|
| unpacked, **apparent** | **391 945 KB = 0.37 GB** *(the number the threshold is about)* |
| unpacked, on-disk (allocated) | ~409 700 KB |
| entries | **7 963 files, 9 symlinks, 1 097 dirs** |
| **THRESHOLD >2 GB** | **PASS — 5.4× under budget** |
| OCI layout as emitted | **147 396 KB = 0.14 GB** (one layer blob, 150 933 138 B) |

Where the 0.37 GB lives — this is the pruning menu if a future engine blows the
budget, and nothing on it needs cutting today:

```
   206 696 KB  site-packages/mlx        (173.9 MB of it is ONE file: mlx.metallib)
    48 647 KB  site-packages/transformers
    21 796 KB  site-packages/numpy
    17 632 KB  bin/                     (python3.12, 17.2 MB)
     8 579 KB  site-packages/tokenizers
     7 662 KB  site-packages/hf_xet
     5 411 KB  site-packages/pip        <- prunable: nothing at runtime needs it
     4 675 KB  site-packages/pygments   <- prunable: rich/typer console prettiness
     3 436 KB  site-packages/sentencepiece
```

**`mlx.metallib` is 47 % of the whole image on its own** (182 351 120 B — the
precompiled Metal shader library). It is not prunable: it is what makes the S1
finding "no shader-cache write is needed" true, because the kernels are already
compiled. Treat it as the floor. Any future *pruning* exercise should start with
`pip`, `pygments` and `share/`, which together are under 3 % — i.e. pruning is
not a lever on this payload, and the plan's remediation branch is moot.

**Compression is worth 2.7×** on the wire: 401 352 401 B of files → a
150 933 138 B layer blob. See the defect section for why that is a finding
rather than a benefit.

## B. Cold start — **PASS** (3.2 s against the >1 min threshold)

Spawn → first token, measured inside the process against the parent's
pre-`exec` timestamp, from a **clonefiled** rootfs (i.e. the real per-pod
materialize path), model `Qwen2.5-0.5B-Instruct-4bit`. One discarded warm-up,
then three measured runs; the spread is under 30 ms.

| phase (cumulative from spawn) | unsandboxed | **under the S1 Seatbelt profile** |
|---|---|---|
| interpreter up | 0.01 s | 0.03 s |
| `import mlx_lm` | 0.81 s | 0.82 s |
| weights loaded | 1.08 s | 1.10 s |
| **FIRST TOKEN** | **1.21 s** | **3.19 s** |
| 12 tokens done | 1.26 s | 3.24 s |
| **THRESHOLD >1 min** | **PASS (19×)** | **PASS (19×)** |

**The one non-obvious number: Seatbelt costs ~2.1 s, and all of it lands between
"weights loaded" and "first token".** Import and model load are within noise of
unsandboxed (0.82 vs 0.81; 1.10 vs 1.08); the entire penalty is the **first Metal
operation** — device open through the two `iokit-open` user clients, pipeline
state setup. It is a **one-time per-process** cost, not a per-token one: the
remaining 11 tokens take 50 ms in both modes.

**Consequence for M8.5:** a readiness/health probe with an `initialDelaySeconds`
or `timeoutSeconds` tuned against an unsandboxed dev measurement will flap. Size
the first-token budget from the **sandboxed** column, and note it scales with
model size only in the "weights loaded" term — the ~2.1 s Metal-init term is
model-independent.

**Honest limit on "cold".** Dropping the page cache needs root, which the M8.0
lab guardrails forbid, so **both columns are warm-page-cache**. They therefore
measure *process* cold start, not *first-pull-on-a-fresh-node* cold start. The
threshold is still cleared by 19× with the entire disk-read term at zero, so the
verdict is safe: a genuinely cold read of 0.37 GB would have to run at under
6 MB/s to reach 60 s. It does **not** license a claim about first-pull latency,
which is dominated by the network fetch of the 0.14 GB layer.

## C. Ad-hoc tree-sign cost — **negligible, and S2's arch-aware rule is confirmed exactly**

Measured on a clone so the stage stays pristine.

| pass | cost |
|---|---|
| Mach-O discovery walk (`file` over 7 963 files) | **8.4 s**, finds **41 Mach-Os** |
| verify, both spellings, 41 files × 2 | **1.87 s** (~23 ms per file per pass) |
| unconditional re-sign all 41 (`codesign -f -s -`) | **0.67 s** (16.4 ms/file) |
| signed clone still execs | `Device(gpu, 0)` |

**41 Mach-Os — the exact count S2 measured** across `venv/` + `pyinstall/`,
reproduced here on an independently assembled tree (and internally consistent:
S5 counts 30 in the mlx-lm venv alone, plus S2's 11 in the CPython dist). S2's
"41 is an M8.0 datum, not an M8.4 budget" caveat is discharged **for this
payload** — and **findings-s5.md re-opens it with the number**: the chosen engine
brings the tree to ~353 Mach-Os over ~36 000 entries, which is where the walk
cost below stops being a footnote.

**S2's binding consequence is confirmed with a clean signal, not a muddied one:**

```
  invalid: arch-aware=0   whole-file=1
    INVALID_WHOLE_FILE  site-packages/google/_upb/_message.abi3.so
```

Exactly one file, exactly the fat `google/_upb/_message.abi3.so` S2 characterized
(x86_64 slice unsigned, arm64 slice valid). `codesign -v --arch arm64` reports it
**valid**; bare `codesign -v` reports it **invalid**. So a whole-file check would
re-sign one file per tree that needs no signing — de-CoWing it, which is what
Res. 13's check-then-sign-only-if-invalid clause exists to prevent.
**`AdHocSignTree` must verify with `--arch <native>`.**

**The cost shape is the useful finding, and it is the opposite of what the plan
budgeted for.** Signing is *free* (0.67 s worst case); **finding** the Mach-Os
costs 12× more (8.4 s) because it is a `file(1)` exec per candidate over 7 963
files. A Go implementation reading the 4-byte Mach-O magic itself collapses that
to a single tree walk. Budget the walk, not the signature.

**Mechanization trap, recorded because it cost a measurement cycle here:**
`file(1)` emits **three** lines for a universal binary (`<p>: Mach-O universal
…`, then one `<p> (for architecture …):` line per slice) and pads the description
with spaces *after* the colon. Naively stripping at the last colon produced two
phantom paths and two spurious `SIGN_FAIL`s. The script now splits at the first
colon and keeps only fields that are a real file.

## D. clonefile — per-pod materialize is **1.2 s and ~zero bytes**

| | time | used-KB delta |
|---|---|---|
| `cp -Rc` (clonefile) ×3 | **1.20 / 1.21 / 1.19 s** | −15 100 / +3 112 / +2 808 (noise — the filesystem moves more than the clone does) |
| `cp -R` (byte copy) | 1.68 s | **+410 596** |

A 0.37 GB tree materializes in **1.2 s at zero marginal disk**, versus 401 MB for
a byte copy. Consistent with S2's 330 MB / 1.00 s measurement on a different
tree, and the ratio confirms the dominant cost is **inode creation over ~9 000
entries**, not data — 1.2 s for 9 069 entries is ~130 µs/entry, and the byte copy
adds only 0.5 s for 401 MB.

**Per-pod materialize budget: 1.2 s clone + 3.2 s to first token ≈ 4.4 s.** Both
terms scale with entry count and model size respectively, neither with image
bytes.

## E. Per-pod rootfs write amplification — **9 files, 37 KB** (a new number the plan did not ask for)

Every byte a pod writes *inside* its cloned rootfs breaks CoW sharing with every
other pod on the node. Measured after four starts:

```
  9 files, 37 732 bytes CoW-broken
    site-packages/mlx_lm/models/__pycache__/qwen2.cpython-312.pyc
    site-packages/transformers/models/qwen2/__pycache__/configuration_qwen2.cpython-312.pyc
    …
  staged tree already ships 674 precompiled .pyc in 82 __pycache__ dirs
```

All nine are `__pycache__` bytecode for the **model-architecture modules the
lockfile could not know would be imported** — `qwen2.py` and friends are loaded
by name at model-load time. 37 KB is negligible in itself; the finding is the
*shape*: **the amount is a function of which model runs**, so a node serving many
architectures accumulates a little private state per pod, and a **read-only
rootfs would make the interpreter fail to write and fall back to recompiling on
every start** (~0.8 s of the import phase).

**Recommendation for M8.4-d1:** either ship `PYTHONDONTWRITEBYTECODE=1` in the
image `ENV` and accept the recompile, or (better) run `compileall` over
site-packages at build time so the count goes to zero and the tree stays fully
shared. The latter is one build-script line and keeps the import phase at 0.8 s.

*(This one also bit the harness: the strict-tar-reader probe's own
`import tarfile` dropped a `.pyc` into the staged tree between the build and the
comparison, turning `PREMISE_CONTENT` red for a reason that had nothing to do
with the image. Every measurement-side use of the staged interpreter now runs
`-B` with `PYTHONDONTWRITEBYTECODE=1`.)*

## F. THE PACKAGING PREMISE — **PASS**

```
k3sm build --file <df> --tag mlx-serve:s4 --format oci --output <dir> <stage>
  rc=0  3.9 s     config: os=darwin arch=arm64 variant=v8 entrypoint=['/bin/python3.12']
```

Dockerfile (the Dockerfile lives **outside** the context so `COPY . /` cannot
absorb it):

```dockerfile
FROM scratch
COPY . /
ENTRYPOINT ["/bin/python3.12"]
```

### Symlinks — all 9, byte-for-byte

```
  source symlinks: 9   unpacked symlinks: 9
    OK  bin/2to3                       -> 2to3-3.12
    OK  bin/idle3                      -> idle3.12
    OK  bin/pydoc3                     -> pydoc3.12
    OK  bin/python                     -> python3.12
    OK  bin/python3                    -> python3.12
    OK  bin/python3-config             -> python3.12-config
    OK  lib/pkgconfig/python3-embed.pc -> python-3.12-embed.pc
    OK  lib/pkgconfig/python3.pc       -> python-3.12.pc
    OK  share/man/man1/python3.1       -> python3.12.1
  MISSING=0 DEMOTED_TO_FILE=0 TARGET_MISMATCH=0 INVENTED=0
  PREMISE_SYMLINKS=PASS
```

The four failure modes are checked **separately and by name**, because they have
different causes and only one of them is visible in a count: a symlink dropped
(`MISSING`), a symlink **dereferenced into a copy of its target** (`DEMOTED`,
the silent one — entry counts still match and the image still works, just fatter
and no longer describing the recipe), a preserved symlink pointing somewhere
else (`TARGET_MISMATCH`), and a symlink the builder synthesized (`INVENTED`).
All four are zero.

### Contents — whole-tree digest, not a count

```
  regular files: src=7963 dst=7963   dirs: src=1097 dst=1097
  content digest src=9fd6d791651b4668758e22caa8d8a8a28f85ec89ef923af1f72d4a0acce871b9
  content digest dst=9fd6d791651b4668758e22caa8d8a8a28f85ec89ef923af1f72d4a0acce871b9
  PREMISE_CONTENT=PASS
```

A sha256 over every `(path, sha256(body))` pair, so a truncated or substituted
file cannot hide behind a matching entry count.

### And it runs, *through* the symlink

```
  bin/python3 -> python3.12
  unpacked-tree exec via bin/python3 SYMLINK: OK Device(gpu, 0)
```

A byte-identical tree whose interpreter will not exec is still a broken image, so
the unpacked rootfs was executed via the symlink and reached the GPU.

### Reproducibility

Two builds of the same context and Dockerfile: **IDENTICAL** manifest digest
`sha256:c97691ca…`. That is M8.4-d1's "builds reproducibly from the lockfile"
gate in miniature — with the caveat in the defect section below.

### Negative controls — one build per symlink SHAPE

The premise is only as good as the shapes it was tested against, so each was
built on its own (a single mixed context reports whichever failure the walk hits
first, which is how the first attempt mistook the dangling link for the absolute
one):

| shape | rc | builder's verdict |
|---|---|---|
| `rel.txt -> real.txt` (relative, in-context) | **0** | built |
| `abs.txt -> <abs>/real.txt` (absolute, target in-context) | **1** | `"abs.txt" targets the absolute path …: invalid entry name` |
| `dangling.txt -> nowhere.txt` | **1** | `COPY ".": source not found in the build context` |
| `escape.txt -> ../../../etc/hosts` | **1** | `COPY ".": source not found in the build context` |

**Binding for M8.4-d1:** the builder accepts **relative, resolvable, in-context**
symlinks and **nothing else**. This is not hypothetical for this payload — `uv
python install` maintains a version-alias symlink
(`cpython-3.12-macos-aarch64-none → <absolute> cpython-3.12.14-macos-aarch64-none`)
**one level above** the dist dir. Stage the **resolved versioned directory**, never
`pyinstall/` itself, or the build fails on `invalid entry name`. The staging step
in `s4.sh` does exactly that.

A second consequence: **the dangling and escaping cases both report
`source not found in the build context`, naming `"."` rather than the offending
link.** On a 7 963-file tree that is a poor diagnostic. Worth a follow-up so the
error names the entry — but it is a message defect, not a behavior defect, and
the behavior (refuse) is right.

## The layer-format defect — **gzip bytes under an uncompressed mediaType**

Found while proving the premise. **This is a prerequisite for M8.4, and it is a
`pkg/oci` bug, not an S4 threshold failure.**

```
  layer[0] DECLARED mediaType=application/vnd.oci.image.layer.v1.tar size=150933138
      manifest digest =sha256:3c97e3bb28bec7fd297fb0d128094e9554ce9e534081e10921e97baaebcee1c3
      config diff_id  =sha256:af250aa74d7c000e4dc904141c1237b8bfa490386d5229e0c7100e948432288f
      ACTUAL bytes    =gzip compressed data, max speed, original size modulo 2^32 408062464
      sha256 as-is    =3c97e3bb28bec7fd297fb0d128094e9554ce9e534081e10921e97baaebcee1c3
      sha256 gunzipped=af250aa74d7c000e4dc904141c1237b8bfa490386d5229e0c7100e948432288f
      LAYER_FORMAT=MISLABELLED (gzip bytes under an UNCOMPRESSED mediaType)
      STRICT_TAR_READ=FAIL ReadError: invalid header
```

Read that carefully — the image is **internally consistent as a gzip layer** and
**mislabelled by exactly one string**:

- the manifest's layer `digest` is the sha256 of the **gzip** bytes (matches);
- the config's `rootfs.diff_ids[0]` is the sha256 of the **gunzipped tar** (matches);
- the declared `mediaType` is `application/vnd.oci.image.layer.v1.tar`, i.e. the
  **uncompressed** OCI type. The correct string for these bytes is
  `application/vnd.oci.image.layer.v1.tar+gzip`.

The `--format docker` sink emits the same blob and even *names* it
`<digest>.tar.gz` inside the save tarball, so the label is wrong in the OCI
layout specifically.

**Why the round-trip above still passed:** macOS `tar` is bsdtar, which **sniffs**
the gzip magic and transparently decompresses regardless of what any manifest
says. A reader that trusts the mediaType does not:

```
  STRICT_TAR_READ=FAIL ReadError: invalid header      # tarfile.open(mode="r:")
```

**Why it matters concretely.** `runtimed/pkg/image/load.go` opens every archive
layer with **`open: layer.Compressed`** and hands the reader to
`LayerApplier.Apply`, which does `tar.NewReader` — and `runtimed` contains **no
gzip decompression anywhere**. `Apply` has no production caller yet (the puller
lands with the OCI-layer unpacker), so **the bug is latent, not live** — which is
precisely why recording it now is worth more than finding it during M8.4
integration.

**Root cause.** `pkg/oci/layer.go:103` calls
`tarball.LayerFromFile(staged, tarball.WithMediaType(types.OCIUncompressedLayer))`.
`WithMediaType` sets the **reported** media type only; go-containerregistry still
computes `Digest()` over `Compressed()`, i.e. it gzips a tar it was not told to
leave alone. The call site's own comment states the opposite intent — *"Uncompressed:
the digest then depends only on this package's tar output, never on compress/flate's
byte-level behavior, which carries no cross-version compatibility promise"* — so
the code and its comment disagree, and the comment is the design.

**A second consequence the code comment already predicted.** Because the digest
is taken over gzip output, the emitted digest **does** depend on `compress/flate`'s
byte-level behavior. The IDENTICAL-digest result above was two builds of one
binary; it is **not** evidence of reproducibility across Go toolchain versions,
which is exactly the property the comment was protecting and exactly what
M8.4-d1's "builds reproducibly from the lockfile" gate will be read to mean. Do
not cite this spike's IDENTICAL result as cross-toolchain reproducibility.

**Two acceptable fixes, one decision:**

1. **Emit genuinely uncompressed layers** (keep the declared type): build the
   ggcr layer from a `static`/`stream` layer whose `Compressed()` is the tar
   itself, so digest == diffID and the comment's reproducibility argument holds.
   Costs 2.7× on pull (0.37 GB instead of 0.14 GB) — still well inside budget.
2. **Declare `…tar+gzip`** and keep the compression. Cheaper on the wire; gives
   up the cross-toolchain digest-stability property the comment argues for.

Either way the unpacker must be verified against the choice. **This is on the
critical path for M8.4-d2's digest-pinned publish** — a digest that is not stable
across toolchains cannot be pinned, and a mislabelled layer will not be pulled by
a spec-conformant client.

## What W4's builder must do differently

1. **No pruning.** 0.37 GB and 3.2 s clear both thresholds by ~5× and ~19×. The
   remediation branch does not fire.
2. **Fix or re-declare the layer mediaType before M8.4-d1 lands** — and verify
   the unpacker against the choice. `runtimed` has no gunzip path today.
3. **`AdHocSignTree` verifies per-arch** (`--arch <native>`), confirmed again on
   an independent tree: 0 invalid arch-aware, 1 invalid whole-file, same file.
4. **Budget the Mach-O *walk*, not the signature** — 8.4 s vs 0.67 s here, and
   the walk is `file(1)`-per-file; read the magic in Go instead. Against the S5
   engine decision this is no longer optional: ~353 Mach-Os over ~36 000 entries
   puts the same walk near 38 s. (Also: run any such walk under `LC_ALL=C` — a
   UTF-8 `awk` aborts on the first invalid byte in a binary blob, SIGPIPEs
   `file(1)`, and silently **truncates** the count. Observed on the S5 trees: 1
   Mach-O reported for a 1 GB payload.)
5. **Stage the RESOLVED versioned interpreter directory.** The builder refuses
   absolute, dangling and escaping symlinks; `uv`'s alias symlink is absolute.
6. **Strip `lib/python3.12/EXTERNALLY-MANAGED`** from the staged dist, and
   **compile the lockfile natively** (never `--python-platform macos`).
7. **`compileall` at build time, or `PYTHONDONTWRITEBYTECODE=1` in the image ENV** —
   otherwise every pod CoW-breaks ~9 files of `__pycache__`, and the set depends
   on which model runs.
8. **Size M8.5's readiness probe off the SANDBOXED first-token number.** Seatbelt
   adds ~2.1 s, all of it one-time Metal device/pipeline init, none of it
   per-token.
