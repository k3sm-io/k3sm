# S2 — nested-dylib signing under AMFI (M8.0-d2) — **PASS**

> **Verdict: PASS.** No redesign consequence fires (the M8 plan Res. 17 S2 is
> terminal-or-redesign). Signatures survive `clonefile`, the cloned tree execs
> both unsandboxed and under the S1 Seatbelt profile, and the one file the walk
> flags is a *known, characterized* class that `AdHocSignTree` must handle.

Run: 2026-08-29 on the S1 rig (M1 Ultra, macOS 26.5.2 / (redacted)). Re-run with
`hack/spike/m8/s2.sh`.

## The walk

Tree walked with `file -b` as the Mach-O discriminator (a `.so`/`.dylib`
extension is neither necessary nor sufficient in a wheel tree), then classified
by `codesign -dvvv` / `codesign -v`.

| tree | files | Mach-O | linker-ad-hoc | Developer-ID | unsigned | **INVALID** |
|---|---|---|---|---|---|---|
| `venv/` (the wheel payload — mlx, mlx-metal, numpy, tokenizers, safetensors, regex, hf_xet, markupsafe, protobuf) | 6165 | **30** | 29 | 0 | 0 | **1** |
| `pyinstall/` (CPython 3.12.14, the python-build-standalone analog) | 1828 | **11** | 11 | 0 | 0 | 0 |
| **total** | 7993 | **41** | **40** | **0** | **0** | **1** |

Two facts M8.4 depends on, both confirmed:

- **Wheels arrive linker-ad-hoc-signed.** 40 of 41 carry
  `flags=0x20002(adhoc,linker-signed)` — the arm64 linker signs every Mach-O it
  emits. `LC_CODE_SIGNATURE` is present before k3sm touches anything.
- **Nothing carries a Developer-ID / team identity.** `SIGNED_IDENTITY=0` across
  both trees. There is no upstream signature for k3sm to preserve or to conflict
  with, so ad-hoc re-signing a whole tree is a free action, not a downgrade.

The absolute count is small (**41 Mach-Os**, not "hundreds") because mlx-lm is
pure Python and the engine is two dylibs. **The S5 winner will change this
number** — vllm-mlx/oMLX pull a much heavier dependency set — so M8.4's
walk-verify must be mechanized (it is: `s2walk.sh` here is the shape), not
eyeballed against 41.

## The one INVALID file — and it is the interesting one

```
/…/site-packages/google/_upb/_message.abi3.so
  Architectures in the fat file: x86_64 arm64
  arch x86_64: code object is not signed at all
  arch arm64:  VALID
```

A **universal (fat) Mach-O whose arm64 slice is validly ad-hoc signed and whose
x86_64 slice is not signed at all.** A bare `codesign -v` (no `--arch`) reports
"code object is not signed at all" for the whole file, which is why the naive
tally calls it INVALID — and why the naive tally is misleading.

**Binding consequence for `AdHocSignTree` (M8.2-d3): it must be arch-aware.**

- A whole-file `codesign -v` verdict is **not** a usable signal on a fat binary:
  it fails on a file whose native slice is perfectly valid, and would drive an
  unnecessary re-sign (which de-CoWs the file — precisely the invariant Res. 13's
  `gateSignature` check-then-sign-only-if-invalid clause exists to protect).
- The check must be `codesign -v --arch <native>`, or the re-sign must cover the
  whole fat file. Verifying the *native* slice is the cheaper and correct rule:
  the x86_64 slice is never executed on a Darwin/arm64 pod.
- This is not an exotic case. Any manylinux/macos universal2 wheel in the
  dependency closure has the same shape, and the S5 winner will bring more.

## clonefile — signatures and exec

| measurement | value |
|---|---|
| tree size | 330 MB (338 160 KB apparent) |
| `cp -Rc` (clonefile) | **1.00 s**, free-space delta **+2 168 KB** (noise; a second run measured **−7 860 KB**) |
| `cp -R` (byte copy) | **1.53 s**, free-space delta **340 912 KB** |
| signing tally after clone | `FILES=6165 MACHO=30 ADHOC=29 SIGNED_IDENTITY=0 UNSIGNED=0 INVALID=1` — **identical to the source** |
| exec from clone, unsandboxed | `TOKENS_OK` |
| exec from clone, **under the S1 Seatbelt profile** | `TOKENS_OK` |

- **Signatures survive `clonefile` unchanged** — the tally is byte-for-byte the
  same before and after, and the fat-binary INVALID reproduces identically
  (i.e. clonefile is not the cause of it).
- **The clone is genuinely CoW**: a 330 MB tree costs ~0 bytes of disk and 1.00 s
  versus 340 MB and 1.53 s for a byte copy. The dominant clone cost is directory
  walk / inode creation over 6165 files, not data.
- **AMFI executes the cloned Mach-Os without re-signing.** No re-sign was
  performed between clone and exec in either the unsandboxed or the sandboxed
  run. The ad-hoc signature is content-addressed and the clone is the same
  content, so AMFI's page-hash validation passes on the clone.

## What W4's builder must know

1. **`AdHocSignTree` must verify per-arch** (`codesign -v --arch <native>`), or
   fat binaries with an unsigned foreign slice will be re-signed every start —
   de-CoWing argv[0] and its dylibs, which is exactly what Res. 13's
   check-then-sign-only-if-invalid clause forbids.
2. **The walk needs `file -b`, not a suffix match.** Extensions in a wheel tree
   are unreliable in both directions.
3. **A clone-then-exec needs no signing step at all** for a tree that arrives
   linker-signed. `AdHocSignTree`'s job is the *arrival* path (a tree unpacked
   from OCI layers, where `LC_CODE_SIGNATURE` survived the tar but the file may
   have been produced by a non-linker path), not the per-pod materialize.
4. **41 Mach-Os is an M8.0 datum, not an M8.4 budget.** Re-measure against the
   S5 winner's wheel set before sizing the tree-sign cost (that is S4's job).
