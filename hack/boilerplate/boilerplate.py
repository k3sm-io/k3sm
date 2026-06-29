#!/usr/bin/env python3
# boilerplate.py — k3sm per-file Apache-2.0 license-header check/apply.
#
# Adapted from the Kubernetes hack/boilerplate verifier (Apache License 2.0, The
# Kubernetes Authors). Checks — or with --apply, inserts — the canonical header in
# the sibling boilerplate.go.txt at the top of every .go file, placed BELOW any
# //go:build constraint block (so gofmt keeps the build tag on line 1) and above
# the package clause. Generated files (*.pb.go, zz_generated*, and any file marked
# "// Code generated ... DO NOT EDIT.") are excluded. The same header source drives
# both check and apply, so the gate and the sweep can never disagree.
import argparse
import os
import sys

SKIP_DIRS = {".git", "vendor", "testdata", "node_modules"}


def is_generated(path, text):
    base = os.path.basename(path)
    if base.endswith(".pb.go") or base.endswith("_grpc.pb.go"):
        return True
    if base.startswith("zz_generated") or ".zz_generated." in base:
        return True
    for line in text.splitlines()[:5]:
        if line.startswith("// Code generated") and "DO NOT EDIT" in line:
            return True
    return False


def split_buildtags(lines):
    """Return (preamble, rest): the leading //go:build / // +build block (with any
    interleaved/trailing blank lines), only when the file STARTS with a build
    constraint; otherwise ([], lines)."""
    if lines and (lines[0].startswith("//go:build") or lines[0].startswith("// +build")):
        i, n = 0, len(lines)
        while i < n and (
            lines[i].startswith("//go:build")
            or lines[i].startswith("// +build")
            or lines[i].strip() == ""
        ):
            i += 1
        return lines[:i], lines[i:]
    return [], lines


def main():
    ap = argparse.ArgumentParser(description="k3sm license-header check/apply")
    ap.add_argument("--rootdir", default=".")
    ap.add_argument("--apply", action="store_true", help="insert the header where missing")
    args = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    header = open(os.path.join(here, "boilerplate.go.txt")).read().rstrip("\n") + "\n"

    missing, changed = [], []
    for dirpath, dirnames, filenames in os.walk(args.rootdir):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in sorted(filenames):
            if not fn.endswith(".go"):
                continue
            path = os.path.join(dirpath, fn)
            with open(path) as f:
                text = f.read()
            if is_generated(path, text):
                continue
            preamble, rest = split_buildtags(text.splitlines(keepends=True))
            rest_text = "".join(rest)
            if rest_text.lstrip("\n").startswith(header):
                continue
            if args.apply:
                pre = "".join(preamble).rstrip("\n")
                body = rest_text.lstrip("\n")
                new = (pre + "\n\n" if pre else "") + header + "\n" + body
                with open(path, "w") as f:
                    f.write(new)
                changed.append(path)
            else:
                missing.append(path)

    if args.apply:
        print(f"boilerplate: inserted header into {len(changed)} file(s)")
        return 0
    if missing:
        print("boilerplate: missing license header in:")
        for m in missing:
            print("  " + m)
        print(f"\n{len(missing)} file(s) missing the header. Run: hack/verify-boilerplate.sh --apply")
        return 1
    print("boilerplate: all .go files carry the license header")
    return 0


if __name__ == "__main__":
    sys.exit(main())
