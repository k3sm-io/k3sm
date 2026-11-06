#!/usr/bin/env python3
"""Make one variant of a rendered sandbox profile for the removal and addition measurement.

Usage:
  variant.py IN OUT [--remove TEXT]... [--add TEXT]
  variant.py --self-test

Every --remove must match the profile text exactly, or the run stops: a removal
that matched nothing would be recorded as "not load-bearing" when nothing was
removed. Removals are applied first, the addition is appended last under a
marker comment, so the measured profile reads as the shipped one plus one edit.
"""
import argparse
import sys

MARK = ";; VARIANT, measured and not shipped\n"


def edit(text, removals, addition):
    for r in removals:
        if not r or r not in text:
            raise ValueError("removal does not match the profile: %r" % (r[:60],))
        text = text.replace(r, "", 1)
    if addition:
        text = text.rstrip("\n") + "\n" + MARK + addition + "\n"
    return text


def self_test():
    base = '(version 1)\n(deny default)\n(allow a)\n(allow b)\n'
    assert edit(base, [], "") == base
    assert edit(base, ["(allow a)\n"], "") == '(version 1)\n(deny default)\n(allow b)\n'
    got = edit(base, [], "(allow c)")
    assert got.endswith(MARK + "(allow c)\n") and got.startswith(base)
    for bad in (["(allow z)"], [""]):
        try:
            edit(base, bad, "")
        except ValueError:
            continue
        raise AssertionError("an unmatched removal was accepted: %r" % (bad,))
    print("variant.py self-test ok")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return 0
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("out")
    ap.add_argument("--remove", action="append", default=[])
    ap.add_argument("--add", default="")
    a = ap.parse_args()
    with open(a.src) as f:
        text = f.read()
    try:
        text = edit(text, a.remove, a.add)
    except ValueError as e:
        print("variant.py: %s" % e, file=sys.stderr)
        return 1
    with open(a.out, "w") as f:
        f.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
