#!/usr/bin/env python3
"""A digest of a source checkout, taken so the tree that was built is the tree that was pinned.

Usage: python3 -I source_digest.py ROOT

Prints the digest and the file count. The walk is lstat-based and never follows
a link. It refuses, with a non-zero exit, a nested .git, a .gitmodules that is
not a zero-length regular file, a gitlink (mode 160000) in HEAD's tree, a FIFO,
socket or device, and two names that differ only by case. A zero-length
.gitmodules is hashed as an ordinary file.
"""
import hashlib, os, stat, subprocess, sys
root = os.fsencode(sys.argv[1]); recs = []; seen = {}
def die(m): sys.exit("REFUSE: %r" % (m,))
if os.path.lexists(os.path.join(root, b".git")):
    out = subprocess.run(["git", "-C", os.fsdecode(root), "ls-tree", "-r", "-z", "HEAD"],
                         check=True, stdout=subprocess.PIPE).stdout
    ents = [e for e in out.split(b"\0") if e]
    links = [e for e in ents if e.startswith(b"160000 ")]
    print("git ls-tree -r HEAD: entries=%d gitlinks=%d" % (len(ents), len(links)))
    if links: die(("gitlink", links[0]))
for d, dirs, files in os.walk(root, followlinks=False):
    rel = os.path.relpath(d, root)
    for n in list(dirs) + files:
        p = os.path.join(d, n); r = os.path.normpath(os.path.join(rel, n)); st = os.lstat(p)
        if n == b".git":
            if d == root: continue
            die(r)
        if n == b".gitmodules" and not (stat.S_ISREG(st.st_mode) and st.st_size == 0): die(r)
        k = r.lower()
        if k in seen and seen[k] != r: die((r, seen[k]))
        seen[k] = r
        if stat.S_ISLNK(st.st_mode):
            recs.append((r, b"120000", hashlib.sha256(os.readlink(p)).hexdigest()))
        elif stat.S_ISREG(st.st_mode):
            h = hashlib.sha256()
            with open(p, "rb") as f:
                for c in iter(lambda: f.read(1 << 20), b""): h.update(c)
            recs.append((r, b"100755" if st.st_mode & 0o111 else b"100644", h.hexdigest()))
        elif stat.S_ISDIR(st.st_mode): pass
        else: die(r)
    if d == root and b".git" in dirs: dirs.remove(b".git")
recs.sort(key=lambda x: x[0]); out = hashlib.sha256()
for r, m, h in recs: out.update(m + b" " + h.encode() + b" " + r + b"\0")
print(out.hexdigest(), len(recs))
