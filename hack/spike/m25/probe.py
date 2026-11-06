#!/usr/bin/env python3
"""probe.py <port> <cmd>: stdlib client on 127.0.0.1. cmds: wait [secs]; smoke; prompt-over <ntok>; imageurl <listen-port>; concurrent <n>; get <path>"""
import json, sys, time, threading, urllib.request as u, urllib.error as e
port = sys.argv[1]; cmd = sys.argv[2]; base = "http://127.0.0.1:%s" % port
OP = u.build_opener(u.ProxyHandler({}))
def get(p, to=5):
    try:
        r = OP.open(base + p, timeout=to); return r.status, r.read().decode(errors="replace")
    except e.HTTPError as x: return x.code, x.read().decode(errors="replace")
def post(p, body, to=120):
    q = u.Request(base + p, json.dumps(body).encode(), {"Content-Type": "application/json"})
    try:
        r = OP.open(q, timeout=to); return r.status, r.read().decode(errors="replace")
    except e.HTTPError as x: return x.code, x.read().decode(errors="replace")
MSG = [{"role": "user", "content": "/no_think Name three primary colors."}]
if cmd == "wait":
    lim = float(sys.argv[3]) if len(sys.argv) > 3 else 90; t0 = time.time(); last = None
    while time.time() - t0 < lim:
        try: s = get("/health", 2)
        except Exception as x: s = ("conn", type(x).__name__)
        if s != last: print("health %+.2fs %s %s" % (time.time() - t0, s[0], str(s[1])[:160])); last = s
        if s[0] == 200: print("READY %.2fs" % (time.time() - t0)); sys.exit(0)
        time.sleep(0.05)
    print("NOT_READY"); sys.exit(1)
if cmd == "smoke":
    t0 = time.time(); s, b = post("/v1/chat/completions", {"model": "x", "messages": MSG, "max_tokens": 48, "temperature": 0, "seed": 1}, 180)
    try:
        d = json.loads(b); print("chat", s, "%.2fs" % (time.time() - t0), json.dumps(d["choices"][0]["message"].get("content"))[:150]); print("timings", {k: round(v, 1) for k, v in d.get("timings", {}).items() if k in ("prompt_per_second", "predicted_per_second", "predicted_n", "prompt_n")}); print("usage", d.get("usage"))
    except Exception: print("chat", s, b[:400])
elif cmd == "get":
    s, b = get(sys.argv[3]); print(s, b[:int(sys.argv[4]) if len(sys.argv) > 4 else 2000])
elif cmd == "prompt-over":
    n = int(sys.argv[3]); txt = "word " * n
    for nm, path, body in (("chat", "/v1/chat/completions", {"model": "x", "messages": [{"role": "user", "content": txt}], "max_tokens": 8}), ("completion", "/completion", {"prompt": txt, "n_predict": 8})):
        s, b = post(path, body); print(nm, s, b[:500])
elif cmd == "imageurl":
    lp = sys.argv[3]
    for url in ("http://127.0.0.1:%s/probe.png" % lp, "https://example.invalid/x.png"):
        s, b = post("/v1/chat/completions", {"model": "x", "max_tokens": 4, "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}, {"type": "image_url", "image_url": {"url": url}}]}]}); print(url, s, b[:400])
elif cmd == "concurrent":
    n = int(sys.argv[3]); out = [None] * n; ts = [None] * n
    def w(i):
        t = time.time(); s, b = post("/v1/chat/completions", {"model": "x", "messages": [{"role": "user", "content": "/no_think Count from %d upward, one number per line." % (i + 1)}], "max_tokens": 64, "temperature": 0}, 180)
        ts[i] = time.time() - t
        try: d = json.loads(b); out[i] = (s, d["usage"]["completion_tokens"], round(d["timings"]["predicted_per_second"], 1), d["choices"][0]["finish_reason"], round(ts[i], 2))
        except Exception: out[i] = (s, b[:200], round(ts[i], 2))
    th = [threading.Thread(target=w, args=(i,)) for i in range(n)]; [t.start() for t in th]; [t.join() for t in th]
    for o in out: print(o)
    print("all200", all(o[0] == 200 for o in out))
