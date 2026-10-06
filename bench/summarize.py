#!/usr/bin/env python3
"""Collect wrk/vegeta outputs from a bench/run.sh result directory into a Markdown table."""
import re, sys, pathlib

def num(s):
    m = re.match(r"([\d.]+)\s*([kKMGmu]?s?)", s)
    return m.group(0) if m else s

def parse_wrk(p):
    t = p.read_text()
    g = lambda pat: (re.search(pat, t) or [None, "-"])[1]
    return {
        "rps": g(r"Requests/sec:\s+([\d.]+)"),
        "xfer": g(r"Transfer/sec:\s+(\S+)"),
        "p50": g(r"\s50%\s+(\S+)"),
        "p99": g(r"\s99%\s+(\S+)"),
        "err": "yes" if re.search(r"Non-2xx|Socket errors", t) else "",
    }

def main(d):
    d = pathlib.Path(d)
    names = sorted({p.name.split(".")[0] for p in d.glob("*.wrk.txt")})
    print("### wrk (throughput)\n")
    print("| scenario | server | req/s | transfer/s | p50 | p99 | errors |")
    print("|---|---|---:|---:|---:|---:|---|")
    for n in names:
        res = {s: parse_wrk(d / f"{n}.{s}.wrk.txt") for s in ("vajra", "nginx") if (d / f"{n}.{s}.wrk.txt").exists()}
        for s, r in res.items():
            print(f"| {n} | {s} | {float(r['rps']):,.0f} | {r['xfer']} | {r['p50']} | {r['p99']} | {r['err']} |" if r["rps"] != "-" else f"| {n} | {s} | - | - | - | - | |")
        if len(res) == 2 and all(r["rps"] != "-" for r in res.values()):
            ratio = float(res["vajra"]["rps"]) / float(res["nginx"]["rps"])
            print(f"| {n} | **vajra / nginx** | **{ratio:.2f}x** | | | | |")
    vs = sorted(d.glob("vegeta.*.txt"))
    vs = [p for p in vs if "hist" not in p.name]
    if vs:
        print("\n### vegeta (fixed rate)\n")
        for p in vs:
            print(f"**{p.name.split('.')[1]}**\n\n```\n{p.read_text().strip()}\n```\n")

main(sys.argv[1] if len(sys.argv) > 1 else ".")
