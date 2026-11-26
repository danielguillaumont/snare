"""Summarize `go test -bench -count N` output: median ns/op with min-max range, per benchmark.

    python bench/summarize.py bench/token-before.txt [bench/token-after.txt]

With two files it prints both medians and the speed-up. Standard library only.
"""
import re
import statistics
import sys

LINE = re.compile(r"^(Benchmark\S+?)(?:-\d+)?\s+\d+\s+([\d.]+) ns/op(?:.*?\s([\d.]+) B/op\s+(\d+) allocs/op)?")


def load(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        m = LINE.match(line)
        if m:
            out.setdefault(m.group(1), []).append(float(m.group(2)))
    return out


def fmt(ns):
    for unit, div in (("ms", 1e6), ("µs", 1e3)):
        if ns >= div:
            return f"{ns / div:.3g} {unit}"
    return f"{ns:.3g} ns"


def cell(v):
    return f"{fmt(statistics.median(v))} ({fmt(min(v))}–{fmt(max(v))}, n={len(v)})"


a = load(sys.argv[1])
b = load(sys.argv[2]) if len(sys.argv) > 2 else None
if b is None:
    print("| Benchmark | Median (min–max, runs) |\n|---|---|")
    for k, v in a.items():
        print(f"| `{k}` | {cell(v)} |")
else:
    print("| Benchmark | Before | After | Speed-up |\n|---|---|---|---|")
    for k, v in a.items():
        if k in b:
            print(f"| `{k}` | {cell(v)} | {cell(b[k])} | {statistics.median(v) / statistics.median(b[k]):.1f}× |")
