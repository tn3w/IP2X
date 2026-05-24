#!/usr/bin/env python3
import argparse
import bisect
import ipaddress
import socket
import struct
import sys
from pathlib import Path

import numpy as np

TSV_FILES = ("isp", "domain", "last_seen", "provider", "fraud_score")
BUCKET_FILES = ("usage", "threat")
NETSET_FILE = "proxy_pub.netset"


def _ip_to_int(s: str) -> tuple[int, bool]:
    if ":" in s:
        return int.from_bytes(socket.inet_pton(socket.AF_INET6, s), "big"), True
    return struct.unpack("!I", socket.inet_aton(s))[0], False


def _parse_range(token: str) -> tuple[int, int, bool]:
    if "+" in token:
        ip_s, span_s = token.split("+", 1)
        start, is_v6 = _ip_to_int(ip_s)
        return start, start + int(span_s), is_v6
    start, is_v6 = _ip_to_int(token)
    return start, start, is_v6


def _parse_cidr(token: str) -> tuple[int, int, bool]:
    if "/" in token:
        ip_s, prefix_s = token.split("/", 1)
        start, is_v6 = _ip_to_int(ip_s)
        prefix = int(prefix_s)
        width = 128 if is_v6 else 32
        size = 1 << (width - prefix)
        return start, start + size - 1, is_v6
    start, is_v6 = _ip_to_int(token)
    return start, start, is_v6


def _split_ranges(rows: list[tuple[int, int, object]]):
    rows.sort(key=lambda r: r[0])
    starts = [r[0] for r in rows]
    ends = [r[1] for r in rows]
    vals = [r[2] for r in rows]
    return starts, ends, vals


def _query(starts: list[int], ends: list[int], vals: list, ip: int):
    if not starts:
        return None
    i = bisect.bisect_right(starts, ip) - 1
    if i < 0 or ip > ends[i]:
        return None
    return vals[i]


class TsvIdx:
    def __init__(self, path: Path):
        self.dict: list[str] = []
        v4_rows: list[tuple[int, int, object]] = []
        v6_rows: list[tuple[int, int, object]] = []
        section = None
        with open(path, "rb") as f:
            for raw in f:
                if not raw or raw[:1] == b"#":
                    s = raw.rstrip(b"\n").decode("utf-8", "replace")
                    if s == "#dict":
                        section = "dict"
                    elif s == "#data":
                        section = "data"
                    continue
                line = raw.rstrip(b"\n").decode("utf-8", "replace")
                if section == "dict":
                    idx_s, _, val = line.partition("\t")
                    idx = int(idx_s)
                    if idx >= len(self.dict):
                        self.dict.extend([""] * (idx - len(self.dict) + 1))
                    self.dict[idx] = val
                elif section == "data":
                    tok, _, idx_s = line.partition("\t")
                    start, end, is_v6 = _parse_range(tok)
                    rows = v6_rows if is_v6 else v4_rows
                    rows.append((start, end, int(idx_s)))
        self.v4 = _split_ranges(v4_rows)
        self.v6 = _split_ranges(v6_rows)

    def lookup(self, ip: int, is_v6: bool) -> str | None:
        starts, ends, vals = self.v6 if is_v6 else self.v4
        idx = _query(starts, ends, vals, ip)
        return self.dict[idx] if idx is not None else None


class BucketIdx:
    def __init__(self, path: Path):
        v4_rows: list[tuple[int, int, object]] = []
        v6_rows: list[tuple[int, int, object]] = []
        cur = None
        with open(path, "rb") as f:
            for raw in f:
                if not raw or raw[:1] == b"#":
                    continue
                line = raw.rstrip(b"\n").decode("utf-8", "replace")
                if not line:
                    continue
                if line[:1] == "[" and line[-1:] == "]":
                    cur = line[1:-1]
                    continue
                if cur is None:
                    continue
                start, end, is_v6 = _parse_range(line)
                rows = v6_rows if is_v6 else v4_rows
                rows.append((start, end, cur))
        self.v4 = _split_ranges(v4_rows)
        self.v6 = _split_ranges(v6_rows)

    def lookup(self, ip: int, is_v6: bool) -> str | None:
        starts, ends, vals = self.v6 if is_v6 else self.v4
        return _query(starts, ends, vals, ip)


class NetsetIdx:
    def __init__(self, path: Path):
        v4: list[tuple[int, int]] = []
        v6: list[tuple[int, int]] = []
        with open(path, "rb") as f:
            for raw in f:
                if not raw or raw[:1] == b"#":
                    continue
                line = raw.rstrip(b"\n").decode("utf-8", "replace").strip()
                if not line:
                    continue
                start, end, is_v6 = _parse_cidr(line)
                (v6 if is_v6 else v4).append((start, end))
        v4.sort()
        v6.sort()
        self.v4_s = np.array([r[0] for r in v4], dtype=np.uint32)
        self.v4_e = np.array([r[1] for r in v4], dtype=np.uint32)
        self.v6_s = [r[0] for r in v6]
        self.v6_e = [r[1] for r in v6]

    def contains(self, ip: int, is_v6: bool) -> bool:
        if is_v6:
            if not self.v6_s:
                return False
            i = bisect.bisect_right(self.v6_s, ip) - 1
            return i >= 0 and ip <= self.v6_e[i]
        if not len(self.v4_s):
            return False
        i = int(np.searchsorted(self.v4_s, np.uint32(ip), side="right")) - 1
        return i >= 0 and ip <= int(self.v4_e[i])


class ProxyDb:
    def __init__(self, base: Path):
        self.tsv = {n: TsvIdx(base / f"{n}.tsv") for n in TSV_FILES}
        self.buckets = {n: BucketIdx(base / f"{n}.buckets") for n in BUCKET_FILES}
        self.netset = NetsetIdx(base / NETSET_FILE)

    def lookup(self, ip_s: str) -> dict:
        ip, is_v6 = _ip_to_int(ip_s)
        out: dict = {"ip": ip_s, "is_v6": is_v6}
        out["proxy_pub"] = self.netset.contains(ip, is_v6)
        for name, idx in self.tsv.items():
            out[name] = idx.lookup(ip, is_v6)
        for name, idx in self.buckets.items():
            out[name] = idx.lookup(ip, is_v6)
        return out


def main():
    ap = argparse.ArgumentParser(description="lookup IP across proxyx outputs")
    ap.add_argument("--dir", default=".")
    ap.add_argument("ip", nargs="+")
    args = ap.parse_args()
    db = ProxyDb(Path(args.dir))
    for ip in args.ip:
        rec = db.lookup(ip)
        print(f"=== {ip} ===")
        for k, v in rec.items():
            if k == "ip":
                continue
            print(f"{k}\t{v}")


if __name__ == "__main__":
    sys.exit(main())
