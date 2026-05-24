#!/usr/bin/env python3
import argparse
import ipaddress
import mmap
import struct
import sys
from pathlib import Path

import numpy as np

MAGIC = b"GEO1"
HEADER_LEN = 24
SCALE = 1000.0


def _u24(buf, o: int) -> int:
    return buf[o] | (buf[o + 1] << 8) | (buf[o + 2] << 16)


def _i24(buf, o: int) -> int:
    v = _u24(buf, o)
    return v - 0x1000000 if v & 0x800000 else v


class GeoDb:
    def __init__(self, path: str | Path):
        self.fp = open(path, "rb")
        self.mm = mmap.mmap(self.fp.fileno(), 0, prot=mmap.PROT_READ)
        if bytes(self.mm[:4]) != MAGIC:
            raise ValueError("bad magic, not a geo.bin")
        self.idx_bits = self.mm[6]
        self.idx_mask = (1 << self.idx_bits) - 1
        n_pts, n4, n6, nb4 = struct.unpack_from("<IIII", self.mm, 8)
        o = HEADER_LEN
        self.pts = memoryview(self.mm)[o:o + n_pts * 6]
        o += n_pts * 6
        self.bases4 = np.frombuffer(self.mm, dtype="<u4", count=nb4, offset=o)
        o += nb4 * 4
        self.off4 = np.frombuffer(self.mm, dtype="<u4", count=nb4 + 1, offset=o)
        o += (nb4 + 1) * 4
        deltas_len = int(self.off4[-1])
        self.deltas4 = memoryview(self.mm)[o:o + deltas_len]
        o += deltas_len
        v4_idx_len = (n4 * self.idx_bits + 7) // 8 + 4
        self.v4_idx = memoryview(self.mm)[o:o + v4_idx_len]
        o += v4_idx_len
        self.v6_k = np.frombuffer(self.mm, dtype="<u8", count=n6, offset=o)
        o += n6 * 8
        v6_idx_len = (n6 * self.idx_bits + 7) // 8 + 4
        self.v6_idx = memoryview(self.mm)[o:o + v6_idx_len]
        self.n4 = n4
        self.n6 = n6

    def _packed(self, buf, i: int) -> int:
        bit = i * self.idx_bits
        byte = bit >> 3
        shift = bit & 7
        v = int.from_bytes(buf[byte:byte + 4], "little")
        return (v >> shift) & self.idx_mask

    def _point(self, idx: int):
        if idx == 0:
            return None
        o = idx * 6
        return (_i24(self.pts, o) / SCALE, _i24(self.pts, o + 3) / SCALE)

    def _lookup_v4(self, ip: int):
        pos = int(np.searchsorted(self.bases4, np.uint32(ip), side="right"))
        if pos == 0:
            return None
        bi = pos - 1
        base = int(self.bases4[bi])
        bo = int(self.off4[bi])
        be = int(self.off4[bi + 1])
        cnt = (be - bo) // 3
        target = ip - base
        lo, hi = 0, cnt
        d = self.deltas4
        while lo < hi:
            mid = (lo + hi) >> 1
            mo = bo + mid * 3
            v = d[mo] | (d[mo + 1] << 8) | (d[mo + 2] << 16)
            if v <= target:
                lo = mid + 1
            else:
                hi = mid
        if lo == 0:
            return None
        row = bo // 3 + (lo - 1)
        return self._point(self._packed(self.v4_idx, row))

    def _lookup_v6(self, ip: int):
        key = np.uint64(ip >> 64)
        pos = int(np.searchsorted(self.v6_k, key, side="right"))
        if pos == 0:
            return None
        return self._point(self._packed(self.v6_idx, pos - 1))

    def lookup(self, ip: str):
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv4Address):
            return self._lookup_v4(int(addr))
        return self._lookup_v6(int(addr))


def main():
    ap = argparse.ArgumentParser(description="lookup IP -> (lat, lon) in geo.bin")
    ap.add_argument("--db", default="geo.bin")
    ap.add_argument("ip", nargs="+")
    args = ap.parse_args()
    db = GeoDb(args.db)
    for ip in args.ip:
        r = db.lookup(ip)
        if r is None:
            print(f"{ip}\tnot found")
        else:
            print(f"{ip}\t{r[0]:.3f}, {r[1]:.3f}")


if __name__ == "__main__":
    sys.exit(main())
