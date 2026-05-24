#!/usr/bin/env python3
import argparse
import ipaddress
import mmap
import struct
import sys

import numpy as np

MAGIC = b"PRX2"
VERSION = 2
HEADER_LEN = 36
BLOCK_SHIFT = 8
BLOCK = 1 << BLOCK_SHIFT
TAIL_PAD = 8


def _u24(buf, o: int) -> int:
    return buf[o] | (buf[o + 1] << 8) | (buf[o + 2] << 16)


def _packed(buf, i: int, bits: int) -> int:
    bit = i * bits
    byte = bit >> 3
    shift = bit & 7
    v = int.from_bytes(buf[byte:byte + 4], "little")
    return (v >> shift) & ((1 << bits) - 1)


class ProxyDb:
    def __init__(self, path: str):
        self.fp = open(path, "rb")
        self.mm = mmap.mmap(self.fp.fileno(), 0, prot=mmap.PROT_READ)
        if bytes(self.mm[:4]) != MAGIC:
            raise ValueError("bad magic, not a proxy.bin")
        if self.mm[4] != VERSION:
            raise ValueError(f"unsupported version {self.mm[4]}")
        if self.mm[5] != BLOCK_SHIFT:
            raise ValueError(f"unsupported block shift {self.mm[5]}")
        self.v6_bits = self.mm[6]
        n_pairs, n_strs, n4, n6, nb4, d_len, i_len = struct.unpack_from(
            "<IIIIIII", self.mm, 8
        )
        self.n4, self.n6, self.nb4 = n4, n6, nb4

        o = HEADER_LEN
        self.pairs = memoryview(self.mm)[o:o + n_pairs * 6]
        o += n_pairs * 6
        self.str_off = np.frombuffer(self.mm, dtype="<u4", count=n_strs + 1, offset=o)
        o += (n_strs + 1) * 4
        blob_len = int(self.str_off[-1])
        self.str_blob = memoryview(self.mm)[o:o + blob_len]
        o += blob_len
        self.bases4 = np.frombuffer(self.mm, dtype="<u4", count=nb4, offset=o)
        o += nb4 * 4
        self.dbits4 = memoryview(self.mm)[o:o + nb4]
        o += nb4
        self.ibits4 = memoryview(self.mm)[o:o + nb4]
        o += nb4
        self.d_off = np.frombuffer(self.mm, dtype="<u4", count=nb4 + 1, offset=o)
        o += (nb4 + 1) * 4
        self.i_off = np.frombuffer(self.mm, dtype="<u4", count=nb4 + 1, offset=o)
        o += (nb4 + 1) * 4
        self.d_blob = memoryview(self.mm)[o:o + d_len + TAIL_PAD]
        o += d_len + TAIL_PAD
        self.i_blob = memoryview(self.mm)[o:o + i_len + TAIL_PAD]
        o += i_len + TAIL_PAD
        self.v6_k = np.frombuffer(self.mm, dtype="<u8", count=n6, offset=o)
        o += n6 * 8
        v6_idx_len = (n6 * self.v6_bits + 7) // 8 + TAIL_PAD
        self.v6_idx = memoryview(self.mm)[o:o + v6_idx_len]

    def _str(self, i: int) -> str:
        if i == 0:
            return ""
        a = int(self.str_off[i])
        b = int(self.str_off[i + 1])
        return bytes(self.str_blob[a:b]).decode("utf-8", "replace")

    def _pair(self, pi: int):
        if pi == 0:
            return None
        o = pi * 6
        return (self._str(_u24(self.pairs, o)), self._str(_u24(self.pairs, o + 3)))

    def _lookup_v4(self, ip: int):
        pos = int(np.searchsorted(self.bases4, np.uint32(ip), side="right"))
        if pos == 0:
            return None
        bi = pos - 1
        base = int(self.bases4[bi])
        target = ip - base
        db = self.dbits4[bi]
        d_a = int(self.d_off[bi])
        row_start = bi << BLOCK_SHIFT
        cnt = min(BLOCK, self.n4 - row_start)
        d = self.d_blob[d_a:]
        lo, hi = 0, cnt
        while lo < hi:
            mid = (lo + hi) >> 1
            if _packed(d, mid, db) <= target:
                lo = mid + 1
            else:
                hi = mid
        if lo == 0:
            return None
        ib = self.ibits4[bi]
        i_a = int(self.i_off[bi])
        return self._pair(_packed(self.i_blob[i_a:], lo - 1, ib))

    def _lookup_v6(self, ip: int):
        key = np.uint64(ip >> 64)
        pos = int(np.searchsorted(self.v6_k, key, side="right"))
        if pos == 0:
            return None
        return self._pair(_packed(self.v6_idx, pos - 1, self.v6_bits))

    def lookup(self, ip_s: str):
        addr = ipaddress.ip_address(ip_s)
        if isinstance(addr, ipaddress.IPv4Address):
            return self._lookup_v4(int(addr))
        return self._lookup_v6(int(addr))


def main():
    ap = argparse.ArgumentParser(description="lookup IP -> (isp, domain) in proxy.bin")
    ap.add_argument("--db", default="proxy.bin")
    ap.add_argument("ip", nargs="+")
    args = ap.parse_args()
    db = ProxyDb(args.db)
    for ip in args.ip:
        r = db.lookup(ip)
        if r is None:
            print(f"{ip}\tnot found")
        else:
            isp, dom = r
            print(f"{ip}\tisp={isp}\tdomain={dom}")


if __name__ == "__main__":
    sys.exit(main())
