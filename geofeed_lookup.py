#!/usr/bin/env python3
"""Look up IP → geofeed record in geofeed.bin (GFD3). mmap + bisect, stdlib only."""
import bisect, ipaddress, mmap, struct, sys
from pathlib import Path

MAGIC = b"GFD3"
HEADER = 28
FIELDS = ["country", "region", "city", "postal", "feed", "rir"]


class GeofeedDB:
    def __init__(self, path):
        f = open(path, "rb")
        self.mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        if self.mm[:4] != MAGIC:
            sys.exit("bad magic")
        self.width = self.mm[5]
        self.fields = self.mm[6]
        self.v4_breaks, self.v6_breaks, self.records, self.strs, _ = struct.unpack_from(
            "<5I", self.mm, 8
        )
        self.v4_starts = HEADER
        self.v4_ids = self.v4_starts + self.v4_breaks * 4
        self.v6_starts = self.v4_ids + self.v4_breaks * self.width
        self.v6_ids = self.v6_starts + self.v6_breaks * 16
        self.rectab = self.v6_ids + self.v6_breaks * self.width
        self.offsets = self.rectab + self.records * self.fields * 4
        self.blob = self.offsets + (self.strs + 1) * 4

    def _u32(self, off):
        return struct.unpack_from("<I", self.mm, off)[0]

    def _string(self, i):
        a = self._u32(self.offsets + i * 4)
        b = self._u32(self.offsets + (i + 1) * 4)
        return self.mm[self.blob + a:self.blob + b].decode("utf-8", "replace")

    def _record(self, ids_off, starts_off, step, breaks, ip):
        def start(i):
            return int.from_bytes(self.mm[starts_off + i * step:starts_off + i * step + step], "little")

        pos = bisect.bisect_right(range(breaks), ip, key=start)
        if pos == 0:
            return None
        off = ids_off + (pos - 1) * self.width
        rid = int.from_bytes(self.mm[off:off + self.width], "little")
        if rid == 0:
            return None
        base = self.rectab + (rid - 1) * self.fields * 4
        return {name: self._string(self._u32(base + i * 4))
                for i, name in enumerate(FIELDS)}

    def lookup(self, ip):
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv4Address):
            return self._record(self.v4_ids, self.v4_starts, 4, self.v4_breaks, int(addr))
        return self._record(self.v6_ids, self.v6_starts, 16, self.v6_breaks, int(addr))


def main():
    args = sys.argv[1:]
    db_path = "geofeed.bin"
    if "--db" in args:
        i = args.index("--db")
        db_path = args[i + 1]
        del args[i:i + 2]
    db = GeofeedDB(Path(db_path))
    for ip in args:
        record = db.lookup(ip)
        if record is None:
            print(f"{ip}\tnot found")
            continue
        print(ip)
        for name in FIELDS:
            print(f"  {name}\t{record[name]}")


if __name__ == "__main__":
    main()
