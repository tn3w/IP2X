#!/usr/bin/env python3
"""Look up IPv4 → geofeed record in geofeed.bin (GFD2). mmap + bisect, stdlib only."""
import bisect, ipaddress, mmap, struct, sys
from pathlib import Path

MAGIC = b"GFD2"
HEADER = 24
FIELDS = ["country", "region", "city", "postal", "feed", "rir"]

class GeofeedDB:
    def __init__(self, path):
        f = open(path, "rb")
        self.mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        if self.mm[:4] != MAGIC:
            sys.exit("bad magic")
        self.width = self.mm[5]
        self.fields = self.mm[6]
        self.breaks, self.records, self.strs, _ = struct.unpack_from("<4I", self.mm, 8)
        self.starts = HEADER
        self.ids = self.starts + self.breaks * 4
        self.rectab = self.ids + self.breaks * self.width
        self.offsets = self.rectab + self.records * self.fields * 4
        self.blob = self.offsets + (self.strs + 1) * 4

    def _u32(self, off):
        return struct.unpack_from("<I", self.mm, off)[0]

    def _start(self, i):
        return self._u32(self.starts + i * 4)

    def _string(self, i):
        a = self._u32(self.offsets + i * 4)
        b = self._u32(self.offsets + (i + 1) * 4)
        return self.mm[self.blob + a:self.blob + b].decode("utf-8", "replace")

    def lookup(self, ip):
        ip = int(ipaddress.IPv4Address(ip))
        pos = bisect.bisect_right(range(self.breaks), ip, key=self._start)
        if pos == 0:
            return None
        off = self.ids + (pos - 1) * self.width
        rid = int.from_bytes(self.mm[off:off + self.width], "little")
        if rid == 0:
            return None
        base = self.rectab + (rid - 1) * self.fields * 4
        return {name: self._string(self._u32(base + i * 4))
                for i, name in enumerate(FIELDS)}

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
