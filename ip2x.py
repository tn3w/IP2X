"""Read an IP2X database or plain-text view: one address in, the stored row out."""

import json
import mmap
import struct
import sys
from array import array
from bisect import bisect_right
from itertools import accumulate
from pathlib import Path
from socket import AF_INET, AF_INET6, inet_pton

try:
    from compression.zstd import ZstdDict, decompress
except ImportError:
    from pyzstd import ZstdDict, decompress

MAGIC = b"IP2X\x01"
PLAIN = {1: "B", 2: "H", 4: "I", 8: "Q"}
STEPPED = {1: "b", 2: "h", 4: "i", 8: "q"}
SWAPPED = sys.byteorder == "big"
HOST_BITS = 64
CACHED = 4096
SCALE = 1000
PUBLIC = "PUB"


def parse(text: str) -> tuple[bool, int]:
    wide = ":" in text
    return wide, int.from_bytes(inet_pton(AF_INET6 if wide else AF_INET, text), "big")


def varints(data, at: int, count: int) -> tuple[list[int], int]:
    values = []
    append = values.append
    for _ in range(count):
        byte = data[at]
        at += 1
        if byte < 0x80:
            append(byte)
            continue
        value, shift = byte & 0x7F, 7
        while True:
            byte = data[at]
            at += 1
            value |= (byte & 0x7F) << shift
            if byte < 0x80:
                break
            shift += 7
        append(value)
    return values, at


class Cache(dict):
    def __init__(self, build) -> None:
        super().__init__()
        self.build = build

    def __missing__(self, key):
        if len(self) >= CACHED:
            self.clear()
        value = self[key] = self.build(key)
        return value


class Section:
    def __init__(self, view: memoryview, entry: dict) -> None:
        self.count = entry["count"]
        self.per_block = entry["block"]
        blocks, self.width, book = struct.unpack_from("<III", view, 0)
        at = 12
        self.offsets = struct.unpack_from(f"<{blocks + 1}I", view, at)
        at += 4 * (blocks + 1)
        self.keys = [int.from_bytes(view[head:head + self.width], "big")
                     for head in range(at, at + self.width * blocks, self.width or 1)]
        at += self.width * blocks
        self.book = ZstdDict(bytes(view[at:at + book])) if book else None
        self.data = view[at + book:]
        self.cache = Cache(self.block)

    def raw(self, index: int) -> bytes:
        held = self.data[self.offsets[index]:self.offsets[index + 1]]
        return decompress(held, zstd_dict=self.book)

    def held(self, index: int) -> int:
        return min(self.per_block, self.count - index * self.per_block)

    def __getitem__(self, row: int):
        index, place = divmod(row, self.per_block)
        return self.cache[index][place]


class Column(Section):
    def __init__(self, view: memoryview, entry: dict) -> None:
        super().__init__(view, entry)
        self.stepped = entry["encoding"] == "step"
        self.formats = STEPPED if entry.get("signed") else PLAIN

    def block(self, index: int):
        raw = self.raw(index)
        values = array(self.formats[raw[0]], raw[1:])
        if SWAPPED:
            values.byteswap()
        return list(accumulate(values)) if self.stepped else values


class Strings(Section):
    def block(self, index: int) -> list[str]:
        raw, at, last = self.raw(index), 0, b""
        values = []
        for _ in range(self.held(index)):
            shared, fresh = raw[at], raw[at + 1]
            at += 2
            if fresh > 0x7F:
                (fresh,), at = varints(raw, at - 1, 1)
            last = last[:shared] + raw[at:at + fresh]
            at += fresh
            values.append(last.decode("utf-8", "replace"))
        return values


class Index(Section):
    def __init__(self, view: memoryview, entry: dict) -> None:
        super().__init__(view, entry)
        self.host_bits = HOST_BITS if self.width == 16 else 0

    def block(self, index: int) -> list[int]:
        size, raw = self.held(index), self.raw(index)
        gaps, at = varints(raw, 0, size - 1)
        high = list(accumulate(gaps, initial=self.keys[index] >> self.host_bits))
        if not self.host_bits:
            return high
        low, _ = varints(raw, at, size)
        return [value << self.host_bits | rest for value, rest in zip(high, low)]

    def row(self, address: int) -> int | None:
        index = bisect_right(self.keys, address) - 1
        if index < 0:
            return None
        place = bisect_right(self.cache[index], address) - 1
        return None if place < 0 else index * self.per_block + place


KINDS = {"index": Index, "text": Strings}


class Database:
    """One file, opened without preload; every block faults in and stays cached."""

    def __init__(self, path: str) -> None:
        with open(path, "rb") as handle:
            view = memoryview(mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ))
        if bytes(view[:len(MAGIC)]) != MAGIC:
            raise ValueError(f"{path} is not an IP2X database")
        size = struct.unpack_from("<I", view, len(MAGIC))[0]
        at = len(MAGIC) + 4
        self.head = json.loads(bytes(view[at:at + size]))
        body = at + size
        self.sections = {}
        for name, entry in self.head["sections"].items():
            start = body + entry["offset"]
            kind = KINDS.get(entry["encoding"], Column)
            self.sections[name] = kind(view[start:start + entry["bytes"]], entry)
        self.fields = [(field["name"], field["read"],
                        self.sections[f"field.{field['name']}"])
                       for field in self.head["fields"]]
        self.pool = self.sections.get("strings")
        self.answers = Cache(self.record)

    def record(self, identifier: int) -> dict:
        row = {}
        for name, read, column in self.fields:
            value = column[identifier]
            if read == "scaled":
                row[name] = value / SCALE
            elif read == "text":
                row[name] = self.pool[value] or None
            else:
                row[name] = value or None
        return row

    def lookup(self, text: str) -> dict | None:
        """The stored row, or None where nothing is known; cached, so do not edit it."""
        wide, address = parse(text)
        family = 6 if wide else 4
        spine = self.sections.get(f"spine.v{family}")
        row = None if spine is None else spine.row(address)
        if row is None:
            return None
        identifier = self.sections[f"row.v{family}"][row]
        return None if not identifier else self.answers[identifier - 1]


def spanned(text: str, value: str) -> tuple[bool, int, int, str]:
    head, _, extra = text.partition("+")
    wide, start = parse(head)
    return wide, start, start + int(extra or 0), value


def netted(text: str, value: str) -> tuple[bool, int, int, str]:
    head, _, prefix = text.partition("/")
    wide, start = parse(head)
    bits = 128 if wide else 32
    return wide, start, start + (1 << (bits - int(prefix or bits))) - 1, value


def netset_rows(lines):
    for line in lines:
        yield netted(line, PUBLIC)


def bucket_rows(lines):
    value = ""
    for line in lines:
        if line.startswith("["):
            value = line[1:-1]
            continue
        yield spanned(line, value)


def table_rows(lines):
    words, naming = [], False
    for line in lines:
        if line.startswith("#"):
            naming = line == "#dict"
        elif naming:
            words.append(line.split("\t", 1)[1])
        else:
            place, index = line.split("\t")
            yield spanned(place, words[int(index)])


VIEWS = {".netset": netset_rows, ".buckets": bucket_rows, ".tsv": table_rows}


def body(path: str):
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if line and line != "#" and not line.startswith("# "):
                yield line


class View:
    """A plain-text view (.netset, .buckets, .tsv) read into sorted IP ranges."""

    def __init__(self, path: str) -> None:
        rows = VIEWS[Path(path).suffix](body(path))
        self.ranges = {False: [], True: []}
        for wide, start, end, value in rows:
            self.ranges[wide].append((start, end, value))
        for held in self.ranges.values():
            held.sort()
        self.starts = {wide: [start for start, _, _ in held]
                       for wide, held in self.ranges.items()}

    def lookup(self, text: str) -> str | None:
        """The value covering the address, or None where no range holds it."""
        wide, address = parse(text)
        place = bisect_right(self.starts[wide], address) - 1
        if place < 0:
            return None
        _, end, value = self.ranges[wide][place]
        return value if address <= end else None


def open_source(path: str):
    return View(path) if Path(path).suffix in VIEWS else Database(path)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="look an address up in an IP2X database or plain-text view")
    parser.add_argument("--db", default="geo.ip2x")
    parser.add_argument("address", nargs="+")
    args = parser.parse_args()
    source = open_source(args.db)
    for address in args.address:
        found = source.lookup(address)
        print(address, json.dumps(found, ensure_ascii=False), sep="\t")


if __name__ == "__main__":
    main()
