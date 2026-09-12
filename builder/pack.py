"""Write an IP2X database: fixed blocks, one trained dictionary, a JSON header."""

import json
import struct
import sys
from array import array
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from itertools import accumulate

try:
    from compression.zstd import ZstdDict, compress, train_dict
except ImportError:
    from pyzstd import ZstdDict, compress, train_dict

MAGIC = b"IP2X\x01"
LEVEL = 19
BOOK = 112 * 1024
SHARES = (256, 64, 1)
PROBE = 32
WIDTHS = (1, 2, 4, 8)
PLAIN = {1: "B", 2: "H", 4: "I", 8: "Q"}
STEPPED = {1: "b", 2: "h", 4: "i", 8: "q"}
SWAPPED = sys.byteorder == "big"
HOST_BITS = 64
SIZES = {"index": 1024, "column": 65536, "text": 1024}


def varint(out: bytearray, value: int) -> None:
    while value >= 0x80:
        out.append(value & 0x7F | 0x80)
        value >>= 7
    out.append(value)


def room(value: int, signed: bool) -> int:
    for width in WIDTHS:
        bits = width * 8 - signed
        if -(1 << bits) * signed <= value < 1 << bits:
            return width
    return 8


def chunked(values, size: int) -> list:
    return [values[at:at + size] for at in range(0, len(values), size)]


def numbers(values: list[int], signed: bool) -> bytes:
    width = max((room(value, signed) for value in values), default=1)
    held = array(STEPPED[width] if signed else PLAIN[width], values)
    if SWAPPED:
        held.byteswap()
    return bytes([width]) + held.tobytes()


def steps(values: list[int]) -> list[int]:
    return [value - last for value, last in zip(values, [0, *values])]


def addresses(keys: list[int], host_bits: int) -> bytes:
    out = bytearray()
    high = [key >> host_bits for key in keys]
    for value, last in zip(high[1:], high):
        varint(out, value - last)
    if host_bits:
        mask = (1 << host_bits) - 1
        for key in keys:
            varint(out, key & mask)
    return bytes(out)


def front(names: list[str]) -> bytes:
    out, last = bytearray(), b""
    for name in names:
        held = name.encode()
        limit = min(len(last), len(held), 255)
        shared = 0
        while shared < limit and last[shared] == held[shared]:
            shared += 1
        out.append(shared)
        varint(out, len(held) - shared)
        out += held[shared:]
        last = held
    return bytes(out)


def squeeze(blocks: list[bytes], book: bytes) -> list[bytes]:
    holder = ZstdDict(book) if book else None
    with ThreadPoolExecutor() as pool:
        return list(pool.map(lambda raw: compress(raw, LEVEL, zstd_dict=holder), blocks))


def weigh(blocks: list[bytes], book: bytes) -> int:
    step = max(len(blocks) // PROBE, 1)
    return sum(map(len, squeeze(blocks[::step], book))) * step + len(book)


def trained(blocks: list[bytes]) -> bytes:
    """A dictionary is bytes of its own, so it is kept only where it earns them back."""
    if len(blocks) < 8:
        return b""
    raw = sum(map(len, blocks))
    best, book, last = weigh(blocks, b""), b"", 0
    for share in SHARES:
        size = min(raw // share, BOOK)
        if size < 1024 or size <= last:
            continue
        last = size
        try:
            candidate = train_dict(blocks, size).dict_content
        except Exception:
            continue
        cost = weigh(blocks, candidate)
        if cost < best:
            best, book = cost, candidate
    return book


def body(blocks: list[bytes], keys: list[int], width: int) -> bytes:
    book = trained(blocks)
    stored = squeeze(blocks, book)
    out = bytearray(struct.pack("<III", len(blocks), width, len(book)))
    out += array("I", accumulate((len(held) for held in stored), initial=0)).tobytes()
    for key in keys:
        out += key.to_bytes(width, "big")
    out += book
    for held in stored:
        out += held
    return bytes(out)


class Writer:
    def __init__(self, kind: str) -> None:
        self.kind = kind
        self.parts: list[tuple[str, dict, bytes]] = []

    def index(self, name: str, keys: list[int], wide: bool) -> None:
        size, width = SIZES["index"], 16 if wide else 4
        groups = chunked(keys, size)
        blocks = [addresses(group, HOST_BITS if wide else 0) for group in groups]
        entry = {"encoding": "index", "count": len(keys), "block": size}
        self.parts.append((name, entry, body(blocks, [g[0] for g in groups], width)))

    def column(self, name: str, values: list[int], signed: bool = False) -> None:
        size = SIZES["column"]
        groups = chunked(values, size)
        plain = [numbers(group, signed) for group in groups]
        stepped = [numbers(steps(group), True) for group in groups]
        narrow = sum(map(len, stepped)) < sum(map(len, plain))
        entry = {"encoding": "step" if narrow else "plain", "signed": signed or narrow,
                 "count": len(values), "block": size}
        self.parts.append((name, entry, body(stepped if narrow else plain, [], 0)))

    def strings(self, name: str, pool: list[str]) -> None:
        size = SIZES["text"]
        blocks = [front(group) for group in chunked(pool, size)]
        entry = {"encoding": "text", "count": len(pool), "block": size}
        self.parts.append((name, entry, body(blocks, [], 0)))

    def write(self, path: str, fields: list[dict], **meta) -> int:
        sections, at = {}, 0
        for name, entry, held in self.parts:
            sections[name] = {**entry, "offset": at, "bytes": len(held)}
            at += len(held)
        head = json.dumps({"format": 1, "kind": self.kind, "built": str(date.today()),
                           **meta, "fields": fields, "sections": sections},
                          separators=(",", ":")).encode()
        with open(path, "wb") as handle:
            handle.write(MAGIC + struct.pack("<I", len(head)) + head)
            for _, _, held in self.parts:
                handle.write(held)
        return len(MAGIC) + 4 + len(head) + at
