import struct

import numpy as np

MARKER = b"\xab\xcd\xefMaxMind.com"
ALIASES = {(0, 96), (0xFFFF00000000, 96), (0x2002 << 112, 16), (0x20010000 << 96, 32)}
POINTER_BASE = (0, 2048, 526336, 0)


class Ip2Location:
    def __init__(self, path: str) -> None:
        self.mm = np.memmap(path, dtype=np.uint8, mode="r")
        head = bytes(self.mm[:21])
        columns = head[1]
        self.v4_count, v4_at, self.v6_count, v6_at = struct.unpack_from("<IIII", head, 5)
        self.starts = {False: v4_at - 1, True: v6_at - 1}
        self.words = {False: columns, True: columns + 3}
        self.skip = {False: 1, True: 4}
        self.held: dict[bool, np.ndarray] = {}

    def rows(self, wide: bool) -> np.ndarray:
        if wide not in self.held:
            self.held[wide] = self.read(wide)
        return self.held[wide]

    def read(self, wide: bool) -> np.ndarray:
        count = self.v6_count if wide else self.v4_count
        width = self.words[wide]
        at = self.starts[wide]
        raw = np.array(self.mm[at:at + count * width * 4])
        return raw.view(np.uint32).reshape(count, width)

    def addresses(self, rows: np.ndarray, wide: bool) -> np.ndarray:
        if not wide:
            return rows[:, 0]
        parts = rows[:, :4].astype(object)
        return parts[:, 0] | parts[:, 1] << 32 | parts[:, 2] << 64 | parts[:, 3] << 96

    def floats(self, rows: np.ndarray, column: int, wide: bool) -> np.ndarray:
        return rows[:, self.skip[wide] + column - 2].copy().view(np.float32)

    def texts(self, rows: np.ndarray, column: int, wide: bool):
        pointers = rows[:, self.skip[wide] + column - 2]
        unique = np.unique(pointers)
        values = [self.text(int(pointer)) for pointer in unique]
        return np.searchsorted(unique, pointers), values

    def text(self, pointer: int) -> str:
        if not pointer or pointer >= len(self.mm):
            return ""
        size = int(self.mm[pointer])
        value = bytes(self.mm[pointer + 1:pointer + 1 + size]).decode("utf-8", "replace")
        return "" if value == "-" else value


class Mmdb:
    def __init__(self, path: str) -> None:
        with open(path, "rb") as handle:
            self.data = handle.read()
        at = self.data.rfind(MARKER)
        if at < 0:
            raise ValueError(f"{path} is not an mmdb")
        self.base = at + len(MARKER)
        meta = self.decode(self.base)[0]
        self.nodes = meta["node_count"]
        self.bits = meta["record_size"]
        self.base = self.nodes * self.bits // 4 + 16
        self.cache: dict[int, dict] = {}
        self.left, self.right = self.records()

    def records(self) -> tuple[np.ndarray, np.ndarray]:
        width = self.bits // 4
        raw = np.frombuffer(self.data, np.uint8, self.nodes * width)
        raw = raw.reshape(self.nodes, width).astype(np.uint32)
        if self.bits == 28:
            left = raw[:, 0] << 16 | raw[:, 1] << 8 | raw[:, 2] | (raw[:, 3] >> 4) << 24
            right = (raw[:, 3] & 0xF) << 24 | raw[:, 4] << 16 | raw[:, 5] << 8 | raw[:, 6]
            return left, right
        half = width // 2
        pick = lambda part: sum(part[:, i] << (8 * (half - 1 - i)) for i in range(half))
        return pick(raw[:, :half]), pick(raw[:, half:])

    def start(self, depth: int) -> int:
        node = 0
        for _ in range(depth):
            node = int(self.left[node])
        return node

    def walk(self, node: int, depth: int, skip: bool):
        stack = [(node, 0, depth)]
        while stack:
            node, network, prefix = stack.pop()
            if node > self.nodes:
                yield network, prefix, node - self.nodes - 16
                continue
            if node == self.nodes:
                continue
            step = 1 << (127 - prefix)
            for bit, branch in ((1, self.right), (0, self.left)):
                nested = network + step * bit
                if skip and (nested, prefix + 1) in ALIASES:
                    continue
                stack.append((int(branch[node]), nested, prefix + 1))

    def points(self, wide: bool) -> list[tuple[int, int, float, float]]:
        node, depth = (0, 0) if wide else (self.start(96), 96)
        out = []
        for network, prefix, at in self.walk(node, depth, wide):
            found = self.cache.get(at)
            if found is None:
                found = self.cache[at] = self.decode(self.base + at)[0]
            point = found.get("location") if isinstance(found, dict) else None
            if not point:
                continue
            lat, lon = point.get("latitude"), point.get("longitude")
            if lat is None or lon is None or (lat == 0.0 and lon == 0.0):
                continue
            span = 1 << (128 - prefix)
            out.append((network, network + span - 1, lat, lon))
        out.sort()
        return out

    def decode(self, at: int):
        control = self.data[at]
        kind, size, at = control >> 5, control & 0x1F, at + 1
        if kind == 1:
            width = (control >> 3) & 3
            value = int.from_bytes(self.data[at:at + width + 1], "big")
            head = (control & 7) << (8 * (width + 1)) if width < 3 else 0
            return self.decode(self.base + head + value + POINTER_BASE[width])[0], \
                at + width + 1
        if kind == 0:
            kind, at = 7 + self.data[at], at + 1
        if size == 29:
            size, at = 29 + self.data[at], at + 1
        elif size == 30:
            size, at = 285 + int.from_bytes(self.data[at:at + 2], "big"), at + 2
        elif size == 31:
            size, at = 65821 + int.from_bytes(self.data[at:at + 3], "big"), at + 3
        return self.value(kind, size, at)

    def value(self, kind: int, size: int, at: int):
        if kind == 7:
            out = {}
            for _ in range(size):
                key, at = self.decode(at)
                out[key], at = self.decode(at)
            return out, at
        if kind == 11:
            out = []
            for _ in range(size):
                item, at = self.decode(at)
                out.append(item)
            return out, at
        held = self.data[at:at + size]
        if kind == 2:
            return held.decode("utf-8", "replace"), at + size
        if kind == 3:
            return struct.unpack(">d", held)[0], at + size
        if kind == 15:
            return struct.unpack(">f", held)[0], at + size
        if kind == 8:
            value = int.from_bytes(held, "big")
            top = 1 << (size * 8 - 1)
            return (value - (top << 1) if value & top else value), at + size
        if kind == 14:
            return bool(size), at
        return int.from_bytes(held, "big"), at + size
