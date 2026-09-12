"""Build geo.ip2x, proxy.ip2x and geofeed.ip2x from their sources."""

import argparse
import csv
import ipaddress
import json
import math
import sys
from pathlib import Path

import numpy as np

import views
from pack import Writer
from sources import Ip2Location, Mmdb

SCALE = 1000
V4_CEILING = (1 << 32) - 1
V6_CEILING = (1 << 128) - 1
GEO_BLOCKS = {4: 8, 6: 88}
GEO_FIELDS = [{"name": "lat", "read": "scaled", "signed": True},
              {"name": "lon", "read": "scaled", "signed": True}]
PROXY_FIELDS = [
    {"name": "proxy_type", "read": "text", "column": 2},
    {"name": "isp", "read": "text", "column": 6},
    {"name": "domain", "read": "text", "column": 7},
    {"name": "usage_type", "read": "text", "column": 8},
    {"name": "asn", "read": "int", "column": 9},
    {"name": "as_name", "read": "text", "column": 10},
    {"name": "last_seen", "read": "int", "column": 11},
    {"name": "threat", "read": "text", "column": 12},
    {"name": "provider", "read": "text", "column": 13},
    {"name": "fraud_score", "read": "int", "column": 14},
]
FEED_COLUMNS = ("country", "region", "city", "postal", "feed", "rir")
GEOFEED_FIELDS = [{"name": name, "read": "text"}
                  for name in (*FEED_COLUMNS, "provider", "tags")]


def quantise(value: float) -> int:
    return math.floor(value * SCALE + 0.5)


def emit(path: str, kind: str, fields: list[dict], records: list[tuple],
         families: dict[int, tuple[list[int], list[int]]], pool=None, **meta) -> int:
    writer = Writer(kind)
    for family, (starts, identifiers) in families.items():
        if not starts:
            continue
        writer.index(f"spine.v{family}", starts, family == 6)
        writer.column(f"row.v{family}", identifiers)
    for place, field in enumerate(fields):
        values = [record[place] for record in records]
        writer.column(f"field.{field['name']}", values, field.get("signed", False))
    if pool is not None:
        writer.strings("strings", pool)
    shown = [{"name": f["name"], "read": f["read"]} for f in fields]
    size = writer.write(path, shown, records=len(records), **meta)
    print(f"{path}: {size / 1e6:.1f} MB, {len(records)} records, "
          f"{', '.join(f'v{k} {len(v[0])}' for k, v in families.items())}")
    return size


def ranked(families: dict[int, list[tuple[int, tuple | None]]]):
    """Records are numbered as they first appear, so the ids in a block stay close."""
    identifier: dict[tuple, int] = {}
    for rows in families.values():
        for _, record in rows:
            if record is not None and record not in identifier:
                identifier[record] = len(identifier) + 1
    held = {family: ([start for start, _ in rows],
                     [identifier.get(record, 0) for _, record in rows])
            for family, rows in families.items()}
    return list(identifier), held


def push(out: list, start: int, point) -> None:
    if out and out[-1][1] == point:
        return
    out.append((start, point))


def merge(rows: list[tuple[int, tuple | None]], fallback: list, ceiling: int) -> list:
    """IP2Location first; where it holds no point, MaxMind fills the span."""
    out: list = []
    at = 0
    for place, (start, point) in enumerate(rows):
        end = rows[place + 1][0] - 1 if place + 1 < len(rows) else ceiling
        if point is not None:
            push(out, start, point)
            continue
        while at < len(fallback) and fallback[at][1] < start:
            at += 1
        cursor = start
        while cursor <= end:
            if at >= len(fallback) or fallback[at][0] > end:
                push(out, cursor, None)
                break
            low, high, other = fallback[at]
            if low > cursor:
                push(out, cursor, None)
                cursor = low
            push(out, cursor, other)
            stop = min(high, end)
            if stop == ceiling:
                break
            cursor = stop + 1
            if high <= end:
                at += 1
    return out


def located(source: Ip2Location, wide: bool) -> list[tuple[int, tuple | None]]:
    rows = source.rows(wide)
    starts = source.addresses(rows, wide).tolist()
    lats = source.floats(rows, 5, wide).tolist()
    lons = source.floats(rows, 6, wide).tolist()
    return [(start, (quantise(lat), quantise(lon)) if lat or lon else None)
            for start, lat, lon in zip(starts, lats, lons)]


def mark(runs: list, block: int, point, shift: int) -> None:
    at = block << shift
    if runs and runs[-1][0] == at:
        runs[-1] = (at, point)
    elif not runs or runs[-1][1] != point:
        runs.append((at, point))


def blocked(segments: list[tuple[int, int, tuple | None]], shift: int) -> list:
    """Runs no finer than a block, each block taking the point that covers most of it."""
    runs: list = []
    held = None
    for first, last, point in segments:
        head, tail = first >> shift, last >> shift
        if held and held[0] < head:
            mark(runs, held[0], held[1], shift)
            held = None
        if head == tail:
            weight = last - first + 1
            if not (held and held[0] == head and held[2] >= weight):
                held = (head, point, weight)
            continue
        reach = ((head + 1) << shift) - first
        winner = held[1] if held and held[0] == head and held[2] >= reach else point
        mark(runs, head, winner, shift)
        mark(runs, head + 1, point, shift)
        held = (tail, point, last - (tail << shift) + 1)
    if held:
        mark(runs, held[0], held[1], shift)
    out: list = []
    for at, point in runs:
        if not out or out[-1][1] != point:
            out.append((at, point))
    return out


def spans(rows: list[tuple[int, tuple | None]], ceiling: int) -> list:
    ends = [start - 1 for _, start in zip(rows, [start for start, _ in rows[1:]])]
    return [(start, end, record)
            for (start, record), end in zip(rows, [*ends, ceiling])]


def build_geo(ip2l: str, mmdb: str, out: str, blocks: dict[int, int]) -> None:
    source, maxmind = Ip2Location(ip2l), Mmdb(mmdb)
    families = {}
    for family, wide, ceiling in ((4, False, V4_CEILING), (6, True, V6_CEILING)):
        fallback = [(low, high, (quantise(lat), quantise(lon)))
                    for low, high, lat, lon in maxmind.points(wide)]
        print(f"v{family}: {source.v6_count if wide else source.v4_count} ip2location, "
              f"{len(fallback)} maxmind", file=sys.stderr)
        rows = merge(located(source, wide), fallback, ceiling)
        families[family] = blocked(spans(rows, ceiling), blocks[family])
    records, held = ranked(families)
    emit(out, "geo", GEO_FIELDS, records, held, blocks=blocks, scale=SCALE,
         source="IP2Location LITE DB11 + MaxMind GeoLite2-City")


def interned(source: Ip2Location, wide: bool) -> tuple[np.ndarray, list[str]]:
    """Every text column at once, so the shared pool is sorted and coded only here."""
    rows = source.rows(wide)
    table = np.empty((len(rows), len(PROXY_FIELDS)), dtype=np.int32)
    pools: list[list[str]] = []
    for place, field in enumerate(PROXY_FIELDS):
        codes, values = source.texts(rows, field["column"], wide)
        if field["read"] == "int":
            numbers = np.array([int(value) if value.isdigit() else 0
                                for value in values], dtype=np.int32)
            table[:, place] = numbers[codes]
            pools.append([])
            continue
        table[:, place] = codes
        pools.append(values)
    return table, pools


def numbered(tables: dict[int, np.ndarray]):
    """The same interning as ranked, done without ever leaving numpy."""
    families = list(tables)
    unique, inverse = np.unique(np.vstack([tables[f] for f in families]), axis=0,
                                return_inverse=True)
    inverse = inverse.reshape(-1)
    firsts = np.argsort(np.unique(inverse, return_index=True)[1])
    ranking = np.empty(len(unique), np.int64)
    ranking[firsts] = np.arange(len(unique))
    identifiers = ranking[inverse] + 1
    identifiers[(~unique.any(axis=1))[inverse]] = 0
    records = [tuple(record) for record in unique[firsts].tolist()]
    held, at = {}, 0
    for family in families:
        size = len(tables[family])
        held[family] = identifiers[at:at + size].tolist()
        at += size
    return records, held


def build_proxy(px12: str, out: str, views_dir: str | None) -> None:
    source = Ip2Location(px12)
    tables, pools = {}, {}
    for family, wide in ((4, False), (6, True)):
        tables[family], pools[family] = interned(source, wide)
    texts = {""}
    for held in pools.values():
        texts.update(value for values in held for value in values)
    pool = sorted(texts)
    at = {value: number for number, value in enumerate(pool)}
    starts = {}
    for family, wide in ((4, False), (6, True)):
        table = tables[family]
        for place, field in enumerate(PROXY_FIELDS):
            if field["read"] == "text":
                shared = np.array([at[value] for value in pools[family][place]])
                table[:, place] = shared[table[:, place]]
        kept = np.flatnonzero(np.append(True, (table[1:] != table[:-1]).any(axis=1)))
        tables[family] = table[kept]
        starts[family] = source.addresses(source.rows(wide), wide)[kept].tolist()
    source.held.clear()
    records, identifiers = numbered(tables)
    families = {family: (starts[family], identifiers[family]) for family in starts}
    emit(out, "proxy", PROXY_FIELDS, records, families, pool=pool,
         source="IP2Location LITE PX12")
    if views_dir:
        views.write(source, PROXY_FIELDS, views_dir)


def segments(ranges: list[tuple[int, int, int]], ceiling: int):
    """Feeds nest and overlap, so the ranges are flattened into breakpoints first."""
    ranges.sort(key=lambda held: (held[0], -held[1]))
    points: list[tuple[int, int]] = []
    stack: list[tuple[int, int]] = []
    for start, end, identifier in ranges:
        while stack and stack[-1][0] < start:
            top = stack.pop()[0]
            if top < ceiling:
                points.append((top + 1, stack[-1][1] if stack else 0))
        points.append((start, identifier))
        stack.append((end, identifier))
    while stack:
        top = stack.pop()[0]
        if top < ceiling:
            points.append((top + 1, stack[-1][1] if stack else 0))
    points.sort(key=lambda held: held[0])
    out: list[tuple[int, int]] = []
    for position, identifier in points:
        if out and out[-1][0] == position:
            out[-1] = (position, identifier)
            continue
        if out and out[-1][1] == identifier:
            continue
        out.append((position, identifier))
    return out


def parse_cidr(text: str) -> tuple[int, int, bool] | None:
    try:
        network = ipaddress.ip_network(text.strip(), strict=False)
    except ValueError:
        return None
    return int(network[0]), int(network[-1]), network.version == 6


def build_geofeed(data: str, out: str, mapping: str) -> None:
    known = json.loads(Path(mapping).read_text()) if Path(mapping).exists() else {}
    texts, rows = {""}, []
    with open(data, newline="", encoding="utf-8", errors="replace") as handle:
        for row in csv.DictReader(handle):
            found = parse_cidr(row.get("cidr") or "")
            if found is None:
                continue
            record = tuple(normalised(name, row.get(name) or "")
                           for name in FEED_COLUMNS)
            operator = known.get(record[FEED_COLUMNS.index("feed")], {})
            record += (operator.get("provider", ""),
                       ",".join(operator.get("tags", ())))
            texts.update(record)
            rows.append((*found, record))
    pool = sorted(texts)
    place = {value: at for at, value in enumerate(pool)}
    identifier: dict[tuple, int] = {}
    for _, _, _, record in rows:
        identifier.setdefault(record, len(identifier) + 1)
    order = list(identifier)
    families = {}
    for family, wide, ceiling in ((4, False, V4_CEILING), (6, True, V6_CEILING)):
        held = [(low, high, identifier[record])
                for low, high, is_wide, record in rows if is_wide == wide]
        broken = segments(held, ceiling)
        families[family] = ([start for start, _ in broken],
                            [value for _, value in broken])
    records = [tuple(place[value] for value in record) for record in order]
    emit(out, "geofeed", GEOFEED_FIELDS, records, families, pool=pool,
         source="RIR bulk WHOIS + RFC 8805 feeds")


def normalised(field: str, value: str) -> str:
    return value.strip().upper() if field in ("country", "rir") else value.strip()


def main() -> None:
    parser = argparse.ArgumentParser(description="build the IP2X databases")
    sub = parser.add_subparsers(dest="command", required=True)
    geo = sub.add_parser("geo")
    geo.add_argument("--ip2l", default="IP2LOCATION-LITE-DB11.IPV6.BIN")
    geo.add_argument("--mmdb", default="GeoLite2-City.mmdb")
    geo.add_argument("--out", default="geo.ip2x")
    geo.add_argument("--v4-block", type=int, default=GEO_BLOCKS[4],
                     help="snap IPv4 boundaries to blocks of 2**N addresses")
    geo.add_argument("--v6-block", type=int, default=GEO_BLOCKS[6],
                     help="snap IPv6 boundaries to blocks of 2**N addresses")
    proxy = sub.add_parser("proxy")
    proxy.add_argument("--px12", default="IP2PROXY-LITE-PX12.BIN")
    proxy.add_argument("--out", default="proxy.ip2x")
    proxy.add_argument("--views", default=None)
    feed = sub.add_parser("geofeed")
    feed.add_argument("--data", default="geofeeds_data.csv")
    feed.add_argument("--out", default="geofeed.ip2x")
    feed.add_argument("--map", default="geofeed_map.json")
    args = parser.parse_args()
    if args.command == "geo":
        build_geo(args.ip2l, args.mmdb, args.out,
                  {4: args.v4_block, 6: args.v6_block})
    elif args.command == "proxy":
        build_proxy(args.px12, args.out, args.views)
    else:
        build_geofeed(args.data, args.out, args.map)


if __name__ == "__main__":
    main()
