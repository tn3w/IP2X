"""Round-trip the container: every section kind written, read back and compared."""

import bisect
import random
import tempfile
from pathlib import Path

from ip2x import Database, View
from builder.pack import Writer

FIELDS = [{"name": "lat", "read": "scaled"}, {"name": "name", "read": "text"},
          {"name": "count", "read": "int"}]


def sample(seed: int = 3):
    rng = random.Random(seed)
    pool = sorted({"", *(f"city-{rng.randrange(9999):04d}" for _ in range(400))})
    records = [(rng.randrange(-90_000, 90_000), rng.randrange(len(pool)),
                rng.randrange(1000)) for _ in range(300)]
    starts = {4: sorted({rng.randrange(1, 1 << 32) for _ in range(5000)}),
              6: sorted({rng.randrange(1, 1 << 128) for _ in range(4000)})}
    ids = {family: [rng.randrange(0, len(records) + 1) for _ in starts[family]]
           for family in starts}
    return pool, records, starts, ids


def build(path: str, held) -> None:
    pool, records, starts, ids = held
    writer = Writer("test")
    for family in (4, 6):
        writer.index(f"spine.v{family}", starts[family], family == 6)
        writer.column(f"row.v{family}", ids[family])
    for place, field in enumerate(FIELDS):
        writer.column(f"field.{field['name']}", [r[place] for r in records],
                      field["name"] == "lat")
    writer.strings("strings", pool)
    writer.write(path, FIELDS)


def expected(held, family: int, address: int):
    pool, records, starts, ids = held
    at = bisect.bisect_right(starts[family], address) - 1
    if at < 0 or not ids[family][at]:
        return None
    lat, name, count = records[ids[family][at] - 1]
    return {"lat": lat / 1000, "name": pool[name] or None, "count": count or None}


def check_views(folder: str) -> int:
    table = Path(folder) / "isp.tsv"
    table.write_text("#\n# isp.tsv\n#\n#dict\n0\tACME Net\n1\tOther Ltd\n"
                     "#data\n1.0.19.0+255\t0\n2001:dead::+65535\t1\n")
    buckets = Path(folder) / "usage.buckets"
    buckets.write_text("#\n[COM]\n8.8.8.8\n[DCH]\n1.0.19.0+255\n")
    netset = Path(folder) / "proxy_pub.netset"
    netset.write_text("#\n1.0.19.0/24\n2001:dead::/32\n")
    wanted = [(table, "1.0.19.98", "ACME Net"), (table, "2001:dead::5", "Other Ltd"),
              (table, "9.9.9.9", None), (buckets, "8.8.8.8", "COM"),
              (buckets, "1.0.19.1", "DCH"), (buckets, "8.8.8.9", None),
              (netset, "1.0.19.255", "PUB"), (netset, "1.0.20.0", None),
              (netset, "2001:dead::1", "PUB")]
    for path, address, want in wanted:
        got = View(str(path)).lookup(address)
        assert got == want, f"{path.name} {address}: {got} != {want}"
    return len(wanted)


DUMP = """inetnum: 10.0.0.0 - 10.0.255.255
netname: WIDE-NET
org: ORG-A
country: de
status: ALLOCATED PA

inetnum: 10.0.1.0 - 10.0.1.255
netname: NARROW-NET
descr: A customer

inetnum: 8.0.0.0 - 8.255.255.255
netname: IANA-NETBLOCK-8
descr: This network range is not allocated to APNIC.

inet6num: 2001:db8::/32
netname: SIX-NET
"""


def check_whois(folder: str) -> int:
    import gzip

    from builder import feeds
    from builder.build import build_whois

    cache = Path(folder) / "bulk"
    cache.mkdir()
    for rir, urls in feeds.BULK.items():
        for place, _ in enumerate(urls):
            text = DUMP if rir == "RIPE" and place == 0 else ""
            path = cache / f"{rir.lower()}-{place}.gz"
            path.write_bytes(gzip.compress(text.encode()))
    for rir in feeds.ORGANISATIONS:
        held = b"organisation: ORG-A\norg-name: Example GmbH\n"
        (cache / f"{rir.lower()}-org-0.gz").write_bytes(gzip.compress(held))
    path = str(Path(folder) / "whois.ip2x")
    build_whois(str(cache), path)
    database = Database(path)
    wide = database.lookup("10.0.0.1")
    assert wide["netname"] == "WIDE-NET" and wide["org"] == "Example GmbH", wide
    assert (wide["country"], wide["status"]) == ("DE", "ALLOCATED PA"), wide
    assert database.lookup("10.0.1.1")["netname"] == "NARROW-NET"
    assert database.lookup("10.0.2.1")["netname"] == "WIDE-NET"
    assert database.lookup("8.8.8.8") is None
    assert database.lookup("2001:db8::1")["netname"] == "SIX-NET"
    return 5


def main() -> None:
    import ipaddress
    data = sample()
    starts = data[2]
    with tempfile.TemporaryDirectory() as folder:
        path = str(Path(folder) / "test.bin")
        build(path, data)
        database = Database(path)
        rng = random.Random(17)
        checked = 0
        for family in (4, 6):
            for _ in range(2000):
                address = starts[family][rng.randrange(len(starts[family]))]
                address += rng.randrange(0, 1 << (16 if family == 4 else 48))
                address %= 1 << (32 if family == 4 else 128)
                text = str(ipaddress.ip_address(address))
                got, want = database.lookup(text), expected(data, family, address)
                assert got == want, f"{text}: {got} != {want}"
                checked += 1
        checked += check_views(folder)
        checked += check_whois(folder)
    print(f"ok: {checked} lookups round-tripped")


if __name__ == "__main__":
    main()
