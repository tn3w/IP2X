"""Plain-text views of the proxy data: a netset, bucketed fields and dict+ranges."""

import struct
from collections import Counter
from datetime import datetime, timezone
from ipaddress import IPv6Address
from pathlib import Path
from socket import inet_ntoa

import numpy as np

V4_CEILING = (1 << 32) - 1
V6_CEILING = (1 << 128) - 1
BUCKETED = {"usage_type": "usage", "threat": "threat"}
TABLED = ("isp", "domain", "asn", "as_name", "last_seen", "provider", "fraud_score")
PUBLIC = "PUB"


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def ranges(source, column: int, wide: bool):
    """Adjacent rows holding the same value are one range; empty values are dropped."""
    rows = source.rows(wide)
    codes, values = source.texts(rows, column, wide)
    starts = source.addresses(rows, wide)
    ceiling = V6_CEILING if wide else V4_CEILING
    heads = np.flatnonzero(np.append(True, codes[1:] != codes[:-1]))
    edges = starts[heads].tolist()
    chosen = codes[heads].tolist()
    out = []
    for place, code in enumerate(chosen):
        value = values[code]
        if not value:
            continue
        end = edges[place + 1] - 1 if place + 1 < len(edges) else ceiling
        out.append((int(edges[place]), int(end), value))
    return out


def span(start: int, end: int, wide: bool) -> str:
    text = str(IPv6Address(start)) if wide else inet_ntoa(struct.pack(">I", start))
    return text if start == end else f"{text}+{end - start}"


def cidrs(start: int, end: int, bits: int):
    out = []
    while True:
        step = bits if start == 0 else (start & -start).bit_length() - 1
        step = min(step, (end - start + 1).bit_length() - 1)
        out.append((start, bits - step))
        if step >= bits or start + (1 << step) > end:
            return out
        start += 1 << step


def header(handle, lines: list[str]) -> None:
    handle.write("#\n")
    for line in lines:
        handle.write(f"# {line}\n".replace("# \n", "#\n"))
    handle.write("#\n")


def write_netset(source, column: int, path: Path) -> None:
    nets = []
    for wide, bits in ((False, 32), (True, 128)):
        for start, end, value in ranges(source, column, wide):
            if value == PUBLIC:
                nets += [(address, prefix, wide) for address, prefix in
                         cidrs(start, end, bits)]
    with open(path, "w") as handle:
        header(handle, [
            "proxy_pub.netset  -  ipv4+ipv6 hash:net netset", "",
            'CIDR list of public proxies (proxy_type == "PUB").',
            "Compatible with ipset/iptables/nftables/ufw.", "",
            f"Built at  : {now()}", f"CIDR lines: {len(nets)}"])
        for address, prefix, wide in nets:
            text = str(IPv6Address(address)) if wide \
                else inet_ntoa(struct.pack(">I", address))
            handle.write(text if prefix == (128 if wide else 32)
                         else f"{text}/{prefix}")
            handle.write("\n")


def write_buckets(source, column: int, name: str, path: Path) -> None:
    buckets: dict[str, list[str]] = {}
    for wide in (False, True):
        for start, end, value in ranges(source, column, wide):
            buckets.setdefault(value, []).append(span(start, end, wide))
    with open(path, "w") as handle:
        header(handle, [
            f"{name}.buckets  -  IP range -> {name}", "",
            "Categorical field, bucketed per value to avoid string repetition.",
            "  [VALUE]", "  <start_ip>[+<span>]   (v4 then v6, ascending)",
            "span = end - start; omitted when a single IP.",
            "Lookup: scan sections, bisect ranges within the section.", "",
            f"Built at  : {now()}", f"Categories: {len(buckets)}"])
        for value in sorted(buckets):
            handle.write(f"[{value}]\n")
            handle.write("\n".join(buckets[value]))
            handle.write("\n")


def write_table(source, column: int, name: str, path: Path) -> None:
    held = [(start, end, value, wide) for wide in (False, True)
            for start, end, value in ranges(source, column, wide)]
    counts = Counter(value for _, _, value, _ in held)
    words = sorted(counts, key=lambda value: (-counts[value], value))
    place = {value: at for at, value in enumerate(words)}
    with open(path, "w") as handle:
        header(handle, [
            f"{name}.tsv  -  IP range -> {name}", "",
            "Two sections, each introduced by a marker line:",
            "  #dict", "    <idx>\\t<value>",
            "  #data", "    <start_ip>[+<span>]\\t<idx>",
            "span = end - start; omitted when a single IP.",
            "Dict ordered by descending frequency (smaller idx = more common).",
            "v4 block first, then v6; each sorted ascending by start_ip.", "",
            f"Built at    : {now()}", f"Dict entries: {len(words)}",
            f"Entries     : {len(held)}"])
        handle.write("#dict\n")
        handle.write("".join(f"{at}\t{value}\n" for at, value in enumerate(words)))
        handle.write("#data\n")
        handle.write("".join(f"{span(start, end, wide)}\t{place[value]}\n"
                             for start, end, value, wide in held))


def write(source, fields: list[dict], directory: str) -> None:
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    columns = {field["name"]: field["column"] for field in fields}
    write_netset(source, columns["proxy_type"], out / "proxy_pub.netset")
    for name, stem in BUCKETED.items():
        write_buckets(source, columns[name], stem, out / f"{stem}.buckets")
    for name in TABLED:
        write_table(source, columns[name], name, out / f"{name}.tsv")
    for path in sorted(out.iterdir()):
        print(f"{path.name}: {path.stat().st_size / 1e6:.1f} MB")
