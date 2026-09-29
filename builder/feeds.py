"""Discover RFC 8805 geofeeds from the RIR bulk WHOIS dumps and fetch them all."""

import argparse
import csv
import gzip
import ipaddress
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.request import Request, urlopen

BULK = {
    "RIPE": ("https://ftp.ripe.net/ripe/dbase/split/ripe.db.inetnum.gz",
             "https://ftp.ripe.net/ripe/dbase/split/ripe.db.inet6num.gz"),
    "APNIC": ("https://ftp.apnic.net/apnic/whois/apnic.db.inetnum.gz",
              "https://ftp.apnic.net/apnic/whois/apnic.db.inet6num.gz"),
    "AFRINIC": ("https://ftp.afrinic.net/pub/dbase/afrinic.db.gz",),
}
ORGANISATIONS = {
    "RIPE": "https://ftp.ripe.net/ripe/dbase/split/ripe.db.organisation.gz",
    "APNIC": "https://ftp.apnic.net/apnic/whois/apnic.db.organisation.gz",
}
LACNIC = "https://milacnic.lacnic.net/lacnic/geofeeds"
THREADS = 64
TIMEOUT = 25
LIMIT = 64 << 20
AGENT = "IP2X geofeed fetcher (+https://github.com/tn3w/IP2X)"
COLUMNS = ("cidr", "country", "region", "city", "postal", "feed", "rir")


def get(url: str, limit: int = LIMIT) -> bytes:
    with urlopen(Request(url, headers={"User-Agent": AGENT}), timeout=TIMEOUT) as held:
        return held.read(limit)


def cached(directory: Path, rir: str, place: int, url: str) -> Path:
    path = directory / f"{rir.lower()}-{place}.gz"
    if not path.exists():
        print(f"download {url}", file=sys.stderr)
        path.write_bytes(get(url, 2 << 30))
    return path


def spans(text: str) -> tuple[int, int] | None:
    text = text.strip()
    if "-" in text and "/" not in text:
        low, _, high = text.partition("-")
        try:
            return int(ipaddress.ip_address(low.strip())), \
                int(ipaddress.ip_address(high.strip()))
        except ValueError:
            return None
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None
    return int(network[0]), int(network[-1])


def referenced(line: str) -> str | None:
    value = line.partition(":")[2].strip()
    if "geofeed" not in value.lower() or "http" not in value:
        return None
    return value[value.find("http"):].split()[0]


def discover(rir: str, path: Path) -> list[tuple[str, tuple[int, int], str]]:
    """One object at a time: the range it covers and the feed it points at."""
    out, authority, url = [], None, None
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.rstrip()
            if not line:
                if authority and url:
                    out.append((rir, authority, url))
                authority = url = None
            elif line.startswith(("inetnum:", "inet6num:")):
                authority = spans(line.partition(":")[2])
            elif line.startswith("geofeed:"):
                url = line.partition(":")[2].strip()
            elif line.startswith("remarks:"):
                url = referenced(line) or url
    if authority and url:
        out.append((rir, authority, url))
    return out


def body(url: str) -> str | None:
    try:
        return get(url).decode("utf-8", "replace")
    except Exception:
        return None


def parsed(text: str) -> list[tuple[tuple[int, int], list[str]]]:
    """A feed is parsed once, however many registry objects point at it."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [part.strip() for part in line.split(",")]
        found = spans(parts[0])
        if found is None:
            continue
        out.append((found, [parts[0], *(parts[place] if place < len(parts) else ""
                                        for place in range(1, 5))]))
    return out


def covered(authority: tuple[int, int] | None, span: tuple[int, int]) -> bool:
    return not authority or (authority[0] <= span[0] and span[1] <= authority[1])


def named(authority: tuple[int, int] | None) -> str:
    if authority is None:
        return ""
    low, high = (ipaddress.ip_address(edge) for edge in authority)
    return f"{low} - {high}"


def fetch(cache: str, out: str) -> None:
    directory = Path(cache)
    directory.mkdir(parents=True, exist_ok=True)
    entries = []
    for rir, urls in BULK.items():
        for place, url in enumerate(urls):
            entries += discover(rir, cached(directory, rir, place, url))
    entries.append(("LACNIC", None, LACNIC))
    print(f"discovered {len(entries)} feed references", file=sys.stderr)

    references = Path(out).with_name("geofeeds.csv")
    with open(references, "w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("rir", "inetnum", "url"))
        for rir, authority, url in entries:
            writer.writerow((rir, named(authority), url))

    urls = list(dict.fromkeys(url for _, _, url in entries))
    print(f"fetching {len(urls)} unique feeds", file=sys.stderr)
    with ThreadPoolExecutor(THREADS) as pool:
        bodies = dict(zip(urls, pool.map(body, urls)))
    print(f"fetched {sum(held is not None for held in bodies.values())}/{len(urls)}",
          file=sys.stderr)
    tables = {url: parsed(text) for url, text in bodies.items() if text is not None}

    count = 0
    with open(out, "w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(COLUMNS)
        for rir, authority, url in entries:
            for span, row in tables.get(url, ()):
                if covered(authority, span):
                    writer.writerow((*row, url, rir))
                    count += 1
    print(f"wrote {count} rows to {out}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description="fetch the RIR geofeed references")
    parser.add_argument("--cache", default=".cache/rir-bulk")
    parser.add_argument("--out", default="geofeeds_data.csv")
    args = parser.parse_args()
    fetch(args.cache, args.out)


if __name__ == "__main__":
    main()
