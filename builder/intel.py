"""Gather the extra databases: regex lists, cloud ranges, Tor, resolvers, IRR routes."""

import csv
import gzip
import io
import ipaddress
import json
import re
import socket
import sys
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import date, timedelta
from functools import cache
from pathlib import Path

import pycountry

from builder import feeds
from builder.region_country import country

LISTS = Path(__file__).with_name("lists.json")
SETTINGS = {"url", "regex", "within", "days", "hosts"}
ADDRESS = r"[0-9a-fA-F:.]+(?:/\d{1,3})?"
EMPTY = {"", "none", "null", "-", "n/a"}
AZURE_PAGE = "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
AZURE_FILE = r"https://download\.microsoft\.com/[^\"]+ServiceTags_Public_\d+\.json"
TOR = ("https://onionoo.torproject.org/details?type=relay&running=true&fields="
       "nickname,fingerprint,or_addresses,exit_addresses,flags,first_seen,"
       "observed_bandwidth,platform")
RESOLVERS = "https://public-dns.info/nameservers.csv"
ALFRED = "https://raw.githubusercontent.com/lord-alfred/ipranges/main/"
IRR = {
    "RIPE": ("https://ftp.ripe.net/ripe/dbase/split/ripe.db.route.gz",
             "https://ftp.ripe.net/ripe/dbase/split/ripe.db.route6.gz"),
    "APNIC": ("https://ftp.apnic.net/apnic/whois/apnic.db.route.gz",
              "https://ftp.apnic.net/apnic/whois/apnic.db.route6.gz"),
    "AFRINIC": feeds.BULK["AFRINIC"],
    "ARIN": ("https://ftp.arin.net/pub/rr/arin.db.gz",),
    "LACNIC": ("https://ftp.lacnic.net/lacnic/irr/lacnic.db.gz",),
    "NTTCOM": ("https://rr.ntt.net/nttcomRR/nttcom.db.gz",),
    "RADB": ("ftp://ftp.radb.net/radb/dbase/radb.db.gz",),
    "ALTDB": ("ftp://ftp.altdb.net/pub/altdb/altdb.db.gz",),
}
ROUTE_KEYS = ("route", "route6", "origin", "mnt-by", "source")


def opened(data: bytes) -> str:
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    elif data[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            largest = max(archive.infolist(), key=lambda member: member.file_size)
            data = archive.read(largest)
    return data.decode("utf-8", "replace")


def fetched(urls) -> dict[str, str]:
    def one(url: str) -> str | None:
        try:
            return opened(feeds.get(url))
        except Exception as error:
            print(f"missed {url}: {error}", file=sys.stderr)
            return None

    urls = list(dict.fromkeys(urls))
    with ThreadPoolExecutor(16) as pool:
        return dict(zip(urls, pool.map(one, urls)))


def day(text: str) -> str:
    found = re.fullmatch(r"(\d\d)-(\d\d)-(\d{4})", text)
    return f"{found[3]}-{found[2]}-{found[1]}" if found else text[:10]


def kept(value) -> bool:
    return str(value).strip().lower() not in EMPTY


def matches(entry: dict, text: str, place: int):
    if "within" in entry:
        text = "\n".join(re.findall(entry["within"], text, re.S))
    constants = {key: value for key, value in entry.items() if key not in SETTINGS}
    oldest = str(date.today() - timedelta(days=entry["days"])) if "days" in entry else ""
    for match in re.finditer(entry["regex"], text, re.M):
        groups = match.groupdict() or {"ip": match[1]}
        record = constants | {key: value.strip() for key, value in groups.items()
                              if value and kept(value)}
        if "first_seen" in record:
            record["first_seen"] = day(record["first_seen"])
            if record["first_seen"] < oldest:
                continue
        record["lists"] = place
        yield record.pop("ip"), record


def addresses(host: str) -> list[str]:
    try:
        return [held[4][0] for held in socket.getaddrinfo(host, None)]
    except OSError:
        return []


def resolved(pattern: str, text: str) -> str:
    """Hostname lists become the addresses they resolve to, one per line."""
    hosts = sorted(set(re.findall(pattern, text, re.M)))
    with ThreadPoolExecutor(32) as pool:
        found = {address for held in pool.map(addresses, hosts) for address in held}
    return "\n".join(sorted(found))


def listed(name: str) -> list[tuple[str, dict]]:
    """One lists.json section: named groups (else group 1 as ip) and constants."""
    entries = json.loads(LISTS.read_text())[name]
    bodies = fetched(entry["url"] for entry in entries)
    rows = []
    for place, entry in enumerate(entries):
        text = bodies.get(entry["url"])
        if text and "hosts" in entry:
            text = resolved(entry["hosts"], text)
        found = list(matches(entry, text, place)) if text else []
        print(f"{name}: {len(found)} from {entry['url']}", file=sys.stderr)
        rows += found
    return rows


@cache
def located(region: str) -> str:
    if region.lower() in ("", "global"):
        return ""
    return country(region) or ""


def network(text: str) -> bool:
    try:
        ipaddress.ip_network(text, strict=False)
    except ValueError:
        return False
    return True


def alpha2(code: str) -> str:
    found = pycountry.countries.get(alpha_3=code) if len(code) == 3 else None
    return found.alpha_2 if found else code.upper()


def amazon(text: str):
    held = json.loads(text)
    services: dict[tuple[str, str], list[str]] = {}
    for row in held["prefixes"] + held["ipv6_prefixes"]:
        prefix = row.get("ip_prefix") or row["ipv6_prefix"]
        services.setdefault((prefix, row["region"]), []).append(row["service"])
    for (prefix, region), named in services.items():
        for service in [name for name in named if name != "AMAZON"] or named:
            yield prefix, {"service": service, "region": region}


def google(text: str):
    for row in json.loads(text)["prefixes"]:
        prefix = row.get("ipv4Prefix") or row.get("ipv6Prefix")
        yield prefix, {"service": row.get("service", ""), "region": row.get("scope", "")}


def azure(text: str):
    for tag in json.loads(text)["values"]:
        held = tag["properties"]
        for prefix in held["addressPrefixes"]:
            yield prefix, {"service": held["systemService"], "region": held["region"]}


def oracle(text: str):
    for region in json.loads(text)["regions"]:
        for row in region["cidrs"]:
            yield row["cidr"], {"service": row["tags"], "region": region["region"]}


def ibm(text: str):
    for center in json.loads(text)["data_centers"]:
        for row in center["cidr_networks"]:
            if ipaddress.ip_network(row["cidr_notation"], strict=False).is_private:
                continue
            yield row["cidr_notation"], {
                "service": row["service"], "region": center["name"],
                "city": center["city"], "country": alpha2(center["country"])}


def keyed(text: str):
    """Services named by the JSON keys that hold them: GitHub meta, Datadog."""
    for service, value in json.loads(text).items():
        lists = value.values() if isinstance(value, dict) else [value]
        for held in lists:
            for prefix in held if isinstance(held, list) else ():
                if isinstance(prefix, str) and network(prefix):
                    yield prefix, {"service": service}


def atlassian(text: str):
    for row in json.loads(text)["items"]:
        yield row["cidr"], {"service": row["product"], "region": row["region"]}


def zscaler(text: str):
    for cities in json.loads(text)["zscaler.net"].values():
        for named, rows in cities.items():
            city = named.partition(":")[2].strip()
            for row in rows:
                yield row["range"], {"service": "ZIA", "city": city,
                                     "country": located(city)}


def office(text: str):
    for row in json.loads(text):
        for prefix in row.get("ips", ()):
            yield prefix, {"service": row["serviceAreaDisplayName"]}


def found(service: str, pattern: str = ADDRESS):
    """Every address or range a page names, whatever wraps it."""
    def ranges(text: str):
        for prefix in re.findall(pattern, text, re.M):
            if network(prefix):
                yield prefix, {"service": service}
    return ranges


def geofeed(service: str):
    def rows(text: str):
        for line in text.splitlines():
            parts = [part.strip() for part in line.split(",")]
            if len(parts) < 4 or line.startswith("#"):
                continue
            yield parts[0], {"service": service, "country": parts[1].upper(),
                             "city": parts[3]}
    return rows


CLOUD = [
    ("Amazon Web Services", "https://ip-ranges.amazonaws.com/ip-ranges.json", amazon),
    ("Amazon Web Services", "https://ip-ranges.amazonaws.com/geo-ip-feed.csv",
     geofeed("")),
    ("Google Cloud", "https://www.gstatic.com/ipranges/cloud.json", google),
    ("Google Cloud", "https://www.gstatic.com/ipranges/cloud_geofeed", geofeed("")),
    ("Google", "https://www.gstatic.com/ipranges/publicdns.json", found("Public DNS")),
    ("Microsoft Azure", None, azure),
    ("Microsoft 365", "https://endpoints.office.com/endpoints/worldwide?"
     "clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7", office),
    ("Oracle Cloud", "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json",
     oracle),
    ("IBM Cloud", "https://raw.githubusercontent.com/dprosper/cidr-calculator/main/"
     "data/datacenters.json", ibm),
    ("GitHub", "https://api.github.com/meta", keyed),
    ("Datadog", "https://ip-ranges.datadoghq.com/", keyed),
    ("Atlassian", "https://ip-ranges.atlassian.com/", atlassian),
    ("Zscaler", "https://config.zscaler.com/api/zscaler.net/cenr/json", zscaler),
    ("Cloudflare", "https://www.cloudflare.com/ips-v4/", found("CDN")),
    ("Cloudflare", "https://www.cloudflare.com/ips-v6/", found("CDN")),
    ("Cloudflare", "https://api.cloudflare.com/local-ip-ranges.csv", geofeed("egress")),
    ("Cloudflare", "https://api.cloudflare.com/warp-egress-ip-ranges.csv",
     geofeed("WARP")),
    ("Fastly", "https://api.fastly.com/public-ip-list", found("CDN")),
    ("DigitalOcean", "https://digitalocean.com/geo/google.csv", geofeed("")),
    ("Akamai Linode", "https://geoip.linode.com/", geofeed("")),
    ("Vultr", "https://geofeed.constant.com/", geofeed("")),
    ("Exoscale", "https://exoscale-prefixes.sos.exo.io/exoscale_geofeed", geofeed("")),
    ("UpCloud", "https://upcloud.com/geofeed.csv", geofeed("")),
    ("Equinix Metal", "https://geofeed.equinixmetal.com/", geofeed("")),
    ("Cherry Servers", "https://geofeed.cherryservers.com/geofeed.csv", geofeed("")),
    ("Hostinger", "https://raw.githubusercontent.com/hostinger/geofeed/main/geofeed.csv",
     geofeed("")),
    ("Civo", "https://raw.githubusercontent.com/civo/geofeed/master/civo-geofeed.csv",
     geofeed("")),
    ("STACKIT", "https://raw.githubusercontent.com/SchwarzIT/geofeeds/main/geofeed.csv",
     geofeed("")),
    ("Clouvider", "https://clouvider.com/geoipfeed.csv", geofeed("")),
    ("Akamai Linode", f"{ALFRED}linode/ipv4.txt", found("")),
    ("Akamai Linode", f"{ALFRED}linode/ipv6.txt", found("")),
    ("Vultr", f"{ALFRED}vultr/ipv4.txt", found("")),
    ("Vultr", f"{ALFRED}vultr/ipv6.txt", found("")),
    ("Amazon Web Services", "https://d7uri8nf7uskq.cloudfront.net/tools/"
     "list-cloudfront-ips", found("CLOUDFRONT")),
    ("Bunny CDN", "https://api.bunny.net/system/edgeserverlist", found("CDN")),
    ("CacheFly", "https://cachefly.cachefly.net/ips/cdn.txt", found("CDN")),
    ("Gcore", "https://api.gcore.com/cdn/public-ip-list", found("CDN")),
    ("Imperva", "https://my.imperva.com/api/integration/v1/ips", found("CDN")),
    ("KeyCDN", "https://www.keycdn.com/shield-prefixes.json", found("CDN")),
    ("ArvanCloud", "https://www.arvancloud.ir/en/ips.txt", found("CDN")),
    ("QUIC.cloud", "https://quic.cloud/ips?ln", found("CDN")),
    ("Netflix Open Connect",
     "https://raw.githubusercontent.com/Netflix/nflx-geofeed/main/geofeed.csv",
     geofeed("CDN")),
    ("Google", "https://www.gstatic.com/ipranges/goog.json", found("")),
    ("Google", "https://www.gstatic.com/geofeed/corp_external", geofeed("corporate")),
    ("Google", "https://www.gstatic.com/vpn/geofeed", geofeed("VPN by Google")),
    ("Apple", "https://mask-api.icloud.com/egress-ip-ranges.csv",
     geofeed("iCloud Private Relay")),
    ("Microsoft", "https://download.microsoft.com/download/"
     "0b9dc6ca-68f9-43b2-b094-da4f6d509bc3/geoloc-Microsoft.csv", geofeed("")),
    ("Meta", f"{ALFRED}facebook/ipv4.txt", found("")),
    ("Meta", f"{ALFRED}facebook/ipv6.txt", found("")),
    ("X", f"{ALFRED}twitter/ipv4.txt", found("")),
    ("X", f"{ALFRED}twitter/ipv6.txt", found("")),
    ("Telegram", "https://core.telegram.org/resources/cidr.txt", found("")),
    ("Yandex", "https://yandex.com/ips",
     found("", r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}/\d{1,2}")),
    ("Zoom", "https://assets.zoom.us/docs/ipranges/Zoom.txt", found("")),
    ("Okta", "https://s3.amazonaws.com/okta-ip-ranges/ip_ranges.json", found("")),
    ("Salesforce", "https://ip-ranges.salesforce.com/ip-ranges.json", found("")),
    ("Stripe", "https://stripe.com/files/ips/ips_api.txt", found("API")),
    ("Stripe", "https://stripe.com/files/ips/ips_webhooks.txt", found("webhooks")),
    ("Stripe", "https://stripe.com/files/ips/ips_armada_gator.txt", found("Armada")),
    ("Auth0", "https://cdn.auth0.com/ip-ranges.json", found("")),
    ("Paddle", "https://api.paddle.com/ips", found("webhooks")),
    ("Check Point", "https://raw.githubusercontent.com/ShadowWhisperer/IPs/master/Lists/"
     "Tunnels.csv", found("SASE", r"^([0-9a-fA-F:.]+),Check Point\r?$")),
]


def azure_file() -> str:
    found = re.search(AZURE_FILE, fetched([AZURE_PAGE])[AZURE_PAGE] or "")
    return found[0] if found else AZURE_PAGE


def parsed(parse, text: str | None) -> list:
    try:
        return list(parse(text)) if text else []
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        print(f"unreadable: {error}", file=sys.stderr)
        return []


def cloud() -> list[tuple[str, dict]]:
    """Each provider's published ranges with the service, region and place it names."""
    sources = [(provider, url or azure_file(), parse) for provider, url, parse in CLOUD]
    bodies = fetched(url for _, url, _ in sources)
    rows = []
    for provider, url, parse in sources:
        found = parsed(parse, bodies.get(url))
        print(f"cloud: {len(found)} from {provider} {url}", file=sys.stderr)
        for prefix, record in found:
            region = record.get("region", "")
            if "country" not in record and isinstance(region, str):
                record["country"] = located(region)
            rows.append((prefix, {"provider": provider, **record}))
    return rows


def tor() -> list[tuple[str, dict]]:
    """Every running relay on every address it listens or exits on."""
    rows = []
    for relay in json.loads(fetched([TOR])[TOR] or "{}").get("relays", ()):
        hosts = [held.rpartition(":")[0].strip("[]") for held in relay["or_addresses"]]
        record = {"nickname": relay["nickname"], "fingerprint": relay["fingerprint"],
                  "flags": relay.get("flags", []), "first_seen": relay["first_seen"][:10],
                  "bandwidth": relay.get("observed_bandwidth", 0),
                  "platform": relay.get("platform", ""), "relays": relay["fingerprint"]}
        for address in dict.fromkeys(hosts + relay.get("exit_addresses", [])):
            rows.append((address, record))
    print(f"tor: {len(rows)} addresses", file=sys.stderr)
    return rows


def resolvers() -> list[tuple[str, dict]]:
    """Public resolvers that answered public-dns.info's last check."""
    rows = []
    for row in csv.DictReader(io.StringIO(fetched([RESOLVERS])[RESOLVERS] or "")):
        reliability = round(float(row["reliability"] or 0) * 100)
        if not reliability or row["error"]:
            continue
        rows.append((row["ip_address"], {
            "name": row["name"].rstrip("."), "software": row["version"],
            "dnssec": int(row["dnssec"] == "true"), "reliability": reliability}))
    print(f"resolvers: {len(rows)} addresses", file=sys.stderr)
    return rows


def irr(cache: str) -> list[tuple[str, dict]]:
    """Route objects of every registry and the large IRRs: who may originate a prefix."""
    directory = Path(cache)
    directory.mkdir(parents=True, exist_ok=True)
    rows = []
    for registry, urls in IRR.items():
        for place, url in enumerate(urls):
            name = registry if registry == "AFRINIC" else f"irr-{registry}"
            try:
                path = feeds.cached(directory, name, place, url)
            except Exception as error:
                print(f"missed {url}: {error}", file=sys.stderr)
                continue
            for held in feeds.objects(path, ROUTE_KEYS):
                prefix = held.get("route") or held.get("route6")
                if prefix and held.get("origin"):
                    rows.append((prefix, {
                        "origin": held["origin"].upper().split()[0],
                        "source": held.get("source", registry).upper().split()[0],
                        "maintainer": held.get("mnt-by", "").partition(" ")[0]}))
    print(f"irr: {len(rows)} route objects", file=sys.stderr)
    return rows
