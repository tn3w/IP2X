<div align="center">

# 🌍 IP2X

Fast IP geolocation and proxy detection with compressed binary databases

<p align="center">
  <img src="https://img.shields.io/github/actions/workflow/status/tn3w/IP2X/update-databases.yml?label=Build&style=for-the-badge" alt="GitHub Workflow Status">
</p>

<p align="center">
  <a href="https://github.com/tn3w/IP2X/releases/latest/download/geo.bin">
    <img src="https://img.shields.io/badge/geo.bin-216MB-blue?style=for-the-badge" alt="Download Geo">
  </a>
  <a href="https://github.com/tn3w/IP2X/releases/latest/download/asn.bin">
    <img src="https://img.shields.io/badge/asn.bin-62MB-green?style=for-the-badge" alt="Download ASN">
  </a>
  <a href="https://github.com/tn3w/IP2X/releases/latest/download/isp.bin">
    <img src="https://img.shields.io/badge/isp.bin-32MB-orange?style=for-the-badge" alt="Download ISP">
  </a>
  <a href="https://github.com/tn3w/IP2X/releases/latest/download/proxy_types.bin">
    <img src="https://img.shields.io/badge/proxy__types.bin-8MB-red?style=for-the-badge" alt="Download Proxy">
  </a>
</p>

<p align="center">
  <a href="#quick-start">🚀 Quick Start</a> •
  <a href="#features">✨ Features</a> •
  <a href="#usage">💡 Usage</a>
</p>

</div>

## 📥 Download & Extract

Pre-built binary databases are available for download:

```bash
# Download the latest release files
wget https://github.com/tn3w/IP2X/releases/latest/download/geo.bin
wget https://github.com/tn3w/IP2X/releases/latest/download/proxy_types.bin
wget https://github.com/tn3w/IP2X/releases/latest/download/asn.bin
wget https://github.com/tn3w/IP2X/releases/latest/download/isp.bin

# Verify the files
ls -lh *.bin
```

The binary databases are approximately 320MB total and updated daily via GitHub Actions.

## 📊 Architecture

```
CSV Data ──────────> Rust Builder ──────────> Binary Databases
(IP2Location)        (main.rs)                (geo.bin, etc.)
                          │
                          └──> MaxMind Reader
                               (GeoLite2-City.mmdb)
```

## Overview

**IP2X** converts IP2Location CSV databases into highly compressed binary formats for fast lookups. It combines IP2Location data with MaxMind GeoLite2 for comprehensive IP intelligence.

The project includes:
- **Rust builder** — Processes CSV files into optimized binary databases
- **Python reader** — Fast lookups with minimal dependencies

## ✨ Features

- **Geolocation** — Latitude/longitude coordinates for any IP
- **Proxy Detection** — Identify proxy types (VPN, TOR, DCH, etc.)
- **ASN Information** — Autonomous System Numbers and names
- **ISP Data** — Internet Service Provider and domain information
- **IPv4 & IPv6** — Full support for both protocols
- **Compressed Format** — Varint encoding reduces file sizes by 60-70%

## 🚀 Quick Start

### Build Binary Databases

```bash
# Set up data directory with CSV files
export DATA_DIR=./data

# Build binary databases
cargo run --release
```

This generates: `geo.bin`, `proxy_types.bin`, `asn.bin`, `isp.bin`

### Lookup IP Information

```python
from ip2x import DatabaseLoader
import json

# Load databases into memory once
db = DatabaseLoader()
db.load_all()

# Fast lookups
result = db.lookup_all("8.8.8.8")
print(json.dumps(result, indent=2))
```

**Output:**
```
Databases loaded in 24.033s
{
  "ip": "8.8.8.8",
  "latitude": 37.386,
  "longitude": -122.084,
  "cidr": "8.8.8.0/24",
  "asn": "15169",
  "as_name": "Google LLC"
}
Lookup completed in 0.139ms
```

## 📦 Data Sources

The builder requires these CSV files in the `data/` directory:

| File | Description | Source |
|------|-------------|--------|
| `DB5LITECSV.CSV` | IPv4 geolocation | IP2Location |
| `DB5LITECSVIPV6.CSV` | IPv6 geolocation | IP2Location |
| `DBASNLITE.CSV` | IPv4 ASN data | IP2Location |
| `DBASNLITEIPV6.CSV` | IPv6 ASN data | IP2Location |
| `PX12LITECSV.CSV` | IPv4 proxy data | IP2Location |
| `PX12LITECSVIPV6.CSV` | IPv6 proxy data | IP2Location |
| `GeoLite2-City.mmdb` | Additional geo data | MaxMind |

Download IP2Location databases from [ip2location.com](https://www.ip2location.com/) (requires free account).

## 💡 Usage

### Individual Lookups

```python
from ip2x import DatabaseLoader

db = DatabaseLoader()
db.load_all()

# Geolocation only
geo = db.lookup_geo("1.1.1.1")
# {"latitude": -37.7, "longitude": 145.183}

# ASN information
asn = db.lookup_asn("1.1.1.1")
# {"cidr": "1.1.1.0/24", "asn": "13335", "as_name": "CLOUDFLARENET"}

# Proxy detection
proxy = db.lookup_proxy_type("1.1.1.1")
# {"proxy_type": "DCH"} or {}

# ISP information
isp = db.lookup_isp("1.1.1.1")
# {"isp": "Cloudflare", "domain": "cloudflare.com", "provider": "-"}
```

### Batch Processing

```python
from ip2x import DatabaseLoader

db = DatabaseLoader()
db.load_all()

ips = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
results = [db.lookup_all(ip) for ip in ips]
```

## 🛠️ Requirements

**Builder:**
- Rust 1.70+
- IP2Location CSV files
- GeoLite2-City.mmdb

**Reader:**
- Python 3.7+
- No external dependencies

## 🔄 Automated Updates

The project includes a GitHub Actions workflow that:
- Downloads latest IP2Location databases daily
- Builds binary files
- Creates releases with updated databases

See [`.github/workflows/update-databases.yml`](.github/workflows/update-databases.yml) for details.

## 📄 License

MIT
