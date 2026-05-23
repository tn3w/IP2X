<div align="center">

# 🌍 IP2X

Fast IP intelligence with compressed binary databases

<p align="center">
  <img src="https://img.shields.io/github/actions/workflow/status/tn3w/IP2X/build.yml?label=Build&style=for-the-badge" alt="Build">
</p>

<p align="center">
  <a href="https://github.com/tn3w/IP2X/releases/latest/download/geo.bin">
    <img src="https://img.shields.io/badge/geo.bin-42MB-blue?style=for-the-badge" alt="Download geo">
  </a>
</p>

</div>

## 📥 Download

```bash
wget https://github.com/tn3w/IP2X/releases/latest/download/geo.bin
ls -lh geo.bin
```

Updated daily via GitHub Actions.

## Overview

**IP2X** packages public IP data into compact, mmap-friendly binary files for fast lookups. Each binary is built by a small, single-purpose Rust crate inside this repo.

| crate | output | content | size |
|---|---|---|---|
| [`ip2loc`](ip2loc/) | `geo.bin` | IP → (latitude, longitude) | ~42 MB |

`ip2loc` combines IP2Location DB11 LITE (preferred) with MaxMind GeoLite2-City (fallback). Coordinates quantised to 0.001° (~111 m, village-scale). See [`ip2loc/README.md`](ip2loc/README.md) for the file format and optimisation history.

## ✨ Features

- **IPv4 & IPv6** full coverage from a single file
- **mmap-friendly** ~0.2 MB resident at open; pages fault in on demand
- **Sub-µs lookups** binary search over delta-encoded blocks
- **No runtime decompression** all encoding is structural (bit-packing, deltas, truncation)

## 🚀 Quick start

### Build locally

```bash
# 1. Get the source DBs (or let the workflow do it)
#    IP2LOCATION-LITE-DB11.IPV6.BIN   (from ip2location.com)
#    GeoLite2-City.mmdb               (e.g. github.com/P3TERX/GeoLite.mmdb)

# 2. Build the binary
cd ip2loc
cargo build --release

# 3. Pack the data
./target/release/ip2loc build \
    --ip2l ../IP2LOCATION-LITE-DB11.IPV6.BIN \
    --mmdb ../GeoLite2-City.mmdb \
    --out  ../geo.bin

# 4. Look something up
./target/release/ip2loc lookup --db ../geo.bin 8.8.8.8
# 37.386, -122.084
```

### Read from your own program

`geo.bin` is a self-describing little-endian format starting with magic `GEO1`. The reader is ~30 lines: binary-search `v4_bases`, binary-search the deltas inside the matched block, read a bit-packed point index, decode two i24 values, divide by 1000. Full layout in [`ip2loc/README.md`](ip2loc/README.md).

## 🔄 Automated updates

[`.github/workflows/build.yml`](.github/workflows/build.yml):

1. Downloads `DB11LITEBINIPV6` from IP2Location (token via `IP2LOCATION_TOKEN` secret).
2. Downloads `GeoLite2-City.mmdb` from a public mirror.
3. Builds `geo.bin` with `ip2loc`.
4. Publishes a timestamped release; prunes to the latest 5.

## 📝 Attribution

IP2X uses the IP2Location LITE database for <a href="https://lite.ip2location.com">IP geolocation</a>, and MaxMind GeoLite2 for fallback coverage.

## 📄 License

Copyright 2026 TN3W

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
