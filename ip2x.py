import struct
import ipaddress
import json
import time
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple


def ip_to_int(ip: str) -> int:
    ip_obj = ipaddress.ip_address(ip)
    if ip_obj.version == 4:
        return (0xFFFF << 32) | int(ip_obj)
    return int(ip_obj)


def read_varint(f) -> int:
    result = shift = 0
    while True:
        byte = f.read(1)[0]
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result
        shift += 7


def read_signed_varint(f) -> int:
    result = shift = 0
    while True:
        byte = f.read(1)[0]
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return (result >> 1) ^ -(result & 1)
        shift += 7


def binary_search(ranges: list, target: int) -> Optional[int]:
    left, right = 0, len(ranges) - 1
    best_match = None
    best_size = float('inf')

    while left <= right:
        mid = (left + right) // 2
        start = ranges[mid][0]
        end = ranges[mid][1]

        if start <= target <= end:
            size = end - start
            if size < best_size:
                best_size = size
                best_match = mid
            left = mid + 1
        elif target < start:
            right = mid - 1
        else:
            left = mid + 1

    return best_match


class DatabaseLoader:
    def __init__(self):
        self.geo_ranges: List[Tuple] = []
        self.proxy_types: Dict[str, List[Tuple]] = {}
        self.asn_strings: List[str] = []
        self.asn_ranges: List[Tuple] = []
        self.isp_strings: List[str] = []
        self.isp_ranges: List[Tuple] = []
        self.isp_use_u16: bool = True

    def load_all(self):
        start = time.time()
        self._load_geo()
        self._load_proxy_types()
        self._load_asn()
        self._load_isp()
        elapsed = time.time() - start
        print(f"Databases loaded in {elapsed:.3f}s")

    def _load_geo(self):
        if not Path("geo.bin").exists():
            return

        with open("geo.bin", "rb") as f:
            count = struct.unpack("<I", f.read(4))[0]
            current = 0

            for _ in range(count):
                current += read_varint(f)
                size = read_varint(f)
                lat = struct.unpack("<i", f.read(4))[0] / 1000.0
                lon = struct.unpack("<i", f.read(4))[0] / 1000.0
                self.geo_ranges.append((current, current + size, lat, lon))

    def _load_proxy_types(self):
        if not Path("proxy_types.bin").exists():
            return

        with open("proxy_types.bin", "rb") as f:
            type_count = struct.unpack("<H", f.read(2))[0]

            for _ in range(type_count):
                name_len = struct.unpack("<B", f.read(1))[0]
                proxy_type = f.read(name_len).decode("utf-8")
                range_count = struct.unpack("<I", f.read(4))[0]

                ranges = []
                current = 0
                for _ in range(range_count):
                    current += read_varint(f)
                    size = read_varint(f)
                    ranges.append((current, current + size))

                self.proxy_types[proxy_type] = ranges

    def _load_asn(self):
        if not Path("asn.bin").exists():
            return

        with open("asn.bin", "rb") as f:
            str_count = struct.unpack("<I", f.read(4))[0]
            for _ in range(str_count):
                str_len = struct.unpack("<H", f.read(2))[0]
                self.asn_strings.append(f.read(str_len).decode("utf-8"))

            range_count = struct.unpack("<I", f.read(4))[0]
            current = cidr = asn = name = 0

            for _ in range(range_count):
                current += read_varint(f)
                size = read_varint(f)
                cidr += read_signed_varint(f)
                asn += read_signed_varint(f)
                name += read_signed_varint(f)
                self.asn_ranges.append(
                    (current, current + size, cidr, asn, name)
                )

    def _load_isp(self):
        if not Path("isp.bin").exists():
            return

        with open("isp.bin", "rb") as f:
            str_count = struct.unpack("<I", f.read(4))[0]
            for _ in range(str_count):
                str_len = struct.unpack("<H", f.read(2))[0]
                self.isp_strings.append(
                    "-" if str_len == 0 else f.read(str_len).decode("utf-8")
                )

            self.isp_use_u16 = str_count < 65536
            range_count = struct.unpack("<I", f.read(4))[0]
            current = 0

            for _ in range(range_count):
                current += read_varint(f)
                size = read_varint(f)
                fmt = "<HHH" if self.isp_use_u16 else "<III"
                isp_idx, domain_idx, provider_idx = struct.unpack(
                    fmt, f.read(6 if self.isp_use_u16 else 12)
                )
                self.isp_ranges.append(
                    (current, current + size, isp_idx, domain_idx, provider_idx)
                )

    def lookup_geo(self, ip: str) -> Dict[str, Any]:
        if not self.geo_ranges:
            return {}

        target = ip_to_int(ip)
        idx = binary_search(self.geo_ranges, target)
        if idx is not None:
            return {
                "latitude": self.geo_ranges[idx][2],
                "longitude": self.geo_ranges[idx][3],
            }
        return {}

    def lookup_proxy_type(self, ip: str) -> Dict[str, Any]:
        if not self.proxy_types:
            return {}

        target = ip_to_int(ip)
        for proxy_type, ranges in self.proxy_types.items():
            if binary_search(ranges, target) is not None:
                return {"proxy_type": proxy_type}
        return {}

    def lookup_asn(self, ip: str) -> Dict[str, Any]:
        if not self.asn_ranges:
            return {}

        target = ip_to_int(ip)
        idx = binary_search(self.asn_ranges, target)
        if idx is not None:
            r = self.asn_ranges[idx]
            return {
                "cidr": self.asn_strings[r[2]],
                "asn": self.asn_strings[r[3]],
                "as_name": self.asn_strings[r[4]],
            }
        return {}

    def lookup_isp(self, ip: str) -> Dict[str, Any]:
        if not self.isp_ranges:
            return {}

        target = ip_to_int(ip)
        idx = binary_search(self.isp_ranges, target)
        if idx is not None:
            r = self.isp_ranges[idx]
            return {
                "isp": self.isp_strings[r[2]],
                "domain": self.isp_strings[r[3]],
                "provider": self.isp_strings[r[4]],
            }
        return {}

    def lookup_all(self, ip: str) -> Dict[str, Any]:
        return {
            "ip": ip,
            **self.lookup_geo(ip),
            **self.lookup_asn(ip),
            **self.lookup_proxy_type(ip),
            **self.lookup_isp(ip),
        }


db = DatabaseLoader()
db.load_all()

start = time.time()
result = db.lookup_all("8.8.8.8")
elapsed = time.time() - start

print(json.dumps(result, indent=2))
print(f"Lookup completed in {elapsed*1000:.3f}ms")
