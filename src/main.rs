use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};

mod maxmind;
use maxmind::MaxMindReader;

fn main() {
    let data_dir = std::env::var("DATA_DIR").unwrap_or_else(|_| "data".to_string());
    build_geo_bin(&data_dir);
    build_proxy_types_bin(&data_dir);
    build_asn_bin(&data_dir);
    build_isp_bin(&data_dir);
}

fn write_varint(out: &mut BufWriter<File>, mut value: u128) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.write_all(&[byte]).unwrap();
        if value == 0 {
            break;
        }
    }
}

fn write_signed_varint(out: &mut BufWriter<File>, value: i64) {
    let encoded = ((value << 1) ^ (value >> 63)) as u64;
    let mut val = encoded;
    loop {
        let mut byte = (val & 0x7F) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
        }
        out.write_all(&[byte]).unwrap();
        if val == 0 {
            break;
        }
    }
}

fn build_geo_bin(data_dir: &str) {
    let mut ranges = Vec::new();

    process_geo_csv(&format!("{}/DB5LITECSV.CSV", data_dir), true, &mut ranges);
    process_geo_csv(
        &format!("{}/DB5LITECSVIPV6.CSV", data_dir),
        false,
        &mut ranges,
    );

    let maxmind_path = format!("{}/GeoLite2-City.mmdb", data_dir);
    if let Ok(reader) = MaxMindReader::open(&maxmind_path) {
        let maxmind_entries = reader.load_all_geo();

        let mut range_map: HashMap<(u128, u128), usize> = HashMap::new();
        for (i, range) in ranges.iter().enumerate() {
            range_map.insert((range.0, range.1), i);
        }

        for (start, end, lat, lon) in maxmind_entries {
            if lat == 0.0 && lon == 0.0 {
                continue;
            }

            if !range_map.contains_key(&(start, end)) {
                ranges.push((start, end, lat, lon));
            }
        }
    }

    ranges.sort_by(|a, b| {
        a.0.cmp(&b.0).then_with(|| {
            let size_a = a.1 - a.0;
            let size_b = b.1 - b.0;
            size_a.cmp(&size_b)
        })
    });

    let mut out = BufWriter::new(File::create("geo.bin").unwrap());
    out.write_all(&(ranges.len() as u32).to_le_bytes()).unwrap();

    let mut prev_from = 0u128;
    for (from, to, lat, lon) in &ranges {
        let from_delta = from - prev_from;
        let range_size = to - from;

        write_varint(&mut out, from_delta);
        write_varint(&mut out, range_size);

        let lat_i32 = (lat * 1000.0).round() as i32;
        let lon_i32 = (lon * 1000.0).round() as i32;
        out.write_all(&lat_i32.to_le_bytes()).unwrap();
        out.write_all(&lon_i32.to_le_bytes()).unwrap();

        prev_from = *from;
    }
}

fn process_geo_csv(path: &str, is_v4: bool, ranges: &mut Vec<(u128, u128, f32, f32)>) {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.unwrap();
        let parts = parse_csv_line(&line);

        if parts.len() < 8 {
            continue;
        }

        let mut from = parse_u128(&parts[0]);
        let mut to = parse_u128(&parts[1]);
        let lat = parse_f32(&parts[6]);
        let lon = parse_f32(&parts[7]);

        if lat == 0.0 && lon == 0.0 {
            continue;
        }

        if is_v4 {
            from = ipv4_to_ipv6(from as u32);
            to = ipv4_to_ipv6(to as u32);
        }

        ranges.push((from, to, lat, lon));
    }
}

fn build_proxy_types_bin(data_dir: &str) {
    let mut types: HashMap<String, Vec<(u128, u128)>> = HashMap::new();

    process_proxy_csv(&format!("{}/PX12LITECSV.CSV", data_dir), true, &mut types);
    process_proxy_csv(
        &format!("{}/PX12LITECSVIPV6.CSV", data_dir),
        false,
        &mut types,
    );

    for ranges in types.values_mut() {
        ranges.sort_by_key(|r| r.0);
    }

    let mut out = BufWriter::new(File::create("proxy_types.bin").unwrap());
    out.write_all(&(types.len() as u16).to_le_bytes()).unwrap();

    for (proxy_type, ranges) in types {
        let bytes = proxy_type.as_bytes();
        out.write_all(&(bytes.len() as u8).to_le_bytes()).unwrap();
        out.write_all(bytes).unwrap();
        out.write_all(&(ranges.len() as u32).to_le_bytes()).unwrap();

        let mut prev_from = 0u128;
        for (from, to) in ranges {
            let from_delta = from - prev_from;
            let range_size = to - from;

            write_varint(&mut out, from_delta);
            write_varint(&mut out, range_size);

            prev_from = from;
        }
    }
}

fn process_proxy_csv(path: &str, is_v4: bool, types: &mut HashMap<String, Vec<(u128, u128)>>) {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.unwrap();
        let parts = parse_csv_line(&line);

        if parts.len() < 3 {
            continue;
        }

        let mut from = parse_u128(&parts[0]);
        let mut to = parse_u128(&parts[1]);
        let proxy_type = parts[2].clone();

        if is_v4 {
            from = ipv4_to_ipv6(from as u32);
            to = ipv4_to_ipv6(to as u32);
        }

        types.entry(proxy_type).or_default().push((from, to));
    }
}

fn build_asn_bin(data_dir: &str) {
    let mut strings = Vec::new();
    let mut string_map = HashMap::new();
    let mut data = Vec::new();

    process_asn_csv(
        &format!("{}/DBASNLITE.CSV", data_dir),
        true,
        &mut data,
        &mut strings,
        &mut string_map,
    );
    process_asn_csv(
        &format!("{}/DBASNLITEIPV6.CSV", data_dir),
        false,
        &mut data,
        &mut strings,
        &mut string_map,
    );

    data.sort_by(|a, b| {
        a.0.cmp(&b.0).then_with(|| {
            let size_a = a.1 - a.0;
            let size_b = b.1 - b.0;
            size_a.cmp(&size_b)
        })
    });

    let mut out = BufWriter::new(File::create("asn.bin").unwrap());

    out.write_all(&(strings.len() as u32).to_le_bytes())
        .unwrap();
    for s in &strings {
        let bytes = s.as_bytes();
        out.write_all(&(bytes.len() as u16).to_le_bytes()).unwrap();
        out.write_all(bytes).unwrap();
    }

    out.write_all(&(data.len() as u32).to_le_bytes()).unwrap();

    let mut prev_from = 0u128;
    let mut prev_cidr = 0usize;
    let mut prev_asn = 0usize;
    let mut prev_name = 0usize;

    for (from, to, cidr_idx, asn_idx, name_idx, _) in &data {
        let from_delta = from - prev_from;
        let range_size = to - from;

        write_varint(&mut out, from_delta);
        write_varint(&mut out, range_size);

        let cidr_delta = (*cidr_idx as i64) - (prev_cidr as i64);
        let asn_delta = (*asn_idx as i64) - (prev_asn as i64);
        let name_delta = (*name_idx as i64) - (prev_name as i64);

        write_signed_varint(&mut out, cidr_delta);
        write_signed_varint(&mut out, asn_delta);
        write_signed_varint(&mut out, name_delta);

        prev_from = *from;
        prev_cidr = *cidr_idx;
        prev_asn = *asn_idx;
        prev_name = *name_idx;
    }
}

fn process_asn_csv(
    path: &str,
    is_v4: bool,
    data: &mut Vec<(u128, u128, usize, usize, usize, usize)>,
    strings: &mut Vec<String>,
    string_map: &mut HashMap<String, usize>,
) {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.unwrap();
        let parts = parse_csv_line(&line);

        if parts.len() < 5 {
            continue;
        }

        let mut from = parse_u128(&parts[0]);
        let mut to = parse_u128(&parts[1]);
        let cidr = &parts[2];
        let asn = &parts[3];
        let as_name = &parts[4];

        if asn == "-" {
            continue;
        }

        if is_v4 {
            from = ipv4_to_ipv6(from as u32);
            to = ipv4_to_ipv6(to as u32);
        }

        let cidr_idx = intern(cidr, strings, string_map);
        let asn_idx = intern(asn, strings, string_map);
        let name_idx = intern(as_name, strings, string_map);
        let org_idx = 0;

        data.push((from, to, cidr_idx, asn_idx, name_idx, org_idx));
    }
}

fn build_isp_bin(data_dir: &str) {
    let mut strings = Vec::new();
    let mut string_map = HashMap::new();
    let mut data = Vec::new();

    process_isp_csv(
        &format!("{}/PX12LITECSV.CSV", data_dir),
        true,
        &mut data,
        &mut strings,
        &mut string_map,
    );
    process_isp_csv(
        &format!("{}/PX12LITECSVIPV6.CSV", data_dir),
        false,
        &mut data,
        &mut strings,
        &mut string_map,
    );

    data.sort_by(|a, b| {
        a.0.cmp(&b.0).then_with(|| {
            let size_a = a.1 - a.0;
            let size_b = b.1 - b.0;
            size_a.cmp(&size_b)
        })
    });

    let mut out = BufWriter::new(File::create("isp.bin").unwrap());
    let use_u16 = strings.len() < 65536;
    write_string_table(&mut out, &strings);
    out.write_all(&(data.len() as u32).to_le_bytes()).unwrap();

    let mut prev_from = 0u128;
    for (from, to, isp_idx, domain_idx, provider_idx) in data {
        let from_delta = from - prev_from;
        let range_size = to - from;

        write_varint(&mut out, from_delta);
        write_varint(&mut out, range_size);

        if use_u16 {
            out.write_all(&(isp_idx as u16).to_le_bytes()).unwrap();
            out.write_all(&(domain_idx as u16).to_le_bytes()).unwrap();
            out.write_all(&(provider_idx as u16).to_le_bytes()).unwrap();
        } else {
            out.write_all(&(isp_idx as u32).to_le_bytes()).unwrap();
            out.write_all(&(domain_idx as u32).to_le_bytes()).unwrap();
            out.write_all(&(provider_idx as u32).to_le_bytes()).unwrap();
        }

        prev_from = from;
    }
}

fn process_isp_csv(
    path: &str,
    is_v4: bool,
    data: &mut Vec<(u128, u128, usize, usize, usize)>,
    strings: &mut Vec<String>,
    string_map: &mut HashMap<String, usize>,
) {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.unwrap();
        let parts = parse_csv_line(&line);

        if parts.len() < 9 {
            continue;
        }

        let mut from = parse_u128(&parts[0]);
        let mut to = parse_u128(&parts[1]);
        let isp = &parts[7];
        let domain = &parts[8];
        let provider = if parts.len() > 13 { &parts[13] } else { "-" };

        if is_v4 {
            from = ipv4_to_ipv6(from as u32);
            to = ipv4_to_ipv6(to as u32);
        }

        let isp_idx = intern_with_offset(isp, strings, string_map);
        let domain_idx = intern_with_offset(domain, strings, string_map);
        let provider_idx = intern_with_offset(provider, strings, string_map);

        data.push((from, to, isp_idx, domain_idx, provider_idx));
    }
}

fn write_string_table(out: &mut BufWriter<File>, strings: &[String]) {
    out.write_all(&((strings.len() + 1) as u32).to_le_bytes())
        .unwrap();
    out.write_all(&(0u16).to_le_bytes()).unwrap();

    for s in strings {
        let bytes = s.as_bytes();
        out.write_all(&(bytes.len() as u16).to_le_bytes()).unwrap();
        out.write_all(bytes).unwrap();
    }
}

fn intern(s: &str, strings: &mut Vec<String>, map: &mut HashMap<String, usize>) -> usize {
    if s == "-" {
        return 0;
    }

    if let Some(&idx) = map.get(s) {
        return idx;
    }

    strings.push(s.to_string());
    let idx = strings.len() - 1;
    map.insert(s.to_string(), idx);
    idx
}

fn intern_with_offset(
    s: &str,
    strings: &mut Vec<String>,
    map: &mut HashMap<String, usize>,
) -> usize {
    if s == "-" {
        return 0;
    }

    if let Some(&idx) = map.get(s) {
        return idx;
    }

    strings.push(s.to_string());
    let idx = strings.len();
    map.insert(s.to_string(), idx);
    idx
}

fn parse_u128(s: &str) -> u128 {
    s.trim_matches('"').parse().unwrap_or(0)
}

fn parse_f32(s: &str) -> f32 {
    let cleaned = s.trim_matches('"');
    if cleaned == "-" {
        return 0.0;
    }
    cleaned.parse().unwrap_or(0.0)
}

fn ipv4_to_ipv6(ipv4: u32) -> u128 {
    (0xffffu128 << 32) | ipv4 as u128
}

fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '"' => {
                if in_quotes && chars.peek() == Some(&'"') {
                    current.push('"');
                    chars.next();
                } else {
                    in_quotes = !in_quotes;
                }
            }
            ',' if !in_quotes => {
                fields.push(current.clone());
                current.clear();
            }
            _ => current.push(c),
        }
    }
    fields.push(current);
    fields
}
