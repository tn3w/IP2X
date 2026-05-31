use memmap2::Mmap;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

const MAGIC: &[u8; 4] = b"GFD3";
const HEADER: usize = 28;
pub const FIELDS: &[&str] = &["country", "region", "city", "postal", "feed", "rir"];
const K: usize = FIELDS.len();

#[derive(Clone, Copy)]
pub enum Range {
    V4(u32, u32),
    V6(u128, u128),
}

pub fn parse_cidr(s: &str) -> Option<Range> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if s.contains(':') {
        let (start, end) = v6_cidr(s)?;
        return Some(Range::V6(start, end));
    }
    let (start, end) = v4_cidr(s)?;
    Some(Range::V4(start, end))
}

pub fn parse_inetnum(s: &str) -> Option<Range> {
    if let Some((a, b)) = s.split_once('-') {
        let start = a.trim().parse::<Ipv4Addr>().ok()?;
        let end = b.trim().parse::<Ipv4Addr>().ok()?;
        return Some(Range::V4(start.into(), end.into()));
    }
    parse_cidr(s)
}

pub fn parse_inet6num(s: &str) -> Option<Range> {
    if let Some((a, b)) = s.split_once('-') {
        let start = a.trim().parse::<Ipv6Addr>().ok()?;
        let end = b.trim().parse::<Ipv6Addr>().ok()?;
        return Some(Range::V6(start.into(), end.into()));
    }
    parse_cidr(s)
}

pub fn contains(authority: &Range, inner: &Range) -> bool {
    match (authority, inner) {
        (Range::V4(a, b), Range::V4(s, e)) => a <= s && e <= b,
        (Range::V6(a, b), Range::V6(s, e)) => a <= s && e <= b,
        _ => false,
    }
}

fn v4_cidr(s: &str) -> Option<(u32, u32)> {
    let (addr, len) = match s.split_once('/') {
        Some((a, l)) => (a, l.trim().parse::<u32>().ok()?),
        None => (s, 32),
    };
    if len > 32 {
        return None;
    }
    let base = u32::from(addr.trim().parse::<Ipv4Addr>().ok()?);
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    Some((base & mask, (base & mask) | !mask))
}

fn v6_cidr(s: &str) -> Option<(u128, u128)> {
    let (addr, len) = match s.split_once('/') {
        Some((a, l)) => (a, l.trim().parse::<u32>().ok()?),
        None => (s, 128),
    };
    if len > 128 {
        return None;
    }
    let base = u128::from(addr.trim().parse::<Ipv6Addr>().ok()?);
    let mask = if len == 0 { 0 } else { u128::MAX << (128 - len) };
    Some((base & mask, (base & mask) | !mask))
}

pub fn build(data: &Path, out: &Path) -> std::io::Result<()> {
    let text = std::fs::read_to_string(data)?;
    let (mut strings, mut str_id) = (Vec::<String>::new(), HashMap::<String, u32>::new());
    let mut intern = |s: &str| -> u32 {
        if let Some(&i) = str_id.get(s) {
            return i;
        }
        let i = strings.len() as u32;
        strings.push(s.to_string());
        str_id.insert(s.to_string(), i);
        i
    };

    let mut v4: Vec<(u32, u32, [u32; K])> = Vec::new();
    let mut v6: Vec<(u128, u128, [u32; K])> = Vec::new();
    let mut freq: HashMap<[u32; K], u32> = HashMap::new();
    for line in text.lines().skip(1) {
        let row = parse_csv(line);
        let Some(range) = parse_cidr(row.first().map(|s| s.as_str()).unwrap_or("")) else {
            continue;
        };
        let mut rec = [0u32; K];
        for (i, field) in rec.iter_mut().enumerate() {
            let value = row.get(i + 1).map(|s| s.trim()).unwrap_or("");
            *field = intern(&normalize(FIELDS[i], value));
        }
        *freq.entry(rec).or_insert(0) += 1;
        match range {
            Range::V4(s, e) => v4.push((s, e, rec)),
            Range::V6(s, e) => v6.push((s, e, rec)),
        }
    }

    let mut order: Vec<([u32; K], u32)> = freq.into_iter().collect();
    order.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let mut rec_id: HashMap<[u32; K], u32> = HashMap::new();
    let mut records: Vec<[u32; K]> = Vec::with_capacity(order.len());
    for (rec, _) in order {
        rec_id.insert(rec, records.len() as u32 + 1);
        records.push(rec);
    }

    let v4_ranges = v4.iter().map(|(s, e, r)| (*s, *e, rec_id[r])).collect();
    let v6_ranges = v6.iter().map(|(s, e, r)| (*s, *e, rec_id[r])).collect();
    let (v4_starts, v4_ids) = segments(v4_ranges, |e| e.checked_add(1));
    let (v6_starts, v6_ids) = segments(v6_ranges, |e| e.checked_add(1));
    write_db(out, &v4_starts, &v4_ids, &v6_starts, &v6_ids, &records, &strings)
}

fn normalize(field: &str, value: &str) -> String {
    match field {
        "country" | "rir" => value.to_uppercase(),
        _ => value.to_string(),
    }
}

fn segments<T: Copy + Ord>(
    mut ranges: Vec<(T, T, u32)>, inc: impl Fn(T) -> Option<T>,
) -> (Vec<T>, Vec<u32>) {
    ranges.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
    let mut points: Vec<(T, u32)> = Vec::new();
    let mut stack: Vec<(T, u32)> = Vec::new();
    for (start, end, id) in ranges {
        while let Some(&(top_end, _)) = stack.last() {
            if top_end >= start {
                break;
            }
            stack.pop();
            close(&mut points, top_end, stack.last().map(|x| x.1).unwrap_or(0), &inc);
        }
        points.push((start, id));
        stack.push((end, id));
    }
    while let Some((top_end, _)) = stack.pop() {
        close(&mut points, top_end, stack.last().map(|x| x.1).unwrap_or(0), &inc);
    }

    points.sort_by(|a, b| a.0.cmp(&b.0));
    let (mut starts, mut ids) = (Vec::new(), Vec::new());
    for (pos, id) in points {
        if starts.last() == Some(&pos) {
            *ids.last_mut().unwrap() = id;
            continue;
        }
        if ids.last() == Some(&id) {
            continue;
        }
        starts.push(pos);
        ids.push(id);
    }
    (starts, ids)
}

fn close<T>(points: &mut Vec<(T, u32)>, end: T, id: u32, inc: &impl Fn(T) -> Option<T>) {
    if let Some(next) = inc(end) {
        points.push((next, id));
    }
}

fn id_bytes(record_count: usize) -> u8 {
    match record_count {
        0..=0xFF => 1,
        0x100..=0xFFFF => 2,
        0x1_0000..=0xFF_FFFF => 3,
        _ => 4,
    }
}

fn write_db(
    out: &Path, v4_starts: &[u32], v4_ids: &[u32], v6_starts: &[u128], v6_ids: &[u32],
    records: &[[u32; K]], strings: &[String],
) -> std::io::Result<()> {
    let width = id_bytes(records.len());
    let mut blob: Vec<u8> = Vec::new();
    let mut offsets: Vec<u32> = Vec::with_capacity(strings.len() + 1);
    offsets.push(0);
    for s in strings {
        blob.extend_from_slice(s.as_bytes());
        offsets.push(blob.len() as u32);
    }

    let mut head: Vec<u8> = Vec::with_capacity(HEADER);
    head.extend_from_slice(MAGIC);
    head.push(3);
    head.push(width);
    head.push(K as u8);
    head.push(0);
    head.extend_from_slice(&(v4_starts.len() as u32).to_le_bytes());
    head.extend_from_slice(&(v6_starts.len() as u32).to_le_bytes());
    head.extend_from_slice(&(records.len() as u32).to_le_bytes());
    head.extend_from_slice(&(strings.len() as u32).to_le_bytes());
    head.extend_from_slice(&(blob.len() as u32).to_le_bytes());

    let mut w = BufWriter::new(File::create(out)?);
    w.write_all(&head)?;
    for s in v4_starts {
        w.write_all(&s.to_le_bytes())?;
    }
    for id in v4_ids {
        w.write_all(&id.to_le_bytes()[..width as usize])?;
    }
    for s in v6_starts {
        w.write_all(&s.to_le_bytes())?;
    }
    for id in v6_ids {
        w.write_all(&id.to_le_bytes()[..width as usize])?;
    }
    for rec in records {
        for field in rec {
            w.write_all(&field.to_le_bytes())?;
        }
    }
    for o in &offsets {
        w.write_all(&o.to_le_bytes())?;
    }
    w.write_all(&blob)?;
    w.flush()?;
    println!(
        "v4 breaks {} | v6 breaks {} | records {} | strings {} | id_bytes {}",
        v4_starts.len(), v6_starts.len(), records.len(), strings.len(), width
    );
    Ok(())
}

fn parse_csv(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => fields.push(std::mem::take(&mut field)),
            _ => field.push(c),
        }
    }
    fields.push(field);
    fields
}

pub struct Hit {
    pub fields: Vec<(&'static str, String)>,
}

pub struct Db {
    map: Mmap,
    width: usize,
    fields: usize,
    v4_breaks: usize,
    v6_breaks: usize,
    v4_starts: usize,
    v4_ids: usize,
    v6_starts: usize,
    v6_ids: usize,
    records: usize,
    offsets: usize,
    blob: usize,
}

impl Db {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let map = unsafe { Mmap::map(&File::open(path)?)? };
        assert_eq!(&map[0..4], MAGIC, "bad magic");
        let width = map[5] as usize;
        let fields = map[6] as usize;
        let v4_breaks = u32(&map, 8) as usize;
        let v6_breaks = u32(&map, 12) as usize;
        let record_count = u32(&map, 16) as usize;
        let str_count = u32(&map, 20) as usize;
        let v4_starts = HEADER;
        let v4_ids = v4_starts + v4_breaks * 4;
        let v6_starts = v4_ids + v4_breaks * width;
        let v6_ids = v6_starts + v6_breaks * 16;
        let records = v6_ids + v6_breaks * width;
        let offsets = records + record_count * fields * 4;
        let blob = offsets + (str_count + 1) * 4;
        Ok(Self {
            map, width, fields, v4_breaks, v6_breaks,
            v4_starts, v4_ids, v6_starts, v6_ids, records, offsets, blob,
        })
    }

    pub fn lookup_v4(&self, ip: Ipv4Addr) -> Option<Hit> {
        let ip = u32::from(ip);
        let pos = upper(self.v4_breaks, |i| u32(&self.map, self.v4_starts + i * 4), ip);
        self.hit(self.v4_ids, pos)
    }

    pub fn lookup_v6(&self, ip: Ipv6Addr) -> Option<Hit> {
        let ip = u128::from(ip);
        let pos = upper(self.v6_breaks, |i| u128(&self.map, self.v6_starts + i * 16), ip);
        self.hit(self.v6_ids, pos)
    }

    fn hit(&self, ids_off: usize, pos: usize) -> Option<Hit> {
        if pos == 0 {
            return None;
        }
        let id = self.id_at(ids_off, pos - 1);
        if id == 0 {
            return None;
        }
        let base = self.records + (id as usize - 1) * self.fields * 4;
        let fields = FIELDS.iter().enumerate()
            .map(|(i, &name)| (name, self.string(u32(&self.map, base + i * 4))))
            .collect();
        Some(Hit { fields })
    }

    fn id_at(&self, ids_off: usize, i: usize) -> u32 {
        let off = ids_off + i * self.width;
        let mut bytes = [0u8; 4];
        bytes[..self.width].copy_from_slice(&self.map[off..off + self.width]);
        u32::from_le_bytes(bytes)
    }

    fn string(&self, i: u32) -> String {
        let i = i as usize;
        let start = u32(&self.map, self.offsets + i * 4) as usize;
        let end = u32(&self.map, self.offsets + (i + 1) * 4) as usize;
        String::from_utf8_lossy(&self.map[self.blob + start..self.blob + end]).into_owned()
    }
}

fn upper<T: Ord, F: Fn(usize) -> T>(len: usize, at: F, key: T) -> usize {
    let (mut lo, mut hi) = (0, len);
    while lo < hi {
        let mid = (lo + hi) / 2;
        if at(mid) <= key {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

fn u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

fn u128(buf: &[u8], off: usize) -> u128 {
    u128::from_le_bytes(buf[off..off + 16].try_into().unwrap())
}
