mod ip2l;
mod mmdb;

use clap::{Parser, Subcommand};
use memmap2::Mmap;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 4] = b"GEO1";
const SCALE: f64 = 1000.0;
const BLOCK: usize = 256;
const MAX_DELTA_V4: u32 = 0xFFFFFF;
const HEADER_LEN: usize = 24;

type Point = (i32, i32);

#[derive(Parser)]
struct Cli { #[command(subcommand)] cmd: Cmd }

#[derive(Subcommand)]
enum Cmd {
    Build {
        #[arg(long, default_value = "IP2LOCATION-LITE-DB11.IPV6.BIN")]
        ip2l: PathBuf,
        #[arg(long, default_value = "GeoLite2-City.mmdb")]
        mmdb: PathBuf,
        #[arg(long, default_value = "geo.bin")]
        out: PathBuf,
    },
    Lookup {
        #[arg(long, default_value = "geo.bin")]
        db: PathBuf,
        ip: String,
    },
}

fn main() -> std::io::Result<()> {
    match Cli::parse().cmd {
        Cmd::Build { ip2l, mmdb, out } => build(&ip2l, &mmdb, &out),
        Cmd::Lookup { db, ip } => lookup_cmd(&db, &ip),
    }
}

fn q(v: f64) -> i32 { (v * SCALE).round() as i32 }
fn deq(v: i32) -> f64 { v as f64 / SCALE }

fn put_u24(buf: &mut Vec<u8>, v: u32) {
    buf.push(v as u8); buf.push((v >> 8) as u8); buf.push((v >> 16) as u8);
}
fn put_i24(buf: &mut Vec<u8>, v: i32) { put_u24(buf, v as u32 & 0xFFFFFF); }
fn get_u24(b: &[u8]) -> u32 {
    b[0] as u32 | ((b[1] as u32) << 8) | ((b[2] as u32) << 16)
}
fn get_i24(b: &[u8]) -> i32 {
    let u = get_u24(b);
    if u & 0x800000 != 0 { (u | 0xFF000000) as i32 } else { u as i32 }
}

struct PackWriter { buf: Vec<u8>, bit_pos: usize, bits: u8 }
impl PackWriter {
    fn new(bits: u8, cap_bits: usize) -> Self {
        Self { buf: vec![0u8; (cap_bits + 64) / 8 + 8], bit_pos: 0, bits }
    }
    fn push(&mut self, val: u32) {
        let byte = self.bit_pos >> 3;
        let shift = self.bit_pos & 7;
        let cur = u64::from_le_bytes(self.buf[byte..byte + 8].try_into().unwrap());
        let merged = cur | ((val as u64) << shift);
        self.buf[byte..byte + 8].copy_from_slice(&merged.to_le_bytes());
        self.bit_pos += self.bits as usize;
    }
    fn finish(mut self) -> Vec<u8> {
        let needed = (self.bit_pos + 7) / 8 + 4;
        self.buf.truncate(needed);
        self.buf
    }
}

#[inline]
fn read_packed(buf: &[u8], i: usize, bits: u8) -> u32 {
    let bit = i * bits as usize;
    let byte = bit >> 3;
    let shift = (bit & 7) as u32;
    let v = u32::from_le_bytes(buf[byte..byte + 4].try_into().unwrap());
    (v >> shift) & ((1u32 << bits) - 1)
}

fn ip2l_v4_latlon(b: &ip2l::Bin, i: u32) -> (f64, f64) {
    let la = b.f32_at(b.col_off(i, false, 5)) as f64;
    let lo = b.f32_at(b.col_off(i, false, 6)) as f64;
    (la, lo)
}
fn ip2l_v6_latlon(b: &ip2l::Bin, i: u32) -> (f64, f64) {
    let la = b.f32_at(b.col_off(i, true, 5)) as f64;
    let lo = b.f32_at(b.col_off(i, true, 6)) as f64;
    (la, lo)
}

fn push<T: PartialEq + Copy>(out: &mut Vec<(T, Option<Point>)>, s: T, p: Option<Point>) {
    if let Some(&(_, prev)) = out.last() {
        if prev == p { return; }
    }
    out.push((s, p));
}

fn merge_v4(ip: &ip2l::Bin, mmdb: &[(u32, u32, f64, f64)])
    -> Vec<(u32, Option<Point>)> {
    let n = ip.v4_n;
    let mut out = Vec::with_capacity(n as usize);
    let mut mi = 0usize;
    for i in 0..n {
        let start = ip.ipv4_at(i);
        let (lat, lon) = ip2l_v4_latlon(ip, i);
        let end = if i + 1 < n { ip.ipv4_at(i + 1) - 1 } else { u32::MAX };
        if lat != 0.0 || lon != 0.0 {
            push(&mut out, start, Some((q(lat), q(lon))));
            continue;
        }
        while mi < mmdb.len() && mmdb[mi].1 < start { mi += 1; }
        let mut cur = start;
        while cur <= end {
            if mi >= mmdb.len() || mmdb[mi].0 > end {
                push(&mut out, cur, None);
                break;
            }
            let m = mmdb[mi];
            if m.0 > cur { push(&mut out, cur, None); cur = m.0; }
            let stop = m.1.min(end);
            push(&mut out, cur, Some((q(m.2), q(m.3))));
            if stop == u32::MAX { break; }
            cur = stop + 1;
            if m.1 <= end { mi += 1; }
        }
    }
    out
}

fn merge_v6(ip: &ip2l::Bin, mmdb: &[(u128, u128, f64, f64)])
    -> Vec<(u128, Option<Point>)> {
    let n = ip.v6_n;
    let mut out = Vec::with_capacity(n as usize);
    let mut mi = 0usize;
    for i in 0..n {
        let start = ip.ipv6_at(i);
        let (lat, lon) = ip2l_v6_latlon(ip, i);
        let end = if i + 1 < n { ip.ipv6_at(i + 1) - 1 } else { u128::MAX };
        if lat != 0.0 || lon != 0.0 {
            push(&mut out, start, Some((q(lat), q(lon))));
            continue;
        }
        while mi < mmdb.len() && mmdb[mi].1 < start { mi += 1; }
        let mut cur = start;
        while cur <= end {
            if mi >= mmdb.len() || mmdb[mi].0 > end {
                push(&mut out, cur, None);
                break;
            }
            let m = mmdb[mi];
            if m.0 > cur { push(&mut out, cur, None); cur = m.0; }
            let stop = m.1.min(end);
            push(&mut out, cur, Some((q(m.2), q(m.3))));
            if stop == u128::MAX { break; }
            cur = stop + 1;
            if m.1 <= end { mi += 1; }
        }
    }
    out
}

fn intern(map: &mut HashMap<Point, u32>, pts: &mut Vec<Point>, p: Option<Point>) -> u32 {
    let Some(pp) = p else { return 0; };
    *map.entry(pp).or_insert_with(|| {
        pts.push(pp);
        (pts.len() - 1) as u32
    })
}

struct Prep {
    points: Vec<Point>,
    v4_starts: Vec<u32>,
    v4_idx: Vec<u32>,
    v6_starts: Vec<u128>,
    v6_idx: Vec<u32>,
}

fn prepare(ip2l_p: &Path, mmdb_p: &Path) -> std::io::Result<Prep> {
    eprintln!("open ip2l + mmdb…");
    let ip = ip2l::Bin::open(ip2l_p)?;
    let md = mmdb::Mmdb::open(mmdb_p)?;
    eprintln!("walk mmdb…");
    let m4 = md.walk_v4_geo();
    let m6 = md.walk_v6_geo();
    eprintln!("merge v4 ({} ip2l, {} mmdb)…", ip.v4_n, m4.len());
    let r4 = merge_v4(&ip, &m4);
    eprintln!("merge v6 ({} ip2l, {} mmdb)…", ip.v6_n, m6.len());
    let r6 = merge_v6(&ip, &m6);
    eprintln!("intern points…");
    let mut points: Vec<Point> = vec![(0, 0)];
    let mut map: HashMap<Point, u32> = HashMap::new();
    let mut v4_starts = Vec::with_capacity(r4.len());
    let mut v4_idx = Vec::with_capacity(r4.len());
    for (s, p) in &r4 {
        v4_starts.push(*s);
        v4_idx.push(intern(&mut map, &mut points, *p));
    }
    let mut v6_starts = Vec::with_capacity(r6.len());
    let mut v6_idx = Vec::with_capacity(r6.len());
    for (s, p) in &r6 {
        v6_starts.push(*s);
        v6_idx.push(intern(&mut map, &mut points, *p));
    }
    eprintln!(
        "prep: {} pts, {} v4 rows, {} v6 rows",
        points.len(), v4_starts.len(), v6_starts.len()
    );
    Ok(Prep { points, v4_starts, v4_idx, v6_starts, v6_idx })
}

fn dedup_v6_u64(starts: &[u128], idx: &[u32]) -> (Vec<u64>, Vec<u32>) {
    let mut out_s = Vec::with_capacity(starts.len());
    let mut out_i = Vec::with_capacity(starts.len());
    for (k, &s) in starts.iter().enumerate() {
        let key = (s >> 64) as u64;
        if let Some(&prev) = out_s.last() {
            if prev == key { continue; }
        }
        out_s.push(key);
        out_i.push(idx[k]);
    }
    (out_s, out_i)
}

fn build_blocks_v4(starts: &[u32]) -> (Vec<u32>, Vec<u32>, Vec<u8>) {
    let mut bases = Vec::new();
    let mut offsets = vec![0u32];
    let mut deltas = Vec::with_capacity(starts.len() * 3);
    let mut i = 0;
    while i < starts.len() {
        let base = starts[i];
        bases.push(base);
        let cap = (i + BLOCK).min(starts.len());
        let mut j = i + 1;
        while j < cap && starts[j] - base <= MAX_DELTA_V4 { j += 1; }
        for k in i..j { put_u24(&mut deltas, starts[k] - base); }
        offsets.push(deltas.len() as u32);
        i = j;
    }
    (bases, offsets, deltas)
}

fn idx_bits_for(n_points: usize) -> u8 {
    let mut b = 1u8;
    while (1u64 << b) < n_points as u64 { b += 1; }
    b
}

fn build(ip2l_p: &Path, mmdb_p: &Path, out_p: &Path) -> std::io::Result<()> {
    let p = prepare(ip2l_p, mmdb_p)?;
    let idx_bits = idx_bits_for(p.points.len());
    assert!(idx_bits <= 24);
    let (bases4, off4, deltas4) = build_blocks_v4(&p.v4_starts);
    let (k6, i6) = dedup_v6_u64(&p.v6_starts, &p.v6_idx);

    let mut pw4 = PackWriter::new(idx_bits, p.v4_idx.len() * idx_bits as usize);
    for &x in &p.v4_idx { pw4.push(x); }
    let v4_idx_buf = pw4.finish();

    let mut pw6 = PackWriter::new(idx_bits, i6.len() * idx_bits as usize);
    for &x in &i6 { pw6.push(x); }
    let v6_idx_buf = pw6.finish();

    let mut f = File::create(out_p)?;
    let mut h = Vec::with_capacity(HEADER_LEN);
    h.extend_from_slice(MAGIC);
    h.push(1);
    h.push(3);
    h.push(idx_bits);
    h.push(0);
    h.extend_from_slice(&(p.points.len() as u32).to_le_bytes());
    h.extend_from_slice(&(p.v4_idx.len() as u32).to_le_bytes());
    h.extend_from_slice(&(k6.len() as u32).to_le_bytes());
    h.extend_from_slice(&(bases4.len() as u32).to_le_bytes());
    f.write_all(&h)?;

    let mut buf = Vec::with_capacity(p.points.len() * 6);
    for &(la, lo) in &p.points { put_i24(&mut buf, la); put_i24(&mut buf, lo); }
    f.write_all(&buf)?;

    buf.clear();
    for &b in &bases4 { buf.extend_from_slice(&b.to_le_bytes()); }
    f.write_all(&buf)?;
    buf.clear();
    for &o in &off4 { buf.extend_from_slice(&o.to_le_bytes()); }
    f.write_all(&buf)?;
    f.write_all(&deltas4)?;
    f.write_all(&v4_idx_buf)?;

    buf.clear();
    buf.reserve(k6.len() * 8);
    for &k in &k6 { buf.extend_from_slice(&k.to_le_bytes()); }
    f.write_all(&buf)?;
    f.write_all(&v6_idx_buf)?;

    eprintln!(
        "wrote {} bytes (idx_bits={}, pts={}, v4={}, v6={}, blocks4={})",
        std::fs::metadata(out_p)?.len(), idx_bits,
        p.points.len(), p.v4_idx.len(), k6.len(), bases4.len()
    );
    Ok(())
}

struct Geo<'a> {
    idx_bits: u8,
    pts: &'a [u8],
    bases4: &'a [u8], off4: &'a [u8], deltas4: &'a [u8], v4_idx: &'a [u8], nb4: u32,
    v6_k: &'a [u8], v6_idx: &'a [u8], n6: u32,
}

fn off_at(off: &[u8], i: usize) -> usize {
    u32::from_le_bytes(off[i * 4..i * 4 + 4].try_into().unwrap()) as usize
}

impl<'a> Geo<'a> {
    fn from(mm: &'a [u8]) -> Self {
        assert_eq!(&mm[0..4], MAGIC);
        let idx_bits = mm[6];
        let n_pts = u32::from_le_bytes(mm[8..12].try_into().unwrap()) as usize;
        let n4 = u32::from_le_bytes(mm[12..16].try_into().unwrap()) as usize;
        let n6 = u32::from_le_bytes(mm[16..20].try_into().unwrap());
        let nb4 = u32::from_le_bytes(mm[20..24].try_into().unwrap());
        let mut o = HEADER_LEN;
        let pts = &mm[o..o + n_pts * 6]; o += pts.len();
        let bases4 = &mm[o..o + nb4 as usize * 4]; o += bases4.len();
        let off4 = &mm[o..o + (nb4 as usize + 1) * 4]; o += off4.len();
        let deltas4_len = off_at(off4, nb4 as usize);
        let deltas4 = &mm[o..o + deltas4_len]; o += deltas4.len();
        let v4_idx_len = (n4 * idx_bits as usize + 7) / 8 + 4;
        let v4_idx = &mm[o..o + v4_idx_len]; o += v4_idx.len();
        let v6_k = &mm[o..o + n6 as usize * 8]; o += v6_k.len();
        let v6_idx_len = (n6 as usize * idx_bits as usize + 7) / 8 + 4;
        let v6_idx = &mm[o..o + v6_idx_len];
        Self { idx_bits, pts, bases4, off4, deltas4, v4_idx, nb4, v6_k, v6_idx, n6 }
    }

    fn point_at(&self, idx: u32) -> Option<(f64, f64)> {
        if idx == 0 { return None; }
        let o = idx as usize * 6;
        Some((deq(get_i24(&self.pts[o..o + 3])), deq(get_i24(&self.pts[o + 3..o + 6]))))
    }

    fn lookup_v4(&self, ip: u32) -> Option<(f64, f64)> {
        let (mut lo, mut hi) = (0u32, self.nb4);
        while lo < hi {
            let mid = (lo + hi) / 2;
            let v = u32::from_le_bytes(
                self.bases4[mid as usize * 4..mid as usize * 4 + 4].try_into().unwrap());
            if v <= ip { lo = mid + 1; } else { hi = mid; }
        }
        if lo == 0 { return None; }
        let bi = (lo - 1) as usize;
        let base = u32::from_le_bytes(
            self.bases4[bi * 4..bi * 4 + 4].try_into().unwrap());
        let bo = off_at(self.off4, bi);
        let be = off_at(self.off4, bi + 1);
        let cnt = (be - bo) / 3;
        let row_start = bo / 3;
        let target = ip - base;
        let deltas = &self.deltas4[bo..be];
        let (mut bl, mut bh) = (0u32, cnt as u32);
        while bl < bh {
            let mid = (bl + bh) / 2;
            let d = get_u24(&deltas[mid as usize * 3..mid as usize * 3 + 3]);
            if d <= target { bl = mid + 1; } else { bh = mid; }
        }
        if bl == 0 { return None; }
        let row = row_start + (bl - 1) as usize;
        self.point_at(read_packed(self.v4_idx, row, self.idx_bits))
    }

    fn lookup_v6(&self, ip: u128) -> Option<(f64, f64)> {
        let key = (ip >> 64) as u64;
        let (mut lo, mut hi) = (0u32, self.n6);
        while lo < hi {
            let mid = (lo + hi) / 2;
            let v = u64::from_le_bytes(
                self.v6_k[mid as usize * 8..mid as usize * 8 + 8].try_into().unwrap());
            if v <= key { lo = mid + 1; } else { hi = mid; }
        }
        if lo == 0 { return None; }
        let i = (lo - 1) as usize;
        self.point_at(read_packed(self.v6_idx, i, self.idx_bits))
    }

    fn lookup(&self, ip: IpAddr) -> Option<(f64, f64)> {
        match ip {
            IpAddr::V4(v) => self.lookup_v4(u32::from(v)),
            IpAddr::V6(v) => self.lookup_v6(u128::from(v)),
        }
    }
}

fn lookup_cmd(db_p: &Path, ip_s: &str) -> std::io::Result<()> {
    let f = File::open(db_p)?;
    let mm = unsafe { Mmap::map(&f)? };
    let g = Geo::from(&mm);
    let ip: IpAddr = ip_s.parse().expect("invalid ip");
    match g.lookup(ip) {
        Some((la, lo)) => println!("{:.3}, {:.3}", la, lo),
        None => println!("not found"),
    }
    Ok(())
}
