use crate::ip2l::Bin;
use memmap2::Mmap;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;

pub const MAGIC: &[u8; 4] = b"PRX2";
const VERSION: u8 = 2;
const HEADER_LEN: usize = 36;
const BLOCK_SHIFT: u8 = 8;
const BLOCK: usize = 1 << BLOCK_SHIFT;
const ISP_COL: u8 = 6;
const DOM_COL: u8 = 7;
const TAIL_PAD: usize = 8;

fn put_u24(b: &mut Vec<u8>, v: u32) {
    b.push(v as u8);
    b.push((v >> 8) as u8);
    b.push((v >> 16) as u8);
}
fn get_u24(b: &[u8]) -> u32 {
    b[0] as u32 | ((b[1] as u32) << 8) | ((b[2] as u32) << 16)
}

fn bits_needed(max_val: u32) -> u8 {
    if max_val == 0 { 1 } else { 32 - max_val.leading_zeros() as u8 }
}

fn pack_into(buf: &mut Vec<u8>, vals: &[u32], bits: u8) {
    let start_bit = buf.len() * 8;
    let total_bits = vals.len() * bits as usize;
    let need = (start_bit + total_bits + 64) / 8 + 8;
    if buf.len() < need {
        buf.resize(need, 0);
    }
    let mut bit_pos = start_bit;
    for &v in vals {
        let byte = bit_pos >> 3;
        let shift = bit_pos & 7;
        let cur = u64::from_le_bytes(buf[byte..byte + 8].try_into().unwrap());
        let merged = cur | ((v as u64) << shift);
        buf[byte..byte + 8].copy_from_slice(&merged.to_le_bytes());
        bit_pos += bits as usize;
    }
    buf.truncate((bit_pos + 7) / 8);
}

#[inline]
fn read_packed(buf: &[u8], i: usize, bits: u8) -> u32 {
    let bit = i * bits as usize;
    let byte = bit >> 3;
    let shift = (bit & 7) as u32;
    let v = u32::from_le_bytes(buf[byte..byte + 4].try_into().unwrap());
    (v >> shift) & ((1u32 << bits) - 1)
}

fn intern_str(map: &mut HashMap<String, u32>, list: &mut Vec<String>, s: &str) -> u32 {
    if s.is_empty() { return 0; }
    if let Some(&i) = map.get(s) { return i; }
    list.push(s.to_string());
    let i = (list.len() - 1) as u32;
    map.insert(s.to_string(), i);
    i
}

fn intern_pair(
    pair_map: &mut HashMap<(u32, u32), u32>,
    pairs: &mut Vec<(u32, u32)>,
    isp: u32,
    dom: u32,
) -> u32 {
    *pair_map.entry((isp, dom)).or_insert_with(|| {
        pairs.push((isp, dom));
        (pairs.len() - 1) as u32
    })
}

struct Prep {
    strs: Vec<String>,
    pairs: Vec<(u32, u32)>,
    v4_starts: Vec<u32>,
    v4_idx: Vec<u32>,
    v6_starts: Vec<u128>,
    v6_idx: Vec<u32>,
}

fn collect(b: &Bin) -> Prep {
    let mut strs = vec![String::new()];
    let mut str_map = HashMap::new();
    str_map.insert(String::new(), 0u32);
    let mut pairs = vec![(0u32, 0u32)];
    let mut pair_map = HashMap::new();
    pair_map.insert((0u32, 0u32), 0u32);

    eprintln!("collect v4 ({} rows)…", b.v4_n);
    let mut v4_starts = Vec::new();
    let mut v4_raw = Vec::with_capacity(b.v4_n as usize);
    for i in 0..b.v4_n {
        let isp = intern_str(&mut str_map, &mut strs, b.str_at(i, false, ISP_COL));
        let dom = intern_str(&mut str_map, &mut strs, b.str_at(i, false, DOM_COL));
        let p = intern_pair(&mut pair_map, &mut pairs, isp, dom);
        v4_raw.push((b.ipv4_at(i), p));
    }
    eprintln!("collect v6 ({} rows)…", b.v6_n);
    let mut v6_raw = Vec::with_capacity(b.v6_n as usize);
    for i in 0..b.v6_n {
        let isp = intern_str(&mut str_map, &mut strs, b.str_at(i, true, ISP_COL));
        let dom = intern_str(&mut str_map, &mut strs, b.str_at(i, true, DOM_COL));
        let p = intern_pair(&mut pair_map, &mut pairs, isp, dom);
        v6_raw.push((b.ipv6_at(i), p));
    }

    let mut counts = vec![0u32; pairs.len()];
    for &(_, p) in &v4_raw { counts[p as usize] += 1; }
    for &(_, p) in &v6_raw { counts[p as usize] += 1; }
    let mut order: Vec<u32> = (1..pairs.len() as u32).collect();
    order.sort_by(|&a, &b| counts[b as usize].cmp(&counts[a as usize]));
    let mut remap = vec![0u32; pairs.len()];
    let mut new_pairs = vec![(0u32, 0u32)];
    for (new_i, &old_i) in order.iter().enumerate() {
        remap[old_i as usize] = (new_i + 1) as u32;
        new_pairs.push(pairs[old_i as usize]);
    }

    let mut v4_idx = Vec::with_capacity(v4_raw.len());
    let mut prev = u32::MAX;
    for (s, p) in &v4_raw {
        let np = remap[*p as usize];
        if np == prev { continue; }
        v4_starts.push(*s);
        v4_idx.push(np);
        prev = np;
    }
    let mut v6_starts = Vec::new();
    let mut v6_idx = Vec::new();
    let mut prev = u32::MAX;
    for (s, p) in &v6_raw {
        let np = remap[*p as usize];
        if np == prev { continue; }
        v6_starts.push(*s);
        v6_idx.push(np);
        prev = np;
    }
    eprintln!(
        "prep: {} strs, {} pairs, {} v4 rows, {} v6 rows",
        strs.len(), new_pairs.len(), v4_starts.len(), v6_starts.len()
    );
    Prep { strs, pairs: new_pairs, v4_starts, v4_idx, v6_starts, v6_idx }
}

struct V4Blocks {
    bases: Vec<u32>,
    dbits: Vec<u8>,
    ibits: Vec<u8>,
    d_off: Vec<u32>,
    i_off: Vec<u32>,
    d_blob: Vec<u8>,
    i_blob: Vec<u8>,
}

fn build_v4(starts: &[u32], idx: &[u32]) -> V4Blocks {
    let n = starts.len();
    let nb = (n + BLOCK - 1) / BLOCK;
    let mut bases = Vec::with_capacity(nb);
    let mut dbits = Vec::with_capacity(nb);
    let mut ibits = Vec::with_capacity(nb);
    let mut d_off = Vec::with_capacity(nb + 1);
    let mut i_off = Vec::with_capacity(nb + 1);
    let mut d_blob = Vec::new();
    let mut i_blob = Vec::new();
    for k in 0..nb {
        let lo = k * BLOCK;
        let hi = (lo + BLOCK).min(n);
        let base = starts[lo];
        let max_d = starts[lo..hi].iter().map(|s| s - base).max().unwrap();
        let max_i = idx[lo..hi].iter().copied().max().unwrap();
        let db = bits_needed(max_d);
        let ib = bits_needed(max_i);
        bases.push(base);
        dbits.push(db);
        ibits.push(ib);
        d_off.push(d_blob.len() as u32);
        i_off.push(i_blob.len() as u32);
        let deltas: Vec<u32> = starts[lo..hi].iter().map(|s| s - base).collect();
        pack_into(&mut d_blob, &deltas, db);
        pack_into(&mut i_blob, &idx[lo..hi], ib);
    }
    d_off.push(d_blob.len() as u32);
    i_off.push(i_blob.len() as u32);
    d_blob.resize(d_blob.len() + TAIL_PAD, 0);
    i_blob.resize(i_blob.len() + TAIL_PAD, 0);
    V4Blocks { bases, dbits, ibits, d_off, i_off, d_blob, i_blob }
}

fn dedup_v6(starts: &[u128], idx: &[u32]) -> (Vec<u64>, Vec<u32>) {
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

pub fn build(px12: &Path, out_p: &Path) -> std::io::Result<()> {
    let b = Bin::open(px12)?;
    let p = collect(&b);
    let n4 = p.v4_idx.len();
    let vb = build_v4(&p.v4_starts, &p.v4_idx);
    let (k6, i6) = dedup_v6(&p.v6_starts, &p.v6_idx);
    let v6_bits = bits_needed(*i6.iter().max().unwrap_or(&0));
    let mut v6_blob = Vec::new();
    pack_into(&mut v6_blob, &i6, v6_bits);
    v6_blob.resize(v6_blob.len() + TAIL_PAD, 0);

    let mut f = File::create(out_p)?;
    let mut h = Vec::with_capacity(HEADER_LEN);
    h.extend_from_slice(MAGIC);
    h.push(VERSION);
    h.push(BLOCK_SHIFT);
    h.push(v6_bits);
    h.extend_from_slice(&[0u8; 1]);
    h.extend_from_slice(&(p.pairs.len() as u32).to_le_bytes());
    h.extend_from_slice(&(p.strs.len() as u32).to_le_bytes());
    h.extend_from_slice(&(n4 as u32).to_le_bytes());
    h.extend_from_slice(&(k6.len() as u32).to_le_bytes());
    h.extend_from_slice(&(vb.bases.len() as u32).to_le_bytes());
    h.extend_from_slice(&(vb.d_blob.len() as u32 - TAIL_PAD as u32).to_le_bytes());
    h.extend_from_slice(&(vb.i_blob.len() as u32 - TAIL_PAD as u32).to_le_bytes());
    assert_eq!(h.len(), HEADER_LEN);
    f.write_all(&h)?;

    let mut buf = Vec::new();
    for &(a, b) in &p.pairs { put_u24(&mut buf, a); put_u24(&mut buf, b); }
    f.write_all(&buf)?;

    let mut blob = Vec::new();
    let mut offs = Vec::with_capacity(p.strs.len() + 1);
    for s in &p.strs { offs.push(blob.len() as u32); blob.extend_from_slice(s.as_bytes()); }
    offs.push(blob.len() as u32);
    buf.clear();
    for o in &offs { buf.extend_from_slice(&o.to_le_bytes()); }
    f.write_all(&buf)?;
    f.write_all(&blob)?;

    buf.clear();
    for &x in &vb.bases { buf.extend_from_slice(&x.to_le_bytes()); }
    f.write_all(&buf)?;
    f.write_all(&vb.dbits)?;
    f.write_all(&vb.ibits)?;
    buf.clear();
    for &x in &vb.d_off { buf.extend_from_slice(&x.to_le_bytes()); }
    f.write_all(&buf)?;
    buf.clear();
    for &x in &vb.i_off { buf.extend_from_slice(&x.to_le_bytes()); }
    f.write_all(&buf)?;
    f.write_all(&vb.d_blob)?;
    f.write_all(&vb.i_blob)?;

    buf.clear();
    for &x in &k6 { buf.extend_from_slice(&x.to_le_bytes()); }
    f.write_all(&buf)?;
    f.write_all(&v6_blob)?;

    let sz = std::fs::metadata(out_p)?.len();
    let avg_db: f64 = vb.dbits.iter().map(|&x| x as f64).sum::<f64>() / vb.dbits.len() as f64;
    let avg_ib: f64 = vb.ibits.iter().map(|&x| x as f64).sum::<f64>() / vb.ibits.len() as f64;
    eprintln!(
        "wrote {} bytes (pairs={}, strs={}, v4={} blocks4={} avg_dbits={:.1} avg_ibits={:.1} v6={} v6_bits={})",
        sz, p.pairs.len(), p.strs.len(), n4, vb.bases.len(), avg_db, avg_ib, k6.len(), v6_bits,
    );
    Ok(())
}

pub struct Db {
    pub mm: Mmap,
    n_pairs: u32,
    pairs_off: usize,
    str_off_off: usize,
    str_blob_off: usize,
    n4: u32,
    nb4: u32,
    bases4: &'static [u8],
    dbits4: &'static [u8],
    ibits4: &'static [u8],
    d_off: &'static [u8],
    i_off: &'static [u8],
    d_blob: &'static [u8],
    i_blob: &'static [u8],
    n6: u32,
    v6_bits: u8,
    v6_k: &'static [u8],
    v6_idx: &'static [u8],
}

fn rd_u32(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap())
}

impl Db {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let f = File::open(path)?;
        let mm = unsafe { Mmap::map(&f)? };
        assert_eq!(&mm[0..4], MAGIC);
        assert_eq!(mm[4], VERSION);
        assert_eq!(mm[5], BLOCK_SHIFT);
        let v6_bits = mm[6];
        let n_pairs = u32::from_le_bytes(mm[8..12].try_into().unwrap());
        let n_strs = u32::from_le_bytes(mm[12..16].try_into().unwrap()) as usize;
        let n4 = u32::from_le_bytes(mm[16..20].try_into().unwrap());
        let n6 = u32::from_le_bytes(mm[20..24].try_into().unwrap());
        let nb4 = u32::from_le_bytes(mm[24..28].try_into().unwrap());
        let d_blob_len = u32::from_le_bytes(mm[28..32].try_into().unwrap()) as usize;
        let i_blob_len = u32::from_le_bytes(mm[32..36].try_into().unwrap()) as usize;

        let slice = |a: usize, n: usize| -> &'static [u8] {
            unsafe { std::slice::from_raw_parts(mm.as_ptr().add(a), n) }
        };

        let mut o = HEADER_LEN;
        let pairs_off = o; o += n_pairs as usize * 6;
        let str_off_off = o; o += (n_strs + 1) * 4;
        let blob_len = rd_u32(&mm[str_off_off..], n_strs) as usize;
        let str_blob_off = o; o += blob_len;
        let bases4 = slice(o, nb4 as usize * 4); o += bases4.len();
        let dbits4 = slice(o, nb4 as usize); o += dbits4.len();
        let ibits4 = slice(o, nb4 as usize); o += ibits4.len();
        let d_off = slice(o, (nb4 as usize + 1) * 4); o += d_off.len();
        let i_off = slice(o, (nb4 as usize + 1) * 4); o += i_off.len();
        let d_blob = slice(o, d_blob_len + TAIL_PAD); o += d_blob_len + TAIL_PAD;
        let i_blob = slice(o, i_blob_len + TAIL_PAD); o += i_blob_len + TAIL_PAD;
        let v6_k = slice(o, n6 as usize * 8); o += v6_k.len();
        let v6_idx_len = (n6 as usize * v6_bits as usize + 7) / 8 + TAIL_PAD;
        let v6_idx = slice(o, v6_idx_len);

        Ok(Self {
            mm, n_pairs, pairs_off, str_off_off, str_blob_off,
            n4, nb4, bases4, dbits4, ibits4, d_off, i_off, d_blob, i_blob,
            n6, v6_bits, v6_k, v6_idx,
        })
    }

    fn str_at(&self, i: u32) -> &str {
        if i == 0 { return ""; }
        let o = self.str_off_off + i as usize * 4;
        let a = u32::from_le_bytes(self.mm[o..o + 4].try_into().unwrap()) as usize;
        let b = u32::from_le_bytes(self.mm[o + 4..o + 8].try_into().unwrap()) as usize;
        std::str::from_utf8(&self.mm[self.str_blob_off + a..self.str_blob_off + b]).unwrap_or("")
    }

    fn pair_strs(&self, pi: u32) -> (&str, &str) {
        if pi == 0 || pi >= self.n_pairs { return ("", ""); }
        let o = self.pairs_off + pi as usize * 6;
        let isp = get_u24(&self.mm[o..o + 3]);
        let dom = get_u24(&self.mm[o + 3..o + 6]);
        (self.str_at(isp), self.str_at(dom))
    }

    fn lookup_v4_idx(&self, ip: u32) -> Option<u32> {
        let (mut lo, mut hi) = (0u32, self.nb4);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if rd_u32(self.bases4, mid as usize) <= ip { lo = mid + 1; } else { hi = mid; }
        }
        if lo == 0 { return None; }
        let bi = (lo - 1) as usize;
        let base = rd_u32(self.bases4, bi);
        let target = ip - base;
        let db = self.dbits4[bi];
        let ib = self.ibits4[bi];
        let d_a = rd_u32(self.d_off, bi) as usize;
        let i_a = rd_u32(self.i_off, bi) as usize;
        let row_start = bi << BLOCK_SHIFT;
        let row_end = (row_start + BLOCK).min(self.n4 as usize);
        let cnt = (row_end - row_start) as u32;
        let deltas = &self.d_blob[d_a..];
        let (mut bl, mut bh) = (0u32, cnt);
        while bl < bh {
            let mid = (bl + bh) / 2;
            let d = read_packed(deltas, mid as usize, db);
            if d <= target { bl = mid + 1; } else { bh = mid; }
        }
        if bl == 0 { return None; }
        let local = (bl - 1) as usize;
        Some(read_packed(&self.i_blob[i_a..], local, ib))
    }

    fn lookup_v6_idx(&self, ip: u128) -> Option<u32> {
        let key = (ip >> 64) as u64;
        let (mut lo, mut hi) = (0u32, self.n6);
        while lo < hi {
            let mid = (lo + hi) / 2;
            let v = u64::from_le_bytes(
                self.v6_k[mid as usize * 8..mid as usize * 8 + 8].try_into().unwrap(),
            );
            if v <= key { lo = mid + 1; } else { hi = mid; }
        }
        if lo == 0 { return None; }
        Some(read_packed(self.v6_idx, (lo - 1) as usize, self.v6_bits))
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<(&str, &str)> {
        let pi = match ip {
            IpAddr::V4(v) => self.lookup_v4_idx(u32::from(v))?,
            IpAddr::V6(v) => self.lookup_v6_idx(u128::from(v))?,
        };
        if pi == 0 { return None; }
        Some(self.pair_strs(pi))
    }
}
