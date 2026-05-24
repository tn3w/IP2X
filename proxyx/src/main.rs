mod db;
mod ip2l;

use clap::{Parser, Subcommand};
use ip2l::Bin;
use std::collections::{BTreeMap, HashMap};
use std::fs::{create_dir_all, File};
use std::io::{BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const PROXY_TYPE_COL: u8 = 2;
const TSV_FIELDS: &[(&str, u8)] = &[
    ("isp", 6),
    ("domain", 7),
    ("last_seen", 11),
    ("provider", 13),
    ("fraud_score", 14),
];
const BUCKET_FIELDS: &[(&str, u8)] = &[
    ("usage", 8),
    ("threat", 12),
];

#[derive(Parser)]
struct Cli { #[command(subcommand)] cmd: Cmd }

#[derive(Subcommand)]
enum Cmd {
    Build {
        #[arg(long, default_value = "IP2PROXY-LITE-PX12.BIN")]
        px12: PathBuf,
        #[arg(long, default_value = "out")]
        out: PathBuf,
    },
    BuildDb {
        #[arg(long, default_value = "IP2PROXY-LITE-PX12.BIN")]
        px12: PathBuf,
        #[arg(long, default_value = "proxy.bin")]
        out: PathBuf,
    },
    Lookup {
        #[arg(long, default_value = "proxy.bin")]
        db: PathBuf,
        ip: String,
    },
}

fn main() -> std::io::Result<()> {
    match Cli::parse().cmd {
        Cmd::Build { px12, out } => build(&px12, &out),
        Cmd::BuildDb { px12, out } => db::build(&px12, &out),
        Cmd::Lookup { db: dbp, ip } => lookup_cmd(&dbp, &ip),
    }
}

fn lookup_cmd(db_p: &Path, ip_s: &str) -> std::io::Result<()> {
    let d = db::Db::open(db_p)?;
    let ip: IpAddr = ip_s.parse().expect("invalid ip");
    match d.lookup(ip) {
        Some((isp, dom)) => println!("isp\t{isp}\ndomain\t{dom}"),
        None => println!("not found"),
    }
    Ok(())
}

fn build(px12: &Path, out: &Path) -> std::io::Result<()> {
    let b = Bin::open(px12)?;
    create_dir_all(out)?;
    let date = utc_now();
    write_pub_netset(&b, &out.join("proxy_pub.netset"), &date)?;
    for &(name, col) in TSV_FIELDS {
        write_field(&b, col, name, &out.join(format!("{name}.tsv")), &date)?;
    }
    for &(name, col) in BUCKET_FIELDS {
        write_bucketed(&b, col, name, &out.join(format!("{name}.buckets")), &date)?;
    }
    Ok(())
}

fn collect_v4(b: &Bin, col: u8, want_pub: bool) -> Vec<(u32, u32, String)> {
    let mut out = Vec::new();
    for i in 0..b.v4_n {
        let val = b.str_at(i, false, col).to_string();
        if val.is_empty() { continue; }
        if want_pub && b.str_at(i, false, PROXY_TYPE_COL) != "PUB" { continue; }
        let s = b.ipv4_at(i);
        let e = if i + 1 < b.v4_n { b.ipv4_at(i + 1) - 1 } else { u32::MAX };
        out.push((s, e, val));
    }
    out
}

fn collect_v6(b: &Bin, col: u8, want_pub: bool) -> Vec<(u128, u128, String)> {
    let mut out = Vec::new();
    for i in 0..b.v6_n {
        let val = b.str_at(i, true, col).to_string();
        if val.is_empty() { continue; }
        if want_pub && b.str_at(i, true, PROXY_TYPE_COL) != "PUB" { continue; }
        let s = b.ipv6_at(i);
        let e = if i + 1 < b.v6_n { b.ipv6_at(i + 1) - 1 } else { u128::MAX };
        out.push((s, e, val));
    }
    out
}

fn merge_v4(v: Vec<(u32, u32, String)>) -> Vec<(u32, u32, String)> {
    let mut out: Vec<(u32, u32, String)> = Vec::with_capacity(v.len());
    for (s, e, val) in v {
        if let Some(last) = out.last_mut() {
            if last.2 == val && last.1.saturating_add(1) == s {
                last.1 = e;
                continue;
            }
        }
        out.push((s, e, val));
    }
    out
}

fn merge_v6(v: Vec<(u128, u128, String)>) -> Vec<(u128, u128, String)> {
    let mut out: Vec<(u128, u128, String)> = Vec::with_capacity(v.len());
    for (s, e, val) in v {
        if let Some(last) = out.last_mut() {
            if last.2 == val && last.1.saturating_add(1) == s {
                last.1 = e;
                continue;
            }
        }
        out.push((s, e, val));
    }
    out
}

fn fmt4(s: u32, e: u32) -> String {
    if s == e { Ipv4Addr::from(s).to_string() }
    else { format!("{}+{}", Ipv4Addr::from(s), e - s) }
}

fn fmt6(s: u128, e: u128) -> String {
    if s == e { Ipv6Addr::from(s).to_string() }
    else { format!("{}+{}", Ipv6Addr::from(s), e - s) }
}

fn freq_dict(
    v4: &[(u32, u32, String)], v6: &[(u128, u128, String)],
) -> (Vec<String>, HashMap<String, u32>) {
    let mut count: HashMap<String, u32> = HashMap::new();
    for (_, _, v) in v4 { *count.entry(v.clone()).or_insert(0) += 1; }
    for (_, _, v) in v6 { *count.entry(v.clone()).or_insert(0) += 1; }
    let mut sorted: Vec<_> = count.into_iter().collect();
    sorted.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let dict: Vec<String> = sorted.into_iter().map(|(s, _)| s).collect();
    let idx: HashMap<String, u32> = dict.iter().enumerate()
        .map(|(i, s)| (s.clone(), i as u32)).collect();
    (dict, idx)
}

fn write_field(
    b: &Bin, col: u8, name: &str, out: &Path, date: &str,
) -> std::io::Result<()> {
    let v4 = merge_v4(collect_v4(b, col, false));
    let v6 = merge_v6(collect_v6(b, col, false));
    let (dict, idx) = freq_dict(&v4, &v6);
    let mut w = BufWriter::new(File::create(out)?);
    field_header(&mut w, name, date, v4.len(), v6.len(), dict.len())?;
    writeln!(w, "#dict")?;
    for (i, s) in dict.iter().enumerate() {
        writeln!(w, "{i}\t{s}")?;
    }
    writeln!(w, "#data")?;
    for (s, e, val) in &v4 {
        writeln!(w, "{}\t{}", fmt4(*s, *e), idx[val])?;
    }
    for (s, e, val) in &v6 {
        writeln!(w, "{}\t{}", fmt6(*s, *e), idx[val])?;
    }
    w.flush()
}

fn write_bucketed(b: &Bin, col: u8, name: &str, out: &Path, date: &str)
    -> std::io::Result<()>
{
    let v4 = merge_v4(collect_v4(b, col, false));
    let v6 = merge_v6(collect_v6(b, col, false));
    let mut cats: BTreeMap<String, (Vec<(u32, u32)>, Vec<(u128, u128)>)> = BTreeMap::new();
    for (s, e, val) in v4 { cats.entry(val).or_default().0.push((s, e)); }
    for (s, e, val) in v6 { cats.entry(val).or_default().1.push((s, e)); }
    let mut w = BufWriter::new(File::create(out)?);
    bucket_header(&mut w, name, date, cats.len())?;
    for (val, (r4, r6)) in &cats {
        writeln!(w, "[{val}]")?;
        for (s, e) in r4 { writeln!(w, "{}", fmt4(*s, *e))?; }
        for (s, e) in r6 { writeln!(w, "{}", fmt6(*s, *e))?; }
    }
    w.flush()
}

fn write_pub_netset(b: &Bin, out: &Path, date: &str) -> std::io::Result<()> {
    let v4 = merge_v4(collect_v4(b, PROXY_TYPE_COL, true));
    let v6 = merge_v6(collect_v6(b, PROXY_TYPE_COL, true));
    let mut v4_cidrs: Vec<(u32, u8)> = Vec::new();
    for (s, e, _) in &v4 { v4_cidrs.extend(cidrs_v4(*s, *e)); }
    let mut v6_cidrs: Vec<(u128, u8)> = Vec::new();
    for (s, e, _) in &v6 { v6_cidrs.extend(cidrs_v6(*s, *e)); }
    let mut w = BufWriter::new(File::create(out)?);
    netset_header(&mut w, date, v4.len(), v6.len(), v4_cidrs.len() + v6_cidrs.len())?;
    for (a, p) in v4_cidrs {
        if p == 32 { writeln!(w, "{}", Ipv4Addr::from(a))?; }
        else { writeln!(w, "{}/{}", Ipv4Addr::from(a), p)?; }
    }
    for (a, p) in v6_cidrs {
        if p == 128 { writeln!(w, "{}", Ipv6Addr::from(a))?; }
        else { writeln!(w, "{}/{}", Ipv6Addr::from(a), p)?; }
    }
    w.flush()
}

fn cidrs_v4(mut s: u32, e: u32) -> Vec<(u32, u8)> {
    let mut out = Vec::new();
    loop {
        let max_size = if s == 0 { 32 } else { s.trailing_zeros() as u8 };
        let span = (e - s).saturating_add(1);
        let span_bits = if span == 0 { 32 } else { 31 - span.leading_zeros() as u8 };
        let bits = max_size.min(span_bits);
        out.push((s, 32 - bits));
        let next = s as u64 + (1u64 << bits);
        if next > e as u64 { break; }
        s = next as u32;
    }
    out
}

fn cidrs_v6(mut s: u128, e: u128) -> Vec<(u128, u8)> {
    let mut out = Vec::new();
    loop {
        let max_size = if s == 0 { 128 } else { s.trailing_zeros() as u8 };
        let span = e.saturating_sub(s).saturating_add(1);
        let span_bits = if span == 0 { 128 } else { 127 - span.leading_zeros() as u8 };
        let bits = max_size.min(span_bits);
        out.push((s, 128 - bits));
        if bits >= 128 { break; }
        let next = s.saturating_add(1u128 << bits);
        if next > e { break; }
        s = next;
    }
    out
}

fn netset_header<W: Write>(
    w: &mut W, date: &str, v4r: usize, v6r: usize, cidrs: usize,
) -> std::io::Result<()> {
    writeln!(w, "#")?;
    writeln!(w, "# proxy_pub.netset  -  ipv4+ipv6 hash:net netset")?;
    writeln!(w, "#")?;
    writeln!(w, "# CIDR list of public proxies (proxy_type == \"PUB\").")?;
    writeln!(w, "# Generated by proxyx. Compatible with ipset/iptables/nftables/ufw.")?;
    writeln!(w, "#")?;
    writeln!(w, "# Built at        : {date}")?;
    writeln!(w, "# v4 source ranges: {v4r}")?;
    writeln!(w, "# v6 source ranges: {v6r}")?;
    writeln!(w, "# Total CIDR lines: {cidrs}")?;
    writeln!(w, "#")?;
    Ok(())
}

fn field_header<W: Write>(
    w: &mut W, name: &str, date: &str, v4r: usize, v6r: usize, dict_n: usize,
) -> std::io::Result<()> {
    writeln!(w, "#")?;
    writeln!(w, "# {name}.tsv  -  IP range -> {name}")?;
    writeln!(w, "#")?;
    writeln!(w, "# Two sections, each introduced by a marker line:")?;
    writeln!(w, "#   #dict")?;
    writeln!(w, "#     <idx>\\t<value>      (one per line, idx in decimal)")?;
    writeln!(w, "#   #data")?;
    writeln!(w, "#     <start_ip>[+<span>]\\t<idx>")?;
    writeln!(w, "#       span = end - start (decimal); omitted when single IP.")?;
    writeln!(w, "#       <idx> resolves to <value> via the dict above.")?;
    writeln!(w, "# Dict ordered by descending frequency (smaller idx = more common).")?;
    writeln!(w, "# Rows with empty {name} omitted; adjacent equal values merged.")?;
    writeln!(w, "# v4 block first, then v6; each sorted ascending by start_ip.")?;
    writeln!(w, "# Generated by proxyx.")?;
    writeln!(w, "#")?;
    writeln!(w, "# Built at    : {date}")?;
    writeln!(w, "# Dict entries: {dict_n}")?;
    writeln!(w, "# Entries v4  : {v4r}")?;
    writeln!(w, "# Entries v6  : {v6r}")?;
    writeln!(w, "#")?;
    Ok(())
}

fn bucket_header<W: Write>(
    w: &mut W, name: &str, date: &str, n_cats: usize,
) -> std::io::Result<()> {
    writeln!(w, "#")?;
    writeln!(w, "# {name}.buckets  -  IP range -> {name}")?;
    writeln!(w, "#")?;
    writeln!(w, "# Categorical field, bucketed per value to avoid string repetition.")?;
    writeln!(w, "# Format:")?;
    writeln!(w, "#   [VALUE]")?;
    writeln!(w, "#   <start_ip>[+<span>]   (v4 then v6, ascending)")?;
    writeln!(w, "#   [NEXT_VALUE]")?;
    writeln!(w, "#   ...")?;
    writeln!(w, "# span = end - start (decimal); omitted when single IP.")?;
    writeln!(w, "# Lookup: scan sections, bisect ranges within the section.")?;
    writeln!(w, "# Generated by proxyx.")?;
    writeln!(w, "#")?;
    writeln!(w, "# Built at  : {date}")?;
    writeln!(w, "# Categories: {n_cats}")?;
    writeln!(w, "#")?;
    Ok(())
}

fn utc_now() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(0);
    let days = (secs / 86400) as i64;
    let mut rem = (secs % 86400) as u32;
    let h = rem / 3600; rem %= 3600;
    let m = rem / 60;
    let s = rem % 60;
    let (y, mo, d) = civil(days);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02} UTC")
}

fn civil(z: i64) -> (i32, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i32 + era as i32 * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
