use crate::db::{self, Range};
use flate2::read::GzDecoder;
use std::collections::HashMap;
use std::fs::{create_dir_all, File};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

const RIR_BULK: &[(&str, &[&str])] = &[
    ("RIPE", &[
        "https://ftp.ripe.net/ripe/dbase/split/ripe.db.inetnum.gz",
        "https://ftp.ripe.net/ripe/dbase/split/ripe.db.inet6num.gz",
    ]),
    ("APNIC", &[
        "https://ftp.apnic.net/apnic/whois/apnic.db.inetnum.gz",
        "https://ftp.apnic.net/apnic/whois/apnic.db.inet6num.gz",
    ]),
    ("AFRINIC", &["https://ftp.afrinic.net/pub/dbase/afrinic.db.gz"]),
];
const LACNIC_GEOFEEDS: &str = "https://milacnic.lacnic.net/lacnic/geofeeds";
const THREADS: usize = 64;
const FEED_LIMIT: u64 = 64 << 20;
const BULK_LIMIT: u64 = 2 << 30;

struct Entry {
    rir: &'static str,
    authority: Option<Range>,
    url: String,
}

pub fn fetch(cache: &Path, out: &Path) -> io::Result<()> {
    let bulk = ensure_bulk(cache)?;
    let mut entries: Vec<Entry> = Vec::new();
    for (rir, path) in &bulk {
        discover(rir, path, &mut entries)?;
    }
    entries.push(Entry { rir: "LACNIC", authority: None, url: LACNIC_GEOFEEDS.to_string() });
    eprintln!("discovered {} feed references", entries.len());

    let mut index: HashMap<&str, usize> = HashMap::new();
    let mut urls: Vec<String> = Vec::new();
    for e in &entries {
        if !index.contains_key(e.url.as_str()) {
            index.insert(e.url.as_str(), urls.len());
            urls.push(e.url.clone());
        }
    }
    eprintln!("fetching {} unique feeds", urls.len());
    let bodies = fetch_all(&urls);
    let ok = bodies.iter().filter(|b| b.is_some()).count();
    eprintln!("fetched {ok}/{}", urls.len());

    let mut w = BufWriter::new(File::create(out)?);
    writeln!(w, "cidr,country,region,city,postal,feed,rir")?;
    let mut rows = 0u64;
    for e in &entries {
        let Some(body) = &bodies[index[e.url.as_str()]] else {
            continue;
        };
        for line in body.lines() {
            let Some((range, cols)) = parse_feed_row(line) else {
                continue;
            };
            if let Some(authority) = &e.authority {
                if !db::contains(authority, &range) {
                    continue;
                }
            }
            writeln!(
                w, "{},{},{},{},{},{},{}",
                csv(&cols[0]), csv(&cols[1]), csv(&cols[2]), csv(&cols[3]), csv(&cols[4]),
                csv(&e.url), e.rir
            )?;
            rows += 1;
        }
    }
    w.flush()?;
    eprintln!("wrote {rows} rows to {}", out.display());
    Ok(())
}

fn parse_feed_row(line: &str) -> Option<(Range, [String; 5])> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let cols = split_csv(line);
    let prefix = cols.first()?.trim().to_string();
    let range = db::parse_cidr(&prefix)?;
    let g = |i: usize| cols.get(i).map(|s| s.trim().to_string()).unwrap_or_default();
    Some((range, [prefix, g(1), g(2), g(3), g(4)]))
}

fn discover(rir: &'static str, path: &Path, out: &mut Vec<Entry>) -> io::Result<()> {
    let mut reader = BufReader::new(GzDecoder::new(File::open(path)?));
    let (mut authority, mut url): (Option<Range>, Option<String>) = (None, None);
    let mut buf: Vec<u8> = Vec::new();
    loop {
        buf.clear();
        if reader.read_until(b'\n', &mut buf)? == 0 {
            break;
        }
        let line = String::from_utf8_lossy(&buf);
        let line = line.trim_end();
        if line.is_empty() {
            flush(rir, &mut authority, &mut url, out);
            continue;
        }
        if let Some(v) = line.strip_prefix("inetnum:") {
            authority = db::parse_inetnum(v.trim());
        } else if let Some(v) = line.strip_prefix("inet6num:") {
            authority = db::parse_inet6num(v.trim());
        } else if let Some(v) = line.strip_prefix("geofeed:") {
            url = Some(v.trim().to_string());
        } else if let Some(v) = remarks_geofeed(line) {
            url = Some(v);
        }
    }
    flush(rir, &mut authority, &mut url, out);
    Ok(())
}

fn remarks_geofeed(line: &str) -> Option<String> {
    let v = line.strip_prefix("remarks:")?.trim();
    let lower = v.to_ascii_lowercase();
    if !lower.contains("geofeed") {
        return None;
    }
    let start = v.find("http")?;
    Some(v[start..].split_whitespace().next()?.to_string())
}

fn flush(
    rir: &'static str, authority: &mut Option<Range>, url: &mut Option<String>,
    out: &mut Vec<Entry>,
) {
    if let (Some(a), Some(u)) = (*authority, url.take()) {
        out.push(Entry { rir, authority: Some(a), url: u });
    }
    *authority = None;
    *url = None;
}

fn ensure_bulk(cache: &Path) -> io::Result<Vec<(&'static str, PathBuf)>> {
    create_dir_all(cache)?;
    let mut out = Vec::new();
    for (rir, urls) in RIR_BULK {
        for (i, url) in urls.iter().enumerate() {
            let path = cache.join(format!("{}-{i}.gz", rir.to_lowercase()));
            if !path.exists() {
                eprintln!("download {url}");
                std::fs::write(&path, get(url, BULK_LIMIT)?)?;
            }
            out.push((*rir, path));
        }
    }
    Ok(out)
}

fn fetch_all(urls: &[String]) -> Vec<Option<String>> {
    let results: Vec<Mutex<Option<String>>> = urls.iter().map(|_| Mutex::new(None)).collect();
    let next = AtomicUsize::new(0);
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(25))
        .build();
    std::thread::scope(|scope| {
        for _ in 0..THREADS {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= urls.len() {
                    break;
                }
                if let Ok(body) = get_text(&agent, &urls[i]) {
                    *results[i].lock().unwrap() = Some(body);
                }
            });
        }
    });
    results.into_iter().map(|m| m.into_inner().unwrap()).collect()
}

fn get_text(agent: &ureq::Agent, url: &str) -> io::Result<String> {
    let reader = agent.get(url).call().map_err(other)?.into_reader();
    let mut buf = Vec::new();
    reader.take(FEED_LIMIT).read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn get(url: &str, limit: u64) -> io::Result<Vec<u8>> {
    let reader = ureq::get(url).call().map_err(other)?.into_reader();
    let mut buf = Vec::new();
    reader.take(limit).read_to_end(&mut buf)?;
    Ok(buf)
}

fn other<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

fn split_csv(line: &str) -> Vec<String> {
    line.split(',').map(|s| s.trim().to_string()).collect()
}

fn csv(value: &str) -> String {
    if value.contains([',', '"', '\n']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}
