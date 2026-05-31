mod db;
mod fetch;

use clap::{Parser, Subcommand};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Fetch {
        #[arg(long, default_value = ".cache/rir-bulk")]
        cache: PathBuf,
        #[arg(long, default_value = "geofeeds_data.csv")]
        out: PathBuf,
    },
    Build {
        #[arg(long, default_value = "geofeeds_data.csv")]
        data: PathBuf,
        #[arg(long, default_value = "geofeed.bin")]
        out: PathBuf,
    },
    Lookup {
        #[arg(long, default_value = "geofeed.bin")]
        db: PathBuf,
        ip: String,
    },
    Bench {
        #[arg(long, default_value = "geofeed.bin")]
        db: PathBuf,
        #[arg(long, default_value_t = 5_000_000)]
        n: u32,
    },
}

fn main() -> std::io::Result<()> {
    match Cli::parse().cmd {
        Cmd::Fetch { cache, out } => fetch::fetch(&cache, &out),
        Cmd::Build { data, out } => db::build(&data, &out),
        Cmd::Lookup { db: path, ip } => lookup(&path, &ip),
        Cmd::Bench { db: path, n } => bench(&path, n),
    }
}

fn bench(path: &Path, n: u32) -> std::io::Result<()> {
    use std::time::Instant;
    let t = Instant::now();
    let d = db::Db::open(path)?;
    let load = t.elapsed();
    let mut seed = 0x9e3779b9u32;
    let mut hits = 0u64;
    let t = Instant::now();
    for _ in 0..n {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        if d.lookup_v4(Ipv4Addr::from(seed)).is_some() {
            hits += 1;
        }
    }
    let per = t.elapsed().as_nanos() as f64 / n as f64;
    println!("load {load:?} | {n} lookups | {per:.1} ns/lookup | hits {hits}");
    Ok(())
}

fn lookup(path: &Path, ip: &str) -> std::io::Result<()> {
    let d = db::Db::open(path)?;
    let addr: IpAddr = ip.parse().expect("invalid ip");
    let hit = match addr {
        IpAddr::V4(v4) => d.lookup_v4(v4),
        IpAddr::V6(v6) => d.lookup_v6(v6),
    };
    let Some(hit) = hit else {
        println!("not found");
        return Ok(());
    };
    for (name, value) in &hit.fields {
        println!("{name}\t{value}");
    }
    Ok(())
}
