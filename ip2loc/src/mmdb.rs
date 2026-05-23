use maxminddb::{geoip2, Reader};
use std::net::IpAddr;
use std::path::Path;

pub struct Mmdb {
    r: Reader<Vec<u8>>,
}

impl Mmdb {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        Reader::open_readfile(path)
            .map(|r| Self { r })
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    pub fn walk_v4_geo(&self) -> Vec<(u32, u32, f64, f64)> {
        let mut out = Vec::new();
        let it = self.r.within("0.0.0.0/0".parse().unwrap(), Default::default());
        for res in it.into_iter().flatten().flatten() {
            let Ok(net) = res.network() else { continue };
            let IpAddr::V4(a) = net.network() else { continue };
            let s = u32::from(a);
            let pfx = net.prefix() as u32;
            let e = if pfx == 0 { u32::MAX }
                else { s | (((1u64 << (32 - pfx)) - 1) as u32) };
            let Ok(Some(city)) = res.decode::<geoip2::City>() else { continue };
            let loc = city.location;
            let (Some(lat), Some(lon)) = (loc.latitude, loc.longitude) else { continue };
            if lat == 0.0 && lon == 0.0 { continue; }
            out.push((s, e, lat, lon));
        }
        out.sort_by_key(|r| r.0);
        out
    }

    pub fn walk_v6_geo(&self) -> Vec<(u128, u128, f64, f64)> {
        let mut out = Vec::new();
        let it = self.r.within("::/0".parse().unwrap(), Default::default());
        for res in it.into_iter().flatten().flatten() {
            let Ok(net) = res.network() else { continue };
            let IpAddr::V6(a) = net.network() else { continue };
            let s = u128::from(a);
            let pfx = net.prefix() as u32;
            let e = if pfx == 0 { u128::MAX } else { s | ((1u128 << (128 - pfx)) - 1) };
            let Ok(Some(city)) = res.decode::<geoip2::City>() else { continue };
            let loc = city.location;
            let (Some(lat), Some(lon)) = (loc.latitude, loc.longitude) else { continue };
            if lat == 0.0 && lon == 0.0 { continue; }
            out.push((s, e, lat, lon));
        }
        out.sort_by_key(|r| r.0);
        out
    }
}
