use memmap2::Mmap;
use std::fs::File;
use std::path::Path;

pub struct Bin {
    mm: Mmap,
    pub v4_n: u32,
    v4_addr: u32,
    pub v6_n: u32,
    v6_addr: u32,
    v4_stride: usize,
    v6_stride: usize,
}

impl Bin {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let f = File::open(path)?;
        let mm = unsafe { Mmap::map(&f)? };
        let dbcol = mm[1] as usize;
        let v4_n = u32::from_le_bytes(mm[5..9].try_into().unwrap());
        let v4_addr = u32::from_le_bytes(mm[9..13].try_into().unwrap());
        let v6_n = u32::from_le_bytes(mm[13..17].try_into().unwrap());
        let v6_addr = u32::from_le_bytes(mm[17..21].try_into().unwrap());
        Ok(Self {
            mm, v4_n, v4_addr, v6_n, v6_addr,
            v4_stride: dbcol * 4,
            v6_stride: dbcol * 4 + 12,
        })
    }

    pub fn ipv4_at(&self, mid: u32) -> u32 {
        let o = (self.v4_addr - 1) as usize + (mid as usize) * self.v4_stride;
        u32::from_le_bytes(self.mm[o..o + 4].try_into().unwrap())
    }

    pub fn ipv6_at(&self, mid: u32) -> u128 {
        let o = (self.v6_addr - 1) as usize + (mid as usize) * self.v6_stride;
        u128::from_le_bytes(self.mm[o..o + 16].try_into().unwrap())
    }

    pub fn col_off(&self, mid: u32, is_v6: bool, col: u8) -> usize {
        let (base, stride, ipsz) = if is_v6 {
            (self.v6_addr, self.v6_stride, 16)
        } else {
            (self.v4_addr, self.v4_stride, 4)
        };
        let row = (base - 1) as usize + (mid as usize) * stride;
        row + ipsz + (col as usize - 2) * 4
    }

    pub fn f32_at(&self, off: usize) -> f32 {
        f32::from_le_bytes(self.mm[off..off + 4].try_into().unwrap())
    }
}
