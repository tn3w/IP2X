use std::collections::HashMap;
use std::fs::File;
use std::io::{Error, ErrorKind, Read, Result};
use std::net::{Ipv4Addr, Ipv6Addr};

const DATA_SEPARATOR_SIZE: usize = 16;
const METADATA_MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum Value {
    String(String),
    Int(i32),
    UInt(u64),
    Float(f32),
    Double(f64),
    Bool(bool),
    Map(HashMap<String, Value>),
    Array(Vec<Value>),
    Bytes(Vec<u8>),
}

impl Value {
    fn as_map(&self) -> Option<&HashMap<String, Value>> {
        if let Value::Map(m) = self {
            Some(m)
        } else {
            None
        }
    }

    fn as_u64(&self) -> Option<u64> {
        match self {
            Value::UInt(n) => Some(*n),
            Value::Int(n) => Some(*n as u64),
            _ => None,
        }
    }

    fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Double(f) => Some(*f),
            Value::Float(f) => Some(*f as f64),
            _ => None,
        }
    }
}

struct Metadata {
    node_count: u32,
    record_size: u16,
    ip_version: u16,
    search_tree_size: usize,
}

pub struct MaxMindReader {
    buffer: Vec<u8>,
    metadata: Metadata,
    ipv4_start: u32,
}

impl MaxMindReader {
    pub fn open(path: &str) -> Result<Self> {
        let mut buffer = Vec::new();
        File::open(path)?.read_to_end(&mut buffer)?;

        let metadata_start = Self::find_metadata_start(&buffer)?;
        let metadata = Self::parse_metadata(&buffer, metadata_start)?;
        let ipv4_start = Self::find_ipv4_start(
            &buffer,
            metadata.node_count,
            metadata.record_size,
            metadata.ip_version,
        )?;

        Ok(Self {
            buffer,
            metadata,
            ipv4_start,
        })
    }

    fn find_metadata_start(buffer: &[u8]) -> Result<usize> {
        buffer
            .windows(METADATA_MARKER.len())
            .rposition(|w| w == METADATA_MARKER)
            .map(|pos| pos + METADATA_MARKER.len())
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "No metadata"))
    }

    fn parse_metadata(buffer: &[u8], start: usize) -> Result<Metadata> {
        let mut decoder = Decoder::new(buffer, start);
        let (value, _) = decoder.decode(start)?;
        let map = value
            .as_map()
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Bad metadata"))?;

        let node_count = map
            .get("node_count")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "No node_count"))?
            as u32;

        let record_size = map
            .get("record_size")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "No record_size"))?
            as u16;

        let ip_version = map.get("ip_version").and_then(|v| v.as_u64()).unwrap_or(6) as u16;

        let search_tree_size = node_count as usize * (record_size / 4) as usize;

        Ok(Metadata {
            node_count,
            record_size,
            ip_version,
            search_tree_size,
        })
    }

    fn find_ipv4_start(
        buffer: &[u8],
        node_count: u32,
        record_size: u16,
        ip_version: u16,
    ) -> Result<u32> {
        if ip_version != 6 {
            return Ok(0);
        }

        let node_byte_size = record_size / 4;
        let mut node = 0u32;

        for _ in 0..96 {
            if node >= node_count {
                break;
            }
            node = Self::read_node_static(buffer, node, 0, record_size, node_byte_size)?;
        }

        Ok(node)
    }

    #[allow(dead_code)]
    pub fn load_all(&self) -> Vec<(u128, u128, HashMap<String, Value>)> {
        let pointers = self.collect_pointers();
        self.decode_all(pointers)
    }

    pub fn load_all_geo(&self) -> Vec<(u128, u128, f32, f32)> {
        let pointers = self.collect_pointers();
        self.decode_geo(pointers)
    }

    fn collect_pointers(&self) -> Vec<(usize, u128, u128)> {
        let capacity = (self.metadata.node_count / 2) as usize;
        let mut pointers = Vec::with_capacity(capacity);
        let mut stack = Vec::with_capacity(1024);
        stack.push((0u32, 0usize, 0u128));

        while let Some((node, depth, ip_acc)) = stack.pop() {
            if ip_acc != 0 && node == self.ipv4_start {
                continue;
            }

            if node > self.metadata.node_count {
                let (start, end) = self.calculate_range(depth, ip_acc);
                let offset = self.node_to_offset(node);
                pointers.push((offset, start, end));
                continue;
            }

            if node >= self.metadata.node_count {
                continue;
            }

            self.push_children(&mut stack, node, depth, ip_acc);
        }

        pointers
    }

    fn calculate_range(&self, depth: usize, ip_acc: u128) -> (u128, u128) {
        let bits = if self.metadata.ip_version == 6 {
            128
        } else {
            32
        };
        let start = ip_acc << (bits - depth);

        let (prefix_len, effective_bits) = if bits == 128 && start <= (1u128 << 32) {
            (depth.saturating_sub(96), 32)
        } else {
            (depth, bits)
        };

        let end = start | ((1u128 << (effective_bits - prefix_len)) - 1);
        (start, end)
    }

    fn node_to_offset(&self, node: u32) -> usize {
        node as usize - self.metadata.node_count as usize + self.metadata.search_tree_size
    }

    fn push_children(
        &self,
        stack: &mut Vec<(u32, usize, u128)>,
        node: u32,
        depth: usize,
        ip_acc: u128,
    ) {
        let record_size = self.metadata.record_size;
        let node_byte_size = record_size / 4;

        if let Ok(right) =
            Self::read_node_static(&self.buffer, node, 1, record_size, node_byte_size)
        {
            stack.push((right, depth + 1, (ip_acc << 1) | 1));
        }

        if let Ok(left) = Self::read_node_static(&self.buffer, node, 0, record_size, node_byte_size)
        {
            stack.push((left, depth + 1, ip_acc << 1));
        }
    }

    fn decode_all(
        &self,
        pointers: Vec<(usize, u128, u128)>,
    ) -> Vec<(u128, u128, HashMap<String, Value>)> {
        let mut results = Vec::with_capacity(pointers.len());
        let data_base = self.metadata.search_tree_size + DATA_SEPARATOR_SIZE;
        let mut decoder = Decoder::new(&self.buffer, data_base);

        for (offset, start, end) in pointers {
            if let Ok((value, _)) = decoder.decode(offset) {
                if let Some(map) = value.as_map().cloned() {
                    results.push((start, end, map));
                }
            }
        }

        results
    }

    fn decode_geo(&self, pointers: Vec<(usize, u128, u128)>) -> Vec<(u128, u128, f32, f32)> {
        let mut results = Vec::with_capacity(pointers.len());
        let data_base = self.metadata.search_tree_size + DATA_SEPARATOR_SIZE;
        let mut decoder = Decoder::new(&self.buffer, data_base);

        for (offset, start, end) in pointers {
            if let Ok((value, _)) = decoder.decode(offset) {
                if let Some((lat, lon)) = Self::extract_location(&value) {
                    if lat != 0.0 || lon != 0.0 {
                        results.push((start, end, lat, lon));
                    }
                }
            }
        }

        results
    }

    fn extract_location(value: &Value) -> Option<(f32, f32)> {
        let map = value.as_map()?;
        let location = map.get("location")?.as_map()?;
        let lat = location.get("latitude")?.as_f64()? as f32;
        let lon = location.get("longitude")?.as_f64()? as f32;
        Some((lat, lon))
    }

    #[allow(dead_code)]
    pub fn lookup(&self, ip: &str) -> Option<HashMap<String, Value>> {
        let (packed, bit_count) = self.parse_ip(ip)?;
        let (pointer, _) = self.find_in_tree(&packed, bit_count)?;

        if pointer == 0 {
            return None;
        }

        let offset = self.node_to_offset(pointer);
        let data_base = self.metadata.search_tree_size + DATA_SEPARATOR_SIZE;
        let mut decoder = Decoder::new(&self.buffer, data_base);
        let (value, _) = decoder.decode(offset).ok()?;

        value.as_map().cloned()
    }

    fn parse_ip(&self, ip: &str) -> Option<(Vec<u8>, usize)> {
        if let Ok(v4) = ip.parse::<Ipv4Addr>() {
            return Some((v4.octets().to_vec(), 32));
        }
        if let Ok(v6) = ip.parse::<Ipv6Addr>() {
            return Some((v6.octets().to_vec(), 128));
        }
        None
    }

    fn find_in_tree(&self, packed: &[u8], bit_count: usize) -> Option<(u32, usize)> {
        let mut node = if self.metadata.ip_version == 6 && bit_count == 32 {
            self.ipv4_start
        } else {
            0
        };

        let mut i = 0;
        while i < bit_count && node < self.metadata.node_count {
            let bit = (packed[i / 8] >> (7 - (i % 8))) & 1;
            node = self.read_node(node, bit as usize).ok()?;
            i += 1;
        }

        if node == self.metadata.node_count {
            return Some((0, i));
        }
        if node > self.metadata.node_count {
            return Some((node, i));
        }

        None
    }

    fn read_node(&self, node_number: u32, index: usize) -> Result<u32> {
        Self::read_node_static(
            &self.buffer,
            node_number,
            index,
            self.metadata.record_size,
            self.metadata.record_size / 4,
        )
    }

    fn read_node_static(
        buffer: &[u8],
        node_number: u32,
        index: usize,
        record_size: u16,
        node_byte_size: u16,
    ) -> Result<u32> {
        let base = node_number as usize * node_byte_size as usize;

        let bytes = match record_size {
            24 => Self::read_24bit(buffer, base, index),
            28 => Self::read_28bit(buffer, base, index),
            32 => Self::read_32bit(buffer, base, index),
            _ => return Err(Error::new(ErrorKind::InvalidData, "Bad record size")),
        };

        Ok(u32::from_be_bytes(bytes))
    }

    fn read_24bit(buffer: &[u8], base: usize, index: usize) -> [u8; 4] {
        let offset = base + index * 3;
        let mut bytes = [0u8; 4];
        bytes[1..4].copy_from_slice(&buffer[offset..offset + 3]);
        bytes
    }

    fn read_28bit(buffer: &[u8], base: usize, index: usize) -> [u8; 4] {
        let offset = base + 3 * index;
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&buffer[offset..offset + 4]);

        if index == 1 {
            bytes[0] &= 0x0F;
        } else {
            let middle = (bytes[3] & 0xF0) >> 4;
            bytes[3] = bytes[2];
            bytes[2] = bytes[1];
            bytes[1] = bytes[0];
            bytes[0] = middle;
        }

        bytes
    }

    fn read_32bit(buffer: &[u8], base: usize, index: usize) -> [u8; 4] {
        let offset = base + index * 4;
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&buffer[offset..offset + 4]);
        bytes
    }
}

struct Decoder<'a> {
    buffer: &'a [u8],
    pointer_base: usize,
}

impl<'a> Decoder<'a> {
    fn new(buffer: &'a [u8], pointer_base: usize) -> Self {
        Self {
            buffer,
            pointer_base,
        }
    }

    fn decode(&mut self, offset: usize) -> std::io::Result<(Value, usize)> {
        let ctrl_byte = self.buffer[offset];
        let mut type_num = (ctrl_byte >> 5) as usize;
        let mut new_offset = offset + 1;

        if type_num == 0 {
            type_num = self.buffer[new_offset] as usize + 7;
            new_offset += 1;
        }

        let (size, new_offset) = self.size_from_ctrl_byte(ctrl_byte, new_offset, type_num)?;

        match type_num {
            1 => self.decode_pointer(size, new_offset),
            2 => self.decode_string(size, new_offset),
            3 => self.decode_double(size, new_offset),
            4 => self.decode_bytes(size, new_offset),
            5 | 6 | 9 | 10 => self.decode_uint(size, new_offset),
            7 => self.decode_map(size, new_offset),
            8 => self.decode_int32(size, new_offset),
            11 => self.decode_array(size, new_offset),
            14 => Ok((Value::Bool(size != 0), new_offset)),
            15 => self.decode_float(size, new_offset),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Unknown type",
            )),
        }
    }

    fn decode_pointer(&mut self, size: usize, offset: usize) -> std::io::Result<(Value, usize)> {
        let pointer_size = (size >> 3) + 1;
        let buf = &self.buffer[offset..offset + pointer_size];
        let new_offset = offset + pointer_size;

        let pointer = match pointer_size {
            1 => {
                let bytes = [size as u8 & 0x7, buf[0]];
                u16::from_be_bytes(bytes) as usize + self.pointer_base
            }
            2 => {
                let bytes = [0, size as u8 & 0x7, buf[0], buf[1]];
                u32::from_be_bytes(bytes) as usize + 2048 + self.pointer_base
            }
            3 => {
                let bytes = [size as u8 & 0x7, buf[0], buf[1], buf[2]];
                u32::from_be_bytes(bytes) as usize + 526336 + self.pointer_base
            }
            _ => u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize + self.pointer_base,
        };

        let (value, _) = self.decode(pointer)?;
        Ok((value, new_offset))
    }

    fn decode_string(&self, size: usize, offset: usize) -> std::io::Result<(Value, usize)> {
        let new_offset = offset + size;
        let s = String::from_utf8_lossy(&self.buffer[offset..new_offset]).into_owned();
        Ok((Value::String(s), new_offset))
    }

    fn decode_double(&self, size: usize, offset: usize) -> std::io::Result<(Value, usize)> {
        if size != 8 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid double size",
            ));
        }
        let new_offset = offset + size;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.buffer[offset..new_offset]);
        Ok((Value::Double(f64::from_be_bytes(bytes)), new_offset))
    }

    fn decode_float(&self, size: usize, offset: usize) -> std::io::Result<(Value, usize)> {
        if size != 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid float size",
            ));
        }
        let new_offset = offset + size;
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&self.buffer[offset..new_offset]);
        Ok((Value::Float(f32::from_be_bytes(bytes)), new_offset))
    }

    fn decode_bytes(&self, size: usize, offset: usize) -> std::io::Result<(Value, usize)> {
        let new_offset = offset + size;
        Ok((
            Value::Bytes(self.buffer[offset..new_offset].to_vec()),
            new_offset,
        ))
    }

    fn decode_uint(&self, size: usize, offset: usize) -> std::io::Result<(Value, usize)> {
        let new_offset = offset + size;
        let mut value = 0u64;
        for &byte in &self.buffer[offset..new_offset] {
            value = (value << 8) | byte as u64;
        }
        Ok((Value::UInt(value), new_offset))
    }

    fn decode_int32(&self, size: usize, offset: usize) -> std::io::Result<(Value, usize)> {
        if size == 0 {
            return Ok((Value::Int(0), offset));
        }
        let new_offset = offset + size;
        let bytes = &self.buffer[offset..new_offset];

        let mut padded = [0u8; 4];
        padded[4 - size..].copy_from_slice(bytes);
        Ok((Value::Int(i32::from_be_bytes(padded)), new_offset))
    }

    fn decode_map(&mut self, size: usize, mut offset: usize) -> std::io::Result<(Value, usize)> {
        let mut map = HashMap::new();
        for _ in 0..size {
            let (key, new_offset) = self.decode(offset)?;
            offset = new_offset;
            let (value, new_offset) = self.decode(offset)?;
            offset = new_offset;
            if let Value::String(k) = key {
                map.insert(k, value);
            }
        }
        Ok((Value::Map(map), offset))
    }

    fn decode_array(&mut self, size: usize, mut offset: usize) -> std::io::Result<(Value, usize)> {
        let mut array = Vec::new();
        for _ in 0..size {
            let (value, new_offset) = self.decode(offset)?;
            offset = new_offset;
            array.push(value);
        }
        Ok((Value::Array(array), offset))
    }

    fn size_from_ctrl_byte(
        &self,
        ctrl_byte: u8,
        offset: usize,
        type_num: usize,
    ) -> std::io::Result<(usize, usize)> {
        let mut size = (ctrl_byte & 0x1F) as usize;
        if type_num == 1 || size < 29 {
            return Ok((size, offset));
        }

        if size == 29 {
            size = 29 + self.buffer[offset] as usize;
            return Ok((size, offset + 1));
        }

        if size == 30 {
            let bytes = [self.buffer[offset], self.buffer[offset + 1]];
            size = 285 + u16::from_be_bytes(bytes) as usize;
            return Ok((size, offset + 2));
        }

        let bytes = [
            0,
            self.buffer[offset],
            self.buffer[offset + 1],
            self.buffer[offset + 2],
        ];
        size = u32::from_be_bytes(bytes) as usize + 65821;
        Ok((size, offset + 3))
    }
}

#[allow(dead_code)]
pub fn get_nested<'a>(map: &'a HashMap<String, Value>, keys: &[&str]) -> Option<&'a Value> {
    let mut current = map.get(keys[0])?;
    for &key in &keys[1..] {
        current = current.as_map()?.get(key)?;
    }
    Some(current)
}
