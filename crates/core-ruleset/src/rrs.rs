//! RRS —— WutherCore Rule Set 自研二进制规则集格式。
//!
//! ## 设计目标
//!
//! | 维度 | 实现 |
//! |---|---|
//! | **高性能** | 定长 header + 紧凑顺序 section；O(N) decode 全程零拷贝读取 |
//! | **低占用** | LEB128 var-len 长度 + 字符串引用 + CIDR 直存 5/17B；不依赖 zstd 也 ~3-5× 小于 YAML |
//! | **准确性** | 4B magic + 2B version + 8B createdAt + **CRC32(body)** + body length；任一字段错都立刻拒绝 |
//! | **跨工具** | encode/decode 完整双向；CLI `ruleset convert` 把 yaml/txt/json ↔ rrs 互转 |
//!
//! ## 文件布局（v3）
//!
//! ```text
//!   offset  bytes  field
//!   0       4      magic = "RRS\0"
//!   4       2      version (u16 LE) = 3
//!   6       2      flags  (u16 LE) —— 保留位（bit0 future zstd）
//!   8       8      created_at (u64 LE epoch_secs)
//!   16      4      body_len (u32 LE)
//!   20      4      body_crc32 (u32 LE)        ← CRC32 of bytes [24, 24+body_len)
//!   24      ...    body
//! ```
//!
//! ## body —— 12 个固定 section + 1 个扩展 classical section
//!
//! ```text
//!   for kind in [DomainExact, DomainSuffix, DomainKeyword, DomainRegex,
//!                DstCidrV4, DstCidrV6, SrcCidrV4, SrcCidrV6,
//!                DstPort, SrcPort, ProcessName, ProcessPath]:
//!     count   var-len u32
//!     for i in 0..count:
//!       payload_for_kind
//!   extended_classical:
//!     count var-len u32
//!     for i in 0..count:
//!       var-len len || utf8 "KIND,VALUE[,no-resolve]"
//! ```
//!
//! Per-kind payload：
//! * **string-based** (DomainExact / Suffix / Keyword / Regex / Process)：`var-len len || utf8 bytes`
//! * **CidrV4**：`4B network LE || 1B prefix`
//! * **CidrV6**：`16B network || 1B prefix`
//! * **Port**：`2B lo BE || 2B hi BE`
//!
//! ## 准确性保证
//!
//! 1. magic + version 必须严格匹配；
//! 2. body_len 必须等于实际剩余字节数；
//! 3. CRC32 必须匹配；
//! 4. 每个 string len ≤ 4096；CIDR prefix ≤ 32/128；
//! 5. 任一校验失败：返回精确字节偏移的 `ParseError`。

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{
    matcher::{ClassicalEntry, ClassicalKind},
    parser::ParseError,
};

pub const MAGIC: [u8; 4] = *b"RRS\0";
const VERSION_V1: u16 = 1;
const VERSION_V2: u16 = 2;
pub const VERSION: u16 = 3;
pub const HEADER_LEN: usize = 24;
pub const MAX_STR_LEN: usize = 4096;

/* ============================================================
Encode
============================================================ */

/// 把任意 [`ClassicalEntry`] 序列编码为 RRS 字节流。
pub fn encode(entries: &[ClassicalEntry]) -> Vec<u8> {
    // 按 kind 分桶 + 去重 + 排序
    let mut domains: Vec<String> = Vec::new();
    let mut suffixes: Vec<String> = Vec::new();
    let mut keywords: Vec<String> = Vec::new();
    let mut regex: Vec<String> = Vec::new();
    let mut dst_v4: Vec<(Ipv4Addr, u8)> = Vec::new();
    let mut dst_v6: Vec<(Ipv6Addr, u8)> = Vec::new();
    let mut src_v4: Vec<(Ipv4Addr, u8)> = Vec::new();
    let mut src_v6: Vec<(Ipv6Addr, u8)> = Vec::new();
    let mut dst_ports: Vec<(u16, u16)> = Vec::new();
    let mut src_ports: Vec<(u16, u16)> = Vec::new();
    let mut processes: Vec<String> = Vec::new();
    let mut process_paths: Vec<String> = Vec::new();
    let mut extended: Vec<String> = Vec::new();

    for e in entries {
        if e.policy.is_some() {
            extended.push(format_classical_entry(e));
            continue;
        }
        match e.kind {
            ClassicalKind::Domain => domains.push(e.value.to_ascii_lowercase()),
            ClassicalKind::DomainSuffix => {
                suffixes.push(e.value.trim_matches('.').to_ascii_lowercase())
            }
            ClassicalKind::DomainKeyword => keywords.push(e.value.to_ascii_lowercase()),
            ClassicalKind::DomainRegex => regex.push(e.value.clone()),
            ClassicalKind::DomainWildcard => extended.push(format_classical_entry(e)),
            ClassicalKind::IpCidr => {
                if let Ok(net) = e.value.parse::<ipnet::IpNet>() {
                    match net {
                        ipnet::IpNet::V4(n) => dst_v4.push((n.network(), n.prefix_len())),
                        ipnet::IpNet::V6(n) => dst_v6.push((n.network(), n.prefix_len())),
                    }
                }
            }
            ClassicalKind::SrcIpCidr => {
                if let Ok(net) = e.value.parse::<ipnet::IpNet>() {
                    match net {
                        ipnet::IpNet::V4(n) => src_v4.push((n.network(), n.prefix_len())),
                        ipnet::IpNet::V6(n) => src_v6.push((n.network(), n.prefix_len())),
                    }
                }
            }
            ClassicalKind::DstPort => {
                if let Some(r) = parse_port_range(&e.value) {
                    dst_ports.push(r);
                }
            }
            ClassicalKind::SrcPort => {
                if let Some(r) = parse_port_range(&e.value) {
                    src_ports.push(r);
                }
            }
            ClassicalKind::ProcessName => processes.push(e.value.to_ascii_lowercase()),
            ClassicalKind::ProcessPath => process_paths.push(e.value.clone()),
            _ => extended.push(format_classical_entry(e)),
        }
    }

    fn dedup_sort(v: &mut Vec<String>) {
        v.sort();
        v.dedup();
    }
    dedup_sort(&mut domains);
    dedup_sort(&mut suffixes);
    dedup_sort(&mut keywords);
    dedup_sort(&mut regex);
    dedup_sort(&mut processes);
    dedup_sort(&mut process_paths);
    dedup_sort(&mut extended);
    dst_v4.sort_by_key(|(ip, p)| (u32::from(*ip), *p));
    dst_v4.dedup();
    dst_v6.sort_by_key(|(ip, p)| (u128::from(*ip), *p));
    dst_v6.dedup();
    src_v4.sort_by_key(|(ip, p)| (u32::from(*ip), *p));
    src_v4.dedup();
    src_v6.sort_by_key(|(ip, p)| (u128::from(*ip), *p));
    src_v6.dedup();
    dst_ports.sort();
    dst_ports.dedup();
    src_ports.sort();
    src_ports.dedup();

    // 拼 body
    let mut body = Vec::with_capacity(256 + entries.len() * 16);
    encode_string_section(&mut body, &domains);
    encode_string_section(&mut body, &suffixes);
    encode_string_section(&mut body, &keywords);
    encode_string_section(&mut body, &regex);
    encode_v4_section(&mut body, &dst_v4);
    encode_v6_section(&mut body, &dst_v6);
    encode_v4_section(&mut body, &src_v4);
    encode_v6_section(&mut body, &src_v6);
    encode_port_section(&mut body, &dst_ports);
    encode_port_section(&mut body, &src_ports);
    encode_string_section(&mut body, &processes);
    encode_string_section(&mut body, &process_paths);
    encode_string_section(&mut body, &extended);

    let body_len = body.len() as u32;
    let body_crc = crc32fast::hash(&body);
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // flags
    out.extend_from_slice(&created_at.to_le_bytes());
    out.extend_from_slice(&body_len.to_le_bytes());
    out.extend_from_slice(&body_crc.to_le_bytes());
    debug_assert_eq!(out.len(), HEADER_LEN);
    out.extend_from_slice(&body);
    out
}

fn write_varlen(out: &mut Vec<u8>, mut v: u32) {
    while v >= 0x80 {
        out.push(((v & 0x7f) as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn encode_string_section(out: &mut Vec<u8>, items: &[String]) {
    write_varlen(out, items.len() as u32);
    for s in items {
        let bytes = s.as_bytes();
        debug_assert!(bytes.len() <= MAX_STR_LEN);
        write_varlen(out, bytes.len() as u32);
        out.extend_from_slice(bytes);
    }
}

fn encode_v4_section(out: &mut Vec<u8>, items: &[(Ipv4Addr, u8)]) {
    write_varlen(out, items.len() as u32);
    for (ip, prefix) in items {
        out.extend_from_slice(&ip.octets());
        out.push(*prefix);
    }
}

fn encode_v6_section(out: &mut Vec<u8>, items: &[(Ipv6Addr, u8)]) {
    write_varlen(out, items.len() as u32);
    for (ip, prefix) in items {
        out.extend_from_slice(&ip.octets());
        out.push(*prefix);
    }
}

fn encode_port_section(out: &mut Vec<u8>, items: &[(u16, u16)]) {
    write_varlen(out, items.len() as u32);
    for (lo, hi) in items {
        out.extend_from_slice(&lo.to_be_bytes());
        out.extend_from_slice(&hi.to_be_bytes());
    }
}

/* ============================================================
Decode
============================================================ */

/// 反序列化 RRS 二进制为 [`ClassicalEntry`] 列表。
pub fn decode(buf: &[u8]) -> Result<Vec<ClassicalEntry>, ParseError> {
    let mut r = Reader::new(buf);
    // header
    let magic = r.take(4)?;
    if magic != MAGIC {
        return Err(err(format!("bad magic: {:?}", magic)));
    }
    let version = r.read_u16_le()?;
    if !matches!(version, VERSION_V1 | VERSION_V2 | VERSION) {
        return Err(err(format!("unsupported RRS version: {}", version)));
    }
    let _flags = r.read_u16_le()?;
    let _created_at = r.read_u64_le()?;
    let body_len = r.read_u32_le()? as usize;
    let body_crc = r.read_u32_le()?;
    if r.remaining() != body_len {
        return Err(err(format!(
            "body_len mismatch: header={}, actual={}",
            body_len,
            r.remaining()
        )));
    }
    let body = r.take(body_len)?;
    let actual_crc = crc32fast::hash(body);
    if actual_crc != body_crc {
        return Err(err(format!(
            "CRC32 mismatch: header={:08x}, computed={:08x}",
            body_crc, actual_crc
        )));
    }

    let mut br = Reader::new(body);
    let mut out = Vec::new();
    if version == VERSION_V1 {
        decode_v1_body(&mut br, &mut out)?;
    } else if version == VERSION_V2 {
        decode_v2_body(&mut br, &mut out)?;
    } else {
        decode_v2_body(&mut br, &mut out)?;
        decode_extended_section(&mut br, &mut out)?;
    }
    if br.remaining() != 0 {
        return Err(err(format!("trailing bytes in body: {}", br.remaining())));
    }
    Ok(out)
}

fn decode_extended_section(
    reader: &mut Reader<'_>,
    out: &mut Vec<ClassicalEntry>,
) -> Result<(), ParseError> {
    let count = reader.read_varlen()? as usize;
    for _ in 0..count {
        let len = reader.read_varlen()? as usize;
        if len > MAX_STR_LEN {
            return Err(err(format!("extended rule too long: {len}")));
        }
        let bytes = reader.take(len)?;
        let line = std::str::from_utf8(bytes)
            .map_err(|error| err(format!("non-utf8 extended rule: {error}")))?;
        out.push(
            crate::parser::txt::parse_classical_line_strict(line)
                .map_err(|error| err(format!("invalid extended rule `{line}`: {error}")))?,
        );
    }
    Ok(())
}

fn decode_v1_body(
    reader: &mut Reader<'_>,
    out: &mut Vec<ClassicalEntry>,
) -> Result<(), ParseError> {
    decode_string_section(reader, ClassicalKind::Domain, out)?;
    decode_string_section(reader, ClassicalKind::DomainSuffix, out)?;
    decode_string_section(reader, ClassicalKind::DomainKeyword, out)?;
    decode_string_section(reader, ClassicalKind::DomainRegex, out)?;
    decode_v4_section(reader, ClassicalKind::IpCidr, out)?;
    decode_v6_section(reader, ClassicalKind::IpCidr, out)?;
    decode_port_section(reader, ClassicalKind::DstPort, out)?;
    decode_string_section(reader, ClassicalKind::ProcessName, out)
}

fn decode_v2_body(
    reader: &mut Reader<'_>,
    out: &mut Vec<ClassicalEntry>,
) -> Result<(), ParseError> {
    decode_string_section(reader, ClassicalKind::Domain, out)?;
    decode_string_section(reader, ClassicalKind::DomainSuffix, out)?;
    decode_string_section(reader, ClassicalKind::DomainKeyword, out)?;
    decode_string_section(reader, ClassicalKind::DomainRegex, out)?;
    decode_v4_section(reader, ClassicalKind::IpCidr, out)?;
    decode_v6_section(reader, ClassicalKind::IpCidr, out)?;
    decode_v4_section(reader, ClassicalKind::SrcIpCidr, out)?;
    decode_v6_section(reader, ClassicalKind::SrcIpCidr, out)?;
    decode_port_section(reader, ClassicalKind::DstPort, out)?;
    decode_port_section(reader, ClassicalKind::SrcPort, out)?;
    decode_string_section(reader, ClassicalKind::ProcessName, out)?;
    decode_string_section(reader, ClassicalKind::ProcessPath, out)
}

fn decode_string_section(
    reader: &mut Reader<'_>,
    kind: ClassicalKind,
    out: &mut Vec<ClassicalEntry>,
) -> Result<(), ParseError> {
    let count = reader.read_varlen()? as usize;
    for _ in 0..count {
        let len = reader.read_varlen()? as usize;
        if len > MAX_STR_LEN {
            return Err(err(format!("string too long: {len}")));
        }
        let bytes = reader.take(len)?;
        let value = std::str::from_utf8(bytes)
            .map_err(|error| err(format!("non-utf8: {error}")))?
            .to_string();
        out.push(ClassicalEntry {
            kind,
            value,
            policy: None,
        });
    }
    Ok(())
}

fn decode_v4_section(
    reader: &mut Reader<'_>,
    kind: ClassicalKind,
    out: &mut Vec<ClassicalEntry>,
) -> Result<(), ParseError> {
    let count = reader.read_varlen()? as usize;
    for _ in 0..count {
        let octets = reader.take(4)?;
        let prefix = reader.take(1)?[0];
        if prefix > 32 {
            return Err(err(format!("v4 prefix > 32: {prefix}")));
        }
        let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
        out.push(ClassicalEntry {
            kind,
            value: format!("{ip}/{prefix}"),
            policy: None,
        });
    }
    Ok(())
}

fn decode_v6_section(
    reader: &mut Reader<'_>,
    kind: ClassicalKind,
    out: &mut Vec<ClassicalEntry>,
) -> Result<(), ParseError> {
    let count = reader.read_varlen()? as usize;
    for _ in 0..count {
        let raw = reader.take(16)?;
        let mut octets = [0u8; 16];
        octets.copy_from_slice(raw);
        let prefix = reader.take(1)?[0];
        if prefix > 128 {
            return Err(err(format!("v6 prefix > 128: {prefix}")));
        }
        out.push(ClassicalEntry {
            kind,
            value: format!("{}/{prefix}", Ipv6Addr::from(octets)),
            policy: None,
        });
    }
    Ok(())
}

fn decode_port_section(
    reader: &mut Reader<'_>,
    kind: ClassicalKind,
    out: &mut Vec<ClassicalEntry>,
) -> Result<(), ParseError> {
    let count = reader.read_varlen()? as usize;
    for _ in 0..count {
        let lo_bytes = reader.take(2)?;
        let hi_bytes = reader.take(2)?;
        let lo = u16::from_be_bytes([lo_bytes[0], lo_bytes[1]]);
        let hi = u16::from_be_bytes([hi_bytes[0], hi_bytes[1]]);
        if lo > hi {
            return Err(err(format!("port range starts after its end: {lo}-{hi}")));
        }
        out.push(ClassicalEntry {
            kind,
            value: if lo == hi {
                lo.to_string()
            } else {
                format!("{lo}-{hi}")
            },
            policy: None,
        });
    }
    Ok(())
}

fn parse_port_range(s: &str) -> Option<(u16, u16)> {
    if let Some((a, b)) = s.split_once('-') {
        Some((a.parse().ok()?, b.parse().ok()?))
    } else {
        let p: u16 = s.parse().ok()?;
        Some((p, p))
    }
}

fn err(msg: impl Into<String>) -> ParseError {
    ParseError::Json(msg.into()) // 复用错误变体；信息已自带语义
}

/* ---------------- Reader ---------------- */

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        if self.pos + n > self.buf.len() {
            return Err(err(format!("unexpected EOF at {} (need {})", self.pos, n)));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn read_u16_le(&mut self) -> Result<u16, ParseError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn read_u32_le(&mut self) -> Result<u32, ParseError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn read_u64_le(&mut self) -> Result<u64, ParseError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }
    fn read_varlen(&mut self) -> Result<u32, ParseError> {
        let mut shift = 0u32;
        let mut acc = 0u32;
        loop {
            let b = self.take(1)?[0];
            acc |= ((b & 0x7f) as u32) << shift;
            if b & 0x80 == 0 {
                return Ok(acc);
            }
            shift += 7;
            if shift >= 32 {
                return Err(err("varlen overflow".to_string()));
            }
        }
    }
}

/* ============================================================
双向转换辅助 —— 把 entries 序列化回各种文本格式
============================================================ */

pub fn entries_to_yaml(entries: &[ClassicalEntry]) -> String {
    let mut out = String::from("payload:\n");
    for e in entries {
        out.push_str("  - ");
        out.push_str(
            &serde_json::to_string(&format_classical_entry(e))
                .expect("serializing a classical rule string cannot fail"),
        );
        out.push('\n');
    }
    out
}

pub fn entries_to_txt(entries: &[ClassicalEntry]) -> String {
    let mut out = String::new();
    for e in entries {
        out.push_str(&format_classical_entry(e));
        out.push('\n');
    }
    out
}

fn format_classical_entry(entry: &ClassicalEntry) -> String {
    let mut line = kind_str(entry.kind).to_owned();
    if !entry.value.is_empty() {
        line.push(',');
        line.push_str(&entry.value);
    }
    if let Some(policy) = &entry.policy {
        line.push(',');
        line.push_str(policy);
    }
    line
}

pub fn entries_to_singbox_json(entries: &[ClassicalEntry]) -> Result<String, String> {
    use std::collections::{BTreeMap, BTreeSet};

    use serde_json::{Map, Value, json};

    // ClassicalEntry 列表是顶层 OR。sing-box default rule 内部却是字段组间
    // AND，因此只能合并官方定义为同一 OR 组的 destination domain/IP 字段；
    // source IP、process、source/destination port 必须拆成独立顶层规则。
    let mut destination: BTreeMap<&'static str, Vec<Value>> = BTreeMap::new();
    let mut source_ips = Vec::new();
    let mut processes = Vec::new();
    let mut process_paths = Vec::new();
    let mut destination_ports = Vec::new();
    let mut destination_port_ranges = Vec::new();
    let mut source_ports = Vec::new();
    let mut source_port_ranges = Vec::new();
    let mut unsupported = BTreeSet::new();

    for e in entries {
        if e.policy.is_some() {
            unsupported.insert(format_classical_entry(e));
            continue;
        }
        match e.kind {
            ClassicalKind::Domain => destination
                .entry("domain")
                .or_default()
                .push(json!(e.value)),
            ClassicalKind::DomainSuffix => {
                // WutherCore classical DomainSuffix 始终是 root + subdomain；
                // sing-box leading dot 却表示仅 subdomain，因此导出时必须剥点。
                let suffix = e.value.trim().trim_start_matches('.').trim_end_matches('.');
                if !suffix.is_empty() {
                    destination
                        .entry("domain_suffix")
                        .or_default()
                        .push(json!(suffix));
                }
            }
            ClassicalKind::DomainKeyword => destination
                .entry("domain_keyword")
                .or_default()
                .push(json!(e.value)),
            ClassicalKind::DomainRegex => destination
                .entry("domain_regex")
                .or_default()
                .push(json!(e.value)),
            ClassicalKind::DomainWildcard => destination
                .entry("domain_regex")
                .or_default()
                .push(json!(wildcard_regex(&e.value))),
            ClassicalKind::IpCidr => destination
                .entry("ip_cidr")
                .or_default()
                .push(json!(e.value)),
            ClassicalKind::SrcIpCidr => source_ips.push(json!(e.value)),
            ClassicalKind::DstPort => {
                if let Some((start, end)) = parse_port_range(&e.value) {
                    if start == end {
                        destination_ports.push(json!(start));
                    } else {
                        destination_port_ranges.push(json!(format!("{start}:{end}")));
                    }
                }
            }
            ClassicalKind::SrcPort => {
                if let Some((start, end)) = parse_port_range(&e.value) {
                    if start == end {
                        source_ports.push(json!(start));
                    } else {
                        source_port_ranges.push(json!(format!("{start}:{end}")));
                    }
                }
            }
            ClassicalKind::ProcessName => processes.push(json!(e.value)),
            ClassicalKind::ProcessPath => process_paths.push(json!(e.value)),
            _ => {
                unsupported.insert(format_classical_entry(e));
            }
        }
    }
    if !unsupported.is_empty() {
        return Err(format!(
            "以下 Mihomo classical 规则没有等价的 sing-box headless rule 表达，已拒绝有损导出：{}",
            unsupported.into_iter().collect::<Vec<_>>().join("; ")
        ));
    }

    let mut rules = Vec::new();
    if !destination.is_empty() {
        let mut rule = Map::new();
        for (field, values) in destination {
            rule.insert(field.into(), Value::Array(values));
        }
        rules.push(Value::Object(rule));
    }
    if !source_ips.is_empty() {
        rules.push(json!({"source_ip_cidr": source_ips}));
    }
    if !destination_ports.is_empty() || !destination_port_ranges.is_empty() {
        let mut rule = Map::new();
        if !destination_ports.is_empty() {
            rule.insert("port".into(), Value::Array(destination_ports));
        }
        if !destination_port_ranges.is_empty() {
            rule.insert("port_range".into(), Value::Array(destination_port_ranges));
        }
        rules.push(Value::Object(rule));
    }
    if !source_ports.is_empty() || !source_port_ranges.is_empty() {
        let mut rule = Map::new();
        if !source_ports.is_empty() {
            rule.insert("source_port".into(), Value::Array(source_ports));
        }
        if !source_port_ranges.is_empty() {
            rule.insert("source_port_range".into(), Value::Array(source_port_ranges));
        }
        rules.push(Value::Object(rule));
    }
    if !processes.is_empty() {
        rules.push(json!({"process_name": processes}));
    }
    if !process_paths.is_empty() {
        rules.push(json!({"process_path": process_paths}));
    }

    let mut output = serde_json::to_string_pretty(&json!({"version": 2, "rules": rules}))
        .expect("serializing a JSON value cannot fail");
    output.push('\n');
    Ok(output)
}

fn kind_str(k: ClassicalKind) -> &'static str {
    match k {
        ClassicalKind::Domain => "DOMAIN",
        ClassicalKind::DomainSuffix => "DOMAIN-SUFFIX",
        ClassicalKind::DomainKeyword => "DOMAIN-KEYWORD",
        ClassicalKind::DomainRegex => "DOMAIN-REGEX",
        ClassicalKind::DomainWildcard => "DOMAIN-WILDCARD",
        ClassicalKind::GeoSite => "GEOSITE",
        ClassicalKind::GeoIp => "GEOIP",
        ClassicalKind::SrcGeoIp => "SRC-GEOIP",
        ClassicalKind::IpCidr => "IP-CIDR",
        ClassicalKind::SrcIpCidr => "SRC-IP-CIDR",
        ClassicalKind::IpSuffix => "IP-SUFFIX",
        ClassicalKind::SrcIpSuffix => "SRC-IP-SUFFIX",
        ClassicalKind::IpAsn => "IP-ASN",
        ClassicalKind::SrcIpAsn => "SRC-IP-ASN",
        ClassicalKind::DstPort => "DST-PORT",
        ClassicalKind::SrcPort => "SRC-PORT",
        ClassicalKind::InPort => "IN-PORT",
        ClassicalKind::InType => "IN-TYPE",
        ClassicalKind::InUser => "IN-USER",
        ClassicalKind::InName => "IN-NAME",
        ClassicalKind::Dscp => "DSCP",
        ClassicalKind::Uid => "UID",
        ClassicalKind::ProcessName => "PROCESS-NAME",
        ClassicalKind::ProcessPath => "PROCESS-PATH",
        ClassicalKind::ProcessNameRegex => "PROCESS-NAME-REGEX",
        ClassicalKind::ProcessPathRegex => "PROCESS-PATH-REGEX",
        ClassicalKind::ProcessNameWildcard => "PROCESS-NAME-WILDCARD",
        ClassicalKind::ProcessPathWildcard => "PROCESS-PATH-WILDCARD",
        ClassicalKind::RematchName => "REMATCH-NAME",
        ClassicalKind::Network => "NETWORK",
        ClassicalKind::And => "AND",
        ClassicalKind::Or => "OR",
        ClassicalKind::Not => "NOT",
        ClassicalKind::Match => "MATCH",
    }
}

fn wildcard_regex(pattern: &str) -> String {
    let mut output = String::from("^");
    let mut literal = String::new();
    let flush = |literal: &mut String, output: &mut String| {
        if !literal.is_empty() {
            output.push_str(&regex::escape(literal));
            literal.clear();
        }
    };
    for character in pattern.chars() {
        match character {
            '*' => {
                flush(&mut literal, &mut output);
                output.push_str(".*");
            }
            '?' => {
                flush(&mut literal, &mut output);
                output.push('.');
            }
            character => literal.push(character),
        }
    }
    flush(&mut literal, &mut output);
    output.push('$');
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(k: ClassicalKind, v: &str) -> ClassicalEntry {
        ClassicalEntry {
            kind: k,
            value: v.into(),
            policy: None,
        }
    }

    #[test]
    fn roundtrip_full_kinds() {
        let input = vec![
            entry(ClassicalKind::Domain, "exact.com"),
            entry(ClassicalKind::DomainSuffix, "example.com"),
            entry(ClassicalKind::DomainKeyword, "google"),
            entry(ClassicalKind::DomainRegex, r"^a\.b$"),
            entry(ClassicalKind::IpCidr, "1.2.3.0/24"),
            entry(ClassicalKind::IpCidr, "fd00::/8"),
            entry(ClassicalKind::SrcIpCidr, "10.0.0.0/8"),
            entry(ClassicalKind::DstPort, "443"),
            entry(ClassicalKind::DstPort, "1000-2000"),
            entry(ClassicalKind::SrcPort, "5353"),
            entry(ClassicalKind::ProcessName, "Code"),
            entry(ClassicalKind::ProcessPath, r"C:\Apps\Code.exe"),
        ];
        let bin = encode(&input);
        assert_eq!(&bin[..4], &MAGIC);
        let out = decode(&bin).unwrap();
        assert_eq!(out.len(), input.len());
        // 关键值可还原
        let values: std::collections::BTreeSet<_> = out.iter().map(|e| e.value.clone()).collect();
        assert!(values.contains("exact.com"));
        assert!(values.contains("example.com"));
        assert!(values.contains("1.2.3.0/24"));
        assert!(values.contains("fd00::/8"));
        assert!(values.contains("443"));
        assert!(values.contains("1000-2000"));
        assert!(values.contains("10.0.0.0/8"));
        assert!(values.contains("5353"));
        assert!(values.contains("code")); // 进程名小写
        assert!(values.contains(r"C:\Apps\Code.exe"));
        assert!(
            out.iter()
                .any(|entry| entry.kind == ClassicalKind::SrcIpCidr && entry.value == "10.0.0.0/8")
        );
        assert!(
            out.iter()
                .any(|entry| entry.kind == ClassicalKind::SrcPort && entry.value == "5353")
        );
        assert!(
            out.iter()
                .any(|entry| entry.kind == ClassicalKind::ProcessPath
                    && entry.value == r"C:\Apps\Code.exe")
        );
    }

    #[test]
    fn decodes_legacy_v1_without_reinterpreting_its_sections() {
        let mut body = Vec::new();
        encode_string_section(&mut body, &["legacy.example".into()]);
        encode_string_section(&mut body, &[]);
        encode_string_section(&mut body, &[]);
        encode_string_section(&mut body, &[]);
        encode_v4_section(&mut body, &[("192.0.2.0".parse().unwrap(), 24)]);
        encode_v6_section(&mut body, &[]);
        encode_port_section(&mut body, &[(443, 443)]);
        encode_string_section(&mut body, &["legacy.exe".into()]);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&VERSION_V1.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&crc32fast::hash(&body).to_le_bytes());
        bytes.extend_from_slice(&body);

        let entries = decode(&bytes).unwrap();
        assert!(entries.iter().any(
            |entry| entry.kind == ClassicalKind::Domain && entry.value == "legacy.example"
        ));
        assert!(
            entries
                .iter()
                .any(|entry| entry.kind == ClassicalKind::IpCidr && entry.value == "192.0.2.0/24")
        );
        assert!(
            entries
                .iter()
                .any(|entry| entry.kind == ClassicalKind::DstPort && entry.value == "443")
        );
    }

    #[test]
    fn dedup_and_sort_in_encode() {
        let dup = vec![
            entry(ClassicalKind::Domain, "B.com"),
            entry(ClassicalKind::Domain, "a.com"),
            entry(ClassicalKind::Domain, "a.com"),
        ];
        let bin = encode(&dup);
        let out = decode(&bin).unwrap();
        assert_eq!(out.len(), 2, "duplicate domains should be merged");
        assert_eq!(out[0].value, "a.com");
        assert_eq!(out[1].value, "b.com");
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bin = encode(&[entry(ClassicalKind::Domain, "x.com")]);
        bin[0] = b'X';
        assert!(decode(&bin).is_err());
    }

    #[test]
    fn rejects_bad_version() {
        let mut bin = encode(&[entry(ClassicalKind::Domain, "x.com")]);
        bin[4] = 99;
        assert!(decode(&bin).is_err());
    }

    #[test]
    fn rejects_corrupted_body() {
        let mut bin = encode(&[
            entry(ClassicalKind::Domain, "x.com"),
            entry(ClassicalKind::Domain, "y.com"),
        ]);
        // 翻转 body 的某一字节
        let n = bin.len();
        bin[n - 3] ^= 0xff;
        let r = decode(&bin);
        assert!(r.is_err(), "CRC32 should catch tampered body");
    }

    #[test]
    fn size_smaller_than_yaml() {
        let mut entries = Vec::new();
        for i in 0..1000u32 {
            entries.push(entry(
                ClassicalKind::DomainSuffix,
                &format!("host{}.example.com", i),
            ));
        }
        let bin = encode(&entries);
        let yaml = entries_to_yaml(&entries);
        let txt = entries_to_txt(&entries);
        assert!(
            bin.len() < yaml.len() / 2,
            "rrs={} yaml={}",
            bin.len(),
            yaml.len()
        );
        assert!(bin.len() < txt.len(), "rrs={} txt={}", bin.len(), txt.len());
    }

    #[test]
    fn singbox_json_export_parseable() {
        let input = vec![
            entry(ClassicalKind::DomainSuffix, ".example.com"),
            entry(ClassicalKind::DstPort, "443"),
            entry(ClassicalKind::DstPort, "1000-2000"),
            entry(ClassicalKind::ProcessPath, r"C:\Apps\browser.exe"),
        ];
        let direct_json = entries_to_singbox_json(&input).unwrap();
        let direct_value: serde_json::Value = serde_json::from_str(&direct_json).unwrap();
        assert_eq!(
            direct_value["rules"][0]["domain_suffix"][0],
            serde_json::Value::String("example.com".into())
        );
        let bin = encode(&input);
        let out = decode(&bin).unwrap();
        let json = entries_to_singbox_json(&out).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value["rules"][0]["domain_suffix"][0],
            serde_json::Value::String("example.com".into())
        );
        // 用语义 parser 反解；原 classical 列表的顶层 OR 必须保持。
        let program = crate::parser::sb_json::parse(json.as_bytes()).unwrap();
        let matcher = crate::RulesetMatcher::compile_semantic("roundtrip", program);
        assert!(matcher.matches("example.com", None, Some(80), None));
        assert!(matcher.matches("www.example.com", None, Some(80), None));
        assert!(matcher.matches("unrelated.test", None, Some(443), None));
        assert!(matcher.matches("unrelated.test", None, Some(1500), None));
        assert!(!matcher.matches("unrelated.test", None, Some(80), None));
        let context = crate::RulesetMatchContext {
            process_path: Some(r"C:\Apps\browser.exe"),
            ..Default::default()
        };
        assert!(matcher.matches_context(&context));
    }

    #[test]
    fn v3_roundtrip_preserves_extended_rules_and_match_without_trailing_comma() {
        let mut no_resolve = entry(ClassicalKind::IpAsn, "13335");
        no_resolve.policy = Some("no-resolve".into());
        let input = vec![
            entry(ClassicalKind::DomainWildcard, "*.example.com"),
            entry(ClassicalKind::InType, "http/socks"),
            entry(ClassicalKind::And, "((DOMAIN,logic.example),(NETWORK,tcp))"),
            entry(ClassicalKind::Match, ""),
            no_resolve,
        ];
        let output = decode(&encode(&input)).unwrap();
        let text = entries_to_txt(&output);
        assert!(text.lines().any(|line| line == "MATCH"));
        assert!(!text.lines().any(|line| line == "MATCH,"));
        for expected in [
            ClassicalKind::DomainWildcard,
            ClassicalKind::InType,
            ClassicalKind::And,
            ClassicalKind::Match,
            ClassicalKind::IpAsn,
        ] {
            assert!(output.iter().any(|entry| entry.kind == expected));
        }
        assert!(output.iter().any(|entry| {
            entry.kind == ClassicalKind::IpAsn && entry.policy.as_deref() == Some("no-resolve")
        }));
    }

    #[test]
    fn singbox_export_rejects_rules_it_cannot_represent_without_loss() {
        let error =
            entries_to_singbox_json(&[entry(ClassicalKind::IpSuffix, "8.8.8.8/24")]).unwrap_err();
        assert!(error.contains("IP-SUFFIX,8.8.8.8/24"));
    }
}
