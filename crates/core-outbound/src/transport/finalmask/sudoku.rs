use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, LazyLock},
};

use base64::Engine as _;
use core_config::SudokuMaskConfig;
use parking_lot::Mutex;
use rand::RngExt;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::adapter::BoxedStream;

const PERM4: [[usize; 4]; 24] = [
    [0, 1, 2, 3],
    [0, 1, 3, 2],
    [0, 2, 1, 3],
    [0, 2, 3, 1],
    [0, 3, 1, 2],
    [0, 3, 2, 1],
    [1, 0, 2, 3],
    [1, 0, 3, 2],
    [1, 2, 0, 3],
    [1, 2, 3, 0],
    [1, 3, 0, 2],
    [1, 3, 2, 0],
    [2, 0, 1, 3],
    [2, 0, 3, 1],
    [2, 1, 0, 3],
    [2, 1, 3, 0],
    [2, 3, 0, 1],
    [2, 3, 1, 0],
    [3, 0, 1, 2],
    [3, 0, 2, 1],
    [3, 1, 0, 2],
    [3, 1, 2, 0],
    [3, 2, 0, 1],
    [3, 2, 1, 0],
];

// Go's compatibility-stable math/rand Source. The cooked state and algorithm
// are from the Go standard library (BSD-3-Clause). Keeping this tiny local
// implementation avoids pulling the Linux/Windows-only `ggstd` crate into
// macOS and Android builds.
const GO_RNG_LEN: usize = 607;
const GO_RNG_TAP: usize = 273;
const GO_RNG_MASK: u64 = (1 << 63) - 1;

static GO_RNG_COOKED: LazyLock<[i64; GO_RNG_LEN]> = LazyLock::new(|| {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(concat!(
            "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"
        ))
        .expect("embedded Go math/rand state must be valid base64");
    assert_eq!(bytes.len(), GO_RNG_LEN * size_of::<i64>());

    let mut cooked = [0_i64; GO_RNG_LEN];
    for (slot, bytes) in cooked.iter_mut().zip(bytes.chunks_exact(size_of::<i64>())) {
        *slot = i64::from_le_bytes(bytes.try_into().expect("eight-byte Go RNG state"));
    }
    cooked
});

struct GoRng {
    tap: usize,
    feed: usize,
    state: [i64; GO_RNG_LEN],
}

impl GoRng {
    fn new(seed: i64) -> Self {
        let mut rng = Self {
            tap: 0,
            feed: GO_RNG_LEN - GO_RNG_TAP,
            state: [0; GO_RNG_LEN],
        };
        rng.seed(seed);
        rng
    }

    fn seed(&mut self, seed: i64) {
        self.tap = 0;
        self.feed = GO_RNG_LEN - GO_RNG_TAP;

        let mut seed = seed % i64::from(i32::MAX);
        if seed < 0 {
            seed += i64::from(i32::MAX);
        }
        if seed == 0 {
            seed = 89_482_311;
        }

        let mut value = seed as i32;
        for index in -20_isize..GO_RNG_LEN as isize {
            value = go_seed_rand(value);
            if index >= 0 {
                let mut state = i64::from(value) << 40;
                value = go_seed_rand(value);
                state ^= i64::from(value) << 20;
                value = go_seed_rand(value);
                state ^= i64::from(value);
                state ^= GO_RNG_COOKED[index as usize];
                self.state[index as usize] = state;
            }
        }
    }

    fn uint32(&mut self) -> u32 {
        ((self.uint64() & GO_RNG_MASK) >> 31) as u32
    }

    fn uint64(&mut self) -> u64 {
        if self.tap == 0 {
            self.tap = GO_RNG_LEN;
        }
        self.tap -= 1;
        if self.feed == 0 {
            self.feed = GO_RNG_LEN;
        }
        self.feed -= 1;

        let value = self.state[self.feed].wrapping_add(self.state[self.tap]);
        self.state[self.feed] = value;
        value as u64
    }
}

fn go_seed_rand(value: i32) -> i32 {
    const A: i32 = 48_271;
    const Q: i32 = 44_488;
    const R: i32 = 3_399;

    let high = value / Q;
    let low = value % Q;
    let next = A * low - R * high;
    if next < 0 { next + i32::MAX } else { next }
}

#[derive(Clone)]
enum LayoutKind {
    Ascii,
    Entropy,
    Custom {
        x_bits: [u8; 2],
        p_bits: [u8; 2],
        v_bits: [u8; 4],
        x_mask: u8,
    },
}

#[derive(Clone)]
struct Layout {
    hint_mask: u8,
    hint_value: u8,
    pad_marker: u8,
    padding_pool: Vec<u8>,
    kind: LayoutKind,
}

impl Layout {
    fn is_hint(&self, byte: u8) -> bool {
        (byte & self.hint_mask) == self.hint_value
            || (matches!(self.kind, LayoutKind::Ascii) && byte == b'\n')
    }

    fn encode_group(&self, group: u8) -> u8 {
        match &self.kind {
            LayoutKind::Ascii => {
                let byte = 0x40 | (group & 0x3f);
                if byte == 0x7f { b'\n' } else { byte }
            }
            LayoutKind::Entropy => {
                let value = group & 0x3f;
                ((value & 0x30) << 1) | (value & 0x0f)
            }
            LayoutKind::Custom {
                x_bits,
                p_bits,
                v_bits,
                x_mask,
            } => encode_custom_group(group, *x_bits, *p_bits, *v_bits, *x_mask, None),
        }
    }

    fn decode_group(&self, byte: u8) -> Option<u8> {
        match &self.kind {
            LayoutKind::Ascii => {
                if byte == b'\n' {
                    Some(0x3f)
                } else if byte & 0x40 != 0 {
                    Some(byte & 0x3f)
                } else {
                    None
                }
            }
            LayoutKind::Entropy => {
                (byte & 0x90 == 0).then_some(((byte >> 1) & 0x30) | (byte & 0x0f))
            }
            LayoutKind::Custom {
                p_bits,
                v_bits,
                x_mask,
                ..
            } => {
                if byte & x_mask != *x_mask {
                    return None;
                }
                let mut value = 0;
                let mut position = 0;
                if byte & (1 << p_bits[0]) != 0 {
                    value |= 2;
                }
                if byte & (1 << p_bits[1]) != 0 {
                    value |= 1;
                }
                for (index, bit) in v_bits.iter().copied().enumerate() {
                    if byte & (1 << bit) != 0 {
                        position |= 1 << (3 - index);
                    }
                }
                Some((value << 4) | position)
            }
        }
    }
}

struct Table {
    encode: Vec<Vec<[u8; 4]>>,
    decode: HashMap<u32, u8>,
    layout: Arc<Layout>,
}

type Grid = [u8; 16];
type BasePatterns = Vec<Vec<[u8; 4]>>;

static BASE_PATTERNS: LazyLock<Result<BasePatterns, String>> = LazyLock::new(build_base_patterns);
static TABLE_CACHE: LazyLock<Mutex<HashMap<String, Arc<Vec<Arc<Table>>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub(super) fn wrap(inner: BoxedStream, config: &SudokuMaskConfig) -> std::io::Result<BoxedStream> {
    let tables = get_tables(config)?;
    let padding_min = effective_padding_min(config).min(100);
    let padding_max = effective_padding_max(config).max(padding_min).min(100);
    let (client, worker) = tokio::io::duplex(64 * 1024);
    let (mut app_read, mut app_write) = tokio::io::split(worker);
    let (mut raw_read, mut raw_write) = tokio::io::split(inner);
    let encode_tables = tables.clone();
    tokio::spawn(async move {
        let mut codec = Encoder::new(encode_tables, padding_min, padding_max);
        let mut buffer = vec![0; 32 * 1024];
        let result = async {
            loop {
                let count = app_read.read(&mut buffer).await?;
                if count == 0 {
                    raw_write.shutdown().await?;
                    return Ok::<_, std::io::Error>(());
                }
                let encoded = codec.encode(&buffer[..count])?;
                raw_write.write_all(&encoded).await?;
            }
        }
        .await;
        if let Err(error) = result {
            tracing::debug!(%error, "finalmask sudoku encoder stopped");
        }
    });
    tokio::spawn(async move {
        // Xray 26.7.11 is directional: clients write classic four-hint
        // Sudoku and read the packed 6-bit downlink representation.
        let mut decoder = PackedDecoder::new(tables);
        let mut buffer = vec![0; 32 * 1024];
        let result = async {
            loop {
                let count = raw_read.read(&mut buffer).await?;
                if count == 0 {
                    app_write.shutdown().await?;
                    return Ok::<_, std::io::Error>(());
                }
                let decoded = decoder.decode(&buffer[..count])?;
                if !decoded.is_empty() {
                    app_write.write_all(&decoded).await?;
                }
            }
        }
        .await;
        if let Err(error) = result {
            tracing::debug!(%error, "finalmask sudoku decoder stopped");
        }
    });
    Ok(Box::pin(client))
}

/// Server direction is intentionally asymmetric in Xray 26.7.11: the server
/// reads classic four-hint Sudoku and writes the packed six-bit form.
pub(super) fn wrap_server(
    inner: BoxedStream,
    config: &SudokuMaskConfig,
) -> std::io::Result<BoxedStream> {
    let tables = get_tables(config)?;
    let padding_min = effective_padding_min(config).min(100);
    let padding_max = effective_padding_max(config).max(padding_min).min(100);
    let (client, worker) = tokio::io::duplex(64 * 1024);
    let (mut app_read, mut app_write) = tokio::io::split(worker);
    let (mut raw_read, mut raw_write) = tokio::io::split(inner);
    let encode_tables = tables.clone();
    tokio::spawn(async move {
        let mut codec = PackedEncoder::new(encode_tables, padding_min, padding_max);
        let mut buffer = vec![0; 32 * 1024];
        let result = async {
            loop {
                let count = app_read.read(&mut buffer).await?;
                if count == 0 {
                    raw_write.shutdown().await?;
                    return Ok::<_, std::io::Error>(());
                }
                raw_write
                    .write_all(&codec.encode(&buffer[..count])?)
                    .await?;
            }
        }
        .await;
        if let Err(error) = result {
            tracing::debug!(%error, "finalmask sudoku packed encoder stopped");
        }
    });
    tokio::spawn(async move {
        let mut decoder = HintDecoder::new(tables);
        let mut buffer = vec![0; 32 * 1024];
        let result = async {
            loop {
                let count = raw_read.read(&mut buffer).await?;
                if count == 0 {
                    app_write.shutdown().await?;
                    return Ok::<_, std::io::Error>(());
                }
                let decoded = decoder.decode(&buffer[..count])?;
                if !decoded.is_empty() {
                    app_write.write_all(&decoded).await?;
                }
            }
        }
        .await;
        if let Err(error) = result {
            tracing::debug!(%error, "finalmask sudoku hint decoder stopped");
        }
    });
    Ok(Box::pin(client))
}

pub(super) struct UdpCodec {
    tables: Arc<Vec<Arc<Table>>>,
    padding_min: u32,
    padding_max: u32,
}

impl UdpCodec {
    pub(super) fn new(config: &SudokuMaskConfig) -> std::io::Result<Self> {
        let tables = get_tables(config)?;
        let padding_min = effective_padding_min(config).min(100);
        let padding_max = effective_padding_max(config).max(padding_min).min(100);
        Ok(Self {
            tables,
            padding_min,
            padding_max,
        })
    }

    /// UDP resets table index and padding choice for every datagram upstream.
    pub(super) fn encode(&self, payload: &[u8]) -> std::io::Result<Vec<u8>> {
        Encoder::new(self.tables.clone(), self.padding_min, self.padding_max).encode(payload)
    }

    pub(super) fn decode(&self, packet: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut decoder = HintDecoder::new(self.tables.clone());
        let output = decoder.decode(packet)?;
        if !decoder.hints.is_empty() {
            return Err(invalid(
                "UDP Sudoku datagram ends with an incomplete hint tuple",
            ));
        }
        Ok(output)
    }
}

struct Encoder {
    tables: Arc<Vec<Arc<Table>>>,
    table_index: usize,
    padding_chance: u32,
}

impl Encoder {
    fn new(tables: Arc<Vec<Arc<Table>>>, min: u32, max: u32) -> Self {
        let padding_chance = if min == max {
            min
        } else {
            rand::rng().random_range(min..=max)
        };
        Self {
            tables,
            table_index: 0,
            padding_chance,
        }
    }

    fn should_pad(&self, rng: &mut impl rand::Rng) -> bool {
        self.padding_chance >= 100
            || (self.padding_chance > 0 && rng.random_range(0..100) < self.padding_chance)
    }

    fn encode(&mut self, input: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut rng = rand::rng();
        let mut output = Vec::with_capacity(input.len() * 6 + 8);
        for &byte in input {
            let table = &self.tables[self.table_index % self.tables.len()];
            if self.should_pad(&mut rng) {
                output.push(
                    table.layout.padding_pool[rng.random_range(0..table.layout.padding_pool.len())],
                );
            }
            let candidates = &table.encode[byte as usize];
            let hints = candidates
                .get(rng.random_range(0..candidates.len()))
                .ok_or_else(|| invalid("sudoku encode table is empty"))?;
            let permutation = PERM4[rng.random_range(0..PERM4.len())];
            for index in permutation {
                if self.should_pad(&mut rng) {
                    output.push(
                        table.layout.padding_pool
                            [rng.random_range(0..table.layout.padding_pool.len())],
                    );
                }
                output.push(hints[index]);
            }
            self.table_index += 1;
        }
        if self.should_pad(&mut rng) {
            let table = &self.tables[self.table_index % self.tables.len()];
            output.push(
                table.layout.padding_pool[rng.random_range(0..table.layout.padding_pool.len())],
            );
        }
        Ok(output)
    }
}

struct PackedDecoder {
    tables: Arc<Vec<Arc<Table>>>,
    group_index: usize,
    bit_buffer: u64,
    bit_count: usize,
}

struct HintDecoder {
    tables: Arc<Vec<Arc<Table>>>,
    table_index: usize,
    hints: Vec<u8>,
}

impl HintDecoder {
    fn new(tables: Arc<Vec<Arc<Table>>>) -> Self {
        Self {
            tables,
            table_index: 0,
            hints: Vec::with_capacity(4),
        }
    }

    fn decode(&mut self, input: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut output = Vec::with_capacity(input.len() / 4 + 1);
        for &byte in input {
            let table = &self.tables[self.table_index % self.tables.len()];
            if !table.layout.is_hint(byte) {
                continue;
            }
            self.hints.push(byte);
            if self.hints.len() != 4 {
                continue;
            }
            let mut hints: [u8; 4] = self.hints[..].try_into().expect("four hints");
            hints.sort_unstable();
            let decoded = table
                .decode
                .get(&pack_key(hints))
                .copied()
                .ok_or_else(|| invalid("invalid sudoku hint tuple"))?;
            output.push(decoded);
            self.hints.clear();
            self.table_index += 1;
        }
        Ok(output)
    }
}

struct PackedEncoder {
    tables: Arc<Vec<Arc<Table>>>,
    group_index: usize,
    padding_chance: u32,
}

impl PackedEncoder {
    fn new(tables: Arc<Vec<Arc<Table>>>, min: u32, max: u32) -> Self {
        let padding_chance = if min == max {
            min
        } else {
            rand::rng().random_range(min..=max)
        };
        Self {
            tables,
            group_index: 0,
            padding_chance,
        }
    }

    fn should_pad(&self, rng: &mut impl rand::Rng) -> bool {
        self.padding_chance >= 100
            || (self.padding_chance > 0 && rng.random_range(0..100) < self.padding_chance)
    }

    fn maybe_pad(&self, output: &mut Vec<u8>, layout: &Layout, rng: &mut impl rand::Rng) {
        if !self.should_pad(rng) {
            return;
        }
        loop {
            let byte = layout.padding_pool[rng.random_range(0..layout.padding_pool.len())];
            if byte != layout.pad_marker {
                output.push(byte);
                return;
            }
        }
    }

    fn encode(&mut self, input: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut output = Vec::with_capacity(input.len() * 2 + 8);
        let mut bit_buffer = 0u64;
        let mut bit_count = 0usize;
        let mut rng = rand::rng();
        for &byte in input {
            bit_buffer = (bit_buffer << 8) | u64::from(byte);
            bit_count += 8;
            while bit_count >= 6 {
                bit_count -= 6;
                let layout = &self.tables[self.group_index % self.tables.len()].layout;
                let group = (bit_buffer >> bit_count) as u8 & 0x3f;
                self.maybe_pad(&mut output, layout, &mut rng);
                output.push(layout.encode_group(group));
                self.group_index += 1;
                if bit_count == 0 {
                    bit_buffer = 0;
                } else {
                    bit_buffer &= (1u64 << bit_count) - 1;
                }
            }
        }
        if bit_count > 0 {
            let layout = &self.tables[self.group_index % self.tables.len()].layout;
            let group = (bit_buffer << (6 - bit_count)) as u8 & 0x3f;
            self.maybe_pad(&mut output, layout, &mut rng);
            output.push(layout.encode_group(group));
            self.group_index += 1;
            output.push(
                self.tables[self.group_index % self.tables.len()]
                    .layout
                    .pad_marker,
            );
        }
        let layout = &self.tables[self.group_index % self.tables.len()].layout;
        self.maybe_pad(&mut output, layout, &mut rng);
        Ok(output)
    }
}

impl PackedDecoder {
    fn new(tables: Arc<Vec<Arc<Table>>>) -> Self {
        Self {
            tables,
            group_index: 0,
            bit_buffer: 0,
            bit_count: 0,
        }
    }

    fn decode(&mut self, input: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut output = Vec::with_capacity(input.len() * 3 / 4);
        for &byte in input {
            let table = &self.tables[self.group_index % self.tables.len()];
            if !table.layout.is_hint(byte) {
                // Packed encoders terminate a padded partial 6-bit group with
                // the next layout's marker. Discarding the residual bits is
                // what keeps independently written chunks byte-aligned.
                if byte == table.layout.pad_marker {
                    self.bit_buffer = 0;
                    self.bit_count = 0;
                }
                continue;
            }
            let group = table
                .layout
                .decode_group(byte)
                .ok_or_else(|| invalid("invalid packed sudoku byte"))?;
            self.group_index += 1;
            self.bit_buffer = (self.bit_buffer << 6) | u64::from(group);
            self.bit_count += 6;
            while self.bit_count >= 8 {
                self.bit_count -= 8;
                output.push((self.bit_buffer >> self.bit_count) as u8);
                if self.bit_count == 0 {
                    self.bit_buffer = 0;
                } else {
                    self.bit_buffer &= (1u64 << self.bit_count) - 1;
                }
            }
        }
        Ok(output)
    }
}

fn get_tables(config: &SudokuMaskConfig) -> std::io::Result<Arc<Vec<Arc<Table>>>> {
    let key = serde_json::to_string(config).map_err(invalid)?;
    if let Some(cached) = TABLE_CACHE.lock().get(&key).cloned() {
        return Ok(cached);
    }
    let mode = normalize_ascii(&config.ascii)?;
    let patterns = normalized_patterns(config, mode)?;
    let mut tables = Vec::with_capacity(patterns.len());
    for pattern in patterns {
        let layout = match mode {
            "prefer_ascii" => ascii_layout(),
            _ if !pattern.is_empty() => custom_layout(&pattern)?,
            _ => entropy_layout(),
        };
        tables.push(Arc::new(build_table(&config.password, Arc::new(layout))?));
    }
    let tables = Arc::new(tables);
    TABLE_CACHE.lock().insert(key, tables.clone());
    Ok(tables)
}

fn normalize_ascii(value: &str) -> std::io::Result<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "entropy" | "prefer_entropy" => Ok("prefer_entropy"),
        "ascii" | "prefer_ascii" => Ok("prefer_ascii"),
        _ => Err(invalid(format!("invalid sudoku ascii mode `{value}`"))),
    }
}

fn normalized_patterns(config: &SudokuMaskConfig, mode: &str) -> std::io::Result<Vec<String>> {
    if mode == "prefer_ascii" {
        return Ok(vec![String::new()]);
    }
    let custom_table = if config.custom_table.is_empty() {
        &config.legacy_custom_table
    } else {
        &config.custom_table
    };
    let source = if !config.custom_tables.is_empty() {
        config.custom_tables.clone()
    } else if !config.legacy_custom_sets.is_empty() {
        config.legacy_custom_sets.clone()
    } else {
        vec![custom_table.clone()]
    };
    let mut seen = HashSet::new();
    let mut output = Vec::new();
    for pattern in source {
        let pattern = if pattern.trim().is_empty() {
            String::new()
        } else {
            normalize_custom_table(&pattern)?
        };
        if seen.insert(pattern.clone()) {
            output.push(pattern);
        }
    }
    if output.is_empty() {
        output.push(String::new());
    }
    Ok(output)
}

fn effective_padding_min(config: &SudokuMaskConfig) -> u32 {
    if config.padding_min == 0 {
        config.legacy_padding_min
    } else {
        config.padding_min
    }
}

fn effective_padding_max(config: &SudokuMaskConfig) -> u32 {
    if config.padding_max == 0 {
        config.legacy_padding_max
    } else {
        config.padding_max
    }
}

fn ascii_layout() -> Layout {
    Layout {
        hint_mask: 0x40,
        hint_value: 0x40,
        pad_marker: 0x3f,
        padding_pool: (0x20..0x40).collect(),
        kind: LayoutKind::Ascii,
    }
}

fn entropy_layout() -> Layout {
    let mut padding_pool = Vec::with_capacity(16);
    for index in 0..8 {
        padding_pool.extend_from_slice(&[0x80 + index, 0x10 + index]);
    }
    Layout {
        hint_mask: 0x90,
        hint_value: 0,
        pad_marker: 0x80,
        padding_pool,
        kind: LayoutKind::Entropy,
    }
}

fn normalize_custom_table(pattern: &str) -> std::io::Result<String> {
    let pattern = pattern.trim().to_ascii_lowercase().replace(' ', "");
    if pattern.len() != 8
        || pattern.bytes().filter(|&byte| byte == b'x').count() != 2
        || pattern.bytes().filter(|&byte| byte == b'p').count() != 2
        || pattern.bytes().filter(|&byte| byte == b'v').count() != 4
        || pattern
            .bytes()
            .any(|byte| !matches!(byte, b'x' | b'p' | b'v'))
    {
        return Err(invalid("customTable must contain exactly 2 x, 2 p and 4 v"));
    }
    Ok(pattern)
}

fn custom_layout(pattern: &str) -> std::io::Result<Layout> {
    let pattern = normalize_custom_table(pattern)?;
    let mut x = Vec::new();
    let mut p = Vec::new();
    let mut v = Vec::new();
    for (index, byte) in pattern.bytes().enumerate() {
        let bit = 7 - index as u8;
        match byte {
            b'x' => x.push(bit),
            b'p' => p.push(bit),
            b'v' => v.push(bit),
            _ => unreachable!(),
        }
    }
    let x_bits = [x[0], x[1]];
    let p_bits = [p[0], p[1]];
    let v_bits = [v[0], v[1], v[2], v[3]];
    let x_mask = (1 << x_bits[0]) | (1 << x_bits[1]);
    let mut padding = HashSet::new();
    for drop in 0..2 {
        for value in 0..4 {
            for position in 0..16 {
                let group = (value << 4) | position;
                let byte = encode_custom_group(group, x_bits, p_bits, v_bits, x_mask, Some(drop));
                if byte.count_ones() >= 5 {
                    padding.insert(byte);
                }
            }
        }
    }
    let mut padding_pool = padding.into_iter().collect::<Vec<_>>();
    padding_pool.sort_unstable();
    if padding_pool.is_empty() {
        return Err(invalid("customTable produced empty padding pool"));
    }
    let pad_marker = padding_pool[0];
    Ok(Layout {
        hint_mask: x_mask,
        hint_value: x_mask,
        pad_marker,
        padding_pool,
        kind: LayoutKind::Custom {
            x_bits,
            p_bits,
            v_bits,
            x_mask,
        },
    })
}

fn encode_custom_group(
    group: u8,
    x_bits: [u8; 2],
    p_bits: [u8; 2],
    v_bits: [u8; 4],
    x_mask: u8,
    drop_x: Option<usize>,
) -> u8 {
    let mut output = x_mask;
    if let Some(drop) = drop_x {
        output &= !(1 << x_bits[drop]);
    }
    let value = (group >> 4) & 3;
    let position = group & 15;
    if value & 2 != 0 {
        output |= 1 << p_bits[0];
    }
    if value & 1 != 0 {
        output |= 1 << p_bits[1];
    }
    for (index, bit) in v_bits.into_iter().enumerate() {
        if (position >> (3 - index)) & 1 != 0 {
            output |= 1 << bit;
        }
    }
    output
}

fn build_table(password: &str, layout: Arc<Layout>) -> std::io::Result<Table> {
    let patterns = BASE_PATTERNS.as_ref().map_err(|error| invalid(error))?;
    if patterns.len() < 256 {
        return Err(invalid("not enough sudoku grids"));
    }
    let mut order = (0..patterns.len()).collect::<Vec<_>>();
    let hash = Sha256::digest(password.as_bytes());
    let seed = i64::from_be_bytes(hash[..8].try_into().expect("sha prefix"));
    let mut go_rng = GoRng::new(seed);
    for index in (1..order.len()).rev() {
        // Go's Shuffle uses its private Lemire `int31n`, deliberately not the
        // public compatibility-preserving `Int31n`. Copy that reduction over
        // the exact Go Source stream implemented above.
        let n = (index + 1) as u32;
        let mut value = go_rng.uint32();
        let mut product = u64::from(value) * u64::from(n);
        let mut low = product as u32;
        if low < n {
            let threshold = n.wrapping_neg() % n;
            while low < threshold {
                value = go_rng.uint32();
                product = u64::from(value) * u64::from(n);
                low = product as u32;
            }
        }
        order.swap(index, (product >> 32) as usize);
    }
    let mut encode = vec![Vec::new(); 256];
    let mut decode = HashMap::with_capacity(1 << 16);
    for byte in 0..256 {
        for groups in &patterns[order[byte]] {
            let mut hints = groups.map(|group| layout.encode_group(group));
            hints.sort_unstable();
            let key = pack_key(hints);
            if let Some(previous) = decode.insert(key, byte as u8)
                && previous != byte as u8
            {
                return Err(invalid("sudoku decode key collision"));
            }
            encode[byte].push(groups.map(|group| layout.encode_group(group)));
        }
    }
    Ok(Table {
        encode,
        decode,
        layout,
    })
}

fn build_base_patterns() -> Result<BasePatterns, String> {
    let grids = generate_all_grids();
    let positions = hint_positions();
    let mut patterns = vec![Vec::new(); grids.len()];
    for positions in positions {
        let mut counts = HashMap::<u32, u16>::with_capacity(grids.len());
        let mut keys = Vec::with_capacity(grids.len());
        let mut groups_by_grid = Vec::with_capacity(grids.len());
        for grid in &grids {
            let mut groups = positions.map(|position| clue_group(grid, position));
            groups.sort_unstable();
            let key = pack_key(groups);
            *counts.entry(key).or_default() += 1;
            keys.push(key);
            groups_by_grid.push(groups);
        }
        for index in 0..grids.len() {
            if counts[&keys[index]] == 1 {
                patterns[index].push(groups_by_grid[index]);
            }
        }
    }
    if patterns.iter().any(Vec::is_empty) {
        return Err("a sudoku grid has no uniquely decodable clue set".into());
    }
    Ok(patterns)
}

fn generate_all_grids() -> Vec<Grid> {
    fn dfs(index: usize, grid: &mut Grid, output: &mut Vec<Grid>) {
        if index == 16 {
            output.push(*grid);
            return;
        }
        let row = index / 4;
        let column = index % 4;
        let box_row = (row / 2) * 2;
        let box_column = (column / 2) * 2;
        for number in 1..=4 {
            if (0..4).any(|i| grid[row * 4 + i] == number || grid[i * 4 + column] == number) {
                continue;
            }
            if (0..2).any(|r| (0..2).any(|c| grid[(box_row + r) * 4 + box_column + c] == number)) {
                continue;
            }
            grid[index] = number;
            dfs(index + 1, grid, output);
            grid[index] = 0;
        }
    }
    let mut output = Vec::with_capacity(288);
    dfs(0, &mut [0; 16], &mut output);
    output
}

fn hint_positions() -> Vec<[u8; 4]> {
    let mut output = Vec::with_capacity(1820);
    for a in 0..13 {
        for b in a + 1..14 {
            for c in b + 1..15 {
                for d in c + 1..16 {
                    output.push([a, b, c, d]);
                }
            }
        }
    }
    output
}

fn clue_group(grid: &Grid, position: u8) -> u8 {
    ((grid[position as usize] - 1) << 4) | (position & 15)
}

fn pack_key(bytes: [u8; 4]) -> u32 {
    u32::from_be_bytes(bytes)
}

fn invalid(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_roundtrip_and_go_shuffle_are_stable() {
        let config = SudokuMaskConfig {
            password: "sudoku-golden".into(),
            ascii: "prefer_ascii".into(),
            ..Default::default()
        };
        let tables = get_tables(&config).unwrap();
        let table = &tables[0];
        // This table is derived using Go math/rand, not Rust's
        // ChaCha RNG. Every official hint tuple must decode to its byte.
        for byte in [0u8, 1, 42, 127, 255] {
            let mut hints = table.encode[byte as usize][0];
            hints.sort_unstable();
            assert_eq!(table.decode.get(&pack_key(hints)), Some(&byte));
        }

        // Generated by the pinned Xray 26.7.11 `buildTable` implementation
        // (commit 6e3322d) over every candidate tuple, including list order.
        let mut digest = Sha256::new();
        for candidates in &table.encode {
            digest.update((candidates.len() as u32).to_be_bytes());
            for tuple in candidates {
                digest.update(tuple);
            }
        }
        assert_eq!(
            hex::encode(digest.finalize()),
            "8b1bf1fdb13064b003cda40f0d40a0bf7b3af2100e49c21db12e324e7271c564"
        );
        assert_eq!(table.encode[0][0], *b"KX`q");
        assert_eq!(table.encode[1][0], *b"JPis");
        assert_eq!(table.encode[42][0], *b"BD`{");
        assert_eq!(table.encode[127][0], *b"NTbp");
        assert_eq!(table.encode[255][0], *b"DPjr");
    }

    #[test]
    fn packed_client_downlink_matches_xray_ascii_golden_across_chunks() {
        let table = Arc::new(build_table("packed-golden", Arc::new(ascii_layout())).unwrap());
        let mut decoder = PackedDecoder::new(Arc::new(vec![table]));

        // Xray's packed encoder maps [0x48, 0x69, 0xff] to the four 6-bit
        // groups `R`, `F`, `g`, `\n`. A one-byte write [0xab] becomes `j`,
        // `p`, followed by ASCII's 0x3f pad marker to discard the padded tail.
        assert_eq!(decoder.decode(b"RF").unwrap(), [0x48]);
        assert_eq!(decoder.decode(b"g\n").unwrap(), [0x69, 0xff]);
        assert_eq!(decoder.decode(&[b'j', b'p', 0x3f]).unwrap(), [0xab]);
    }

    #[test]
    fn packed_group_codec_roundtrips_every_official_layout() {
        let layouts = [
            ascii_layout(),
            entropy_layout(),
            custom_layout("xxppvvvv").unwrap(),
        ];
        for layout in layouts {
            assert!(!layout.is_hint(layout.pad_marker));
            for group in 0..64 {
                let encoded = layout.encode_group(group);
                assert!(layout.is_hint(encoded));
                assert_eq!(layout.decode_group(encoded), Some(group));
            }
        }
    }

    #[test]
    fn udp_codec_restarts_at_table_zero_for_every_datagram() {
        let config = SudokuMaskConfig {
            password: "udp-golden".into(),
            custom_tables: vec!["xxppvvvv".into(), "vvxxppvv".into()],
            ..Default::default()
        };
        let codec = UdpCodec::new(&config).unwrap();
        for payload in [b"one".as_slice(), b"second datagram".as_slice()] {
            let encoded = codec.encode(payload).unwrap();
            assert_eq!(codec.decode(&encoded).unwrap(), payload);
        }
    }

    #[test]
    fn udp_codec_rejects_truncated_hint_tuple() {
        let config = SudokuMaskConfig {
            password: "udp-negative".into(),
            ascii: "prefer_ascii".into(),
            ..Default::default()
        };
        let codec = UdpCodec::new(&config).unwrap();
        assert!(codec.decode(b"ABC").is_err());
    }

    #[tokio::test]
    async fn client_and_server_stream_directions_roundtrip() {
        let config = SudokuMaskConfig {
            password: "stream-bidirectional".into(),
            ascii: "prefer_ascii".into(),
            ..Default::default()
        };
        let (left, right) = tokio::io::duplex(64 * 1024);
        let mut client = wrap(Box::pin(left), &config).unwrap();
        let mut server = wrap_server(Box::pin(right), &config).unwrap();
        client.write_all(b"request").await.unwrap();
        let mut request = [0; 7];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"request");
        server.write_all(b"response").await.unwrap();
        let mut response = [0; 8];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");
    }
}
