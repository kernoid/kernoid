// SPDX-License-Identifier: AGPL-3.0-or-later
//! QR codes for TOTP URIs, kernoid's own, written from ISO/IEC 18004:2015: byte mode, error correction level M,
//! versions 1 to 40 (the smallest that holds the data), Reed–Solomon codes over GF(256), the eight data masks chosen
//! by the four penalty rules, and an SVG of the symbol with its quiet zone.

use std::fmt::Write as _;

/// The data does not fit into a version-40 symbol at level M.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooLong;

/// Error correction codewords per block at level M, by version (ISO/IEC 18004, table 9).
const EC_PER_BLOCK: [usize; 40] = [
    10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
];
/// Error correction blocks at level M, by version (table 9).
const BLOCKS: [usize; 40] = [
    1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33,
    35, 37, 38, 40, 43, 45, 47, 49,
];
/// The two bits of level M in the format information (table 12).
const LEVEL_M: u32 = 0b00;

/// A QR symbol: its modules row by row, `true` for dark.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrCode {
    version: usize,
    size: usize,
    modules: Vec<bool>,
}

impl QrCode {
    /// `data` in byte mode at level M, in the smallest version that holds it.
    pub fn encode(data: &[u8]) -> Result<Self, TooLong> {
        let version = (1..=40).find(|&version| fits(version, data.len())).ok_or(TooLong)?;
        Ok(Self::encode_in(version, data))
    }

    fn encode_in(version: usize, data: &[u8]) -> Self {
        let codewords = add_error_correction(version, &data_codewords(version, data));
        let mut symbol = Symbol::new(version);
        symbol.place(&codewords);
        // The mask with the lowest penalty, the first of equal ones.
        let mut best: Option<(u32, Symbol)> = None;
        for mask in 0..8 {
            let mut candidate = symbol.clone();
            candidate.apply_mask(mask);
            candidate.draw_format(mask);
            let score = candidate.penalty();
            if best.as_ref().is_none_or(|(lowest, _)| score < *lowest) {
                best = Some((score, candidate));
            }
        }
        let (_, symbol) = best.expect("eight masks tried");
        Self { version, size: symbol.size, modules: symbol.dark }
    }

    pub fn version(&self) -> usize {
        self.version
    }

    /// Modules per side.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Whether the module in column `x`, row `y` is dark.
    pub fn dark(&self, x: usize, y: usize) -> bool {
        self.modules[y * self.size + x]
    }

    /// The symbol as an SVG image, with the quiet zone of four modules, at least `min_side` pixels wide and high: dark
    /// modules black on white, as one path.
    pub fn svg(&self, min_side: usize) -> String {
        const QUIET: usize = 4;
        let modules = self.size + 2 * QUIET;
        let scale = min_side.div_ceil(modules).max(1);
        let side = modules * scale;
        let mut path = String::new();
        for y in 0..self.size {
            for x in 0..self.size {
                if self.dark(x, y) {
                    let _ = write!(path, "M{} {}h{scale}v{scale}h-{scale}z", (x + QUIET) * scale, (y + QUIET) * scale);
                }
            }
        }
        format!(
            "<?xml version=\"1.0\" standalone=\"yes\"?><svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.1\" \
             width=\"{side}\" height=\"{side}\" viewBox=\"0 0 {side} {side}\" shape-rendering=\"crispEdges\">\
             <rect x=\"0\" y=\"0\" width=\"{side}\" height=\"{side}\" fill=\"#ffffff\"/>\
             <path fill=\"#000000\" d=\"{path}\"/></svg>"
        )
    }
}

/// All modules of a symbol of `version` that are not function patterns.
fn raw_modules(version: usize) -> usize {
    let mut modules = (16 * version + 128) * version + 64;
    if version >= 2 {
        let alignments = version / 7 + 2;
        modules -= (25 * alignments - 10) * alignments - 55;
        if version >= 7 {
            modules -= 36;
        }
    }
    modules
}

/// Data codewords of `version` at level M.
fn data_capacity(version: usize) -> usize {
    raw_modules(version) / 8 - EC_PER_BLOCK[version - 1] * BLOCKS[version - 1]
}

/// Bits of the character count in byte mode (table 3).
fn count_bits(version: usize) -> usize {
    if version <= 9 { 8 } else { 16 }
}

fn fits(version: usize, length: usize) -> bool {
    length < (1 << count_bits(version)) && 4 + count_bits(version) + 8 * length <= 8 * data_capacity(version)
}

/// The bit stream (7.4): mode, count, data, terminator, padding to the capacity.
fn data_codewords(version: usize, data: &[u8]) -> Vec<u8> {
    let capacity = data_capacity(version) * 8;
    let mut bits = Bits::default();
    bits.push(0b0100, 4);
    bits.push(data.len() as u32, count_bits(version));
    for byte in data {
        bits.push(u32::from(*byte), 8);
    }
    bits.push(0, 4.min(capacity - bits.len));
    bits.push(0, (8 - bits.len % 8) % 8);
    for pad in [0xEC, 0x11].into_iter().cycle() {
        if bits.len >= capacity {
            break;
        }
        bits.push(pad, 8);
    }
    bits.bytes
}

#[derive(Default)]
struct Bits {
    bytes: Vec<u8>,
    len: usize,
}

impl Bits {
    fn push(&mut self, value: u32, count: usize) {
        for i in (0..count).rev() {
            if self.len.is_multiple_of(8) {
                self.bytes.push(0);
            }
            if (value >> i) & 1 == 1 {
                *self.bytes.last_mut().expect("pushed") |= 0x80 >> (self.len % 8);
            }
            self.len += 1;
        }
    }
}

/// The data split into blocks, each with its Reed–Solomon codewords, interleaved (7.5, 7.6).
fn add_error_correction(version: usize, data: &[u8]) -> Vec<u8> {
    let blocks = BLOCKS[version - 1];
    let ec_len = EC_PER_BLOCK[version - 1];
    let total = raw_modules(version) / 8;
    let short_blocks = blocks - total % blocks;
    let short_len = total / blocks;
    let divisor = generator(ec_len);
    let mut split = Vec::with_capacity(blocks);
    let mut at = 0;
    for block in 0..blocks {
        let data_len = short_len - ec_len + usize::from(block >= short_blocks);
        let part = &data[at..at + data_len];
        at += data_len;
        split.push((part.to_vec(), remainder(part, &divisor)));
    }
    let mut out = Vec::with_capacity(total);
    for i in 0..=short_len - ec_len {
        for (part, _) in &split {
            if let Some(byte) = part.get(i) {
                out.push(*byte);
            }
        }
    }
    for i in 0..ec_len {
        for (_, ec) in &split {
            out.push(ec[i]);
        }
    }
    out
}

/// Multiplication in GF(256) with the polynomial x⁸ + x⁴ + x³ + x² + 1.
fn gf_multiply(x: u8, y: u8) -> u8 {
    let mut product: u16 = 0;
    for i in (0..8).rev() {
        product = (product << 1) ^ ((product >> 7) * 0x11D);
        product ^= u16::from((y >> i) & 1) * u16::from(x);
    }
    product as u8
}

/// The coefficients (highest first, the leading 1 left out) of (x − α⁰)(x − α¹)…(x − αⁿ⁻¹).
fn generator(degree: usize) -> Vec<u8> {
    let mut coefficients = vec![0u8; degree];
    coefficients[degree - 1] = 1;
    let mut root: u8 = 1;
    for _ in 0..degree {
        for j in 0..degree {
            coefficients[j] = gf_multiply(coefficients[j], root);
            if j + 1 < degree {
                coefficients[j] ^= coefficients[j + 1];
            }
        }
        root = gf_multiply(root, 0x02);
    }
    coefficients
}

/// The remainder of the data polynomial times xⁿ divided by the generator: the error correction codewords.
fn remainder(data: &[u8], divisor: &[u8]) -> Vec<u8> {
    let mut result = vec![0u8; divisor.len()];
    for byte in data {
        let factor = byte ^ result.remove(0);
        result.push(0);
        for (slot, coefficient) in result.iter_mut().zip(divisor) {
            *slot ^= gf_multiply(*coefficient, factor);
        }
    }
    result
}

/// A symbol being built: its modules and which of them belong to function patterns.
#[derive(Debug, Clone)]
struct Symbol {
    version: usize,
    size: usize,
    dark: Vec<bool>,
    function: Vec<bool>,
}

impl Symbol {
    /// The function patterns of `version` (6.3): finders with separators, timing, alignment, the dark module, and
    /// the areas of format and version information.
    fn new(version: usize) -> Self {
        let size = version * 4 + 17;
        let mut symbol = Self { version, size, dark: vec![false; size * size], function: vec![false; size * size] };
        for i in 0..size {
            symbol.set_function(6, i, i % 2 == 0);
            symbol.set_function(i, 6, i % 2 == 0);
        }
        symbol.draw_finder(3, 3);
        symbol.draw_finder(size - 4, 3);
        symbol.draw_finder(3, size - 4);
        let positions = alignment_positions(version);
        let last = positions.len().saturating_sub(1);
        for (i, &x) in positions.iter().enumerate() {
            for (j, &y) in positions.iter().enumerate() {
                // Not where the finders are.
                if !((i == 0 && j == 0) || (i == 0 && j == last) || (i == last && j == 0)) {
                    symbol.draw_alignment(x, y);
                }
            }
        }
        // Reserved now, written once the mask is known.
        symbol.draw_format(0);
        symbol.draw_version();
        symbol
    }

    fn set_function(&mut self, x: usize, y: usize, dark: bool) {
        self.dark[y * self.size + x] = dark;
        self.function[y * self.size + x] = true;
    }

    /// A finder pattern centred on (x, y) with its separator, clipped at the edges.
    fn draw_finder(&mut self, x: usize, y: usize) {
        for dy in -4i32..=4 {
            for dx in -4i32..=4 {
                let distance = dx.abs().max(dy.abs());
                let (column, row) = (x as i32 + dx, y as i32 + dy);
                if (0..self.size as i32).contains(&column) && (0..self.size as i32).contains(&row) {
                    self.set_function(column as usize, row as usize, distance != 2 && distance != 4);
                }
            }
        }
    }

    fn draw_alignment(&mut self, x: usize, y: usize) {
        for dy in -2i32..=2 {
            for dx in -2i32..=2 {
                let dark = dx.abs().max(dy.abs()) != 1;
                self.set_function((x as i32 + dx) as usize, (y as i32 + dy) as usize, dark);
            }
        }
    }

    /// The format information (7.9): level and mask, BCH-coded, masked with 101010000010010, in both copies; and
    /// the dark module.
    fn draw_format(&mut self, mask: u32) {
        let data = (LEVEL_M << 3) | mask;
        let mut remainder = data;
        for _ in 0..10 {
            remainder = (remainder << 1) ^ ((remainder >> 9) * 0x537);
        }
        let bits = ((data << 10) | remainder) ^ 0x5412;
        let bit = |i: u32| (bits >> i) & 1 == 1;
        let size = self.size;
        for i in 0..6 {
            self.set_function(8, i, bit(i as u32));
        }
        self.set_function(8, 7, bit(6));
        self.set_function(8, 8, bit(7));
        self.set_function(7, 8, bit(8));
        for i in 9..15 {
            self.set_function(14 - i, 8, bit(i as u32));
        }
        for i in 0..8 {
            self.set_function(size - 1 - i, 8, bit(i as u32));
        }
        for i in 8..15 {
            self.set_function(8, size - 15 + i, bit(i as u32));
        }
        self.set_function(8, size - 8, true);
    }

    /// The version information of versions 7 and up (7.10): the version, BCH-coded, in both corners.
    fn draw_version(&mut self) {
        if self.version < 7 {
            return;
        }
        let data = self.version as u32;
        let mut remainder = data;
        for _ in 0..12 {
            remainder = (remainder << 1) ^ ((remainder >> 11) * 0x1F25);
        }
        let bits = (data << 12) | remainder;
        for i in 0..18 {
            let dark = (bits >> i) & 1 == 1;
            let (a, b) = (self.size - 11 + i % 3, i / 3);
            self.set_function(a, b, dark);
            self.set_function(b, a, dark);
        }
    }

    /// The codewords in the zigzag of two columns, from the bottom right, skipping the vertical timing pattern (7.7.3).
    fn place(&mut self, codewords: &[u8]) {
        let size = self.size;
        let mut bit = 0;
        let mut right = size - 1;
        loop {
            if right == 6 {
                right = 5;
            }
            let upward = (right + 1) & 2 == 0;
            for step in 0..size {
                let y = if upward { size - 1 - step } else { step };
                for x in [right, right - 1] {
                    if !self.function[y * size + x] && bit < codewords.len() * 8 {
                        self.dark[y * size + x] = (codewords[bit / 8] >> (7 - bit % 8)) & 1 == 1;
                        bit += 1;
                    }
                }
            }
            if right < 2 {
                break;
            }
            right -= 2;
        }
    }

    /// The data masks of 7.8.2, on every module outside the function patterns.
    fn apply_mask(&mut self, mask: u32) {
        for y in 0..self.size {
            for x in 0..self.size {
                let flip = match mask {
                    0 => (x + y) % 2 == 0,
                    1 => y % 2 == 0,
                    2 => x % 3 == 0,
                    3 => (x + y) % 3 == 0,
                    4 => (x / 3 + y / 2) % 2 == 0,
                    5 => (x * y) % 2 + (x * y) % 3 == 0,
                    6 => ((x * y) % 2 + (x * y) % 3) % 2 == 0,
                    _ => ((x + y) % 2 + (x * y) % 3) % 2 == 0,
                };
                let at = y * self.size + x;
                if flip && !self.function[at] {
                    self.dark[at] = !self.dark[at];
                }
            }
        }
    }

    /// The penalty of the symbol by the four rules of 7.8.3.
    fn penalty(&self) -> u32 {
        let size = self.size;
        let at = |x: usize, y: usize| self.dark[y * size + x];
        let mut score = 0;
        // 1: runs of five or more modules of one colour in a row or column; 3: 1:1:3:1:1 with four light modules
        // on one side, inside the symbol.
        for line in 0..size {
            for vertical in [false, true] {
                let module = |i: usize| if vertical { at(line, i) } else { at(i, line) };
                let mut run = 1;
                for i in 1..=size {
                    if i < size && module(i) == module(i - 1) {
                        run += 1;
                    } else {
                        if run >= 5 {
                            score += 3 + (run - 5) as u32;
                        }
                        run = 1;
                    }
                }
                const FINDER: [bool; 7] = [true, false, true, true, true, false, true];
                for i in 0..size.saturating_sub(6) {
                    if (0..7).all(|k| module(i + k) == FINDER[k]) {
                        let light_before = i >= 4 && (i - 4..i).all(|k| !module(k));
                        let light_after = i + 11 <= size && (i + 7..i + 11).all(|k| !module(k));
                        if light_before || light_after {
                            score += 40;
                        }
                    }
                }
            }
        }
        // 2: blocks of 2 × 2 modules of one colour.
        for y in 0..size - 1 {
            for x in 0..size - 1 {
                let colour = at(x, y);
                if colour == at(x + 1, y) && colour == at(x, y + 1) && colour == at(x + 1, y + 1) {
                    score += 3;
                }
            }
        }
        // 4: the share of dark modules away from half, in steps of five per cent.
        let dark = self.dark.iter().filter(|dark| **dark).count();
        let total = size * size;
        let deviation = (dark * 20).abs_diff(total * 10);
        score += 10 * (deviation / total) as u32;
        score
    }
}

/// The centres of the alignment patterns in each direction (annex E).
fn alignment_positions(version: usize) -> Vec<usize> {
    if version == 1 {
        return Vec::new();
    }
    let count = version / 7 + 2;
    let step = if version == 32 { 26 } else { (version * 4 + count * 2 + 1) / (count * 2 - 2) * 2 };
    let mut positions = vec![6];
    let mut position = version * 4 + 17 - 7;
    let mut rest = Vec::new();
    for _ in 0..count - 1 {
        rest.push(position);
        position -= step;
    }
    rest.reverse();
    positions.extend(rest);
    positions
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Symbols made by another, independent encoder from the same input, in byte mode at level M (one line each: the
    /// version, the input, the modules row by row with `1` for dark).
    const VECTORS: &str = include_str!("testdata/qr-vectors.txt");

    #[test]
    fn symbols_match_another_encoder_module_for_module() {
        let mut checked = 0;
        for line in VECTORS.lines().filter(|line| !line.is_empty()) {
            let mut fields = line.split('\t');
            let version: usize = fields.next().unwrap().parse().unwrap();
            let input = fields.next().unwrap();
            let modules = fields.next().unwrap();
            let code = QrCode::encode(input.as_bytes()).unwrap();
            assert_eq!(code.version(), version, "{input}");
            let ours: String = code.modules.iter().map(|dark| if *dark { '1' } else { '0' }).collect();
            assert_eq!(ours, modules, "{input}");
            checked += 1;
        }
        assert!(checked >= 5);
    }

    #[test]
    fn tables_give_the_capacities_of_the_standard() {
        // Data codewords at level M (table 7) and byte-mode capacities (table 7, "8-bit byte").
        assert_eq!(data_capacity(1), 16);
        assert_eq!(data_capacity(7), 124);
        assert_eq!(data_capacity(10), 216);
        assert_eq!(data_capacity(40), 2334);
        assert!(fits(1, 14) && !fits(1, 15));
        assert!(fits(40, 2331) && !fits(40, 2332));
        assert_eq!(QrCode::encode(&[b'a'; 2332]), Err(TooLong));
        assert_eq!(alignment_positions(7), [6, 22, 38]);
        assert_eq!(alignment_positions(32), [6, 34, 60, 86, 112, 138]);
    }

    #[test]
    fn reed_solomon_codewords_are_those_of_the_standard() {
        // Annex I: "01234567" at version 1-M – its data codewords and their ten error correction codewords.
        let data = [0x10, 0x20, 0x0C, 0x56, 0x61, 0x80, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11];
        assert_eq!(remainder(&data, &generator(10)), [0xA5, 0x24, 0xD4, 0xC1, 0xED, 0x36, 0xC7, 0x87, 0x2C, 0x55]);
    }

    #[test]
    fn the_svg_draws_every_dark_module_with_a_quiet_zone() {
        let code = QrCode::encode(b"a").unwrap();
        let svg = code.svg(200);
        // 21 modules and 8 of quiet zone, 7 pixels each.
        assert!(svg.contains("width=\"203\" height=\"203\""));
        let dark = code.modules.iter().filter(|dark| **dark).count();
        assert_eq!(svg.matches('M').count(), dark);
        assert!(svg.contains("M28 28h7v7h-7z"), "the top left finder's corner");
    }
}
