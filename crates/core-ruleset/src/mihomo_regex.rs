//! Mihomo-compatible regular-expression compilation.
//!
//! Mihomo evaluates `DOMAIN-REGEX` with regexp2 in case-insensitive mode. Rust's
//! linear-time `regex` crate intentionally rejects look-around and backreferences,
//! so provider rules using those Mihomo features need the bounded backtracking
//! engine from `fancy-regex`.

use fancy_regex::{Error, Regex, RegexBuilder};

const BACKTRACK_LIMIT: usize = 1_000_000;
const DELEGATE_SIZE_LIMIT: usize = 8 * 1024 * 1024;

/// Compile one Mihomo `DOMAIN-REGEX` pattern.
///
/// The execution budget prevents a downloaded provider from causing unbounded
/// catastrophic backtracking while retaining regexp2-style look-around,
/// backreferences, and case-insensitive matching.
pub fn compile_mihomo_domain_regex(pattern: &str) -> Result<Regex, Error> {
    let mut builder = RegexBuilder::new(pattern);
    builder
        .case_insensitive(true)
        .oniguruma_mode(true)
        .backtrack_limit(BACKTRACK_LIMIT)
        .delegate_size_limit(DELEGATE_SIZE_LIMIT);
    builder.build()
}
