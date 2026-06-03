//! Tokenization for the wildcard/regex reverse index.
//!
//! Inspired by Brave's `adblock-rust`: instead of scanning every wildcard/regex
//! rule on each query, we bucket each such rule under one rare literal *token*
//! (a maximal alphanumeric run) and only check candidates that share a token
//! with the query name. Any rule for which we can't derive a guaranteed-present
//! token falls back to an always-scanned list, so correctness is never traded
//! for speed.
//!
//! Safety rule: a literal run in a pattern is usable as an index token only if
//! it is **interior** — bounded on both sides by a real separator (not a `*`
//! wildcard and not the pattern edge, where anchoring is ambiguous). Any domain
//! matching such a pattern necessarily contains that run as a complete token, so
//! tokenizing the query name will surface it. Query names are concrete, so we
//! tokenize *all* their runs.

/// Minimum token length. Must be identical for pattern and query tokenization.
const MIN_TOKEN_LEN: usize = 3;

#[inline]
fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

/// FNV-1a 32-bit hash of a byte slice (case-insensitive on ASCII).
fn fast_hash(s: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for &b in s {
        h ^= b.to_ascii_lowercase() as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

/// Tokenize a concrete query name into `tokens` (cleared first): every maximal
/// alphanumeric run of length `>= MIN_TOKEN_LEN`, de-duplicated. Taking a caller
/// buffer lets the query hot path reuse a thread-local scratch `Vec` instead of
/// allocating on every lookup.
pub fn tokenize_query_into(name: &str, tokens: &mut Vec<u32>) {
    tokens.clear();
    let bytes = name.as_bytes();
    let mut start = None;
    for (i, &b) in bytes.iter().enumerate() {
        if is_token_char(b) {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            push_run(tokens, &bytes[s..i]);
        }
    }
    if let Some(s) = start {
        push_run(tokens, &bytes[s..]);
    }
    tokens.sort_unstable();
    tokens.dedup();
}

/// Tokenize a concrete query name: every maximal alphanumeric run of length
/// `>= MIN_TOKEN_LEN`. Returns de-duplicated token hashes. Convenience wrapper
/// over [`tokenize_query_into`] for callers that don't hold a scratch buffer.
pub fn tokenize_query(name: &str) -> Vec<u32> {
    let mut tokens = Vec::new();
    tokenize_query_into(name, &mut tokens);
    tokens
}

fn push_run(tokens: &mut Vec<u32>, run: &[u8]) {
    if run.len() >= MIN_TOKEN_LEN {
        tokens.push(fast_hash(run));
    }
}

/// Tokenize a wildcard pattern body, returning only **safe interior** token
/// hashes (see module docs). `body` is the pattern with `*` wildcards and `^`
/// separators still present (anchors already stripped).
pub fn tokenize_pattern_safe(body: &str) -> Vec<u32> {
    let bytes = body.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    let len = bytes.len();
    while i < len {
        if !is_token_char(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < len && is_token_char(bytes[i]) {
            i += 1;
        }
        // Interior: both neighbors exist and neither is a `*` wildcard.
        let left_ok = start > 0 && bytes[start - 1] != b'*';
        let right_ok = i < len && bytes[i] != b'*';
        if left_ok && right_ok && (i - start) >= MIN_TOKEN_LEN {
            tokens.push(fast_hash(&bytes[start..i]));
        }
    }
    tokens.sort_unstable();
    tokens.dedup();
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_tokens() {
        let t = tokenize_query("ad.doubleclick.net");
        assert!(t.contains(&fast_hash(b"doubleclick")));
        assert!(t.contains(&fast_hash(b"net")));
        // "ad" is too short.
        assert!(!t.contains(&fast_hash(b"ad")));
    }

    #[test]
    fn interior_tokens_only() {
        // `*.doubleclick.net` -> "doubleclick" is interior & safe; "net" is at
        // the edge (ambiguous anchoring) so it's excluded.
        let t = tokenize_pattern_safe("*.doubleclick.net");
        assert_eq!(t, vec![fast_hash(b"doubleclick")]);
    }

    #[test]
    fn star_adjacent_excluded() {
        // `*track*` -> "track" touches `*` on both sides -> unusable.
        assert!(tokenize_pattern_safe("*track*").is_empty());
    }

    #[test]
    fn case_insensitive() {
        assert_eq!(tokenize_query("EXAMPLE.com"), tokenize_query("example.COM"));
    }
}
