//! Tokenization for wildcard and regex reverse indexing.

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

/// Writes deduplicated query-name token hashes into a reusable buffer.
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

/// Returns deduplicated query-name token hashes.
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

/// Streams query-name token hashes without allocating or deduplicating.
#[inline]
pub fn for_each_query_token(name: &str, mut f: impl FnMut(u32)) {
    let bytes = name.as_bytes();
    let mut start = None;
    for (i, &b) in bytes.iter().enumerate() {
        if is_token_char(b) {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            if i - s >= MIN_TOKEN_LEN {
                f(fast_hash(&bytes[s..i]));
            }
        }
    }
    if let Some(s) = start {
        if bytes.len() - s >= MIN_TOKEN_LEN {
            f(fast_hash(&bytes[s..]));
        }
    }
}

/// Returns hashes of guaranteed interior wildcard-pattern tokens.
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
        assert!(!t.contains(&fast_hash(b"ad")));
    }

    #[test]
    fn interior_tokens_only() {
        let t = tokenize_pattern_safe("*.doubleclick.net");
        assert_eq!(t, vec![fast_hash(b"doubleclick")]);
    }

    #[test]
    fn star_adjacent_excluded() {
        assert!(tokenize_pattern_safe("*track*").is_empty());
    }

    #[test]
    fn case_insensitive() {
        assert_eq!(tokenize_query("EXAMPLE.com"), tokenize_query("example.COM"));
    }
}
