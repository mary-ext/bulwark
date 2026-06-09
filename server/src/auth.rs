//! Password hashing (Argon2) and stateless session tokens (signed JWTs).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Hash a plaintext password with Argon2id.
pub fn hash_password(password: &str) -> anyhow::Result<String> {
    // Generate a random 16-byte salt (avoids depending on password_hash's
    // rand_core version, which can clash with the rand crate's).
    let mut salt_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut salt_bytes);
    let salt =
        SaltString::encode_b64(&salt_bytes).map_err(|e| anyhow::anyhow!("salt error: {e}"))?;
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hash error: {e}"))?;
    Ok(hash.to_string())
}

/// Verify a password against a stored Argon2 hash.
pub fn verify_password(password: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// Cookie name for the session token.
pub const SESSION_COOKIE: &str = "bw_session";

/// Session lifetime. Sessions slide (see [`SessionSigner::check`]), so an active
/// user is re-issued a fresh token well before this elapses; it only bites after
/// two weeks of inactivity.
pub const SESSION_TTL_SECS: u64 = 14 * 24 * 3600;

/// Generate a fresh signing secret: 32 random bytes, base64url-encoded for
/// storage in the config YAML. Called once on first run.
pub fn generate_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    B64.encode(bytes)
}

/// Fixed JWT header for HS256. Pre-encoded so verification can pin it with a
/// byte compare — we never read `alg` from an incoming token, which sidesteps
/// the classic `alg: none` / algorithm-confusion downgrade.
const JWT_HEADER_B64: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"; // {"alg":"HS256","typ":"JWT"}

#[derive(Serialize, Deserialize)]
struct Claims {
    /// Issued-at (unix seconds).
    iat: u64,
    /// Expiry (unix seconds).
    exp: u64,
}

/// Stateless session authority. Issues and verifies signed JWTs using an HMAC
/// secret persisted in the config — no server-side store, so nothing grows
/// unbounded and tokens survive restarts. Logout clears the cookie but cannot
/// revoke an outstanding token before its `exp`; rotating the secret (deleting
/// it from config) invalidates every token at once.
pub struct SessionSigner {
    secret: Vec<u8>,
    ttl: Duration,
}

impl SessionSigner {
    /// Build from the base64url secret stored in config. A non-decodable value
    /// (hand-edited config) falls back to using its raw bytes as the key, so
    /// auth still works deterministically rather than panicking at startup.
    pub fn new(secret_b64: &str, ttl: Duration) -> Self {
        let secret = B64
            .decode(secret_b64)
            .unwrap_or_else(|_| secret_b64.as_bytes().to_vec());
        Self { secret, ttl }
    }

    fn sign(&self, signing_input: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts any key length");
        mac.update(signing_input.as_bytes());
        B64.encode(mac.finalize().into_bytes())
    }

    /// Issue a new session token valid for `ttl`.
    pub fn issue(&self) -> String {
        let now = now_unix();
        let claims = Claims {
            iat: now,
            exp: now + self.ttl.as_secs(),
        };
        let payload = B64.encode(serde_json::to_vec(&claims).expect("claims serialize"));
        let signing_input = format!("{JWT_HEADER_B64}.{payload}");
        let sig = self.sign(&signing_input);
        format!("{signing_input}.{sig}")
    }

    /// Verify a token's signature, header, and expiry. Returns true if valid.
    pub fn verify(&self, token: &str) -> bool {
        !matches!(self.check(token), SessionVerdict::Invalid)
    }

    /// Verify a token and report whether the caller should slide the session by
    /// re-issuing the cookie. We refresh once the token is past the halfway
    /// point of its lifetime, so an active user never has to log back in.
    pub fn check(&self, token: &str) -> SessionVerdict {
        let Some(claims) = self.verify_inner(token) else {
            return SessionVerdict::Invalid;
        };
        let now = now_unix();
        if now >= claims.exp {
            SessionVerdict::Invalid
        } else if now >= claims.iat + self.ttl.as_secs() / 2 {
            SessionVerdict::Refresh
        } else {
            SessionVerdict::Valid
        }
    }

    /// Verify signature and header, returning the decoded claims (expiry not yet
    /// checked — that's the caller's job via [`Self::check`]).
    fn verify_inner(&self, token: &str) -> Option<Claims> {
        let mut parts = token.splitn(4, '.');
        let header = parts.next()?;
        let payload = parts.next()?;
        let sig = parts.next()?;
        if parts.next().is_some() || header != JWT_HEADER_B64 {
            return None;
        }
        // Recompute the MAC and compare in constant time.
        let expected = B64.decode(sig).ok()?;
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts any key length");
        mac.update(format!("{header}.{payload}").as_bytes());
        mac.verify_slice(&expected).ok()?;

        serde_json::from_slice(&B64.decode(payload).ok()?).ok()
    }
}

/// Outcome of verifying a session token.
#[derive(Debug, PartialEq, Eq)]
pub enum SessionVerdict {
    /// Missing, malformed, mis-signed, or expired.
    Invalid,
    /// Valid and still fresh — no action needed.
    Valid,
    /// Valid but past half its lifetime — caller should re-issue the cookie.
    Refresh,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify() {
        let h = hash_password("hunter2").unwrap();
        assert!(verify_password("hunter2", &h));
        assert!(!verify_password("wrong", &h));
    }

    #[test]
    fn fresh_token_is_valid() {
        let s = SessionSigner::new(&generate_secret(), Duration::from_secs(3600));
        // Well within the first half of its life → valid, no refresh.
        assert_eq!(s.check(&s.issue()), SessionVerdict::Valid);
        assert!(s.verify(&s.issue()));
        assert_eq!(s.check("bogus"), SessionVerdict::Invalid);
        assert_eq!(s.check("a.b.c"), SessionVerdict::Invalid);
    }

    #[test]
    fn past_half_life_asks_to_refresh() {
        // ttl/2 == 0, so a just-issued token is already past its halfway mark.
        let s = SessionSigner::new(&generate_secret(), Duration::from_secs(1));
        assert_eq!(s.check(&s.issue()), SessionVerdict::Refresh);
    }

    #[test]
    fn expired_token_rejected() {
        let s = SessionSigner::new(&generate_secret(), Duration::from_secs(0));
        // exp == iat == now, and verification requires now < exp.
        assert_eq!(s.check(&s.issue()), SessionVerdict::Invalid);
    }

    #[test]
    fn tampered_or_foreign_token_rejected() {
        let secret = generate_secret();
        let s = SessionSigner::new(&secret, Duration::from_secs(60));
        let t = s.issue();

        // A token minted under a different secret must not verify.
        let other = SessionSigner::new(&generate_secret(), Duration::from_secs(60));
        assert!(!s.verify(&other.issue()));

        // Flipping a character in the payload breaks the signature.
        let mut bytes = t.into_bytes();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 1;
        assert!(!s.verify(&String::from_utf8(bytes).unwrap()));
    }
}
