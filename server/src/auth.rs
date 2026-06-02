//! Password hashing (Argon2) and in-memory session management.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use parking_lot::Mutex;
use rand::RngCore;

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

/// In-memory session store. Tokens expire after a TTL.
pub struct Sessions {
    inner: Mutex<HashMap<String, Instant>>,
    ttl: Duration,
}

impl Sessions {
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    fn random_token() -> String {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Create a new session and return its token.
    pub fn create(&self) -> String {
        let token = Self::random_token();
        self.inner.lock().insert(token.clone(), Instant::now());
        token
    }

    /// Validate a token, refreshing its expiry. Returns true if valid.
    pub fn validate(&self, token: &str) -> bool {
        let mut map = self.inner.lock();
        match map.get(token) {
            Some(created) if created.elapsed() < self.ttl => {
                map.insert(token.to_string(), Instant::now());
                true
            }
            Some(_) => {
                map.remove(token);
                false
            }
            None => false,
        }
    }

    pub fn remove(&self, token: &str) {
        self.inner.lock().remove(token);
    }
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
    fn sessions_validate_and_expire() {
        let s = Sessions::new(Duration::from_secs(60));
        let t = s.create();
        assert!(s.validate(&t));
        s.remove(&t);
        assert!(!s.validate(&t));
        assert!(!s.validate("bogus"));
    }
}
