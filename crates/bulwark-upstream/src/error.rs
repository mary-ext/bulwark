//! Upstream error type.

use std::sync::Arc;

/// Errors that can occur talking to an upstream resolver.
#[derive(Debug, thiserror::Error, Clone)]
pub enum UpstreamError {
    #[error("timed out")]
    Timeout,
    #[error("i/o error: {0}")]
    Io(String),
    #[error("dns protocol error: {0}")]
    Proto(String),
    #[error("tls error: {0}")]
    Tls(String),
    #[error("quic error: {0}")]
    Quic(String),
    #[error("http error: {0}")]
    Http(String),
    #[error("bootstrap failed to resolve {0}")]
    Bootstrap(String),
    #[error("no upstreams configured")]
    NoUpstreams,
    #[error("all upstreams failed; last error: {0}")]
    AllFailed(Box<UpstreamError>),
    #[error("invalid upstream spec: {0}")]
    InvalidSpec(String),
}

/// Convenience alias for fallible upstream operations.
pub type Result<T> = std::result::Result<T, UpstreamError>;

/// Shared (cloneable) error used by the single-flight machinery, where one
/// computed result is handed to many awaiting callers.
pub type SharedResult<T> = std::result::Result<T, Arc<UpstreamError>>;
