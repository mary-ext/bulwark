//! Bulwark server library: the REST API, app wiring, embedded UI assets, auth,
//! persistence, the API DTOs, and the generated OpenAPI document.
//!
//! Exposed as a library (alongside the `bulwark` binary) so the `gen-openapi`
//! binary can emit the OpenAPI spec without running the server — keeping the
//! Rust build independent of the front-end build.

pub mod api;
pub mod app;
pub mod assets;
pub mod auth;
pub mod dto;
pub mod openapi;
pub mod persist;
