//! Emit the OpenAPI spec for the Bulwark API as pretty JSON to stdout.
//!
//! This is the first step of the front-end build pipeline:
//!
//! ```sh
//! cargo run -p bulwark --bin gen-openapi > web/openapi.json
//! ```
//!
//! It deliberately does not touch the engine or bind any sockets — it only
//! serializes the static API description, so it runs fast and without config.

use bulwark::openapi::ApiDoc;
use utoipa::OpenApi;

fn main() {
    let json = ApiDoc::openapi()
        .to_pretty_json()
        .expect("serialize OpenAPI document");
    println!("{json}");
}
