//! Emit the OpenAPI specification as formatted JSON.

use bulwark::openapi::ApiDoc;
use utoipa::OpenApi;

fn main() {
    let json = ApiDoc::openapi()
        .to_pretty_json()
        .expect("serialize OpenAPI document");
    println!("{json}");
}
