//! Embedded web assets and SPA fallback.

use axum::body::Body;
use axum::extract::Path;
use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../web/dist"]
struct Assets;

fn serve_path(path: &str) -> Response {
    let path = path.trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    match Assets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            (
                [(header::CONTENT_TYPE, mime.as_ref())],
                Body::from(content.data.to_vec()),
            )
                .into_response()
        }
        None => serve_index(),
    }
}

/// SPA fallback: serve index.html so client-side routing works.
fn serve_index() -> Response {
    match Assets::get("index.html") {
        Some(content) => (
            [(header::CONTENT_TYPE, "text/html")],
            Body::from(content.data.to_vec()),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            "Web UI not built. Run `pnpm install && pnpm build` in web/.",
        )
            .into_response(),
    }
}

async fn index() -> Response {
    serve_path("index.html")
}

async fn asset(Path(path): Path<String>) -> Response {
    serve_path(&format!("assets/{path}"))
}

async fn fallback(uri: Uri) -> Response {
    if uri.path().starts_with("/api") {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    serve_path(uri.path())
}

/// Router serving the embedded UI.
pub fn router() -> Router {
    Router::new()
        .route("/", get(index))
        .route("/assets/{*path}", get(asset))
        .fallback(fallback)
}
