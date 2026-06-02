//! Re-embed the web UI when its built bundle changes.
//!
//! The Rust build is intentionally *decoupled* from the front-end build: this
//! script never runs `pnpm`. It only tells Cargo to re-run (and thus re-embed
//! via `rust-embed`) when `web/dist` changes. Building the front-end is an
//! explicit, separate step — see `justfile` / the README "Build" section.
//!
//! Decoupling matters because the front-end is generated from an OpenAPI spec
//! that the server itself emits (`cargo run --bin gen-openapi`). If `cargo
//! build` also drove `pnpm build`, that would be a cycle: building the server
//! would require the web bundle, which would require the spec, which would
//! require building the server. Keeping the steps separate makes the pipeline a
//! straight line: spec → client codegen → `pnpm build` → `cargo build`.
//!
//! A plain `cargo build` still produces a runnable binary: `rust-embed` embeds
//! whatever is in `web/dist` (just the `.gitkeep` until the UI is built, in
//! which case the server serves a small "UI not built" placeholder).

use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let dist = manifest.join("..").join("web").join("dist");

    // `rust-embed`'s `#[folder]` requires the directory to exist at compile
    // time. The bundle isn't committed (and `vite build`'s `emptyOutDir` wipes
    // it), so ensure an empty `web/dist` exists for a stand-alone `cargo build`.
    // A `.keep` marker keeps the folder non-empty and gives `rust-embed`
    // something to embed; the server still serves the "UI not built" placeholder
    // because there's no `index.html`.
    std::fs::create_dir_all(&dist).expect("create web/dist");
    let keep = dist.join(".keep");
    if !keep.exists() {
        let _ = std::fs::write(&keep, b"");
    }

    // Re-embed when the built bundle changes. (We deliberately do *not* watch
    // `web/src` — Cargo doesn't build the front-end; `pnpm build` does.)
    println!("cargo:rerun-if-changed={}", dist.display());

    // A friendly nudge when there's nothing to embed yet.
    let built = std::fs::read_dir(&dist)
        .map(|d| d.filter_map(Result::ok).any(|e| e.file_name() != ".keep"))
        .unwrap_or(false);
    if !built {
        println!(
            "cargo:warning=web/dist has no UI bundle — embedding the \"UI not built\" placeholder. \
             Build the front-end first (`just web` or `cd web && pnpm install && pnpm build`)."
        );
    }
}
